/**
 * muse-driver.mjs
 * ------------------------------------------------------------------
 * Browser driver for Meta Muse (https://muse.ai) — the "Hatch" agent VM.
 *
 * WHY THIS EXISTS
 *   Muse chat is NOT a REST/SSE API. It is an RPC gateway over an
 *   *encrypted* WebSocket ("noise" transport: X25519 + HKDF + AES-GCM),
 *   with Ed25519-signed auth_token/notary_token in the WS URL. See
 *   https://hatch.metaaivm.com/v1/noise and methods like chat.stream.
 *
 *   Rather than reimplementing the Noise handshake (phase 2), this driver
 *   drives the REAL client in a real Chrome so the app performs all crypto
 *   itself. It then reads the rendered assistant reply from the DOM.
 *
 * SELECTORS (harvested from the captured client JS / HAR)
 *   composer root : [data-hatch-composer-root]
 *   editor        : [data-lexical-editor="true"]   (Lexical contenteditable)
 *   send          : Enter key (analytics event "composer_enter_key")
 *   streaming     : [data-testid="hatch-composer-stop-button"]
 *   messages      : [data-message-item] (data-message-role = user|assistant)
 *   error         : [data-testid="assistant-response-error-notice"]
 *   auth check    : POST /api/auth/check  -> { ok, viewer_id, access_token }
 * ------------------------------------------------------------------
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

export const SELECTORS = {
  composerRoot: '[data-hatch-composer-root]',
  editor: '[data-lexical-editor="true"], [data-hatch-composer-root] textarea, [data-hatch-composer-prehydration-input], [data-hatch-composer-root] [contenteditable="true"]',
  stopButton: '[data-testid="hatch-composer-stop-button"]',
  actionSlot: '[data-hatch-composer-action-slot]',
  fileInput: '[data-hatch-composer-root] input[type="file"]',
  attachButton: '[data-hatch-composer-root] button[aria-label="Attach file"]',
  message: '[data-message-item]',
  threadRow: '[data-testid="hatch-thread-row"]',
  assistant: '[data-message-item][data-message-role="assistant"]',
  user: '[data-message-item][data-message-role="user"]',
  errorNotice: '[data-testid="assistant-response-error-notice"]',
  approvalStack: '[data-hatch-composer-approval-stack]',
}

const APP_URL = process.env.MUSE_URL || 'https://muse.ai/'
const PROFILE_DIR =
  process.env.MUSE_PROFILE_DIR || path.join(__dirname, '.muse-profile')
const CHANNEL = process.env.MUSE_CHANNEL || 'chrome'
const LAUNCH_TIMEOUT = Number(process.env.MUSE_LAUNCH_TIMEOUT_MS || 60000)
// Headless runs copy the logged-in persistent profile to this throwaway dir,
// so we never lock `.muse-profile` and can run several instances at once.
// Muse keeps its device session in profile IndexedDB + localStorage, so we
// need the real profile state — not just cookies.
const HEADLESS_PROFILE = process.env.MUSE_HEADLESS_PROFILE || path.join(__dirname, '.muse-headless-profile')
// Cross-process send lock: Muse has one Main chat per account, so concurrent
// senders (other MCP processes, or your own Muse tab) would otherwise cross
// replies. Held for the duration of a send, reclaimed if the holder dies.
const LOCK_DIR = process.env.MUSE_SEND_LOCK || path.join(__dirname, '.muse-send.lock')
const LOCK_TTL_MS = Number(process.env.MUSE_SEND_LOCK_TTL_MS || 600000)
// Streaming: only surface text that has been stable this long, so we never emit
// a mid-generation "skeleton" that Muse later rewrites (which would duplicate in
// an append-only SSE stream).
const STREAM_QUIET_MS = Number(process.env.MUSE_STREAM_QUIET_MS || 600)

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

class MuseDriver {
  constructor() {
    this.ctx = null
    this.page = null
    this.browser = null
    this.lastError = null
    this._queue = Promise.resolve()
    this._headlessActual = false
    this._headlessStamp = 0
  }

  /** Serialize browser actions (one window = one action at a time). */
  _serial(fn) {
    const run = this._queue.then(fn, fn)
    this._queue = run.then(() => {}, () => {})
    return run
  }

  /**
   * Cross-process lock around a send.
   *
   * `_serial` only serializes *this* process, but Muse is one server-side Main
   * chat per account: a second Muse-Chat-MCP process (or a real browser tab) can
   * append to the same thread, and whoever reads the DOM last would otherwise
   * get the other party's reply. Lock the send window across processes with an
   * atomic directory create; stale locks are reclaimed after LOCK_TTL_MS.
   */
  async _withSendLock(fn) {
    const deadline = Date.now() + 120000
    while (!this._acquireLock()) {
      if (Date.now() > deadline) break // don't hang forever on a stale holder
      await sleep(500)
    }
    try {
      return await fn()
    } finally {
      this._releaseLock()
    }
  }

  _acquireLock() {
    try {
      fs.mkdirSync(LOCK_DIR) // atomic: succeeds only if we created it
      try {
        fs.writeFileSync(path.join(LOCK_DIR, 'owner.json'), JSON.stringify({ pid: process.pid, at: Date.now() }))
      } catch { /* best effort */ }
      this._holdsLock = true
      return true
    } catch (e) {
      // Already held — reclaim if the holder died or went stale.
      try {
        const st = fs.statSync(LOCK_DIR).mtimeMs
        let owner = null
        try { owner = JSON.parse(fs.readFileSync(path.join(LOCK_DIR, 'owner.json'), 'utf8')) } catch { /* ignore */ }
        const alive = owner && owner.pid ? (() => { try { process.kill(owner.pid, 0); return true } catch { return false } })() : false
        if (!alive || Date.now() - st > LOCK_TTL_MS) {
          fs.rmSync(LOCK_DIR, { recursive: true, force: true })
          return this._acquireLock()
        }
      } catch { /* ignore */ }
      return false
    }
  }

  _releaseLock() {
    if (!this._holdsLock) return
    try { fs.rmSync(LOCK_DIR, { recursive: true, force: true }) } catch { /* ignore */ }
    this._holdsLock = false
  }

  isRunning() {
    return !!(this.ctx && this.page && !this.page.isClosed())
  }

  /**
   * Snapshot the logged-in persistent profile into the throwaway headless dir.
   * Muse keeps its device session in profile IndexedDB + localStorage (cookies
   * alone are rejected with `401 hatchAdmissionInvalidated`), so headless needs
   * a full copy. Copying also means `.muse-profile` is never locked, so several
   * headless instances can run concurrently.
   */
  _cloneProfile() {
    try {
      if (!fs.existsSync(PROFILE_DIR)) return false
      fs.rmSync(HEADLESS_PROFILE, { recursive: true, force: true })
      fs.cpSync(PROFILE_DIR, HEADLESS_PROFILE, { recursive: true })
      return true
    } catch (e) {
      this.lastError = `could not clone profile: ${String((e && e.message) || e)}`
      return false
    }
  }

  /** Newest mtime under the profile, or 0 if it is missing. */
  _profileStamp() {
    let newest = 0
    const walk = (dir, depth) => {
      if (depth > 6) return
      let entries
      try { entries = fs.readdirSync(dir, { withFileTypes: true }) } catch { return }
      for (const e of entries) {
        if (e.name === 'SingletonLock' || e.name === 'SingletonSocket' || e.name === 'SingletonCookie') continue
        const full = path.join(dir, e.name)
        if (e.isDirectory()) { walk(full, depth + 1); continue }
        try { const m = fs.statSync(full).mtimeMs; if (m > newest) newest = m } catch { /* ignore */ }
      }
    }
    walk(PROFILE_DIR, 0)
    return newest
  }

  async launch({ headed = false, profile = null } = {}) {
    if (this.isRunning()) return this.page
    const { chromium } = await import('playwright-core')

    // Headed only for the interactive login (or an explicit MUSE_HEADLESS=0);
    // every other run is headless so no window pops up.
    const useHeadless = !headed && process.env.MUSE_HEADLESS !== '0'
    const persistDir = profile || (useHeadless ? HEADLESS_PROFILE : PROFILE_DIR)
    // Headless needs the real profile state (IndexedDB + localStorage), so
    // snapshot the logged-in profile into a throwaway dir first. Only re-copy
    // when the source changed (it is ~170 MB).
    if (useHeadless && !profile) {
      const stamp = this._profileStamp()
      if (!fs.existsSync(HEADLESS_PROFILE) || stamp > this._headlessStamp) this._cloneProfile()
      this._headlessStamp = stamp
    }

    const launchPersistent = (profileDir, opts = {}) =>
      chromium.launchPersistentContext(profileDir, {
        channel: CHANNEL,
        headless: useHeadless,
        viewport: { width: 1366, height: 900 },
        acceptDownloads: false,
        ignoreDefaultArgs: ['--enable-automation'],
        ...opts,
        args: [
          ...(opts.args || []),
          '--no-first-run',
          '--no-default-browser-check',
          '--disable-blink-features=AutomationControlled',
          '--disable-features=Translate,OptimizationGuideModelDownloading',
        ],
      })
    const attachCDP = async (url) => {
      this.browser = await chromium.connectOverCDP(url)
      this.ctx = this.browser.contexts()[0] || (await this.browser.newContext())
    }

    // Explicit CDP attach (user-managed browser). Never owned by us.
    if (process.env.MUSE_CDP) {
      try {
        await attachCDP(process.env.MUSE_CDP)
      } catch (e) {
        this.browser = null
        this.ctx = null
        this.ctx = await launchPersistent(persistDir)
      }
    }
    // Headless: dedicated throwaway profile so we never touch / lock .muse-profile.
    else if (useHeadless) {
      this._headlessActual = true
      this.ctx = await launchPersistent(HEADLESS_PROFILE)
    }
    // Headed (first-run login, or MUSE_HEADLESS=0): use the persistent profile.
    else {
      try {
        this.ctx = await launchPersistent(PROFILE_DIR)
      } catch (e) {
        const msg = String((e && e.message) || e)
        if (!/singleton|lock|profile|already running|browser is already/i.test(msg)) throw e
        try {
          await attachCDP('http://127.0.0.1:9222')
        } catch {
          throw new Error(
            `Could not open the Muse Chrome profile (${PROFILE_DIR}): it is locked by ` +
              `another Chrome window, and no debugger is listening on 127.0.0.1:9222. ` +
              `Close the Chrome window using this profile, or restart it with ` +
              `--remote-debugging-port=9222 and set MUSE_CDP=http://127.0.0.1:9222.`,
          )
        }
      }
    }

    this.ctx.on('close', () => {
      this.ctx = null
      this.page = null
      this.browser = null
    })
    const pages = this.ctx.pages()
    this.page = pages.find((p) => p.url().includes('muse.ai')) || pages[0] || (await this.ctx.newPage())
    this.page.setDefaultTimeout(LAUNCH_TIMEOUT)
    await this.gotoApp()
    return this.page
  }

  async gotoApp() {
    const p = await this.requirePage()
    if (!p.url().startsWith('https://muse.ai')) {
      await p.goto(APP_URL, { waitUntil: 'domcontentloaded', timeout: LAUNCH_TIMEOUT })
    }
    return p
  }

  async requirePage() {
    if (!this.isRunning()) await this.launch()
    return this.page
  }

  /** Cookie-based auth probe performed from inside the page origin. */
  async checkAuth() {
    const p = await this.requirePage()
    try {
      const r = await p.evaluate(async () => {
        try {
          const res = await fetch('/api/auth/check', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: '{}',
            credentials: 'same-origin',
          })
          const j = await res.json().catch(() => null)
          return { status: res.status, ok: !!(j && j.ok), viewerId: (j && j.viewer_id) || null }
        } catch (e) {
          return { status: 0, ok: false, error: String(e) }
        }
      })
      return r
    } catch (e) {
      return { status: 0, ok: false, error: String(e) }
    }
  }

  async hasComposer() {
    const p = await this.requirePage()
    try {
      await p.locator(SELECTORS.editor).first().waitFor({ state: 'visible', timeout: 8000 })
      return true
    } catch {
      return false
    }
  }

  async status() {
    const running = this.isRunning()
    const url = running ? this.page.url() : null
    const headless = this._headlessActual
    const base = { profileDir: PROFILE_DIR, headless, headlessProfileDir: HEADLESS_PROFILE }
    if (!running) {
      return { browserRunning: false, url: null, loggedIn: false, composerReady: false, ...base }
    }
    const auth = await this.checkAuth()
    const composerReady = await this.hasComposer()
    return {
      browserRunning: true,
      url,
      loggedIn: auth.ok,
      viewerId: auth.viewerId || null,
      composerReady,
      ...base,
    }
  }

  /** Open the app and, if needed, wait for the user to complete Meta login. */
  async login(timeoutMs = 300000) {
    await this.launch({ headed: true }) // re-login must pop a visible window
    await this.gotoApp()
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
      const auth = await this.checkAuth()
      if (auth.ok) return { loggedIn: true, viewerId: auth.viewerId || null }
      await sleep(2000)
    }
    return { loggedIn: false, hint: 'Complete the Meta sign-in in the opened Chrome window, then call muse_login again or muse_status.' }
  }

  /**
   * Refresh the throwaway headless profile from the logged-in one, so the next
   * headless run picks up the current session. No-op while the login window is
   * still open (the profile is locked then).
   */
  async syncHeadlessProfile() {
    if (!fs.existsSync(PROFILE_DIR)) return { ok: false, reason: 'no profile' }
    try {
      fs.rmSync(HEADLESS_PROFILE, { recursive: true, force: true })
      fs.cpSync(PROFILE_DIR, HEADLESS_PROFILE, { recursive: true })
      this._headlessStamp = this._profileStamp()
      return { ok: true, dir: HEADLESS_PROFILE }
    } catch (e) {
      return { ok: false, reason: String((e && e.message) || e) }
    }
  }

  async _newChat() {
    const p = await this.requirePage()
    await this.gotoApp()
    // Prefer the app's own "New side chat" control (reliable); fall back to the home composer.
    try {
      const btn = p.getByRole('button', { name: /new side chat/i })
      if (await btn.count()) {
        await btn.first().click({ timeout: 5000 })
        await sleep(1200)
        await this.waitForComposer()
        return { ok: true, url: p.url() }
      }
    } catch { /* fall through */ }
    await p.goto(APP_URL, { waitUntil: 'domcontentloaded', timeout: LAUNCH_TIMEOUT })
    await this.waitForComposer()
    return { ok: true, url: p.url() }
  }

  async newChat() {
    return this._serial(() => this._newChat())
  }

  /**
   * Normalize attachment entries into Playwright file payloads.
   * Accepts: "C:\\path\\img.png" | { path } | { url } (http/https/data:) |
   *          { name, mimeType, buffer } (Buffer or base64 string).
   */
  async _toFilePayloads(files) {
    const out = []
    for (const f of files || []) {
      if (!f) continue
      let e = f
      if (typeof e === 'string') e = /^(https?:|data:)/i.test(e) ? { url: e } : { path: e }

      if (e.buffer) {
        const buf = Buffer.isBuffer(e.buffer) ? e.buffer : Buffer.from(e.buffer, 'base64')
        out.push({ name: e.name || 'file', mimeType: e.mimeType || 'application/octet-stream', buffer: buf })
        continue
      }
      if (e.url && /^data:/i.test(e.url)) {
        const m = e.url.match(/^data:([^;,]*)(;base64)?,(.*)$/s)
        if (m) {
          const buf = Buffer.from(m[3], m[2] ? 'base64' : 'utf8')
          out.push({ name: e.name || `attachment`, mimeType: m[1] || e.mimeType || 'application/octet-stream', buffer: buf })
          continue
        }
      }
      if (e.url && /^file:\/\//i.test(e.url)) { out.push(fileURLToPath(e.url)); continue }
      if (e.url && /^https?:\/\//i.test(e.url)) {
        const res = await fetch(e.url)
        if (!res.ok) throw new Error(`failed to fetch attachment ${e.url}: ${res.status}`)
        const buf = Buffer.from(await res.arrayBuffer())
        let name = e.name
        if (!name) { try { name = decodeURIComponent(new URL(e.url).pathname.split('/').pop()) || 'attachment' } catch { name = 'attachment' } }
        out.push({ name, mimeType: res.headers.get('content-type') || e.mimeType || 'application/octet-stream', buffer: buf })
        continue
      }
      if (e.url) { out.push(e.url); continue } // bare local path passed via `url`
      if (e.path) out.push(e.path)
    }
    return out
  }

  /** Attach files/images/videos to the composer (no send). */
  async attachFiles(files) {
    return this._serial(() => this._attachFiles(files))
  }

  async _attachFiles(files) {
    const payloads = await this._toFilePayloads(files)
    if (!payloads.length) return { ok: true, count: 0 }
    const p = await this.requirePage()
    await this.gotoApp()
    await this.waitForComposer()
    await p.locator(SELECTORS.fileInput).first().setInputFiles(payloads)
    await sleep(600) // let the app register the attachment(s)
    return { ok: true, count: payloads.length }
  }

  async waitForComposer(timeoutMs = 90000) {
    const p = await this.requirePage()
    await p.locator(SELECTORS.editor).first().waitFor({ state: 'visible', timeout: timeoutMs })
    // wait until not busy (aria-busy on composer root)
    const root = p.locator(SELECTORS.composerRoot).first()
    try {
      await root.waitFor({ state: 'visible', timeout: 10000 })
      const start = Date.now()
      while (Date.now() - start < 15000) {
        const busy = await root.getAttribute('aria-busy')
        if (busy !== 'true') break
        await sleep(250)
      }
    } catch {
      /* composer root optional */
    }
  }

  async composerText() {
    const p = await this.requirePage()
    try {
      const el = p.locator(SELECTORS.editor).first()
      const tag = await el.evaluate((e) => e.tagName)
      if (tag === 'TEXTAREA' || tag === 'INPUT') return await el.inputValue()
      return await el.innerText()
    } catch {
      return ''
    }
  }

  /**
   * Send a prompt and wait for the assistant reply to finish streaming.
   * @returns {Promise<{reply:string, messages:string[], threadUrl:string, elapsedMs:number, error?:string, timedOut?:boolean, needsApproval?:boolean}>}
   */
  async _run(prompt, { timeoutMs = 240000, newThread = false, onDelta, files, chat } = {}) {
    const hasFiles = Array.isArray(files) && files.length > 0
    if ((!prompt || !prompt.trim()) && !hasFiles) throw new Error('prompt is empty')
    const p = await this.requirePage()
    if (newThread) await this._newChat()
    else if (chat !== undefined && chat !== null && chat !== '') await this._openChat(chat)
    else await this.gotoApp()
    await this.waitForComposer()

    // Clear any transient error notice.
    this.lastError = null

    // Attach images/videos/files (if any) before typing the prompt.
    if (hasFiles) {
      const payloads = await this._toFilePayloads(files)
      if (payloads.length) {
        await p.locator(SELECTORS.fileInput).first().setInputFiles(payloads)
        await sleep(800) // let the app ingest + preview the attachment(s)
      }
    }

    const before0 = await p.locator(SELECTORS.assistant).count()

    // Focus + fill the composer. insertText is O(1) for big prompts;
    // fall back to per-key typing if the editor ignores it.
    const editor = p.locator(SELECTORS.editor).first()
    await editor.click()
    await p.keyboard.press('Control+A').catch(() => {})
    await p.keyboard.press('Delete').catch(() => {})
    try { if (prompt) await p.keyboard.insertText(prompt) } catch { /* fall back below */ }
    await sleep(120)
    if (prompt && !(await this.composerText()).trim()) {
      await p.keyboard.type(prompt, { delay: 1 })
    }
    await sleep(150)

    const t0 = Date.now()
    await p.keyboard.press('Enter')

    // Confirm the message actually left the composer; else click the send action.
    let sent = false
    for (let i = 0; i < 10; i++) {
      await sleep(300)
      const txt = (await this.composerText()).trim()
      const stop = await p.locator(SELECTORS.stopButton).count()
      if (txt.length === 0 || stop > 0) { sent = true; break }
    }
    if (!sent) {
      const slot = p.locator(`${SELECTORS.actionSlot} button`).last()
      if (await slot.count()) { await slot.click({ timeout: 5000 }).catch(() => {}) }
      await p.keyboard.press('Control+Enter').catch(() => {})
    }

    // Confirm OUR message actually landed. The transcript renders in batches a few
    // seconds after send (nothing is in the DOM before that), and another Muse
    // session on this account can append messages while we wait — so we anchor
    // on our own user bubble before trusting any assistant reply.
    let userSent = !prompt
    let before = before0
    if (prompt) {
      const anchor = Date.now() + 30000
      const want = prompt.replace(/\s+/g, ' ').trim().slice(0, 40)
      const norm = (s) => (s || '').replace(/^(You:|User message:|Assistant message:)\s*/i, '').replace(/\s+/g, ' ').trim()
      while (Date.now() < anchor) {
        const users = p.locator(SELECTORS.user)
        if (await users.count()) {
          // Our turn is the newest user bubble (Muse shows it before replying).
          const mine = await users.last().innerText().catch(() => '')
          if (norm(mine).slice(0, 40) === want) {
            userSent = true
            // Anchor past any assistant reply that landed before ours.
            before = Math.max(before0, (await p.locator(SELECTORS.assistant).count()) - 1)
            break
          }
        }
        await sleep(400)
      }
    }

    // Wait for the reply to complete.
    const deadline = t0 + timeoutMs
    let started = false
    let lastText = ''
    let committed = ''
    let stableSince = Date.now()
    let timedOut = false

    while (Date.now() < deadline) {
      const stop = await p.locator(SELECTORS.stopButton).count()
      if (stop > 0) started = true
      const n = await p.locator(SELECTORS.assistant).count()
      if (n > before) {
        const txt = await p.locator(SELECTORS.assistant).last().innerText().catch(() => '')
        if (txt !== lastText) {
          lastText = txt
          stableSince = Date.now()
        }
        const idle = Date.now() - stableSince
        // Commit only stable + monotonic growth (never a re-written draft).
        if (onDelta && txt && txt !== committed && txt.startsWith(committed) && idle >= STREAM_QUIET_MS) {
          committed = txt
          try { onDelta(committed) } catch { /* ignore */ }
        }
        if (stop === 0 && ((started && idle > 1200) || (!started && idle > 2500))) break
      }
      if (await p.locator(SELECTORS.errorNotice).count()) {
        this.lastError = await p.locator(SELECTORS.errorNotice).first().innerText().catch(() => 'assistant error')
      }
      await sleep(300)
    }
    if (Date.now() >= deadline) timedOut = true

    const items = await p.locator(SELECTORS.assistant).evaluateAll(
      (els, start) => els.slice(start).map((e) => (e.innerText || '').trim()).filter(Boolean),
      before,
    )
    const reply = (items.length ? items[items.length - 1] : lastText).trim()
    const needsApproval = (await p.locator(SELECTORS.approvalStack).count()) > 0

    // Flush any remainder that arrived after the last stable commit.
    if (onDelta && reply && reply !== committed && reply.startsWith(committed)) {
      try { onDelta(reply) } catch { /* ignore */ }
    }

    return {
      reply,
      messages: items,
      threadUrl: p.url(),
      elapsedMs: Date.now() - t0,
      ...(this.lastError ? { error: this.lastError } : {}),
      ...(timedOut ? { timedOut: true } : {}),
      ...(prompt && !userSent ? { sendUnconfirmed: true } : {}),
      ...(needsApproval ? { needsApproval: true } : {}),
    }
  }

  /** Send a prompt and wait for the full assistant reply. */
  async chat(prompt, opts = {}) {
    return this._serial(() => this._withSendLock(() => this._run(prompt, opts)))
  }

  /**
   * Same as chat(), but streams incremental text.
   * @param {(fullText:string)=>void} opts.onDelta called with the cumulative reply text
   */
  async chatStream(prompt, opts = {}) {
    return this._serial(() => this._withSendLock(() => this._run(prompt, opts)))
  }

  async readLast() {
    return this._serial(() => this._readLast())
  }

  async _readLast() {
    const p = await this.requirePage()
    await this.gotoApp()
    const n = await p.locator(SELECTORS.assistant).count()
    if (!n) return { reply: '', messages: [], threadUrl: p.url() }
    const reply = await p.locator(SELECTORS.assistant).last().innerText().catch(() => '')
    return { reply: reply.trim(), messages: [reply.trim()], threadUrl: p.url() }
  }

  /** List the chats shown in the Muse sidebar (Main chat, Channels, Side chats). */
  async listChats(query) {
    return this._serial(() => this._listChats(query))
  }

  async _listChats(query) {
    const p = await this.requirePage()
    await this.gotoApp()
    await sleep(400)
    let chats = await p.locator(SELECTORS.threadRow).evaluateAll((els) =>
      els.map((el) => ({
        title: (el.innerText || '').replace(/\s+/g, ' ').replace(/\s*More thread actions\s*$/i, '').trim(),
        active: el.getAttribute('aria-current') === 'page' || el.getAttribute('aria-selected') === 'true',
      })).filter((c) => c.title),
    )
    if (query) {
      const q = String(query).toLowerCase()
      chats = chats.filter((c) => c.title.toLowerCase().includes(q))
    }
    return { chats, threadUrl: p.url() }
  }

  /**
   * Open a chat. `target` can be:
   *   - a number         -> chat index from listChats()
   *   - a title/name     -> matched (substring, case-insensitive) against the sidebar
   *   - a thread URL or bare thread id (uuid) -> navigated to directly
   *   - null/undefined   -> the home / main chat
   */
  async openChat(target) {
    return this._serial(() => this._openChat(target))
  }

  async _openChat(target) {
    const p = await this.requirePage()
    if (target === null || target === undefined || target === '') {
      await this.gotoApp()
    } else if (typeof target === 'number') {
      await this.gotoApp()
      const row = p.locator(SELECTORS.threadRow).nth(target)
      if (!(await row.count())) throw new Error(`chat index ${target} out of range`)
      await row.click()
    } else {
      const s = String(target).trim()
      if (/^https?:\/\//i.test(s)) {
        await p.goto(s, { waitUntil: 'domcontentloaded', timeout: LAUNCH_TIMEOUT })
      } else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) {
        await p.goto(`https://muse.ai/thread/${s}`, { waitUntil: 'domcontentloaded', timeout: LAUNCH_TIMEOUT })
      } else {
        await this.gotoApp()
        const row = p.locator(SELECTORS.threadRow, { hasText: s }).first()
        if (!(await row.count())) throw new Error(`no chat matching "${s}"`)
        await row.click()
      }
    }
    await sleep(1200)
    await this.waitForComposer()
    return { ok: true, url: p.url() }
  }

  /** Read messages of the currently open chat. */
  async readChat(max = 100) {
    return this._serial(() => this._readChat(max))
  }

  async _readChat(max = 100) {
    const p = await this.requirePage()
    const all = await p.locator(SELECTORS.message).evaluateAll((els) =>
      els
        .map((el) => {
          const text = (el.innerText || '').replace(/^(You:|User message:|Assistant message:)\s*/i, '').trim()
          const media = [...new Set(
            [...el.querySelectorAll('a[href], img[src], video[src], source[src]')]
              .map((n) => n.href || n.currentSrc || n.src || (n.getAttribute && n.getAttribute('src')))
              .filter((u) => u && /^(https?:|blob:)/i.test(u)),
          )]
          return { role: el.getAttribute('data-message-role') || '', text, ...(media.length ? { media } : {}) }
        })
        .filter((m) => m.text || (m.media && m.media.length)),
    )
    return { messages: all.slice(-max), count: all.length, threadUrl: p.url() }
  }

  /** Extract media links (images/videos/attachments) from a chat's messages, optionally downloading. */
  async chatMedia(chat, opts = {}) {
    return this._serial(() => this._chatMedia(chat, opts))
  }

  async _chatMedia(chat, { download = false, dir } = {}) {
    const p = await this.requirePage()
    if (chat !== undefined && chat !== null && chat !== '') await this._openChat(chat)
    else await this.gotoApp()
    const items = await p.locator(SELECTORS.message).evaluateAll((els) =>
      els
        .map((el, index) => {
          const role = el.getAttribute('data-message-role') || ''
          const urls = [...new Set(
            [...el.querySelectorAll('a[href], img[src], video[src], source[src]')]
              .map((n) => n.href || n.currentSrc || n.src || (n.getAttribute && n.getAttribute('src')))
              .filter((u) => u && /^(https?:|blob:)/i.test(u)),
          )]
          const text = (el.innerText || '').replace(/^(You:|User message:|Assistant message:)\s*/i, '').replace(/\s+/g, ' ').trim()
          return { index, role, text: text.slice(0, 120), urls }
        })
        .filter((m) => m.urls.length),
    )
    const all = [...new Set(items.flatMap((m) => m.urls))]
    const result = { items, urls: all, count: all.length, threadUrl: p.url() }
    if (download && all.length) result.downloads = await this._downloadMedia(all, dir)
    return result
  }

  async downloadMedia(urls, dir) {
    return this._serial(() => this._downloadMedia(urls, dir))
  }

  async _downloadMedia(urls, dir) {
    const outDir = dir || path.join(__dirname, 'downloads')
    fs.mkdirSync(outDir, { recursive: true })
    const p = this.page
    const saved = []
    for (const u of urls) {
      try {
        let buf = null
        let mime = ''
        // Prefer fetching inside the page: handles blob: URLs and cookie-authed http.
        if (p && !p.isClosed()) {
          const r = await p.evaluate(async (url) => {
            try {
              const res = await fetch(url)
              const ab = await res.arrayBuffer()
              const bytes = new Uint8Array(ab)
              let s = ''
              const CH = 0x8000
              for (let i = 0; i < bytes.length; i += CH) s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH))
              return { ok: res.ok, status: res.status, mime: res.headers.get('content-type') || '', b64: btoa(s), len: bytes.length }
            } catch (e) { return { ok: false, error: String(e) } }
          }, u)
          if (r && r.ok && r.b64) { buf = Buffer.from(r.b64, 'base64'); mime = r.mime }
          else if (r && r.error) throw new Error(r.error)
        }
        if (!buf) {
          const res = await fetch(u)
          if (!res.ok) throw new Error(`HTTP ${res.status}`)
          buf = Buffer.from(await res.arrayBuffer())
          mime = res.headers.get('content-type') || ''
        }
        const ext = mime.includes('mp4') ? '.mp4' : mime.includes('webm') ? '.webm' : mime.includes('webp') ? '.webp'
          : mime.includes('png') ? '.png' : (mime.includes('jpeg') || mime.includes('jpg')) ? '.jpg' : mime.includes('gif') ? '.gif' : ''
        let name = 'media'
        try { name = decodeURIComponent(new URL(u).pathname.split('/').pop() || 'media') } catch { /* blob: -> uuid */ }
        if (!path.extname(name)) name += ext || '.bin'
        const dest = path.join(outDir, `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}-${name}`)
        fs.writeFileSync(dest, buf)
        saved.push({ url: u.startsWith('blob:') ? 'blob' : u, file: dest, bytes: buf.length, mime })
      } catch (e) {
        saved.push({ url: u.startsWith('blob:') ? 'blob' : u, error: String((e && e.message) || e) })
      }
    }
    return { dir: outDir, saved }
  }

  /** Diagnostic: dump transcript HTML so selectors can be re-verified. */
  async dumpDom(maxChars = 20000) {
    return this._serial(() => this._dumpDom(maxChars))
  }

  async _dumpDom(maxChars = 20000) {
    const p = await this.requirePage()
    await this.gotoApp()
    const info = await p.evaluate((sels) => {
      const pick = (s) => document.querySelector(s)
      const log = pick('[role="log"]')
      const first = pick('[data-message-item]')
      const container = log || (first && first.parentElement) || document.body
      return {
        url: location.href,
        title: document.title,
        counts: {
          messages: document.querySelectorAll(sels.message).length,
          assistant: document.querySelectorAll(sels.assistant).length,
          user: document.querySelectorAll(sels.user).length,
          editor: document.querySelectorAll(sels.editor).length,
        },
        hasApproval: !!document.querySelector(sels.approvalStack),
        html: container.outerHTML,
      }
    }, SELECTORS)
    return { ...info, html: (info.html || '').slice(0, maxChars) }
  }

  async close() {
    this._releaseLock()
    if (this.browser) {
      // CDP-attached: disconnect only, never kill the user's browser.
      await this.browser.close().catch(() => {})
      this.browser = null
      this.ctx = null
      this.page = null
      return { ok: true, disconnected: true }
    }
    if (this.ctx) {
      await this.ctx.close().catch(() => {})
      this.ctx = null
      this.page = null
    }
    return { ok: true }
  }
}

export const driver = new MuseDriver()
export default driver
