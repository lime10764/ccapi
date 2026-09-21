/**
 * 乐库音乐后端 · 零依赖单文件 Cloudflare Worker
 * ------------------------------------------------------------------
 * 部署（手机也能操作）：
 *   1. Cloudflare 控制台 → Workers & Pages → 创建 Worker
 *   2. 把本文件【全部内容】粘贴进在线编辑器，点部署
 *   3. Worker → 设置 → 绑定 → KV 命名空间，变量名必须填 MUSIC_KV
 *      （头像可选 R2 绑定，变量名 AVATAR_BUCKET；不绑也能用，头像自动存 KV）
 *   4. 管理后台：https://你的Worker域名/admin  初始密码 admin123（登录后请改）
 *
 * 接口契约与线上 App v4.7.x 完全一致：
 *   GET  /api/ping
 *   POST /api/auth/send-code        {email}
 *   POST /api/auth/verify           {email,code} -> {token}
 *   GET  /api/challenge/request     -> {nonce,type,question,ttl}
 *   POST /api/challenge/verify      {nonce,answer} -> {verifyToken,ttl}
 *   攻击模式拦截：403 {error,code:"VERIFY_REQUIRED"}，放行头 X-Verify-Token
 * 新增（资料/头像）：
 *   GET  /api/me                     Authorization: Bearer <用户token>
 *   POST /api/me/profile             {nickname,signature}
 *   POST /api/me/avatar              原始 image/webp 字节（≤200KB）-> {avatarUrl}
 *   GET  /avatar/:id
 */

const KV_BINDING = 'MUSIC_KV'
const VERSION = '4.13'
const R2_BINDING = 'AVATAR_BUCKET'
const CODE_TTL = 300          // 验证码 5 分钟
const RESEND_COOLDOWN = 60    // 60 秒重发限制
const TOKEN_TTL = 30 * 86400    // 用户 token 30 天
const VERIFY_TTL = 1800       // 人机验证 30 分钟
const AVATAR_MAX = 200 * 1024

const DEFAULT_SETTINGS = {
  adminPassword: 'admin123',
  email: {
    provider: 'dev',          // dev | smtp（原生直连，推荐） | resend | mailer
    fromName: '乐库音乐',
    fromEmail: '',
    resendKey: '',
    mailerUrl: '',
    mailerSecret: '',
    smtp: { host: '', port: '465', secure: true, user: '', pass: '', senderName: '乐库音乐' }
  },
  thresholds: {
    globalPerSec: 20, ipPer10s: 60, uaPer10s: 120,
    loginFailRate: 0.5, loginMinSamples: 10,
    challengeFailRate: 0.6, challengeMinSamples: 10,
    cooldownSec: 60
  }
}

const json = (obj, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...extraHeaders }
  })
const err = (msg, status = 400, extra) => json({ error: msg, ...extra }, status)
const rand = (n = 16) => {
  const a = new Uint8Array(n)
  crypto.getRandomValues(a)
  return [...a].map(x => x.toString(16).padStart(2, '0')).join('')
}
const EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/

async function getSettings(env) {
  const s = JSON.parse((await env[KV_BINDING].get('settings')) || '{}')
  return {
    ...DEFAULT_SETTINGS,
    ...s,
    email: { ...DEFAULT_SETTINGS.email, ...(s.email || {}), smtp: { ...DEFAULT_SETTINGS.email.smtp, ...((s.email || {}).smtp || {}) } },
    thresholds: { ...DEFAULT_SETTINGS.thresholds, ...(s.thresholds || {}) }
  }
}
const saveSettings = (env, s) => env[KV_BINDING].put('settings', JSON.stringify(s))

async function pushLog(env, type, text) {
  try {
    const key = type === 'attack' ? 'log:attack' : 'log:ops'
    const arr = JSON.parse((await env[KV_BINDING].get(key)) || '[]')
    arr.unshift({ ts: Date.now(), text })
    await env[KV_BINDING].put(key, JSON.stringify(arr.slice(0, 50)))
  } catch (_) { /* 日志失败不影响主流程 */ }
}

// ============================ 邮件发送 ============================

function codeEmail(code, ttlMin) {
  const row = n => `<td style="width:54px;height:64px;margin:0 6px;border-radius:14px;background:rgba(255,77,109,.12);border:1px solid rgba(255,77,109,.35);color:#FF4D6D;font-size:30px;font-weight:700;text-align:center;line-height:64px;font-family:ui-sans-serif,system-ui">${n}</td>`
  return {
    subject: '乐库音乐 · 登录验证码',
    html: `<!doctype html><div style="background:#0b0e14;padding:32px 16px;font-family:ui-sans-serif,system-ui">
      <div style="max-width:420px;margin:0 auto;background:#141821;border:1px solid rgba(255,255,255,.08);border-radius:24px;padding:32px;text-align:center">
      <div style="color:#fff;font-size:20px;font-weight:700">乐库音乐</div>
      <div style="color:#9aa4b5;font-size:14px;margin:10px 0 26px">你正在登录 / 注册，验证码是</div>
      <table style="margin:0 auto;border-collapse:separate;border-spacing:0"><tr>${[...code].map(row).join('')}</tr></table>
      <div style="color:#9aa4b5;font-size:13px;margin-top:26px">验证码 ${ttlMin} 分钟内有效，请勿泄露给他人</div>
      <div style="color:#5b6472;font-size:12px;margin-top:14px">非本人操作请忽略此邮件</div>
      </div></div>`
  }
}

// Worker 原生 SMTP 发信（cloudflare:sockets，无需额外服务器）
// 465 = 隐式 TLS；587/25 = STARTTLS。QQ smtp.qq.com:465、163 smtp.163.com:465
async function sendViaSmtp(cfg, { to, subject, html, text }) {
  const { connect } = await import('cloudflare:sockets')
  const host = String(cfg.host || '').trim()
  const port = Number(cfg.port) || 465
  const user = String(cfg.user || '').trim()
  const pass = String(cfg.pass || '')
  if (!host || !user || !pass) throw new Error('SMTP 配置不完整（服务器/账号/授权码必填）')
  const implicitTls = port === 465

  let socket = connect(`${host}:${port}`, { secureTransport: implicitTls ? 'on' : 'off' })
  const enc = new TextEncoder(), dec = new TextDecoder()
  let reader = socket.readable.getReader(), writer = socket.writable.getWriter()
  const reset = s => { reader = s.readable.getReader(); writer = s.writable.getWriter() }

  const readReply = () => new Promise((resolve, reject) => {
    let buf = ''
    const timer = setTimeout(() => reject(new Error('SMTP 读取超时（' + host + '）')), 15000)
    const pump = async () => {
      try {
        const { value, done } = await reader.read()
        if (value) buf += dec.decode(value, { stream: true })
        const lines = buf.split('\r\n').filter(Boolean)
        const last = lines[lines.length - 1]
        if (last && /^\d{3}\s/.test(last)) { clearTimeout(timer); resolve(lines); return }
        if (done) { clearTimeout(timer); reject(new Error('SMTP 连接被关闭：' + buf)); return }
        pump()
      } catch (e) { clearTimeout(timer); reject(e) }
    }
    pump()
  })
  const cmd = async (line, ok) => {
    await writer.write(enc.encode(line + '\r\n'))
    const lines = await readReply()
    const code = Number(lines[lines.length - 1].slice(0, 3))
    if (ok && !ok.includes(code)) throw new Error('SMTP 命令失败：' + lines.join(' / '))
    return lines
  }

  try {
    await readReply() // 220 问候
    await cmd('EHLO leku-music', [250])
    if (!implicitTls) {
      await cmd('STARTTLS', [220])
      socket = socket.startTls()
      reset(socket)
      await cmd('EHLO leku-music', [250])
    }
    await cmd('AUTH LOGIN', [334])
    await cmd(btoa(user), [334])
    await cmd(btoa(pass), [235])
    await cmd(`MAIL FROM:<${user}>`, [250])
    await cmd(`RCPT TO:<${to}>`, [250, 251])
    await cmd('DATA', [354])

    const b64utf8 = s => btoa(String.fromCharCode(...new TextEncoder().encode(s)))
    // RFC 2045：base64 正文每行最多 76 字符，否则触发 RFC 5321 的 998 字节行长限制
    const b64wrap = s => b64utf8(s).match(/.{1,76}/g).join('\r\n')
    const h = s => '=?UTF-8?B?' + b64utf8(s) + '?='
    const body = [
      `From: ${h(cfg.senderName || '乐库音乐')} <${user}>`,
      `To: ${to}`,
      `Subject: ${h(subject)}`,
      'MIME-Version: 1.0',
      'Date: ' + new Date().toUTCString(),
      'Content-Type: multipart/alternative; boundary="lk-boundary"',
      '',
      '--lk-boundary',
      'Content-Type: text/plain; charset=utf-8',
      'Content-Transfer-Encoding: base64', '',
      b64wrap(text), '',
      '--lk-boundary',
      'Content-Type: text/html; charset=utf-8',
      'Content-Transfer-Encoding: base64', '',
      b64wrap(html),
      '--lk-boundary--',
      ''
    ].join('\r\n')
    await writer.write(enc.encode(body + '\r\n.\r\n'))
    const lines = await readReply()
    const code = Number(lines[lines.length - 1].slice(0, 3))
    if (code !== 250) throw new Error('SMTP 投递失败：' + lines.join(' / '))
    try { await cmd('QUIT', [221]) } catch (_) {}
  } finally {
    try { await writer.close() } catch (_) {}
  }
}

async function sendEmail(env, to, code) {
  const s = await getSettings(env)
  const e = s.email
  const mail = codeEmail(code, Math.floor(CODE_TTL / 60))

  // 原生 SMTP 直连（QQ/163 授权码，465 SSL，无需额外服务器）
  if (e.provider === 'smtp' && e.smtp && e.smtp.host && e.smtp.user && e.smtp.pass) {
    await sendViaSmtp(e.smtp, {
      to, subject: mail.subject, html: mail.html,
      text: `你的乐库音乐验证码是 ${code}，${CODE_TTL / 60} 分钟内有效，非本人操作请忽略。`
    })
    return { channel: 'smtp' }
  }

  if (e.provider === 'resend' && e.resendKey && e.fromEmail) {
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { authorization: `Bearer ${e.resendKey}`, 'content-type': 'application/json' },
      body: JSON.stringify({ from: `${e.fromName || '乐库音乐'} <${e.fromEmail}>`, to, subject: mail.subject, html: mail.html })
    })
    if (!resp.ok) throw new Error('Resend 发信失败：' + (await resp.text()).slice(0, 200))
    return { channel: 'resend' }
  }

  if (e.provider === 'mailer' && e.mailerUrl) {
    const resp = await fetch(e.mailerUrl.replace(/\/$/, '') + '/internal/send-email', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-internal-secret': e.mailerSecret || '' },
      body: JSON.stringify({ to, subject: mail.subject, html: mail.html, text: `你的乐库音乐验证码是 ${code}，${CODE_TTL / 60} 分钟内有效。` })
    })
    if (!resp.ok) throw new Error('邮件服务发信失败：' + (await resp.text()).slice(0, 200))
    return { channel: 'mailer' }
  }

  // 开发模式：不真正发信，验证码进 KV，后台「概览」页可见，同时打印到 tail 日志
  const arr = JSON.parse((await env[KV_BINDING].get('devcodes')) || '[]')
  arr.unshift({ email: to, code, ts: Date.now() })
  await env[KV_BINDING].put('devcodes', JSON.stringify(arr.slice(0, 20)))
  console.log(`[dev-code] ${to} => ${code}`)
  return { channel: 'dev', devCode: code }
}

// ============================ 攻击模式检测 ============================

const A = { g: new Map(), ip: new Map(), ua: new Map(), auth: new Map(), lf: new Map(), cf: new Map(), cp: new Map(), lastFlush: 0 }
const b10 = () => Math.floor(Date.now() / 10000)
const b60 = () => Math.floor(Date.now() / 60000)
const b300 = () => Math.floor(Date.now() / 300000)
async function sha(s) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(s))
  return [...new Uint8Array(buf)].slice(0, 8).map(x => x.toString(16).padStart(2, '0')).join('')
}
function recordRequest(env, ctx, req) {
  const now = Date.now()
  A.g.set(b10(), (A.g.get(b10()) || 0) + 1)
  const ip = req.headers.get('CF-Connecting-IP') || 'unknown'
  const ua = (req.headers.get('user-agent') || 'unknown').slice(0, 200)
  ctx.waitUntil((async () => {
    const ik = `${await sha(ip)}:${b10()}`, uk = `${await sha(ua)}:${b10()}`
    A.ip.set(ik, (A.ip.get(ik) || 0) + 1)
    A.ua.set(uk, (A.ua.get(uk) || 0) + 1)
    if (now - A.lastFlush > 10000) { A.lastFlush = now; await flushMetrics(env) }
  })())
}
const recordAuth = fail => { const b = b60(); A.auth.set(b, (A.auth.get(b) || 0) + 1); if (fail) A.lf.set(b, (A.lf.get(b) || 0) + 1) }
const recordChallenge = pass => { const b = b300(); A.cp.set(b, (A.cp.get(b) || 0) + (pass ? 1 : 0)); if (!pass) A.cf.set(b, (A.cf.get(b) || 0) + 1) }
async function kvIncr(env, k, d, ttl) { const v = (parseInt((await env[KV_BINDING].get(k)) || '0', 10) || 0) + d; await env[KV_BINDING].put(k, String(v), { expirationTtl: ttl }) }
async function mergeHot(env, key, map, ttl) {
  const hot = JSON.parse((await env[KV_BINDING].get(key)) || '{}')
  for (const [k, v] of map) hot[k] = (hot[k] || 0) + v
  const top = Object.fromEntries(Object.entries(hot).sort((x, y) => y[1] - x[1]).slice(0, 20))
  await env[KV_BINDING].put(key, JSON.stringify(top), { expirationTtl: ttl })
}
async function flushMetrics(env) {
  try {
    const tasks = []
    for (const [b, n] of A.g) { tasks.push(kvIncr(env, `m:g:${b}`, n, 40)); }
    A.g.clear()
    for (const [b, n] of A.auth) tasks.push(kvIncr(env, `m:auth:${b}`, n, 180))
    A.auth.clear()
    for (const [b, n] of A.lf) tasks.push(kvIncr(env, `m:lf:${b}`, n, 180))
    A.lf.clear()
    for (const [b, n] of A.cf) tasks.push(kvIncr(env, `m:cf:${b}`, n, 700))
    A.cf.clear()
    for (const [b, n] of A.cp) tasks.push(kvIncr(env, `m:cp:${b}`, n, 700))
    A.cp.clear()
    const ipCur = new Map(), uaCur = new Map()
    for (const [k, n] of A.ip) { const [id, b] = k.split(':'); if (b === String(b10())) ipCur.set(id, (ipCur.get(id) || 0) + n) }
    for (const [k, n] of A.ua) { const [id, b] = k.split(':'); if (b === String(b10())) uaCur.set(id, (uaCur.get(id) || 0) + n) }
    A.ip.clear(); A.ua.clear()
    if (ipCur.size) tasks.push(mergeHot(env, `m:hotip:${b10()}`, ipCur, 40))
    if (uaCur.size) tasks.push(mergeHot(env, `m:hotua:${b10()}`, uaCur, 40))
    await Promise.all(tasks)
  } catch (_) { /* KV 抖动忽略 */ }
}

let evalCache = { at: 0, state: null }
async function collectMetrics(env) {
  const g = parseInt((await env[KV_BINDING].get(`m:g:${b10()}`)) || '0', 10) || 0
  const hotIp = JSON.parse((await env[KV_BINDING].get(`m:hotip:${b10()}`)) || '{}')
  const hotUa = JSON.parse((await env[KV_BINDING].get(`m:hotua:${b10()}`)) || '{}')
  const auth60 = parseInt((await env[KV_BINDING].get(`m:auth:${b60()}`)) || '0', 10) || 0
  const lf60 = parseInt((await env[KV_BINDING].get(`m:lf:${b60()}`)) || '0', 10) || 0
  const cf = parseInt((await env[KV_BINDING].get(`m:cf:${b300()}`)) || '0', 10) || 0
  const cp = parseInt((await env[KV_BINDING].get(`m:cp:${b300()}`)) || '0', 10) || 0
  return {
    qps: +(g / 10).toFixed(1), global10s: g,
    maxIp10s: Math.max(0, ...Object.values(hotIp)),
    maxUa10s: Math.max(0, ...Object.values(hotUa)),
    auth60, loginFails60: lf60, loginFailRate: auth60 ? +(lf60 / auth60).toFixed(2) : 0,
    challenge300: cf + cp, challengeFailRate: cf + cp ? +(cf / (cf + cp)).toFixed(2) : 0
  }
}
function breachesOf(m, t) {
  const r = []
  if (m.global10s > t.globalPerSec * 10) r.push(`全局 QPS 超限（${m.qps}/s）`)
  if (m.maxIp10s > t.ipPer10s) r.push(`单 IP 请求过密（${m.maxIp10s}/10s）`)
  if (m.maxUa10s > t.uaPer10s) r.push(`单 UA 请求过密（${m.maxUa10s}/10s）`)
  if (m.auth60 >= t.loginMinSamples && m.loginFailRate > t.loginFailRate) r.push(`登录失败率异常（${(m.loginFailRate * 100) | 0}%）`)
  if (m.challenge300 >= t.challengeMinSamples && m.challengeFailRate > t.challengeFailRate) r.push(`人机验证失败率异常（${(m.challengeFailRate * 100) | 0}%）`)
  return r
}
async function evaluate(env, force = false) {
  const now = Date.now()
  if (!force && evalCache.at && now - evalCache.at < 3000 && evalCache.state) return evalCache.state
  const settings = await getSettings(env)
  const t = settings.thresholds
  const metrics = await collectMetrics(env)
  const breaches = breachesOf(metrics, t)
  const st = Object.assign({ on: false, manual: false, reasons: [], since: 0, calmSince: 0, mutedUntil: 0 },
    JSON.parse((await env[KV_BINDING].get('attack')) || '{}'))
  let changed = false
  const muted = !!st.mutedUntil && now < st.mutedUntil
  if (st.on && st.manual) { /* 人工开启只能人工解除 */ }
  else if (muted) {
    // 管理员刚手动解除：静默期内不允许自动重开，避免“关不掉”
    if (st.on) Object.assign(st, { on: false, reasons: [], since: 0 }); changed = true
  }
  else if (!st.on && breaches.length) {
    Object.assign(st, { on: true, manual: false, reasons: breaches, since: now, calmSince: 0, mutedUntil: 0 }); changed = true
    await pushLog(env, 'attack', '自动开启：' + breaches.join('；'))
  } else if (st.on && !st.manual) {
    if (breaches.length) { st.reasons = breaches; st.calmSince = 0 }
    else {
      if (!st.calmSince) st.calmSince = now
      if (now - st.calmSince >= t.cooldownSec * 1000) {
        Object.assign(st, { on: false, reasons: [], since: 0, calmSince: 0, mutedUntil: 0 }); changed = true
        await pushLog(env, 'attack', '流量恢复正常，自动解除防护')
      }
    }
  }
  if (changed) await env[KV_BINDING].put('attack', JSON.stringify(st))
  const out = {
    on: st.on, manual: st.manual, reasons: st.reasons, since: st.since,
    muted, muteLeft: muted ? Math.ceil((st.mutedUntil - now) / 1000) : 0,
    cooldownLeft: st.on && st.calmSince ? Math.max(0, t.cooldownSec - Math.floor((now - st.calmSince) / 1000)) : 0,
    metrics
  }
  evalCache = { at: now, state: out }
  return out
}
async function setManual(env, on) {
  const now = Date.now()
  const st = on
    ? { on: true, manual: true, reasons: ['管理员手动开启'], since: now, calmSince: 0, mutedUntil: 0 }
    : { on: false, manual: false, reasons: [], since: 0, calmSince: 0, mutedUntil: now + 10 * 60 * 1000 }
  await env[KV_BINDING].put('attack', JSON.stringify(st))
  await pushLog(env, 'attack', on ? '管理员手动开启防护' : '管理员手动解除防护（10 分钟内不自动重开）')
  evalCache.at = 0
  return evaluate(env, true)
}

// ============================ 业务辅助 ============================

async function getUser(env, email) {
  return JSON.parse((await env[KV_BINDING].get('user:' + email)) || 'null')
}
async function saveUser(env, u) { await env[KV_BINDING].put('user:' + u.email, JSON.stringify(u)) }
async function userByToken(env, req) {
  const auth = req.headers.get('authorization') || ''
  const tk = auth.startsWith('Bearer ') ? auth.slice(7) : ''
  if (!tk) return null
  const email = await env[KV_BINDING].get('tk:' + tk)
  if (!email) return null
  const u = await getUser(env, email)
  return u && !u.disabled ? u : null
}
function avatarUrl(req, id) { return new URL(req.url).origin + '/avatar/' + id }

async function verifyTokenValid(env, req) {
  const t = req.headers.get('x-verify-token')
  if (t && (await env[KV_BINDING].get('vt:' + t))) return true
  const cookie = req.headers.get('cookie') || ''
  const m = cookie.match(/(?:^|;\s*)vt=([^;]+)/)
  if (m && (await env[KV_BINDING].get('vt:' + m[1]))) return true
  return false
}

// ============================ 路由 ============================

export default {
  async fetch(request, env, ctx) {
    try {
      return await handle(request, env, ctx)
    } catch (e) {
      console.log('[error]', e.stack || e.message)
      return err('服务器内部错误：' + e.message, 500)
    }
  }
}

async function handle(req, env, ctx) {
  const url = new URL(req.url)
  const p = url.pathname
  const method = req.method

  recordRequest(env, ctx, req)

  // ---- 管理后台页面（由函数直接输出，保证页面与接口同版本，不被缓存/静态部署影响）----
  if (p === '/admin' || p === '/admin/' || p === '/admin/index.html')
    return new Response(ADMIN_HTML, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } })
  if (p === '/' ) return Response.redirect(url.origin + '/admin/', 302)

  // ---- 头像公开读取（任何模式可访问）----
  if (method === 'GET' && p.startsWith('/avatar/')) {
    const id = decodeURIComponent(p.slice(8))
    if (!/^av_[a-f0-9]+$/.test(id)) return err('头像不存在', 404)
    if (env[R2_BINDING]) {
      const obj = await env[R2_BINDING].get(id + '.webp')
      if (!obj) return err('头像不存在', 404)
      return new Response(obj.body, { headers: { 'content-type': 'image/webp', 'cache-control': 'public, max-age=86400' } })
    }
    const b64 = await env[KV_BINDING].get('av:' + id)
    if (!b64) return err('头像不存在', 404)
    return new Response(Uint8Array.from(atob(b64), c => c.charCodeAt(0)), {
      headers: { 'content-type': 'image/webp', 'cache-control': 'public, max-age=86400' }
    })
  }

  // ---- 浏览器攻击警告页表单提交 ----
  if (method === 'POST' && p === '/challenge/verify') {
    const form = await req.formData()
    const nonce = form.get('nonce') || '', answer = String(form.get('answer') || '').trim()
    const ch = JSON.parse((await env[KV_BINDING].get('cn:' + nonce)) || 'null')
    if (!ch) { const fresh = await newChallenge(env); return browserWarnPage(fresh.nonce, fresh.question, '验证已过期，请重试') }
    if (String(ch.a) !== answer) {
      recordChallenge(false)
      await env[KV_BINDING].delete('cn:' + nonce)
      const fresh = await newChallenge(env)
      return browserWarnPage(fresh.nonce, fresh.question, '答案错误，请重新验证')
    }
    recordChallenge(true)
    await env[KV_BINDING].delete('cn:' + nonce)
    const vt = rand(20)
    await env[KV_BINDING].put('vt:' + vt, '1', { expirationTtl: VERIFY_TTL })
    return new Response('', { status: 302, headers: { location: '/', 'set-cookie': `vt=${vt}; Path=/; Max-Age=${VERIFY_TTL}; HttpOnly; SameSite=Lax` } })
  }

  // ---- 公开/管理员接口不受攻击门限影响 ----
  const isPublic = p === '/api/ping' || p.startsWith('/api/challenge/') || p.startsWith('/api/admin/') || p.startsWith('/internal/')

  if (!isPublic) {
    const st = await evaluate(env)
    if (st.on && !(await verifyTokenValid(env, req))) {
      // 浏览器访问整站 → 警告验证页
      const accept = req.headers.get('accept') || ''
      if (accept.includes('text/html') && !p.startsWith('/api/')) {
        const ch = await newChallenge(env)
        return browserWarnPage(ch.nonce, ch.question, null, st)
      }
      return err('需要先完成人机验证', 403, { code: 'VERIFY_REQUIRED' })
    }
  }

  // ================= 健康检查 =================
  if (method === 'GET' && p === '/api/ping') return json({ ok: true, v: VERSION, ts: Date.now() })

  // ================= 人机验证 =================
  if (method === 'GET' && p === '/api/challenge/request') {
    return json(await newChallenge(env))
  }
  if (method === 'POST' && p === '/api/challenge/verify') {
    const b = await req.json().catch(() => ({}))
    const ch = JSON.parse((await env[KV_BINDING].get('cn:' + (b.nonce || ''))) || 'null')
    if (!ch) return err('验证已过期', 400)
    if (String(ch.a) !== String(b.answer || '').trim()) {
      recordChallenge(false)
      await env[KV_BINDING].delete('cn:' + b.nonce)
      return err('答案错误', 400)
    }
    recordChallenge(true)
    await env[KV_BINDING].delete('cn:' + b.nonce)
    const vt = rand(20)
    await env[KV_BINDING].put('vt:' + vt, '1', { expirationTtl: VERIFY_TTL })
    return json({ verifyToken: vt, ttl: VERIFY_TTL })
  }

  // ================= 登录注册 =================
  if (method === 'POST' && p === '/api/auth/send-code') {
    const b = await req.json().catch(() => ({}))
    const email = String(b.email || '').toLowerCase().trim()
    if (!EMAIL_RE.test(email)) return err('邮箱格式不正确')
    if (await env[KV_BINDING].get('cd2:' + email)) return err('请求过于频繁，请60秒后再试', 429)
    const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 900000 + 100000)
    await env[KV_BINDING].put('cd:' + email, JSON.stringify({ code, exp: Date.now() + CODE_TTL * 1000, attempts: 0 }), { expirationTtl: CODE_TTL })
    await env[KV_BINDING].put('cd2:' + email, '1', { expirationTtl: RESEND_COOLDOWN })
    const r = await sendEmail(env, email, code)
    return json({ ok: true, ttl: CODE_TTL, ...(r.channel === 'dev' ? { devHint: '开发模式：验证码可在管理后台概览页查看' } : {}) })
  }

  if (method === 'POST' && p === '/api/auth/verify') {
    const b = await req.json().catch(() => ({}))
    const email = String(b.email || '').toLowerCase().trim()
    const code = String(b.code || '').trim()
    if (!EMAIL_RE.test(email)) return err('邮箱格式不正确')
    const cd = JSON.parse((await env[KV_BINDING].get('cd:' + email)) || 'null')
    if (!cd) { recordAuth(true); return err('验证码已过期，请重新获取', 400) }
    if (cd.code !== code) {
      recordAuth(true)
      cd.attempts = (cd.attempts || 0) + 1
      if (cd.attempts >= 5) { await env[KV_BINDING].delete('cd:' + email); return err('错误次数过多，验证码已失效', 400) }
      await env[KV_BINDING].put('cd:' + email, JSON.stringify(cd), { expirationTtl: CODE_TTL })
      return err('验证码不正确', 400)
    }
    recordAuth(false)
    await env[KV_BINDING].delete('cd:' + email)
    await env[KV_BINDING].delete('cd2:' + email)

    let u = await getUser(env, email)
    const isNew = !u
    if (!u) u = { email, nick: email.split('@')[0], sign: '', avatarId: '', createdAt: Date.now(), disabled: false }
    if (u.disabled) return err('账号已被禁用，请联系管理员', 403)
    u.lastLogin = Date.now()
    await saveUser(env, u)

    const tk = rand(20)
    await env[KV_BINDING].put('tk:' + tk, email, { expirationTtl: TOKEN_TTL })
    await pushLog(env, 'ops', `${isNew ? '新用户注册' : '用户登录'}：${email}`)
    return json({ token: tk, ttl: TOKEN_TTL })
  }

  // ================= 用户资料 =================
  if (method === 'GET' && p === '/api/me') {
    const u = await userByToken(env, req)
    if (!u) return err('未授权', 401)
    return json(profileOf(u, req))
  }
  if (method === 'POST' && p === '/api/me/profile') {
    const u = await userByToken(env, req)
    if (!u) return err('未授权', 401)
    const b = await req.json().catch(() => ({}))
    if (typeof b.nickname === 'string') u.nick = b.nickname.trim().slice(0, 24)
    if (typeof b.signature === 'string') u.sign = b.signature.trim().slice(0, 80)
    await saveUser(env, u)
    return json({ ok: true, ...profileOf(u, req) })
  }
  if (method === 'POST' && p === '/api/me/avatar') {
    const u = await userByToken(env, req)
    if (!u) return err('未授权', 401)
    const ct = req.headers.get('content-type') || ''
    if (!ct.includes('webp') && !ct.includes('image')) return err('仅支持 WebP 头像', 400)
    const buf = await req.arrayBuffer()
    if (buf.byteLength === 0 || buf.byteLength > AVATAR_MAX) return err(`头像需在 ${AVATAR_MAX / 1024}KB 以内`, 400)
    const id = 'av_' + rand(16)
    if (env[R2_BINDING]) {
      await env[R2_BINDING].put(id + '.webp', buf, { httpMetadata: { contentType: 'image/webp' } })
    } else {
      let bin = ''
      const bytes = new Uint8Array(buf)
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
      await env[KV_BINDING].put('av:' + id, btoa(bin))
    }
    const old = u.avatarId
    u.avatarId = id
    await saveUser(env, u)
    if (old && old !== id) {
      runBg(env, async () => {
        if (env[R2_BINDING]) await env[R2_BINDING].delete(old + '.webp')
        else await env[KV_BINDING].delete('av:' + old)
      }, ctx)
    }
    return json({ ok: true, avatarUrl: avatarUrl(req, id) })
  }

  // ================= 邮件服务内部接口 =================
  if (method === 'GET' && p === '/internal/smtp-config') {
    const secret = url.searchParams.get('secret') || ''
    const s = await getSettings(env)
    const expected = s.email.mailerSecret || env.INTERNAL_SECRET || ''
    if (!expected || secret !== expected) return err('forbidden', 403)
    return json({ host: s.email.smtp.host, port: Number(s.email.smtp.port) || 465, secure: s.email.smtp.secure !== false, user: s.email.smtp.user, pass: s.email.smtp.pass, from: `${s.email.smtp.senderName || '乐库音乐'} <${s.email.smtp.user}>` })
  }

  // ================= 管理员接口 =================
  if (p.startsWith('/api/admin/')) return handleAdmin(req, env, ctx, p, method)

  return err('接口不存在', 404)
}

function runBg(env, fn, ctx) { try { ctx.waitUntil(fn()) } catch (_) { } }

function profileOf(u, req) {
  return {
    email: u.email, nickname: u.nick || u.email.split('@')[0], signature: u.sign || '',
    avatarUrl: u.avatarId ? avatarUrl(req, u.avatarId) : '',
    createdAt: u.createdAt || 0
  }
}

async function newChallenge(env) {
  const a = crypto.getRandomValues(new Uint32Array(1))[0] % 89 + 10
  const b = crypto.getRandomValues(new Uint32Array(1))[0] % 89 + 10
  const nonce = rand(16)
  await env[KV_BINDING].put('cn:' + nonce, JSON.stringify({ a: a + b }), { expirationTtl: CODE_TTL })
  return { nonce, type: 'math', question: `${a} + ${b} = ?`, ttl: CODE_TTL }
}

function browserWarnPage(nonce, question, errorMsg, st) {
  const safe = (s) => String(s).replace(/[<>&"]/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c]))
  const reasons = (st?.reasons || ['系统正在防护异常流量']).map(safe).join('、')
  return new Response(`<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>安全验证 · 乐库音乐</title>
  <style>body{margin:0;background:#0b0e14;color:#fff;font-family:ui-sans-serif,system-ui;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px}
  .c{max-width:380px;width:100%;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:24px;padding:32px;text-align:center;backdrop-filter:blur(20px)}
  h1{font-size:20px;margin:0 0 8px}.t{color:#9aa4b5;font-size:14px;line-height:1.6;margin-bottom:22px}
  .q{font-size:30px;font-weight:700;letter-spacing:2px;margin:6px 0 18px}
  input{width:100%;box-sizing:border-box;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.18);border-radius:14px;color:#fff;font-size:22px;text-align:center;padding:14px;outline:none}
  button{width:100%;margin-top:16px;background:linear-gradient(135deg,#FF4D6D,#E63956);color:#fff;border:0;border-radius:14px;padding:15px;font-size:16px;font-weight:600}
  .e{color:#FF6B81;font-size:13px;margin-top:12px;min-height:18px}.r{display:inline-block;margin:6px 0 18px;padding:4px 12px;border-radius:999px;background:rgba(255,77,109,.14);color:#FF8BA0;font-size:12px}</style></head>
  <body><form class="c" method="post" action="/challenge/verify">
  <h1>安全验证</h1><div class="t">为保障服务稳定，请完成下面的算术题后继续访问</div>
  <div class="r">${reasons}</div>
  <input type="hidden" name="nonce" value="${safe(nonce)}">
  <div class="q">${safe(question || '')}</div>
  <input name="answer" inputmode="numeric" placeholder="输入答案" autofocus required>
  <button type="submit">验证并继续</button><div class="e">${safe(errorMsg || '')}</div>
  </form></body></html>`, { headers: { 'content-type': 'text/html; charset=utf-8' } })
}

// ============================ 管理员 ============================

async function adminAuth(env, req) {
  const s = await getSettings(env)
  const auth = req.headers.get('authorization') || ''
  const tk = auth.startsWith('Bearer ') ? auth.slice(7) : ''
  return tk && tk === s.adminPassword
}

async function handleAdmin(req, env, ctx, p, method) {
  if (p === '/api/admin/login' && method === 'POST') {
    const b = await req.json().catch(() => ({}))
    const s = await getSettings(env)
    if (String(b.password || '') !== s.adminPassword) return err('密码错误', 401)
    return json({ token: s.adminPassword })
  }
  if (!(await adminAuth(env, req))) return err('未授权', 403)

  if (p === '/api/admin/metrics' && method === 'GET') {
    const st = await evaluate(env, true)
    const listed = await env[KV_BINDING].list({ prefix: 'user:', limit: 1000 })
    const users = await Promise.all(listed.keys.map(k => env[KV_BINDING].get(k.name)))
    const parsed = users.map(x => JSON.parse(x))
    const today = new Date(); today.setHours(0, 0, 0, 0)
    const devcodes = JSON.parse((await env[KV_BINDING].get('devcodes')) || '[]')
    const logAttack = JSON.parse((await env[KV_BINDING].get('log:attack')) || '[]')
    const logOps = JSON.parse((await env[KV_BINDING].get('log:ops')) || '[]')
    const cur = b10()
    const series = []
    for (let i = 29; i >= 0; i--) series.push(parseInt((await env[KV_BINDING].get(`m:g:${cur - i}`)) || '0', 10) || 0)
    return json({
      version: VERSION,
      state: { attack: st.on, manual: st.manual, muted: st.muted, muteLeft: st.muteLeft, reasons: st.reasons, cooldownLeft: st.cooldownLeft },
      qps: { total: series.reduce((a, b) => a + b, 0), qps: st.metrics.qps, series },
      metrics: st.metrics,
      users: { total: parsed.length, today: parsed.filter(u => (u.lastLogin || 0) >= today.getTime()).length, disabled: parsed.filter(u => u.disabled).length },
      devcodes, logs: { attack: logAttack, ops: logOps.slice(0, 20) }
    })
  }

  if (p === '/api/admin/attack' && method === 'POST') {
    const b = await req.json().catch(() => ({}))
    const st = await setManual(env, !!b.on)
    return json({ state: { attack: st.on, manual: st.manual, muted: st.muted, muteLeft: st.muteLeft, reasons: st.reasons, cooldownLeft: st.cooldownLeft } })
  }

  if (p === '/api/admin/settings' && method === 'GET') {
    const s = await getSettings(env)
    return json(s)
  }
  if (p === '/api/admin/settings' && method === 'PUT') {
    const b = await req.json().catch(() => ({}))
    const s = await getSettings(env)
    if (b.email && typeof b.email === 'object') {
      s.email = {
        ...s.email, ...b.email,
        smtp: { ...s.email.smtp, ...(b.email.smtp || {}) }
      }
    }
    if (b.thresholds && typeof b.thresholds === 'object') {
      for (const [k, v] of Object.entries(b.thresholds)) {
        const num = Number(v)
        if (Number.isFinite(num)) s.thresholds[k] = num
      }
    }
    if (typeof b.adminPassword === 'string') {
      if (b.adminPassword.length < 6) return err('管理员密码至少 6 位')
      s.adminPassword = b.adminPassword
    }
    await saveSettings(env, s)
    await pushLog(env, 'ops', '管理员更新了系统配置')
    return json({ ok: true })
  }

  if (p === '/api/admin/users' && method === 'GET') {
    const listed = await env[KV_BINDING].list({ prefix: 'user:', limit: 1000 })
    const users = await Promise.all(listed.keys.map(async k => {
      const u = JSON.parse(await env[KV_BINDING].get(k.name))
      return {
        email: u.email, nickname: u.nick, signature: u.sign, disabled: !!u.disabled,
        avatarUrl: u.avatarId ? avatarUrl(req, u.avatarId) : '',
        createdAt: u.createdAt || 0, lastLogin: u.lastLogin || 0
      }
    }))
    users.sort((a, b) => b.lastLogin - a.lastLogin)
    return json({ users })
  }
  if (p === '/api/admin/users/status' && method === 'POST') {
    const b = await req.json().catch(() => ({}))
    const email = String(b.email || '').toLowerCase().trim()
    const u = await getUser(env, email)
    if (!u) return err('用户不存在', 404)
    u.disabled = !!b.disabled
    await saveUser(env, u)
    await pushLog(env, 'ops', `账号 ${email} 被管理员${u.disabled ? '禁用' : '启用'}`)
    return json({ ok: true, disabled: u.disabled })
  }

  if (p === '/api/admin/email/test' && method === 'POST') {
    const b = await req.json().catch(() => ({}))
    const to = String(b.to || '').toLowerCase().trim()
    if (!EMAIL_RE.test(to)) return err('邮箱格式不正确')
    try {
      // 测试邮件也用随机验证码（与真实登录验证码同一套生成规则）
      const testCode = String(crypto.getRandomValues(new Uint32Array(1))[0] % 900000 + 100000)
      const r = await sendEmail(env, to, testCode)
      return json({ ok: true, ...r, code: r.channel === 'dev' ? testCode : undefined })
    } catch (e) {
      return err(e.message, 502)
    }
  }

  return err('接口不存在', 404)
}

const ADMIN_HTML = "<!doctype html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">\n<title>乐库音乐 · 管理后台</title>\n<style>\n:root{\n  --bg:#07090d; --card:rgba(255,255,255,.055); --card2:rgba(255,255,255,.08);\n  --line:rgba(255,255,255,.10); --line2:rgba(255,255,255,.18);\n  --txt:#f5f7fa; --sub:#9aa4b5; --mut:#5f6878;\n  --accent:#FF4D6D; --accent2:#E63956; --accent-soft:rgba(255,77,109,.14);\n  --ok:#34d399; --warn:#fbbf24; --danger:#fb7185;\n  --r:18px;\n}\n*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}\nhtml,body{margin:0;height:100%}\nbody{background:\n  radial-gradient:fixed;\n  background:radial-gradient(900px 500px at 80% -10%,rgba(255,77,109,.14),transparent 60%),\n            radial-gradient(700px 500px at -10% 110%,rgba(99,102,241,.10),transparent 60%),var(--bg);\n  color:var(--txt);font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,\"PingFang SC\",\"Microsoft YaHei\",system-ui,sans-serif;\n  font-size:15px;line-height:1.6;-webkit-font-smoothing:antialiased}\nbutton,input,select{font:inherit;color:inherit}\nbutton{cursor:pointer;border:0}\n.hidden{display:none!important}\n\n/* ---------- 登录 ---------- */\n#login{min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:24px}\n.login-card{width:100%;max-width:380px;background:var(--card);border:1px solid var(--line);\n  border-radius:28px;padding:36px 30px;backdrop-filter:blur(24px);box-shadow:0 30px 80px rgba(0,0,0,.5)}\n.logo{width:58px;height:58px;border-radius:18px;margin:0 auto 16px;display:grid;place-items:center;\n  background:linear-gradient(135deg,var(--accent),var(--accent2));font-size:26px;font-weight:800;box-shadow:0 12px 30px rgba(255,77,109,.35)}\n.login-card h1{text-align:center;font-size:21px;margin:0 0 4px}.login-card p{text-align:center;color:var(--sub);font-size:13px;margin:0 0 26px}\n.field{margin-bottom:14px}\n.field label{display:block;font-size:12.5px;color:var(--sub);margin:0 2px 7px}\n.input{width:100%;background:rgba(255,255,255,.06);border:1px solid var(--line);border-radius:14px;\n  padding:13px 15px;outline:none;transition:.2s;color:var(--txt)}\n.input:focus{border-color:rgba(255,77,109,.6);background:rgba(255,255,255,.09);box-shadow:0 0 0 4px rgba(255,77,109,.12)}\n.input::placeholder{color:var(--mut)}\n.btn{width:100%;border-radius:14px;padding:14px;font-weight:600;font-size:15px;margin-top:8px;\n  background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;transition:.18s;\n  box-shadow:0 10px 26px rgba(255,77,109,.28)}\n.btn:active{transform:scale(.975)}.btn:disabled{opacity:.55}\n.btn.ghost{background:var(--card2);border:1px solid var(--line);box-shadow:none;color:var(--txt)}\n.btn.danger{background:rgba(251,113,133,.14);color:var(--danger);border:1px solid rgba(251,113,133,.3);box-shadow:none}\n.btn.sm{width:auto;padding:8px 14px;font-size:13px;border-radius:10px;margin:0}\n.btn.sm.ghost{background:rgba(255,255,255,.07)}\n.err{color:var(--danger);font-size:13px;min-height:20px;margin-top:10px;text-align:center}\n\n/* ---------- 主框架 ---------- */\n#app{min-height:100dvh;display:grid;grid-template-columns:230px 1fr}\n.side{padding:26px 16px;border-right:1px solid var(--line);display:flex;flex-direction:column;gap:6px;\n  position:sticky;top:0;height:100dvh;background:rgba(255,255,255,.02);backdrop-filter:blur(20px)}\n.brand{display:flex;align-items:center;gap:11px;padding:4 10px 22px}\n.brand .dot{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;font-weight:800;\n  background:linear-gradient(135deg,var(--accent),var(--accent2));font-size:18px}\n.brand b{font-size:16px}.brand span{display:block;font-size:11px;color:var(--mut)}\n.nav{display:flex;flex-direction:column;gap:4px}\n.nav button{display:flex;align-items:center;gap:11px;background:none;color:var(--sub);padding:11px 13px;\n  border-radius:13px;font-size:14.5px;text-align:left;transition:.15s}\n.nav button .ic{width:19px;height:19px;flex:none}\n.nav button.active{background:var(--accent-soft);color:#fff;box-shadow:inset 0 0 0 1px rgba(255,77,109,.25)}\n.nav button:active{background:rgba(255,255,255,.06)}\n.side .spacer{flex:1}\n.main{padding:26px 30px 60px;max-width:1080px;width:100%;margin:0 auto}\n.topbar{display:flex;align-items:center;gap:12px;margin-bottom:24px}\n.topbar h2{font-size:22px;margin:0;flex:1}\n.pill{display:inline-flex;align-items:center;gap:7px;font-size:12.5px;padding:6px 13px;border-radius:999px;\n  border:1px solid var(--line);background:var(--card)}\n.pill .led{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 10px var(--ok)}\n.pill.attack .led{background:var(--danger);box-shadow:0 0 12px var(--danger);animation:pulse 1.1s infinite}\n@keyframes pulse{50%{opacity:.35}}\n\n/* ---------- 卡片/网格 ---------- */\n.grid{display:grid;gap:14px}\n.g4{grid-template-columns:repeat(4,1fr)}.g2{grid-template-columns:1fr 1fr}\n.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:19px;backdrop-filter:blur(18px)}\n.card h3{margin:0 0 14px;font-size:15px;display:flex;align-items:center;gap:8px}\n.card h3 .tag{font-size:11px;color:var(--mut);font-weight:400}\n.stat .n{font-size:27px;font-weight:700;letter-spacing:-.5px}.stat .l{color:var(--sub);font-size:12.5px;margin-top:2px}\n.stat .ic{float:right;width:34px;height:34px;border-radius:11px;display:grid;place-items:center;background:var(--accent-soft);color:var(--accent)}\n.stat .n small{font-size:13px;color:var(--sub);font-weight:400;margin-left:3px}\n\n/* 条形图 */\n.chart{display:flex;align-items:flex-end;gap:4px;height:96px;margin-top:6px}\n.chart .bar{flex:1;background:linear-gradient(180deg,var(--accent),rgba(255,77,109,.25));border-radius:4px 4px 2px 2px;min-height:3px;transition:height .5s}\n.chart .bar.hot{background:linear-gradient(180deg,var(--danger),rgba(251,113,133,.3))}\n.chart-x{display:flex;justify-content:space-between;color:var(--mut);font-size:11px;margin-top:7px}\n\n/* 列表 */\n.list{display:flex;flex-direction:column;gap:9px;max-height:430px;overflow:auto}\n.row{display:flex;align-items:center;gap:12px;padding:11px 13px;border-radius:14px;background:rgba(255,255,255,.04);border:1px solid var(--line)}\n.row .av{width:42px;height:42px;border-radius:50%;flex:none;object-fit:cover;display:grid;place-items:center;\n  background:linear-gradient(135deg,#2a3140,#1a1f2b);color:var(--sub);font-weight:700;font-size:16px;overflow:hidden}\n.row .av img{width:100%;height:100%;object-fit:cover}\n.row .meta{flex:1;min-width:0}.row .meta b{display:block;font-size:14.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n.row .meta span{display:block;color:var(--mut);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n.badge{font-size:11px;padding:3px 9px;border-radius:999px;flex:none}\n.badge.on{background:rgba(52,211,153,.13);color:var(--ok)}.badge.off{background:rgba(251,113,133,.14);color:var(--danger)}\n.logline{font-size:12.5px;color:var(--sub);padding:7px 0;border-bottom:1px dashed rgba(255,255,255,.06);display:flex;gap:9px}\n.logline time{color:var(--mut);flex:none;font-variant-numeric:tabular-nums}\n.logline.attack{color:#ffb3c0}\n.mono{font-family:ui-monospace,Menlo,Consolas,monospace}\n.codechip{display:inline-block;background:rgba(255,77,109,.13);border:1px solid rgba(255,77,109,.3);\n  color:#ff9db0;padding:3px 12px;border-radius:9px;font-weight:700;letter-spacing:2px;font-size:15px}\n\n/* 表单分段 */\n.seg{display:flex;background:rgba(255,255,255,.05);border:1px solid var(--line);border-radius:13px;padding:4px;gap:4px;margin-bottom:16px}\n.seg button{flex:1;background:none;color:var(--sub);padding:9px;border-radius:10px;font-size:13.5px;transition:.15s}\n.seg button.active{background:var(--card2);color:#fff;box-shadow:0 2px 10px rgba(0,0,0,.3)}\n.hint{font-size:12.5px;color:var(--mut);line-height:1.7;background:rgba(255,255,255,.035);\n  border:1px dashed var(--line);border-radius:12px;padding:11px 14px;margin-bottom:14px}\n.hint a{color:#ff8ba0}\n.switch{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:13px 0;border-bottom:1px solid var(--line)}\n.switch:last-child{border-bottom:0}\n.switch .t b{font-size:14.5px}.switch .t span{display:block;font-size:12px;color:var(--mut)}\n.toggle{width:46px;height:27px;border-radius:999px;background:rgba(255,255,255,.14);position:relative;flex:none;transition:.2s}\n.toggle i{position:absolute;top:3px;left:3px;width:21px;height:21px;border-radius:50%;background:#fff;transition:.2s}\n.toggle.on{background:linear-gradient(135deg,var(--accent),var(--accent2))}.toggle.on i{left:22px}\n.toast{position:fixed;left:50%;bottom:34px;transform:translateX(-50%) translateY(20px);background:rgba(20,24,33,.96);\n  border:1px solid var(--line2);padding:12px 22px;border-radius:999px;font-size:14px;opacity:0;pointer-events:none;\n  transition:.25s;z-index:99;backdrop-filter:blur(14px);max-width:88vw;text-align:center}\n.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}\n.toast.err{border-color:rgba(251,113,133,.5);color:#ffc4cf}\n.empty{text-align:center;color:var(--mut);font-size:13px;padding:34px 0}\n\n@media(max-width:820px){\n  #app{display:block}\n  .side{position:fixed;left:0;right:0;bottom:0;top:auto;height:auto;z-index:40;flex-direction:row;\n    padding:8px 6px calc(8px + env(safe-area-inset-bottom));border-right:0;border-top:1px solid var(--line);\n    background:rgba(10,13,19,.85)}\n  .brand,.side .spacer,#navLogout{display:none}\n  .nav{flex-direction:row;width:100%;justify-content:space-around;gap:2px}\n  .nav button{flex-direction:column;gap:3px;padding:7px 4px;font-size:10.5px;flex:1;justify-content:center}\n  .nav button .ic{width:21px;height:21px}\n  .main{padding:18px 15px 96px}\n  .g4{grid-template-columns:1fr 1fr}.g2{grid-template-columns:1fr}\n  .topbar h2{font-size:19px}\n}\n</style>\n</head>\n<body>\n\n<!-- 登录 -->\n<div id=\"login\">\n  <div class=\"login-card\">\n    <div class=\"logo\">♪</div>\n    <h1>乐库音乐控制台</h1>\n    <p>登录管理后台</p>\n    <div class=\"field\">\n      <label>管理员密码</label>\n      <input class=\"input\" id=\"lpw\" type=\"password\" placeholder=\"初始密码 admin123\"\n             onkeydown=\"if(event.key==='Enter')doLogin()\">\n    </div>\n    <button class=\"btn\" id=\"lbtn\" onclick=\"doLogin()\">登 录</button>\n    <div class=\"err\" id=\"lerr\"></div>\n  </div>\n</div>\n\n<!-- 主界面 -->\n<div id=\"app\" class=\"hidden\">\n  <aside class=\"side\">\n    <div class=\"brand\"><div class=\"dot\">♪</div><div><b>乐库音乐</b><span>管理控制台</span></div></div>\n    <nav class=\"nav\" id=\"nav\">\n      <button data-tab=\"dash\" class=\"active\" onclick=\"tab('dash')\">\n        <svg class=\"ic\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" stroke-linecap=\"round\"><rect x=\"3\" y=\"3\" width=\"7\" height=\"9\" rx=\"1.5\"/><rect x=\"14\" y=\"3\" width=\"7\" height=\"5\" rx=\"1.5\"/><rect x=\"14\" y=\"12\" width=\"7\" height=\"9\" rx=\"1.5\"/><rect x=\"3\" y=\"16\" width=\"7\" height=\"5\" rx=\"1.5\"/></svg>概览</button>\n      <button data-tab=\"users\" onclick=\"tab('users')\">\n        <svg class=\"ic\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" stroke-linecap=\"round\"><circle cx=\"9\" cy=\"8\" r=\"3.2\"/><path d=\"M3.5 20c.6-3.2 2.9-5 5.5-5s4.9 1.8 5.5 5\"/><path d=\"M16 5.2a3.2 3.2 0 0 1 0 5.6M17.5 15.2c2 .7 3.2 2.3 3.5 4.8\"/></svg>用户</button>\n      <button data-tab=\"email\" onclick=\"tab('email')\">\n        <svg class=\"ic\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" stroke-linecap=\"round\"><rect x=\"3\" y=\"5\" width=\"18\" height=\"14\" rx=\"2.5\"/><path d=\"m4 7 8 6 8-6\"/></svg>邮件</button>\n      <button data-tab=\"guard\" onclick=\"tab('guard')\">\n        <svg class=\"ic\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" stroke-linecap=\"round\"><path d=\"M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6z\"/><path d=\"m9.2 12 2 2 3.8-4\"/></svg>防护</button>\n      <button data-tab=\"setting\" onclick=\"tab('setting')\">\n        <svg class=\"ic\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" stroke-linecap=\"round\"><circle cx=\"12\" cy=\"12\" r=\"3\"/><path d=\"M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2V21a2 2 0 1 1-4 0v-.1A1.7 1.7 0 0 0 7 19.4a1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1A1.7 1.7 0 0 0 4.6 14H4.5a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.2-2.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1A1.7 1.7 0 0 0 10 4.6V4.5a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 2.9 1.2l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9v.1a1.7 1.7 0 0 0 1.2 2.9h.1a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.2 1z\"/></svg>设置</button>\n    </nav>\n    <div class=\"spacer\"></div>\n    <button class=\"nav\" id=\"navLogout\" style=\"background:none;color:var(--sub);padding:11px 13px;border-radius:13px;text-align:left;font-size:14px\" onclick=\"logout()\">退出登录</button>\n  </aside>\n\n  <main class=\"main\">\n    <div class=\"topbar\">\n      <h2 id=\"title\">概览</h2>\n      <span class=\"pill\" id=\"attackPill\"><span class=\"led\"></span><span id=\"attackText\">防护正常</span></span>\n    </div>\n\n    <!-- 概览 -->\n    <section id=\"tab-dash\">\n      <div class=\"grid g4\" id=\"statGrid\"></div>\n      <div class=\"grid g2\" style=\"margin-top:14px\">\n        <div class=\"card\">\n          <h3>近 5 分钟请求量 <span class=\"tag\">每 10 秒一格</span></h3>\n          <div class=\"chart\" id=\"chart\"></div>\n          <div class=\"chart-x\"><span>5 分钟前</span><span>现在</span></div>\n        </div>\n        <div class=\"card\">\n          <h3>实时指标</h3>\n          <div id=\"liveMetrics\" class=\"grid\" style=\"gap:8px\"></div>\n        </div>\n      </div>\n      <div class=\"grid g2\" style=\"margin-top:14px\">\n        <div class=\"card\">\n          <h3>开发模式验证码 <span class=\"tag\">配置真实邮件后自动消失</span></h3>\n          <div class=\"list\" id=\"devCodes\"><div class=\"empty\">暂无</div></div>\n        </div>\n        <div class=\"card\">\n          <h3>防护与操作日志</h3>\n          <div class=\"list\" id=\"logs\" style=\"max-height:360px\"><div class=\"empty\">暂无</div></div>\n        </div>\n      </div>\n    </section>\n\n    <!-- 用户 -->\n    <section id=\"tab-users\" class=\"hidden\">\n      <div class=\"card\">\n        <h3>用户管理 <span class=\"tag\" id=\"userCount\"></span></h3>\n        <div class=\"list\" id=\"userList\" style=\"max-height:62vh\"><div class=\"empty\">加载中…</div></div>\n      </div>\n    </section>\n\n    <!-- 邮件 -->\n    <section id=\"tab-email\" class=\"hidden\">\n      <div class=\"card\">\n        <h3>发信通道</h3>\n        <div class=\"seg\" id=\"mailSeg\">\n          <button data-p=\"dev\" class=\"active\" onclick=\"mailProvider('dev')\">开发模式</button>\n          <button data-p=\"smtp\" onclick=\"mailProvider('smtp')\">SMTP 直连（QQ/163）</button>\n          <button data-p=\"resend\" onclick=\"mailProvider('resend')\">Resend</button>\n          <button data-p=\"mailer\" onclick=\"mailProvider('mailer')\">自建邮件服务</button>\n        </div>\n\n        <div id=\"mp-body\"></div>\n\n        <button class=\"btn\" onclick=\"saveEmail()\">保存邮件配置</button>\n      </div>\n      <div class=\"card\" style=\"margin-top:14px\">\n        <h3>发送测试邮件</h3>\n        <div style=\"display:flex;gap:10px\">\n          <input class=\"input\" id=\"testTo\" placeholder=\"输入接收测试邮件的邮箱\" style=\"flex:1\">\n          <button class=\"btn sm\" style=\"margin:0;white-space:nowrap;padding:13px 20px\" onclick=\"testEmail()\">发送测试</button>\n        </div>\n      </div>\n    </section>\n\n    <!-- 防护 -->\n    <section id=\"tab-guard\" class=\"hidden\">\n      <div class=\"card\">\n        <h3>攻击模式</h3>\n        <div class=\"switch\">\n          <div class=\"t\"><b>自动检测防护</b><span>按下面阈值自动开启，流量恢复后自动解除</span></div>\n          <div class=\"toggle on\" id=\"tg-auto\"><i></i></div>\n        </div>\n        <div class=\"switch\">\n          <div class=\"t\"><b id=\"manualT\">手动开启防护</b><span>手动开启后不会自动解除</span></div>\n          <button class=\"btn sm ghost\" id=\"btnManual\" onclick=\"manualToggle()\">立即开启</button>\n        </div>\n        <div id=\"guardState\" style=\"margin-top:14px\"></div>\n      </div>\n      <div class=\"card\" style=\"margin-top:14px\">\n        <h3>自动触发阈值</h3>\n        <div class=\"grid g2\">\n          <div class=\"field\"><label>全局 QPS 上限（请求/秒）</label><input class=\"input\" id=\"t-qps\" type=\"number\" min=\"1\"></div>\n          <div class=\"field\"><label>单 IP 每 10 秒请求上限</label><input class=\"input\" id=\"t-ip\" type=\"number\" min=\"1\"></div>\n          <div class=\"field\"><label>单 UA 每 10 秒请求上限</label><input class=\"input\" id=\"t-ua\" type=\"number\" min=\"1\"></div>\n          <div class=\"field\"><label>登录失败率阈值（0~1）</label><input class=\"input\" id=\"t-lfr\" type=\"number\" step=\"0.05\" min=\"0.1\" max=\"1\"></div>\n          <div class=\"field\"><label>登录最小样本数</label><input class=\"input\" id=\"t-lms\" type=\"number\" min=\"3\"></div>\n          <div class=\"field\"><label>人机失败率阈值（0~1）</label><input class=\"input\" id=\"t-cfr\" type=\"number\" step=\"0.05\" min=\"0.1\" max=\"1\"></div>\n          <div class=\"field\"><label>人机最小样本数</label><input class=\"input\" id=\"t-cms\" type=\"number\" min=\"3\"></div>\n          <div class=\"field\"><label>恢复冷却时间（秒）</label><input class=\"input\" id=\"t-cd\" type=\"number\" min=\"10\"></div>\n        </div>\n        <button class=\"btn\" onclick=\"saveThresholds()\">保存阈值</button>\n      </div>\n      <div class=\"card\" style=\"margin-top:14px\">\n        <h3>防护事件</h3>\n        <div class=\"list\" id=\"attackLog\" style=\"max-height:300px\"><div class=\"empty\">暂无</div></div>\n      </div>\n    </section>\n\n    <!-- 设置 -->\n    <section id=\"tab-setting\" class=\"hidden\">\n      <div class=\"card\" style=\"max-width:520px\">\n        <h3>修改管理员密码</h3>\n        <div class=\"field\"><label>新密码（至少 6 位）</label><input class=\"input\" id=\"newPw\" type=\"password\" placeholder=\"新密码\"></div>\n        <div class=\"field\"><label>确认新密码</label><input class=\"input\" id=\"newPw2\" type=\"password\" placeholder=\"再输一次\"></div>\n        <button class=\"btn\" onclick=\"savePassword()\">更新密码</button>\n      </div>\n      <div class=\"card\" style=\"margin-top:14px\">\n        <h3>版本信息</h3>\n        <div class=\"hint\">后台页面版本：<b id=\"uiVer\">-</b>　后端接口版本：<b id=\"apiVer\">检测中…</b><br>\n        两个版本必须一致；不一致说明 functions 没更新成功，请重新部署并强制刷新（清缓存/无痕窗口）。</div>\n      </div>\n    </section>\n  </main>\n</div>\n\n<div class=\"toast\" id=\"toast\"></div>\n\n<script>\nconst API = ''\nlet TOKEN = localStorage.getItem('admin_token') || ''\nlet SETTINGS = null\nlet GUARD = null\nconst UI_VERSION = '4.13'\nlet timer = null\n\nconst $ = s => document.querySelector(s)\nfunction toast(msg, isErr){ const t=$('#toast'); t.textContent=msg; t.className='toast show'+(isErr?' err':''); clearTimeout(t._t); t._t=setTimeout(()=>t.className='toast',2600) }\nfunction fmtTime(ts){ const d=new Date(ts); const p=n=>String(n).padStart(2,'0'); return `${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}` }\n\nasync function api(path, opts={}){\n  const resp = await fetch(API+path, {\n    ...opts,\n    headers: { 'content-type':'application/json', ...(TOKEN?{authorization:'Bearer '+TOKEN}:{}), ...(opts.headers||{}) }\n  })\n  const data = await resp.json().catch(()=>({}))\n  if(resp.status===403 || resp.status===401){ logout(); throw new Error('未授权') }\n  if(!resp.ok) throw new Error(data.error||('请求失败 '+resp.status))\n  return data\n}\n\nasync function doLogin(){\n  const pw = $('#lpw').value.trim(); if(!pw) return\n  $('#lbtn').disabled = true; $('#lbtn').textContent = '登录中…'\n  try{\n    const r = await api('/api/admin/login',{method:'POST',body:JSON.stringify({password:pw})})\n    TOKEN = r.token; localStorage.setItem('admin_token', TOKEN)\n    enterApp()\n  }catch(e){ $('#lerr').textContent = e.message }\n  finally{ $('#lbtn').disabled=false; $('#lbtn').textContent='登 录' }\n}\nfunction logout(){ TOKEN=''; localStorage.removeItem('admin_token'); $('#app').classList.add('hidden'); $('#login').classList.remove('hidden'); clearInterval(timer) }\nasync function enterApp(){\n  $('#login').classList.add('hidden'); $('#app').classList.remove('hidden')\n  $('#uiVer').textContent=UI_VERSION\n  await Promise.all([loadDash(), loadSettings()])\n  tab('dash')\n  clearInterval(timer); timer = setInterval(()=>{ if(currentTab==='dash')loadDash() }, 5000)\n}\n\nlet currentTab='dash'\nconst TITLES={dash:'概览',users:'用户',email:'邮件配置',guard:'攻击防护',setting:'系统设置'}\nfunction tab(name){\n  currentTab=name\n  document.querySelectorAll('#nav button').forEach(b=>b.classList.toggle('active',b.dataset.tab===name))\n  document.querySelectorAll('main section').forEach(s=>s.classList.add('hidden'))\n  $('#tab-'+name).classList.remove('hidden')\n  $('#title').textContent=TITLES[name]\n  if(name==='dash')loadDash()\n  if(name==='users')loadUsers()\n  if(name==='guard')loadGuard()\n}\n\nasync function loadDash(){\n  try{\n    const d = await api('/api/admin/metrics')\n    const el=$('#apiVer'); if(el){ el.textContent=d.version||'旧版（请重新部署 functions）'; el.style.color=d.version===UI_VERSION?'#7ee2a8':'#fb7185' }\n    const atk = d.state.attack\n    $('#attackPill').className = 'pill'+(atk?' attack':'')\n    $('#attackText').textContent = atk ? (d.state.manual?'防护中（手动）':'防护中（自动）') : '防护正常'\n    $('#statGrid').innerHTML = `\n      ${statCard('用户总数',d.users.total,'',icon('users'))}\n      ${statCard('今日活跃',d.users.today,'',icon('act'))}\n      ${statCard('当前 QPS',d.qps.qps,'/秒',icon('bolt'))}\n      ${statCard('已禁用账号',d.users.disabled,'',icon('ban'))}`\n    const max = Math.max(10,...d.qps.series)\n    $('#chart').innerHTML = d.qps.series.map((v,i)=>{\n      const h = Math.max(3, v/max*100)\n      return `<div class=\"bar${v/max>0.8?' hot':''}\" style=\"height:${h}%\" title=\"${v} 次/10秒\"></div>`\n    }).join('')\n    const m=d.metrics\n    $('#liveMetrics').innerHTML = [\n      ['近 10 秒请求',m.global10s+' 次'],['单 IP 峰值',m.maxIp10s+' 次/10s'],\n      ['单 UA 峰值',m.maxUa10s+' 次/10s'],['登录失败率',(m.loginFailRate*100).toFixed(0)+'% （'+m.auth60+' 次尝试）'],\n      ['人机失败率',(m.challengeFailRate*100).toFixed(0)+'% （'+m.challenge300+' 次验证）']\n    ].map(([k,v])=>`<div class=\"row\" style=\"padding:9px 13px\"><span class=\"meta\" style=\"color:var(--sub);font-size:13px\">${k}</span><b style=\"font-size:13.5px\">${v}</b></div>`).join('')\n    $('#devCodes').innerHTML = d.devcodes.length ? d.devcodes.map(c=>\n      `<div class=\"row\"><div class=\"meta\"><b>${c.email}</b><span>${fmtTime(c.ts)}</span></div><span class=\"codechip mono\">${c.code}</span></div>`).join('')\n      : '<div class=\"empty\">暂无（配置真实邮件通道后，验证码直接发到邮箱）</div>'\n    const logs=[...d.logs.attack.map(x=>({...x,atk:true})),...d.logs.ops].sort((a,b)=>b.ts-a.ts).slice(0,20)\n    $('#logs').innerHTML = logs.length ? logs.map(l=>\n      `<div class=\"logline ${l.atk?'attack':''}\"><time>${fmtTime(l.ts)}</time><span>${l.text}</span></div>`).join('')\n      : '<div class=\"empty\">暂无</div>'\n  }catch(e){ /* 静默，等下一轮 */ }\n}\nfunction statCard(l,n,unit,ic){ return `<div class=\"card stat\"><div class=\"ic\">${ic}</div><div class=\"n\">${n}<small>${unit}</small></div><div class=\"l\">${l}</div></div>` }\nfunction icon(k){const p={users:'<circle cx=\"9\" cy=\"8\" r=\"3\"/><path d=\"M3.5 20c.6-3.2 2.9-5 5.5-5s4.9 1.8 5.5 5\"/>',act:'<path d=\"M13 3 4 14h7l-1 7 9-11h-7z\"/>',bolt:'<path d=\"M13 3 4 14h7l-1 7 9-11h-7z\"/>',ban:'<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"m5.6 5.6 12.8 12.8\"/>'};return `<svg width=\"18\" height=\"18\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" stroke-linecap=\"round\">${p[k]}</svg>`}\n\nasync function loadUsers(){\n  try{\n    const r = await api('/api/admin/users')\n    $('#userCount').textContent = r.users.length+' 位用户'\n    $('#userList').innerHTML = r.users.length ? r.users.map(u=>`\n      <div class=\"row\">\n        <div class=\"av\">${u.avatarUrl?`<img src=\"${u.avatarUrl}\" alt=\"\">`:(u.nickname||u.email)[0].toUpperCase()}</div>\n        <div class=\"meta\"><b>${escapeHtml(u.nickname||u.email)}</b>\n        <span>${u.email}${u.signature?' · '+escapeHtml(u.signature):''} · 最近登录 ${u.lastLogin?fmtTime(u.lastLogin):'未登录'}</span></div>\n        <span class=\"badge ${u.disabled?'off':'on'}\">${u.disabled?'已禁用':'正常'}</span>\n        <button class=\"btn sm ${u.disabled?'':'danger'}\" onclick=\"setUser('${u.email}',${!u.disabled})\">${u.disabled?'启用':'禁用'}</button>\n      </div>`).join('') : '<div class=\"empty\">还没有用户注册</div>'\n  }catch(e){ $('#userList').innerHTML='<div class=\"empty\">加载失败：'+e.message+'</div>' }\n}\nasync function setUser(email,disabled){\n  try{ await api('/api/admin/users/status',{method:'POST',body:JSON.stringify({email,disabled})}); toast(disabled?'已禁用':'已启用'); loadUsers() }\n  catch(e){ toast(e.message,1) }\n}\nfunction escapeHtml(s){return String(s).replace(/[<>&\"]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;','\"':'&quot;'}[c]))}\n\nconst MAIL_PANELS={\n  dev:`<div class=\"hint\">开发模式下<b>不会真正发邮件</b>：验证码会显示在「概览」页，并打印到 Worker 日志（wrangler tail）。适合先联调登录流程。</div>`,\n  smtp:`<div class=\"hint\">推荐 QQ/163 邮箱：Worker 直连 SMTP，<b>不需要额外服务器</b>。\n    去邮箱「设置 → 账户」开启 <b>POP3/SMTP 服务</b>，生成<b>授权码</b>（16 位，不是登录密码）。\n    QQ <code>smtp.qq.com:465</code>、163 <code>smtp.163.com:465</code>、Outlook <code>smtp.office365.com:587</code>。</div>\n    <div class=\"g2 grid\">\n      <div class=\"field\"><label>发件人名称</label><input class=\"input\" id=\"s-name\" placeholder=\"乐库音乐\"></div>\n      <div class=\"field\"><label>发件邮箱（SMTP 账号）</label><input class=\"input\" id=\"s-user\" placeholder=\"you@qq.com\" inputmode=\"email\"></div>\n      <div class=\"field\"><label>SMTP 服务器</label><input class=\"input\" id=\"s-host\" placeholder=\"smtp.qq.com\"></div>\n      <div class=\"field\"><label>端口（465 加密 / 587）</label><input class=\"input\" id=\"s-port\" placeholder=\"465\" inputmode=\"numeric\"></div>\n    </div>\n    <div class=\"field\"><label>SMTP 授权码（不是登录密码）</label><input class=\"input\" id=\"s-pass\" type=\"password\" placeholder=\"授权码\"></div>`,\n  resend:`<div class=\"hint\">注册 <a href=\"https://resend.com\" target=\"_blank\">resend.com</a>（免费每月 3000 封），在 API Keys 页创建密钥；发件域名需在 Resend 验证。</div>\n    <div class=\"field\"><label>发件人名称</label><input class=\"input\" id=\"r-fromName\" placeholder=\"乐库音乐\"></div>\n    <div class=\"field\"><label>发件邮箱（已验证域名）</label><input class=\"input\" id=\"r-fromEmail\" placeholder=\"noreply@你的域名.com\" inputmode=\"email\"></div>\n    <div class=\"field\"><label>Resend API Key</label><input class=\"input\" id=\"r-key\" placeholder=\"re_xxxxxxxx\"></div>`,\n  mailer:`<div class=\"hint\">高级：自建 Node 邮件服务（nodemailer）。SMTP 账号在「SMTP 直连」面板里填写，邮件服务每分钟自动拉取；这里只填服务地址。</div>\n    <div class=\"field\"><label>邮件服务地址</label><input class=\"input\" id=\"m-url\" placeholder=\"https://mailer.你的域名.com\" inputmode=\"url\"></div>\n    <div class=\"field\"><label>共享密钥（与邮件服务 INTERNAL_SECRET 一致）</label><input class=\"input\" id=\"m-secret\" placeholder=\"随机长字符串\"></div>`\n}\nconst val=id=>{const n=document.getElementById(id);return n?n.value.trim():null}\nasync function loadSettings(){\n  SETTINGS = await api('/api/admin/settings')\n  const e=SETTINGS.email||{}\n  mailProvider(e.provider||'dev', true)\n  const t=SETTINGS.thresholds||{}\n  $('#t-qps').value=t.globalPerSec??20;$('#t-ip').value=t.ipPer10s??60;$('#t-ua').value=t.uaPer10s??120\n  $('#t-lfr').value=t.loginFailRate??0.5;$('#t-lms').value=t.loginMinSamples??10\n  $('#t-cfr').value=t.challengeFailRate??0.6;$('#t-cms').value=t.challengeMinSamples??10;$('#t-cd').value=t.cooldownSec??60\n}\nfunction mailProvider(p,silent){\n  document.querySelectorAll('#mailSeg button').forEach(b=>b.classList.toggle('active',b.dataset.p===p))\n  $('#mp-body').innerHTML = MAIL_PANELS[p]||MAIL_PANELS.dev\n  if(!silent && SETTINGS){ SETTINGS.email.provider=p }\n  // 渲染完面板后回填已保存的值\n  if(SETTINGS){ const e=SETTINGS.email||{}, sm=e.smtp||{}\n    if(val('s-name')!==null){ $('#s-name').value=sm.senderName||'';$('#s-user').value=sm.user||'';$('#s-host').value=sm.host||''\n      $('#s-port').value=sm.port||'465';$('#s-pass').value=sm.pass||'' }\n    if(val('r-key')!==null){ $('#r-fromName').value=e.fromName||'';$('#r-fromEmail').value=e.fromEmail||'';$('#r-key').value=e.resendKey||'' }\n    if(val('m-url')!==null){ $('#m-url').value=e.mailerUrl||'';$('#m-secret').value=e.mailerSecret||'' }\n  }\n}\nasync function saveEmail(){\n  const p=document.querySelector('#mailSeg button.active').dataset.p\n  const old=(SETTINGS&&SETTINGS.email)||{}; const oldSm=old.smtp||{}\n  // 只收集当前面板字段，其余通道保留原值，避免未渲染的输入框把配置清空\n  const email={provider:p,\n    fromName:old.fromName||'',fromEmail:old.fromEmail||'',resendKey:old.resendKey||'',\n    mailerUrl:old.mailerUrl||'',mailerSecret:old.mailerSecret||'',\n    smtp:{senderName:oldSm.senderName||'',user:oldSm.user||'',host:oldSm.host||'',port:oldSm.port||'465',pass:oldSm.pass||'',secure:true}}\n  if(p==='smtp'){\n    const host=val('s-host'),user=val('s-user'),pass=val('s-pass'),port=val('s-port')\n    if(!host||!user||!pass){toast('请填完发件邮箱、SMTP 服务器、授权码',1);return}\n    if(!/^\\d{2,3}$/.test(port)){toast('端口不正确（465 或 587）',1);return}\n    email.smtp={senderName:val('s-name')||'乐库音乐',user,host,port,pass,secure:true}\n  }else if(p==='resend'){\n    email.fromName=val('r-fromName')||'乐库音乐';email.fromEmail=val('r-fromEmail')||'';email.resendKey=val('r-key')||''\n  }else if(p==='mailer'){\n    email.mailerUrl=val('m-url')||'';email.mailerSecret=val('m-secret')||''\n  }\n  try{ await api('/api/admin/settings',{method:'PUT',body:JSON.stringify({email})}); toast('邮件配置已保存'); await loadSettings(); mailProvider(p,true) }\n  catch(e){ toast(e.message,1) }\n}\nasync function testEmail(){\n  const to=$('#testTo').value.trim(); if(!to){toast('请输入邮箱',1);return}\n  toast('正在发送…')\n  try{ const r=await api('/api/admin/email/test',{method:'POST',body:JSON.stringify({to})})\n    toast(r.channel==='dev'?'当前是开发模式：验证码去概览页查看':'测试邮件已发送，请查收') }\n  catch(e){ toast(e.message,1) }\n}\n\nasync function loadGuard(){\n  const d=await api('/api/admin/metrics')\n  GUARD=d.state\n  const st=d.state\n  const onNow=!!(st.attack&&st.manual)\n  $('#btnManual').textContent=onNow?'解除防护':'立即开启'\n  $('#btnManual').className='btn sm '+(onNow?'':'ghost')\n  $('#guardState').innerHTML = st.attack\n    ? `<div class=\"hint\" style=\"border-color:rgba(251,113,133,.4);color:#ffc4cf\">\n       <b>防护进行中${st.manual?'（手动）':'（自动）'}</b><br>${(st.reasons||[]).join('；')||'异常流量'}\n       ${st.cooldownLeft?`<br>指标已回落，${st.cooldownLeft} 秒后自动解除`:''}</div>`\n    : (st.muted\n      ? `<div class=\"hint\" style=\"border-color:rgba(250,204,21,.4);color:#ffe58a\">\n         <b>自动防护已暂停（手动解除后的冷静期）</b><br>${st.muteLeft} 秒后恢复自动检测，期间可随时点「立即开启」</div>`\n      : '<div class=\"hint\">当前流量正常，攻击模式未开启。自动检测始终运行。</div>')\n  const logs=d.logs.attack||[]\n  $('#attackLog').innerHTML=logs.length?logs.map(l=>`<div class=\"logline attack\"><time>${fmtTime(l.ts)}</time><span>${l.text}</span></div>`).join(''):'<div class=\"empty\">暂无防护事件</div>'\n}\nfunction manualToggle(){\n  // 按当前真实状态决定开/关（修复按钮文字变了但 onclick 仍是“开启”的问题）\n  const onNow = !!(GUARD && GUARD.attack && GUARD.manual)\n  manualAttack(!onNow)\n}\nasync function manualAttack(on){\n  try{ await api('/api/admin/attack',{method:'POST',body:JSON.stringify({on})}); toast(on?'防护已手动开启':'防护已解除'); await loadGuard() }\n  catch(e){ toast(e.message,1) }\n}\nasync function saveThresholds(){\n  const thresholds={globalPerSec:+$('#t-qps').value,ipPer10s:+$('#t-ip').value,uaPer10s:+$('#t-ua').value,\n    loginFailRate:+$('#t-lfr').value,loginMinSamples:+$('#t-lms').value,\n    challengeFailRate:+$('#t-cfr').value,challengeMinSamples:+$('#t-cms').value,cooldownSec:+$('#t-cd').value}\n  try{ await api('/api/admin/settings',{method:'PUT',body:JSON.stringify({thresholds})}); toast('阈值已保存') }\n  catch(e){ toast(e.message,1) }\n}\nasync function savePassword(){\n  const a=$('#newPw').value,b=$('#newPw2').value\n  if(a.length<6){toast('密码至少 6 位',1);return}\n  if(a!==b){toast('两次输入不一致',1);return}\n  try{ await api('/api/admin/settings',{method:'PUT',body:JSON.stringify({adminPassword:a})})\n    localStorage.setItem('admin_token',a); TOKEN=a; toast('密码已更新'); $('#newPw').value='';$('#newPw2').value='' }\n  catch(e){ toast(e.message,1) }\n}\n\n// 自动检测开关（关闭=阈值调到极大；开启=恢复默认阈值）\nconst DEFAULT_T={globalPerSec:20,ipPer10s:60,uaPer10s:120,loginFailRate:.5,loginMinSamples:10,challengeFailRate:.6,challengeMinSamples:10,cooldownSec:60}\n$('#tg-auto').addEventListener('click',async()=>{\n  const el=$('#tg-auto'); const on=!el.classList.contains('on')\n  el.classList.toggle('on',on)\n  const patch=on?DEFAULT_T:{globalPerSec:999999,ipPer10s:999999,uaPer10s:999999,loginMinSamples:999999,challengeMinSamples:999999}\n  try{ await api('/api/admin/settings',{method:'PUT',body:JSON.stringify({thresholds:patch})}); toast(on?'自动检测已开启':'自动检测已关闭'); await loadSettings() }\n  catch(e){ toast(e.message,1); el.classList.toggle('on',!on) }\n})\n\nif(TOKEN){ enterApp().catch(()=>logout()) }\n</script>\n</body>\n</html>\n"


export async function handleRequest(req, env, ctx) {
  const pathname = new URL(req.url).pathname
  const dynamic =
    pathname.startsWith('/api/') ||
    pathname.startsWith('/avatar/') ||
    pathname.startsWith('/internal/') ||
    pathname === '/admin' ||
    pathname === '/admin/' ||
    pathname === '/admin/index.html' ||
    pathname === '/challenge/verify' ||
    pathname === '/favicon.ico'
  if (!dynamic) return null
  return handle(req, env, ctx)
}
