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
const R2_BINDING = 'AVATAR_BUCKET'
const CODE_TTL = 300          // 验证码 5 分钟
const RESEND_COOLDOWN = 60    // 60 秒重发限制
const TOKEN_TTL = 30 * 86400    // 用户 token 30 天
const VERIFY_TTL = 1800       // 人机验证 30 分钟
const AVATAR_MAX = 200 * 1024

const DEFAULT_SETTINGS = {
  adminPassword: 'admin123',
  email: {
    provider: 'dev',          // dev | resend | mailer
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

async function sendEmail(env, to, code) {
  const s = await getSettings(env)
  const e = s.email
  const mail = codeEmail(code, Math.floor(CODE_TTL / 60))

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
  const st = Object.assign({ on: false, manual: false, reasons: [], since: 0, calmSince: 0 },
    JSON.parse((await env[KV_BINDING].get('attack')) || '{}'))
  let changed = false
  if (st.on && st.manual) { /* 人工开启只能人工解除 */ }
  else if (!st.on && breaches.length) {
    Object.assign(st, { on: true, manual: false, reasons: breaches, since: now, calmSince: 0 }); changed = true
    await pushLog(env, 'attack', '自动开启：' + breaches.join('；'))
  } else if (st.on && !st.manual) {
    if (breaches.length) { st.reasons = breaches; st.calmSince = 0 }
    else {
      if (!st.calmSince) st.calmSince = now
      if (now - st.calmSince >= t.cooldownSec * 1000) {
        Object.assign(st, { on: false, reasons: [], since: 0, calmSince: 0 }); changed = true
        await pushLog(env, 'attack', '流量恢复正常，自动解除防护')
      }
    }
  }
  if (changed) await env[KV_BINDING].put('attack', JSON.stringify(st))
  const out = {
    on: st.on, manual: st.manual, reasons: st.reasons, since: st.since,
    cooldownLeft: st.on && st.calmSince ? Math.max(0, t.cooldownSec - Math.floor((now - st.calmSince) / 1000)) : 0,
    metrics
  }
  evalCache = { at: now, state: out }
  return out
}
async function setManual(env, on) {
  const now = Date.now()
  const st = on
    ? { on: true, manual: true, reasons: ['管理员手动开启'], since: now, calmSince: 0 }
    : { on: false, manual: false, reasons: [], since: 0, calmSince: 0 }
  await env[KV_BINDING].put('attack', JSON.stringify(st))
  await pushLog(env, 'attack', on ? '管理员手动开启防护' : '管理员手动解除防护')
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

  // ---- 管理后台页面 ----
  // 管理后台静态页（Pages 静态资源）
  if (p === '/admin' || p === '/admin/' || p === '/admin/index.html') {
    const assetUrl = new URL('/admin/index.html', url).href
    return env.ASSETS.fetch(new Request(assetUrl, req))
  }
  if (p === '/') return Response.redirect(url.origin + '/admin/', 302)
  if (p === '/favicon.ico') return new Response(null, { status: 204 })

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
  if (method === 'GET' && p === '/api/ping') return json({ ok: true, ts: Date.now() })

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
      state: { attack: st.on, manual: st.manual, reasons: st.reasons, cooldownLeft: st.cooldownLeft },
      qps: { total: series.reduce((a, b) => a + b, 0), qps: st.metrics.qps, series },
      metrics: st.metrics,
      users: { total: parsed.length, today: parsed.filter(u => (u.lastLogin || 0) >= today.getTime()).length, disabled: parsed.filter(u => u.disabled).length },
      devcodes, logs: { attack: logAttack, ops: logOps.slice(0, 20) }
    })
  }

  if (p === '/api/admin/attack' && method === 'POST') {
    const b = await req.json().catch(() => ({}))
    const st = await setManual(env, !!b.on)
    return json({ state: { attack: st.on, manual: st.manual, reasons: st.reasons, cooldownLeft: st.cooldownLeft } })
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
      const r = await sendEmail(env, to, '888888')
      return json({ ok: true, ...r })
    } catch (e) {
      return err(e.message, 502)
    }
  }

  return err('接口不存在', 404)
}

// Pages 版后台 HTML 由 env.ASSETS 静态资源提供
