'use strict';
/**
 * Pickup Logger — single-file Node.js app (no npm packages needed, Node 18+).
 *
 *   driver -> logs trips (date, guest names, pax, from, destination); sees ONLY their own
 *   admin  -> sees every trip, filters by driver / search / date, copies rows to Excel, manages drivers
 *
 * Run:   ADMIN_PASSWORD=choose-one SECRET_KEY=long-random node server.js
 * Env:   PORT, SECRET_KEY, ADMIN_USERNAME, ADMIN_PASSWORD, DATA_FILE, TZ_NAME, COOKIE_SECURE, TRUST_PROXY
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// ------------------------------------------------------------------ config
const PORT = Number(process.env.PORT) || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data', 'data.json');
const SECRET = process.env.SECRET_KEY || crypto.randomBytes(32).toString('hex');
const TZ_NAME = process.env.TZ_NAME || 'Africa/Dar_es_Salaam';
const TRUST_PROXY = process.env.TRUST_PROXY === '1' || !!process.env.RENDER;
const COOKIE_SECURE = process.env.COOKIE_SECURE !== undefined
  ? process.env.COOKIE_SECURE === '1'
  : (process.env.NODE_ENV === 'production' || !!process.env.RENDER);
const APP_NAME = process.env.APP_NAME || 'E.KILASI DRIVERS DAILY TRANSFERS';
const COMPANY = process.env.COMPANY_NAME || 'Bapta Safaris';
const SESSION_MS = 12 * 60 * 60 * 1000;
const PER_PAGE = 100, MAX_PAX = 500, MAX_COPY_ROWS = 5000;
if (!process.env.SECRET_KEY) console.warn('WARNING: SECRET_KEY not set. Everyone is signed out on every restart.');

// ----------------------------------------------------------------- storage
// One JSON file, held in memory, written atomically (temp file + rename) after every change.
let db = { seq: { user: 0, log: 0 }, users: [], logs: [] };
function load() {
  try { db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch (e) { if (e.code !== 'ENOENT') throw e; }
}
function save() {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DATA_FILE);
}

// -------------------------------------------------------------------- logo
// Put your logo next to this file as logo.png (or .jpg / .jpeg / .webp / .svg). No logo file = text only.
const LOGO_TYPES = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp', svg: 'image/svg+xml' };
let LOGO = null;
for (const ext of Object.keys(LOGO_TYPES)) {
  const f = path.join(__dirname, 'logo.' + ext);
  if (fs.existsSync(f)) { LOGO = { buf: fs.readFileSync(f), type: LOGO_TYPES[ext] }; break; }
}
const logoImg = cls => (LOGO ? `<img class="${cls}" src="/logo" alt="${esc(COMPANY)} logo">` : '');

// ---------------------------------------------------------------- passwords
function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function checkPw(pw, stored) {
  const [salt, hash] = String(stored).split(':');
  const a = crypto.scryptSync(pw, salt, 64), b = Buffer.from(hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const DUMMY = hashPw('not-a-real-password'); // equalises timing for unknown usernames

function addUser(username, fullName, password, role) {
  const u = { id: ++db.seq.user, username, full_name: fullName, pw: hashPw(password), pwv: 1, role, active: true };
  db.users.push(u);
  save();
  return u;
}
function bootstrapAdmin() {
  if (db.users.some(u => u.role === 'admin')) return;
  const username = process.env.ADMIN_USERNAME || 'admin';
  let pw = process.env.ADMIN_PASSWORD, generated = false;
  if (!pw) { pw = crypto.randomBytes(9).toString('base64url'); generated = true; }
  addUser(username, 'Administrator', pw, 'admin');
  if (generated) console.warn(`FIRST RUN: admin login created. username=${username} password=${pw} (change it under Account)`);
}

// ------------------------------------------------------------------ helpers
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const clean = (v, n) => String(v ?? '').replace(/\s+/g, ' ').trim().slice(0, n);
const likeIncl = (hay, needle) => String(hay).toLowerCase().includes(needle.toLowerCase());
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const todayStr = () => new Intl.DateTimeFormat('en-CA', { timeZone: TZ_NAME }).format(new Date());
function parseDate(s) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s || '')) return '';
  const d = new Date(s + 'T00:00:00Z');
  return !isNaN(d) && d.toISOString().slice(0, 10) === s ? s : '';
}
const fmtDate = iso => /^\d{4}-\d{2}-\d{2}$/.test(iso) ? iso.split('-').reverse().join('/') : iso;
const xlSafe = t => /^[=+\-@]/.test(t) ? "'" + t : t; // stop Excel treating text as a formula
const userById = id => db.users.find(u => u.id === id);

// ----------------------------------------------------------- session + ctx
const sign = p => { const b = Buffer.from(JSON.stringify(p)).toString('base64url'); return b + '.' + crypto.createHmac('sha256', SECRET).update(b).digest('base64url'); };
function unsign(tok) {
  if (!tok || !tok.includes('.')) return null;
  const [b, mac] = tok.split('.');
  if (!safeEq(mac, crypto.createHmac('sha256', SECRET).update(b).digest('base64url'))) return null;
  try { const p = JSON.parse(Buffer.from(b, 'base64url').toString()); return p.exp > Date.now() ? p : null; } catch { return null; }
}
function makeCtx(req, res, url) {
  const cookies = Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split(/=(.*)/s).slice(0, 2)).filter(c => c[0]));
  let s = unsign(cookies.sid), dirty = false;
  if (!s) { s = { csrf: crypto.randomBytes(16).toString('hex'), exp: Date.now() + SESSION_MS }; dirty = true; }
  const ctx = { req, res, url, q: url.searchParams, s, user: null, nonce: crypto.randomBytes(12).toString('base64'),
    touch() { dirty = true; }, get dirty() { return dirty; } };
  if (s.uid) {
    const u = db.users.find(x => x.id === s.uid && x.active && x.pwv === s.pwv);
    if (u) ctx.user = u; else { delete s.uid; delete s.pwv; dirty = true; }
  }
  return ctx;
}
function clientIp(req) {
  if (TRUST_PROXY) { const x = String(req.headers['x-forwarded-for'] || '').split(',').map(v => v.trim()).filter(Boolean); if (x.length) return x[x.length - 1]; }
  return req.socket.remoteAddress || '';
}
function send(ctx, status, body, type = 'text/html; charset=utf-8', extra = {}) {
  const h = {
    'Content-Type': type, 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin', 'Cache-Control': 'no-store',
    'Content-Security-Policy': `default-src 'none'; style-src 'nonce-${ctx.nonce}'; script-src 'nonce-${ctx.nonce}'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
    ...extra,
  };
  if (ctx.dirty) h['Set-Cookie'] = `sid=${sign(ctx.s)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_MS / 1000}${COOKIE_SECURE ? '; Secure' : ''}`;
  ctx.res.writeHead(status, h);
  ctx.res.end(body);
}
const redirect = (ctx, to) => send(ctx, 303, '', 'text/plain', { Location: to });
const flash = (ctx, t, m) => { (ctx.s.flash ||= []).push({ t, m }); ctx.touch(); };
const homeFor = u => (u.role === 'admin' ? '/admin' : '/driver');

function readForm(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > 65536) { reject({ status: 413 }); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(new URLSearchParams(Buffer.concat(chunks).toString())));
    req.on('error', reject);
  });
}

// ----------------------------------------------------------------- queries
function queryLogs(ctx, scopeDriverId) {
  const q = ctx.q;
  const f = { driver: clean(q.get('driver'), 80), q: clean(q.get('q'), 120), from: parseDate(q.get('from')),
              to: parseDate(q.get('to')), order: q.get('order') === 'asc' ? 'asc' : 'desc' };
  let rows = db.logs.filter(l => scopeDriverId == null || l.driverId === scopeDriverId) // row-level isolation
    .map(l => ({ ...l, driverName: userById(l.driverId).full_name, username: userById(l.driverId).username }));
  if (scopeDriverId == null && f.driver) rows = rows.filter(l => likeIncl(l.driverName, f.driver) || likeIncl(l.username, f.driver));
  if (f.q) rows = rows.filter(l => likeIncl(l.group, f.q) || likeIncl(l.from, f.q) || likeIncl(l.to, f.q));
  if (f.from) rows = rows.filter(l => l.date >= f.from);
  if (f.to) rows = rows.filter(l => l.date <= f.to);
  const dir = f.order === 'asc' ? 1 : -1;
  rows.sort((a, b) => dir * ((a.date < b.date ? -1 : a.date > b.date ? 1 : 0) || a.id - b.id));
  const page = Math.max(1, parseInt(q.get('page'), 10) || 1);
  return { f, rows, page, pages: Math.max(1, Math.ceil(rows.length / PER_PAGE)),
           pageRows: rows.slice((page - 1) * PER_PAGE, page * PER_PAGE),
           trips: rows.length, guests: rows.reduce((t, l) => t + l.pax, 0) };
}
// Tab-separated, no header: pastes into Excel as DATE | GROUP NAME (N pax) | FROM | DESTINATION [| DRIVER]
function sheetText(rows, withDriver) {
  return rows.slice(0, MAX_COPY_ROWS).map(l => [fmtDate(l.date), xlSafe(`${l.group} (${l.pax} pax)`), xlSafe(l.from), xlSafe(l.to),
    ...(withDriver ? [xlSafe(l.driverName)] : [])].join('\t')).join('\n');
}
const csvCell = v => { v = String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };

function readTrip(form) {
  const v = { date: clean(form.get('pickup_date'), 10), group: clean(form.get('group_name'), 150), pax: clean(form.get('pax'), 6),
              from: clean(form.get('pickup_location'), 150), to: clean(form.get('destination'), 150) };
  const errors = [];
  if (!parseDate(v.date)) errors.push('Enter a valid date.');
  if (!v.group) errors.push('Enter the guest names.');
  if (!v.from) errors.push('Enter where you picked them up (From).');
  if (!v.to) errors.push('Enter the destination.');
  const pax = /^\d+$/.test(v.pax) ? Number(v.pax) : NaN;
  if (!(pax >= 1 && pax <= MAX_PAX)) errors.push(`Number of guests must be a whole number from 1 to ${MAX_PAX}.`);
  return { v, pax, errors };
}

// --------------------------------------------------------------- templates
const CSS = `
:root{
  --bg:#f6f3ee; --card:#fff; --ink:#1c1917; --muted:#78716c; --line:#e7e2da;
  --accent:#c2410c; --accent-ink:#fff; --ok:#166534; --okbg:#dcfce7; --err:#991b1b; --errbg:#fee2e2;
  --radius:12px; --th:#6fb83f; --th-ink:#14240a; --zebra:#e9eefa;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#171412; --card:#211d1a; --ink:#f5f1ec; --muted:#a8a29e; --line:#37312c;
  --accent:#ea580c; --th:#4d8a2a; --th-ink:#f1fae9; --zebra:#27231f; --ok:#86efac; --okbg:#14532d; --err:#fecaca; --errbg:#7f1d1d;
}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
h1{font-size:1.6rem;margin:.2em 0 .6em;letter-spacing:-.02em}
h2{font-size:1.05rem;margin:0 0 .9em}
.wrap{max-width:1040px;margin:0 auto;padding:20px 16px 60px}
.muted{color:var(--muted)}
.bar{display:flex;flex-wrap:wrap;align-items:center;gap:8px 20px;padding:10px 16px;background:var(--card);border-bottom:1px solid var(--line)}
.brand{font-weight:800;font-size:1.15rem;text-decoration:none;color:var(--ink);letter-spacing:-.02em}
.brand span,.login h1 span{color:var(--accent)}
.bar nav{display:flex;gap:4px;flex:1}
.bar nav a{padding:6px 12px;border-radius:8px;text-decoration:none;color:var(--muted);font-weight:500}
.bar nav a[aria-current]{background:var(--bg);color:var(--ink)}
.who{display:flex;align-items:center;gap:10px;margin:0;font-size:.9rem}
.who em{font-style:normal;font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;background:var(--bg);padding:2px 7px;border-radius:99px;color:var(--muted);margin-left:4px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:20px;margin:0 0 16px}
.card.narrow{max-width:460px}
.login{max-width:380px;margin:12vh auto 0}
.login h1{font-size:2rem;margin:0}
label{display:flex;flex-direction:column;gap:5px;font-size:.88rem;font-weight:600;margin-bottom:12px}
label small{font-weight:400;color:var(--muted)}
input{font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);min-width:0;width:100%}
input:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:transparent}
.btn{font:inherit;font-weight:600;padding:10px 18px;border:1px solid var(--accent);background:var(--accent);color:var(--accent-ink);border-radius:8px;cursor:pointer;text-decoration:none;display:inline-block;text-align:center}
.btn:hover{filter:brightness(1.08)}
.btn.block{width:100%}
.btn.ghost{background:transparent;color:var(--ink);border-color:var(--line)}
.btn.danger{background:transparent;color:var(--err);border-color:var(--line)}
.btn.sm{padding:5px 11px;font-size:.85rem}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:0 14px}
.grid .full{grid-column:1/-1}
.filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:0 12px;align-items:end;margin-bottom:12px}
.filters .actions{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:16px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:14px 16px}
.stat b{display:block;font-size:1.9rem;line-height:1.1;font-variant-numeric:tabular-nums}
.stat span{color:var(--muted);font-size:.85rem}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.93rem}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);white-space:nowrap}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
td form{margin:0}
form.inline{display:flex;gap:6px}
form.inline input{padding:5px 9px;min-width:120px}
.pill{font-size:.75rem;font-weight:600;padding:2px 9px;border-radius:99px}
.pill.on{background:var(--okbg);color:var(--ok)} .pill.off{background:var(--errbg);color:var(--err)}
.flash{padding:11px 14px;border-radius:8px;margin-bottom:14px;font-weight:500}
.flash.ok{background:var(--okbg);color:var(--ok)} .flash.error{background:var(--errbg);color:var(--err)}
.empty{color:var(--muted);text-align:center;padding:24px 0;margin:0}
.pager{display:flex;justify-content:center;align-items:center;gap:14px;margin-top:14px;color:var(--muted);font-size:.9rem}
@media (max-width:620px){
  .grid{grid-template-columns:1fr}
  .who span{display:none}
  .bar{padding:8px 12px}
  td,th{padding:8px 6px}
}

select{font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);width:100%}
.head{display:flex;flex-wrap:wrap;gap:10px 16px;justify-content:space-between;align-items:center;margin-bottom:12px}
.head h2{margin:0}
.actions{display:flex;gap:8px;flex-wrap:wrap}
.grid .actions{align-self:end}
.offscreen{position:absolute;left:-9999px;top:0;width:1px;height:1px;opacity:0}
.small{font-size:.85rem;margin:12px 0 0}
table.sheet thead th{background:var(--th);color:var(--th-ink);text-align:center;font-size:.8rem}
table.sheet tbody tr:nth-child(odd){background:var(--zebra)}
table.sheet td{border:1px solid var(--line)}
td.gname{white-space:normal;min-width:200px}
td.row-actions{white-space:nowrap}
td.row-actions form{display:inline;margin-left:6px}
a.btn.sm{padding:5px 11px;font-size:.85rem}
.grid>.btn{align-self:end}
.brand{display:flex;align-items:center;gap:10px;font-size:.95rem;line-height:1.15;letter-spacing:0;text-decoration:none;color:var(--ink)}
.brand span,.login h1 span{color:inherit}
img.logo{height:38px;width:auto;max-width:90px;object-fit:contain;flex:none}
img.logo-big{display:block;height:84px;width:auto;max-width:100%;object-fit:contain;margin:0 auto 12px}
.login{text-align:center}
.login h1{font-size:1.25rem;letter-spacing:.02em;margin:0 0 4px}
.login form{text-align:left}
@media (max-width:620px){.brand{font-size:.8rem;max-width:62vw}img.logo{height:32px}}
`;
const CLIENT_JS = `
// Confirm before deleting.
document.querySelectorAll("form[data-confirm]").forEach(f =>
  f.addEventListener("submit", e => { if (!confirm(f.dataset.confirm)) e.preventDefault(); }));

// "Copy for Excel": tab-separated text pastes into separate cells.
document.querySelectorAll("[data-copy]").forEach(btn => {
  const label = btn.textContent;
  const box = document.getElementById(btn.dataset.copy);
  const done = ok => {
    btn.textContent = ok ? "Copied " + btn.dataset.rows + " rows" : "Copy failed: press Ctrl+C";
    setTimeout(() => { btn.textContent = label; }, 2500);
  };
  const fallback = () => {
    box.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (e) {}
    done(ok);
  };
  btn.addEventListener("click", () => {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(box.value).then(() => done(true), fallback);
    } else { fallback(); }
  });
});
`;
const FAVICON = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%23c2410c'/%3E%3Cpath d='M8 17h16M8 17l4-5m-4 5l4 5' stroke='white' stroke-width='3' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E";

const csrf = ctx => `<input type="hidden" name="csrf_token" value="${ctx.s.csrf}">`;

function layout(ctx, title, body) {
  const fl = ctx.s.flash || [];
  if (fl.length) { delete ctx.s.flash; ctx.touch(); }
  const u = ctx.user, p = ctx.url.pathname;
  const cur = href => (p === href ? ' aria-current="page"' : '');
  const nav = !u ? '' : `<header class="bar"><a class="brand" href="/">${logoImg('logo')}<span>${esc(APP_NAME)}</span></a><nav>
    ${u.role === 'admin' ? `<a href="/admin"${cur('/admin')}>All trips</a><a href="/admin/drivers"${cur('/admin/drivers')}>Drivers</a>` : `<a href="/driver"${cur('/driver')}>My trips</a>`}
    <a href="/account"${cur('/account')}>Account</a></nav>
    <form method="post" action="/logout" class="who">${csrf(ctx)}<span>${esc(u.full_name)} <em>${u.role}</em></span><button class="btn ghost sm">Sign out</button></form></header>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · ${esc(APP_NAME)}</title><link rel="icon" href="${FAVICON}">
<style nonce="${ctx.nonce}">${CSS}</style></head><body>${nav}
<main class="wrap">${fl.map(f => `<div class="flash ${f.t}" role="alert">${esc(f.m)}</div>`).join('')}${body}</main>
<script nonce="${ctx.nonce}">${CLIENT_JS}</script></body></html>`;
}
const page = (ctx, status, title, body) => send(ctx, status, layout(ctx, title, body));
const errorPage = (ctx, status, msg) => page(ctx, status, String(status),
  `<section class="card narrow"><h1>${status}</h1><p>${esc(msg)}</p><a class="btn" href="/">Back to start</a></section>`);

function tripFields(v, places) {
  return `<label for="f-date">Date<input id="f-date" type="date" name="pickup_date" value="${esc(v.date || todayStr())}" required></label>
<label for="f-group">Guest names<input id="f-group" name="group_name" maxlength="150" placeholder="e.g. Susanne Horster" value="${esc(v.group)}" autocomplete="off" required></label>
<label for="f-pax">Number of guests<input id="f-pax" type="number" name="pax" min="1" max="${MAX_PAX}" inputmode="numeric" value="${esc(v.pax)}" required></label>
<label for="f-from">From<input id="f-from" name="pickup_location" maxlength="150" list="places" placeholder="e.g. JRO" value="${esc(v.from)}" autocomplete="off" required></label>
<label for="f-to">Destination<input id="f-to" name="destination" maxlength="150" list="places" placeholder="e.g. Giraffe Manor" value="${esc(v.to)}" autocomplete="off" required></label>
${places ? `<datalist id="places">${places.map(x => `<option value="${esc(x)}">`).join('')}</datalist>` : ''}`;
}
function copyButton(rows, withDriver) {
  if (!rows.length) return '';
  const n = Math.min(rows.length, MAX_COPY_ROWS);
  return `<textarea id="copybox" class="offscreen" readonly tabindex="-1" aria-hidden="true">${esc(sheetText(rows, withDriver))}</textarea>
<button type="button" class="btn ghost" data-copy="copybox" data-rows="${n}">Copy ${n} row${n === 1 ? '' : 's'} for Excel</button>`;
}
function filtersForm(ctx, f, admin) {
  return `<form method="get" class="filters">
  ${admin ? `<label for="x-driver">Driver<input id="x-driver" name="driver" value="${esc(f.driver)}" list="driver-list" placeholder="Name or username">
    <datalist id="driver-list">${db.users.filter(u => u.role === 'driver').map(u => `<option value="${esc(u.full_name)}">`).join('')}</datalist></label>` : ''}
  <label for="x-q">Search<input id="x-q" name="q" value="${esc(f.q)}" placeholder="Guest, from or destination"></label>
  <label for="x-from">From date<input id="x-from" type="date" name="from" value="${esc(f.from)}"></label>
  <label for="x-to">To date<input id="x-to" type="date" name="to" value="${esc(f.to)}"></label>
  <label for="x-order">Order<select id="x-order" name="order"><option value="desc"${f.order === 'desc' ? ' selected' : ''}>Newest first</option><option value="asc"${f.order === 'asc' ? ' selected' : ''}>Oldest first</option></select></label>
  <div class="actions"><button class="btn">Apply</button><a class="btn ghost" href="${ctx.url.pathname}">Reset</a></div></form>`;
}
function pager(ctx, r) {
  if (r.pages <= 1) return '';
  const link = (n, label) => { const p = new URLSearchParams(ctx.url.search); p.set('page', n); return `<a class="btn ghost sm" href="?${esc(p.toString())}">${label}</a>`; };
  return `<nav class="pager" aria-label="Pages">${r.page > 1 ? link(r.page - 1, '← Previous') : ''}<span>Page ${r.page} of ${r.pages}</span>${r.page < r.pages ? link(r.page + 1, 'Next →') : ''}</nav>`;
}

// ------------------------------------------------------------------- pages
function loginPage(ctx, username = '', status = 200) {
  return send(ctx, status, layout(ctx, 'Sign in', `<section class="login card">${logoImg('logo-big')}<h1>${esc(APP_NAME)}</h1>
  <p class="muted">${esc(COMPANY)}. Sign in to log and review trips.</p>
  <form method="post" action="/login">${csrf(ctx)}
    <label for="l-user">Username<input id="l-user" name="username" value="${esc(username)}" autocomplete="username" autocapitalize="none" required autofocus></label>
    <label for="l-pass">Password<input id="l-pass" name="password" type="password" autocomplete="current-password" required></label>
    <button class="btn block">Sign in</button></form></section>`), 'text/html; charset=utf-8');
}

function driverPage(ctx, form = {}, status = 200) {
  const me = ctx.user, r = queryLogs(ctx, me.id), today = todayStr();
  const mine = db.logs.filter(l => l.driverId === me.id && l.date === today);
  const places = [...new Set(['JRO', 'ARK', ...db.logs.filter(l => l.driverId === me.id).flatMap(l => [l.from, l.to])])].sort();
  const rows = r.pageRows.map(l => `<tr><td>${fmtDate(l.date)}</td><td class="gname">${esc(l.group)}</td><td class="n">${l.pax}</td><td>${esc(l.from)}</td><td>${esc(l.to)}</td>
    <td class="row-actions"><a class="btn ghost sm" href="/driver/logs/${l.id}/edit">Edit</a>
    <form method="post" action="/driver/logs/${l.id}/delete" data-confirm="Delete this trip?">${csrf(ctx)}<button class="btn danger sm">Delete</button></form></td></tr>`).join('');
  const body = `<h1>My trips</h1>
  <div class="stats"><div class="stat"><b>${mine.length}</b><span>trips today</span></div><div class="stat"><b>${mine.reduce((t, l) => t + l.pax, 0)}</b><span>guests today</span></div>
  <div class="stat"><b>${r.trips}</b><span>trips in list</span></div><div class="stat"><b>${r.guests}</b><span>guests in list</span></div></div>
  <section class="card"><h2>Add a trip</h2><form method="post" action="/driver/logs" class="grid">${csrf(ctx)}${tripFields(form, places)}<button class="btn">Save trip</button></form></section>
  <section class="card"><div class="head"><h2>My list</h2>${copyButton(r.rows, false)}</div>${filtersForm(ctx, r.f, false)}
  ${r.rows.length ? `<div class="scroll"><table class="sheet"><thead><tr><th>Date</th><th>Group name</th><th class="n">Pax</th><th>From</th><th>Destination</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>${pager(ctx, r)}`
    : '<p class="empty">No trips yet. Add your first one above.</p>'}</section>`;
  return send(ctx, status, layout(ctx, 'My trips', body));
}

function adminPage(ctx) {
  const r = queryLogs(ctx, null);
  const by = new Map();
  r.rows.forEach(l => { const e = by.get(l.driverName) || { trips: 0, guests: 0 }; e.trips++; e.guests += l.pax; by.set(l.driverName, e); });
  const rows = r.pageRows.map(l => `<tr><td>${fmtDate(l.date)}</td><td class="gname">${esc(l.group)}</td><td class="n">${l.pax}</td><td>${esc(l.from)}</td><td>${esc(l.to)}</td><td>${esc(l.driverName)}</td></tr>`).join('');
  const qs = ctx.url.search;
  const body = `<h1>All trips</h1>
  <div class="stats"><div class="stat"><b>${r.trips}</b><span>trips</span></div><div class="stat"><b>${r.guests}</b><span>guests</span></div><div class="stat"><b>${by.size}</b><span>drivers in list</span></div></div>
  <section class="card"><h2>Filter</h2>${filtersForm(ctx, r.f, true)}</section>
  ${by.size ? `<section class="card"><h2>By driver</h2><div class="scroll"><table><thead><tr><th>Driver</th><th class="n">Trips</th><th class="n">Guests</th></tr></thead><tbody>
    ${[...by].sort((a, b) => b[1].trips - a[1].trips).map(([n, v]) => `<tr><td>${esc(n)}</td><td class="n">${v.trips}</td><td class="n">${v.guests}</td></tr>`).join('')}</tbody></table></div></section>` : ''}
  <section class="card"><div class="head"><h2>Trips</h2><div class="actions">${copyButton(r.rows, true)}${r.rows.length ? `<a class="btn ghost" href="/admin/export.csv${esc(qs)}">Download CSV</a>` : ''}</div></div>
  ${r.rows.length ? `<div class="scroll"><table class="sheet"><thead><tr><th>Date</th><th>Group name</th><th class="n">Pax</th><th>From</th><th>Destination</th><th>Driver</th></tr></thead><tbody>${rows}</tbody></table></div>${pager(ctx, r)}
  <p class="muted small">"Copy for Excel" copies all ${Math.min(r.rows.length, MAX_COPY_ROWS)} rows in this filter, not just this page. Paste into Excel and each part lands in its own column.</p>`
    : '<p class="empty">No trips match these filters.</p>'}</section>`;
  return send(ctx, 200, layout(ctx, 'All trips', body));
}

function driversPage(ctx) {
  const list = db.users.filter(u => u.role === 'driver').sort((a, b) => (b.active - a.active) || a.full_name.localeCompare(b.full_name));
  const rows = list.map(d => `<tr><td>${esc(d.full_name)}</td><td>${esc(d.username)}</td><td class="n">${db.logs.filter(l => l.driverId === d.id).length}</td>
    <td><span class="pill ${d.active ? 'on' : 'off'}">${d.active ? 'Active' : 'Disabled'}</span></td>
    <td><form method="post" action="/admin/drivers/${d.id}/password" class="inline">${csrf(ctx)}<input name="password" minlength="8" placeholder="New password" autocomplete="off" required><button class="btn ghost sm">Set</button></form></td>
    <td><form method="post" action="/admin/drivers/${d.id}/toggle">${csrf(ctx)}<button class="btn ghost sm">${d.active ? 'Disable' : 'Enable'}</button></form></td></tr>`).join('');
  return send(ctx, 200, layout(ctx, 'Drivers', `<h1>Drivers</h1>
  <section class="card"><h2>Add a driver</h2><form method="post" class="grid">${csrf(ctx)}
    <label for="n-name">Full name<input id="n-name" name="full_name" maxlength="80" required></label>
    <label for="n-user">Username<input id="n-user" name="username" maxlength="40" autocapitalize="none" required></label>
    <label for="n-pass">Temporary password (8+ characters)<input id="n-pass" name="password" minlength="8" autocomplete="off" required></label>
    <button class="btn">Create driver</button></form></section>
  <section class="card"><h2>All drivers</h2>${list.length ? `<div class="scroll"><table><thead><tr><th>Name</th><th>Username</th><th class="n">Trips</th><th>Status</th><th>Reset password</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
    : '<p class="empty">No drivers yet. Add the first one above.</p>'}</section>`));
}

// ------------------------------------------------------------------ router
const attempts = new Map(); // "ip|username" -> [timestamps]

async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/healthz') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('ok'); }
  if (url.pathname === '/logo' && LOGO) {
    res.writeHead(200, { 'Content-Type': LOGO.type, 'Cache-Control': 'public, max-age=86400', 'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'" });
    return res.end(LOGO.buf);
  }
  const ctx = makeCtx(req, res, url);
  const p = url.pathname, m = req.method;
  let form = null;
  if (m === 'POST') {
    form = await readForm(req);
    if (!safeEq(form.get('csrf_token') || '', ctx.s.csrf)) return errorPage(ctx, 400, 'Invalid or missing security token. Reload the page and try again.');
  } else if (m !== 'GET') return errorPage(ctx, 405, 'Method not allowed.');

  const need = role => { if (!ctx.user) { redirect(ctx, '/login'); return false; } if (role && ctx.user.role !== role) { errorPage(ctx, 403, "You don't have access to this page."); return false; } return true; };
  let mt;

  if (p === '/' && m === 'GET') return redirect(ctx, ctx.user ? homeFor(ctx.user) : '/login');

  // ---- auth
  if (p === '/login') {
    if (ctx.user) return redirect(ctx, homeFor(ctx.user));
    if (m === 'GET') return loginPage(ctx);
    const username = clean(form.get('username'), 60), key = clientIp(req) + '|' + username.toLowerCase(), now = Date.now();
    const recent = (attempts.get(key) || []).filter(t => now - t < 900000);
    attempts.set(key, recent);
    if (recent.length >= 5) { flash(ctx, 'error', 'Too many failed attempts. Try again in 15 minutes.'); return loginPage(ctx, username, 429); }
    const u = db.users.find(x => x.username.toLowerCase() === username.toLowerCase() && x.active);
    const ok = checkPw(form.get('password') || '', u ? u.pw : DUMMY);
    if (u && ok) {
      attempts.delete(key);
      ctx.s = { csrf: crypto.randomBytes(16).toString('hex'), exp: Date.now() + SESSION_MS, uid: u.id, pwv: u.pwv }; // fresh session on login
      ctx.touch();
      return redirect(ctx, homeFor(u));
    }
    recent.push(now);
    flash(ctx, 'error', 'Incorrect username or password.');
    return loginPage(ctx, username, 401);
  }
  if (p === '/logout' && m === 'POST') { ctx.s = { csrf: crypto.randomBytes(16).toString('hex'), exp: Date.now() + SESSION_MS }; ctx.touch(); return redirect(ctx, '/login'); }

  if (p === '/account') {
    if (!need()) return;
    if (m === 'POST') {
      const [cur, nw, conf] = ['current', 'new', 'confirm'].map(k => form.get(k) || '');
      if (!checkPw(cur, ctx.user.pw)) flash(ctx, 'error', 'Current password is incorrect.');
      else if (nw.length < 8) flash(ctx, 'error', 'New password must be at least 8 characters.');
      else if (nw !== conf) flash(ctx, 'error', 'New passwords do not match.');
      else {
        ctx.user.pw = hashPw(nw); ctx.user.pwv++; save();           // pwv bump signs out other devices
        ctx.s.pwv = ctx.user.pwv; ctx.touch(); flash(ctx, 'ok', 'Password updated.');
      }
      return redirect(ctx, '/account');
    }
    return send(ctx, 200, layout(ctx, 'Account', `<section class="card narrow"><h1>Change password</h1><form method="post">${csrf(ctx)}
      <label for="a-cur">Current password<input id="a-cur" type="password" name="current" autocomplete="current-password" required></label>
      <label for="a-new">New password (8+ characters)<input id="a-new" type="password" name="new" minlength="8" autocomplete="new-password" required></label>
      <label for="a-conf">Confirm new password<input id="a-conf" type="password" name="confirm" minlength="8" autocomplete="new-password" required></label>
      <button class="btn">Update password</button></form></section>`));
  }

  // ---- driver
  if (p === '/driver' && m === 'GET') { if (!need('driver')) return; return driverPage(ctx); }
  if (p === '/driver/logs' && m === 'POST') {
    if (!need('driver')) return;
    const { v, pax, errors } = readTrip(form);
    if (errors.length) { errors.forEach(e => flash(ctx, 'error', e)); return driverPage(ctx, v, 400); }
    db.logs.push({ id: ++db.seq.log, driverId: ctx.user.id, date: v.date, group: v.group, pax, from: v.from, to: v.to });
    save(); flash(ctx, 'ok', 'Saved.');
    return redirect(ctx, '/driver');
  }
  if ((mt = p.match(/^\/driver\/logs\/(\d+)\/(edit|delete)$/))) {
    if (!need('driver')) return;
    const id = Number(mt[1]);
    const log = db.logs.find(l => l.id === id && l.driverId === ctx.user.id); // drivers can only touch their own rows
    if (!log) return errorPage(ctx, 404, 'Not found.');
    if (mt[2] === 'delete') {
      if (m !== 'POST') return errorPage(ctx, 405, 'Method not allowed.');
      db.logs = db.logs.filter(l => l !== log); save(); flash(ctx, 'ok', 'Trip deleted.');
      return redirect(ctx, '/driver');
    }
    let v = { date: log.date, group: log.group, pax: log.pax, from: log.from, to: log.to };
    if (m === 'POST') {
      const r = readTrip(form);
      if (!r.errors.length) { Object.assign(log, { date: r.v.date, group: r.v.group, pax: r.pax, from: r.v.from, to: r.v.to }); save(); flash(ctx, 'ok', 'Changes saved.'); return redirect(ctx, '/driver'); }
      r.errors.forEach(e => flash(ctx, 'error', e)); v = r.v;
    }
    return send(ctx, 200, layout(ctx, 'Edit trip', `<section class="card"><h1>Edit trip</h1><form method="post" class="grid">${csrf(ctx)}${tripFields(v)}
      <div class="actions"><button class="btn">Save changes</button><a class="btn ghost" href="/driver">Cancel</a></div></form></section>`));
  }

  // ---- admin
  if (p === '/admin' && m === 'GET') { if (!need('admin')) return; return adminPage(ctx); }
  if (p === '/admin/export.csv' && m === 'GET') {
    if (!need('admin')) return;
    const r = queryLogs(ctx, null);
    const out = ['DATE,GROUP NAME,PAX,FROM,DESTINATION,DRIVER', ...r.rows.map(l => [fmtDate(l.date), xlSafe(l.group), l.pax, xlSafe(l.from), xlSafe(l.to), xlSafe(l.driverName)].map(csvCell).join(','))].join('\r\n');
    return send(ctx, 200, '﻿' + out, 'text/csv; charset=utf-8', { 'Content-Disposition': 'attachment; filename=pickup-logs.csv' });
  }
  if (p === '/admin/drivers') {
    if (!need('admin')) return;
    if (m === 'POST') {
      const username = clean(form.get('username'), 40), name = clean(form.get('full_name'), 80), pw = form.get('password') || '';
      if (!username || !name) flash(ctx, 'error', 'Name and username are required.');
      else if (pw.length < 8) flash(ctx, 'error', 'Password must be at least 8 characters.');
      else if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase())) flash(ctx, 'error', 'That username is already taken.');
      else { addUser(username, name, pw, 'driver'); flash(ctx, 'ok', `Driver ${name} created.`); return redirect(ctx, '/admin/drivers'); }
    }
    return driversPage(ctx);
  }
  if ((mt = p.match(/^\/admin\/drivers\/(\d+)\/(toggle|password)$/)) && m === 'POST') {
    if (!need('admin')) return;
    const d = db.users.find(u => u.id === Number(mt[1]) && u.role === 'driver');
    if (!d) return errorPage(ctx, 404, 'Not found.');
    if (mt[2] === 'toggle') d.active = !d.active;
    else if ((form.get('password') || '').length < 8) { flash(ctx, 'error', 'Password must be at least 8 characters.'); return redirect(ctx, '/admin/drivers'); }
    else { d.pw = hashPw(form.get('password')); d.pwv++; flash(ctx, 'ok', 'Password reset.'); }
    save();
    return redirect(ctx, '/admin/drivers');
  }

  return errorPage(ctx, 404, 'Page not found.');
}

const server = http.createServer((req, res) => {
  handle(req, res).catch(err => {
    if (err && err.status === 413) { res.writeHead(413); return res.end('Too large'); }
    console.error(err);
    if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Server error');
  });
});

load();
bootstrapAdmin();
module.exports = { server };
if (require.main === module) {
  server.listen(PORT, '0.0.0.0', () => console.log(`Pickup Logger running on http://localhost:${PORT}`);
}