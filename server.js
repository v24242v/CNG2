/* CNG Mileage Board — server
   Zero npm dependencies (Node 18+). Serves index.html and stores all data on the server.
   Data lives in DATA_DIR (default ./data). On Render this MUST be a persistent disk,
   otherwise everything is wiped on each redeploy/restart. */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const KV_DIR = path.join(DATA_DIR, 'kv');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const LOGS_FILE = path.join(DATA_DIR, 'logs.json');
const INDEX_FILE = path.join(__dirname, 'index.html');
const SALT = ':cngboard-v1';
const MAX_BODY = 25 * 1024 * 1024;
const MAX_LOGS = 5000;
const SESSION_IDLE_MS = 12 * 60 * 60 * 1000;
const MAX_FAILS = 5, LOCK_MS = 60 * 1000;

fs.mkdirSync(KV_DIR, { recursive: true });

const DEFAULT_USERS = {
  vc1705: { display: 'vc1705', role: 'superadmin', hash: '8bdec9d983a1a3f9454f9dec36d8440398e702bf98029cfca686b638995e65db' },
  admin:  { display: 'Admin',  role: 'user',       hash: '21e7fc8075b7684a41b63c2794144c8540a400e30e35b29d9694752e5b349842' }
};

function readJSON(file, fb) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return fb; } }
function writeAtomic(file, text) { const tmp = file + '.' + process.pid + '.tmp'; fs.writeFileSync(tmp, text); fs.renameSync(tmp, file); }
function writeJSON(file, obj) { writeAtomic(file, JSON.stringify(obj)); }

if (!fs.existsSync(USERS_FILE)) writeJSON(USERS_FILE, DEFAULT_USERS);
const hash = (key, pw) => crypto.createHash('sha256').update(key + ':' + pw + SALT).digest('hex');
const users = () => readJSON(USERS_FILE, DEFAULT_USERS);

/* ---------- activity log ---------- */
let logs = readJSON(LOGS_FILE, []);
let logTimer = null;
function saveLogsSoon() { clearTimeout(logTimer); logTimer = setTimeout(() => writeJSON(LOGS_FILE, logs), 500); }
function addLog(user, type, detail, ip) {
  const now = Date.now();
  if (type === 'act') {
    for (let i = logs.length - 1; i >= Math.max(0, logs.length - 15); i--) {
      const l = logs[i];
      if (now - l.t > 120000) break;
      if (l.type === 'act' && l.user === user && l.detail === detail) { l.t = now; l.count = (l.count || 1) + 1; saveLogsSoon(); return; }
    }
  }
  logs.push({ t: now, user, type, detail: String(detail || '').slice(0, 300), ip: ip || '', count: 1 });
  if (logs.length > MAX_LOGS) logs.splice(0, logs.length - MAX_LOGS);
  saveLogsSoon();
}

/* ---------- sessions & lockout (in memory; a server restart just asks people to sign in again) ---------- */
const sessions = new Map();
const fails = new Map();
function getSession(req) {
  const m = /^Bearer (\w+)$/.exec(req.headers['authorization'] || '');
  if (!m) return null;
  const s = sessions.get(m[1]);
  if (!s) return null;
  if (Date.now() - s.last > SESSION_IDLE_MS) { sessions.delete(m[1]); return null; }
  s.last = Date.now();
  return s;
}
const clientIp = req => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

/* ---------- key/value files: one file per key, name = hex of key (no collisions, no path tricks) ---------- */
const kvFile = (key, shared) => path.join(KV_DIR, (shared ? 's_' : 'p_') + Buffer.from(key, 'utf8').toString('hex') + '.json');

/* ---------- http helpers ---------- */
function send(res, code, body, type) {
  res.writeHead(code, { 'Content-Type': type || 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > MAX_BODY) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;

    if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
      return send(res, 200, fs.readFileSync(INDEX_FILE), 'text/html; charset=utf-8');
    }
    if (!p.startsWith('/api/')) return send(res, 404, 'Not found', 'text/plain');
    const route = p.slice(5);
    const ip = clientIp(req);

    if (route === 'ping') return send(res, 200, { app: 'cng-board', ok: true });

    if (route === 'login' && req.method === 'POST') {
      const { username, password } = JSON.parse(await readBody(req) || '{}');
      const key = String(username || '').trim().toLowerCase();
      const fkey = key + '|' + ip;
      const f = fails.get(fkey) || { count: 0, until: 0 };
      if (f.until > Date.now()) return send(res, 429, { error: `Too many wrong attempts. Try again in ${Math.ceil((f.until - Date.now()) / 1000)}s.` });
      const u = users()[key];
      if (!u || hash(key, String(password || '')) !== u.hash) {
        f.count++; if (f.count >= MAX_FAILS) { f.until = Date.now() + LOCK_MS; f.count = 0; }
        fails.set(fkey, f);
        const typed = String(username || '').trim().slice(0, 40) || '(blank)';
        addLog(typed, 'fail', `Wrong credentials for "${typed}"`, ip);
        return send(res, 401, { error: 'Invalid username or password.' });
      }
      fails.delete(fkey);
      const token = crypto.randomBytes(24).toString('hex');
      sessions.set(token, { key, display: u.display, role: u.role, last: Date.now() });
      addLog(u.display, 'login', u.role === 'superadmin' ? 'Signed in (Super Admin)' : 'Signed in', ip);
      return send(res, 200, { token, display: u.display, role: u.role, key });
    }

    const s = getSession(req);
    if (!s) return send(res, 401, { error: 'Not signed in' });

    if (route === 'me') return send(res, 200, { display: s.display, role: s.role });

    if (route === 'logout' && req.method === 'POST') {
      addLog(s.display, 'logout', 'Signed out', ip);
      sessions.delete((req.headers['authorization'] || '').slice(7));
      return send(res, 200, { ok: true });
    }

    if (route === 'log' && req.method === 'POST') {
      const { detail } = JSON.parse(await readBody(req) || '{}');
      addLog(s.display, 'act', detail, ip);
      return send(res, 200, { ok: true });
    }

    if (route === 'logs') {
      if (s.role !== 'superadmin') return send(res, 403, { error: 'Forbidden' });
      if (req.method === 'GET') return send(res, 200, logs);
      if (req.method === 'DELETE') { logs = []; addLog(s.display, 'act', 'Cleared user log', ip); return send(res, 200, { ok: true }); }
    }

    if (route === 'password' && req.method === 'POST') {
      if (s.role !== 'superadmin') return send(res, 403, { error: 'Only Super Admin can change passwords.' });
      const { target, password } = JSON.parse(await readBody(req) || '{}');
      const all = users();
      if (!all[target]) return send(res, 400, { error: 'Unknown user.' });
      if (String(password || '').length < 4) return send(res, 400, { error: 'Use at least 4 characters.' });
      all[target].hash = hash(target, String(password));
      writeJSON(USERS_FILE, all);
      for (const [t, ss] of sessions) if (ss.key === target && target !== s.key) sessions.delete(t); // sign the changed user out everywhere
      addLog(s.display, 'pw', `Changed password of ${all[target].display}`, ip);
      return send(res, 200, { ok: true, msg: `✓ Password updated for ${all[target].display}.` });
    }

    if (route === 'kv' && req.method === 'GET') {
      const shared = url.searchParams.get('shared') === '1';
      const prefix = url.searchParams.get('prefix') || '';
      const pre = shared ? 's_' : 'p_';
      const keys = fs.readdirSync(KV_DIR)
        .filter(n => n.startsWith(pre) && n.endsWith('.json'))
        .map(n => Buffer.from(n.slice(2, -5), 'hex').toString('utf8'))
        .filter(k => k.startsWith(prefix));
      return send(res, 200, { keys });
    }
    if (route.startsWith('kv/')) {
      const key = decodeURIComponent(route.slice(3));
      if (!key || key.length > 200) return send(res, 400, { error: 'Bad key' });
      const file = kvFile(key, url.searchParams.get('shared') === '1');
      if (req.method === 'GET') {
        if (!fs.existsSync(file)) return send(res, 404, { error: 'Key not found' });
        return send(res, 200, fs.readFileSync(file, 'utf8'), 'text/plain; charset=utf-8');
      }
      if (req.method === 'PUT') { writeAtomic(file, await readBody(req)); return send(res, 200, { ok: true }); }
      if (req.method === 'DELETE') { try { fs.unlinkSync(file); } catch (e) {} return send(res, 200, { ok: true }); }
    }
    return send(res, 404, { error: 'Unknown route' });
  } catch (e) {
    console.error(e);
    return send(res, 500, { error: 'Server error' });
  }
});

process.on('SIGTERM', () => { try { writeJSON(LOGS_FILE, logs); } catch (e) {} process.exit(0); });
server.listen(PORT, () => console.log(`CNG board on :${PORT}, data in ${DATA_DIR}`));
