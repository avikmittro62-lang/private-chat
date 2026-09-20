'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

// ---------- Settings ----------
const PASSWORD = process.env.CHAT_PASSWORD;
if (!PASSWORD || PASSWORD.length < 8) {
  console.error('CHAT_PASSWORD সেট করুন (কমপক্ষে ৮ অক্ষর). Example: CHAT_PASSWORD=mysecret123 npm start');
  process.exit(1);
}
const PORT = process.env.PORT || 3000;
const MAX_USERS = 2;          // একসাথে সর্বোচ্চ দুজন
const HISTORY_LIMIT = 100;    // সার্ভারের memory-তে শেষ ১০০টা মেসেজ থাকে
const MAX_TEXT = 2000;
const MAX_NAME = 24;
const AUTH_TIMEOUT_MS = 10000;

// ---------- Password check (constant time) ----------
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const PASSWORD_HASH = sha(PASSWORD);
const passwordOk = (attempt) => crypto.timingSafeEqual(sha(attempt), PASSWORD_HASH);

// ---------- Brute-force protection ----------
const WINDOW_MS = 10 * 60 * 1000;
const MAX_FAILS = 5;
const fails = new Map(); // ip -> { count, first }

function isBlocked(ip) {
  const r = fails.get(ip);
  if (!r) return false;
  if (Date.now() - r.first > WINDOW_MS) {
    fails.delete(ip);
    return false;
  }
  return r.count >= MAX_FAILS;
}
function recordFail(ip) {
  const now = Date.now();
  const r = fails.get(ip);
  if (!r || now - r.first > WINDOW_MS) fails.set(ip, { count: 1, first: now });
  else r.count += 1;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, r] of fails) if (now - r.first > WINDOW_MS) fails.delete(ip);
}, WINDOW_MS).unref();

function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const parts = String(xff).split(',').map((s) => s.trim()).filter(Boolean);
    if (parts.length) return parts[parts.length - 1];
  }
  return req.socket.remoteAddress || 'unknown';
}

// ---------- HTTP (serves the chat page) ----------
const indexHtml = fs.readFileSync(path.join(__dirname, 'index.html'));

const SECURITY_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'X-Robots-Tag': 'noindex, nofollow',
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src https://fonts.gstatic.com; connect-src 'self' ws: wss:; img-src 'self' data:; frame-ancestors 'none'",
};

const server = http.createServer((req, res) => {
  const url = (req.url || '/').split('?')[0];
  if (url === '/' || url === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...SECURITY_HEADERS });
    res.end(indexHtml);
  } else if (url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
  } else if (url === '/robots.txt') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('User-agent: *\nDisallow: /\n');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  }
});

// ---------- WebSocket chat ----------
const wss = new WebSocketServer({ server, maxPayload: 8 * 1024 });
const clients = new Map(); // ws -> { name, times: [] }
const history = [];

const send = (ws, obj) => {
  if (ws.readyState === 1) ws.send(JSON.stringify(obj));
};
const peerNames = () => [...clients.values()].map((c) => c.name);
const broadcast = (obj, except) => {
  for (const ws of clients.keys()) if (ws !== except) send(ws, obj);
};
const cleanName = (n) =>
  String(n || '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, MAX_NAME);

function reject(ws, reason) {
  send(ws, { type: 'error', reason });
  ws.close(4001);
}

function handleJoin(ws, req, m) {
  const ip = clientIp(req);
  if (isBlocked(ip)) return reject(ws, 'too_many_attempts');

  const name = cleanName(m.name);
  if (!name) return reject(ws, 'bad_name');

  if (typeof m.password !== 'string' || !passwordOk(m.password)) {
    recordFail(ip);
    return reject(ws, 'wrong_password');
  }
  fails.delete(ip);

  // একই নামে আগের connection থাকলে (যেমন ফোন reconnect করলে) সেটা বদলে দেওয়া হয়
  for (const [other, info] of clients) {
    if (info.name.toLowerCase() === name.toLowerCase()) {
      clients.delete(other);
      send(other, { type: 'error', reason: 'replaced' });
      other.close(4000);
    }
  }

  if (clients.size >= MAX_USERS) return reject(ws, 'room_full');

  clients.set(ws, { name, times: [] });
  send(ws, { type: 'joined', you: name, peers: peerNames(), history });
  broadcast({ type: 'presence', peers: peerNames() }, ws);
}

wss.on('connection', (ws, req) => {
  // অন্য কোনো ওয়েবসাইট থেকে connect করা আটকানো
  const origin = req.headers.origin;
  if (origin) {
    try {
      if (new URL(origin).host !== req.headers.host) return ws.close(4003);
    } catch {
      return ws.close(4003);
    }
  }

  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  const authTimer = setTimeout(() => {
    if (!clients.has(ws)) ws.close(4002);
  }, AUTH_TIMEOUT_MS);

  ws.on('message', (data, isBinary) => {
    if (isBinary) return;
    let m;
    try { m = JSON.parse(data.toString()); } catch { return; }
    if (!m || typeof m.type !== 'string') return;

    const me = clients.get(ws);
    if (!me) {
      if (m.type === 'join') handleJoin(ws, req, m);
      return;
    }

    if (m.type === 'msg') {
      const text = typeof m.text === 'string' ? m.text.trim().slice(0, MAX_TEXT) : '';
      if (!text) return;
      // flood control: ১০ সেকেন্ডে সর্বোচ্চ ৩০টা
      const now = Date.now();
      me.times = me.times.filter((t) => now - t < 10000);
      if (me.times.length >= 30) return;
      me.times.push(now);

      const entry = { id: crypto.randomUUID(), from: me.name, text, ts: now };
      history.push(entry);
      if (history.length > HISTORY_LIMIT) history.shift();
      for (const c of clients.keys()) send(c, { type: 'msg', ...entry });
    } else if (m.type === 'typing') {
      broadcast({ type: 'typing', from: me.name }, ws);
    }
  });

  ws.on('close', () => {
    clearTimeout(authTimer);
    if (clients.delete(ws)) broadcast({ type: 'presence', peers: peerNames() });
  });
  ws.on('error', () => {});
});

// মরে যাওয়া connection সরিয়ে ফেলা (ফোনের নেট কেটে গেলে)
const heartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) { ws.terminate(); continue; }
    ws.isAlive = false;
    ws.ping();
  }
}, 25000);
heartbeat.unref();

server.listen(PORT, () => console.log('Chat running on port ' + PORT));

process.on('SIGTERM', () => {
  wss.close();
  server.close(() => process.exit(0));
});
