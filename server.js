// NeonRoom signaling server - no dependencies, plain Node http.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 5173);
const ROOT = path.join(__dirname, 'public');
const DATA_FILE = path.join(__dirname, 'rooms.json');
const rooms = new Map();      // roomId -> room
const clients = new Map();    // peerId -> { res, roomId, name }

let saved = {};
try { saved = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch (_) { saved = {}; }
function saveRooms() {
  try { fs.writeFileSync(DATA_FILE, JSON.stringify(saved, null, 2)); } catch (_) {}
}
// Restore Pro rooms (room memory) on startup.
Object.values(saved).forEach(r => {
  rooms.set(r.id, {
    id: r.id, name: r.name, owner: r.owner, pro: true,
    createdAt: r.createdAt || Date.now(), expiresAt: null, expired: false,
    bg: r.bg || 'aurora', history: r.history || [], participants: new Map()
  });
});

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}

function sse(res, event, data) {
  try { res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`); } catch (_) {}
}

function broadcast(roomId, event, data, exceptPeerId) {
  const room = rooms.get(roomId);
  if (!room) return;
  for (const [peerId, client] of clients) {
    if (client.roomId !== roomId || peerId === exceptPeerId) continue;
    sse(client.res, event, data);
  }
}

function sendTo(peerId, event, data) {
  const c = clients.get(peerId);
  if (c) sse(c.res, event, data);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 2e6) req.destroy();
    });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function id(len = 6) {
  return crypto.randomBytes(len).toString('base64url').slice(0, len).toUpperCase();
}

function publicRoom(r) {
  return {
    id: r.id,
    name: r.name,
    pro: r.pro,
    owner: r.owner,
    createdAt: r.createdAt,
    expiresAt: r.expiresAt,
    count: r.participants.size,
    limit: r.pro ? 50 : 4,
    bg: r.bg || 'aurora',
    history: (r.history || []).length
  };
}

function cleanupPeer(peerId) {
  const c = clients.get(peerId);
  if (!c) return;
  clients.delete(peerId);
  const room = rooms.get(c.roomId);
  if (room) {
    room.participants.delete(peerId);
    broadcast(c.roomId, 'peer-left', { peerId }, null);
    if (room.participants.size === 0 && !room.pro) rooms.delete(c.roomId);
  }
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const p = url.pathname;

    if (req.method === 'OPTIONS') {
      res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': '*' });
      return res.end();
    }

    // ---------- API ----------
    if (p === '/api/rooms/create' && req.method === 'POST') {
      const b = await readBody(req);
      const owner = String(b.owner || 'anon');
      const pro = !!b.pro;
      const active = [...rooms.values()].filter(r => !r.expired && r.owner === owner);
      if (!pro && active.length >= 2) return json(res, 403, { error: ' Free: максимум 2 активные комнаты. Закрой одну или открой Pro.' });
      const room = {
        id: id(6), name: String(b.name || 'Комната').slice(0, 60),
        owner, pro, bg: String(b.bg || 'aurora'),
        createdAt: Date.now(),
        expiresAt: pro ? null : Date.now() + 3 * 60 * 60 * 1000,
        expired: false, history: [], participants: new Map()
      };
      rooms.set(room.id, room);
      if (pro) {
        saved[room.id] = { id: room.id, name: room.name, owner, bg: room.bg, createdAt: room.createdAt, history: [] };
        saveRooms();
      }
      return json(res, 200, { room: publicRoom(room) });
    }

    if (p === '/api/rooms/join' && req.method === 'POST') {
      const b = await readBody(req);
      const room = rooms.get(String(b.roomId || '').toUpperCase());
      if (!room) return json(res, 404, { error: 'Комната не найдена' });
      if (room.expired || (room.expiresAt && Date.now() > room.expiresAt)) {
        room.expired = true;
        return json(res, 410, { error: 'Время комнаты истекло. Создай новую.' });
      }
      const limit = room.pro ? 50 : 4;
      if (room.participants.size >= limit) return json(res, 403, { error: 'Комната заполнена' });
      const peerId = id(10);
      const peer = {
        id: peerId,
        name: String(b.name || 'Гость').slice(0, 40),
        avatar: String(b.avatar || ''),
        muted: true, video: false, screen: false, speaking: false, joinedAt: Date.now()
      };
      room.participants.set(peerId, peer);
      const peers = [...room.participants.values()].filter(x => x.id !== peerId).map(x => ({
        id: x.id, name: x.name, avatar: x.avatar, muted: x.muted, video: x.video, screen: x.screen
      }));
      broadcast(room.id, 'peer-joined', { peer }, peerId);
      return json(res, 200, {
        peerId, peers, room: publicRoom(room),
        history: room.pro ? (room.history || []).slice(-100) : []
      });
    }

    if (p === '/api/events' && req.method === 'GET') {
      const peerId = String(url.searchParams.get('peerId') || '');
      const roomId = String(url.searchParams.get('roomId') || '').toUpperCase();
      const old = clients.get(peerId);
      if (old && old.hb) clearInterval(old.hb);
      // NOTE: do NOT cleanupPeer here. EventSource reconnects with the same id;
      // removing the participant on reconnect used to create ghosts and wrong counts.
      res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
      });
      res.write(': connected\n\n');
      const hb = setInterval(() => { try { res.write(': ping\n\n'); } catch (_) {} }, 20000);
      clients.set(peerId, { res, roomId, name: '', hb, lastSeen: Date.now() });

      const room = rooms.get(roomId);
      if (room && !room.participants.has(peerId)) {
        const peer = {
          id: peerId, name: 'Гость', avatar: '',
          muted: true, video: false, screen: false, speaking: false, joinedAt: Date.now()
        };
        room.participants.set(peerId, peer);
        broadcast(roomId, 'peer-joined', { peer }, peerId);
      }
      const list = room ? [...room.participants.values()].filter(x => x.id !== peerId).map(x => ({
        id: x.id, name: x.name, avatar: x.avatar, muted: x.muted, video: x.video, screen: x.screen
      })) : [];
      sse(res, 'hello', { peerId, room: publicRoom(room || { id: roomId, participants: new Map(), pro: false, createdAt: Date.now(), expiresAt: null }) });
      sse(res, 'sync', { peers: list });
      req.on('close', () => {
        clearInterval(hb);
        const cur = clients.get(peerId);
        if (cur && cur.res === res) cleanupPeer(peerId);
      });
      return;
    }

    if (p === '/api/signal' && req.method === 'POST') {
      const b = await readBody(req);
      sendTo(String(b.to || ''), 'signal', { from: String(b.from || ''), data: b.data });
      return json(res, 200, { ok: true });
    }

    if (p === '/api/state' && req.method === 'POST') {
      const b = await readBody(req);
      const room = rooms.get(String(b.roomId || ''));
      if (!room) return json(res, 404, { error: 'no room' });
      const peer = room.participants.get(String(b.peerId || ''));
      if (!peer) return json(res, 404, { error: 'no peer' });
      ['muted', 'video', 'screen', 'speaking', 'avatar', 'name'].forEach(k => {
        if (b[k] !== undefined) peer[k] = b[k];
      });
      broadcast(room.id, 'peer-state', { peer }, b.peerId);
      return json(res, 200, { ok: true });
    }

    if (p === '/api/chat' && req.method === 'POST') {
      const b = await readBody(req);
      const msg = { from: b.from, name: String(b.name || '').slice(0, 40), text: String(b.text || '').slice(0, 4000), enc: !!b.enc, time: Date.now(), avatar: b.avatar || '' };
      broadcast(String(b.roomId || ''), 'chat', msg);
      const room = rooms.get(String(b.roomId || ''));
      if (room && room.pro) {
        room.history = room.history || [];
        room.history.push(msg);
        if (room.history.length > 200) room.history = room.history.slice(-200);
        if (saved[room.id]) { saved[room.id].history = room.history; saveRooms(); }
      }
      return json(res, 200, { ok: true });
    }

    if (p === '/api/reaction' && req.method === 'POST') {
      const b = await readBody(req);
      broadcast(String(b.roomId || ''), 'reaction', { from: b.from, emoji: String(b.emoji || '').slice(0, 12), time: Date.now() });
      return json(res, 200, { ok: true });
    }

    // SSE-relayed media: works through the same HTTPS connection as signaling,
    // so no STUN/TURN/UDP is needed (important on this network).
    if (p === '/api/audio' && req.method === 'POST') {
      const b = await readBody(req);
      broadcast(String(b.roomId || ''), 'audio', { from: b.from, data: String(b.data || '') }, b.from);
      return json(res, 200, { ok: true });
    }
    if (p === '/api/video' && req.method === 'POST') {
      const b = await readBody(req);
      broadcast(String(b.roomId || ''), 'video', { from: b.from, data: String(b.data || '') }, b.from);
      return json(res, 200, { ok: true });
    }

    if (p === '/api/leave' && req.method === 'POST') {
      const b = await readBody(req);
      cleanupPeer(String(b.peerId || ''));
      return json(res, 200, { ok: true });
    }

    if (p === '/api/rooms/list' && req.method === 'GET') {
      const list = [...rooms.values()]
        .filter(r => !r.expired && (!r.expiresAt || Date.now() <= r.expiresAt))
        .sort((a, b) => (b.pro ? 1 : 0) - (a.pro ? 1 : 0) || b.createdAt - a.createdAt)
        .map(publicRoom);
      return json(res, 200, { rooms: list });
    }

    if (p.startsWith('/api/rooms/') && req.method === 'GET') {
      const room = rooms.get(p.split('/').pop().toUpperCase());
      if (!room) return json(res, 404, { error: 'Комната не найдена' });
      return json(res, 200, { room: publicRoom(room) });
    }

    // ---------- static ----------
    let file = p === '/' ? '/index.html' : p;
    file = decodeURIComponent(file).replace(/\.\./g, '');
    const full = path.join(ROOT, file);
    if (!full.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
    fs.readFile(full, (err, data) => {
      if (err) { res.writeHead(404); return res.end('Not found'); }
      res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
      res.end(data);
    });
  } catch (e) {
    json(res, 500, { error: String(e.message || e) });
  }
});

// expire rooms
setInterval(() => {
  const now = Date.now();
  for (const [roomId, r] of rooms) {
    // Drop stale participants that never opened (or lost) their SSE connection.
    const stale = [];
    for (const [pid, peer] of r.participants) {
      if (!clients.has(pid) && now - (peer.joinedAt || 0) > 30000) stale.push(pid);
    }
    stale.forEach(pid => {
      r.participants.delete(pid);
      broadcast(roomId, 'peer-left', { peerId: pid });
    });
    if (!r.expired && r.expiresAt && now > r.expiresAt) {
      r.expired = true;
      broadcast(roomId, 'room-expired', { roomId });
      for (const pid of [...r.participants.keys()]) cleanupPeer(pid);
      rooms.delete(roomId);
    }
  }
}, 15000);

server.listen(PORT, '0.0.0.0', () => {
  console.log(`lipatalk running: http://localhost:${PORT}`);
});
