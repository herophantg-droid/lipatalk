/* NEON ROOM — client. No build step, vanilla JS + WebRTC mesh. */
'use strict';

const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

const EMOJIS = ['🙂','😎','🔥','👾','🌸','🦊','🐺','🎧','🪩','⚡','🌙','🍜','🧊','🎮','🛸','🦄'];
const BGS = {
  aurora:   'linear-gradient(135deg,#0b1026 0%,#16234a 45%,#2a1748 100%)',
  sunset:   'linear-gradient(135deg,#1a1030 0%,#5a2340 55%,#c46a3a 100%)',
  ocean:    'linear-gradient(135deg,#061826 0%,#0b3a4a 55%,#12505c 100%)',
  sakura:   'linear-gradient(135deg,#160e26 0%,#3b1b3f 55%,#7a2f5b 100%)',
  matrix:   'linear-gradient(135deg,#030d08 0%,#0a2a19 60%,#0d3d24 100%)'
};
const REACTIONS = ['🔥','😂','❤️','👏','😮','🎉','💀','🫡'];

const S = {
  peerId: null, roomId: null, room: null, name: '', avatar: '🙂', bg: 'aurora', pro: false,
  peers: new Map(), pcs: new Map(), remoteAudios: new Map(),
  rawStream: null, stream: null, audioCtx: null, source: null, analyser: null, dest: null,
  effectNodes: [], effect: 'none', micOn: false, camOn: false, screenOn: false, videoStream: null,
  dummyVideoTrack: null, es: null, timer: null, silenceTimer: null, silenceActive: false,
  fxType: 0, fxTimer: null, lastVoice: Date.now(), speaking: false, chatCount: 0,
  clientId: null, invited: [], keys: {},
  // E2EE: key comes from the URL fragment (#k=...), never sent to the server.
  inviteKey: null, roomKey: null, roomKeyB64: null, sendSeq: 0,
  pendingAudio: {}, nextPlaySeq: {}
};

/* ---------- utils ---------- */
function api(url, body) {
  return fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) })
    .then(r => r.json().then(j => ({ ok: r.ok, ...j })));
}
function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add('hidden'), 2600);
}
function avatarHTML(a, cls = '') {
  if (!a) return `<div class="avatar ${cls}">🙂</div>`;
  if (a.startsWith('data:') || a.startsWith('http') || a.startsWith('blob:'))
    return `<div class="avatar ${cls}"><img src="${a}" alt=""></div>`;
  return `<div class="avatar ${cls}">${a}</div>`;
}
function loadPrefs() {
  let p = {};
  try { p = JSON.parse(localStorage.getItem('neonroom') || '{}'); } catch (_) {}
  S.clientId = p.clientId || (() => { const v = crypto.randomUUID(); localStorage.setItem('neonroom', JSON.stringify({ ...p, clientId: v })); return v; })();
  S.name = p.name || '';
  S.avatar = p.avatar || '🙂';
  S.bg = BGS[p.bg] ? p.bg : 'aurora';
  S.pro = !!p.pro;
  S.invited = Array.isArray(p.invited) ? p.invited : [];
  S.keys = (p.keys && typeof p.keys === 'object') ? p.keys : {};
  const hashKey = new URLSearchParams(location.hash.slice(1)).get('k');
  if (hashKey) S.inviteKey = hashKey;
}
function savePrefs() {
  localStorage.setItem('neonroom', JSON.stringify({ clientId: S.clientId, name: S.name, avatar: S.avatar, bg: S.bg, pro: S.pro, invited: S.invited, keys: S.keys }));
}
function markInvited(roomId) {
  if (!roomId || S.invited.includes(roomId)) return;
  S.invited.push(roomId);
  savePrefs();
}
function fmt(ms) {
  if (!ms || ms < 0) return '∞';
  const s = Math.floor(ms / 1000), h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return (h ? h + ':' : '') + String(m).padStart(h ? 2 : 1, '0') + ':' + String(sec).padStart(2, '0');
}
function escapeHTML(s) { return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

/* ---------- E2EE (AES-GCM, key lives in the URL fragment only) ---------- */
function bytesToB64(a) {
  let s = '';
  for (let i = 0; i < a.length; i += 4096) s += String.fromCharCode.apply(null, a.subarray(i, i + 4096));
  return btoa(s);
}
function b64ToBytes(s) {
  const bin = atob(s), out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64urlEncode(buf) {
  return bytesToB64(new Uint8Array(buf)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s) {
  let x = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (x.length % 4) x += '=';
  return b64ToBytes(x);
}
async function setRoomKey(b64urlKey) {
  const raw = b64urlDecode(b64urlKey);
  if (raw.length !== 32) throw new Error('bad key length');
  S.roomKey = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  S.roomKeyB64 = b64urlKey;
  S.sendSeq = 0;
  S.pendingAudio = {}; S.nextPlaySeq = {};
}
// Output: [8-byte salt][4-byte counter][ciphertext]. IV = salt || counter,
// so every message has a unique nonce and the receiver can restore ordering.
async function seal(plain) {
  if (!S.roomKey) return bytesToB64(plain);
  const salt = crypto.getRandomValues(new Uint8Array(8));
  const seq = S.sendSeq++;
  const ctr = new Uint8Array(4);
  new DataView(ctr.buffer).setUint32(0, seq, false);
  const iv = new Uint8Array(12); iv.set(salt, 0); iv.set(ctr, 8);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, S.roomKey, plain));
  const out = new Uint8Array(12 + ct.length);
  out.set(salt, 0); out.set(ctr, 8); out.set(ct, 12);
  return bytesToB64(out);
}
async function open(enc) {
  if (!S.roomKey) return { pt: b64ToBytes(enc), seq: null };
  const a = b64ToBytes(enc);
  if (a.length < 28) throw new Error('short ciphertext');
  const iv = a.slice(0, 12);
  const seq = new DataView(a.buffer, a.byteOffset + 8, 4).getUint32(0, false);
  const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, S.roomKey, a.slice(12)));
  return { pt, seq };
}
function inviteURL(roomId) {
  return location.origin + '?room=' + roomId + (S.roomKeyB64 ? '#k=' + S.roomKeyB64 : '');
}
async function ensureRoomKey(roomId, create) {
  let key = null;
  if (create) {
    key = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
  } else {
    const hashKey = new URLSearchParams(location.hash.slice(1)).get('k');
    key = hashKey || S.inviteKey || S.keys[roomId] || $('#join-key')?.value.trim() || null;
    if (!key) {
      key = window.prompt('Введи ключ шифрования из ссылки-приглашения (#k=...):');
      if (!key) { toast('Без ключа шифрование не работает'); return false; }
    }
  }
  try { await setRoomKey(key); } catch (e) { toast('Неверный ключ шифрования'); return false; }
  S.inviteKey = key;
  S.keys[roomId] = key;
  savePrefs();
  return true;
}

/* ---------- lobby ---------- */
function initLobby() {
  $('#create-name').value = S.name;
  $('#join-name').value = S.name;
  renderAvatarPreview();
  renderEmojiPicks();
  renderBgPicks();
  updateProUI();
  loadRoomList();
  $('#refresh-rooms').onclick = loadRoomList;

  $$('.tab').forEach(t => t.onclick = () => {
    $$('.tab').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    $('#tab-create').classList.toggle('hidden', t.dataset.tab !== 'create');
    $('#tab-join').classList.toggle('hidden', t.dataset.tab !== 'join');
  });

  $('#avatar-upload-btn').onclick = () => {
    const inp = document.createElement('input'); inp.type = 'file'; inp.accept = 'image/*';
    inp.onchange = () => {
      const f = inp.files[0]; if (!f) return;
      const r = new FileReader();
      r.onload = () => { S.avatar = r.result; savePrefs(); renderAvatarPreview(); renderEmojiPicks(); };
      r.readAsDataURL(f);
    };
    inp.click();
  };

  $('#create-btn').onclick = async () => {
    const name = $('#create-name').value.trim() || 'Гость';
    S.name = name; savePrefs();
    const b = await api('/api/rooms/create', { owner: S.clientId, name: $('#room-title').value.trim() || 'Комната', pro: S.pro, bg: S.bg });
    if (!b.ok) return toast(b.error || 'Не удалось создать');
    await enterRoom(b.room.id, $('#room-title').value.trim() || 'Комната', name, true);
  };
  $('#join-btn').onclick = async () => {
    const name = $('#join-name').value.trim() || 'Гость';
    const code = $('#join-code').value.trim().toUpperCase();
    if (code.length < 4) return toast('Введи код комнаты');
    S.name = name; savePrefs();
    try {
      const info = await fetch('/api/rooms/' + code).then(r => r.json());
      if (!info.room) return toast('Комната не найдена');
      markInvited(code);
      await enterRoom(code, info.room.name, name);
    } catch (_) { toast('Комната не найдена'); }
  };
  $('#pro-toggle').onclick = () => { S.pro = !S.pro; savePrefs(); updateProUI(); };
}
function updateProUI() {
  $('#pro-toggle').innerHTML = `Pro: ${S.pro ? 'вкл' : 'выкл'} <span class="pill">демо</span>`;
  $('#free-limits').textContent = S.pro
    ? 'Pro: без лимитов · запись · расширенные темы'
    : 'Free: 4 участника · 2 комнаты · 3 часа на комнату';
}
async function loadRoomList() {
  const box = $('#room-list'); if (!box) return;
  try {
    const data = await fetch('/api/rooms/list').then(r => r.json());
    const list = (data.rooms || []).filter(r => !r.pro || r.owner === S.clientId || S.invited.includes(r.id));
    if (!list.length) { box.innerHTML = '<div class="hint">пока нет комнат — создай первую</div>'; return; }
    box.innerHTML = '';
    list.forEach(r => {
      const b = document.createElement('button');
      b.className = 'room-row';
      b.innerHTML = `<span class="dot ${r.pro ? '' : 'free'}"></span>
        <span class="rn">${escapeHTML(r.name)}</span>
        ${r.pro ? '<span class="mem">ПАМЯТЬ</span>' : ''}
        <span class="rc">${r.count}/${r.limit} 👤</span>`;
      b.onclick = () => quickJoin(r);
      box.appendChild(b);
    });
  } catch (_) { box.innerHTML = '<div class="hint">не удалось загрузить список</div>'; }
}
async function quickJoin(room) {
  const name = S.name || $('#create-name').value.trim() || $('#join-name').value.trim() || 'Гость';
  S.name = name; markInvited(room.id); savePrefs();
  await enterRoom(room.id, room.name, name);
}
function renderAvatarPreview() { $('#avatar-preview').outerHTML = avatarHTML(S.avatar, 'big').replace('class="avatar big"', 'class="avatar big" id="avatar-preview"'); }
function renderEmojiPicks() {
  const box = $('#emoji-picks'); box.innerHTML = '';
  EMOJIS.forEach(e => {
    const b = document.createElement('button'); b.textContent = e;
    if (S.avatar === e) b.classList.add('sel');
    b.onclick = () => { S.avatar = e; savePrefs(); renderAvatarPreview(); renderEmojiPicks(); };
    box.appendChild(b);
  });
}
function renderBgPicks() {
  const box = $('#bg-picks'); box.innerHTML = '';
  Object.entries(BGS).forEach(([k, grad]) => {
    const b = document.createElement('button'); b.style.background = grad;
    if (S.bg === k) b.classList.add('sel');
    b.title = k;
    b.onclick = () => { S.bg = k; savePrefs(); renderBgPicks(); if (S.room) applyStageBg(); };
    box.appendChild(b);
  });
}
function applyStageBg() { $('#stage').style.background = BGS[S.bg] || BGS.aurora; }

/* ---------- room entry ---------- */
async function enterRoom(roomId, title, name, create) {
  const b = await api('/api/rooms/join', { roomId, name, avatar: S.avatar });
  if (!b.ok) return toast(b.error || 'Не удалось войти');
  if (!await ensureRoomKey(b.room.id, !!create)) return;
  S.roomId = b.room.id; S.room = b.room; S.peerId = b.peerId; S.name = name;
  $('#lobby').classList.remove('active');
  $('#room').classList.add('active');
  $('#display-title').textContent = title || b.room.name;
  $('#pro-badge').classList.toggle('hidden', !b.room.pro);
  applyStageBg();
  renderReactionsBar();
  $('#chat-messages').innerHTML = ''; S.chatCount = 0; $('#chat-count').textContent = '0';
  if (b.history && b.history.length) b.history.forEach(appendChat);
  b.peers.forEach(addPeer);
  renderPeers();
  connectSSE();
  startTimer();
  await initMedia();
  startAudioRelay();
  startVideoRelay();
  for (const peer of b.peers) ensurePC(peer.id, true);
  startVisualizer();
  startSilenceWatch();
  $('#net-status').textContent = '🔒 E2EE · подключение';
  try { history.replaceState(null, '', inviteURL(S.roomId)); } catch (_) {}
  toast('Вы в комнате · E2EE включено 🔒');
  try { await navigator.clipboard.writeText(inviteURL(S.roomId)); } catch (_) {}
}

function connectSSE() {
  if (S.es) S.es.close();
  S.es = new EventSource(`/api/events?peerId=${S.peerId}&roomId=${S.roomId}`);
  const on = (evt, fn) => S.es.addEventListener(evt, e => { try { fn(JSON.parse(e.data)); } catch (_) {} });
  on('peer-joined', d => { if (d.peer && d.peer.id !== S.peerId && !S.peers.has(d.peer.id)) { addPeer(d.peer); renderPeers(); } });
  on('sync', d => {
    const ids = new Set((d.peers || []).map(p => p.id));
    (d.peers || []).forEach(p => {
      if (p.id === S.peerId) return;
      if (!S.peers.has(p.id)) addPeer(p);
      ensurePC(p.id, true);
    });
    [...S.peers.keys()].forEach(id => { if (!ids.has(id)) removePeer(id); });
    renderPeers();
  });
  on('peer-left', d => { removePeer(d.peerId); });
  on('peer-state', d => { if (!d.peer || d.peer.id === S.peerId) return; const p = S.peers.get(d.peer.id); if (p) { Object.assign(p, d.peer); renderPeers(); } });
  on('signal', d => handleSignal(d.from, d.data));
  on('audio', d => { S.audioChunks = (S.audioChunks || 0) + 1; playAudioChunk(d.from, d.data); });
  on('video', async d => {
    S.videoChunks = (S.videoChunks || 0) + 1;
    const p = S.peers.get(d.from); if (!p) return;
    try {
      const { pt } = await open(d.data);
      p.videoFrame = new TextDecoder().decode(pt);
      const img = document.querySelector(`img[data-peer="${d.from}"]`);
      if (img) img.src = p.videoFrame;
    } catch (e) { console.warn('decrypt video frame', e); }
  });
  on('chat', d => appendChat(d));
  on('reaction', d => spawnReaction(d.emoji));
  on('room-expired', () => { toast('Время комнаты истекло — создай новую'); setTimeout(leaveRoom, 1200); });
}

/* ---------- media ---------- */
function makeDummyVideoTrack() {
  const c = document.createElement('canvas'); c.width = 640; c.height = 360;
  const g = c.getContext('2d');
  g.fillStyle = '#080b18'; g.fillRect(0, 0, 640, 360);
  g.fillStyle = '#5a648f'; g.font = '22px Segoe UI, sans-serif'; g.textAlign = 'center';
  g.fillText('камера выключена', 320, 185);
  const stream = c.captureStream(5);
  return stream.getVideoTracks()[0];
}

async function initMedia() {
  // The video track must exist even when microphone access is denied, otherwise
  // the SDP has no media section and the other side never gets ontrack.
  if (!S.dummyVideoTrack || S.dummyVideoTrack.readyState === 'ended') S.dummyVideoTrack = makeDummyVideoTrack();
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    toast('Браузер не даёт микрофон: открой сайт через http://localhost');
    showMicRetry(); return;
  }
  try {
    if (S.rawStream) S.rawStream.getTracks().forEach(t => t.stop());
    S.rawStream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true }, video: false });
    S.rawStream.getAudioTracks().forEach(t => t.enabled = true);
    S.micOn = true;
    if (!S.dummyVideoTrack || S.dummyVideoTrack.readyState === 'ended') S.dummyVideoTrack = makeDummyVideoTrack();
    buildAudioGraph();
    setMicUI();
    $('#mic-retry').classList.add('hidden');
    if (S.audioCtx && S.audioCtx.state === 'suspended') S.audioCtx.resume().catch(() => {});
    populateMicDevices();
  } catch (e) {
    toast('Микрофон не выбран или доступ запрещён');
    S.micOn = false; setMicUI(); showMicRetry();
  }
}
function showMicRetry() { const b = $('#mic-retry'); if (b) b.classList.remove('hidden'); }

async function populateMicDevices() {
  const sel = $('#mic-select'); if (!sel || !navigator.mediaDevices?.enumerateDevices) return;
  try {
    const devices = (await navigator.mediaDevices.enumerateDevices()).filter(d => d.kind === 'audioinput');
    const current = S.rawStream?.getAudioTracks()[0]?.getSettings().deviceId;
    sel.innerHTML = '';
    if (!devices.length) { sel.innerHTML = '<option>нет устройств</option>'; return; }
    devices.forEach((d, i) => {
      const o = document.createElement('option');
      o.value = d.deviceId;
      o.textContent = (d.label || 'Микрофон ' + (i + 1)).slice(0, 38);
      sel.appendChild(o);
    });
    if (current) sel.value = current;
    sel.onchange = () => switchMic(sel.value);
  } catch (_) {}
}

async function switchMic(deviceId) {
  try {
    if (S.rawStream) S.rawStream.getTracks().forEach(t => t.stop());
    S.rawStream = await navigator.mediaDevices.getUserMedia({ audio: { deviceId: { exact: deviceId } }, video: false });
    S.rawStream.getAudioTracks().forEach(t => t.enabled = true);
    S.micOn = true;
    buildAudioGraph();
    setMicUI();
    toast('Микрофон переключён');
  } catch (e) { toast('Не удалось переключить микрофон'); }
}

function makeCurve(kind) {
  const n = 1024, c = new Float32Array(n);
  for (let i = 0; i < n; i++) {
    const x = i * 2 / n - 1;
    if (kind === 'robot') c[i] = Math.tanh(x * 5) * .8 + Math.sin(x * 18) * .12;
    else if (kind === 'mutant') c[i] = Math.sign(x) * Math.pow(Math.abs(x), .45) + Math.sin(x * 30) * .16;
    else c[i] = x;
  }
  return c;
}

function buildAudioGraph() {
  try { if (S.audioCtx) S.audioCtx.close(); } catch (_) {}
  S.effectNodes = [];
  try {
    const AC = window.AudioContext || window.webkitAudioContext;
    S.audioCtx = new AC();
    if (S.audioCtx.state === 'suspended') S.audioCtx.resume().catch(() => {});
    S.source = S.audioCtx.createMediaStreamSource(S.rawStream);
    S.analyser = S.audioCtx.createAnalyser();
    S.analyser.fftSize = 1024;
    S.dest = S.audioCtx.createMediaStreamDestination();
    let node = S.source;
    node.connect(S.analyser);
    const fx = S.effect;
    if (fx === 'robot') {
      const ws = S.audioCtx.createWaveShaper(); ws.curve = makeCurve('robot');
      const bp = S.audioCtx.createBiquadFilter(); bp.type = 'bandpass'; bp.frequency.value = 1400; bp.Q.value = 1.4;
      node.connect(ws); ws.connect(bp); node = bp; S.effectNodes.push(ws, bp);
    } else if (fx === 'echo') {
      const d = S.audioCtx.createDelay(1); d.delayTime.value = .24;
      const g = S.audioCtx.createGain(); g.gain.value = .42;
      node.connect(d); d.connect(g); g.connect(d); node.connect(S.dest); S.effectNodes.push(d, g);
    } else if (fx === 'mutant') {
      const ws = S.audioCtx.createWaveShaper(); ws.curve = makeCurve('mutant');
      const hp = S.audioCtx.createBiquadFilter(); hp.type = 'highpass'; hp.frequency.value = 320;
      node.connect(ws); ws.connect(hp); node = hp; S.effectNodes.push(ws, hp);
    } else if (fx === 'deep') {
      const lp = S.audioCtx.createBiquadFilter(); lp.type = 'lowpass'; lp.frequency.value = 380;
      node.connect(lp); node = lp; S.effectNodes.push(lp);
    } else if (fx === 'chip') {
      const ws = S.audioCtx.createWaveShaper(); ws.curve = makeCurve('robot');
      const bp = S.audioCtx.createBiquadFilter(); bp.type = 'bandpass'; bp.frequency.value = 2400; bp.Q.value = 3;
      node.connect(ws); ws.connect(bp); node = bp; S.effectNodes.push(ws, bp);
    }
    if (fx !== 'echo') node.connect(S.dest);
    S.stream = S.dest.stream;
  } catch (e) {
    console.warn('audio graph failed, using raw mic', e);
    S.stream = S.rawStream;
  }
  replaceAudioEverywhere(S.stream?.getAudioTracks()[0] || null);
}

function currentVideoTrack() {
  return (S.videoStream && S.videoStream.getVideoTracks()[0]) || S.dummyVideoTrack || null;
}
function replaceAudioEverywhere(track) {
  S.pcs.forEach(pc => { if (pc._audioSender?.replaceTrack) pc._audioSender.replaceTrack(track).catch(() => {}); });
}
function replaceVideoEverywhere(track) {
  S.pcs.forEach(pc => { if (pc._videoSender?.replaceTrack) pc._videoSender.replaceTrack(track).catch(() => {}); });
}

/* ---------- SSE media relay (no STUN/TURN needed) ---------- */
const RELAY_RATE = 16000;
function startAudioRelay() {
  try {
    stopAudioRelay();
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    if (ctx.state === 'suspended') ctx.resume().catch(() => {});
    S.relayCtx = ctx;
    const src = ctx.createMediaStreamSource(S.stream);
    const proc = ctx.createScriptProcessor(2048, 1, 1);
    const sink = ctx.createGain(); sink.gain.value = 0;
    src.connect(proc); proc.connect(sink); sink.connect(ctx.destination);
    S.relaySource = src; S.relayProc = proc; S.relaySink = sink;
    proc.onaudioprocess = e => {
      if (!S.roomId || !S.micOn) return;
      const input = e.inputBuffer.getChannelData(0);
      const ratio = ctx.sampleRate / RELAY_RATE;
      const n = Math.floor(input.length / ratio);
      const pcm = new Int16Array(n);
      for (let i = 0; i < n; i++) {
        let v = input[Math.floor(i * ratio)] || 0;
        pcm[i] = Math.max(-32768, Math.min(32767, v * 32767));
      }
      const bytes = new Uint8Array(pcm.buffer);
      seal(bytes).then(enc => {
        if (S.roomId) api('/api/audio', { roomId: S.roomId, from: S.peerId, data: enc });
      }).catch(() => {});
    };
  } catch (e) { console.warn('audio relay failed', e); }
}
function stopAudioRelay() {
  try { if (S.relayProc) S.relayProc.onaudioprocess = null; if (S.relaySource) S.relaySource.disconnect(); if (S.relayProc) S.relayProc.disconnect(); if (S.relayCtx) S.relayCtx.close(); } catch (_) {}
  S.relaySource = S.relayProc = S.relaySink = S.relayCtx = null;
}
async function playAudioChunk(from, data) {
  if (!data || from === S.peerId) return;
  try {
    const { pt, seq } = await open(data);
    if (seq === null) { playPCM(from, pt); return; }
    S.pendingAudio[from] = S.pendingAudio[from] || new Map();
    if (S.nextPlaySeq[from] === undefined) S.nextPlaySeq[from] = seq;
    S.pendingAudio[from].set(seq, pt);
    // Play in sender order; drop late/duplicate chunks.
    if (seq < S.nextPlaySeq[from]) S.pendingAudio[from].delete(seq);
    let guard = 0;
    while (S.pendingAudio[from].has(S.nextPlaySeq[from]) && guard++ < 30) {
      const chunk = S.pendingAudio[from].get(S.nextPlaySeq[from]);
      S.pendingAudio[from].delete(S.nextPlaySeq[from]);
      playPCM(from, chunk);
      S.nextPlaySeq[from]++;
    }
    if (S.pendingAudio[from].size > 40) S.pendingAudio[from].clear();
  } catch (e) { console.warn('decrypt audio chunk', e); }
}
function playPCM(from, bytes) {
  try {
    const pcm = new Int16Array(bytes.buffer, bytes.byteOffset, Math.floor(bytes.byteLength / 2));
    let ctx = S.playCtx;
    if (!ctx) { ctx = new (window.AudioContext || window.webkitAudioContext)(); S.playCtx = ctx; S.nextPlayTime = {}; }
    if (ctx.state === 'suspended') ctx.resume().catch(() => {});
    const buf = ctx.createBuffer(1, pcm.length, RELAY_RATE);
    const ch = buf.getChannelData(0);
    for (let i = 0; i < pcm.length; i++) ch[i] = pcm[i] / 32768;
    const now = ctx.currentTime;
    let t = S.nextPlayTime[from] || now;
    if (t < now) t = now;
    const src = ctx.createBufferSource(); src.buffer = buf; src.connect(ctx.destination);
    src.start(t);
    S.nextPlayTime[from] = t + buf.duration;
  } catch (e) { console.warn('play audio chunk', e); }
}
function startVideoRelay() {
  stopVideoRelay();
  const canvas = document.createElement('canvas'); canvas.width = 640; canvas.height = 360;
  const g = canvas.getContext('2d');
  const v = document.createElement('video');
  v.autoplay = true; v.muted = true; v.playsInline = true;
  S.relayVideoEl = v;
  S.videoRelayTimer = setInterval(() => {
    if (!S.roomId || !S.videoStream || !(S.camOn || S.screenOn)) return;
    if (v.srcObject !== S.videoStream) { v.srcObject = S.videoStream; v.play().catch(() => {}); }
    if (v.readyState < 2) return;
    if (S.videoSealing) return;
    g.drawImage(v, 0, 0, 640, 360);
    const data = canvas.toDataURL('image/jpeg', 0.45);
    S.videoSealing = true;
    seal(new TextEncoder().encode(data)).then(enc => {
      if (S.roomId) api('/api/video', { roomId: S.roomId, from: S.peerId, data: enc });
    }).catch(() => {}).finally(() => { S.videoSealing = false; });
  }, 180);
}
function stopVideoRelay() {
  clearInterval(S.videoRelayTimer); S.videoRelayTimer = null;
  if (S.relayVideoEl) { S.relayVideoEl.pause(); S.relayVideoEl.srcObject = null; S.relayVideoEl = null; }
}


/* ---------- WebRTC mesh ---------- */
const ICE = {
  iceCandidatePoolSize: 4,
  iceServers: [
    { urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302', 'stun:stun.services.mozilla.com'] },
    { urls: ['turn:openrelay.metered.ca:80'], username: 'openrelayproject', credential: 'openrelayproject' },
    { urls: ['turn:openrelay.metered.ca:443?transport=tcp'], username: 'openrelayproject', credential: 'openrelayproject' },
    { urls: ['turn:openrelay.metered.ca:443'], username: 'openrelayproject', credential: 'openrelayproject' }
  ]
};

function ensurePC(peerId, initiate) {
  if (S.pcs.has(peerId)) return S.pcs.get(peerId);
  const pc = new RTCPeerConnection(ICE);
  S.pcs.set(peerId, pc);

  // Add actual tracks up front. addTransceiver(null) produces recvonly SDP with
  // no ssrc, and replaceTrack afterwards does NOT renegotiate => no media at all.
  const audioTrack = S.stream?.getAudioTracks()[0] || null;
  const videoTrack = currentVideoTrack();
  if (audioTrack) pc._audioSender = pc.addTrack(audioTrack, new MediaStream([audioTrack]));
  else pc._audioSender = pc.addTransceiver('audio', { direction: 'recvonly' }).sender;
  pc._videoSender = pc.addTrack(videoTrack, new MediaStream([videoTrack]));
  pc._tracksReady = Promise.resolve();

  pc.onicecandidate = e => { if (e.candidate) signal(peerId, { type: 'candidate', candidate: e.candidate }); };
  pc.ontrack = e => {
    const stream = e.streams[0];
    if (!stream) return;
    const peer = S.peers.get(peerId); if (!peer) return;
    if (e.track.kind === 'video') {
      peer.videoStream = stream;
    } else {
      let a = S.remoteAudios.get(peerId);
      if (!a) {
        a = document.createElement('audio'); a.autoplay = true; a.playsInline = true;
        document.body.appendChild(a); S.remoteAudios.set(peerId, a);
      }
      a.srcObject = stream; a.play().catch(() => {});
    }
    renderPeers();
  };
  pc.oniceconnectionstatechange = () => {
    if (pc.iceConnectionState === 'failed') {
      console.warn('ICE failed, restarting', peerId);
      toast('Соединение прервалось — переподключаю…');
      try { pc.restartIce(); } catch (_) {}
    }
  };
  pc.onconnectionstatechange = () => {
    const st = pc.connectionState;
    if (st === 'connected') $('#net-status').textContent = '🔒 E2EE · связь есть';
    else if (st === 'disconnected' || st === 'failed') $('#net-status').textContent = '● переподключение';
    if (st === 'failed') { try { pc.restartIce(); } catch (_) {} }
  };

  if (initiate) {
    pc._tracksReady.then(() => pc.createOffer())
      .then(o => pc.setLocalDescription(o))
      .then(() => signal(peerId, { type: 'offer', sdp: pc.localDescription }))
      .catch(e => console.warn('offer', e));
  }
  return pc;
}

async function handleSignal(from, data) {
  const pc = ensurePC(from, false);
  await pc._tracksReady;
  try {
    if (data.type === 'offer') {
      await pc.setRemoteDescription(data.sdp);
      const a = await pc.createAnswer();
      await pc.setLocalDescription(a);
      signal(from, { type: 'answer', sdp: pc.localDescription });
    } else if (data.type === 'answer') {
      await pc.setRemoteDescription(data.sdp);
    } else if (data.type === 'candidate' && data.candidate) {
      await pc.addIceCandidate(data.candidate);
    }
  } catch (e) { console.warn('signal', e); }
}
function signal(to, data) { api('/api/signal', { from: S.peerId, to, data }); }

/* ---------- peers UI ---------- */
function addPeer(p) { S.peers.set(p.id, { ...p, speaking: false, videoStream: null }); }
function removePeer(id) {
  const pc = S.pcs.get(id); if (pc) pc.close();
  S.pcs.delete(id); S.peers.delete(id);
  const a = S.remoteAudios.get(id); if (a) { a.remove(); S.remoteAudios.delete(id); }
  renderPeers();
}
function renderPeers() {
  const box = $('#participants'); if (!box) return;
  let html = tileHTML({ id: S.peerId, name: S.name + ' (вы)', avatar: S.avatar, muted: !S.micOn, video: S.camOn || S.screenOn, screen: S.screenOn, speaking: S.speaking, me: true, videoStream: S.videoStream });
  S.peers.forEach(p => { html += tileHTML(p); });
  box.innerHTML = html;
  box.querySelectorAll('video').forEach(v => {
    const id = v.dataset.peer;
    const stream = id === S.peerId ? S.videoStream : (S.peers.get(id) || {}).videoStream;
    if (stream) { v.srcObject = stream; v.play().catch(() => {}); }
  });
  box.querySelectorAll('img[data-peer]').forEach(img => {
    const p = S.peers.get(img.dataset.peer);
    if (p && p.videoFrame) img.src = p.videoFrame;
  });
}
function tileHTML(p) {
  const hasVideo = !!(p.videoFrame || (p.videoStream && p.videoStream.getVideoTracks().length));
  const vid = hasVideo
    ? (p.me ? `<video data-peer="${p.id}" autoplay playsinline muted></video>`
            : `<img data-peer="${p.id}" alt="">`)
    : '';
  const cls = ['tile', p.speaking ? 'speaking' : '', p.muted ? 'muted' : '', hasVideo ? 'has-video' : '', p.screen ? 'screen-share' : ''].filter(Boolean).join(' ');
  return `<div class="${cls}" data-peer="${p.id}">
    ${vid}
    ${avatarHTML(p.avatar)}
    <div class="name">${escapeHTML(p.name || 'Гость')}</div>
    <div class="states">
      <span class="micstate">${p.muted ? '🔇' : '🎤'}</span>
      ${p.video ? '<span>📷</span>' : ''}${p.screen ? '<span>🖥️</span>' : ''}
    </div>
  </div>`;
}

/* ---------- chat & reactions ---------- */
function renderReactionsBar() {
  const bar = $('#reactions-bar'); bar.innerHTML = '';
  REACTIONS.forEach(e => {
    const b = document.createElement('button'); b.textContent = e;
    b.onclick = () => api('/api/reaction', { roomId: S.roomId, from: S.peerId, emoji: e });
    bar.appendChild(b);
  });
}
async function appendChat(d) {
  let text = d.text || '';
  if (d.enc) {
    try { text = new TextDecoder().decode((await open(text)).pt); }
    catch (_) { text = '🔒 не удалось расшифровать'; }
  }
  const box = $('#chat-messages');
  const div = document.createElement('div');
  div.className = 'msg' + (d.from === S.peerId ? ' me' : '');
  div.innerHTML = `<b>${escapeHTML(d.name || 'Гость')}</b>${escapeHTML(text)}`;
  box.appendChild(div); box.scrollTop = box.scrollHeight;
  S.chatCount++; $('#chat-count').textContent = S.chatCount;
}
function spawnReaction(emoji) {
  const el = document.createElement('div'); el.className = 'reaction'; el.textContent = emoji;
  el.style.left = (10 + Math.random() * 80) + '%';
  el.style.animationDuration = (2.2 + Math.random() * 1.2) + 's';
  $('#reactions').appendChild(el);
  setTimeout(() => el.remove(), 3800);
}

/* ---------- visualizer + silence ---------- */
function startVisualizer() {
  const cv = $('#visualizer'), ctx = cv.getContext('2d');
  let raf;
  function resize() { cv.width = cv.clientWidth; cv.height = cv.clientHeight; }
  resize(); window.addEventListener('resize', resize);
  function draw() {
    raf = requestAnimationFrame(draw);
    if (cv.width !== cv.clientWidth || cv.height !== cv.clientHeight) { cv.width = cv.clientWidth; cv.height = cv.clientHeight; }
    const w = cv.width, h = cv.height; ctx.clearRect(0, 0, w, h);
    if (!S.analyser) return;
    const data = new Uint8Array(S.analyser.frequencyBinCount);
    S.analyser.getByteFrequencyData(data);
    let sum = 0; for (let i = 0; i < 40; i++) sum += data[i];
    const level = sum / 40 / 255;
    const colors = ['rgba(255,179,71,', 'rgba(79,227,255,', 'rgba(255,95,162,'];
    for (let layer = 0; layer < 3; layer++) {
      ctx.beginPath(); ctx.moveTo(0, h);
      for (let x = 0; x <= w; x += 12) {
        const v = data[(x / w * (data.length / 2) + layer * 30) | 0] / 255;
        const y = h - 60 - layer * 30 - v * (70 + level * 120) - Math.sin(x / 90 + Date.now() / 700 + layer) * 14;
        ctx.lineTo(x, y);
      }
      ctx.lineTo(w, h); ctx.closePath();
      ctx.fillStyle = colors[layer] + (0.05 + level * 0.14) + ')';
      ctx.fill();
    }
  }
  draw();
  S._stopViz = () => cancelAnimationFrame(raf);
}

function startSilenceWatch() {
  clearInterval(S.silenceTimer);
  S.silenceTimer = setInterval(() => {
    if (!S.analyser) return;
    const buf = new Uint8Array(S.analyser.fftSize);
    S.analyser.getByteTimeDomainData(buf);
    let sum = 0; for (const v of buf) { const x = (v - 128) / 128; sum += x * x; }
    const rms = Math.sqrt(sum / buf.length);
    const speakingNow = S.micOn && rms > 0.025;
    if (speakingNow) {
      S.lastVoice = Date.now();
      if (S.speaking !== true) { S.speaking = true; pushState(); }
      if (S.silenceActive) stopSilence();
    } else if (S.speaking) { S.speaking = false; pushState(); }
    if (!S.silenceActive && Date.now() - S.lastVoice > 15000) startSilence();
  }, 250);
}
function pushState() {
  if (!S.roomId) return;
  api('/api/state', { roomId: S.roomId, peerId: S.peerId, speaking: S.speaking, muted: !S.micOn, video: S.camOn || S.screenOn, screen: S.screenOn, avatar: S.avatar, name: S.name });
}
function startSilence() {
  S.silenceActive = true; S.fxType = 0;
  $('#silence-label').classList.remove('hidden');
  $('#silence-btn').classList.add('on');
  nextFx();
  clearInterval(S.fxTimer);
  S.fxTimer = setInterval(nextFx, 10000);
}
function stopSilence() {
  S.silenceActive = false;
  S.lastVoice = Date.now();
  $('#silence-label').classList.add('hidden');
  $('#silence-btn').classList.remove('on');
  clearInterval(S.fxTimer);
  fxParticles = [];
  const cv = $('#silence-fx'); cv.getContext('2d').clearRect(0, 0, cv.width, cv.height);
}
function nextFx() {
  S.fxType = (S.fxType + 1) % 6;
  fxParticles = [];
  const cv = $('#silence-fx'); const w = cv.clientWidth, h = cv.clientHeight;
  for (let i = 0; i < 60; i++) fxParticles.push(makeParticle(S.fxType, w, h));
}
function makeParticle(type, w, h) {
  const base = { x: Math.random() * w, y: type === 1 ? Math.random() * h : -Math.random() * h, r: 2 + Math.random() * 5, sp: 1 + Math.random() * 3, rot: Math.random() * 6.28 };
  if (type === 2) base.c = ['#ffb347','#ff5fa2','#4fe3ff','#9b6cff'][(Math.random() * 4) | 0];
  if (type === 3) base.e = ['🔥','🍩','✨','💫','🌸','🎈'][(Math.random() * 6) | 0];
  if (type === 4) { base.y = h - 30 - Math.random() * 40; base.sp = 1.5 + Math.random() * 3; base.dir = Math.random() > .5 ? 1 : -1; base.x = base.dir > 0 ? -40 : w + 40; base.say = ['НУ ГОВОРИ','ПИНГ?','МЫ ЖДЁМ','ЭЙ!','ЗАСНУЛ?'][(Math.random() * 5) | 0]; }
  return base;
}
let fxParticles = [];
function startFxLoop() {
  const cv = $('#silence-fx'), ctx = cv.getContext('2d');
  let raf;
  function resize() { cv.width = cv.clientWidth; cv.height = cv.clientHeight; }
  resize(); window.addEventListener('resize', resize);
  function draw() {
    raf = requestAnimationFrame(draw);
    if (cv.width !== cv.clientWidth || cv.height !== cv.clientHeight) { cv.width = cv.clientWidth; cv.height = cv.clientHeight; }
    const w = cv.width, h = cv.height; ctx.clearRect(0, 0, w, h);
    if (!S.silenceActive) return;
    const t = S.fxType;
    fxParticles.forEach(p => {
      ctx.save();
      if (t === 0) {
        p.y += p.sp * .6; p.x += Math.sin(p.rot += .02) * .6;
        ctx.fillStyle = 'rgba(255,255,255,.8)'; ctx.beginPath(); ctx.arc(p.x, p.y, p.r * .6, 0, 6.28); ctx.fill();
      } else if (t === 1) {
        p.x -= p.sp * 4; p.y += p.sp * 2;
        const g = ctx.createLinearGradient(p.x, p.y, p.x + 60, p.y - 30);
        g.addColorStop(0, 'rgba(79,227,255,.9)'); g.addColorStop(1, 'rgba(79,227,255,0)');
        ctx.strokeStyle = g; ctx.lineWidth = p.r * .6; ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(p.x + 60, p.y - 30); ctx.stroke();
      } else if (t === 2) {
        p.y += p.sp; p.rot += .08;
        ctx.translate(p.x, p.y); ctx.rotate(p.rot); ctx.fillStyle = p.c; ctx.fillRect(-p.r, -p.r * .4, p.r * 2, p.r * .8);
      } else if (t === 3) {
        p.y += p.sp * 1.4;
        ctx.font = (18 + p.r * 3) + 'px sans-serif'; ctx.fillText(p.e, p.x, p.y);
      } else if (t === 4) {
        p.x += p.sp * p.dir; p.rot += .25;
        ctx.font = '26px sans-serif'; ctx.fillText('🏃', p.x, p.y + Math.sin(p.rot) * 5);
        ctx.font = '11px sans-serif'; ctx.fillStyle = '#ffb347'; ctx.fillText(p.say, p.x - 22, p.y - 22);
      } else {
        p.rot += .03; p.y += p.sp * .25;
        const hue = (p.rot * 60) % 360;
        ctx.translate(p.x, p.y); ctx.rotate(p.rot);
        ctx.fillStyle = `hsla(${hue},90%,65%,.75)`;
        for (let i = 0; i < 6; i++) { ctx.rotate(1.04); ctx.fillRect(0, -2, 26, 4); }
      }
      ctx.restore();
      if (p.y > h + 60 || p.x < -100 || p.x > w + 100) Object.assign(p, makeParticle(t, w, h));
    });
  }
  draw();
}

/* ---------- controls ---------- */
function setMicUI() {
  $('#mic-btn').classList.toggle('on', S.micOn);
  $('#mic-btn').classList.toggle('off', !S.micOn);
  $('#mic-btn').querySelector('span').textContent = S.micOn ? '🎤' : '🔇';
}
function initControls() {
  document.addEventListener('click', () => {
    if (S.audioCtx && S.audioCtx.state === 'suspended') S.audioCtx.resume().catch(() => {});
    if (S.playCtx && S.playCtx.state === 'suspended') S.playCtx.resume().catch(() => {});
    S.remoteAudios.forEach(a => a.play().catch(() => {}));
  }, true);
  $('#mic-retry').onclick = () => { initMedia().then(() => { pushState(); renderPeers(); }); };
  $('#mic-btn').onclick = () => {
    S.micOn = !S.micOn;
    if (S.rawStream) S.rawStream.getAudioTracks().forEach(t => t.enabled = S.micOn);
    setMicUI(); pushState(); renderPeers();
  };
  $('#cam-btn').onclick = async () => {
    if (!S.camOn) {
      try {
        S.videoStream = await navigator.mediaDevices.getUserMedia({ video: { width: 640, height: 360 }, audio: false });
        S.camOn = true;
      } catch (e) { return toast('Нет камеры'); }
    } else {
      S.videoStream.getTracks().forEach(t => t.stop()); S.videoStream = null; S.camOn = false;
    }
    replaceVideoEverywhere(currentVideoTrack());
    $('#cam-btn').classList.toggle('on', S.camOn);
    pushState(); renderPeers();
  };
  $('#screen-btn').onclick = async () => {
    if (!S.screenOn) {
      try {
        S.videoStream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
        S.screenOn = true;
        S.videoStream.getVideoTracks()[0].onended = () => $('#screen-btn').click();
      } catch (e) { return; }
    } else {
      S.videoStream.getTracks().forEach(t => t.stop()); S.videoStream = null; S.screenOn = false;
    }
    replaceVideoEverywhere(currentVideoTrack());
    $('#screen-btn').classList.toggle('on', S.screenOn);
    pushState(); renderPeers();
  };
  $('#audio-btn').onclick = () => {
    if (S.audioCtx && S.audioCtx.state === 'suspended') S.audioCtx.resume().catch(() => {});
    if (S.playCtx && S.playCtx.state === 'suspended') S.playCtx.resume().catch(() => {});
    S.remoteAudios.forEach(a => { a.muted = false; a.play().catch(() => {}); });
    toast('Звук включён');
  };
  $('#voice-btn').onclick = () => {
    if (!S.room) return;
    if (!S.room.pro && !S.pro) return openUpgrade();
    openSettings('voice');
  };
  $('#bg-btn').onclick = () => openSettings('bg');
  $('#silence-btn').onclick = () => S.silenceActive ? stopSilence() : startSilence();
  $('#silence-stop').onclick = e => { e.stopPropagation(); stopSilence(); toast('Эффекты выключены'); };
  $('#settings-btn').onclick = () => openSettings();
  $('#copy-link').onclick = () => {
    navigator.clipboard?.writeText(inviteURL(S.roomId));
    toast('Ссылка с ключом скопирована 🔒');
  };
  $('#leave-btn').onclick = leaveRoom;
  $('#modal-close').onclick = closeModal;
  $('#modal-backdrop').onclick = e => { if (e.target.id === 'modal-backdrop') closeModal(); };
  $('#chat-form').onsubmit = e => {
    e.preventDefault();
    const inp = $('#chat-input'), text = inp.value.trim(); if (!text) return;
    seal(new TextEncoder().encode(text)).then(enc => {
      api('/api/chat', { roomId: S.roomId, from: S.peerId, name: S.name, text: enc, enc: true, avatar: S.avatar });
    });
    inp.value = '';
  };
}

/* ---------- modals ---------- */
function openModal(html) { $('#modal-content').innerHTML = html; $('#modal-backdrop').classList.remove('hidden'); }
function closeModal() { $('#modal-backdrop').classList.add('hidden'); }
function openUpgrade() {
  openModal(`<h2>Войс-ченджер — в Pro 🎛️</h2>
    <p>Робот, эхо, мультик, низкий голос и чип-эффект. Работает прямо в браузере, без сервера.</p>
    <div class="upgrade"><b>Pro включает</b>
      <ul><li>войс-ченджер и все эффекты</li><li>до 50 участников</li><li>без лимита 3 часов</li><li>запись разговора и темы</li></ul>
    </div>
    <p style="margin-top:14px">Оплата: логика готова, ключи ЮKassa вставишь сам. Сейчас можно включить демо Pro в лобби.</p>
    <button class="primary big-btn" onclick="document.querySelector('#modal-close').click()">Понятно</button>`);
}
function openSettings() {
  const effects = [['none','Без эффекта'],['robot','Робот'],['echo','Эхо'],['mutant','Мультик'],['deep','Низкий'],['chip','Чип']];
  const effectHTML = effects.map(([k, label]) =>
    `<button class="opt ${S.effect === k ? 'active' : ''}" data-effect="${k}" ${!S.room?.pro && !S.pro && k !== 'none' ? 'disabled style="opacity:.4"' : ''}>${label}${k !== 'none' && !S.room?.pro && !S.pro ? ' 🔒' : ''}</button>`
  ).join('');
  const bgHTML = Object.entries(BGS).map(([k, g]) =>
    `<button class="opt ${S.bg === k ? 'active' : ''}" data-bg="${k}" style="background:${g};color:#fff">${k}</button>`
  ).join('');
  openModal(`<h2>Настройки</h2>
    <h3>Аватарка</h3>
    <div class="avatar-pick">${avatarHTML(S.avatar, 'big')}<button class="mini" id="m-avatar">Загрузить</button><div class="hint">эмодзи — в лобби</div></div>
    <h3>Проверка микрофона</h3>
    <div class="meter"><i id="mic-level"></i></div>
    <div class="hint" id="mic-level-text">говори — полоска должна двигаться</div>
    <h3>Фон комнаты</h3><div class="opt-grid">${bgHTML}</div>
    <h3>Войс-ченджер</h3><div class="opt-grid">${effectHTML}</div>
    <p style="margin-top:14px">${S.room?.pro || S.pro ? 'Pro активен — эффекты доступны.' : 'Эффекты доступны в Pro.'}</p>`);
  $('#m-avatar').onclick = () => {
    const inp = document.createElement('input'); inp.type = 'file'; inp.accept = 'image/*';
    inp.onchange = () => { const f = inp.files[0]; if (!f) return; const r = new FileReader(); r.onload = () => { S.avatar = r.result; savePrefs(); pushState(); renderPeers(); closeModal(); }; r.readAsDataURL(f); };
    inp.click();
  };
  $$('[data-bg]').forEach(b => b.onclick = () => { S.bg = b.dataset.bg; savePrefs(); applyStageBg(); closeModal(); });
  $$('[data-effect]').forEach(b => b.onclick = () => {
    if (b.disabled) return openUpgrade();
    S.effect = b.dataset.effect; buildAudioGraph(); closeModal(); toast('Эффект применён');
  });
}

/* ---------- mic meters ---------- */
function updateMicMeters() {
  if (!S.analyser) return;
  const buf = new Uint8Array(S.analyser.fftSize);
  S.analyser.getByteTimeDomainData(buf);
  let sum = 0; for (const v of buf) { const x = (v - 128) / 128; sum += x * x; }
  const rms = Math.sqrt(sum / buf.length);
  const pct = Math.min(100, rms * 700).toFixed(0) + '%';
  const mini = $('#mic-mini'), big = $('#mic-level');
  if (mini) mini.style.width = pct;
  if (big) big.style.width = pct;
  const label = $('#mic-level-text');
  const st = S.audioCtx ? S.audioCtx.state : 'нет';
  if (label) label.textContent = !S.micOn ? 'Микрофон выключен'
    : st !== 'running' ? 'Звук на паузе — кликни где угодно'
    : (rms > .02 ? 'Слышу тебя ✅' : 'Тишина — проверь микрофон');
}

/* ---------- timer / leave ---------- */
function startTimer() {
  clearInterval(S.timer);
  const tick = () => {
    if (!S.room) return;
    $('#room-timer').textContent = S.room.pro ? '∞' : fmt(S.room.expiresAt - Date.now());
  };
  tick(); S.timer = setInterval(tick, 1000);
}
function leaveRoom() {
  try { api('/api/leave', { peerId: S.peerId }); } catch (_) {}
  if (S.es) S.es.close();
  clearInterval(S.timer); clearInterval(S.silenceTimer); clearInterval(S.fxTimer);
  stopAudioRelay(); stopVideoRelay();
  S.pcs.forEach(pc => pc.close()); S.pcs.clear();
  [S.rawStream, S.videoStream].forEach(s => s && s.getTracks().forEach(t => t.stop()));
  S.remoteAudios.forEach(a => a.remove()); S.remoteAudios.clear();
  S.peers.clear();
  S.room = null; S.roomId = null; S.peerId = null; S.silenceActive = false;
  $('#room').classList.remove('active'); $('#lobby').classList.add('active');
  $('#net-status').textContent = '● подключение';
  loadRoomList();
}

/* ---------- boot ---------- */
// ?fake=1 replaces devices with generated audio/video so media flow can be
// tested end-to-end in an environment without real cameras/microphones.
const params = new URLSearchParams(location.search);
if (params.get('fake') === '1' && navigator.mediaDevices) {
  const canvas = document.createElement('canvas'); canvas.width = 640; canvas.height = 360;
  const g = canvas.getContext('2d');
  let frame = 0;
  setInterval(() => {
    frame++;
    g.fillStyle = `hsl(${frame % 360},70%,35%)`; g.fillRect(0, 0, 640, 360);
    g.fillStyle = '#fff'; g.font = '40px sans-serif'; g.fillText('FAKE ' + frame, 40, 180);
  }, 100);
  navigator.mediaDevices.getUserMedia = async c => {
    if (c && c.video) return canvas.captureStream(15);
    const AC = window.AudioContext || window.webkitAudioContext;
    const ctx = new AC(); if (ctx.state === 'suspended') ctx.resume().catch(() => {});
    const osc = ctx.createOscillator(); osc.frequency.value = 440;
    const dest = ctx.createMediaStreamDestination();
    osc.connect(dest); osc.start();
    return dest.stream;
  };
}
loadPrefs();
initLobby();
initControls();
startFxLoop();
setInterval(updateMicMeters, 100);
setInterval(() => { if (S.audioCtx && S.audioCtx.state === 'suspended') S.audioCtx.resume().catch(() => {}); }, 500);
setInterval(() => { if (!S.room) loadRoomList(); }, 10000);
window.__NR = S; // debug handle
if (params.get('room')) {
  const code = params.get('room').toUpperCase();
  markInvited(code);
  $('#join-code').value = code;
  $$('.tab').forEach(x => x.classList.remove('active'));
  document.querySelector('[data-tab="join"]').classList.add('active');
  $('#tab-create').classList.add('hidden'); $('#tab-join').classList.remove('hidden');
}
