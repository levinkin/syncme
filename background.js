importScripts('tldts.js');
let socket;
const domain = u => tldts.getDomain(u.hostname, {allowPrivateDomains: true});
const scope = u => domain(u) ? u.protocol + '//' + domain(u) : u.origin;
function origin(value) {
  const u = new URL(value);
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password || u.pathname !== '/' || u.search || u.hash || u.origin !== value) throw Error('Enter an exact http(s) origin without a trailing slash.');
  return u;
}
const pending = new Map();
const asking = new Map();
async function allow(value) {
  const w = await chrome.windows.create({url: 'approve.html?site=' + encodeURIComponent(value), type: 'popup', width: 380, height: 220, focused: true});
  return new Promise(resolve => {
    const timer = setTimeout(() => done(false), 100000);
    function done(answer) {
      if (!asking.delete(w.id)) return;
      clearTimeout(timer);
      chrome.windows.remove(w.id).catch(() => {});
      resolve(answer);
    }
    asking.set(w.id, done);
  });
}
chrome.windows.onRemoved.addListener(id => asking.get(id)?.(false));
const hex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
const random = () => hex(crypto.getRandomValues(new Uint8Array(32)));
const text = new TextEncoder();
function iv(n) {
  const b = new Uint8Array(12);
  new DataView(b.buffer).setBigUint64(4, BigInt(n));
  return b;
}
function seal(ws, value) {
  ws.out = ws.out.then(async () => {
    const n = ws.sent++;
    const data = await crypto.subtle.encrypt({name: 'AES-GCM', iv: iv(n)}, ws.keys[1], text.encode(JSON.stringify(value)));
    ws.send(JSON.stringify({op: 'enc', n, data: new Uint8Array(data).toBase64()}));
  }).catch(() => ws.close());
}
async function sign(secret, purpose) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(purpose)));
}
function connect() {
  if (socket) return;
  const ws = new WebSocket('ws://127.0.0.1:47621/');
  socket = ws;
  let secret, nonce, peer, verified = false, received = 0;
  ws.sent = 0;
  ws.out = Promise.resolve();
  const send = value => ws.send(JSON.stringify(value));
  const keepAlive = setInterval(() => verified && ws.readyState === WebSocket.OPEN && seal(ws, {op: 'ping'}), 20000);
  const refuse = async pairing => { await chrome.storage.session.set({pairing}); ws.close(); };
  let chain = Promise.resolve();
  ws.onmessage = event => { chain = chain.then(() => handle(event)).catch(() => ws.close()); };
  const handle = async event => {
    let message;
    try { message = JSON.parse(event.data); } catch (_) { return ws.close(); }
    if (verified) {
      if (message.op !== 'enc' || message.n !== received) return ws.close();
      message = JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name: 'AES-GCM', iv: iv(received++)}, ws.keys[0], Uint8Array.fromBase64(message.data))));
    } else {
      if (message.op === 'hello' && !nonce) {
        ({secret} = await chrome.storage.local.get('secret'));
        if (!message.paired) {
          if (secret) return refuse('lost');
          const pair = await crypto.subtle.generateKey({name: 'X25519'}, false, ['deriveBits']);
          const shared = await crypto.subtle.deriveBits({name: 'X25519', public: await crypto.subtle.importKey('raw', Uint8Array.fromBase64(message.key), {name: 'X25519'}, false, [])}, pair.privateKey, 256);
          secret = hex(await crypto.subtle.deriveBits({name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info: text.encode('syncme pair v1')}, await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']), 256));
          await chrome.storage.local.set({secret});
          send({op: 'pair', key: new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)).toBase64()});
        } else if (!secret) return refuse('other');
        peer = message.nonce;
        nonce = random();
        send({op: 'proof', proof: await sign(secret, 'extension:' + message.nonce), nonce});
      } else if (message.op === 'refused') return refuse('other');
      else if (message.op === 'ready' && nonce && message.proof === await sign(secret, 'server:' + nonce)) {
        const base = await crypto.subtle.importKey('raw', Uint8Array.fromHex(secret), 'HKDF', false, ['deriveKey']);
        ws.keys = await Promise.all(['b2e', 'e2b'].map(d => crypto.subtle.deriveKey({name: 'HKDF', hash: 'SHA-256', salt: Uint8Array.fromHex(peer + nonce), info: text.encode('syncme wire v1 ' + d)}, base, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt'])));
        if (socket !== ws || ws.readyState !== WebSocket.OPEN) return;
        verified = true;
        await chrome.storage.session.set({connected: true, pairing: null});
      } else ws.close();
      return;
    }
    if (message.op === 'copied') { pending.get(message.id)?.(message); pending.delete(message.id); return; }
    const {approved = [], autoSync = false, yolo = false} = await chrome.storage.local.get(['approved', 'autoSync', 'yolo']);
    if (message.op === 'list') { seal(ws, {id: message.id, origins: autoSync ? approved : []}); return; }
    let stage = 'request';
    try {
      if (message.op !== 'sync' || typeof message.id !== 'string') throw Error('Invalid request');
      const u = origin(message.origin);
      const site = scope(u);
      if (!approved.includes(site)) {
        if (!yolo && !await allow(site)) throw Error('Origin not approved');
        const {approved: now = []} = await chrome.storage.local.get('approved');
        await chrome.storage.local.set({approved: [...new Set([...now, site])]});
      }
      stage = 'cookies';
      const found = await chrome.cookies.getAll(domain(u) ? {domain: domain(u)} : {url: u.origin + '/'});
      const cookies = found.filter(c => !c.partitionKey && (!c.secure || u.protocol === 'https:'));
      seal(ws, {id: message.id, origin: u.origin, cookies});
    } catch (_) { seal(ws, {id: message.id, error: stage === 'cookies' ? 'Cookie API refused' : 'Origin unavailable or not approved'}); }
  };
  ws.onclose = ws.onerror = () => {
    clearInterval(keepAlive);
    if (socket !== ws) return;
    socket = undefined;
    verified = false;
    chrome.storage.session.set({connected: false});
    for (const done of pending.values()) done({error: 'Not connected'});
    pending.clear();
  };
  ws.isVerified = () => verified;
}
async function copy(value) {
  const u = origin(value);
  const {approved = []} = await chrome.storage.local.get('approved');
  await chrome.storage.local.set({approved: [...new Set([...approved, scope(u)])]});
  connect();
  if (socket?.readyState !== WebSocket.OPEN || !socket.isVerified()) return {error: 'Not connected'};
  const id = crypto.randomUUID();
  const result = new Promise(resolve => pending.set(id, resolve));
  seal(socket, {op: 'copy', id, origin: u.origin});
  return result;
}
chrome.runtime.onStartup.addListener(connect);
chrome.runtime.onInstalled.addListener(connect);
chrome.alarms.create('connect', {periodInMinutes: 0.5});
chrome.alarms.onAlarm.addListener(connect);
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id) return;
  if (message.op === 'allow') { asking.get(sender.tab?.windowId)?.(message.answer === true); return; }
  if (message.op === 'repair') { chrome.storage.local.remove('secret').then(() => chrome.storage.session.set({pairing: null})).then(() => { socket?.close(); socket = undefined; connect(); }); return; }
  if (message.op !== 'copy') return;
  copy(message.origin).then(reply, () => reply({error: 'Invalid site'}));
  return true;
});
connect();
