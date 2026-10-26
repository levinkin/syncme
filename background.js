let socket;
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
async function sign(secret, purpose) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(purpose)));
}
function connect() {
  if (socket) return;
  const ws = new WebSocket('ws://127.0.0.1:47621/');
  socket = ws;
  let secret, nonce, verified = false;
  const send = value => ws.send(JSON.stringify(value));
  const keepAlive = setInterval(() => verified && ws.readyState === WebSocket.OPEN && send({op: 'ping'}), 20000);
  const refuse = async pairing => { await chrome.storage.session.set({pairing}); ws.close(); };
  let chain = Promise.resolve();
  ws.onmessage = event => { chain = chain.then(() => handle(event)).catch(() => {}); };
  const handle = async event => {
    let message;
    try { message = JSON.parse(event.data); } catch (_) { return; }
    if (!verified) {
      if (message.op === 'hello' && !nonce) {
        ({secret} = await chrome.storage.local.get('secret'));
        if (!message.paired) {
          if (secret) return refuse('lost');
          secret = random();
          await chrome.storage.local.set({secret});
          send({op: 'pair', secret});
        } else if (!secret) return refuse('other');
        nonce = random();
        send({op: 'proof', proof: await sign(secret, 'extension:' + message.nonce), nonce});
      } else if (message.op === 'refused') return refuse('other');
      else if (message.op === 'ready' && nonce && message.proof === await sign(secret, 'server:' + nonce)) {
        if (socket !== ws || ws.readyState !== WebSocket.OPEN) return;
        verified = true;
        await chrome.storage.session.set({connected: true, pairing: null});
      } else ws.close();
      return;
    }
    if (message.op === 'copied') { pending.get(message.id)?.(message); pending.delete(message.id); return; }
    const {approved = [], autoSync = false} = await chrome.storage.local.get(['approved', 'autoSync']);
    if (message.op === 'list') { send({id: message.id, origins: autoSync ? approved : []}); return; }
    let stage = 'request';
    try {
      if (message.op !== 'sync' || typeof message.id !== 'string') throw Error('Invalid request');
      const u = origin(message.origin);
      if (!approved.includes(u.origin)) {
        if (!await allow(u.origin)) throw Error('Origin not approved');
        const {approved: now = []} = await chrome.storage.local.get('approved');
        await chrome.storage.local.set({approved: [...new Set([...now, u.origin])]});
      }
      stage = 'cookies';
      const cookies = (await chrome.cookies.getAll({})).filter(c => (c.hostOnly ? c.domain === u.hostname : ('.' + u.hostname).endsWith(c.domain)) && !c.partitionKey && (!c.secure || u.protocol === 'https:'));
      send({id: message.id, origin: u.origin, cookies});
    } catch (_) { try { send({id: message.id, error: stage === 'cookies' ? 'Cookie API refused' : 'Origin unavailable or not approved'}); } catch (_) {} }
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
  await chrome.storage.local.set({approved: [...new Set([...approved, u.origin])]});
  connect();
  if (socket?.readyState !== WebSocket.OPEN || !socket.isVerified()) return {error: 'Not connected'};
  const id = crypto.randomUUID();
  const result = new Promise(resolve => pending.set(id, resolve));
  socket.send(JSON.stringify({op: 'copy', id, origin: u.origin}));
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
