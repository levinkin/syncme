let port;
function origin(value) {
  const u = new URL(value);
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password || u.pathname !== '/' || u.search || u.hash || u.origin !== value) throw Error('Enter an exact http(s) origin without a trailing slash.');
  return u;
}
const pending = new Map();
function connect() {
  if (port) return;
  port = chrome.runtime.connectNative('local.syncme');
  port.onDisconnect.addListener(() => {
    chrome.runtime.lastError;
    port = undefined;
    chrome.storage.session.set({connected: false});
    for (const done of pending.values()) done({error: 'Not connected'});
    pending.clear();
  });
  port.onMessage.addListener(async message => {
    if (message.op === 'ready') { await chrome.storage.session.set({connected: true}); return; }
    if (message.op === 'copied') { pending.get(message.id)?.(message); pending.delete(message.id); return; }
    const {approved = [], autoSync = false} = await chrome.storage.local.get(['approved', 'autoSync']);
    if (message.op === 'list') { port?.postMessage({id: message.id, origins: autoSync ? approved : []}); return; }
    let stage = 'request';
    try {
      if (message.op !== 'sync' || typeof message.id !== 'string') throw Error('Invalid request');
      const u = origin(message.origin);
      if (!approved.includes(u.origin)) throw Error('Origin not approved');
      stage = 'cookies';
      const cookies = (await chrome.cookies.getAll({domain: u.hostname})).filter(c => c.domain.replace(/^\./, '') === u.hostname && !c.partitionKey && (!c.secure || u.protocol === 'https:'));
      port.postMessage({id: message.id, origin: u.origin, cookies});
    } catch (_) { port?.postMessage({id: message.id, error: stage === 'cookies' ? 'Cookie API refused' : 'Origin unavailable or not approved'}); }
  });
}
async function copy(value) {
  const u = origin(value);
  const {approved = []} = await chrome.storage.local.get('approved');
  await chrome.storage.local.set({approved: [...new Set([...approved, u.origin])]});
  connect();
  const id = crypto.randomUUID();
  const result = new Promise(resolve => pending.set(id, resolve));
  port.postMessage({op: 'copy', id, origin: u.origin});
  return result;
}
chrome.runtime.onStartup.addListener(connect);
chrome.runtime.onInstalled.addListener(connect);
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id || message.op !== 'copy') return;
  copy(message.origin).then(reply, () => reply({error: 'Invalid site'}));
  return true;
});
connect();
