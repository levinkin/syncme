let port;
function origin(value) {
  const u = new URL(value);
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password || u.pathname !== '/' || u.search || u.hash || u.origin !== value) throw Error('Enter an exact http(s) origin without a trailing slash.');
  return u;
}
function connect() {
  if (port) return;
  port = chrome.runtime.connectNative('local.syncme');
  port.onDisconnect.addListener(() => { chrome.runtime.lastError; port = undefined; chrome.storage.session.set({connected: false}); });
  port.onMessage.addListener(async message => {
    let stage = 'request';
    try {
      if (message.op === 'ready') { await chrome.storage.session.set({connected: true}); return; }
      if (message.op !== 'sync' || typeof message.id !== 'string') throw Error('Invalid request');
      const u = origin(message.origin);
      const {approved = []} = await chrome.storage.local.get('approved');
      if (!approved.includes(u.origin)) throw Error('Origin not approved');
      stage = 'cookies';
      const cookies = (await chrome.cookies.getAll({domain: u.hostname})).filter(c => c.domain.replace(/^\./, '') === u.hostname && !c.partitionKey && (!c.secure || u.protocol === 'https:'));
      port.postMessage({id: message.id, origin: u.origin, cookies});
    } catch (_) { port?.postMessage({id: message.id, error: stage === 'cookies' ? 'Cookie API refused' : 'Origin unavailable or not approved'}); }
  });
}
chrome.runtime.onStartup.addListener(connect);
chrome.runtime.onInstalled.addListener(connect);
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id === chrome.runtime.id && message.op === 'connect') { connect(); reply({ok: true}); }
});
connect();
