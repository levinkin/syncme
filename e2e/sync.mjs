// runs the real bridge and extension in a throwaway home and checks cookie scope, wire encryption, tampering, profile cleanup and memory
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {createCipheriv, createHash, createHmac, hkdfSync, randomBytes} from 'node:crypto';
import {cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join} from 'node:path';
import {createInterface} from 'node:readline';
import {setTimeout as sleep} from 'node:timers/promises';
import {fileURLToPath} from 'node:url';
import {chromium} from 'playwright-core';
import {WebSocket} from 'ws';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const port = '47631';
const work = mkdtempSync(join(tmpdir(), 'syncme-e2e-'));
const app = join(work, 'app');
const home = join(work, 'home');
const state = process.platform === 'win32' ? join(home, 'AppData', 'Local', 'syncme') : process.platform === 'darwin' ? join(home, 'Library', 'Application Support', 'syncme') : join(home, '.local', 'state', 'syncme');
const env = {...process.env, HOME: home, USERPROFILE: home, LOCALAPPDATA: join(home, 'AppData', 'Local')};
for (const file of ['syncme.js', 'manifest.json', 'background.js', 'approve.html', 'approve.js', 'options.html', 'options.js', 'icons']) cpSync(join(root, file), join(app, file), {recursive: true});
for (const file of ['syncme.js', 'background.js']) writeFileSync(join(app, file), readFileSync(join(app, file), 'utf8').replaceAll('47621', port));
symlinkSync(join(root, 'node_modules'), join(app, 'node_modules'), 'junction');

const key = Buffer.from(JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8')).key, 'base64');
const extension = 'chrome-extension://' + createHash('sha256').update(key).digest('hex').slice(0, 32).replace(/[0-9a-f]/g, c => String.fromCharCode(97 + parseInt(c, 16)));
let server, user, ai;

async function exchange(socket, value) {
  const reply = once(socket, 'message');
  socket.send(JSON.stringify(value));
  return JSON.parse((await reply)[0]);
}

async function request(message) {
  const token = readFileSync(join(state, 'token'), 'utf8');
  const socket = new WebSocket('ws://127.0.0.1:' + port + '/client');
  const first = once(socket, 'message');
  await once(socket, 'open');
  const {challenge} = JSON.parse((await first)[0]);
  const nonce = randomBytes(32).toString('hex');
  const answer = await exchange(socket, {proof: createHmac('sha256', token).update('client:' + challenge).digest('hex'), nonce});
  assert.equal(answer.proof, createHmac('sha256', token).update('server:' + nonce).digest('hex'));
  const reply = await exchange(socket, message);
  socket.close();
  return reply;
}

function capture(socket, data) {
  const {id, method, params, result} = JSON.parse(data);
  if (method === 'Network.webSocketFrameSent' || method === 'Network.webSocketFrameReceived') socket.frames.push({socket: params.requestId, data: params.response.payloadData});
  socket.results.get(id)?.(result);
}

async function call(socket, method) {
  socket.calls++;
  const id = socket.calls;
  const result = new Promise(resolve => socket.results.set(id, resolve));
  socket.send(JSON.stringify({id, method}));
  return result;
}

async function heap(socket) {
  await call(socket, 'HeapProfiler.collectGarbage');
  return (await call(socket, 'Runtime.getHeapUsage')).usedSize;
}

async function tamper(secret, n, flip) {
  const socket = new WebSocket('ws://127.0.0.1:' + port + '/', {origin: extension});
  const first = once(socket, 'message');
  const closed = once(socket, 'close');
  await once(socket, 'open');
  const hello = JSON.parse((await first)[0]);
  assert.equal(hello.paired, true);
  const nonce = randomBytes(32).toString('hex');
  const ready = await exchange(socket, {op: 'proof', proof: createHmac('sha256', secret).update('extension:' + hello.nonce).digest('hex'), nonce});
  assert.equal(ready.op, 'ready');
  assert.equal(ready.proof, createHmac('sha256', secret).update('server:' + nonce).digest('hex'));
  const iv = Buffer.alloc(12);
  iv.writeBigUInt64BE(BigInt(n), 4);
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(hkdfSync('sha256', Buffer.from(secret, 'hex'), Buffer.from(hello.nonce + nonce, 'hex'), 'syncme wire v1 e2b', 32)), iv);
  const data = Buffer.concat([cipher.update(JSON.stringify({op: 'ping'})), cipher.final(), cipher.getAuthTag()]);
  if (flip) data[0] ^= 1;
  socket.send(JSON.stringify({op: 'enc', n, data: data.toString('base64')}));
  assert.equal(await Promise.race([closed.then(() => 'closed'), sleep(5000, 'open')]), 'closed');
}

try {
  user = await chromium.launchPersistentContext(join(work, 'user-chrome'), {
    channel: 'chromium',
    headless: true,
    args: ['--disable-extensions-except=' + app, '--load-extension=' + app, '--remote-debugging-port=0'],
  });
  const expires = Math.floor(Date.now() / 1000) + 3600;
  const seeded = [['gh_host', 'github.com'], ['gh_parent', '.github.com'], ['gist_only', 'gist.github.com'], ['org_host', 'sub.example.org'], ['org_parent', '.example.org'], ['org_sibling', 'other.example.org'], ['bank_secret', 'bank.test']];
  await user.addCookies(seeded.map(([name, domain]) => ({name, value: name + '-value', domain, path: '/', secure: true, httpOnly: true, sameSite: 'Lax', expires})));
  const worker = user.serviceWorkers()[0] || await user.waitForEvent('serviceworker');
  await worker.evaluate(() => {
    globalThis.readDomains = [];
    globalThis.originalGetAll = chrome.cookies.getAll.bind(chrome.cookies);
    chrome.cookies.getAll = async filter => {
      const found = await originalGetAll(filter);
      readDomains.push(...found.map(c => c.domain));
      return found;
    };
    return chrome.storage.local.set({approved: ['https://github.com', 'https://sub.example.org']});
  });
  const devtoolsPort = Number(readFileSync(join(work, 'user-chrome', 'DevToolsActivePort'), 'utf8').split('\n')[0]);
  const targets = await (await fetch('http://127.0.0.1:' + devtoolsPort + '/json/list')).json();
  const target = targets.find(t => t.type === 'service_worker' && t.url.endsWith('/background.js')).webSocketDebuggerUrl;
  const devtools = new WebSocket(target);
  Object.assign(devtools, {frames: [], results: new Map(), calls: 0});
  devtools.on('message', data => capture(devtools, data));
  await once(devtools, 'open');
  await call(devtools, 'Network.enable');
  server = spawn(process.execPath, [join(app, 'syncme.js'), 'serve'], {env, stdio: 'ignore'});
  for (let i = 0; i < 100 && !(await fetch('http://127.0.0.1:' + port + '/').then(() => true, () => false)); i++) await sleep(100);
  await worker.evaluate(() => connect());
  for (let i = 0; i < 100 && !(await worker.evaluate(() => chrome.storage.session.get('connected'))).connected; i++) await sleep(100);

  user.on('page', page => page.url().includes('approve.html') && page.close());
  const result = await request({op: 'sync', origins: ['https://github.com', 'https://sub.example.org', 'https://denied.test', 'https://github.com']});
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.count, 4);
  assert.deepEqual(result.failed, ['https://denied.test']);
  const mixed = await request({op: 'sync', origins: ['not-an-origin', 'https://github.com']});
  assert.equal(mixed.ok, true, JSON.stringify(mixed));
  assert.deepEqual(mixed.failed, ['not-an-origin']);
  assert.deepEqual(await request({op: 'sync', origins: ['https://denied.test']}), {error: 'Request rejected', failed: ['https://denied.test']});

  const profiles = readdirSync(state).filter(name => name.startsWith('browser'));
  assert.equal(profiles.length, 1, 'ai browser profiles: ' + profiles);
  assert.match(profiles[0], /^browser-/);
  ai = await chromium.connectOverCDP(result.cdp);
  const copied = (await ai.contexts()[0].cookies()).map(c => c.name).sort();
  assert.deepEqual(copied, ['gh_host', 'gh_parent', 'org_host', 'org_parent']);
  const read = await worker.evaluate(() => readDomains);
  assert.ok(!read.some(domain => domain.endsWith('bank.test')), 'extension read unrelated cookies: ' + read);
  await ai.close();

  const mcp = spawn(process.execPath, [join(app, 'syncme.js')], {env, stdio: ['pipe', 'pipe', 'ignore']});
  const lines = createInterface({input: mcp.stdout})[Symbol.asyncIterator]();
  mcp.stdin.write(JSON.stringify({jsonrpc: '2.0', id: 1, method: 'tools/call', params: {name: 'copy_site', arguments: {sites: ['https://github.com', 'https://denied.test']}}}) + '\n');
  const tool = JSON.parse((await lines.next()).value).result;
  mcp.kill();
  assert.equal(tool.isError, false);
  const text = JSON.parse(tool.content[0].text);
  assert.equal(text.copied_cookies, 2);
  assert.deepEqual(text.not_copied, ['https://denied.test']);

  await sleep(200);
  const {secret} = await worker.evaluate(() => chrome.storage.local.get('secret'));
  assert.match(secret, /^[0-9a-f]{64}$/);
  assert.equal(readFileSync(join(state, 'pair'), 'utf8'), secret);
  const parsed = [];
  for (const frame of devtools.frames) {
    let message = {};
    try {
      message = JSON.parse(frame.data);
    } catch {}
    parsed.push({...frame, message});
  }
  assert.ok(parsed.some(frame => frame.message.op === 'pair'), 'first connection not captured');
  for (const frame of devtools.frames) {
    assert.ok(!frame.data.includes(secret), 'secret crossed the socket: ' + frame.data);
    for (const [name] of seeded) assert.ok(!frame.data.includes(name + '-value'), 'cookie in clear: ' + frame.data);
  }
  let sealed = 0;
  for (const id of new Set(parsed.map(frame => frame.socket))) {
    const frames = parsed.filter(frame => frame.socket === id);
    const ready = frames.findIndex(frame => frame.message.op === 'ready');
    if (ready < 0) continue;
    for (const frame of frames.slice(ready + 1)) assert.equal(frame.message.op, 'enc', 'plain frame after ready: ' + frame.data);
    sealed += frames.length - ready - 1;
  }
  assert.ok(sealed > 0, 'no frames captured after ready');
  await call(devtools, 'Network.disable');

  await worker.evaluate(() => (chrome.cookies.getAll = originalGetAll, readDomains = []));
  for (let i = 0; i < 20; i++) await request({op: 'sync', origins: ['https://github.com', 'https://sub.example.org']});
  const before = await heap(devtools);
  const started = Date.now();
  for (let i = 0; i < 500; i++) assert.equal((await request({op: 'sync', origins: ['https://github.com', 'https://sub.example.org']})).count, 4);
  const seconds = (Date.now() - started) / 1000;
  const after = await heap(devtools);
  devtools.close();
  console.log(JSON.stringify({syncs: 500, sites_per_sync: 2, seconds, heap_before_kb: Math.round(before / 1024), heap_after_kb: Math.round(after / 1024), growth_kb: Math.round((after - before) / 1024)}));
  assert.ok(after - before < 512 * 1024, 'extension heap grew more than 512 KB');

  await tamper(secret, 0, true);
  await tamper(secret, 1, false);

  const exited = new Promise(resolve => server.exitCode === null ? server.once('exit', resolve) : resolve());
  assert.equal((await request({op: 'shutdown'})).ok, true);
  await Promise.race([exited, sleep(5000)]);
  assert.deepEqual(readdirSync(state).filter(name => name.startsWith('browser')), [], 'ai browser profile left behind');
  console.log('sync e2e passed');
} finally {
  if (server?.exitCode === null) await request({op: 'shutdown'}).catch(() => {});
  await user?.close().catch(() => {});
  server?.kill();
  rmSync(work, {recursive: true, force: true});
}
