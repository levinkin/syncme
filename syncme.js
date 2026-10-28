#!/usr/bin/env node
import {spawn, spawnSync} from 'node:child_process';
import {createCipheriv, createDecipheriv, createHash, createHmac, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, timingSafeEqual} from 'node:crypto';
import {chmodSync, copyFileSync, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync} from 'node:fs';
import {homedir, tmpdir} from 'node:os';
import {dirname, join} from 'node:path';
import {createInterface} from 'node:readline';
import {fileURLToPath} from 'node:url';
import {chromium} from 'playwright-core';
import {getDomain} from 'tldts';
import {WebSocket, WebSocketServer} from 'ws';

const ROOT = dirname(fileURLToPath(import.meta.url));
const MANIFEST = JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8'));
const EXTENSION = createHash('sha256').update(Buffer.from(MANIFEST.key, 'base64')).digest('hex').slice(0, 32).replace(/[0-9a-f]/g, c => String.fromCharCode(97 + parseInt(c, 16)));
const ORIGIN = 'chrome-extension://' + EXTENSION;
const STATE = process.platform === 'win32' ? join(process.env.LOCALAPPDATA || homedir(), 'syncme') : process.platform === 'darwin' ? join(homedir(), 'Library', 'Application Support', 'syncme') : join(homedir(), '.local', 'state', 'syncme');
const PORT = 47621;
const LIMIT = 1024 * 1024;
const CLIENT_URL = 'ws://127.0.0.1:' + PORT + '/client';
const BRIDGE_URL = 'ws://127.0.0.1:' + PORT + '/';
const SERVER = {command: 'npx', args: ['-y', 'syncme-mcp@latest']};
const SAME_SITE = {no_restriction: 'None', lax: 'Lax', strict: 'Strict', unspecified: 'Lax'};

const rejected = phase => Object.assign(Error('Rejected'), {phase});
const hex64 = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const proof = (token, purpose) => createHmac('sha256', token).update(purpose).digest('hex');
const same = (left, right) => typeof left === 'string' && typeof right === 'string' && left.length === right.length && timingSafeEqual(Buffer.from(left), Buffer.from(right));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function privateState() {
  mkdirSync(STATE, {recursive: true, mode: 0o700});
  if (lstatSync(STATE).isSymbolicLink()) throw Error('Unsafe runtime directory');
  if (process.platform === 'win32') {
    const sid = spawnSync('whoami', ['/user', '/fo', 'csv', '/nh'], {encoding: 'utf8'}).stdout.trim().split(',').pop().trim().replaceAll('"', '');
    const result = spawnSync('icacls', [STATE, '/inheritance:r', '/grant:r', '*' + sid + ':(OI)(CI)F'], {stdio: 'ignore'});
    if (result.status !== 0) throw Error('Unsafe runtime permissions');
  } else chmodSync(STATE, 0o700);
  const token = join(STATE, 'token');
  try {
    writeFileSync(token, randomBytes(32).toString('hex'), {flag: 'wx', mode: 0o600});
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  return readFileSync(token, 'utf8');
}

function send(socket, value) {
  const data = JSON.stringify(value);
  if (!data.length || Buffer.byteLength(data) > LIMIT) throw Error('Message too large');
  if (socket.readyState !== WebSocket.OPEN) throw Error('Disconnected');
  socket.send(data);
}

function iv(n) {
  const value = Buffer.alloc(12);
  value.writeBigUInt64BE(BigInt(n), 4);
  return value;
}

function wipe(dir) {
  if (!dir) return;
  try {
    rmSync(dir, {recursive: true, force: true, maxRetries: 10, retryDelay: 200});
  } catch {}
}

function seal(socket, value) {
  const cipher = createCipheriv('aes-256-gcm', socket.out.key, iv(socket.out.n));
  const data = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final(), cipher.getAuthTag()]).toString('base64');
  send(socket, {op: 'enc', n: socket.out.n, data});
  socket.out.n++;
}

function unseal(socket, frame) {
  if (frame.op !== 'enc' || frame.n !== socket.in.n || typeof frame.data !== 'string') throw Error('Bad frame');
  const data = Buffer.from(frame.data, 'base64');
  if (data.length < 17) throw Error('Bad frame');
  const decipher = createDecipheriv('aes-256-gcm', socket.in.key, iv(socket.in.n));
  decipher.setAuthTag(data.subarray(-16));
  const value = JSON.parse(Buffer.concat([decipher.update(data.subarray(0, -16)), decipher.final()]).toString());
  socket.in.n++;
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Bad frame');
  return value;
}

function messages(socket) {
  const queue = [];
  const waiting = [];
  let failure;
  const fail = () => {
    failure = failure || Error('Connection closed');
    for (const waiter of waiting.splice(0)) waiter.reject(failure);
  };
  socket.on('message', data => {
    let value;
    try {
      value = JSON.parse(data.toString());
    } catch {
      return fail();
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) return fail();
    if (waiting.length) waiting.shift().resolve(value);
    else queue.push(value);
  });
  socket.on('close', fail);
  socket.on('error', fail);
  return () => {
    if (queue.length) return Promise.resolve(queue.shift());
    if (failure) return Promise.reject(failure);
    return new Promise((resolve, reject) => waiting.push({resolve, reject}));
  };
}

async function authorize(socket, next, token) {
  const challenge = randomBytes(32).toString('hex');
  send(socket, {challenge});
  const auth = await next();
  if (!hex64(auth.nonce) || !same(auth.proof, proof(token, 'client:' + challenge))) {
    send(socket, {error: 'Unauthorized'});
    return false;
  }
  send(socket, {proof: proof(token, 'server:' + auth.nonce)});
  return true;
}

async function authenticate(socket, next, token) {
  const {challenge} = await next();
  if (!hex64(challenge)) throw Error('Invalid broker challenge');
  const nonce = randomBytes(32).toString('hex');
  send(socket, {proof: proof(token, 'client:' + challenge), nonce});
  const {proof: answer} = await next();
  if (!same(answer, proof(token, 'server:' + nonce))) throw Error('Untrusted local endpoint');
}

function origin(value) {
  if (typeof value !== 'string' || value.length > 2048 || !/^[\x21-\x7e]+$/.test(value) || value.includes('\\')) throw rejected('origin');
  let url;
  try {
    url = new URL(value);
  } catch {
    throw rejected('origin');
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash || url.origin !== value) throw rejected('origin');
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(url.hostname) || url.hostname.includes('..')) throw rejected('origin');
  return url;
}

function cookiesFor(site, cookies) {
  if (!Array.isArray(cookies) || cookies.length > 3000) throw rejected('cookies');
  const registrable = getDomain(site.hostname, {allowPrivateDomains: true});
  const result = [];
  for (const c of cookies) {
    if (!c || typeof c !== 'object' || typeof c.domain !== 'string' || c.partitionKey) throw rejected('cookies');
    for (const field of ['name', 'value', 'domain', 'path']) {
      if (typeof c[field] !== 'string' || c[field].length > 16384) throw rejected('cookies');
    }
    if (!c.path.startsWith('/') || ['secure', 'httpOnly', 'hostOnly', 'session'].some(field => typeof c[field] !== 'boolean')) throw rejected('cookies');
    if (c.hostOnly ? c.domain !== site.hostname : !registrable || !c.domain.startsWith('.') || c.domain.length <= registrable.length || !('.' + site.hostname).endsWith(c.domain)) throw rejected('cookies');
    if (c.secure && site.protocol !== 'https:') throw rejected('cookies');
    const item = {name: c.name, value: c.value, path: c.path, secure: c.secure, httpOnly: c.httpOnly};
    item.domain = c.hostOnly ? site.hostname : c.domain;
    if (!Object.hasOwn(SAME_SITE, c.sameSite)) throw rejected('cookies');
    item.sameSite = SAME_SITE[c.sameSite];
    if (!c.session) {
      const expiry = c.expirationDate;
      if (typeof expiry !== 'number' || !Number.isFinite(expiry) || expiry <= 0) throw rejected('cookies');
      item.expires = expiry;
    }
    result.push(item);
  }
  return result;
}

function connectSocket(url) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url, {handshakeTimeout: 5000});
    socket.on('error', () => reject(Error('offline')));
    socket.once('open', () => resolve(socket));
  });
}

async function startServer(launch) {
  const token = privateState();
  for (let attempt = 0; attempt < 61; attempt++) {
    let socket;
    try {
      socket = await connectSocket(CLIENT_URL);
      await authenticate(socket, messages(socket), token);
      return socket;
    } catch {
      socket?.close();
      if (!launch) return null;
      if (attempt === 0) spawn(process.execPath, [process.argv[1], 'serve'], {detached: true, stdio: 'ignore', windowsHide: true}).unref();
    }
    await sleep(100);
  }
  throw Error('Could not start syncme bridge');
}

async function request(message) {
  const socket = await startServer(message.op === 'sync' || message.op === 'open');
  if (!socket) return {ok: true};
  const next = messages(socket);
  try {
    send(socket, message);
    return await Promise.race([next(), new Promise(resolve => setTimeout(resolve, 150000 * (message.origins?.length || 1), {error: 'Timed out'}).unref())]);
  } finally {
    socket.close();
  }
}

function verify(info, done) {
  const path = new URL(info.req.url, 'http://127.0.0.1').pathname;
  if (path === '/client') return done(!info.req.headers.origin);
  if (path !== '/') return done(false);
  done(info.origin === ORIGIN);
}

async function serve() {
  const token = privateState();
  const server = new WebSocketServer({host: '127.0.0.1', port: PORT, maxPayload: LIMIT, verifyClient: verify});
  server.on('error', () => process.exit(0));
  await new Promise(resolve => server.once('listening', resolve));
  for (const name of readdirSync(STATE)) if (name === 'browser' || name.startsWith('browser-')) wipe(join(STATE, name));
  let bridge, context, endpoint, profile;
  let headless = false;
  const pending = new Map();
  let queue = Promise.resolve();
  const enqueue = task => (queue = queue.then(task, task).catch(() => {}));
  process.on('exit', () => wipe(profile));
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => closeBrowser().finally(() => process.exit(0)));

  async function closeBrowser() {
    const current = context;
    context = endpoint = undefined;
    if (current) {
      try {
        await current.close();
      } catch {}
    }
    wipe(profile);
    profile = undefined;
  }

  function ask(message) {
    if (!bridge) throw rejected('bridge');
    const id = randomBytes(16).toString('hex');
    const response = new Promise((resolve, reject) => {
      const timer = setTimeout(() => pending.delete(id) && reject(rejected('bridge')), 120000);
      pending.set(id, {resolve: value => (clearTimeout(timer), resolve(value)), reject: error => (clearTimeout(timer), reject(error))});
    });
    seal(bridge, {...message, id});
    return response;
  }

  function bridgeGone(socket) {
    if (bridge !== socket) return;
    bridge = undefined;
    for (const waiter of pending.values()) waiter.reject(Error('Bridge disconnected'));
    pending.clear();
  }

  async function copyIntoBrowser(values, fromExtension) {
    if (values.length && !bridge) throw rejected('bridge');
    if (context) {
      try {
        await context.cookies('https://syncme.invalid');
      } catch {
        await closeBrowser();
      }
    }
    let carried = [];
    if (context && headless && !fromExtension) {
      carried = await context.cookies();
      await context.close();
      context = endpoint = undefined;
      wipe(profile);
      profile = undefined;
    }
    if (!context) {
      headless = fromExtension;
      profile = mkdtempSync(join(STATE, 'browser-'));
      if (process.platform !== 'win32') chmodSync(profile, 0o700);
      try {
        context = await chromium.launchPersistentContext(profile, {channel: 'chrome', headless, args: ['--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0']});
      } catch (error) {
        wipe(profile);
        profile = undefined;
        throw error;
      }
      const launched = context, dir = profile;
      launched.once('close', () => {
        if (context === launched) context = endpoint = profile = undefined;
        wipe(dir);
      });
      await context.addCookies(carried);
      const port = Number(readFileSync(join(profile, 'DevToolsActivePort'), 'utf8').split('\n')[0]);
      if (!(port > 0 && port < 65536)) throw Error('Invalid owned browser endpoint');
      endpoint = 'http://127.0.0.1:' + port;
      if (bridge) {
        const listed = await ask({op: 'list'});
        if (!Array.isArray(listed.origins) || listed.origins.length > 1000) throw rejected('bridge');
        for (const value of listed.origins) if (!values.includes(value)) values.push(value);
      }
    }
    let count = 0;
    const failed = [];
    for (const value of values) {
      try {
        const site = origin(value);
        const response = await ask({op: 'sync', origin: value});
        if (response.origin !== value || response.error) throw rejected('bridge');
        const cookies = cookiesFor(site, response.cookies);
        for (const cookie of await context.cookies()) {
          if ((cookie.domain === site.hostname || cookie.domain.startsWith('.') && ('.' + site.hostname).endsWith(cookie.domain)) && (site.protocol === 'https:' || !cookie.secure)) await context.clearCookies({name: cookie.name, domain: cookie.domain, path: cookie.path});
        }
        await context.addCookies(cookies);
        count += cookies.length;
      } catch {
        failed.push(value);
      }
    }
    return {count, failed};
  }

  function bridgeMessage(socket, message) {
    const waiter = typeof message.id === 'string' ? pending.get(message.id) : undefined;
    if (waiter) {
      pending.delete(message.id);
      waiter.resolve(message);
      return;
    }
    if (message.op === 'copied' || message.op === 'ping') return;
    if (message.op !== 'copy' || typeof message.id !== 'string' || message.id.length > 64) return socket.close();
    if (pending.size) return seal(socket, {op: 'copied', id: message.id, error: 'Busy'});
    enqueue(async () => {
      const reply = {op: 'copied', id: message.id};
      try {
        const {count, failed} = await copyIntoBrowser([message.origin], true);
        seal(socket, failed.length ? {...reply, error: 'Request rejected'} : {...reply, ok: true, cdp: endpoint, count});
      } catch (error) {
        try {
          seal(socket, {...reply, error: error.phase ? 'Request rejected' : 'Owned browser operation failed', phase: error.phase});
        } catch {}
      }
    });
  }

  function shutdown(socket) {
    for (const waiter of pending.values()) waiter.reject(Error('Shutting down'));
    pending.clear();
    const current = bridge;
    bridge = undefined;
    if (current) current.close();
    server.close();
    closeBrowser().finally(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  }

  async function client(socket, next) {
    const guard = setTimeout(() => socket.close(), 30000);
    let message;
    try {
      if (!(await authorize(socket, next, token))) return socket.close();
      message = await next();
    } catch {
      return socket.close();
    } finally {
      clearTimeout(guard);
    }
    enqueue(() => operate(socket, message));
  }

  async function operate(socket, message) {
    try {
      const op = message.op;
      if (op === 'sync' || op === 'open') {
        if (op === 'sync' && (!Array.isArray(message.origins) || !message.origins.length || message.origins.length > 100)) throw rejected('origin');
        const origins = op === 'sync' ? [...new Set(message.origins)] : [];
        const {count, failed} = await copyIntoBrowser([...origins], false);
        send(socket, origins.length && origins.every(site => failed.includes(site)) ? {error: 'Request rejected', failed} : {ok: true, cdp: endpoint, count, failed});
      } else if (op === 'stop' || op === 'shutdown') {
        await closeBrowser();
        send(socket, {ok: true});
      } else return send(socket, {error: 'Unknown operation'});
    } catch (error) {
      try {
        send(socket, {error: error.phase ? 'Request rejected' : 'Owned browser operation failed', phase: error.phase});
      } catch {}
    }
    socket.close();
    if (message.op === 'shutdown') shutdown(socket);
  }

  server.on('connection', (socket, incoming) => {
    if (new URL(incoming.url, 'http://127.0.0.1').pathname === '/client') {
      client(socket, messages(socket));
      return;
    }
    const next = messages(socket);
    (async () => {
      const guard = setTimeout(() => socket.close(), 10000);
      try {
        const pairFile = join(STATE, 'pair');
        let secret = existsSync(pairFile) ? readFileSync(pairFile, 'utf8') : '';
        const nonce = randomBytes(32).toString('hex');
        const pair = secret ? undefined : generateKeyPairSync('x25519');
        send(socket, pair ? {op: 'hello', nonce, paired: false, key: Buffer.from(pair.publicKey.export({format: 'jwk'}).x, 'base64url').toString('base64')} : {op: 'hello', nonce, paired: true});
        let message = await next();
        if (pair) {
          const key = typeof message.key === 'string' ? Buffer.from(message.key, 'base64') : Buffer.alloc(0);
          if (message.op !== 'pair' || key.length !== 32 || key.toString('base64') !== message.key) return socket.close();
          const shared = diffieHellman({privateKey: pair.privateKey, publicKey: createPublicKey({key: {kty: 'OKP', crv: 'X25519', x: key.toString('base64url')}, format: 'jwk'})});
          secret = Buffer.from(hkdfSync('sha256', shared, Buffer.alloc(0), 'syncme pair v1', 32)).toString('hex');
          writeFileSync(pairFile, secret, {flag: 'wx', mode: 0o600});
          message = await next();
        }
        if (message.op !== 'proof' || !hex64(message.nonce) || !same(message.proof, proof(secret, 'extension:' + nonce))) {
          send(socket, {op: 'refused'});
          return socket.close();
        }
        clearTimeout(guard);
        send(socket, {op: 'ready', proof: proof(secret, 'server:' + message.nonce)});
        const salt = Buffer.from(nonce + message.nonce, 'hex');
        socket.out = {key: Buffer.from(hkdfSync('sha256', Buffer.from(secret, 'hex'), salt, 'syncme wire v1 b2e', 32)), n: 0};
        socket.in = {key: Buffer.from(hkdfSync('sha256', Buffer.from(secret, 'hex'), salt, 'syncme wire v1 e2b', 32)), n: 0};
        if (bridge) {
          const previous = bridge;
          bridgeGone(previous);
          previous.close();
        }
        bridge = socket;
        for (;;) {
          message = unseal(socket, await next());
          if (bridge !== socket) break;
          bridgeMessage(socket, message);
        }
      } catch {
        socket.close();
        bridgeGone(socket);
      } finally {
        clearTimeout(guard);
      }
    })();
  });
}

function pack() {
  const stage = mkdtempSync(join(tmpdir(), 'syncme-pack-'));
  const zip = join(ROOT, 'syncme.zip');
  try {
    const {key, ...store} = MANIFEST;
    writeFileSync(join(stage, 'manifest.json'), JSON.stringify(store, null, 2));
    for (const name of ['background.js', 'approve.html', 'approve.js', 'options.html', 'options.js']) copyFileSync(join(ROOT, name), join(stage, name));
    cpSync(join(ROOT, 'icons'), join(stage, 'icons'), {recursive: true});
    rmSync(zip, {force: true});
    const result = process.platform === 'win32'
      ? spawnSync('powershell', ['-NoProfile', '-Command', `Compress-Archive -Path '${join(stage, '*')}' -DestinationPath '${zip}' -Force`], {stdio: 'ignore'})
      : spawnSync('zip', ['-r', '-X', '-q', zip, 'manifest.json', 'background.js', 'approve.html', 'approve.js', 'options.html', 'options.js', 'icons'], {cwd: stage, stdio: 'ignore'});
    if (result.status !== 0) throw Error('Pack failed');
  } finally {
    rmSync(stage, {recursive: true, force: true});
  }
  console.log(JSON.stringify({packed: zip}));
}

function setup() {
  const home = homedir();
  const appData = process.platform === 'win32' ? process.env.APPDATA || join(home, 'AppData', 'Roaming') : join(home, 'Library', 'Application Support');
  const vscode = join(appData, 'Code', 'User');
  const configured = [];
  const failed = [];
  for (const [name, file, key, server] of [
    ['claude desktop', join(appData, 'Claude', 'claude_desktop_config.json'), 'mcpServers', SERVER],
    ['cursor', join(home, '.cursor', 'mcp.json'), 'mcpServers', SERVER],
    ['windsurf', join(home, '.codeium', 'windsurf', 'mcp_config.json'), 'mcpServers', SERVER],
    ['gemini', join(home, '.gemini', 'settings.json'), 'mcpServers', SERVER],
    ['qwen', join(home, '.qwen', 'settings.json'), 'mcpServers', SERVER],
    ['kiro', join(home, '.kiro', 'settings', 'mcp.json'), 'mcpServers', SERVER],
    ['copilot cli', join(home, '.copilot', 'mcp-config.json'), 'mcpServers', {type: 'local', ...SERVER, tools: ['*']}],
    ['opencode', join(home, '.config', 'opencode', 'opencode.json'), 'mcp', {type: 'local', command: [SERVER.command, ...SERVER.args], enabled: true}],
    ['amp', join(home, '.config', 'amp', 'settings.json'), 'amp.mcpServers', SERVER],
    ['cline', join(vscode, 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'), 'mcpServers', SERVER],
    ['roo code', join(vscode, 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json'), 'mcpServers', SERVER],
  ]) {
    if (!existsSync(dirname(file))) continue;
    try {
      const existing = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : {};
      if (!existing || typeof existing !== 'object' || Array.isArray(existing)) throw Error('Unreadable config');
      const servers = existing[key] && typeof existing[key] === 'object' && !Array.isArray(existing[key]) ? existing[key] : {};
      writeFileSync(file, JSON.stringify({...existing, [key]: {...servers, syncme: server}}, null, 2) + '\n');
      configured.push(name);
    } catch {
      failed.push(file);
    }
  }
  for (const [name, args, input] of [
    ['claude', ['mcp', 'add', '--scope', 'user', 'syncme', '--', 'npx', '-y', 'syncme-mcp@latest']],
    ['codex', ['mcp', 'add', 'syncme', '--', 'npx', '-y', 'syncme-mcp@latest']],
    ['hermes', ['mcp', 'add', 'syncme', '--command', 'npx', '--args', '-y', 'syncme-mcp@latest'], 'y\n'],
    ['code', ['--add-mcp', JSON.stringify({name: 'syncme', ...SERVER})]],
  ]) {
    const result = spawnSync(name, args, {input: input || '', stdio: ['pipe', 'ignore', 'ignore'], timeout: 120000});
    if (result.status === 0) configured.push(name + ' cli');
    else if (!result.error || result.error.code !== 'ENOENT') failed.push(name + ' cli');
  }
  console.log(JSON.stringify({configured, failed}));
}

function mcp() {
  const tools = [
    {name: 'copy_site', description: "Copy the user's login cookies for one or more sites (like https://github.com) from their Chrome into the AI browser, then return the AI browser's CDP url. If a site isn't saved yet, the user gets asked in Chrome first. Sites that were not copied are listed in not_copied.", inputSchema: {type: 'object', properties: {sites: {type: 'array', items: {type: 'string', description: 'exact origin, like https://github.com'}, minItems: 1, maxItems: 100}}, required: ['sites']}},
    {name: 'open_browser', description: "Start the AI browser with the user's saved logins and return its CDP url. Connect with Playwright connect_over_cdp or any CDP client.", inputSchema: {type: 'object', properties: {}}},
    {name: 'close_browser', description: 'Close the AI browser.', inputSchema: {type: 'object', properties: {}}},
  ];
  const versions = ['2025-06-18', '2025-03-26', '2024-11-05'];
  const names = tools.map(tool => tool.name);
  const write = value => process.stdout.write(JSON.stringify(value) + '\n');
  let queue = Promise.resolve();
  async function handle(line) {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      return write({jsonrpc: '2.0', id: null, error: {code: -32700, message: 'Parse error'}});
    }
    if (!message || typeof message !== 'object' || Array.isArray(message) || !('id' in message)) return;
    const params = message.params && typeof message.params === 'object' ? message.params : {};
    const args = params.arguments && typeof params.arguments === 'object' ? params.arguments : {};
    const method = message.method;
    if (method === 'tools/call' && !names.includes(params.name)) return write({jsonrpc: '2.0', id: message.id, error: {code: -32602, message: 'Unknown tool'}});
    if (method === 'tools/call' && params.name === 'copy_site' && (!Array.isArray(args.sites) || !args.sites.length || args.sites.length > 100 || args.sites.some(site => typeof site !== 'string'))) return write({jsonrpc: '2.0', id: message.id, error: {code: -32602, message: 'copy_site needs a sites array of 1 to 100 strings'}});
    let result;
    if (method === 'initialize') {
      const requested = params.protocolVersion;
      result = {protocolVersion: versions.includes(requested) ? requested : versions[0], capabilities: {tools: {}}, serverInfo: {name: 'syncme', version: MANIFEST.version}};
    } else if (method === 'tools/list') {
      result = {tools};
    } else if (method === 'tools/call') {
      let response;
      try {
        if (params.name === 'copy_site') {
          response = await request({op: 'sync', origins: args.sites});
        } else response = await request({op: params.name === 'open_browser' ? 'open' : 'stop'});
      } catch {
        response = {error: 'syncme bridge unavailable or site invalid'};
      }
      let text;
      if (response.error) text = 'Failed: ' + response.error + '. The site must be an exact origin like https://github.com, Chrome must be open with the syncme extension, and the user must allow the site.';
      else if (params.name === 'close_browser') text = 'AI browser closed.';
      else text = JSON.stringify({cdp: response.cdp, copied_cookies: response.count, ...(response.failed.length && {not_copied: response.failed})});
      result = {content: [{type: 'text', text}], isError: Boolean(response.error)};
    } else if (method === 'ping') {
      result = {};
    } else return write({jsonrpc: '2.0', id: message.id, error: {code: -32601, message: 'Method not found'}});
    write({jsonrpc: '2.0', id: message.id, result});
  }
  createInterface({input: process.stdin}).on('line', line => (queue = queue.then(() => handle(line)).catch(() => {})));
}

async function main() {
  const command = process.argv[2] || '';
  if (!command) return mcp();
  if (command === 'serve') return serve();
  if (command === 'pack') return pack();
  if (command === 'setup') return setup();
  if (command === 'unpair') return rmSync(join(STATE, 'pair'), {force: true});
  if (!['sync', 'open', 'stop', 'shutdown'].includes(command) || (command === 'sync' ? process.argv.length < 4 : process.argv.length !== 3)) throw Error('Usage: syncme-mcp open | sync https://example.com [https://other.com ...] | stop | shutdown | setup | unpair | pack');
  const message = {op: command};
  if (command === 'sync') {
    message.origins = process.argv.slice(3);
  }
  const response = await request(message);
  console.log(JSON.stringify(response));
  if (response.error) process.exitCode = 1;
}

try {
  await main();
} catch {
  console.error(JSON.stringify({error: 'syncme failed; check the origin and that chrome has the syncme extension'}));
  process.exit(1);
}
