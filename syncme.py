#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
MANIFEST = json.loads((ROOT / 'manifest.json').read_text())
EXTENSION = ''.join(chr(97 + int(c, 16)) for c in hashlib.sha256(base64.b64decode(MANIFEST['key'])).hexdigest()[:32])
CALLER = 'chrome-extension://' + EXTENSION + '/'
STATE = Path(os.environ['LOCALAPPDATA']) / 'syncme' if os.name == 'nt' else Path.home() / 'Library/Application Support/syncme'
LIMIT = 1024 * 1024


def private_state():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if STATE.is_symlink():
        raise ValueError('Unsafe runtime directory')
    if os.name == 'nt':
        sid = subprocess.check_output(['whoami', '/user', '/fo', 'csv', '/nh'], text=True).strip().split(',')[-1].strip('"')
        subprocess.run(['icacls', str(STATE), '/inheritance:r', '/grant:r', '*' + sid + ':(OI)(CI)F'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        os.chmod(STATE, 0o700)
    token = STATE / 'token'
    try:
        fd = os.open(token, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, 'w') as f:
            f.write(secrets.token_hex(32))
    return token.read_text()


def read_exact(stream, n):
    data = bytearray()
    while len(data) < n:
        chunk = stream.recv(n - len(data)) if isinstance(stream, socket.socket) else stream.read(n - len(data))
        if not chunk:
            raise EOFError()
        data.extend(chunk)
    return bytes(data)


def receive(stream):
    n, = struct.unpack('<I', read_exact(stream, 4))
    if not 0 < n <= LIMIT:
        raise ValueError('Invalid frame')
    value = json.loads(read_exact(stream, n))
    if not isinstance(value, dict):
        raise ValueError('Invalid message')
    return value


def send(stream, value):
    data = json.dumps(value, separators=(',', ':'), allow_nan=False).encode()
    if not 0 < len(data) <= LIMIT:
        raise ValueError('Message too large')
    frame = struct.pack('<I', len(data)) + data
    if isinstance(stream, socket.socket):
        stream.sendall(frame)
    else:
        stream.write(frame)
        stream.flush()


def origin(value):
    if not isinstance(value, str) or len(value) > 2048 or not value.isascii() or '\\' in value:
        raise ValueError('Invalid origin')
    u = urlsplit(value)
    if u.scheme not in ('http', 'https') or not u.hostname or u.username is not None or u.password is not None or u.path or u.query or u.fragment:
        raise ValueError('Use an exact http(s) origin without a trailing slash')
    host = u.hostname
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host) or '..' in host:
        raise ValueError('Invalid host')
    port = u.port
    canonical = u.scheme + '://' + host + ((':' + str(port)) if port and port != (443 if u.scheme == 'https' else 80) else '')
    if canonical != value:
        raise ValueError('Use a canonical origin')
    return u


SAME_SITE = {'no_restriction': 'None', 'lax': 'Lax', 'strict': 'Strict', 'unspecified': 'Lax'}


def cookies_for(u, cookies):
    if not isinstance(cookies, list) or len(cookies) > 3000:
        raise ValueError('Invalid cookies')
    result = []
    for c in cookies:
        if not isinstance(c, dict) or c.get('domain', '').removeprefix('.') != u.hostname or c.get('partitionKey'):
            raise ValueError('Cookie outside approved host')
        for field in ('name', 'value', 'domain', 'path'):
            if not isinstance(c.get(field), str) or len(c[field]) > 16384:
                raise ValueError('Invalid cookie field')
        if not c['path'].startswith('/') or any(type(c.get(f)) is not bool for f in ('secure', 'httpOnly', 'hostOnly', 'session')):
            raise ValueError('Invalid cookie flags')
        if c['secure'] and u.scheme != 'https':
            raise ValueError('Secure cookie requires HTTPS')
        item = {k: c[k] for k in ('name', 'value', 'path', 'secure', 'httpOnly')}
        item['domain'] = u.hostname if c['hostOnly'] else c['domain']
        if c.get('sameSite') not in SAME_SITE:
            raise ValueError('Invalid SameSite')
        item['sameSite'] = SAME_SITE[c['sameSite']]
        if not c['session']:
            expiry = c.get('expirationDate')
            if type(expiry) not in (int, float) or not math.isfinite(expiry) or expiry <= 0:
                raise ValueError('Invalid expiry')
            item['expires'] = expiry
        result.append(item)
    return result


def connect():
    info = json.loads((STATE / 'endpoint.json').read_text())
    if set(info) != {'port'} or type(info['port']) is not int or not 0 < info['port'] < 65536:
        raise ValueError('Invalid endpoint')
    return socket.create_connection(('127.0.0.1', info['port']), timeout=25)



def authenticate(s, token):
    challenge = receive(s).get('challenge')
    if not isinstance(challenge, str) or not re.fullmatch('[0-9a-f]{64}', challenge):
        raise ValueError('Invalid broker challenge')
    nonce = secrets.token_hex(32)
    proof = hmac.new(token.encode(), ('client:' + challenge).encode(), 'sha256').hexdigest()
    send(s, {'proof': proof, 'nonce': nonce})
    expected = hmac.new(token.encode(), ('server:' + nonce).encode(), 'sha256').hexdigest()
    response = receive(s).get('proof', '')
    if not isinstance(response, str) or not hmac.compare_digest(response, expected):
        raise ValueError('Untrusted local endpoint')


def authorize(s, token):
    challenge = secrets.token_hex(32)
    send(s, {'challenge': challenge})
    auth = receive(s)
    expected = hmac.new(token.encode(), ('client:' + challenge).encode(), 'sha256').hexdigest()
    nonce, proof = auth.get('nonce'), auth.get('proof')
    if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{64}', nonce) or not isinstance(proof, str) or not hmac.compare_digest(proof, expected):
        send(s, {'error': 'Unauthorized'})
        return False
    send(s, {'proof': hmac.new(token.encode(), ('server:' + nonce).encode(), 'sha256').hexdigest()})
    return True


def start_server(spawn):
    token = private_state()
    for attempt in range(61):
        s = None
        try:
            s = connect()
            authenticate(s, token)
            return s
        except (OSError, ValueError, EOFError):
            if s:
                s.close()
            if not spawn:
                return None
            if attempt == 0:
                subprocess.Popen([sys.executable, str(ROOT / 'syncme.py'), 'serve'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            time.sleep(0.1)
    raise ValueError('Could not start syncme bridge')


def native():
    if len(sys.argv) < 3 or sys.argv[2] != CALLER:
        raise ValueError('Untrusted extension')
    with start_server(True) as s:
        send(s, {'op': 'bridge'})
        if receive(s) != {'ok': True}:
            raise ValueError('Bridge unavailable')
        s.settimeout(None)
        send(sys.stdout.buffer, {'op': 'ready'})
        def replies():
            try:
                while True:
                    send(sys.stdout.buffer, receive(s))
            except (OSError, ValueError, EOFError):
                os._exit(1)
        threading.Thread(target=replies, daemon=True).start()
        while True:
            send(s, receive(sys.stdin.buffer))


def serve():
    token = private_state()
    lock = open(STATE / 'lock', 'a+b')
    try:
        if os.name == 'nt':
            import msvcrt
            lock.seek(0)
            if not lock.read(1):
                lock.write(b'0'); lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return
    from playwright.sync_api import Error, sync_playwright
    bridge = context = None
    endpoint = None
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(8)
    (STATE / 'endpoint.json').write_text(json.dumps({'port': listener.getsockname()[1]}))
    with sync_playwright() as pw:
        try:
            running = True
            def ask(message):
                nonce = secrets.token_hex(16)
                send(bridge, {**message, 'id': nonce})
                while True:
                    response = receive(bridge)
                    if response.get('id') == nonce:
                        return response
                    if response.get('op') != 'copy' or not isinstance(response.get('id'), str) or len(response['id']) > 64:
                        raise ValueError('Unexpected bridge message')
                    send(bridge, {'op': 'copied', 'id': response['id'], 'error': 'Busy'})
            while running:
                ready, _, _ = select.select([listener] + ([bridge] if bridge else []), [], [])
                s = None
                reply = {}
                if bridge and bridge in ready:
                    try:
                        request = receive(bridge)
                    except (OSError, ValueError, EOFError):
                        request = {}
                    if request.get('op') != 'copy' or not isinstance(request.get('id'), str) or len(request['id']) > 64:
                        bridge.close(); bridge = None
                        continue
                    reply = {'op': 'copied', 'id': request['id']}
                    request = {'op': 'sync', 'origin': request.get('origin')}
                    target = bridge
                elif listener in ready:
                    s, _ = listener.accept()
                    s.settimeout(3)
                    target = s
                else:
                    continue
                phase = 'ipc'
                try:
                    if s:
                        if not authorize(s, token):
                            continue
                        request = receive(s)
                    op = request.get('op')
                    if op == 'bridge':
                        if bridge:
                            send(s, {'error': 'Bridge already connected'}); continue
                        send(s, {'ok': True})
                        bridge, s = s, None
                        bridge.settimeout(20)
                    elif op in ('sync', 'open'):
                        phase = 'origin'
                        values = [request.get('origin')] if op == 'sync' else []
                        for value in values:
                            origin(value)
                        phase = 'bridge'
                        if values and not bridge:
                            raise ValueError('Bridge not connected')
                        if context is not None:
                            try:
                                context.cookies('https://syncme.invalid')
                            except Error:
                                context = endpoint = None
                        if context is None:
                            profile = STATE / 'browser'
                            profile.mkdir(mode=0o700, exist_ok=True)
                            (profile / 'DevToolsActivePort').unlink(missing_ok=True)
                            context = pw.chromium.launch_persistent_context(str(profile), channel='chrome', headless=True, args=['--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0'])
                            port = int((profile / 'DevToolsActivePort').read_text().splitlines()[0])
                            if not 0 < port < 65536:
                                raise ValueError('Invalid owned browser endpoint')
                            endpoint = 'http://127.0.0.1:' + str(port)
                            if bridge:
                                listed = ask({'op': 'list'})
                                if not isinstance(listed.get('origins'), list) or len(listed['origins']) > 1000:
                                    raise ValueError('Invalid site list')
                                values += [value for value in listed['origins'] if value not in values]
                        count = 0
                        for value in values:
                            phase = 'bridge'
                            u = origin(value)
                            response = ask({'op': 'sync', 'origin': value})
                            if response.get('origin') != value or response.get('error'):
                                raise ValueError('Origin unavailable or not approved')
                            phase = 'cookies'
                            cookies = cookies_for(u, response.get('cookies'))
                            for c in context.cookies():
                                if c['domain'].removeprefix('.') == u.hostname and (u.scheme == 'https' or not c['secure']):
                                    context.clear_cookies(name=c['name'], domain=c['domain'], path=c['path'])
                            context.add_cookies(cookies)
                            count += len(cookies)
                        send(target, {**reply, 'ok': True, 'cdp': endpoint, 'count': count})
                    elif op in ('stop', 'shutdown'):
                        if context:
                            context.close(); context = None; endpoint = None
                        send(target, {**reply, 'ok': True})
                        running = op != 'shutdown'
                    else:
                        send(target, {**reply, 'error': 'Unknown operation'})
                except (ValueError, OSError, EOFError):
                    if s or reply:
                        try: send(target, {**reply, 'error': 'Request rejected', 'phase': phase})
                        except OSError: pass
                except Exception:
                    if s or reply:
                        try: send(target, {**reply, 'error': 'Owned browser operation failed'})
                        except OSError: pass
                finally:
                    if s: s.close()
        finally:
            if context: context.close()
            if bridge: bridge.close()
            listener.close()
            (STATE / 'endpoint.json').unlink(missing_ok=True)
            lock.close()


def install():
    private_state()
    if os.name == 'nt':
        launcher = ROOT / 'native.cmd'
        launcher.write_text('@echo off\r\n"' + sys.executable + '" "' + str(ROOT / 'syncme.py') + '" native %*\r\n')
        host = ROOT / 'local.syncme.json'
    else:
        launcher = ROOT / 'native'
        import shlex
        launcher.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' ' + shlex.quote(str(ROOT / 'syncme.py')) + ' native "$@"\n')
        launcher.chmod(0o700)
        directory = Path.home() / 'Library/Application Support/Google/Chrome/NativeMessagingHosts'
        directory.mkdir(parents=True, exist_ok=True)
        host = directory / 'local.syncme.json'
    host.write_text(json.dumps({'name': 'local.syncme', 'description': 'syncme cookie bridge', 'path': str(launcher), 'type': 'stdio', 'allowed_origins': [CALLER]}, indent=2))
    if os.name == 'nt':
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r'Software\Google\Chrome\NativeMessagingHosts\local.syncme') as key:
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, str(host))
    else:
        host.chmod(0o600)
    print(json.dumps({'installed': str(host), 'extension': EXTENSION, 'load_unpacked': str(ROOT)}))


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else ''
    if command == 'native': native()
    elif command == 'serve': serve()
    elif command == 'install': install()
    elif command in ('sync', 'open', 'stop', 'shutdown'):
        if len(sys.argv) != (3 if command == 'sync' else 2):
            raise ValueError('Usage: syncme.py sync https://example.com | open | stop | shutdown | install')
        request = {'op': command}
        if command == 'sync':
            origin(sys.argv[2]); request['origin'] = sys.argv[2]
        s = start_server(command in ('sync', 'open'))
        if s is None:
            print(json.dumps({'ok': True}))
            return
        with s:
            s.settimeout(120)
            send(s, request)
            response = receive(s)
        print(json.dumps(response))
        if response.get('error'): sys.exit(1)
    else:
        raise ValueError('Usage: syncme.py install | sync https://example.com | open | stop | shutdown')


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt):
        if len(sys.argv) > 1 and sys.argv[1] != 'native':
            print(json.dumps({'error': 'syncme failed; check installation, origin and bridge connection'}), file=sys.stderr)
        sys.exit(1)
