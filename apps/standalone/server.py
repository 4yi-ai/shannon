"""Authenticated, persistent task API. Run: python3 -m apps.standalone.server."""
import base64
import binascii
import fcntl
import hmac
import json
import os
import re
import signal
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .runner import Runner
from .security import public_url
from .store import Store

MAX_BODY = 48 * 1024 * 1024
STATIC = Path(__file__).with_name('web')
REPORTS = {'markdown': ('Security-Assessment-Report.md', 'text/markdown; charset=utf-8'),
           'pdf': ('Security-Assessment-Report.pdf', 'application/pdf')}


def make_handler(store, runner, api_key):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'Shannon'

        def setup(self):
            super().setup()
            self.connection.settimeout(30)

        def view_task(self, task):
            return dict(task, reports={kind: (runner.directory(task['id']) / 'reports' / filename).is_file()
                                       for kind, (filename, _) in REPORTS.items()})

        def log_message(self, fmt, *args):
            # Never log request paths, tokens, target query strings or response bodies.
            pass

        def send(self, status, body, content_type='application/json', filename=None):
            if not isinstance(body, bytes):
                body = json.dumps(body, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            if filename:
                self.send_header('Content-Disposition', 'attachment; filename="' + filename + '"')
            self.end_headers()
            self.wfile.write(body)

        def authorized(self):
            supplied = self.headers.get('Authorization', '')
            return hmac.compare_digest(supplied.encode(), ('Bearer ' + api_key).encode())

        def do_GET(self):
            try:
                self.get()
            except (KeyError, FileNotFoundError):
                self.send(404, {'error': 'Not found'})
            except ValueError as error:
                self.send(400, {'error': str(error)})

        def get(self):
            parsed = urlsplit(self.path)
            path = parsed.path
            if path == '/healthz':
                self.send(200, {'status': 'ok'})
                return
            if path in ('/', '/app.js', '/style.css'):
                name = {'/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css'}[path]
                mime = {'/': 'text/html; charset=utf-8', '/app.js': 'text/javascript; charset=utf-8', '/style.css': 'text/css; charset=utf-8'}[path]
                self.send(200, (STATIC / name).read_bytes(), mime)
                return
            if path == '/source':
                self.send(200, Path(os.environ.get('SHANNON_SOURCE_ARCHIVE', '/usr/share/shannon/source.tar.gz')).read_bytes(),
                          'application/gzip', 'shannon-corresponding-source.tar.gz')
                return
            if not self.authorized():
                self.send(401, {'error': 'Bearer token required'})
                return
            if path == '/api/v1/config':
                self.send(200, {'execution_enabled': runner.enabled, 'model': os.environ.get('LLM_MODEL'),
                                'authorized_origins': sorted(runner.origins), 'upstream': 'v3.5.0'})
            elif path == '/api/v1/tasks':
                query = parse_qs(parsed.query)
                limit = max(1, min(100, int(query.get('limit', ['50'])[0])))
                offset = max(0, int(query.get('offset', ['0'])[0]))
                self.send(200, {'tasks': [self.view_task(task) for task in store.list(limit, offset)], 'limit': limit, 'offset': offset})
            else:
                match = re.fullmatch(r'/api/v1/tasks/([a-f0-9]{32})(?:/reports/(markdown|pdf))?', path)
                if not match:
                    raise KeyError(path)
                task_id, report_type = match.groups()
                task = store.get(task_id)
                if report_type:
                    filename, mime = REPORTS[report_type]
                    self.send(200, (runner.directory(task_id) / 'reports' / filename).read_bytes(), mime, filename)
                else:
                    self.send(200, self.view_task(task))

        def do_POST(self):
            if not self.authorized():
                self.send(401, {'error': 'Bearer token required'})
                return
            try:
                self.post()
            except (ValueError, binascii.Error, TypeError, OSError) as error:
                self.send(400, {'error': str(error)[:300]})
            except KeyError:
                self.send(404, {'error': 'Not found'})

        def post(self):
            match = re.fullmatch(r'/api/v1/tasks/([a-f0-9]{32})/cancel', self.path)
            if match:
                self.send(202, runner.cancel(match[1]))
                return
            if self.path != '/api/v1/tasks':
                raise KeyError(self.path)
            if not runner.enabled:
                self.send(503, {'error': 'Execution disabled: operator must verify network isolation and configure authorized origins'})
                return
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                raise ValueError('Content-Type must be application/json')
            length = int(self.headers.get('Content-Length', '0'))
            if length < 1 or length > MAX_BODY or self.headers.get('Transfer-Encoding'):
                raise ValueError('Request body must be between 1 byte and 48 MiB')
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict) or body.get('authorization_confirmed') is not True:
                raise ValueError('Explicit authorization confirmation is required')
            target = public_url(body.get('target'), runner.origins)
            source_type = body.get('source_type')
            task = {'target': target, 'source_type': source_type, 'authorization_confirmed': True}
            archive = None
            if source_type == 'zip':
                archive = base64.b64decode(body.get('zip_base64', ''), validate=True)
                if not archive or len(archive) > 32 * 1024 * 1024:
                    raise ValueError('ZIP must be between 1 byte and 32 MiB')
                # Structural safety is checked in the worker before extraction.
            elif source_type == 'git':
                repository = public_url(body.get('repository'))
                if urlsplit(repository).query:
                    raise ValueError('Git URL must not contain query credentials')
                branch = body.get('branch', 'main')
                if not isinstance(branch, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,199}', branch) or '..' in branch:
                    raise ValueError('Invalid branch')
                task.update(repository=repository, branch=branch)
            else:
                raise ValueError('source_type must be zip or git')
            with runner.lock:
                if len(store.active()) >= 10:
                    self.send(429, {'error': 'Task queue full'})
                    return
                if sum(p.stat().st_size for p in store.root.rglob('source.zip')) + len(archive or b'') > 1024 ** 3:
                    self.send(507, {'error': 'Source archive quota exceeded; contact operator'})
                    return
                task = store.create(task)
                if archive is not None:
                    try:
                        directory = runner.directory(task['id'])
                        directory.mkdir(parents=True)
                        with (directory / 'source.zip').open('xb') as output:
                            output.write(archive)
                            output.flush()
                            os.fsync(output.fileno())
                    except OSError:
                        store.update(task['id'], state='failed', error='Source persistence failed')
                        raise
                self.send(202, task)

    return Handler


def main():
    os.umask(0o077)
    api_key = os.environ.get('SHANNON_API_KEY', '')
    if len(api_key) < 32:
        raise SystemExit('SHANNON_API_KEY must contain at least 32 characters')
    origins = {value.strip().rstrip('/') for value in os.environ.get('SHANNON_AUTHORIZED_ORIGINS', '').split(',') if value.strip()}
    enabled = os.environ.get('SHANNON_EXECUTION_ENABLED') == 'true'
    if enabled and (not origins or os.environ.get('SHANNON_EGRESS_POLICY_VERIFIED') != 'true'):
        raise SystemExit('Execution requires authorized origins and verified external egress isolation')
    store = Store(os.environ.get('DATA_DIR', './standalone-data'))
    supervisor_lock = (store.root / '.supervisor.lock').open('a')
    try:
        fcntl.flock(supervisor_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit('Another standalone supervisor already owns this data directory')
    runner = Runner(store, origins, enabled)
    server = ThreadingHTTPServer((os.environ.get('HOST', '0.0.0.0'), int(os.environ.get('PORT', '8080'))), make_handler(store, runner, api_key))
    server.daemon_threads = True
    server.timeout = 1
    def stop(signum, frame):
        runner.stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    runner.start()
    try:
        server.serve_forever()
    finally:
        runner.stop.set()
        runner.thread.join(timeout=45)
        server.server_close()
        supervisor_lock.close()


if __name__ == '__main__':
    main()
