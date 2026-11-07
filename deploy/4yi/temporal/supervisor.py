"""Expose HTTP probes and gRPC on one declared service port, without privileges."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BACKEND = ('127.0.0.1', 17233)
NGINX = '''
worker_processes 1;
pid /tmp/shannon-nginx.pid;
error_log /dev/stderr warn;
events { worker_connections 1024; }
http {
    access_log off;
    client_body_temp_path /tmp/shannon-nginx-body;
    proxy_temp_path /tmp/shannon-nginx-proxy;
    fastcgi_temp_path /tmp/shannon-nginx-fastcgi;
    uwsgi_temp_path /tmp/shannon-nginx-uwsgi;
    scgi_temp_path /tmp/shannon-nginx-scgi;
    client_max_body_size 64m;
    server {
        listen 0.0.0.0:7233;
        http2 on;
        location = /healthz {
            proxy_pass http://127.0.0.1:18080/healthz;
            proxy_connect_timeout 1s;
            proxy_read_timeout 4s;
        }
        location / {
            grpc_pass grpc://127.0.0.1:17233;
            grpc_connect_timeout 3s;
            grpc_read_timeout 3600s;
            grpc_send_timeout 3600s;
        }
    }
}
'''


def readiness():
    try:
        with socket.create_connection(BACKEND, timeout=.5):
            pass
    except OSError:
        return False, 'temporal_starting'
    env = dict(os.environ, PGPASSWORD=os.environ.get('POSTGRES_PASSWORD', ''), PGCONNECT_TIMEOUT='2')
    command = ['psql', '-X', '-qAt', '-h', os.environ.get('POSTGRES_SEEDS', 'shannon-postgres'),
               '-p', os.environ.get('DB_PORT', '5432'), '-U', os.environ.get('POSTGRES_USER', 'temporal'),
               '-d', 'temporal', '-c', 'SELECT 1']
    try:
        result = subprocess.run(command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        return (True, 'ready') if result.returncode == 0 else (False, 'database_unavailable')
    except (OSError, subprocess.TimeoutExpired):
        return False, 'database_unavailable'


class Health(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path != '/healthz':
            self.send_error(404)
            return
        ready, status = readiness()
        body = json.dumps({'service': 'shannon-temporal', 'status': status}).encode()
        self.send_response(200 if ready else 503)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    os.umask(0o077)
    config = Path('/tmp/shannon-temporal-nginx.conf')
    config.write_text(NGINX)
    # Validate before starting children, so a missing module/config cannot leave an orphan.
    subprocess.run(['nginx', '-t', '-c', str(config), '-p', '/tmp/'], check=True)
    health = ThreadingHTTPServer(('127.0.0.1', 18080), Health)
    health.daemon_threads = True
    threading.Thread(target=health.serve_forever, daemon=True).start()
    stopped = threading.Event()
    children = []
    def stop(*args):
        stopped.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    code = 0
    try:
        children.append(subprocess.Popen(['nginx', '-c', str(config), '-p', '/tmp/', '-g', 'daemon off;'], start_new_session=True))
        env = dict(os.environ, TEMPORAL_FRONTEND_PORT=str(BACKEND[1]))
        children.append(subprocess.Popen([sys.executable, '/etc/temporal/standalone-server.py'], env=env, start_new_session=True))
        while not stopped.wait(.25):
            if any(child.poll() is not None for child in children):
                print('Temporal supervisor: a required child exited; stopping service', flush=True)
                code = 1
                break
    finally:
        for child in children:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        for child in children:
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
        health.shutdown()
        health.server_close()
    return code


if __name__ == '__main__':
    raise SystemExit(main())
