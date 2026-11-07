"""SQL-backed Temporal Server: initialize fresh databases, explicitly migrate upgrades."""
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import time


def configuration(environ, address):
    frontend_port = int(environ.get('TEMPORAL_FRONTEND_PORT', '7233'))
    host = environ.get('POSTGRES_SEEDS', 'shannon-postgres')
    port = int(environ.get('DB_PORT', '5432'))
    password = environ['POSTGRES_PASSWORD']
    user = environ.get('POSTGRES_USER', 'temporal')
    def sql(database, maximum):
        return {'sql': {'pluginName': 'postgres12', 'databaseName': database,
                        'connectAddr': f'{host}:{port}', 'connectProtocol': 'tcp',
                        'user': user, 'password': password, 'maxConns': maximum,
                        'maxIdleConns': maximum, 'maxConnLifetime': '1h'}}
    return {
        'log': {'stdout': True, 'level': 'info'},
        'persistence': {'defaultStore': 'main', 'visibilityStore': 'visibility', 'numHistoryShards': 128,
                        'datastores': {'main': sql('temporal', 10), 'visibility': sql('temporal_visibility', 2)}},
        'global': {'membership': {'maxJoinDuration': '30s', 'broadcastAddress': address}},
        'services': {name: {'rpc': {'grpcPort': grpc, 'membershipPort': member, 'bindOnIP': '127.0.0.1' if name == 'frontend' and frontend_port != 7233 else '0.0.0.0'}}
                     for name, grpc, member in [('frontend', frontend_port, 6933), ('history', 7234, 6934),
                                                ('matching', 7235, 6935), ('worker', 7239, 6939)]},
        'clusterMetadata': {'enableGlobalNamespace': False, 'failoverVersionIncrement': 10,
                            'masterClusterName': 'active', 'currentClusterName': 'active',
                            'clusterInformation': {'active': {'enabled': True, 'initialFailoverVersion': 1,
                                                              'rpcName': 'frontend', 'rpcAddress': f'127.0.0.1:{frontend_port}'}}},
        'publicClient': {'hostPort': f'127.0.0.1:{frontend_port}'},
        'dcRedirectionPolicy': {'policy': 'noop'},
        'archival': {'history': {'state': 'disabled', 'enableRead': False},
                     'visibility': {'state': 'disabled', 'enableRead': False}},
        'dynamicConfigClient': {'filepath': '/tmp/shannon-temporal/dynamic.yaml', 'pollInterval': '10s'},
    }


def version_tuple(value):
    if not re.fullmatch(r'\d+(?:\.\d+)*', value):
        raise ValueError('Invalid Temporal schema version')
    return tuple(map(int, value.split('.')))


def main():
    os.umask(0o077)
    mode = sys.argv[1] if len(sys.argv) > 1 else 'start'
    if mode not in ('start', 'migrate'):
        raise SystemExit('Use start (fresh initialization only) or migrate (reviewed schema upgrade)')
    if not os.environ.get('POSTGRES_PASSWORD'):
        raise SystemExit('Per-install POSTGRES_PASSWORD required')
    host = os.environ.get('POSTGRES_SEEDS', 'shannon-postgres')
    port = os.environ.get('DB_PORT', '5432')
    user = os.environ.get('POSTGRES_USER', 'temporal')
    database_env = dict(os.environ, PGPASSWORD=os.environ['POSTGRES_PASSWORD'],
                         SQL_PASSWORD=os.environ['POSTGRES_PASSWORD'], PGCONNECT_TIMEOUT='5')
    psql = ['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-h', host, '-p', port, '-U', user]
    def query(database, statement):
        result = subprocess.run(psql + ['-d', database, '-c', statement], env=database_env,
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            if 'password authentication failed' in result.stderr:
                raise RuntimeError('database_authentication_failed')
            raise RuntimeError('database_connection_failed')
        return result.stdout.strip()
    deadline = time.monotonic() + 180
    last_database_error = None
    while True:
        try:
            query('postgres', 'SELECT 1')
            break
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            reason = str(error) if isinstance(error, RuntimeError) else 'database_unavailable'
            if reason != last_database_error:
                print('Temporal startup blocked: ' + reason + '; verify the existing database role and per-install Secret; PVC is preserved', flush=True)
                last_database_error = reason
            if time.monotonic() >= deadline:
                raise SystemExit('PostgreSQL did not become ready within 180 seconds')
            time.sleep(2)
    # Hold one database-level advisory lock across both schema operations and tool subprocesses.
    locker = subprocess.Popen(psql + ['-d', 'postgres'], env=database_env,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        locker.stdin.write(b"SET lock_timeout='120s'; SELECT pg_advisory_lock(754016291);\n\\echo LOCKED\n")
        locker.stdin.flush()
        received = b''
        lock_deadline = time.monotonic() + 125
        while b'LOCKED\n' not in received:
            if time.monotonic() >= lock_deadline or locker.poll() is not None:
                raise RuntimeError('Could not acquire Temporal schema migration lock')
            if select.select([locker.stdout], [], [], .5)[0]:
                received += os.read(locker.stdout.fileno(), 1024)
        for database, lane in [('temporal', 'temporal'), ('temporal_visibility', 'visibility')]:
            if query('postgres', f"SELECT 1 FROM pg_database WHERE datname='{database}'") != '1':
                query('postgres', f'CREATE DATABASE "{database}"')
            schema = Path('/etc/temporal/schema/postgresql/v12') / lane / 'versioned'
            expected = max((entry.name[1:] for entry in schema.iterdir()
                            if entry.is_dir() and re.fullmatch(r'v\d+(?:\.\d+)*', entry.name)), key=version_tuple)
            fresh = not query(database, "SELECT to_regclass('public.schema_version')")
            tool = ['temporal-sql-tool', '--plugin', 'postgres12', '--ep', host,
                    '-u', user, '-p', port, '--db', database]
            if fresh:
                subprocess.run(tool + ['setup-schema', '-v', '0.0'], env=database_env, check=True)
            current = query(database, 'SELECT curr_version FROM schema_version LIMIT 1')
            if version_tuple(current) > version_tuple(expected):
                raise RuntimeError('Database schema is newer than this pinned Temporal image; refusing downgrade')
            if current != expected:
                if not fresh and mode != 'migrate':
                    raise RuntimeError('Schema upgrade requires a backup and explicit migrate command before deployment')
                subprocess.run(tool + ['update-schema', '-d', str(schema)], env=database_env, check=True)
            print(f'{database}: schema {expected} ready', flush=True)
    finally:
        if locker.poll() is None:
            locker.stdin.close()
            try:
                locker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                locker.kill()
                locker.wait()
    if mode == 'migrate':
        return
    directory = Path('/tmp/shannon-temporal')
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'standalone.yaml').write_text(json.dumps(configuration(os.environ, socket.gethostbyname(socket.gethostname()))))
    (directory / 'dynamic.yaml').write_text('{}')
    os.execvp('temporal-server', ['temporal-server', '--root', str(directory), '--config', '.',
                                  '--env', 'standalone', '--allow-no-auth', 'start'])


if __name__ == '__main__':
    main()
