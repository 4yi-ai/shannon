import base64
import io
import importlib.util
import json
import os
import stat
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from .runner import Runner, outcome
from .security import extract_zip, public_url
from .server import make_handler
from .store import Store


def resolver(address):
    return lambda *args, **kwargs: [(2, 1, 6, '', (address, 443))]


class SecurityTests(unittest.TestCase):
    def test_temporal_config_keeps_secret_out_of_source_and_uses_sql(self):
        path = Path(__file__).resolve().parents[2] / 'deploy/4yi/temporal/server.py'
        spec = importlib.util.spec_from_file_location('temporal_config', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        secret = 'fixture-password-with-quote"-and-newline\n'
        config = module.configuration({'POSTGRES_PASSWORD':secret,'POSTGRES_SEEDS':'fixture-postgres'},'172.18.0.2')
        roundtrip = json.loads(json.dumps(config))
        self.assertEqual(roundtrip['persistence']['datastores']['main']['sql']['password'],secret)
        self.assertEqual(config['persistence']['datastores']['main']['sql']['pluginName'],'postgres12')
        self.assertEqual(config['services']['frontend']['rpc']['grpcPort'],7233)
        self.assertEqual(module.version_tuple('1.17'),(1,17))
        with self.assertRaises(ValueError):
            module.version_tuple('unsafe version')

    def test_private_metadata_and_transition_addresses(self):
        for address in ['127.0.0.1', '10.0.0.1', '169.254.169.254', '100.100.100.200', '::1', 'fe80::1', '::ffff:8.8.8.8', '2002:0808:0808::1']:
            with self.subTest(address=address), self.assertRaises(ValueError):
                public_url('https://target.example', resolver=resolver(address))

    def test_origin_scope_and_credentials(self):
        for value in ['http://target.example', 'https://user:secret@target.example', 'https://target.example:8443', 'https://target.example/#fragment', 'https://localhost', 'https://api.svc']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                public_url(value, resolver=resolver('8.8.8.8'))
        with self.assertRaises(ValueError):
            public_url('https://other.example', {'https://target.example'}, resolver('8.8.8.8'))
        self.assertEqual(public_url('https://target.example/path', {'https://target.example'}, resolver('8.8.8.8')), 'https://target.example/path')

    def test_zip_traversal_symlink_and_bomb(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ['../escape', '/escape', 'a\\escape', '.git/config', '.GiT/config', '.shannon/session.json']:
                archive = io.BytesIO()
                with zipfile.ZipFile(archive, 'w') as z:
                    z.writestr(name, 'bad')
                archive.seek(0)
                with self.assertRaises(ValueError):
                    extract_zip(archive, Path(tmp) / 'source')
            for mode in [stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o600]:
                archive = io.BytesIO()
                item = zipfile.ZipInfo('link')
                item.external_attr = mode << 16
                with zipfile.ZipFile(archive, 'w') as z:
                    z.writestr(item, 'outside')
                archive.seek(0)
                with self.assertRaises(ValueError):
                    extract_zip(archive, Path(tmp) / 'source')
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
                z.writestr('bomb', b'0' * 2000000)
            archive.seek(0)
            with self.assertRaises(ValueError):
                extract_zip(archive, Path(tmp) / 'source')

    def test_zip_extract_and_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr('project/app.py', 'print(1)')
            archive.seek(0)
            root = extract_zip(archive, Path(tmp) / 'source')
            self.assertEqual((root / 'app.py').read_text(), 'print(1)')

    def test_outcomes_never_assume_exit_zero_is_success(self):
        for result, report, code, expected in [({}, True, 0, 'failed'), ({'status': 'partial'}, True, 0, 'partial'),
                ({'status': 'completed'}, True, 0, 'completed'), ({'status': 'completed'}, False, 0, 'failed'),
                ({'status': 'completed'}, True, 1, 'failed'), ({'status': 'cancelled'}, False, 0, 'cancelled')]:
            self.assertEqual(outcome(result, report, code), expected)


class APITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)
        self.runner = Runner(self.store, {'https://target.example'}, enabled=True)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(self.store, self.runner, 'x' * 32))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.store.db.close()
        self.temp.cleanup()

    def request(self, path, body=None, authenticated=True):
        headers = {'Authorization': 'Bearer ' + 'x' * 32} if authenticated else {}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(self.url + path, json.dumps(body).encode() if body is not None else None, headers)
        try:
            with urllib.request.urlopen(req) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as response:
            return response.code, json.load(response)

    def test_auth_health_creation_cancel_persistence(self):
        self.assertEqual(self.request('/healthz', authenticated=False)[0], 200)
        self.assertEqual(self.request('/api/v1/tasks', authenticated=False)[0], 401)
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('app.py', 'print(1)')
        body = {'target': 'https://target.example', 'source_type': 'zip', 'authorization_confirmed': True,
                'zip_base64': base64.b64encode(archive.getvalue()).decode()}
        with patch('apps.standalone.server.public_url', return_value='https://target.example/'):
            status, task = self.request('/api/v1/tasks', body)
        self.assertEqual(status, 202)
        task_id = task['id']
        self.assertTrue((self.runner.directory(task_id) / 'source.zip').exists())
        self.assertEqual(self.request('/api/v1/tasks/' + task_id + '/cancel', {})[1]['state'], 'cancelled')
        reopened = Store(self.temp.name)
        self.assertEqual(reopened.get(task_id)['state'], 'cancelled')
        reopened.db.close()
        self.assertEqual(len(self.request('/api/v1/tasks')[1]['tasks']), 1)

    def test_disabled_execution_and_invalid_input(self):
        self.runner.enabled = False
        self.assertEqual(self.request('/api/v1/tasks', {})[0], 503)
        self.runner.enabled = True
        self.assertEqual(self.request('/api/v1/tasks', {})[0], 400)
        self.assertEqual(self.request('/api/v1/tasks', [1])[0], 400)
        self.assertEqual(self.request('/api/v1/tasks/../../etc/passwd')[0], 404)


class RunnerTests(unittest.TestCase):
    def test_cleanup_failure_never_pretends_task_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(tmp)
            runner = Runner(store, set())
            task = store.create({'target': 'https://target.example', 'source_type': 'zip'})
            task = store.update(task['id'], state='running', workflow_id='fixture')
            with patch.object(runner, 'terminate_workflow', side_effect=OSError('offline')):
                runner.finish(task, 'failed', error='interrupted')
            self.assertEqual(store.get(task['id'])['state'], 'recovering')
            self.assertEqual(store.get(task['id'])['pending_terminal'], 'failed')
            runner.cancel(task['id'])
            task = store.get(task['id'])
            self.assertEqual(task['pending_terminal'], 'cancelled')
            with patch.object(runner, 'terminate_workflow'):
                runner.finish(task, task['pending_terminal'])
            self.assertEqual(store.get(task['id'])['state'], 'cancelled')
            store.db.close()

    def test_real_runner_uses_receipt_and_keeps_partial_outcome(self):
        for status in ['completed', 'partial', 'cancelled', 'missing']:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                store = Store(tmp)
                runner = Runner(store, {'https://target.example'}, True)
                task = store.create({'target': 'https://target.example', 'source_type': 'zip'})
                def execute(command, cwd, env, log, timeout, scan=False):
                    if status != 'missing':
                        (cwd / 'result.json').write_text(json.dumps({'status':status,'partialReasons':[] }))
                    (cwd / 'reports').mkdir()
                    (cwd / 'reports/Security-Assessment-Report.md').write_text('# Fixture')
                    return 0
                with patch.object(runner, 'wait_for_temporal'), patch.object(runner, 'terminate_workflow'), patch.object(runner, 'execute', side_effect=execute), patch('apps.standalone.runner.public_url'), patch('apps.standalone.runner.extract_zip', return_value=Path(tmp)), patch.dict(os.environ, {'LLM_MODEL':'fixture-model','OPENAI_API_BASE':'https://gateway.example/api/v1','OPENAI_API_KEY':'fixture-token'}):
                    runner.run(task)
                self.assertEqual(store.get(task['id'])['state'], 'failed' if status == 'missing' else status)
                self.assertTrue((runner.directory(task['id']) / 'reports/Security-Assessment-Report.md').is_file())
                store.db.close()


class RestartTests(unittest.TestCase):
    def test_process_restart_preserves_history_source_and_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(tmp)
            task = store.create({'target':'https://fixture.example','source_type':'zip'})
            store.update(task['id'],state='completed')
            directory = Path(tmp) / 'tasks' / task['id']
            (directory / 'reports').mkdir(parents=True)
            (directory / 'source.zip').write_bytes(b'persisted-fixture-source')
            (directory / 'reports/Security-Assessment-Report.md').write_text('# Persisted fixture report')
            store.db.close()
            with socket.socket() as probe:
                probe.bind(('127.0.0.1',0))
                port = probe.getsockname()[1]
            env = dict(os.environ, DATA_DIR=tmp, HOST='127.0.0.1', PORT=str(port),
                       SHANNON_API_KEY='fixture-restart-token-32-characters', SHANNON_EXECUTION_ENABLED='false')
            for iteration in range(2):
                process = subprocess.Popen([sys.executable,'-B','-m','apps.standalone.server'],env=env,
                                           stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                try:
                    for attempt in range(100):
                        try:
                            with urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz',timeout=.5) as response:
                                if response.status == 200:
                                    break
                        except OSError:
                            time.sleep(.05)
                    else:
                        self.fail('Standalone HTTP process did not start')
                    request = urllib.request.Request(f'http://127.0.0.1:{port}/api/v1/tasks/{task["id"]}',
                              headers={'Authorization':'Bearer '+env['SHANNON_API_KEY']})
                    with urllib.request.urlopen(request) as response:
                        result = json.load(response)
                    self.assertEqual(result['state'],'completed')
                    self.assertTrue(result['reports']['markdown'])
                    request.full_url += '/reports/markdown'
                    with urllib.request.urlopen(request) as response:
                        self.assertEqual(response.read(),b'# Persisted fixture report')
                    self.assertEqual((directory / 'source.zip').read_bytes(),b'persisted-fixture-source')
                    if iteration == 0:
                        duplicate = subprocess.run([sys.executable,'-B','-m','apps.standalone.server'],env=env,
                                                   capture_output=True,timeout=5)
                        self.assertNotEqual(duplicate.returncode,0)
                        self.assertIn(b'already owns',duplicate.stderr)
                finally:
                    process.terminate()
                    process.communicate(timeout=10)


if __name__ == '__main__':
    unittest.main()
