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

from .auth import Access
from . import manual_otp
from .runner import Runner, outcome
from .security import extract_zip, public_url
from .server import make_handler
from .store import Store
from .target_auth import CredentialVault, validate_auth, redact


SSO_ENV = {'SHANNON_AUTH_MODE':'4yi_sso', 'XCLAW_APP_HOSTNAME':'shannon.fixture.example',
           'XCLAW_CONSUMER_ORG_ID':'11111111-1111-4111-8111-111111111111'}
SSO_HEADERS = {'X-Xclaw-Sso-Session-Id':'22222222-2222-4222-8222-222222222222',
               'X-Xclaw-User-Id':'33333333-3333-4333-8333-333333333333',
               'X-Xclaw-Route-Id':'44444444-4444-4444-8444-444444444444',
               'X-Xclaw-App-Id':'55555555-5555-4555-8555-555555555555',
               'X-Xclaw-Owner-Org-Id':SSO_ENV['XCLAW_CONSUMER_ORG_ID'],
               'X-Xclaw-Hostname':SSO_ENV['XCLAW_APP_HOSTNAME'],
               'X-Forwarded-Host':SSO_ENV['XCLAW_APP_HOSTNAME'], 'X-Forwarded-Proto':'https',
               'Origin':'https://'+SSO_ENV['XCLAW_APP_HOSTNAME']}


def resolver(address):
    return lambda *args, **kwargs: [(2, 1, 6, '', (address, 443))]


LOGIN_FIXTURE = {'login_type':'form', 'login_url':'https://target.example/login',
                 'credentials':{'username':'fixture@example.test','password':'fixture-unique-password',
                                'totp_secret':'JBSWY3DPEHPK3PXP'},
                 'login_flow':['Fill $username', 'Fill $password', 'Fill $totp', 'Click login'],
                 'success_condition':{'type':'url_contains','value':'/dashboard'}}


class TargetLoginTests(unittest.TestCase):
    def test_scope_validation_and_secret_free_errors(self):
        with patch('apps.standalone.target_auth.public_url', side_effect=lambda url, origins: url):
            self.assertEqual(validate_auth(LOGIN_FIXTURE,'https://target.example',{'https://target.example'}),LOGIN_FIXTURE)
            for change in [dict(login_url='https://other.example/login'),dict(login_url='https://target.example/login?token=secret'),
                           dict(login_type='sso'),dict(credentials={'username':'u','password':''}),dict(login_flow=[]),
                           dict(success_condition={'type':'url_equals_exactly','value':'https://other.example/dashboard'})]:
                with self.subTest(change=list(change)), self.assertRaises(ValueError) as error:
                    validate_auth(dict(LOGIN_FIXTURE,**change),'https://target.example',{'https://target.example'})
                self.assertNotIn('fixture-unique-password',str(error.exception))

    def test_encrypted_restart_tampering_and_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)/'task';directory.mkdir()
            vault=CredentialVault(tmp);vault.save(directory,LOGIN_FIXTURE)
            encrypted=(directory/'authentication.enc').read_bytes()
            for secret in LOGIN_FIXTURE['credentials'].values():
                self.assertNotIn(secret.encode(),encrypted)
            self.assertEqual(CredentialVault(tmp).load(directory),LOGIN_FIXTURE)
            self.assertEqual(stat.S_IMODE((directory/'authentication.enc').stat().st_mode),0o600)
            self.assertEqual(stat.S_IMODE((Path(tmp)/'.target-credentials-key').stat().st_mode),0o600)
            corrupted=bytearray(encrypted);corrupted[-1]^=1
            (directory/'authentication.enc').write_bytes(corrupted)
            with self.assertRaises(ValueError):vault.load(directory)
            self.assertEqual(redact({'error':'fixture-unique-password'},LOGIN_FIXTURE),{'error':'[REDACTED]'})


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
        internal = module.configuration({'POSTGRES_PASSWORD':secret,'TEMPORAL_FRONTEND_PORT':'17233'},'172.18.0.2')
        self.assertEqual(internal['services']['frontend']['rpc'], {'grpcPort':17233,'membershipPort':6933,'bindOnIP':'127.0.0.1'})
        self.assertEqual(internal['publicClient']['hostPort'],'127.0.0.1:17233')
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
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(self.store, self.runner, Access(SSO_ENV)))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.store.db.close()
        self.temp.cleanup()

    def request(self, path, body=None, authenticated=True, extra_headers=None):
        headers = dict(SSO_HEADERS) if authenticated else {}
        headers.update(extra_headers or {})
        if body is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(self.url + path, json.dumps(body).encode() if body is not None else None, headers)
        try:
            with urllib.request.urlopen(req) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as response:
            return response.code, json.load(response)

    def test_sso_rejects_missing_identity_wrong_tenant_and_cross_origin(self):
        self.assertEqual(self.request('/api/v1/tasks', authenticated=False,
                         extra_headers={'Authorization':'Bearer '+'x'*64})[0],401)
        self.assertEqual(self.request('/api/v1/tasks', authenticated=False,
                         extra_headers={'X-Xclaw-Owner-Org-Id':SSO_ENV['XCLAW_CONSUMER_ORG_ID']})[0],401)
        for overrides in [
            {'X-Xclaw-Owner-Org-Id':'66666666-6666-4666-8666-666666666666'},
            {'X-Xclaw-Hostname':'another.fixture.example'},
            {'X-Forwarded-Proto':'http'},
            {'X-Forwarded-Host':'another.fixture.example'},
        ]:
            self.assertEqual(self.request('/api/v1/tasks', extra_headers=overrides)[0],403)
        for origin in ('https://attacker.example',''):
            self.assertEqual(self.request('/api/v1/tasks', {}, extra_headers={'Origin':origin})[0],403)
        self.assertEqual(self.store.list(),[])
        self.assertEqual(self.request('/api/v1/config')[1]['auth_mode'],'4yi_sso')

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

    def test_target_login_is_private_and_report_download_is_redacted(self):
        body={'target':'https://target.example','source_type':'git','repository':'https://github.com/example/repo.git',
              'branch':'main','authorization_confirmed':True,'authentication':LOGIN_FIXTURE}
        with patch('apps.standalone.server.public_url', side_effect=lambda url,*args: url), patch('apps.standalone.target_auth.public_url', side_effect=lambda url,*args: url):
            status,task=self.request('/api/v1/tasks',body)
        self.assertEqual(status,202)
        self.assertTrue(task['authenticated_scan'])
        directory=self.runner.directory(task['id'])
        self.assertEqual(CredentialVault(self.store.root).load(directory),LOGIN_FIXTURE)
        for path in ['/api/v1/tasks','/api/v1/tasks/'+task['id']]:
            self.assertNotIn('fixture-unique-password',json.dumps(self.request(path)[1]))
        self.assertNotIn('fixture-unique-password',self.store.db.execute('SELECT body FROM tasks').fetchone()[0])
        reports=directory/'reports';reports.mkdir()
        (reports/'Security-Assessment-Report.md').write_text('Evidence: fixture-unique-password JBSWY3DPEHPK3PXP')
        (reports/'Security-Assessment-Report.pdf').write_bytes(b'unsafe-pdf')
        request=urllib.request.Request(self.url+'/api/v1/tasks/'+task['id']+'/reports/markdown',headers=SSO_HEADERS)
        with urllib.request.urlopen(request) as response:
            self.assertEqual(response.read(),b'Evidence: [REDACTED] [REDACTED]')
        self.assertEqual(self.request('/api/v1/tasks/'+task['id']+'/reports/pdf')[0],400)
        self.assertNotIn('pdf',self.request('/api/v1/tasks/'+task['id'])[1]['reports'])

    def test_manual_email_code_is_task_bound_encrypted_and_never_returned(self):
        authentication=dict(LOGIN_FIXTURE,manual_email_code=True,credentials={'username':'fixture','password':'fixture-password'})
        task=self.store.create({'target':'https://target.example','authenticated_scan':True,'manual_email_code':True})
        directory=self.runner.directory(task['id']);directory.mkdir(parents=True)
        vault=CredentialVault(self.store.root);vault.save(directory,authentication)
        self.store.update(task['id'],state='waiting_for_code')
        request_id='a'*32
        (directory/'otp-request.json').write_text(json.dumps({'id':request_id,'expires_at':time.time()+300}))
        endpoint='/api/v1/tasks/'+task['id']+'/email-code'
        body={'request_id':request_id,'code':'246810'}
        self.assertEqual(self.request(endpoint,body,authenticated=False)[0],401)
        self.assertEqual(self.request(endpoint,body,extra_headers={'Origin':'https://other.example'})[0],403)
        self.assertEqual(self.request(endpoint,dict(body,request_id='b'*32))[0],400)
        self.assertEqual(self.request(endpoint,dict(body,code='bad code'))[0],400)
        self.runner.current=task['id'];self.runner.authentication=authentication
        self.assertEqual(self.request(endpoint,body),(202,{'accepted':True}))
        self.assertEqual(redact('246810',self.runner.authentication),'[REDACTED]')
        self.assertNotIn(b'246810',(directory/'otp-response.enc').read_bytes())
        self.assertEqual(vault.redaction_auth(directory)['credentials']['manual_code'],'246810')
        self.assertEqual(self.request(endpoint,body)[0],400)
        for route in ['/api/v1/tasks','/api/v1/tasks/'+task['id']]:
            self.assertNotIn('246810',json.dumps(self.request(route)[1]))
        self.assertNotIn('246810',self.store.db.execute('SELECT body FROM tasks').fetchone()[0])
        self.assertTrue(self.request('/api/v1/tasks/'+task['id'])[1]['email_challenge']['submitted'])
        manual_otp.cleanup(directory)
        (directory/'otp-request.json').write_text(json.dumps({'id':request_id,'expires_at':time.time()-1}))
        self.assertEqual(self.request(endpoint,body)[0],400)
        self.store.update(task['id'],state='cancelled')
        self.assertEqual(self.request(endpoint,body)[0],400)
        self.runner.finish(self.store.get(task['id']),'cancelled')
        self.assertFalse((directory/'otp-request.json').exists())
        self.assertIsNone(self.request('/api/v1/tasks/'+task['id'])[1]['email_challenge'])

    def test_disabled_execution_and_invalid_input(self):
        self.runner.enabled = False
        self.assertEqual(self.request('/api/v1/tasks', {})[0], 503)
        self.runner.enabled = True
        self.assertEqual(self.request('/api/v1/tasks', {})[0], 400)
        self.assertEqual(self.request('/api/v1/tasks', [1])[0], 400)
        self.assertEqual(self.request('/api/v1/tasks/../../etc/passwd')[0], 404)


class RunnerTests(unittest.TestCase):
    def test_login_config_reaches_worker_and_is_removed_after_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(tmp);runner=Runner(store,{'https://target.example'},True)
            task=store.create({'target':'https://target.example','source_type':'zip','authenticated_scan':True})
            directory=runner.directory(task['id']);directory.mkdir(parents=True)
            CredentialVault(tmp).save(directory,LOGIN_FIXTURE)
            def execute(command,cwd,env,log,timeout,scan=False):
                self.assertTrue(scan)
                config=Path(command[command.index('--config')+1])
                self.assertEqual(json.loads(config.read_text())['authentication'],LOGIN_FIXTURE)
                self.assertEqual(stat.S_IMODE(config.stat().st_mode),0o600)
                (cwd/'progress.json').write_text(json.dumps({'currentPhase':'auth-validation'}))
                raise ValueError('Rejected fixture-unique-password')
            with patch.object(runner,'wait_for_temporal'),patch.object(runner,'terminate_workflow'),patch.object(runner,'execute',side_effect=execute),patch('apps.standalone.runner.public_url'),patch('apps.standalone.target_auth.public_url',side_effect=lambda url,*args:url),patch('apps.standalone.runner.extract_zip',return_value=directory),patch.dict(os.environ,{'LLM_MODEL':'fixture','OPENAI_API_BASE':'https://gateway.example/v1','OPENAI_API_KEY':'fixture'}):
                runner.run(task)
            self.assertEqual(store.get(task['id'])['state'],'failed')
            self.assertNotIn('fixture-unique-password',store.get(task['id'])['error'])
            self.assertFalse((directory/'login-config.json').exists())
            self.assertTrue((directory/'authentication.enc').exists())
            store.db.close()

    def test_expired_email_wait_stops_worker_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(tmp);runner=Runner(store,set())
            task=store.create({'target':'https://target.example'})
            store.update(task['id'],state='running');runner.current=task['id']
            (Path(tmp)/'otp-status.json').write_text(json.dumps({'status':'expired'}))
            code=runner.execute([sys.executable,'-c','import time;time.sleep(30)'],Path(tmp),dict(os.environ),Path(tmp)/'worker.log',10,scan=True)
            self.assertNotEqual(code,0)
            self.assertIsNotNone(runner.process.poll())
            store.db.close()

    def test_worker_console_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(tmp);runner=Runner(store,set())
            task=store.create({'target':'https://target.example'})
            runner.current=task['id'];runner.authentication=LOGIN_FIXTURE
            log=Path(tmp)/'worker.log'
            command=[sys.executable,'-c',"print('fixture-unique-password JBSWY3DPEHPK3PXP')"]
            self.assertEqual(runner.execute(command,Path(tmp),dict(os.environ),log,10),0)
            self.assertEqual(log.read_text().strip(),'[REDACTED] [REDACTED]')
            store.db.close()

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
    def test_missing_platform_context_keeps_http_up_but_blocks_all_api_and_execution(self):
        for org in ('', 'invalid-org'):
            with self.subTest(org=org), tempfile.TemporaryDirectory() as tmp:
                with socket.socket() as probe:
                    probe.bind(('127.0.0.1', 0))
                    port = probe.getsockname()[1]
                env = dict(os.environ, DATA_DIR=tmp, HOST='127.0.0.1', PORT=str(port),
                           XCLAW_APP_HOSTNAME=SSO_ENV['XCLAW_APP_HOSTNAME'], XCLAW_CONSUMER_ORG_ID=org, SHANNON_EXECUTION_ENABLED='true',
                           SHANNON_AUTHORIZED_ORIGINS='https://fixture.example', SHANNON_EGRESS_POLICY_VERIFIED='true')
                process = subprocess.Popen([sys.executable,'-B','-m','apps.standalone.server'],env=env,
                                           stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                base = f'http://127.0.0.1:{port}'
                try:
                    for attempt in range(100):
                        try:
                            with urllib.request.urlopen(base+'/shannon-healthz',timeout=.5) as response:
                                health = json.load(response)
                            break
                        except OSError:
                            time.sleep(.05)
                    else:
                        self.fail('Web must start even when the API credential is invalid')
                    self.assertFalse(health['api_configured'])
                    self.assertFalse(health['execution_enabled'])
                    with urllib.request.urlopen(base+'/') as response:
                        self.assertIn(b'<!doctype html>',response.read().lower())
                    for path, body in [('/api/v1/tasks',None),('/api/v1/tasks',b'{}'),('/api/v1/tasks/'+'a'*32+'/cancel',b'{}')]:
                        request = urllib.request.Request(base+path, data=body, headers={'Authorization':'Bearer old-key-is-not-web-auth'})
                        with self.assertRaises(urllib.error.HTTPError) as error:
                            urllib.request.urlopen(request)
                        self.assertEqual(error.exception.code,503)
                    store = Store(tmp)
                    self.assertEqual(store.list(),[])
                    store.db.close()
                finally:
                    process.terminate()
                    process.communicate(timeout=10)

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
                       SHANNON_EXECUTION_ENABLED='false', **SSO_ENV)
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
                              headers=SSO_HEADERS)
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
