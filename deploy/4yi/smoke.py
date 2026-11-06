#!/usr/bin/env python3
"""Host-side isolated Docker smoke test. Application containers never use Docker."""
import argparse
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--web-image', default='shannon-standalone:trial')
parser.add_argument('--temporal-image', default='shannon-temporal:trial')
parser.add_argument('--postgres-image', default='public.ecr.aws/docker/library/postgres:16.15-alpine@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139')
args = parser.parse_args()
project = 'shannon-test-' + secrets.token_hex(4)
api_key = secrets.token_hex(32)
environment = dict(os.environ, SHANNON_API_KEY=api_key, POSTGRES_PASSWORD=secrets.token_hex(32), OPENAI_API_KEY='', OPENAI_API_BASE='', LLM_MODEL='fixture-model')
root = Path(__file__).resolve().parents[2]

with tempfile.TemporaryDirectory(prefix='shannon-smoke-') as tmp:
    override = Path(tmp) / 'override.json'
    config = json.loads(subprocess.check_output(['docker','compose','-p',project,'-f',str(root/'deploy/4yi/compose.yml'),'config','--format','json'],env=environment))
    config['services']['web'].update(image=args.web_image, ports=[{'target':8080,'published':'0','host_ip':'127.0.0.1','protocol':'tcp'}])
    config['services']['temporal']['image'] = args.temporal_image
    config['services']['postgres']['image'] = args.postgres_image
    for service in config['services'].values():
        service.pop('build', None)
    override.write_text(json.dumps(config))
    compose = ['docker','compose','-p',project,'-f',str(override)]
    def run(arguments, **kwargs):
        return subprocess.run(compose+arguments,env=environment,check=True,capture_output=True,**kwargs)
    def ready(callback, seconds=180):
        deadline = time.monotonic()+seconds
        while time.monotonic()<deadline:
            try:
                return callback()
            except (OSError,subprocess.CalledProcessError,urllib.error.URLError):
                time.sleep(2)
        raise RuntimeError('Timed out waiting for smoke-test service')
    try:
        run(['up','-d','--no-build'],timeout=180)
        print('Started isolated three-service fixture', flush=True)
        web_id = run(['ps','-q','web'],text=True).stdout.strip()
        # Avoid compose merge rules for ports; discover the engine's assigned host port.
        def web_address():
            inspection = json.loads(subprocess.check_output(['docker','inspect',web_id]))[0]
            ports = inspection['NetworkSettings']['Ports']['8080/tcp']
            return 'http://127.0.0.1:'+ports[-1]['HostPort']
        base = web_address()
        def request(path, authenticated=True):
            headers={'Authorization':'Bearer '+api_key} if authenticated else {}
            with urllib.request.urlopen(urllib.request.Request(base+path,headers=headers),timeout=5) as response:
                return response.read()
        ready(lambda:request('/healthz',False))
        assert json.loads(request('/api/v1/config'))['execution_enabled'] is False
        try:
            request('/api/v1/tasks',False)
            raise AssertionError('Unauthenticated history was accepted')
        except urllib.error.HTTPError as error:
            assert error.code == 401
        source = tarfile.open(fileobj=io.BytesIO(request('/source')))
        names = set(source.getnames())
        assert all(name in names for name in ['./LICENSE','./THIRD_PARTY_NOTICES.md','./pnpm-lock.yaml',
                   './deploy/4yi/Dockerfile','./apps/standalone/server.py','./apps/cli/src/commands/start.ts'])
        assert not any('/node_modules/' in name or name.endswith('/.env') for name in names)
        run(['exec','-T','web','sh','-c','test "$(id -u)" = 1001 && test ! -e /var/run/docker.sock'])
        browser = run(['exec','-T','-w','/app/data','web','playwright-cli','open','about:blank'],text=True,timeout=60)
        assert 'about:blank' in browser.stdout and 'Error:' not in browser.stdout
        run(['exec','-T','-w','/app/data','web','playwright-cli','close-all'],timeout=30)
        print('PASS: auth, source archive, non-root browser on about:blank', flush=True)
        ready(lambda:run(['exec','-T','web','node','/app/deploy/4yi/terminate.mjs','--bootstrap']),240)
        output = run(['exec','-T','web','node','/app/deploy/4yi/test-temporal.mjs'],text=True,timeout=90).stdout
        workflow_id = next(line.split('=',1)[1] for line in output.splitlines() if line.startswith('PENDING_WORKFLOW='))
        run(['restart','temporal'],timeout=90)
        ready(lambda:run(['exec','-T','web','node','/app/deploy/4yi/terminate.mjs','--health']),240)
        run(['exec','-T','web','node','/app/deploy/4yi/test-temporal.mjs','verify',workflow_id],timeout=60)
        print('PASS: SQL workflow survived Temporal restart and terminated', flush=True)
        seed = """from apps.standalone.store import Store
from pathlib import Path
import os, zipfile
store=Store(os.environ['DATA_DIR'])
task=store.create({'target':'https://fixture.example','source_type':'zip'})
directory=store.root/'tasks'/task['id']
(directory/'reports').mkdir(parents=True)
with zipfile.ZipFile(directory/'source.zip','w') as source: source.writestr('app.py','# synthetic fixture')
(directory/'reports'/'Security-Assessment-Report.md').write_text('# Persisted container fixture')
store.update(task['id'],state='completed')
store.db.close()
print(task['id'])
"""
        task_id = run(['exec','-T','web','python3','-c',seed],text=True).stdout.strip()
        run(['restart','web'],timeout=90)
        base = web_address()
        ready(lambda:request('/healthz',False))
        task = json.loads(request('/api/v1/tasks/'+task_id))
        assert task['state']=='completed' and task['reports']['markdown']
        assert request('/api/v1/tasks/'+task_id+'/reports/markdown')==b'# Persisted container fixture'
        run(['exec','-T','web','test','-f','/app/data/tasks/'+task_id+'/source.zip'])
        print('PASS: non-root Web, auth, source archive, SQL Temporal bootstrap, synthetic workflow, restart persistence, termination; no scan or real model call')
    except Exception as error:
        logs = subprocess.run(compose+['logs','--tail','60'],env=environment,capture_output=True,text=True)
        # Do not expose even accidentally logged credentials in a failed test.
        details = ''.join(value.decode(errors='replace') if isinstance(value, bytes) else value for value in (getattr(error, 'stdout', '') or '', getattr(error, 'stderr', '') or ''))
        text = (logs.stdout+logs.stderr+details).replace(api_key,'[REDACTED]').replace(environment['POSTGRES_PASSWORD'],'[REDACTED]')
        print(text)
        raise
    finally:
        subprocess.run(compose+['down','--volumes','--remove-orphans'],env=environment,check=False,capture_output=True,timeout=90)
