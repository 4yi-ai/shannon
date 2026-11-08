import json
import os
import re
import signal
import subprocess
import threading
import time
from pathlib import Path

from .security import extract_zip, public_url
from .store import TERMINAL
from .models import gateway_config
from .diagnostics import temporal_failure
from . import manual_otp
from .target_auth import CredentialVault, redact

PROJECT = Path(__file__).resolve().parents[2]


def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}


def outcome(result, report_exists, exit_code):
    # An exit code alone never establishes completion.
    status = result.get('status')
    if exit_code == 0 and status in ('completed', 'partial') and report_exists:
        return status
    if status == 'cancelled':
        return 'cancelled'
    return 'failed'


class Runner:
    def __init__(self, store, origins, enabled=False, execution_mode='isolated'):
        self.store, self.origins, self.enabled = store, origins, enabled
        self.execution_mode = execution_mode
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.process = None
        self.current = None
        self.authentication = None

    def directory(self, task_id):
        return self.store.root / 'tasks' / task_id

    def terminate_workflow(self, task):
        if not task.get('workflow_id'):
            return
        subprocess.run(['node', str(PROJECT / 'deploy/4yi/terminate.mjs'), task['workflow_id']],
                       cwd=PROJECT, check=True, timeout=35, capture_output=True)

    def cancel(self, task_id):
        with self.lock:
            task = self.store.get(task_id)
            if task['state'] in TERMINAL:
                return task
            state = 'cancelled' if task['state'] == 'queued' else 'cancelling'
            task = self.store.update(task_id, state=state, pending_terminal='cancelled')
            if self.current == task_id and self.process and self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGTERM)
            return task

    def wait_for_temporal(self, task_id):
        deadline = time.monotonic() + 180
        while not self.stop.is_set() and self.store.get(task_id)['state'] != 'cancelling':
            try:
                subprocess.run(['node', str(PROJECT / 'deploy/4yi/terminate.mjs'), '--bootstrap'],
                               cwd=PROJECT, check=True, timeout=15, capture_output=True)
                return
            except (OSError, subprocess.SubprocessError) as error:
                if time.monotonic() >= deadline:
                    output = getattr(error, 'stderr', b'') or b''
                    if isinstance(output, bytes):
                        output = output.decode('utf-8', errors='replace')
                    raise ValueError('扫描服务等待 180 秒后仍未就绪。' + temporal_failure(output)) from None
                self.stop.wait(2)
        raise ValueError('Service stopped or task cancelled before startup')

    def start(self):
        self.thread = threading.Thread(target=self.loop, daemon=True, name='scan-supervisor')
        self.thread.start()

    def finish(self, task, state, error=None, **changes):
        try:
            self.terminate_workflow(task)
        except (OSError, subprocess.SubprocessError):
            self.store.update(task['id'], state='recovering', pending_terminal=state,
                              error='Waiting for Temporal cleanup', **changes)
        else:
            with self.lock:
                if self.store.get(task['id'])['state'] == 'cancelling':
                    state, error = 'cancelled', None
                try:
                    (self.directory(task['id']) / 'login-config.json').unlink(missing_ok=True)
                    manual_otp.cleanup(self.directory(task['id']))
                    for session in self.directory(task['id']).rglob('auth-state.json'):
                        session.unlink(missing_ok=True)
                except OSError:
                    self.store.update(task['id'], state='recovering', pending_terminal=state,
                                      error='Waiting for private login artifact cleanup', **changes)
                    return
                self.store.update(task['id'], state=state, error=error, **changes)

    def loop(self):
        # Never silently rerun an interrupted exploit. Clean up its durable workflow first.
        while not self.stop.is_set():
            for task in self.store.active():
                if self.stop.is_set():
                    return
                if task['state'] != 'queued':
                    desired = task.get('pending_terminal', 'cancelled' if task['state'] == 'cancelling' else 'failed')
                    self.finish(task, desired, None if desired == 'cancelled' else 'Interrupted scan; artifacts preserved')
                    if self.store.get(task['id'])['state'] not in TERMINAL:
                        break
                    continue
                if self.enabled:
                    self.run(task)
            self.stop.wait(2)

    def run(self, task):
        task_id = task['id']
        self.authentication = None
        directory = self.directory(task_id)
        with self.lock:
            if self.store.get(task_id)['state'] != 'queued':
                return
            self.current = task_id
            self.store.update(task_id, state='preparing')
        try:
            if task.get('authenticated_scan'):
                self.authentication = CredentialVault(self.store.root).load(directory)
                from .target_auth import validate_auth
                validate_auth(self.authentication, task['target'], self.origins)
            self.wait_for_temporal(task_id)
            # Re-resolve at execution time as well as admission. This does not replace CNI policy.
            public_url(task['target'], self.origins)
            directory.mkdir(parents=True, exist_ok=True)
            if task['source_type'] == 'zip':
                repo = extract_zip(directory / 'source.zip', directory / 'source')
            else:
                public_url(task['repository'])
                branch = task['branch']
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,199}', branch) or '..' in branch:
                    raise ValueError('Invalid Git branch')
                repo = directory / 'source'
                # Disable redirects, credential helpers, hooks and non-HTTPS transports.
                env = dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
                self.execute(['git', '-c', 'http.followRedirects=false', '-c', 'credential.helper=',
                              '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
                              '-c', 'protocol.https.allow=always', 'clone', '--depth', '1',
                              '--single-branch', '--branch', branch, '--', task['repository'], str(repo)],
                             directory, env, directory / 'source.log', 180)
            if self.store.get(task_id)['state'] == 'cancelling':
                self.store.update(task_id, state='cancelled')
                return
            workflow_id = 'scan_' + task_id + '_shannon-' + str(int(time.time() * 1000))
            self.store.update(task_id, state='running', workflow_id=workflow_id)
            model = os.environ['LLM_MODEL']
            base = (os.environ.get('OPENAI_API_BASE') or os.environ.get('OPENAI_BASE_URL', '')).rstrip('/')
            if not base or not os.environ.get('OPENAI_API_KEY'):
                raise ValueError('Per-install gateway credentials are not configured')
            models = gateway_config(model, base)
            (directory / 'models.json').write_text(json.dumps(models))
            (directory / 'workspaces').mkdir(exist_ok=True)
            result_path = directory / 'result.json'
            env = dict(os.environ, SHANNON_AI_MODEL='fouryi:' + model,
                       SHANNON_AI_API_KEY=os.environ['OPENAI_API_KEY'],
                       SHANNON_AI_BASE_URL=base,
                       SHANNON_MODELS_CONFIG=str(directory / 'models.json'),
                       SHANNON_RESULT_PATH=str(result_path),
                       SHANNON_PROGRESS_PATH=str(directory / 'progress.json'),
                       SHANNON_WORKSPACES_DIR=str(directory / 'workspaces'))
            auth_args = []
            if self.authentication:
                config_path = directory / 'login-config.json'
                fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, 'w') as config_file:
                    json.dump({'authentication': {key: value for key, value in self.authentication.items() if key != 'manual_email_code'}, 'report': {'guidance': 'Never include passwords, usernames, TOTP secrets, cookies or session tokens in reports. Use placeholders.'}}, config_file)
                auth_args = ['--config', str(config_path)]
                if task.get('manual_email_code'):
                    env.update(SHANNON_MANUAL_OTP_DIR=str(directory),
                               SHANNON_MANUAL_OTP_KEY_PATH=str(self.store.root / '.target-credentials-key'))
            code = self.execute(['node', str(PROJECT / 'apps/worker/dist/temporal/worker.js'), task['target'],
                                 str(repo), '--task-queue', 'scan-' + task_id, '--workspace', 'scan_' + task_id,
                                 '--workflow-id', workflow_id, '--output', str(directory / 'reports')] + auth_args,
                                directory, env, directory / 'worker.log', 14400, scan=True)
            latest = self.store.get(task_id)
            if latest['state'] == 'cancelling':
                self.finish(latest, 'cancelled')
                return
            result = redact(read_json(result_path), self.authentication)
            state = outcome(result, (directory / 'reports/Security-Assessment-Report.md').is_file(), code)
            error = 'Scan did not produce a verified terminal result and report' if state == 'failed' else None
            if state == 'failed' and read_json(directory / 'otp-status.json').get('status') == 'expired':
                error = 'Email verification time limit reached; create a new task to retry'
            self.finish(latest, state, result=result, error=error)
        except Exception as error:
            latest = self.store.get(task_id)
            self.finish(latest, 'cancelled' if latest['state'] == 'cancelling' else 'failed',
                        error=redact(type(error).__name__ + ': ' + str(error), self.authentication)[:300])
        finally:
            with self.lock:
                self.current, self.process = None, None

    def execute(self, command, cwd, env, log, timeout, scan=False):
        with log.open('ab') as output:
            with self.lock:
                if self.store.get(self.current)['state'] == 'cancelling':
                    raise ValueError('Cancelled before process start')
                self.process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE if self.authentication else output,
                                                stderr=subprocess.STDOUT, start_new_session=True)
                process = self.process
            def capture():
                for line in iter(process.stdout.readline, b''):
                    output.write(redact(line.decode('utf-8', errors='replace'), self.authentication).encode())
                    output.flush()
            reader = None
            if self.authentication:
                reader = threading.Thread(target=capture, daemon=True)
                reader.start()
            deadline = time.monotonic() + timeout
            cancelling_since = None
            while process.poll() is None:
                if scan:
                    with self.lock:
                        latest = self.store.get(self.current)
                        waiting = manual_otp.challenge(cwd)
                        changes = {'progress': redact(read_json(cwd / 'progress.json'), self.authentication)}
                        if latest['state'] in ('running', 'waiting_for_code'):
                            changes['state'] = 'waiting_for_code' if waiting and waiting['deadline_at'] > time.time() else 'running'
                        self.store.update(self.current, **changes)
                cancelling = self.stop.is_set() or self.store.get(self.current)['state'] == 'cancelling'
                otp_status = read_json(cwd / 'otp-status.json').get('status')
                otp_deadline = read_json(cwd / 'otp-session.json').get('deadline')
                if scan and isinstance(otp_deadline, (int, float)) and time.time() * 1000 >= otp_deadline and otp_status != 'authenticated':
                    (cwd / 'otp-status.json').write_text(json.dumps({'status': 'expired'}))
                    otp_status = 'expired'
                otp_failed = scan and otp_status in ('expired', 'failed')
                if cancelling or otp_failed or time.monotonic() > deadline:
                    if cancelling_since is None:
                        cancelling_since = time.monotonic()
                        os.killpg(process.pid, signal.SIGTERM)
                    elif time.monotonic() - cancelling_since > 5:
                        os.killpg(process.pid, signal.SIGKILL)
                time.sleep(0.25)
            # Kill descendants left behind by tools even if the worker exited normally.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if reader:
                reader.join(timeout=5)
                process.stdout.close()
            if not scan and process.returncode:
                raise ValueError('Source checkout failed; see operator logs')
            return process.returncode
