"""One-use, task-bound manual email challenge. No plaintext OTP in task metadata."""
import json
import re
import time
from .target_auth import CredentialVault


def challenge(directory):
    try:
        value = json.loads((directory / 'otp-request.json').read_text())
        if (not isinstance(value, dict) or not re.fullmatch(r'[a-f0-9]{32}', value.get('id', ''))
                or not isinstance(value.get('expires_at'), (int, float))):
            return None
        return {'id': value['id'], 'expires_at': value['expires_at'],
                'submitted': (directory / 'otp-response.enc').exists()}
    except (OSError, ValueError, TypeError):
        return None


def submit(runner, task_id, body):
    with runner.lock:
        task = runner.store.get(task_id)
        directory = runner.directory(task_id)
        current = challenge(directory)
        if (not task.get('manual_email_code') or task['state'] not in ('running', 'waiting_for_code')
                or not current or current['expires_at'] <= time.time() or current['submitted']):
            raise ValueError('No active email verification request; it may have expired or already been submitted')
        if not isinstance(body, dict) or set(body) != {'request_id', 'code'} or body['request_id'] != current['id']:
            raise ValueError('Email verification request changed; refresh the task')
        code = body['code']
        if not isinstance(code, str) or not re.fullmatch(r'[A-Za-z0-9]{4,12}', code):
            raise ValueError('Verification code must contain 4–12 letters or digits')
        vault = CredentialVault(runner.store.root)
        # Keep encrypted redaction material for subsequent report downloads.
        vault.write_private(directory / 'otp-redaction.enc', {'code': code})
        if runner.current == task_id and runner.authentication:
            runner.authentication['credentials']['manual_code'] = code
        vault.write_private(directory / 'otp-response.enc', {'request_id': current['id'], 'code': code})
        return {'accepted': True}


def cleanup(directory):
    for name in ('otp-request.json', 'otp-response.enc', 'otp-request.json.tmp', 'otp-response.enc.tmp', 'otp-redaction.enc.tmp'):
        (directory / name).unlink(missing_ok=True)
