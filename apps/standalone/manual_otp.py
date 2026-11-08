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
                'submitted': (directory / 'otp-response.enc').exists(),
                'deadline_at': value.get('deadline_at', value['expires_at']),
                'resend_after': value.get('resend_after', value['expires_at']),
                'attempt': value.get('attempt', 1), 'max_attempts': 3,
                'reason': value.get('reason') if value.get('reason') in ('initial', 'incorrect', 'after_resend') else 'initial'}
    except (OSError, ValueError, TypeError):
        return None


def submit(runner, task_id, body, resend=False):
    with runner.lock:
        task = runner.store.get(task_id)
        directory = runner.directory(task_id)
        current = challenge(directory)
        if (not task.get('manual_email_code') or task['state'] not in ('running', 'waiting_for_code')
                or not current or current['deadline_at'] <= time.time() or current['submitted']):
            raise ValueError('No active email verification request; it may have expired or already been submitted')
        fields = {'request_id'} if resend else {'request_id', 'code'}
        if not isinstance(body, dict) or set(body) != fields or body['request_id'] != current['id']:
            raise ValueError('Email verification request changed; refresh the task')
        vault = CredentialVault(runner.store.root)
        if resend:
            if current['attempt'] >= current['max_attempts'] or time.time() < current['resend_after']:
                raise ValueError('Resend is cooling down or the attempt limit has been reached')
            vault.write_private(directory / 'otp-response.enc', {'request_id': current['id'], 'action': 'resend'})
            return {'accepted': True}
        if current['expires_at'] <= time.time():
            raise ValueError('This email code has expired; request a new email in this task')
        code = body['code']
        if not isinstance(code, str) or not re.fullmatch(r'[A-Za-z0-9]{4,12}', code):
            raise ValueError('Verification code must contain 4–12 letters or digits')
        # Keep encrypted redaction material for subsequent report downloads.
        codes = []
        archive = directory / 'otp-redaction.enc'
        if archive.exists():
            previous = json.loads(vault.transform('open', archive.read_bytes()))
            codes = previous.get('codes', [previous['code']] if 'code' in previous else [])
        if len(codes) >= 3:
            raise ValueError('Email verification attempt limit reached')
        codes.append(code)
        vault.write_private(archive, {'codes': codes})
        if runner.current == task_id and runner.authentication:
            runner.authentication['credentials']['manual_code_' + str(len(codes))] = code
        vault.write_private(directory / 'otp-response.enc', {'request_id': current['id'], 'code': code})
        return {'accepted': True}


def cleanup(directory):
    for name in ('otp-request.json', 'otp-response.enc', 'otp-request.json.tmp', 'otp-response.enc.tmp', 'otp-redaction.enc.tmp', 'otp-lock'):
        (directory / name).unlink(missing_ok=True)
