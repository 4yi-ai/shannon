"""Target login validation and per-install encrypted credentials (separate from 4YI SSO)."""
import base64
import json
import html
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit, quote, quote_plus

from .security import public_url

BRIDGE = Path(__file__).resolve().parents[2] / 'deploy/4yi/credentials.mjs'


def validate_auth(value, target, origins):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {'manual_email_code'} != {'login_type', 'login_url', 'credentials', 'login_flow', 'success_condition'}:
        raise ValueError('Invalid target authentication fields')
    if 'manual_email_code' in value and not isinstance(value['manual_email_code'], bool):
        raise ValueError('manual_email_code must be a boolean')
    if value['login_type'] != 'form':
        raise ValueError('This version supports same-origin form login only')
    login_url = public_url(value['login_url'], origins)
    if urlsplit(login_url).netloc != urlsplit(target).netloc:
        raise ValueError('Login URL must use the target website origin')
    if urlsplit(login_url).query:
        raise ValueError('Login URL must not contain query credentials')
    credentials = value['credentials']
    if not isinstance(credentials, dict) or set(credentials) - {'username', 'password', 'totp_secret'}:
        raise ValueError('Invalid credential fields')
    if value.get('manual_email_code') and credentials.get('totp_secret'):
        raise ValueError('Choose either manual email verification or TOTP')
    for field in ('username', 'password'):
        if not isinstance(credentials.get(field), str) or not 1 <= len(credentials[field]) <= 255 or any(c in credentials[field] for c in ('\x00', '\r', '\n')):
            raise ValueError('Target username and password must contain 1–255 characters')
    # Match upstream free-text validation without echoing the supplied value.
    def safe_text(text, limit):
        return isinstance(text, str) and 1 <= len(text) <= limit and not re.search(r'\.\./|[<>]|javascript:|data:|file:', text, re.I)
    if not safe_text(credentials['username'], 255):
        raise ValueError('Invalid target username')
    totp = credentials.get('totp_secret')
    if totp is not None and (not isinstance(totp, str) or not re.fullmatch(r'[A-Za-z2-7]{16,128}=*', totp)):
        raise ValueError('Invalid Base32 TOTP secret')
    steps = value['login_flow']
    if not isinstance(steps, list) or not 1 <= len(steps) <= 20 or not all(safe_text(s, 500) for s in steps):
        raise ValueError('Provide 1–20 login steps, each at most 500 characters')
    success = value['success_condition']
    if not isinstance(success, dict) or set(success) != {'type', 'value'} or success['type'] not in ('url_contains', 'text_contains', 'url_equals_exactly') or not safe_text(success['value'], 500):
        raise ValueError('Invalid login success condition')
    if success['type'] == 'url_equals_exactly':
        exact = public_url(success['value'], origins)
        if urlsplit(exact).netloc != urlsplit(target).netloc:
            raise ValueError('Success URL must use the target website origin')
    return dict(value, login_url=login_url)


class CredentialVault:
    def __init__(self, root):
        self.root = Path(root)

    def transform(self, operation, data):
        key_path = self.root / '.target-credentials-key'
        if operation == 'open' and not key_path.is_file():
            raise ValueError('Target credential key missing; restore the matching backup')
        try:
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(os.urandom(32))
                stream.flush()
                os.fsync(stream.fileno())
        payload = json.dumps({'operation': operation, 'key': base64.b64encode(key_path.read_bytes()).decode(),
                              'data': base64.b64encode(data).decode()})
        try:
            output = subprocess.run(['node', str(BRIDGE)], input=payload.encode(), capture_output=True, check=True, timeout=15)
            return base64.b64decode(output.stdout, validate=True)
        except (OSError, subprocess.SubprocessError, ValueError):
            raise ValueError('Target credential storage unavailable') from None

    def write_private(self, file, value):
        encrypted = self.transform('seal', json.dumps(value).encode())
        temporary = file.with_name(file.name + '.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(encrypted)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, file)
        finally:
            temporary.unlink(missing_ok=True)

    def save(self, directory, authentication):
        self.write_private(directory / 'authentication.enc', authentication)

    def load(self, directory):
        return json.loads(self.transform('open', (directory / 'authentication.enc').read_bytes()))

    def redaction_auth(self, directory):
        authentication = self.load(directory)
        file = directory / 'otp-redaction.enc'
        if file.exists():
            extra = json.loads(self.transform('open', file.read_bytes()))
            codes = extra.get('codes', [extra['code']] if 'code' in extra else [])
            for index, code in enumerate(codes, 1):
                authentication['credentials']['manual_code_' + str(index)] = code
        return authentication


def redact(value, authentication):
    raw_secrets = list(authentication.get('credentials', {}).values()) if authentication else []
    secrets = {variant for secret in raw_secrets for variant in (secret, quote(secret, safe=''), quote_plus(secret), html.escape(secret), json.dumps(secret, ensure_ascii=True)[1:-1])}
    if isinstance(value, str):
        for secret in sorted(secrets, key=len, reverse=True):
            if secret:
                value = value.replace(secret, '[REDACTED]')
        return value
    if isinstance(value, dict):
        return {k: redact(v, authentication) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, authentication) for v in value]
    return value
