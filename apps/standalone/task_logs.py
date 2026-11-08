"""Bounded, credential-redacted task logs; never serves arbitrary task files."""
import os
import re
from datetime import datetime, timezone
from .target_auth import CredentialVault, redact

FILES = ('temporal.log', 'source.log', 'worker.log')
LIMIT = 512 * 1024


def sanitize(text, authentication=None):
    credentials = dict((authentication or {}).get('credentials', {}))
    credentials.update({key: value for key, value in os.environ.items()
                        if re.search(r'KEY|TOKEN|PASSWORD|SECRET|CREDENTIAL', key, re.I) and value})
    text = redact(text, {'credentials': credentials})
    text = re.sub(r'(?i)(Bearer\s+)\S+', r'\1[REDACTED]', text)
    text = re.sub(r'(?i)(https?://)[^\s/@]+:[^\s/@]+@', r'\1[REDACTED]@', text)
    text = re.sub(r'(?i)([?&](?:token|key|password|code|secret|signature)=)[^\s&#]*', r'\1[REDACTED]', text)
    return text


def append_temporal(directory, text, authentication=None):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / 'temporal.log'
    with path.open('a') as output:
        os.chmod(path, 0o600)
        output.write(datetime.now(timezone.utc).isoformat() + ' ' + sanitize(text, authentication) + '\n')


def read_logs(root, directory):
    authentication = CredentialVault(root).redaction_auth(directory) if (directory / 'authentication.enc').is_file() else None
    sections = []
    for name in FILES:
        path = directory / name
        if not path.is_file() or path.is_symlink():
            continue
        with path.open('rb') as source:
            size = source.seek(0, 2)
            source.seek(max(0, size - LIMIT))
            body = source.read(LIMIT).decode('utf-8', errors='replace')
        sections.append('=== ' + name + (' (仅最近 512 KiB)' if size > LIMIT else '') + ' ===\n' + sanitize(body, authentication))
    return '\n\n'.join(sections) or '暂无任务日志。旧任务未保存的 Temporal 检查输出无法恢复。'
