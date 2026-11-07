"""4YI trusted reverse-proxy auth; the public router strips client x-xclaw-* headers.

SSO mode requires private, router-only ingress. These headers are not signatures:
never expose the application's service directly or trust a caller-supplied org alone.
"""
import os
import re

UUID = re.compile(r'^[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$')


class Access:
    def __init__(self, environ=None):
        env = os.environ if environ is None else environ
        self.mode = env.get('SHANNON_AUTH_MODE', '4yi_sso')
        self.hostname = env.get('XCLAW_APP_HOSTNAME', '').lower().rstrip('.')
        self.org = env.get('XCLAW_CONSUMER_ORG_ID') or env.get('XCLAW_ORG_ID', '')
        if self.mode != '4yi_sso':
            raise ValueError('Unsupported SHANNON_AUTH_MODE')

    @property
    def configured(self):
        return bool(self.hostname and UUID.fullmatch(self.org))

    def check(self, headers, method):
        if not self.configured:
            return 503, 'Application access is not configured for this installation'
        # Only identity injected after the 4YI router validates its SSO session.
        names = ('sso-session-id', 'user-id', 'route-id', 'app-id')
        if any(not UUID.fullmatch(headers.get('X-Xclaw-' + name, '')) for name in names):
            return 401, 'Open Shannon from the 4YI marketplace to sign in'
        if headers.get('X-Xclaw-Owner-Org-Id', '') != self.org:
            return 403, 'Installation organization mismatch'
        if headers.get('X-Xclaw-Hostname', '').lower() != self.hostname:
            return 403, 'Installation hostname mismatch'
        if headers.get('X-Forwarded-Host', '').lower() != self.hostname or headers.get('X-Forwarded-Proto') != 'https':
            return 403, 'Trusted HTTPS router context required'
        if method not in ('GET', 'HEAD') and headers.get('Origin') != 'https://' + self.hostname:
            return 403, 'Same-origin browser request required'
        return 200, ''
