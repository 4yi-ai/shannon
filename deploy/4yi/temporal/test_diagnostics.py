"""Synthetic credentials only: verify raw logging is opt-in and JSON-escaped."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('temporal_server', Path(__file__).with_name('server.py'))
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class DatabaseDiagnosticsTests(unittest.TestCase):
    def output(self, env):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            server.log_database_configuration(env)
        return stream.getvalue()

    def test_default_does_not_log_password_or_other_credentials(self):
        value = self.output({'POSTGRES_PASSWORD':'synthetic-db-secret', 'OTHER_TOKEN':'synthetic-other-secret'})
        self.assertNotIn('synthetic-db-secret', value)
        self.assertNotIn('synthetic-other-secret', value)
        self.assertIn('"password_configured": true', value)
        self.assertIn('shannon-postgres', value)

    def test_exact_opt_in_logs_only_selected_config_and_escapes_lines(self):
        secret = 'synthetic-secret\nnot-a-new-log'
        env = {'POSTGRES_PASSWORD':secret, 'SHANNON_DEBUG_DATABASE_CREDENTIALS':'true',
               'POSTGRES_SEEDS':'fixture-db', 'POSTGRES_USER':'fixture-role', 'OTHER_TOKEN':'not-selected'}
        value = self.output(env)
        self.assertEqual(len(value.splitlines()),2)
        detail = json.loads(value.splitlines()[1].split(': ',1)[1])
        self.assertEqual(detail['password'],secret)
        self.assertEqual(detail['host'],'fixture-db')
        self.assertNotIn('not-selected',value)
        env['SHANNON_DEBUG_DATABASE_CREDENTIALS']='false'
        self.assertNotIn('synthetic-secret',self.output(env))


if __name__ == '__main__':
    unittest.main()
