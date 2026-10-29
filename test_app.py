import os
import sqlite3
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

import app as medconnect


class ProductionReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        medconnect.app.config.update(
            DATABASE=str(Path(self.temporary_directory.name) / 'test.db'),
            TESTING=True,
        )
        medconnect.app.config['SECRET_KEY'] = 'test-secret-key-with-at-least-32-bytes'
        medconnect.initialize_db()
        self.client = medconnect.app.test_client()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def signup(self, email='person@example.com'):
        return self.client.post(
            '/api/signup',
            json={
                'name': 'Test Person',
                'email': email,
                'password': 'test-password-123',
                'policy_accepted': True,
            },
        )

    def test_policies_health_check_and_security_headers(self):
        privacy = self.client.get('/privacy')
        terms = self.client.get('/terms')
        health = self.client.get('/healthz')

        self.assertEqual(privacy.status_code, 200)
        self.assertIn(b'Information processed', privacy.data)
        self.assertEqual(terms.status_code, 200)
        self.assertIn(b'does not contact emergency services automatically', terms.data)
        self.assertEqual(health.get_json(), {'status': 'ok'})
        self.assertEqual(health.headers['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(health.headers['X-Frame-Options'], 'DENY')

    def test_signup_requires_policy_acceptance_and_records_timestamp(self):
        response = self.client.post(
            '/api/signup',
            json={
                'name': 'Test Person',
                'email': 'person@example.com',
                'password': 'test-password-123',
            },
        )
        self.assertEqual(response.status_code, 400)

        response = self.signup()
        self.assertEqual(response.status_code, 201)
        with medconnect.app.app_context():
            user = medconnect.get_db().execute(
                'SELECT policy_accepted_at FROM users WHERE email = ?',
                ('person@example.com',),
            ).fetchone()
        self.assertIsNotNone(user['policy_accepted_at'])

    def test_account_delete_requires_password_and_removes_user_data(self):
        self.assertEqual(self.signup().status_code, 201)
        medication = self.client.post(
            '/api/medications',
            json={'name': 'Test medicine', 'time': '09:00'},
        ).get_json()['medication']
        self.assertEqual(
            self.client.post(
                f"/api/medications/{medication['id']}/taken",
                json={'date': date.today().isoformat()},
            ).status_code,
            200,
        )

        wrong_password = self.client.post(
            '/api/account/delete',
            json={'password': 'wrong-password'},
        )
        self.assertEqual(wrong_password.status_code, 403)
        self.assertIsNotNone(self.client.get('/api/session').get_json()['user'])

        deleted = self.client.post(
            '/api/account/delete',
            json={'password': 'test-password-123'},
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(self.client.get('/api/session').get_json(), {'user': None})
        self.assertEqual(self.client.get('/api/medications').status_code, 401)

        with medconnect.app.app_context():
            database = medconnect.get_db()
            self.assertEqual(database.execute('SELECT COUNT(*) FROM users').fetchone()[0], 0)
            self.assertEqual(database.execute('SELECT COUNT(*) FROM medications').fetchone()[0], 0)
            self.assertEqual(database.execute('SELECT COUNT(*) FROM dose_history').fetchone()[0], 0)

    def test_password_reset_sends_otp_and_accepts_it(self):
        self.assertEqual(self.signup('person@gmail.com').status_code, 201)
        with patch.object(medconnect.secrets, 'randbelow', return_value=12345):
            with patch.object(medconnect, 'send_password_reset_email') as send_email:
                response = self.client.post(
                    '/api/password-reset/request',
                    json={'email': 'person@gmail.com'},
                )

        self.assertEqual(response.status_code, 200)
        send_email.assert_called_once_with('person@gmail.com', '012345')
        confirmation = self.client.post(
            '/api/password-reset/confirm',
            json={
                'email': 'person@gmail.com',
                'otp': '012345',
                'password': 'new-test-password-456',
            },
        )
        self.assertEqual(confirmation.status_code, 200)
        login = self.client.post(
            '/api/login',
            json={'email': 'person@gmail.com', 'password': 'new-test-password-456'},
        )
        self.assertEqual(login.status_code, 200)

    def test_password_reset_reports_missing_gmail_configuration(self):
        self.assertEqual(self.signup('person@gmail.com').status_code, 201)
        with patch.dict(
            os.environ,
            {'MEDCONNECT_GMAIL_ADDRESS': '', 'MEDCONNECT_GMAIL_APP_PASSWORD': ''},
        ):
            with patch.object(medconnect.logger, 'exception') as log_exception:
                response = self.client.post(
                    '/api/password-reset/request',
                    json={'email': 'person@gmail.com'},
                )

        self.assertEqual(response.status_code, 503)
        self.assertIn('MEDCONNECT_GMAIL_ADDRESS', response.get_json()['error'])
        self.assertIn('MEDCONNECT_GMAIL_APP_PASSWORD', response.get_json()['error'])
        log_exception.assert_called_once_with('Could not send password reset email')

    def test_login_rate_limit_stores_only_hashed_client_address(self):
        for _ in range(10):
            response = self.client.post(
                '/api/login',
                json={'email': 'unknown@example.com', 'password': 'incorrect'},
                environ_overrides={'REMOTE_ADDR': '203.0.113.42'},
            )
            self.assertEqual(response.status_code, 401)

        limited = self.client.post(
            '/api/login',
            json={'email': 'unknown@example.com', 'password': 'incorrect'},
            environ_overrides={'REMOTE_ADDR': '203.0.113.42'},
        )
        self.assertEqual(limited.status_code, 429)
        self.assertGreater(int(limited.headers['Retry-After']), 0)

        with medconnect.app.app_context():
            client_hash = medconnect.get_db().execute(
                "SELECT client_hash FROM rate_limit_counters WHERE scope = 'login'"
            ).fetchone()['client_hash']
        self.assertEqual(len(client_hash), 64)
        self.assertNotIn('203.0.113.42', client_hash)

    def test_account_delete_rate_limits_repeated_password_failures(self):
        self.assertEqual(self.signup().status_code, 201)
        for _ in range(5):
            response = self.client.post(
                '/api/account/delete',
                json={'password': 'wrong-password'},
            )
            self.assertEqual(response.status_code, 403)

        limited = self.client.post(
            '/api/account/delete',
            json={'password': 'wrong-password'},
        )
        self.assertEqual(limited.status_code, 429)

    def test_assistant_rejects_oversized_questions(self):
        response = self.client.post(
            '/ask',
            json={'question': 'x' * 2001, 'language': 'en'},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('under 2,000 characters', response.get_json()['answer'])

    def test_signup_rejects_non_string_email_without_server_error(self):
        response = self.client.post(
            '/api/signup',
            json={
                'name': 'Test Person',
                'email': [],
                'password': 'test-password-123',
                'policy_accepted': True,
            },
        )
        self.assertEqual(response.status_code, 400)


if __name__ == '__main__':
    unittest.main()
