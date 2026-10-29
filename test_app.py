import os
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs
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

    def add_caregiver(self, phone='+919876543210', name='Family member'):
        return self.client.post(
            '/api/caregivers',
            json={
                'name': name,
                'phone': phone,
                'consent_confirmed': True,
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
        self.assertEqual(
            health.headers['Permissions-Policy'],
            'camera=(self), geolocation=(), microphone=(self)',
        )

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
        self.assertEqual(self.add_caregiver().status_code, 201)
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
            self.assertEqual(database.execute('SELECT COUNT(*) FROM caregiver_contacts').fetchone()[0], 0)

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

    def test_caregiver_contacts_require_login_consent_and_international_number(self):
        self.assertEqual(self.client.get('/api/caregivers').status_code, 401)
        self.assertEqual(self.signup().status_code, 201)
        missing_consent = self.client.post(
            '/api/caregivers',
            json={
                'name': 'Family member',
                'phone': '+919876543210',
                'consent_confirmed': False,
            },
        )
        self.assertEqual(missing_consent.status_code, 400)
        invalid_phone = self.client.post(
            '/api/caregivers',
            json={
                'name': 'Family member',
                'phone': '9876543210',
                'consent_confirmed': True,
            },
        )
        self.assertEqual(invalid_phone.status_code, 400)

        added = self.add_caregiver()
        self.assertEqual(added.status_code, 201)
        self.assertFalse(added.get_json()['notifications_configured'])
        listing = self.client.get('/api/caregivers').get_json()
        self.assertEqual(len(listing['caregivers']), 1)
        self.assertEqual(listing['caregivers'][0]['phone_e164'], '+919876543210')
        self.assertEqual(listing['delay_minutes'], 15)
        self.assertEqual(listing['channels'], ['sms', 'whatsapp'])
        self.assertEqual(
            self.client.delete(
                f"/api/caregivers/{added.get_json()['caregiver']['id']}"
            ).status_code,
            200,
        )

    def test_caregiver_timezone_must_be_a_valid_iana_zone(self):
        self.assertEqual(self.signup().status_code, 201)
        updated = self.client.put(
            '/api/caregivers/settings',
            json={'time_zone': 'America/Los_Angeles'},
        )
        invalid = self.client.put(
            '/api/caregivers/settings',
            json={'time_zone': 'not/a-real-zone'},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(invalid.status_code, 400)
        with medconnect.app.app_context():
            time_zone = medconnect.get_db().execute(
                'SELECT time_zone FROM users WHERE email = ?',
                ('person@example.com',),
            ).fetchone()['time_zone']
        self.assertEqual(time_zone, 'America/Los_Angeles')

    def test_due_caregiver_alerts_send_both_channels_once_per_contact(self):
        self.assertEqual(self.signup().status_code, 201)
        medication = self.client.post(
            '/api/medications',
            json={'name': 'Private medicine', 'time': '09:00'},
        ).get_json()['medication']
        self.assertEqual(self.add_caregiver().status_code, 201)
        self.assertEqual(
            self.add_caregiver('+14155550123', 'Second caregiver').status_code,
            201,
        )
        with medconnect.app.app_context():
            medconnect.get_db().execute(
                'UPDATE medications SET schedule_time = ? WHERE id = ?',
                ('09:00', medication['id']),
            )
            medconnect.get_db().commit()

        provider_settings = {
            'TWILIO_ACCOUNT_SID': 'AC' + '1' * 32,
            'TWILIO_AUTH_TOKEN': 'test-token',
            'TWILIO_SMS_FROM': '+14155550100',
            'TWILIO_WHATSAPP_FROM': 'whatsapp:+14155550100',
            'TWILIO_WHATSAPP_CONTENT_SID': 'HX' + '1' * 32,
        }
        due_time = datetime(2026, 1, 1, 3, 45, tzinfo=timezone.utc)
        with patch.dict(os.environ, provider_settings):
            with patch.object(medconnect, 'send_twilio_caregiver_alert') as send_alert:
                sent = medconnect.process_due_caregiver_alerts(due_time)
                repeated = medconnect.process_due_caregiver_alerts(due_time)

        self.assertEqual(sent, 4)
        self.assertEqual(repeated, 0)
        self.assertEqual(send_alert.call_count, 4)
        self.assertEqual(
            {call.args[1] for call in send_alert.call_args_list},
            {'sms', 'whatsapp'},
        )
        self.assertTrue(all(call.args[1] for call in send_alert.call_args_list))
        with medconnect.app.app_context():
            alert = medconnect.get_db().execute(
                'SELECT status FROM caregiver_alerts WHERE medication_id = ?',
                (medication['id'],),
            ).fetchone()
            deliveries = medconnect.get_db().execute(
                '''
                SELECT status, COUNT(*) AS count
                FROM caregiver_alert_deliveries
                GROUP BY status
                '''
            ).fetchall()
        self.assertEqual(alert['status'], 'sent')
        self.assertEqual({row['status']: row['count'] for row in deliveries}, {'sent': 4})

    def test_taken_dose_prevents_caregiver_alerts(self):
        self.assertEqual(self.signup().status_code, 201)
        medication = self.client.post(
            '/api/medications',
            json={'name': 'Test medicine', 'time': '09:00'},
        ).get_json()['medication']
        self.assertEqual(self.add_caregiver().status_code, 201)
        self.assertEqual(
            self.client.post(
                f"/api/medications/{medication['id']}/taken",
                json={'date': '2026-01-01'},
            ).status_code,
            200,
        )
        provider_settings = {
            'TWILIO_ACCOUNT_SID': 'AC' + '1' * 32,
            'TWILIO_AUTH_TOKEN': 'test-token',
            'TWILIO_SMS_FROM': '+14155550100',
            'TWILIO_WHATSAPP_FROM': 'whatsapp:+14155550100',
            'TWILIO_WHATSAPP_CONTENT_SID': 'HX' + '1' * 32,
        }
        with patch.dict(os.environ, provider_settings):
            with patch.object(medconnect, 'send_twilio_caregiver_alert') as send_alert:
                sent = medconnect.process_due_caregiver_alerts(
                    datetime(2026, 1, 1, 3, 45, tzinfo=timezone.utc)
                )
        self.assertEqual(sent, 0)
        send_alert.assert_not_called()

    def test_twilio_whatsapp_request_uses_approved_template_variables(self):
        provider_settings = {
            'TWILIO_ACCOUNT_SID': 'AC' + '1' * 32,
            'TWILIO_AUTH_TOKEN': 'test-token',
            'TWILIO_SMS_FROM': '+14155550100',
            'TWILIO_WHATSAPP_FROM': 'whatsapp:+14155550100',
            'TWILIO_WHATSAPP_CONTENT_SID': 'HX' + '1' * 32,
        }

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *exception_details):
                return not any(exception_details)

            def read(self):
                return b'{"sid":"SM123"}'

        with patch.dict(os.environ, provider_settings):
            with patch.object(
                medconnect.urllib.request,
                'urlopen',
                return_value=FakeResponse(),
            ) as urlopen:
                medconnect.send_twilio_caregiver_alert(
                    '+919876543210',
                    'whatsapp',
                    'Test Person',
                    '09:00',
                )

        provider_request = urlopen.call_args.args[0]
        payload = parse_qs(provider_request.data.decode())
        self.assertEqual(payload['To'], ['whatsapp:+919876543210'])
        self.assertEqual(payload['ContentSid'], [provider_settings['TWILIO_WHATSAPP_CONTENT_SID']])
        self.assertEqual(
            medconnect.json.loads(payload['ContentVariables'][0]),
            {'1': 'Test Person', '2': '09:00', '3': '15'},
        )


if __name__ == '__main__':
    unittest.main()
