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
            'camera=(self), geolocation=(self), microphone=(self)',
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

    def test_weekly_adherence_report_counts_on_time_doses_and_excludes_future_doses(self):
        self.assertEqual(self.signup().status_code, 201)
        morning = self.client.post(
            '/api/medications',
            json={'name': 'Morning medicine', 'time': '08:00'},
        ).get_json()['medication']
        evening = self.client.post(
            '/api/medications',
            json={'name': 'Evening medicine', 'time': '23:00'},
        ).get_json()['medication']
        with medconnect.app.app_context():
            database = medconnect.get_db()
            database.execute(
                'UPDATE medications SET created_at = ? WHERE id IN (?, ?)',
                ('2026-01-01T00:00:00+00:00', morning['id'], evening['id']),
            )
            doses = (
                (morning['id'], '2026-01-02', '2026-01-02T03:00:00+00:00', 'taken'),
                (morning['id'], '2026-01-03', '2026-01-03T03:01:00+00:00', 'taken'),
                (morning['id'], '2026-01-04', '2026-01-04T02:29:00+00:00', 'taken'),
                (evening['id'], '2026-01-02', '2026-01-02T18:00:00+00:00', 'taken'),
            )
            for medication_id, dose_date, taken_at, status in doses:
                database.execute(
                    '''
                    INSERT INTO dose_history(
                        user_id, medication_id, medication_name, schedule_time,
                        taken_at, taken_date, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        1, medication_id,
                        'Morning medicine' if medication_id == morning['id']
                        else 'Evening medicine',
                        '08:00' if medication_id == morning['id'] else '23:00',
                        taken_at, dose_date, status,
                    ),
                )
            database.commit()

        with patch.object(
            medconnect,
            'utc_now',
            return_value=datetime(2026, 1, 8, 12, 0, tzinfo=timezone.utc),
        ):
            response = self.client.get('/api/adherence')

        self.assertEqual(response.status_code, 200)
        report = response.get_json()['report']
        self.assertEqual(report['start_date'], '2026-01-02')
        self.assertEqual(report['end_date'], '2026-01-08')
        self.assertEqual(report['on_time_window_minutes'], 30)
        self.assertEqual(report['scheduled_doses'], 13)
        self.assertEqual(report['on_time_doses'], 2)
        self.assertEqual(report['adherence_percent'], 15)
        self.assertEqual(report['daily'][-1]['scheduled_doses'], 1)
        self.assertEqual(report['daily'][0]['on_time_doses'], 2)

    def test_history_and_taken_status_use_the_users_local_date(self):
        self.assertEqual(self.signup().status_code, 201)
        self.assertEqual(
            self.client.put(
                '/api/caregivers/settings',
                json={'time_zone': 'America/Los_Angeles'},
            ).status_code,
            200,
        )
        medication = self.client.post(
            '/api/medications',
            json={'name': 'Timezone medicine', 'time': '08:00'},
        ).get_json()['medication']
        with medconnect.app.app_context():
            database = medconnect.get_db()
            for dose_date in ('2026-01-01', '2026-01-07'):
                database.execute(
                    '''
                    INSERT INTO dose_history(
                        user_id, medication_id, medication_name, schedule_time,
                        taken_at, taken_date, status
                    ) VALUES (?, ?, ?, ?, ?, ?, 'taken')
                    ''',
                    (
                        1, medication['id'], 'Timezone medicine', '08:00',
                        '2026-01-07T16:00:00+00:00', dose_date,
                    ),
                )
            database.commit()

        with patch.object(
            medconnect,
            'utc_now',
            return_value=datetime(2026, 1, 8, 2, 0, tzinfo=timezone.utc),
        ):
            medications = self.client.get('/api/medications').get_json()['medications']
            history = self.client.get('/api/history').get_json()['history']

        self.assertTrue(medications[0]['taken_today'])
        self.assertIn('2026-01-01', {entry['taken_date'] for entry in history})

    def test_adherence_pdf_requires_login_and_returns_a_pdf(self):
        self.assertEqual(
            self.client.get('/api/adherence/report.pdf').status_code,
            401,
        )
        self.assertEqual(self.signup().status_code, 201)
        response = self.client.get('/api/adherence/report.pdf')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/pdf')
        self.assertTrue(response.data.startswith(b'%PDF-'))
        self.assertIn('attachment;', response.headers['Content-Disposition'])

    def test_panic_sharing_requires_confirmation_and_sends_only_current_location(self):
        self.assertEqual(self.client.get('/api/panic/status').status_code, 401)
        self.assertEqual(self.signup().status_code, 201)
        self.assertEqual(self.add_caregiver().status_code, 201)
        provider_settings = {
            'TWILIO_ACCOUNT_SID': 'AC' + '1' * 32,
            'TWILIO_AUTH_TOKEN': 'test-token',
            'TWILIO_SMS_FROM': '+14155550100',
            'TWILIO_WHATSAPP_FROM': 'whatsapp:+14155550100',
            'TWILIO_WHATSAPP_PANIC_CONTENT_SID': 'HX' + '2' * 32,
        }
        missing_consent = self.client.post(
            '/api/panic/start',
            json={
                'duration_minutes': 30,
                'location_consent_confirmed': False,
                'latitude': 28.6139,
                'longitude': 77.2090,
            },
        )
        self.assertEqual(missing_consent.status_code, 400)
        self.assertEqual(
            self.client.post(
                '/api/panic/start',
                json={
                    'duration_minutes': 30,
                    'location_consent_confirmed': True,
                    'latitude': 91,
                    'longitude': 77.2090,
                },
            ).status_code,
            400,
        )

        with patch.dict(os.environ, provider_settings):
            with patch.object(
                medconnect, 'dispatch_panic_location',
                return_value={'accepted_by_provider': 2, 'failed': 0},
            ) as dispatch:
                with patch.object(
                    medconnect,
                    'utc_now',
                    return_value=datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc),
                ):
                    started = self.client.post(
                        '/api/panic/start',
                        json={
                            'duration_minutes': 30,
                            'location_consent_confirmed': True,
                            'latitude': 28.6139,
                            'longitude': 77.2090,
                        },
                    )
                    session_id = started.get_json()['active_session']['id']
                    self.assertEqual(
                        self.client.post(
                            f'/api/panic/{session_id}/location',
                            json={'latitude': 28.6, 'longitude': 77.2},
                        ).status_code,
                        429,
                    )
                with patch.object(
                    medconnect,
                    'utc_now',
                    return_value=datetime(2026, 1, 1, 0, 15, tzinfo=timezone.utc),
                ):
                    update = self.client.post(
                        f'/api/panic/{session_id}/location',
                        json={'latitude': 28.6, 'longitude': 77.2},
                    )
                self.assertEqual(update.status_code, 200)
                self.assertEqual(
                    self.client.post(f'/api/panic/{session_id}/stop').status_code,
                    200,
                )
                self.assertEqual(
                    self.client.post(
                        f'/api/panic/{session_id}/location',
                        json={'latitude': 28.6, 'longitude': 77.2},
                    ).status_code,
                    404,
                )

        self.assertEqual(started.status_code, 201)
        self.assertEqual(dispatch.call_count, 2)
        with medconnect.app.app_context():
            columns = {
                row['name'] for row in medconnect.get_db().execute(
                    'PRAGMA table_info(panic_sessions)'
                ).fetchall()
            }
            self.assertNotIn('latitude', columns)
            self.assertNotIn('longitude', columns)
            self.assertEqual(
                medconnect.get_db().execute(
                    "SELECT status FROM panic_sessions WHERE id = ?",
                    (session_id,),
                ).fetchone()['status'],
                'stopped',
            )

    def test_panic_start_fails_explicitly_when_messaging_is_not_configured(self):
        self.assertEqual(self.signup().status_code, 201)
        self.assertEqual(self.add_caregiver().status_code, 201)
        response = self.client.post(
            '/api/panic/start',
            json={
                'duration_minutes': 60,
                'location_consent_confirmed': True,
                'latitude': 28.6139,
                'longitude': 77.2090,
            },
        )
        self.assertEqual(response.status_code, 503)
        self.assertIn('Emergency messaging', response.get_json()['error'])
        self.assertIsNone(self.client.get('/api/panic/status').get_json()['active_session'])

    def test_twilio_panic_whatsapp_request_uses_location_template(self):
        provider_settings = {
            'TWILIO_ACCOUNT_SID': 'AC' + '1' * 32,
            'TWILIO_AUTH_TOKEN': 'test-token',
            'TWILIO_SMS_FROM': '+14155550100',
            'TWILIO_WHATSAPP_FROM': 'whatsapp:+14155550100',
            'TWILIO_WHATSAPP_PANIC_CONTENT_SID': 'HX' + '2' * 32,
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
                medconnect.send_twilio_panic_alert(
                    '+919876543210',
                    'whatsapp',
                    'Test Person',
                    'https://maps.google.com/?q=28.613900,77.209000',
                    60,
                )

        payload = parse_qs(urlopen.call_args.args[0].data.decode())
        self.assertEqual(payload['To'], ['whatsapp:+919876543210'])
        self.assertEqual(
            payload['ContentSid'],
            [provider_settings['TWILIO_WHATSAPP_PANIC_CONTENT_SID']],
        )
        self.assertEqual(
            medconnect.json.loads(payload['ContentVariables'][0]),
            {
                '1': 'Test Person',
                '2': 'https://maps.google.com/?q=28.613900,77.209000',
                '3': '60',
            },
        )

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
