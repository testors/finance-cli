"""Synthetic certificate onboarding through the web job contract. No institution connections."""
import base64
import copy
import functools
import io
import json
import sys
from unittest.mock import patch

from support import ROOT, ServerCase
sys.path.insert(0, str(ROOT / 'tests'))
import test_hana_onesign as fixture
from test_certificate import synthetic_material

from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives.serialization import pkcs12, load_der_private_key, BestAvailableEncryption
from cryptography import x509
from finance_cli.core import storage
from finance_cli.credentials.joint import crypto
from finance_cli.credentials.registry import Registry
from finance_cli.server import jobs, worker
from finance_cli.server.adapters import certificates
from finance_cli.services.hana import onesign, onesign_setup, onesign_signup_protocol as signup
from finance_cli.services.hana.onesign_state import State


class CertificateTests(ServerCase):
    @classmethod
    def setUpClass(cls):
        fixture.FlowTests.setUpClass()
        cls.flow = fixture.FlowTests

    def setUp(self):
        super().setUp()
        self.enroll()

    def run_job(self, name, input, secrets):
        row, _ = jobs.submit(self.db, name=name, input=input, origin='web:test')
        return self.run_row(row, secrets)

    def run_row(self, row, secrets):
        worker.run(self.db, row['id'], row['step'], control=io.StringIO(), stdin=io.StringIO(json.dumps(secrets) + '\n'))
        return self.get('/jobs/' + row['id']).json()

    def setup_identity(self):
        self.enterContext(patch.object(ECC, 'generate', return_value=self.flow.signing_key))
        with State('synthetic', fixture.PASSWORD, copy.deepcopy(self.flow.template)) as state:
            self.services = fixture.Services(state, self.flow.cert, self.flow.public)
        original = onesign.operate
        self.enterContext(patch.object(onesign, 'operate', functools.partial(original, exchange=self.services)))

    def stage(self, stage, **secrets):
        return self.run_job('hana.onesign.issue.' + stage, {'name': 'synthetic', **({'send': True} if
                            certificates.OneSignIssuance(stage).remote else {})},
                            {'vault_passphrase': fixture.PASSWORD, **secrets})

    def before_issue(self):
        self.setup_identity()
        profile = {'name': '합성 이름', 'birth7': '9001011', 'phone': '01000000000', 'carrier': '4'}
        self.assertEqual(self.stage('profile', phone_profile=json.dumps(profile),
            agreement=certificates.terms_digest(signup.sms_terms('4')))['outcome'], 'success')
        for stage in ('authenticate', 'request-sms'):
            self.assertEqual(self.stage(stage)['outcome'], 'success')
        verified = self.stage('verify-sms', sms='012345')
        self.assertEqual(verified['result']['next_stage'], 'consent')
        self.assertEqual(self.stage('consent', agreement=verified['result']['terms_digest'])['outcome'], 'success')
        self.assertEqual(self.stage('begin-id')['outcome'], 'success')
        jpeg = b'\xff\xd8\xff\xc0\x00\x11\x08\x01\x00\x02\x00' + bytes(10)
        capture = {'kind': 'resident', 'fields': {'name': '합성 이름', 'issueDate': '2020.02.29',
                    'birthDate': '900101', 'resident': '1000000'},
                   'image': base64.b64encode(jpeg).decode(), 'confirmation': '본인 신분증'}
        self.assertEqual(self.stage('prepare-id', identity_capture=json.dumps(capture))['outcome'], 'success')
        self.assertEqual(self.stage('identity')['outcome'], 'success')
        self.assertEqual(self.stage('account', account_number=fixture.SOURCE, account_password='6049')['outcome'], 'success')

    def assert_private(self, job, *needles):
        text = json.dumps(job, ensure_ascii=False)
        for value in needles:
            self.assertNotIn(value, text)
        with self.db.read() as con:
            rows = con.execute('SELECT * FROM jobs').fetchall()
            events = con.execute('SELECT * FROM job_events').fetchall()
        database = str([tuple(row) for row in [*rows, *events]])
        for value in needles:
            self.assertNotIn(value, database)

    def test_options_authentication_and_allowlist(self):
        self.client.cookies.clear()
        self.assertEqual(self.get('/certificates/options').status_code, 401)
        self.enroll()
        with patch.object(onesign_setup, 'load', return_value={**self.flow.settings, 'extra': 'SYNTHETIC-PRIVATE'}):
            directory = storage.directory(self.home / 'hana' / 'settings')
            storage.write_new(directory / 'synthetic.json', b'{}')
            result = self.get('/certificates/options').json()
        self.assertEqual(result['hana']['settings'], [{'name': 'synthetic', 'version': '1.0.27'}])
        self.assertFalse(result['joint']['issuance'])
        self.assertFalse(result['financial']['issuance'])
        self.assertNotIn('SYNTHETIC-PRIVATE', json.dumps(result))
        self.assertNotIn('secure_token', json.dumps(result))
        self.assertFalse(result['network_used'])

    def test_remote_send_approval_required_before_store_or_worker(self):
        with patch.object(State, '__enter__', side_effect=AssertionError('must not open')), \
                patch('finance_cli.server.app.start_with_secrets') as start:
            refused = self.post('/jobs', {'name': 'hana.onesign.issue.authenticate', 'input': {'name': 'missing'},
                                          'secrets': {'vault_passphrase': fixture.PASSWORD}})
        self.assertEqual(refused.json()['error'], 'send_approval_required')
        start.assert_not_called()
        self.assertEqual(self.get('/jobs').json()['jobs'], [])

    def test_npki_import_is_local_and_private(self):
        cert, private, _ = synthetic_material()
        encrypted = crypto.encrypt(private, 'SYNTHETIC-password')
        encoded_cert, encoded_key = (base64.b64encode(raw).decode() for raw in (cert, encrypted))
        job = self.run_job('cert.joint.import', {'name': 'imported', 'format': 'npki', 'compatibility': 'hana'},
                           {'certificate_password': 'SYNTHETIC-password', 'certificate_file': encoded_cert,
                            'private_key_file': encoded_key})
        self.assertEqual(job['outcome'], 'success', job)
        self.assertEqual(Registry().material('imported', b'SYNTHETIC-password')[0], cert)
        self.assertIsNone(job['service_verdict'])
        self.assert_private(job, encoded_cert, encoded_key, 'SYNTHETIC-password')
        self.assertEqual(job['artifacts'], [])

    def test_pfx_import(self):
        cert, private, _ = synthetic_material()
        password = b'SYNTHETIC-password'
        pfx = pkcs12.serialize_key_and_certificates(b'Synthetic', load_der_private_key(private, None),
                  x509.load_der_x509_certificate(cert), None, BestAvailableEncryption(password))
        job = self.run_job('cert.joint.import', {'name': 'pfx', 'format': 'pfx'},
                           {'certificate_password': password.decode(), 'certificate_file': base64.b64encode(pfx).decode(),
                            'private_key_file': 'unused'})
        self.assertEqual(job['outcome'], 'success', job)
        self.assertEqual(Registry().material('pfx', password)[0], cert)

    def test_init_is_local_and_duplicate_name_does_not_replace(self):
        with patch.object(onesign_setup, 'load', return_value=self.flow.settings):
            job = self.run_job('hana.onesign.issue.init', {'name': 'new', 'settings': 'synthetic'},
                               {'vault_passphrase': fixture.PASSWORD})
            self.assertEqual((job['outcome'], job['result']['next_stage']), ('success', 'profile'))
            original = (self.home / 'hana' / 'identities' / 'new' / 'state.json').read_bytes()
            duplicate = self.run_job('hana.onesign.issue.init', {'name': 'new', 'settings': 'synthetic'},
                                    {'vault_passphrase': fixture.PASSWORD})
        self.assertEqual(duplicate['outcome'], 'not_started')
        self.assertEqual((self.home / 'hana' / 'identities' / 'new' / 'state.json').read_bytes(), original)
        self.assert_private(job, fixture.PASSWORD)

    def test_full_issuance_and_duplicate_step_never_reexecutes(self):
        self.before_issue()
        issued = self.stage('issue', new_pin=fixture.PIN, new_pin_confirmation=fixture.PIN, issue_confirmation='발급')
        self.assertEqual((issued['outcome'], issued['result']['certificate_issued']), ('success', True), issued)
        self.assertEqual(issued['result']['next_stage'], 'complete')
        count = len(self.services.calls)
        repeat = self.stage('issue', new_pin=fixture.PIN, new_pin_confirmation=fixture.PIN, issue_confirmation='발급')
        self.assertEqual((repeat['outcome'], len(self.services.calls)), ('not_started', count))
        finished = self.stage('complete')
        self.assertTrue(finished['result']['ready'], finished)
        self.assertIsNone(finished['result']['next_stage'])
        self.assertEqual(self.get('/logins').json()['logins'], [])  # No automatic login.
        self.assert_private(finished, fixture.PASSWORD, fixture.PIN, fixture.SOURCE, '01000000000', '1000000', 'SYNTHETIC-ACCESS')

    def test_pin_and_confirmation_validation_before_requests(self):
        self.before_issue()
        count = len(self.services.calls)
        bad = self.stage('issue', new_pin=fixture.PIN, new_pin_confirmation='604927', issue_confirmation='발급')
        self.assertEqual((bad['outcome'], bad['local']['stopped']), ('not_started', 'new_pin_confirmation_mismatch'))
        no = self.stage('issue', new_pin=fixture.PIN, new_pin_confirmation=fixture.PIN, issue_confirmation='no')
        self.assertEqual(no['local']['stopped'], 'issuance_not_confirmed')
        self.assertEqual(len(self.services.calls), count)

    def test_terms_changed_and_invalid_phone_stop_without_reserving(self):
        self.setup_identity()
        profile = json.dumps({'name': '합성 이름', 'birth7': '9001011', 'phone': '01000000000', 'carrier': '4'})
        bad = self.stage('profile', phone_profile=profile, agreement='unreviewed')
        self.assertEqual(bad['local']['stopped'], 'phone_consent_not_given')
        self.assertEqual(self.services.calls, [])
        self.assertFalse(bad['attempt'].get('sent'))
        good = self.stage('profile', phone_profile=profile, agreement=certificates.terms_digest(signup.sms_terms('4')))
        self.assertEqual(good['outcome'], 'success')
        self.assertIsNone(good['service_verdict'])

    def test_issued_certificate_survives_registration_failure(self):
        self.before_issue()
        self.services.override[fixture.pin.RA_BASE_PATH + '/registerCertificate'] = OSError('SYNTHETIC-PRIVATE-exception')
        stopped = self.stage('issue', new_pin=fixture.PIN, new_pin_confirmation=fixture.PIN, issue_confirmation='발급')
        self.assertEqual(stopped['outcome'], 'partial_success', stopped)
        self.assertTrue(stopped['result']['certificate_issued'])
        self.assertIsNone(stopped['result'].get('next_stage'))
        self.assert_private(stopped, 'SYNTHETIC-PRIVATE-exception')
        count = len(self.services.calls)
        self.stage('issue', new_pin=fixture.PIN, new_pin_confirmation=fixture.PIN, issue_confirmation='발급')
        self.assertEqual(len(self.services.calls), count)

    def test_success_followed_by_observation_failure_keeps_verdict(self):
        self.before_issue()
        with patch.object(certificates, 'progress', side_effect=OSError('SYNTHETIC-secret')):
            job = self.stage('issue', new_pin=fixture.PIN, new_pin_confirmation=fixture.PIN, issue_confirmation='발급')
        self.assertEqual(job['outcome'], 'success', job)
        self.assertTrue(job['result']['certificate_issued'])
        self.assertTrue(job['service_verdict']['accepted'])
        self.assertEqual(job['local']['stopped'], 'local_processing_error')

    def test_secret_sizes_are_per_field_and_not_available_to_other_jobs(self):
        with patch('finance_cli.server.app.start_with_secrets', return_value='started') as start:
            result = self.post('/jobs', {'name': 'cert.joint.import', 'input': {'name': 'file', 'format': 'pfx'},
                'secrets': {'certificate_password': 'x', 'certificate_file': 'A' * 300000, 'private_key_file': 'unused'}})
            self.assertEqual(result.status_code, 202, result.text)
            self.assertNotIn('A' * 1000, result.text)
            bad = self.post('/jobs', {'name': 'cert.joint.import', 'input': {'name': 'file2', 'format': 'pfx'},
                'secrets': {'certificate_password': 'x' * 1025, 'certificate_file': 'AAAA', 'private_key_file': 'unused'}})
            self.assertEqual(bad.json()['error'], 'step_secrets_required')
            other = self.post('/jobs', {'name': 'giro.readiness', 'input': {'large': 'A' * 300000}})
            self.assertEqual(other.status_code, 413)
            self.assertEqual(start.call_count, 1)
        too_large = self.client.post('/api/v1/jobs', content=b'x' * (12 * 1024 * 1024 + 256 * 1024 + 1), headers=self.headers())
        self.assertEqual(too_large.status_code, 413)
