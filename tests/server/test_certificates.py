"""Synthetic certificate onboarding through the web job contract. No institution connections."""
import base64
import copy
import functools
import io
import json
import sys
from types import SimpleNamespace
from unittest.mock import patch

from support import ROOT, ServerCase
sys.path.insert(0, str(ROOT / 'tests'))
import test_hana_onesign as fixture
from test_certificate import synthetic_material

from Crypto.PublicKey import ECC
from PIL import Image
from cryptography.hazmat.primitives.serialization import pkcs12, load_der_private_key, BestAvailableEncryption
from cryptography import x509
from finance_cli.core import storage
from finance_cli.credentials.joint import crypto
from finance_cli.credentials.registry import Registry
from finance_cli.server import jobs, worker
from finance_cli.server.adapters import certificates
from finance_cli.server.adapters.base import Stop
from finance_cli.services.hana import onesign, onesign_setup, onesign_signup_protocol as signup
from finance_cli.services.hana.onesign_state import State


def synthetic_jpeg(width=512, height=256, orientation=1):
    image = Image.new('RGB', (width, height), 'white')
    metadata = Image.Exif()
    metadata[274] = orientation
    metadata[270] = 'SYNTHETIC-PRIVATE-METADATA'
    output = io.BytesIO()
    image.save(output, format='JPEG', exif=metadata, comment=b'SYNTHETIC-PRIVATE-COMMENT')
    return output.getvalue()


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

    def before_issue(self, kind='resident', jpeg=None):
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
        jpeg = jpeg if jpeg is not None else synthetic_jpeg()
        capture = {'kind': kind, 'fields': {'name': '합성 이름', 'issueDate': '2020.02.29',
                    'birthDate': '900101', 'resident': '1000000'},
                   'image': base64.b64encode(jpeg).decode(), 'confirmation': '본인 신분증'}
        if kind == 'driver':
            capture['fields'].update(regionCode='11', driver1='20', driver2='123456', driver3='78')
        count = len(self.services.calls)
        prepared = self.stage('prepare-id', identity_capture=json.dumps(capture))
        self.assertEqual(prepared['outcome'], 'success', prepared)
        self.assertEqual(len(self.services.calls), count)
        self.assertEqual(self.stage('identity')['outcome'], 'success')
        self.assertEqual(self.stage('account', account_number=fixture.SOURCE, account_password='6049')['outcome'], 'success')
        return prepared

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
                patch.object(self.app.state.vaults, 'get', side_effect=AssertionError('must not access secrets')), \
                patch('finance_cli.server.app.start_with_secrets') as start:
            refused = self.post('/jobs', {'name': 'hana.onesign.issue.authenticate', 'input': {'name': 'missing'},
                                          'secrets': {'vault_passphrase': fixture.PASSWORD}})
        self.assertEqual(refused.json()['error'], 'send_approval_required')
        start.assert_not_called()
        self.assertEqual(self.get('/jobs').json()['jobs'], [])

    def test_issuance_uses_unlocked_store_without_login_or_browser_passphrase(self):
        self.setup_identity()
        self.assertEqual(self.post('/vaults/synthetic/unlock', {'passphrase': fixture.PASSWORD}).status_code, 200)
        with patch('finance_cli.server.app.start_with_secrets', return_value='started') as start:
            response = self.post('/jobs', {'name': 'hana.onesign.issue.inspect', 'input': {'name': 'synthetic'}})
        self.assertEqual(response.status_code, 202, response.text)
        private = start.call_args.args[2]
        self.assertEqual(private, {'vault_passphrase': fixture.PASSWORD})
        with self.db.read() as con:
            row = jobs.get(con, response.json()['id'])
        completed = self.run_row(row, private)
        self.assertEqual(completed['outcome'], 'success')
        self.assert_private(completed, fixture.PASSWORD)
        self.assertEqual(self.get('/logins').json()['logins'], [])
        self.assertEqual(self.services.calls, [])

    def test_remembered_passphrase_does_not_replace_other_issuance_secrets(self):
        self.setup_identity()
        self.post('/vaults/synthetic/unlock', {'passphrase': fixture.PASSWORD})
        for stage, private in (
            ('verify-sms', {'sms': '012345'}),
            ('account', {'account_number': fixture.SOURCE, 'account_password': '6049'}),
            ('issue', {'new_pin': fixture.PIN, 'new_pin_confirmation': fixture.PIN, 'issue_confirmation': '발급'}),
        ):
            with self.subTest(stage=stage), patch('finance_cli.server.app.start_with_secrets', return_value='started') as start:
                request = {'name': 'hana.onesign.issue.' + stage, 'input': {'name': 'synthetic', 'send': True}}
                missing = self.post('/jobs', request)
                self.assertEqual(missing.json()['error'], 'step_secrets_required')
                start.assert_not_called()
                accepted = self.post('/jobs', {**request, 'secrets': private})
                self.assertEqual(accepted.status_code, 202, accepted.text)
                self.assertEqual(start.call_args.args[2], {'vault_passphrase': fixture.PASSWORD, **private})
                self.assert_private(accepted.json(), fixture.PASSWORD, *[v for k, v in private.items() if k != 'issue_confirmation'])
        self.assertEqual(self.services.calls, [])

    def test_cached_passphrase_is_scoped_to_existing_store_and_cleared_by_lock(self):
        self.setup_identity()
        self.post('/vaults/synthetic/unlock', {'passphrase': fixture.PASSWORD})
        with patch('finance_cli.server.app.start_with_secrets', return_value='started') as start:
            for stage, data in (('inspect', {'name': 'other'}), ('init', {'name': 'synthetic', 'settings': 'synthetic'})):
                refused = self.post('/jobs', {'name': 'hana.onesign.issue.' + stage, 'input': data})
                self.assertEqual(refused.json()['error'], 'step_secrets_required')
            self.post('/vaults/synthetic/lock')
            refused = self.post('/jobs', {'name': 'hana.onesign.issue.inspect', 'input': {'name': 'synthetic'}})
            self.assertEqual(refused.json()['error'], 'step_secrets_required')
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

    def test_web_driver_photo_is_prepared_locally_at_service_dimensions(self):
        raw = synthetic_jpeg(2400, 1500)
        with patch.object(onesign, 'prepare_identity', wraps=onesign.prepare_identity) as prepare:
            job = self.before_issue('driver', raw)
        self.assertEqual(onesign.jpeg_size(prepare.call_args.args[2]), (1024, 640))
        self.assertEqual(job['result']['next_stage'], 'identity')
        self.assertFalse(job['result']['network_used'])
        self.assertFalse(job['attempt'].get('sent'))
        self.assertIsNone(job['service_verdict'])
        self.assert_private(job, base64.b64encode(raw).decode(), fixture.PASSWORD, 'SYNTHETIC-PRIVATE-METADATA')

    def test_photo_orientation_aspect_ratio_and_metadata_removal(self):
        for width, height, orientation, expected in ((2400, 1500, 1, (1024, 640)),
                (800, 2000, 6, (1024, 410)), (600, 400, 1, (600, 400))):
            with self.subTest(orientation=orientation, dimensions=(width, height)):
                raw = synthetic_jpeg(width, height, orientation)
                prepared = certificates.identity_jpeg(base64.b64encode(raw).decode())
                self.assertEqual(onesign.jpeg_size(prepared), expected)
                with Image.open(io.BytesIO(prepared)) as photo:
                    photo.load()
                    self.assertEqual(photo.format, 'JPEG')
                    self.assertEqual(dict(photo.getexif()), {})
                    self.assertNotIn('comment', photo.info)
                self.assertNotIn(b'SYNTHETIC-PRIVATE', prepared)

    def test_identity_input_errors_keep_specific_safe_reasons(self):
        valid = {'kind': 'driver', 'fields': {'name': '합성 이름', 'issueDate': '2020.02.29',
                 'birthDate': '900101', 'resident': '1000000', 'regionCode': '11',
                 'driver1': '20', 'driver2': '123456', 'driver3': '78'},
                 'image': base64.b64encode(synthetic_jpeg()).decode(), 'confirmation': '본인 신분증'}
        cases = [('image', 'not-base64', 'identity_jpeg_invalid'),
                 ('image', base64.b64encode(b'\x89PNG\r\n\x1a\nSYNTHETIC').decode(), 'identity_jpeg_required'),
                 ('image', base64.b64encode(b'\xff\xd8SYNTHETIC-broken').decode(), 'identity_jpeg_invalid'),
                 ('issueDate', '20200229', 'identity_date_format'),
                 ('driver2', '12345', 'driver_number_format'),
                 ('resident', '100000', 'resident_number_format'),
                 ('confirmation', 'no', 'identity_not_confirmed')]
        for field, value, code in cases:
            with self.subTest(code=code):
                capture = copy.deepcopy(valid)
                (capture['fields'] if field in capture['fields'] else capture)[field] = value
                with self.assertRaises(Stop) as stopped:
                    certificates.OneSignIssuance('prepare-id').inputs(
                        SimpleNamespace(secrets={'identity_capture': json.dumps(capture)}), {})
                self.assertEqual(stopped.exception.code, code)
        with patch.object(Image, 'MAX_IMAGE_PIXELS', 100), self.assertRaises(Stop) as stopped:
            certificates.identity_jpeg(valid['image'])
        self.assertEqual(stopped.exception.code, 'identity_image_dimensions_too_large')

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
