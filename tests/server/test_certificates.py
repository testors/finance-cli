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
from finance_cli.credentials.id_cards import IdCards
from finance_cli.credentials.joint import crypto
from finance_cli.credentials.registry import Registry
from finance_cli.server import jobs, worker
from finance_cli.server.adapters import certificates
from finance_cli.server.adapters.base import Stop
from finance_cli.services.hana import hana_protocol, onesign, onesign_setup, onesign_signup_protocol as signup
from finance_cli.services.hana.onesign_state import State


def synthetic_jpeg(width=512, height=256, orientation=1):
    image = Image.new('RGB', (width, height), 'white')
    metadata = Image.Exif()
    metadata[274] = orientation
    metadata[270] = 'SYNTHETIC-PRIVATE-METADATA'
    output = io.BytesIO()
    image.save(output, format='JPEG', exif=metadata, comment=b'SYNTHETIC-PRIVATE-COMMENT')
    return output.getvalue()


CARD_PASSPHRASE = 'SYNTHETIC-card-passphrase'
CARD_FIELDS = {'name': '합성 이름', 'issueDate': '2020.02.29', 'birthDate': '900101', 'resident': '1000000'}
DRIVER_FIELDS = {'regionCode': '11', 'driver1': '20', 'driver2': '123456', 'driver3': '78'}


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

    def stage(self, stage, extra=None, **secrets):
        return self.run_job('hana.onesign.issue.' + stage, {'name': 'synthetic', **(extra or {}), **({'send': True} if
                            certificates.OneSignIssuance(stage).remote else {})},
                            {'vault_passphrase': fixture.PASSWORD, **secrets})

    def save_card(self, alias='resident-card', kind='resident'):
        fields = dict(CARD_FIELDS, **(DRIVER_FIELDS if kind == 'driver' else {}))
        return IdCards().add(alias, kind, fields, synthetic_jpeg(1600, 1000), CARD_PASSPHRASE)

    def begin_identity(self):
        self.setup_identity()
        profile = {'name': '합성 이름', 'birth7': '9001011', 'phone': '01000000000', 'carrier': '4'}
        self.assertEqual(self.stage('profile', phone_profile=json.dumps(profile),
            agreement=certificates.terms_digest(signup.sms_terms('4')))['outcome'], 'success')
        for stage in ('authenticate', 'request-sms'):
            self.assertEqual(self.stage(stage)['outcome'], 'success')
        verified = self.stage('verify-sms', sms='012345')
        self.assertEqual(self.stage('consent', agreement=verified['result']['terms_digest'])['outcome'], 'success')
        self.assertEqual(self.stage('begin-id')['outcome'], 'success')

    def saved_choice(self, passphrase=CARD_PASSPHRASE, confirmation='본인 신분증'):
        return json.dumps({'passphrase': passphrase, 'confirmation': confirmation})

    def before_issue(self, kind='resident', jpeg=None, *, stop_at_account=False):
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
        if stop_at_account:
            return prepared
        self.assertEqual(self.stage('list-accounts')['outcome'], 'success')
        self.assertEqual(self.stage('account', account_choice='0', account_password='6049')['outcome'], 'success')
        return prepared

    def test_select_full_bank_account_from_sealed_list_without_requery_or_unrelated_fields(self):
        self.before_issue(stop_at_account=True)
        from finance_cli.services.hana import onesign_issue_protocol as protocol
        other = '98765432101234'
        self.services.override[protocol.PATHS['signup-accounts']] = {
            'expLginAllAcctInq': [{'acctNo': fixture.SOURCE, 'custNm': 'SYNTHETIC-PRIVATE'},
                                {'acctNo': other, 'token': 'SYNTHETIC-PRIVATE'}]}
        before = len(self.services.calls)
        listed = self.stage('list-accounts')
        self.assertEqual(listed['outcome'], 'success', listed)
        self.assertEqual(listed['result']['next_stage'], 'account')
        self.assertEqual(len(listed['result']['accounts']), 2)
        self.assertEqual(listed['result']['accounts'], [
            {'choice': '0', 'label': '하나은행 ' + fixture.SOURCE},
            {'choice': '1', 'label': '하나은행 ' + other}])
        self.assert_private(listed, 'SYNTHETIC-PRIVATE')
        for number in (fixture.SOURCE, other):
            self.assertNotIn(number, json.dumps(listed['events']))
        count = len(self.services.calls)
        self.assertEqual(count, before + 1)
        inspected = self.stage('inspect')
        self.assertEqual(inspected['result']['accounts'], listed['result']['accounts'])
        self.assertEqual(len(self.services.calls), count)
        for choice in ('-1', '2', fixture.SOURCE):
            bad = self.stage('account', account_choice=choice, account_password='6049')
            self.assertEqual(bad['local']['stopped'], 'issuance_account_selection_invalid')
            self.assertFalse(bad['attempt'].get('sent'))
        self.assertEqual(len(self.services.calls), count)
        good = self.stage('account', account_choice='1', account_password='6049')
        self.assertEqual(good['outcome'], 'success', good)
        sent = self.services.calls[count:]
        self.assertEqual([call[1] for call in sent], [protocol.PATHS['keypad'], protocol.PATHS['signup-account']])
        self.assertEqual(json.loads(sent[-1][3])['acctNo'], other)
        self.assert_private(good, '6049')
        repeat = self.stage('account', account_choice='1', account_password='6049')
        self.assertEqual(repeat['outcome'], 'not_started')
        self.assertEqual(len(self.services.calls), count + 2)

    def test_empty_bank_list_stays_accepted_and_cannot_send_account_password(self):
        self.before_issue(stop_at_account=True)
        from finance_cli.services.hana import onesign_issue_protocol as protocol
        self.services.override[protocol.PATHS['signup-accounts']] = {'expLginAllAcctInq': []}
        listed = self.stage('list-accounts')
        self.assertEqual((listed['outcome'], listed['result']['accepted'], listed['result']['accounts']), ('success', True, []))
        count = len(self.services.calls)
        refused = self.stage('account', account_choice='0', account_password='6049')
        self.assertEqual(refused['outcome'], 'not_started')
        self.assertEqual(self.stage('list-accounts')['outcome'], 'not_started')
        self.assertEqual(len(self.services.calls), count)

    def test_legacy_account_mismatch_diagnostic_does_not_clear_halt_or_send(self):
        self.before_issue(stop_at_account=True)
        with State('synthetic', fixture.PASSWORD) as state:
            result = onesign.operate(state, 'account', 'old-direct-account', send=True,
                inputs={'account': lambda rows: '99999999999999',
                        'account_password': lambda *a: self.fail('password must not be requested')})
            self.assertEqual(result['error'], 'issuance_account_not_in_response')
            self.assertEqual((result['accepted'], result['service_status'], result['processing_status']),
                             (True, 'accepted', 'stopped'))
        before = (self.home / 'hana/identities/synthetic/state.json').read_bytes()
        count = len(self.services.calls)
        job = self.stage('inspect')
        self.assertEqual(job['result']['account_diagnostic'], {'network_used': False, 'account_count': 1,
            'password_verification_requested': False, 'selection_not_found': True})
        self.assertIsNone(job['result']['next_stage'])
        self.assertEqual(len(self.services.calls), count)
        self.assertEqual((self.home / 'hana/identities/synthetic/state.json').read_bytes(), before)
        self.assert_private(job, '99999999999999')
        self.assertNotIn(fixture.SOURCE, json.dumps(job['result']['account_diagnostic']))

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

    def test_inspect_identity_receipts_without_sending_or_exposing_private_fields(self):
        self.setup_identity()
        private = 'SYNTHETIC-PRIVATE-NAME-AND-TOKEN'
        with State('synthetic', fixture.PASSWORD) as state:
            state.begin_run('synthetic-attempt', 'identity')
            state.record('synthetic-attempt', 'http-0001-response', {'status': 200,
                'service_status': 'accepted', 'headers': [],
                'body': base64.b64encode(json.dumps({'scss': True, 'name': private}).encode()).decode()})
            state.record('synthetic-attempt', 'http-0002-response', {'status': 200,
                'service_status': 'rejected', 'headers': [
                    ('set-cookie', private),
                    ('hana-sys-header', hana_protocol.encode_header({'CHNL_SYS_HDPT': {
                        'PROC_RSLT_DV_CD': '1', 'STD_TMSG_ERR_CD': 'TEST123', 'TMSG_GLOB_ID': private}})),
                    ('hana-com-header', hana_protocol.encode_header({'STD_MSGPT': [{
                        'OGN_ERR_CD': 'TEST456', 'MSG_INFO_REPT': [{'MSG_CTT': private + ' 이용시간 08:00 ~ 22:00'}]}]}))],
                'body': base64.b64encode(json.dumps({'private': private}).encode()).decode()})
        before = (self.home / 'hana/identities/synthetic/state.json').read_bytes()
        calls = len(self.services.calls)
        job = self.stage('inspect')
        diagnostic = job['result']['identity_diagnostic']
        self.assertEqual(job['outcome'], 'success')
        self.assertFalse(diagnostic['network_used'])
        self.assertEqual(diagnostic['requests'], [
            {'stage': 'image', 'http_status': 200, 'service_status': 'accepted', 'error_codes': [],
             'image_accepted': True, 'information_mismatch_reported': False},
            {'stage': 'identity', 'http_status': 200, 'service_status': 'rejected',
             'processing_code': '1', 'standard_error_code': 'TEST123', 'error_codes': ['TEST456'],
             'message_hints': ['service_hours'], 'service_times': ['08:00', '22:00'],
             'information_mismatch_reported': False}])
        self.assertEqual(len(self.services.calls), calls)
        self.assertEqual((self.home / 'hana/identities/synthetic/state.json').read_bytes(), before)
        self.assert_private(job, private)

    def test_inspect_missing_or_damaged_identity_receipts_preserves_inspection(self):
        self.setup_identity()
        with State('synthetic', fixture.PASSWORD) as state:
            state.begin_run('synthetic-attempt', 'identity')
            state.record('synthetic-attempt', 'http-0001-response', {'status': 200,
                'headers': [('hana-sys-header', 'not-valid-base64')]})
        job = self.stage('inspect')
        self.assertEqual(job['outcome'], 'success')
        self.assertEqual(job['result']['identity_diagnostic']['requests'], [
            {'stage': 'image', 'receipt': 'unreadable'}, {'stage': 'identity', 'receipt': 'not_available'}])

    def test_identity_rejection_keeps_name_mismatch_evidence_and_never_retries(self):
        self.begin_identity()
        fields = dict(CARD_FIELDS, name='운전면허증')
        capture = {'kind': 'resident', 'fields': fields, 'image': base64.b64encode(synthetic_jpeg()).decode(),
                   'confirmation': '본인 신분증'}
        self.assertEqual(self.stage('prepare-id', identity_capture=json.dumps(capture))['outcome'], 'success')
        from finance_cli.services.hana import onesign_issue_protocol as protocol
        original = self.services.bank
        def bank(path, body):
            return {'rspsCd': '901', 'rspsMsg': 'SYNTHETIC-PRIVATE'} if path == protocol.PATHS['identity'] else original(path, body)
        with patch.object(self.services, 'bank', side_effect=bank):
            job = self.stage('identity')
        self.assertEqual(job['outcome'], 'rejected')
        self.assertEqual(job['local']['stopped'], 'identity_verification_failed')
        self.assertEqual(job['result']['identity_diagnostic']['input_checks'], {
            'name_matches_phone': False, 'name_is_document_label': True, 'birth_matches_phone': True,
            'resident_prefix_matches_phone': True, 'resident_tail_seven_digits': True, 'request_matches_capture': True})
        count = len(self.services.calls)
        inspected = self.stage('inspect')
        self.assertEqual(inspected['result']['identity_diagnostic'], job['result']['identity_diagnostic'])
        self.assertEqual(len(self.services.calls), count)
        self.assert_private(inspected, 'SYNTHETIC-PRIVATE', CARD_FIELDS['name'], CARD_FIELDS['resident'])

    def test_identity_diagnostic_failure_preserves_bank_rejection(self):
        self.begin_identity()
        capture = {'kind': 'resident', 'fields': CARD_FIELDS, 'image': base64.b64encode(synthetic_jpeg()).decode(),
                   'confirmation': '본인 신분증'}
        self.stage('prepare-id', identity_capture=json.dumps(capture))
        from finance_cli.services.hana import onesign_issue_protocol as protocol
        original = self.services.bank
        def bank(path, body):
            return {'rspsCd': '901'} if path == protocol.PATHS['identity'] else original(path, body)
        with patch.object(self.services, 'bank', side_effect=bank), \
                patch.object(certificates, 'identity_diagnostics', side_effect=OSError('SYNTHETIC-PRIVATE')):
            job = self.stage('identity')
        self.assertEqual(job['outcome'], 'rejected')
        self.assertEqual(job['local']['stopped'], 'identity_verification_failed')
        self.assertTrue(job['result']['diagnostic_unavailable'])

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
            ('account', {'account_choice': '0', 'account_password': '6049'}),
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
                self.assert_private(accepted.json(), fixture.PASSWORD, *[v for k, v in private.items() if k not in ('issue_confirmation', 'account_choice')])
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
        self.assert_private(finished, fixture.PASSWORD, fixture.PIN, '01000000000', '1000000', 'SYNTHETIC-ACCESS')

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
                        SimpleNamespace(secrets={'identity_capture': json.dumps(capture)}, input={}), {})
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

    def test_saved_card_is_stored_from_the_worker_pipe_only(self):
        raw = synthetic_jpeg(2400, 1500)
        capture = {'kind': 'driver', 'fields': dict(CARD_FIELDS, **DRIVER_FIELDS),
                   'image': base64.b64encode(raw).decode(), 'confirmation': '본인 신분증'}
        job = self.run_job('idcard.add', {'name': 'driver-card'},
                           {'idcard_passphrase': CARD_PASSPHRASE, 'identity_capture': json.dumps(capture)})
        self.assertEqual((job['outcome'], job['result']), ('success', {'name': 'driver-card', 'kind': 'driver',
                                                                       'saved': True, 'network_used': False}), job)
        self.assertIsNone(job['service_verdict'])
        self.assert_private(job, CARD_PASSPHRASE, '합성 이름', '1000000', '900101', '123456', capture['image'])
        listed = self.get('/id-cards').json()
        self.assertEqual([{k: v for k, v in row.items() if k != 'saved_at'} for row in listed['id_cards']],
                         [{'name': 'driver-card', 'kind': 'driver', 'issue_date': '2020.02.29'}])
        self.assertNotIn('합성 이름', json.dumps(listed, ensure_ascii=False))
        card = IdCards().load('driver-card', CARD_PASSPHRASE)
        self.assertEqual(onesign.jpeg_size(card['jpeg']), (1024, 640))
        self.assertNotIn(b'SYNTHETIC-PRIVATE', card['jpeg'])
        duplicate = self.run_job('idcard.add', {'name': 'driver-card'},
                                 {'idcard_passphrase': 'SYNTHETIC-other', 'identity_capture': json.dumps(capture)})
        self.assertEqual((duplicate['outcome'], duplicate['local']['stopped']), ('not_started', 'id_card_name_exists'))
        short = self.run_job('idcard.add', {'name': 'other'}, {'idcard_passphrase': 'abc', 'identity_capture': json.dumps(capture)})
        self.assertEqual(short['local']['stopped'], 'passphrase_minimum_4_characters')
        unconfirmed = self.run_job('idcard.add', {'name': 'other'}, {'idcard_passphrase': CARD_PASSPHRASE,
                                   'identity_capture': json.dumps({**capture, 'confirmation': ''})})
        self.assertEqual(unconfirmed['local']['stopped'], 'identity_not_confirmed')
        self.assertEqual([row['name'] for row in IdCards().list()], ['driver-card'])

    def test_issuance_selects_saved_card_and_only_the_choice_is_recorded(self):
        self.save_card('driver-card', 'driver')
        self.begin_identity()
        count = len(self.services.calls)
        with patch.object(onesign, 'prepare_identity', wraps=onesign.prepare_identity) as prepare:
            prepared = self.stage('prepare-id', {'id_card': 'driver-card'}, identity_capture=self.saved_choice())
        self.assertEqual(prepared['outcome'], 'success', prepared)
        self.assertEqual(prepared['result']['next_stage'], 'identity')
        self.assertEqual(len(self.services.calls), count)
        kind, jpeg, fields = prepare.call_args.args[1:]
        self.assertEqual((kind, fields), ('driver', dict(CARD_FIELDS, **DRIVER_FIELDS)))
        self.assertEqual(onesign.jpeg_size(jpeg), (1024, 640))
        self.assertEqual(prepared['input'].get('id_card'), 'driver-card')
        self.assert_private(prepared, CARD_PASSPHRASE, '합성 이름', '1000000', '123456')
        self.assertEqual(self.stage('identity')['outcome'], 'success')
        self.assertEqual(self.stage('list-accounts')['outcome'], 'success')
        self.assertEqual(self.stage('account', account_choice='0', account_password='6049')['outcome'], 'success')
        self.assertEqual(IdCards().load('driver-card', CARD_PASSPHRASE)['kind'], 'driver')  # Still available.

    def test_saved_card_problems_stop_before_the_bank_and_can_be_corrected(self):
        self.save_card()
        self.begin_identity()
        count = len(self.services.calls)
        for extra, choice, code in (({'id_card': 'resident-card'}, self.saved_choice('SYNTHETIC-other'),
                                     'incorrect_passphrase_or_damaged_id_card'),
                                    ({'id_card': 'resident-card'}, self.saved_choice(confirmation=''), 'identity_not_confirmed'),
                                    ({'id_card': 'missing'}, self.saved_choice(), 'id_card_not_found'),
                                    ({'id_card': 'resident-card'}, json.dumps({'passphrase': CARD_PASSPHRASE}),
                                     'invalid_identity_capture')):
            with self.subTest(code=code):
                stopped = self.stage('prepare-id', extra, identity_capture=choice)
                self.assertEqual((stopped['outcome'], stopped['local']['stopped']), ('not_started', code), stopped)
                self.assertFalse(stopped['attempt'].get('sent'))
                self.assert_private(stopped, CARD_PASSPHRASE, 'SYNTHETIC-other')
        self.assertEqual(len(self.services.calls), count)
        prepared = self.stage('prepare-id', {'id_card': 'resident-card'}, identity_capture=self.saved_choice())
        self.assertEqual(prepared['outcome'], 'success', prepared)

    def test_card_choice_is_accepted_only_by_identity_preparation(self):
        with patch('finance_cli.server.app.start_with_secrets', return_value='started') as start:
            store = {'vault_passphrase': fixture.PASSWORD}
            for name, value, private, code in (
                    ('hana.onesign.issue.identity', {'name': 'synthetic', 'send': True, 'id_card': 'card'}, store,
                     'input_fields_not_accepted'),
                    ('hana.onesign.issue.prepare-id', {'name': 'synthetic', 'id_card': '../card'},
                     {**store, 'identity_capture': 'x'}, 'invalid_name'),
                    ('idcard.add', {'name': 'card', 'kind': 'driver'}, {'idcard_passphrase': 'x', 'identity_capture': 'x'},
                     'input_fields_not_accepted')):
                with self.subTest(name=name):
                    refused = self.post('/jobs', {'name': name, 'input': value, 'secrets': private})
                    self.assertEqual((refused.status_code, refused.json()['error']), (400, code))
            start.assert_not_called()
        self.assertEqual(self.get('/jobs').json()['jobs'], [])

    def test_saved_card_rename_and_remove_need_no_passphrase(self):
        self.save_card()
        self.save_card('other')
        renamed = self.post('/id-cards/resident-card/rename', {'new_name': 'card-2020'})
        self.assertEqual(renamed.json(), {'renamed': True, 'ref': 'card-2020', 'previous_ref': 'resident-card',
                                          'network_used': False})
        self.assertEqual(IdCards().load('card-2020', CARD_PASSPHRASE)['fields'], CARD_FIELDS)
        taken = self.post('/id-cards/card-2020/rename', {'new_name': 'other'})
        self.assertEqual((taken.status_code, taken.json()['error']), (409, 'id_card_name_exists'))
        bad = self.post('/id-cards/card-2020/rename', {'new_name': '../x'})
        self.assertEqual((bad.status_code, bad.json()['error']), (400, 'invalid_name'))
        mismatch = self.post('/id-cards/card-2020/remove', {'confirm': 'other'})
        self.assertEqual((mismatch.status_code, mismatch.json()['error']), (400, 'removal_confirmation_mismatch'))
        removed = self.post('/id-cards/card-2020/remove', {'confirm': 'card-2020'})
        self.assertEqual(removed.json(), {'removed': True, 'ref': 'card-2020', 'blob_removed': True, 'network_used': False})
        self.assertEqual([row['name'] for row in self.get('/id-cards').json()['id_cards']], ['other'])
        missing = self.post('/id-cards/card-2020/remove', {'confirm': 'card-2020'})
        self.assertEqual((missing.status_code, missing.json()['error']), (404, 'id_card_not_found'))
        extra = self.post('/id-cards/other/remove', {'confirm': 'other', 'passphrase': CARD_PASSPHRASE})
        self.assertEqual((extra.status_code, extra.json()['error']), (400, 'input_fields_not_accepted'))
        self.client.cookies.clear()
        self.assertEqual(self.get('/id-cards').status_code, 401)
