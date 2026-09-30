"""New issuance orchestration with injected bank/CA/RA and durable attempts.

Supported entry: domestic adult existing banking customer (regTyp A), SMS,
mandatory signup terms, genuine resident/driver ID, own Hana account, no cloud
upload. The management/reissue and exceptional customer screens are mapped in
the documentation, not silently substituted into this entry.
"""
from datetime import datetime
import hashlib
import re
import secrets
from zoneinfo import ZoneInfo

from Crypto.PublicKey import ECC

from types import SimpleNamespace
from .onesign_compat import truthy
from .onesign_codec import encode
from .onesign_workflow import Workflow
from . import onesign_issue_protocol as protocol
from . import onesign_cmp as cmp
from . import onesign_signup_protocol as signup
from .onesign_signup import consent_digest

from .onesign_crypto import ProtocolError, require, text, derive_pin, b64url, certificate_parts, LOGIN_PATH


class Issuance:
    EXPECTED = {'begin-id': 'new', 'identity': 'id_ready', 'list-accounts': 'identity_verified', 'account': 'identity_verified',
                'issue': 'account_verified', 'complete': 'issued'}
    NEXT = dict(zip(EXPECTED, ('id_ready', 'identity_verified', 'accounts_listed', 'account_verified', 'issued', 'ready')))

    def __init__(self, vault, bank, image, ca, ra, clock, *, ledger_vault=None, encrypt_password=None):
        self.vault, self.bank, self.image, self.ca, self.ra, self.clock = vault, bank, image, ca, ra, clock
        self.encrypt_password = encrypt_password
        self.certificate_issued = False
        self.observed_certificate = None
        self.device = vault.snapshot()['profile']['device_id']
        self.flow = Workflow(vault, self.device, None, bank, ra, clock, ledger_vault=ledger_vault)

    def state(self):
        return self.vault.snapshot()['issuance']

    def change(self, **fields):
        with self.vault.transaction() as value:
            value['issuance'].update(fields)

    def call(self, operation, body):
        name = 'issue-completion-login' if operation == LOGIN_PATH else 'issue-' + operation
        path = protocol.PATHS.get(operation, signup.WEB_PATHS.get(operation, operation))
        if operation == 'instant-number':
            ledger = self.flow.ledger
            ledger.begin(name, -3, path)
            ledger.prepared(name, hashlib.sha256(encode(body)).hexdigest())
            try:
                result = self.bank(path, body)
                ledger.accept(name, hashlib.sha256(encode(result)).hexdigest())
            except Exception as exc:
                ledger.handled(name, str(exc) if type(exc) is ProtocolError else 'source_handled_lookup_error')
                result = {}
        else:
            result = self.flow.exchange(name, -3, self.bank, path, body)
        with self.vault.transaction() as value:
            value['issuance']['responses'][operation] = result
        return result

    def binary(self, operation, path, body, adapter):
        ledger = self.flow.ledger
        ledger.begin(operation, -4, path)
        try:
            ledger.prepared(operation, hashlib.sha256(body).hexdigest())
            result = adapter(body)
            raw = result if isinstance(result, bytes) else encode(result)
            ledger.accept(operation, hashlib.sha256(raw).hexdigest())
            return result
        except BaseException as exc:
            ledger.halt(operation, str(exc) if type(exc) is ProtocolError else 'issuance_exchange_interrupted')
            raise

    def check(self, command):
        s = self.state()
        expected = command in self.EXPECTED and (s['state'] == self.EXPECTED[command]
                   or command == 'account' and s['state'] == 'accounts_listed')
        require(expected and not s.get('pending'), 'issuance_stage_out_of_order')
        entry = self.vault.snapshot()['signup']
        require(entry.get('purpose') == 'issue' and entry['state'] == 'consented'
                and entry['consent_digest'] == consent_digest(entry), 'issuance_entry_or_consent_missing')
        require(not self.vault.snapshot()['halted'], 'workflow_halted')

    def execute(self, command, *, ocr=None, kind=None, account_input=None, password_input=None, pin_input=None, ca_certificate=None):
        self.check(command)
        if command == 'identity':
            protocol.validate_ocr(ocr, kind)  # local correction before reserving any request
        self.change(pending=command)
        try:
            s = self.state()
            if command == 'begin-id':
                entry = self.vault.snapshot()['signup']
                customer = entry['responses']['customer']
                require(customer.get('regTyp') == 'A', 'issuance_additional_customer_screen')
                require(not self.vault.snapshot()['records'], 'issuance_fresh_store_required')
                marketing = signup.marketing_body(entry['responses']['terms-status'])
                if marketing is not None:
                    self.call('terms-save', marketing)
                number = self.call('instant-number', None)
                try:
                    sequence = float(number.get('procSeq') or 0)
                except (ValueError, TypeError):
                    sequence = 0  # JS > 0 is false for undefined/NaN.
                require(not sequence > 0, 'branch_one_time_number_required')
                result = self.call('application', {})
                require(truthy(result.get('apcNo')), 'identity_application_missing')
                require(not truthy(result.get('frnr')), 'branch_foreign_identity')
                self.change(application=result['apcNo'])
            elif command == 'identity':
                content_type, body = protocol.image_upload(s['application'], ocr['encImage'], milliseconds=self.clock())
                response = self.binary('issue-image', protocol.PATHS['image'], body, lambda b: self.image(content_type, b))
                protocol.accept_image(response)
                metadata = protocol.id_body(s['application'], kind, ocr)
                protocol.accept_identity(self.call('identity', metadata), metadata)
                self.change(identity_kind=kind)
            elif command == 'list-accounts':
                self.call('signup-accounts', {'oneSignUseYn': ''})
            elif command == 'account':
                result = s['responses']['signup-accounts'] if s['state'] == 'accounts_listed' else self.call('signup-accounts', {'oneSignUseYn': ''})
                rows = result.get('expLginAllAcctInq')
                require(isinstance(rows, list) and bool(rows), 'issuance_account_list_missing')
                account = account_input(rows)
                require(any(row.get('acctNo') == account for row in rows), 'issuance_account_not_in_response')
                public = self.call('keypad', None)['apiRlseKey']
                password = password_input(account)
                require(isinstance(password, str) and re.fullmatch('[0-9]{4}', password) is not None, 'account_password_four_digits_required')
                try:
                    encrypted = self.encrypt_password(public, password)
                finally:
                    del password
                result = self.call('signup-account', {'acctNo': account, 'acctPw': encrypted})
                require(not truthy(result.get('errCd')), 'issuance_account_verification_failed')
                self.change(account=account, keypad=public)
            elif command == 'issue':
                require(not self.vault.snapshot()['records'], 'issuance_fresh_store_required')
                local = datetime.fromtimestamp(self.clock() / 1000, ZoneInfo('Asia/Seoul')).strftime('%Y%m%d%H%M%S')
                result = self.call('clock', {'bussDt': '', 'tgtDt': ''})
                # Compare exactly the web thresholds, when both strings have 14 digits.
                server = (result.get('dt') or '') + (result.get('tm') or '')
                if len(server) == 14:
                    a, b = (datetime.strptime(v, '%Y%m%d%H%M%S') for v in (local, server))
                    minutes = (a - b).total_seconds() / 60
                    require(abs(minutes) < 5 and minutes < 1, 'issuance_device_clock_mismatch')
                first, confirmation = pin_input()
                protocol.check_new_pin(first)
                protocol.check_new_pin(confirmation)
                require(first == confirmation, 'new_pin_confirmation_mismatch')
                try:
                    body = protocol.pin_check_body(self.encrypt_password(s['keypad'], first), self.encrypt_password(s['keypad'], confirmation))
                    result = self.call('pin-check', body)
                    require(result.get('scss') is True, 'issuance_pin_policy_failed')
                    material = derive_pin(first, device_id=self.device, pin_salt='', pin_spec_version=2)
                finally:
                    del first, confirmation
                registration = self.call('registration', protocol.registration_body())
                key = ECC.generate(curve='P-256')
                # Persist only inside encrypted vault before the one CA attempt.
                # CA success followed by process loss must never trigger reissue.
                self.change(pending_key=b64url(key.export_key(format='DER', use_pkcs8=True)))
                request = cmp.issue_request(key, ca_certificate, text(registration.get('keyId')), text(registration.get('macKey')))
                reply = self.binary('issue-ca', protocol.CA_URL, request.encoded, self.ca)
                def verify_certificate():
                    def observed(certificate):
                        self.certificate_issued = True
                        self.observed_certificate = certificate
                    return cmp.issue_response(reply, request, registration['macKey'],observed=observed)
                certificate = self.flow.local_stage('issue-ca-verification', verify_certificate)
                self.change(certificate_issued=True, pending_certificate=b64url(certificate))
                response = self.flow.exchange('issue-register-certificate', -2, self.ra, '/registerCertificate',
                    protocol.register_certificate_body(certificate, registration['macKey'], material))
                secret, version = protocol.registration_secret(response)
                alias = self.flow.local_stage('issue-store', lambda: self.flow.store.import_key(
                    certificate, SimpleNamespace(key=key, r=secrets.token_bytes(32)), material, secret, version))
                info = {'subjectDer': b64url(certificate_parts(certificate)[2]), 'pinSalt': self.device, 'pinVersion': version}
                external_secret = self.flow.ra_auth('issue-external', info, material)
                self.flow.local_stage('issue-external-store', lambda: self.flow.store.register_external(alias, material, external_secret, registration['scBCertKey']))
                with self.vault.transaction() as value:
                    value['issuance'].update(alias=alias, pending_key=None, pending_certificate=None)
                    value['profile']['enrollment'] = {'state': 'pending', 'alias': alias, 'origin': 'new-issuance'}
            elif command == 'complete':
                entry = self.vault.snapshot()['signup']
                response = self.call('complete-signup', signup.complete_body(self.device))
                with self.vault.transaction() as value:
                    value['profile']['customer_number'] = response.get('custNo')
                self.call(LOGIN_PATH, signup.completion_login_body(entry['phone']))
                with self.vault.transaction() as value:
                    value['profile']['enrollment']['state'] = 'ready'
            self.change(state=self.NEXT[command], pending=None)
            return {'state': self.NEXT[command], 'certificate_issued': bool(self.state().get('certificate_issued')),
                    'cloud_uploaded': False, 'automatic_retry': False, 'resend_allowed': False,
                    'normal_signed_login_verified': False, 'transfer_enabled': False}
        except BaseException as exc:
            saved = self.state()
            fields = {'certificate_issued':self.certificate_issued or saved.get('certificate_issued',False)}
            if self.observed_certificate is not None and saved.get('pending_key'):
                fields['pending_certificate']=b64url(self.observed_certificate)
            self.change(state='halted', reason=str(exc) if type(exc) is ProtocolError else 'issuance_interrupted',**fields)
            with self.vault.transaction() as value:
                value['halted'] = True
            raise
