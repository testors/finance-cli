"""External Hana certificate authentication using an existing shared identity."""
import base64
import copy
import time
import uuid

from finance_cli.services.hana import hana_protocol, onesign as shared, onesign_compat as compat
from finance_cli.services.hana import onesign_crypto as pin, onesign_signup_protocol as signup
from finance_cli.services.hana.onesign_io import Client, send_http
from finance_cli.services.hana.onesign_workflow import Workflow
from .protocol import Stop, require

PREFIX = '/public/pcm/lgin01/capi/hanaCertsCert/'
PRE = PREFIX + 'preEasnCert'
SUBMIT = PREFIX + 'easnCertElecSign'


class External:
    def __init__(self, state, result, *, exchange=send_http):
        self.state, self.result, self.exchange = state, result, exchange
        self.alias, self.entry = shared.record(state)
        self.profile = state.snapshot()['profile']
        require(isinstance(self.profile.get('customer_number'), str) and bool(self.profile['customer_number']),
                'onesign_customer_number_required')
        self.client = None
        self.finished = False

    def start(self):
        # The bank session belongs to this corporate authentication attempt. The
        # certificate, device binding, PIN metadata and vault lock remain shared.
        run = 'corporate-' + uuid.uuid4().hex
        self.control = self.state.begin_run(run, 'corporate-external-auth')
        with self.state.transaction() as value:
            value['sessions'][run] = {'cookies': [], 'purpose': 'corporate-external-auth'}
        self.client = Client(self.state, run, run, send=True, exchange=self.exchange)
        self.client.query_paths.update((PRE, SUBMIT))
        self.flow = Workflow(self.state, self.profile['device_id'], None, None, self.client.ra,
                             lambda: int(time.time() * 1000), ledger_vault=self.control)

    def api(self, path, body):
        require(path in (PRE, SUBMIT), 'external_auth_endpoint_not_allowed')
        headers = self.client.headers()
        common = hana_protocol.decode_header(headers['hana-com-header'])
        common['CNL_HDPT']['SCRN_ID'] = 'COMB0306001401'
        headers['hana-com-header'] = hana_protocol.encode_header(common)
        headers['Content-Type'] = 'application/json;charset=utf-8'
        for key in ('access-token', 'one-access-token', 'nonce', 'uuid'):
            headers[key] = headers.get(key, '').strip()
        headers['hana-1q-env'] = 'Prod'

        def observe(raw):
            reply = compat.web_value(raw)
            if path == SUBMIT and isinstance(reply, dict):
                self.result['external_auth_status'] = 'accepted' if reply.get('rsltCd') == 'NORMAL' else 'rejected' if reply.get('rsltCd') else 'unconfirmed'
            return {}

        raw = self.client.request('bank', 'POST', path, headers, signup.web_body(body), web=True, observe=observe)
        value = compat.web_value(raw)
        require(isinstance(value, dict), 'external_auth_response_unavailable')
        return value

    def authenticate(self, transaction, pin_input):
        require(isinstance(transaction, str) and bool(transaction), 'external_auth_transaction_unavailable')
        self.start()
        self.client.authenticate(self.state.snapshot()['settings'])
        reply = self.api(PRE, {'trscTyp': 'AUTH', 'certTrscId': transaction,
                             'custNoWtBox': self.profile['customer_number'], 'bizDvCd': '', 'closeWebYn': ''})
        code = reply.get('rsltCd')
        if code != 'NORMAL':
            self.result['external_auth_status'] = 'rejected' if code else 'unconfirmed'
            raise Stop({'NO_USER': 'onesign_enrollment_required', 'NO_HANACERTS': 'onesign_certificate_required'}.get(code, 'external_auth_not_ready'))
        detail = reply.get('easnCertPtcl')
        require(isinstance(detail, dict), 'external_auth_signing_details_unavailable')
        require(detail.get('elecCertRqstCd') != '004', 'external_multi_sign_not_supported')
        details = detail.get('easnCertDtlsList')
        require(isinstance(details, list) and bool(details) and all(isinstance(row, dict) for row in details),
                'external_auth_signing_details_unavailable')
        content = details[0].get('elecSignOtxtDat')
        require(isinstance(content, str) and bool(content), 'external_auth_signing_text_unavailable')
        returned_transaction = detail.get('certTrscId')
        require(isinstance(returned_transaction, str) and bool(returned_transaction), 'external_auth_transaction_unavailable')
        entry = self.entry
        info = {k: entry[k] for k in ('pinSalt', 'pinVersion')}
        info['subjectDer'] = pin.b64url(pin.certificate_parts(pin.unb64url(entry['certificate']))[2])
        secret = pin_input()
        try:
            material = self.flow.local_stage('external-pin', lambda: pin.derive_pin(secret,
                device_id=self.profile['device_id'], pin_salt=info['pinSalt'], pin_spec_version=2))
        finally:
            del secret
        ra_secret = self.flow.ra_auth('external', info, material)
        signature = self.flow.local_stage('external-sign', lambda: self.flow.store.sign(
            self.alias, content.encode('utf-8'), material=material, ra_secret=ra_secret))
        signed = base64.b64encode(signature).decode()
        # Empty bank nonce means exactly the server's bytes, including a missing
        # delfinoNonce marker. RA nonce acquisition above is a different protocol.
        body = {'certTrscId': returned_transaction, 'easnCertSignList': [dict(copy.deepcopy(row), elecSignVluDat=signed)
                                                               for row in details], 'tst': False}
        reply = self.api(SUBMIT, body)
        require(reply.get('rsltCd') == 'NORMAL', 'external_auth_not_confirmed')

    def finish(self):
        if self.client is not None:
            self.result['network_used'] |= self.client.sent > 0
            self.result['personal_transport'] = {k: v for k, v in self.client.last.items()
                                                 if k in ('service_status', 'processing_status', 'http_status', 'scope')}
            if not self.finished:
                self.finished = True
                try:
                    with self.control.transaction() as value:
                        value.update(outcome='completed' if self.result['external_auth_status'] == 'accepted' else 'stopped',
                                     result={'external_auth_status': self.result['external_auth_status'],
                                             'transport': self.result['personal_transport']})
                except (OSError, ValueError):
                    self.result['diagnostic_storage_failed'] = True
