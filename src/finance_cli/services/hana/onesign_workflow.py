"""Ordered signing operations with persistent attempt records."""
import base64
import hashlib
import hmac
from . import onesign_crypto as pin
from .onesign_codec import encode
from .onesign_keys import KeyStore, Ledger

class Workflow:
    def __init__(self, vault, device_id, cloud_exchange, bank, ra, now_ms, *,
                 ledger_vault=None, cloud_observer=None):
        self.store, self.ledger = KeyStore(vault, device_id), Ledger(ledger_vault or vault)
        self.bank, self.ra, self.now_ms = bank, ra, now_ms

    def checkpoint(self):
        value = self.ledger.vault.snapshot()
        pin.require(not value['halted'], 'workflow_halted')

    def local_stage(self, name, action):
        self.ledger.begin(name, -1, 'local')
        try:
            self.checkpoint()
            result = action()
            self.ledger.accept(name, 'local-no-response')
            return result
        except Exception as exc:
            code = str(exc) if type(exc) is pin.ProtocolError else 'workflow_stage_failed'
            self.ledger.halt(name, code)
            raise pin.ProtocolError(code) from None

    def exchange(self, name, target, adapter, path, body):
        self.ledger.begin(name, target, path)
        try:
            self.checkpoint()
            self.ledger.prepared(name, hashlib.sha256(encode(body)).hexdigest())
            result = adapter(path, body)
            pin.require(isinstance(result, dict), 'response_object_required')
            self.ledger.accept(name, hashlib.sha256(encode(result)).hexdigest())
            return result
        except Exception as exc:
            code = str(exc) if type(exc) is pin.ProtocolError else 'workflow_exchange_interrupted'
            self.ledger.halt(name, code)
            raise pin.ProtocolError(code) from None

    def ra_auth(self, name, info, material):
        response = self.exchange(name + '-nonce', -2, self.ra, '/nonce', {})
        nonce = self.local_stage(name + '-nonce-check', lambda: pin.ra_nonce(response))
        # Fetch a nonce for each phase; the source does not reject repeated text.
        self.ledger.begin(name + '-nonce-bind', -2, 'nonce-binding')
        try:
            self.ledger.bind_nonce(name + '-nonce-bind', -2, nonce)
            self.ledger.accept(name + '-nonce-bind', 'local-no-response')
        except Exception:
            self.ledger.halt(name + '-nonce-bind', 'nonce_record_failed')
            raise pin.ProtocolError('nonce_record_failed') from None
        body = {'subjectDer': info['subjectDer'], 'nonceHmac': pin.b64url(hmac.digest(material.nonce_key, nonce.encode(), 'sha256')),
                'authType': 'PIN'}
        if info['pinVersion']:
            body['pinVersion'] = info['pinVersion']
        response = self.exchange(name + '-secret', -2, self.ra, '/requestSecretE', body)
        return self.local_stage(name + '-secret-check', lambda: pin.decrypt_ra_secret(nonce, response))

    def prepare_login(self, alias, info, pin_value, *, customer_number, moment):
        # The RA request verifies the PIN/version; no extra cloud status call.
        material = self.local_stage('login-pin', lambda: pin.derive_pin(pin_value, device_id=self.store.device_id,
                                     pin_salt=info['pinSalt'], pin_spec_version=2))
        response = self.exchange('login-bank-nonce', -3, self.bank, pin.BANK_NONCE_PATH, pin.bank_nonce_body(customer_number))
        def validate_nonce():
            return pin.text(response.get('scrtRnum'), empty=True)
        nonce = self.local_stage('login-bank-nonce-check', validate_nonce)
        ra_secret = self.ra_auth('login', info, material)
        def sign():
            content = pin.bind_bank_nonce(pin.login_tbs(customer_number, moment), nonce).encode()
            return pin.login_body(base64.b64encode(self.store.sign(alias, content, material=material, ra_secret=ra_secret)).decode())
        return self.local_stage('login-sign', sign)
