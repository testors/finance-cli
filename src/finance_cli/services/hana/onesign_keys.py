"""PIN and external-auth protected certificate records; encrypted persistence is supplied by the caller."""
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import re
import secrets

from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Util.Padding import pad
from Crypto.Util.asn1 import DerSequence, DerSetOf, DerObjectId, DerObject

from .onesign_codec import encode, decode
from .onesign_crypto import (ProtocolError, require, text, b64url, unb64url, certificate_parts,
                       master_secret, external_master_secret, unwrap_master_password, sign_cms)

PIN_ITEM = 'encryptedMasterPasswordByMasterSecret'
EXTERNAL_ITEM = 'encryptedMasterPasswordBySecretB'
PIN_FLAG, EXTERNAL_FLAG = 1, 8  # Also checked against original enum in JVM comparison.


def stamp():
    return datetime.now(timezone.utc).isoformat()


def seal(key, plain, aad):
    require(isinstance(key, bytes) and len(key) == 32, 'invalid_store_key')
    cipher = AES.new(key, AES.MODE_GCM, nonce=secrets.token_bytes(12))
    cipher.update(aad)
    encrypted, tag = cipher.encrypt_and_digest(plain)
    return b64url(cipher.nonce + tag + encrypted)


def open_sealed(key, value, aad):
    require(isinstance(key, bytes) and len(key) == 32, 'invalid_store_key')
    raw = unb64url(value)
    require(len(raw) >= 28, 'invalid_store_envelope')
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=raw[:12])
        cipher.update(aad)
        return cipher.decrypt_and_verify(raw[28:], raw[12:28])
    except ValueError:
        raise ProtocolError('store_authentication_failed') from None


def wrap_master(secret, master):
    require(len(secret) == len(master) == 32, 'invalid_master_length')
    iv = hashlib.sha256(b'WIZVERA ID2 IV' + secret).digest()[:16]
    return b64url(AES.new(secret, AES.MODE_CBC, iv).encrypt(pad(base64.b64encode(master), 16)))


def certificate_alias(certificate):
    subject = certificate_parts(certificate)[2]
    found = {}
    try:
        for rdn in DerSequence().decode(subject, strict=True):
            for attr in DerSetOf().decode(rdn, strict=True):
                name, value = DerSequence().decode(attr, strict=True)
                name = DerObjectId().decode(name).value
                if name in ('0.9.2342.19200300.100.1.1', '2.5.4.11', '2.5.4.10') and name not in found:
                    raw = DerObject().decode(value, strict=True).payload
                    if value[0] == 12:
                        found[name] = raw.decode('utf-8')
                    elif value[0] == 30:
                        found[name] = raw.decode('utf-16-be')
                    elif value[0] in (18, 19, 20, 21, 22, 25, 26, 27):
                        found[name] = raw.decode('latin-1')
                    else:
                        found[name] = '#' + value.hex()
        # c/c.a uses first value, or empty when the subject field is absent.
        return '-'.join(found.get(name, '') for name in ('0.9.2342.19200300.100.1.1', '2.5.4.11', '2.5.4.10'))
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, ProtocolError):
            raise
        raise ProtocolError('invalid_certificate_alias') from None


class Ledger:
    def __init__(self, vault):
        self.vault = vault

    def begin(self, operation, server, path):
        require(re.fullmatch(r'[a-z0-9_-]{1,60}', operation) is not None, 'invalid_operation_name')
        with self.vault.transaction() as value:
            require(not value['halted'], 'workflow_halted')
            require(operation not in value['operations'], 'operation_already_attempted')
            require(all(item['state'] in ('accepted', 'handled') for item in value['operations'].values()), 'prior_operation_unresolved')
            value['operations'][operation] = {'server': server, 'path': path, 'state': 'pending', 'attempts': 1,
                                              'started_at': stamp()}

    def _update(self, operation, fields):
        with self.vault.transaction() as value:
            require(value['operations'][operation]['state'] == 'pending', 'operation_not_pending')
            value['operations'][operation].update(fields)

    def begin_parts(self):
        with self.vault.transaction() as value:
            require(not value['halted'] and all(row['state'] in ('accepted', 'handled')
                    for row in value['operations'].values()), 'prior_operation_unresolved')
            require(not any('cloud-part-' + str(n) in value['operations'] for n in (1, 2)), 'operation_already_attempted')
            for server in (1, 2):
                value['operations']['cloud-part-' + str(server)] = {'server': server, 'path': 'requestPartialData',
                    'state': 'pending', 'attempts': 1, 'started_at': stamp(), 'parallel_group': 'cloud-parts'}

    def bind_nonce(self, operation, server, nonce):
        digest = hashlib.sha256(text(nonce, empty=True).encode()).hexdigest()
        with self.vault.transaction() as value:
            value['operations'][operation]['nonce_sha256'] = digest

    def prepared(self, operation, digest):
        self._update(operation, {'request_sha256': digest, 'prepared_at': stamp()})

    def accept(self, operation, digest):
        self._update(operation, {'state': 'accepted', 'response_sha256': digest, 'finished_at': stamp()})

    def handled(self, operation, reason):
        self._update(operation, {'state': 'handled', 'reason': reason, 'accepted': False,
                                'continued_by_source_callback': True, 'finished_at': stamp()})

    def halt(self, operation, code):
        with self.vault.transaction() as value:
            value['halted'] = True
            value['operations'][operation].update(state='halted', reason=code, finished_at=stamp())

    def summary(self):
        value = self.vault.snapshot()
        return {'halted': value['halted'], 'operations': value['operations'], 'automatic_retry': False}


class KeyStore:
    def __init__(self, vault, device_id):
        self.vault, self.device_id = vault, text(device_id)

    @staticmethod
    def aad(record):
        return encode({key: record[key] for key in ('alias', 'device_id', 'fingerprint', 'pinSalt', 'pinVersion', 'pinSpecVersion')})

    def import_key(self, certificate, decoded, material, ra_secret, pin_version):
        alias = certificate_alias(certificate)
        public = certificate_parts(certificate)[3]
        require(decoded.key.pointQ == public.pointQ and decoded.key.has_private() and len(decoded.r) == 32,
                'certificate_private_key_mismatch')
        require(material.spec_version == 2, 'unsupported_import_pin_spec')
        master = secrets.token_bytes(32)
        record = {'alias': alias, 'device_id': self.device_id, 'fingerprint': hashlib.sha256(certificate).hexdigest(),
                  'certificate': b64url(certificate), 'pinSalt': material.effective_salt, 'pinVersion': text(pin_version, empty=True),
                  'pinSpecVersion': 2, 'authType': PIN_FLAG,
                  PIN_ITEM: wrap_master(master_secret(material, alias, ra_secret), master)}
        payload = encode({'key': b64url(decoded.key.export_key(format='DER', use_pkcs8=True)), 'r': b64url(decoded.r)})
        # Android changes access key 0 from download password to HEX(master),
        # then sets access key 1 to HEX(master). CLI persists only the final key.
        record['key'] = seal(master, payload, self.aad(record))
        require(open_sealed(master, record['key'], self.aad(record)) == payload, 'store_self_check_failed')
        with self.vault.transaction() as value:
            require(alias not in value['records'], 'certificate_already_stored')
            value['records'][alias] = record
        return alias

    def _record(self, value, alias):
        require(alias in value['records'], 'certificate_not_stored')
        record = value['records'][alias]
        require(record['device_id'] == self.device_id and record['alias'] == alias, 'store_device_mismatch')
        require(hashlib.sha256(unb64url(record['certificate'])).hexdigest() == record['fingerprint'], 'stored_certificate_mismatch')
        return record

    def _unlock(self, record, secret, item):
        require(item in record, 'authentication_method_not_registered')
        master = unwrap_master_password(secret, record[item])
        payload = decode(open_sealed(master, record['key'], self.aad(record)))
        key = ECC.import_key(unb64url(payload['key']))
        require(key.pointQ == certificate_parts(unb64url(record['certificate']))[3].pointQ, 'stored_key_mismatch')
        return master, key

    def register_external(self, alias, material, ra_secret, sc_b_cert_key):
        with self.vault.transaction() as value:
            record = self._record(value, alias)
            require(not record['authType'] & EXTERNAL_FLAG, 'external_auth_already_registered')
            master, _ = self._unlock(record, master_secret(material, alias, ra_secret), PIN_ITEM)
            secret = external_master_secret(sc_b_cert_key, device_id=self.device_id)
            record[EXTERNAL_ITEM] = wrap_master(secret, master)
            require(hmac.compare_digest(unwrap_master_password(secret, record[EXTERNAL_ITEM]), master), 'external_auth_self_check_failed')
            record['authType'] |= EXTERNAL_FLAG

    def sign(self, alias, content, *, material=None, ra_secret=None, sc_b_cert_key=None):
        record = self._record(self.vault.snapshot(), alias)
        require((material is None) != (sc_b_cert_key is None), 'one_authentication_method_required')
        if material is not None:
            require(record['authType'] & PIN_FLAG, 'pin_auth_not_registered')
            secret, item = master_secret(material, alias, ra_secret), PIN_ITEM
        else:
            require(record['authType'] & EXTERNAL_FLAG, 'external_auth_not_registered')
            secret, item = external_master_secret(sc_b_cert_key, device_id=self.device_id), EXTERNAL_ITEM
        _, key = self._unlock(record, secret, item)
        return sign_cms(unb64url(record['certificate']), key, content)
