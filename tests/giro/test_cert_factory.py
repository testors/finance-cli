import base64
from datetime import datetime, timezone, timedelta
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from giro.cert_factory import CertificateBackendLimit, select_certificate, inspect_recipient
from giro.cert_input import CertificateInputError
from giro.cms import _tlv

def sample(number):
    return _tlv(48, _tlv(48, bytes((2, 1, number))) + _tlv(48, b'\x06\x02*\x03') + b'\x03\x02\x00\x01')

def signed_data(certificates, *, suffix=b'1\x00', extra=b'', indefinite=False):
    fields = b'\x02\x01\x011\x00' + _tlv(48, b'\x06\t*\x86H\x86\xf7\r\x01\x07\x01')
    fields += _tlv(160, b''.join(certificates)) + extra + suffix
    contents = b'\x06\t*\x86H\x86\xf7\r\x01\x07\x02' + _tlv(160, _tlv(48, fields))
    return b'0\x80' + contents + b'\x00\x00' if indefinite else _tlv(48, contents)

@unittest.skipUnless(importlib.util.find_spec('asn1crypto'), 'optional asn1crypto unavailable')
class CertificateSelectionTests(unittest.TestCase):

    def test_first_object_ignores_trailing_bytes_and_other_certificates(self):
        result = select_certificate(sample(1) + sample(2) + b'bad trailer')
        self.assertEqual(result.data, sample(1))
        self.assertEqual(result.trailing_bytes, len(sample(2) + b'bad trailer'))
        self.assertFalse(result.certificate_validation_performed)

    def test_signed_data_uses_first_certificate_not_sorted_or_leaf_filtered(self):
        result = select_certificate(signed_data([sample(2), sample(1)]))
        self.assertEqual(result.data, sample(2))
        self.assertEqual(result.container, 'signed_data')

    def test_definite_and_indefinite_cms_select_same_certificate(self):
        for indefinite in (False, True):
            self.assertEqual(select_certificate(signed_data([sample(1)], indefinite=indefinite)).data, sample(1))

    def test_signed_data_does_not_require_signer_infos_or_valid_cms_signature(self):
        self.assertEqual(select_certificate(signed_data([sample(1)], suffix=b'')).data, sample(1))

    def test_later_certificates_tag_overwrites_prior_not_first_wins(self):
        data = signed_data([sample(1)], extra=_tlv(160, sample(2)))
        self.assertEqual(select_certificate(data).data, sample(2))

    def test_first_noncertificate_choice_is_not_skipped(self):
        with self.assertRaises(CertificateInputError):
            select_certificate(signed_data([_tlv(161, b''), sample(1)]))

    def test_empty_certificates_and_unknown_tag_fail_original_structure(self):
        for data in (signed_data([]), signed_data([sample(1)], extra=_tlv(162, b''))):
            with self.assertRaises(CertificateInputError):
                select_certificate(data)

    def test_direct_indefinite_certificate_rejected_but_pem_path_not_same_branch(self):
        contents = sample(1)[2:]
        indefinite = b'0\x80' + contents + b'\x00\x00'
        with self.assertRaisesRegex(CertificateInputError, 'direct_indefinite'):
            select_certificate(indefinite)
        pem = b'-----BEGIN CERTIFICATE-----\n' + base64.b64encode(indefinite) + b'\n'
        self.assertEqual(select_certificate(pem).data, indefinite)

    def test_outer_certificate_structure_is_not_trust_validation(self):
        with self.assertRaisesRegex(CertificateInputError, 'outer_structure'):
            select_certificate(b'0\x03\x02\x01\x01')
        result = select_certificate(sample(1))
        self.assertFalse(result.certificate_validation_performed)
        self.assertNotIn(repr(result.data), repr(result))

    def test_backend_gap_does_not_invent_app_rejection(self):
        with self.assertRaises(CertificateBackendLimit):
            select_certificate(b'0\x82\xff')

@unittest.skipUnless(importlib.util.find_spec('asn1crypto') and importlib.util.find_spec('cryptography'), 'optional certificate packages unavailable')
class CertificateInspectionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'SYNTHETIC DO NOT PRINT')])
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        builder = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key()).serial_number(10).not_valid_before(now).not_valid_after(now + timedelta(days=1))
        ku = x509.KeyUsage(False, False, True, False, False, False, False, False, False)
        cls.good_usage = builder.add_extension(ku, False).sign(private, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        cls.no_usage = builder.sign(private, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def test_expired_untrusted_selfsigned_not_declared_ready_by_usage_pass(self):
        result = inspect_recipient(self.good_usage)
        self.assertTrue(result['subchecks']['recipient_key_usage']['rule_completed'])
        self.assertFalse(result['certificate_validation_performed'])
        self.assertFalse(result['live_login_ready'])
        self.assertNotIn('SYNTHETIC DO NOT PRINT', json.dumps(result))

    def test_usage_failure_is_a_subrule_result_not_giro_response(self):
        result = inspect_recipient(self.no_usage)
        self.assertFalse(result['subchecks']['recipient_key_usage']['rule_completed'])
        self.assertNotIn('app_success', result)
        self.assertNotIn('response_code', result)

    def test_cli_partial_inspection_never_requests_pin_or_opens_socket(self):
        from giro.__main__ import parser, run
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic.der'
            path.write_bytes(self.good_usage)
            args = parser().parse_args(['auth', 'inspect-cert', '--input', str(path)])
            with patch('socket.socket', side_effect=AssertionError('offline only')), patch('getpass.getpass', side_effect=AssertionError('no PIN for inspection')):
                (result, status) = run(args)
        self.assertEqual(status, 0)
        self.assertFalse(result['live_login_ready'])

    def test_cli_backend_gap_is_unmodeled_not_server_failure(self):
        from giro.__main__ import parser, run
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic.der'
            path.write_bytes(b'0\x82\xff')
            (result, status) = run(parser().parse_args(['auth', 'inspect-cert', '--input', str(path)]))
        self.assertEqual(status, 0)
        self.assertEqual(result['analysis_status'], 'unmodeled')
        self.assertFalse(result['certificate_validation_performed'])
