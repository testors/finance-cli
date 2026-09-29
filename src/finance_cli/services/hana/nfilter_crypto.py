"""Offline NFilter compatibility implementation.

Uses the local OpenSSL 3 library.
Compatibility is tested against the recovered ARM64 SDK on synthetic inputs.
Server acceptance and device-session behavior are not verified.
"""
import base64
import ctypes as ct
import io
import secrets
from contextlib import ExitStack
from pathlib import Path

from .nfilter_format import decode_public_key_envelope, public_key_envelope
from .local_toolchain import OPENSSL_LIB

ROOT = Path(__file__).resolve().parents[1]
ORDER = int('04' + '00' * 9 + '01e60fc8821cc74daeafc1', 16)


def encrypt_numeric_password(server_public_key, digits, mac_key):
    """Fresh numeric input encryption with explicitly supplied service material."""
    from .nfilter_number import pack_numeric_input
    if not isinstance(mac_key, bytes) or len(mac_key) != 20:
        raise ValueError('invalid_keypad_mac')
    _, peer = decode_public_key_envelope(base64.b64decode(server_public_key, validate=True), mac_key)
    crypto = OpenSSL()
    public, shared = crypto.curve(secrets.randbelow(ORDER - 1) + 1, peer)
    client = public_key_envelope(b'', public, mac_key)
    ciphertext = crypto.encrypt(shared[:16], pack_numeric_input(shared, digits))
    return base64.b64encode(client).decode() + base64.b64encode(ciphertext).decode()


class OpenSSL:
    _lib = None

    def __init__(self):
        if self._lib is not None:
            self.lib = self._lib
            return
        self.lib = ct.CDLL(OPENSSL_LIB)
        p, n = ct.c_void_p, ct.c_int
        signatures = {
            'OBJ_txt2nid': (n, [ct.c_char_p]),
            'EC_GROUP_new_by_curve_name': (p, [n]), 'EC_GROUP_free': (None, [p]),
            'EC_POINT_new': (p, [p]), 'EC_POINT_free': (None, [p]),
            'BN_CTX_new': (p, []), 'BN_CTX_free': (None, [p]),
            'BN_bin2bn': (p, [ct.c_char_p, n, p]), 'BN_clear_free': (None, [p]),
            'EC_POINT_mul': (n, [p] * 6),
            'EC_POINT_oct2point': (n, [p, p, ct.c_char_p, ct.c_size_t, p]),
            'EC_POINT_is_on_curve': (n, [p, p, p]),
            'EC_POINT_point2oct': (ct.c_size_t, [p, p, n, p, ct.c_size_t, p]),
            'OSSL_PROVIDER_load': (p, [p, ct.c_char_p]),
            'EVP_CIPHER_CTX_new': (p, []), 'EVP_CIPHER_CTX_free': (None, [p]),
            'EVP_seed_cfb128': (p, []),
            'EVP_EncryptInit_ex': (n, [p, p, p, ct.c_char_p, ct.c_char_p]),
            'EVP_EncryptUpdate': (n, [p, p, ct.POINTER(n), ct.c_char_p, n]),
            'EVP_EncryptFinal_ex': (n, [p, p, ct.POINTER(n)]),
        }
        for name, (result, args) in signatures.items():
            function = getattr(self.lib, name)
            function.restype, function.argtypes = result, args
        # Keep providers for this process. Unloading the explicitly loaded
        # default provider disables later EC blinding/random operations.
        for name in (b'default', b'legacy'):
            if not self.lib.OSSL_PROVIDER_load(None, name):
                raise ValueError('OpenSSL provider initialization failed')
        OpenSSL._lib = self.lib

    @staticmethod
    def resource(stack, value, free):
        if not value:
            raise ValueError('OpenSSL allocation/provider initialization failed')
        stack.callback(free, value)
        return value

    def curve(self, private, peer_public=None):
        """Return compressed client public key and optional cofactor shared X."""
        if not 1 <= private < ORDER:
            raise ValueError('Invalid WTLS5 private scalar')
        lib = self.lib
        with ExitStack() as stack:
            def resource(value, free):
                return self.resource(stack, value, free)
            group = resource(lib.EC_GROUP_new_by_curve_name(lib.OBJ_txt2nid(b'wap-wsg-idm-ecid-wtls5')), lib.EC_GROUP_free)
            ctx = resource(lib.BN_CTX_new(), lib.BN_CTX_free)
            own = resource(lib.EC_POINT_new(group), lib.EC_POINT_free)
            scalar = resource(lib.BN_bin2bn(private.to_bytes(21, 'big'), 21, None), lib.BN_clear_free)
            if lib.EC_POINT_mul(group, own, scalar, None, None, ctx) != 1:
                raise ValueError('OpenSSL public-point calculation failed')
            public = ct.create_string_buffer(22)
            if lib.EC_POINT_point2oct(group, own, 2, public, 22, ctx) != 22:
                raise ValueError('Unexpected compressed point size')
            if peer_public is None:
                return public.raw, None
            peer = resource(lib.EC_POINT_new(group), lib.EC_POINT_free)
            shared = resource(lib.EC_POINT_new(group), lib.EC_POINT_free)
            if lib.EC_POINT_oct2point(group, peer, peer_public, len(peer_public), ctx) != 1 or lib.EC_POINT_is_on_curve(group, peer, ctx) != 1:
                raise ValueError('Invalid peer public point')
            doubled = resource(lib.BN_bin2bn((private * 2).to_bytes(21, 'big'), 21, None), lib.BN_clear_free)
            if lib.EC_POINT_mul(group, shared, None, peer, doubled, ctx) != 1:
                raise ValueError('OpenSSL ECDH calculation failed')
            point = ct.create_string_buffer(43)
            if lib.EC_POINT_point2oct(group, shared, 4, point, 43, ctx) != 43:
                raise ValueError('Unexpected/infinite shared point')
            return public.raw, point.raw[1:22]

    def encrypt(self, key, plaintext):
        if len(key) != 16 or not plaintext:
            raise ValueError('Expected a 16-byte key and nonempty plaintext')
        lib = self.lib
        with ExitStack() as stack:
            ctx = self.resource(stack, lib.EVP_CIPHER_CTX_new(), lib.EVP_CIPHER_CTX_free)
            output, first, last = ct.create_string_buffer(len(plaintext) + 32), ct.c_int(), ct.c_int()
            if lib.EVP_EncryptInit_ex(ctx, lib.EVP_seed_cfb128(), None, key, bytes(16)) != 1:
                raise ValueError('SEED-CFB initialization failed')
            if lib.EVP_EncryptUpdate(ctx, output, ct.byref(first), plaintext, len(plaintext)) != 1:
                raise ValueError('SEED-CFB encryption failed')
            if lib.EVP_EncryptFinal_ex(ctx, ct.byref(output, first.value), ct.byref(last)) != 1:
                raise ValueError('SEED-CFB finalization failed')
            return output.raw[:first.value + last.value]
