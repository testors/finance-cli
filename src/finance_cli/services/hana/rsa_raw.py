"""MobileSafeKey-compatible raw RSA type-1 signatures, using trusted OpenSSL.

The recovered SDK was verified with fresh synthetic 1024/2048-bit keys.
This module handles ordinary private DER keys, not SDK device key containers.
"""
import ctypes as ct
from contextlib import ExitStack

from .nfilter_crypto import OpenSSL


def _key(stack, private_der):
    if not isinstance(private_der, bytes) or not private_der:
        raise ValueError('Expected a nonempty private DER key')
    lib = OpenSSL().lib
    p, n, z = ct.c_void_p, ct.c_int, ct.c_size_t
    signatures = {
        'd2i_AutoPrivateKey': (p, [p, ct.POINTER(p), ct.c_long]),
        'EVP_PKEY_free': (None, [p]), 'EVP_PKEY_is_a': (n, [p, ct.c_char_p]),
        'EVP_PKEY_get_size': (n, [p]),
        'EVP_PKEY_CTX_new': (p, [p, p]), 'EVP_PKEY_CTX_free': (None, [p]),
        'EVP_PKEY_sign_init': (n, [p]),
        'EVP_PKEY_CTX_set_rsa_padding': (n, [p, n]),
        'EVP_PKEY_sign': (n, [p, p, ct.POINTER(z), ct.c_char_p, z]),
        'i2d_PUBKEY': (n, [p, ct.POINTER(p)]),
    }
    for name, (result, args) in signatures.items():
        function = getattr(lib, name)
        function.restype, function.argtypes = result, args
    encoded = ct.create_string_buffer(private_der)
    cursor = p(ct.addressof(encoded))
    key = lib.d2i_AutoPrivateKey(None, ct.byref(cursor), len(private_der))
    if not key:
        raise ValueError('Cannot decode private DER key')
    stack.callback(lib.EVP_PKEY_free, key)
    if cursor.value != ct.addressof(encoded) + len(private_der):
        raise ValueError('Trailing bytes after private DER key')
    if lib.EVP_PKEY_is_a(key, b'RSA') != 1:
        raise ValueError('Expected an RSA private key')
    return lib, key


def sign(private_der, message):
    """Sign exact bytes: 00 01 FF...FF 00 message, no hash or DigestInfo."""
    if not isinstance(message, bytes):
        raise ValueError('Expected raw message bytes')
    with ExitStack() as stack:
        lib, key = _key(stack, private_der)
        size = lib.EVP_PKEY_get_size(key)
        if not 1 <= len(message) <= size - 11:
            raise ValueError(f'Raw RSA input must contain 1 to {size - 11} bytes')
        ctx = OpenSSL.resource(stack, lib.EVP_PKEY_CTX_new(key, None), lib.EVP_PKEY_CTX_free)
        if lib.EVP_PKEY_sign_init(ctx) <= 0 or lib.EVP_PKEY_CTX_set_rsa_padding(ctx, 1) <= 0:
            raise ValueError('Raw RSA initialization failed')
        # Deliberately do not set a digest: the SDK signs the original bytes.
        output, length = ct.create_string_buffer(size), ct.c_size_t(size)
        if lib.EVP_PKEY_sign(ctx, output, ct.byref(length), message, len(message)) <= 0 or length.value != size:
            raise ValueError('Raw RSA signature failed')
        return output.raw[:length.value]


def public_der(private_der):
    """Export SubjectPublicKeyInfo, matching the SDK's public-key header."""
    with ExitStack() as stack:
        lib, key = _key(stack, private_der)
        size = lib.i2d_PUBKEY(key, None)
        if size <= 0:
            raise ValueError('Cannot size RSA public key')
        output = ct.create_string_buffer(size)
        cursor = ct.c_void_p(ct.addressof(output))
        if lib.i2d_PUBKEY(key, ct.byref(cursor)) != size:
            raise ValueError('Cannot encode RSA public key')
        return output.raw
