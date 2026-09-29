"""Minimal local SEED cipher backend, using the system OpenSSL library."""
import ctypes as ct
import ctypes.util
import os
from pathlib import Path
from finance_cli.core.native import crypto_library


class OpenSSL:
    _lib = None

    def __init__(self):
        if self._lib is not None:
            self.lib = self._lib
            return
        library = crypto_library()
        self.lib = ct.CDLL(library)
        pointer = ct.c_void_p
        for name, result, args in (
            ('EVP_CIPHER_CTX_new', pointer, []), ('EVP_CIPHER_CTX_free', None, [pointer]),
            ('OSSL_PROVIDER_load', pointer, [pointer, ct.c_char_p]),
        ):
            function = getattr(self.lib, name)
            function.restype, function.argtypes = result, args
        for provider in (b'default', b'legacy'):
            if not self.lib.OSSL_PROVIDER_load(None, provider):
                raise ValueError('openssl_provider_initialization_failed')
        OpenSSL._lib = self.lib

    @staticmethod
    def resource(stack, value, free):
        if not value:
            raise ValueError('openssl_allocation_failed')
        stack.callback(free, value)
        return value
