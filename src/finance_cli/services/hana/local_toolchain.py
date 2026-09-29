"""System OpenSSL discovery, independent of the development checkout."""
from finance_cli.core.native import crypto_library

OPENSSL_LIB = crypto_library()
