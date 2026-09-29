"""Resolve supported host tools without loading mobile SDK binaries."""
import ctypes.util
import os
from pathlib import Path
import shutil
import sys


def crypto_library():
    if os.environ.get('FINANCE_OPENSSL_LIB'):
        return os.environ['FINANCE_OPENSSL_LIB']
    if sys.platform == 'darwin':
        for prefix in ('/opt/homebrew/opt/openssl@3', '/usr/local/opt/openssl@3'):
            path = Path(prefix) / 'lib/libcrypto.dylib'
            if path.is_file():
                return str(path)
        # Apple's libcrypto stub can abort the process instead of raising.
        raise ValueError('OpenSSL 3 설치 또는 FINANCE_OPENSSL_LIB 지정이 필요합니다.')
    library = ctypes.util.find_library('crypto')
    if not library:
        raise ValueError('system_openssl_required')
    return library


def java_executable():
    if os.environ.get('JAVA_HOME'):
        candidate = Path(os.environ['JAVA_HOME']) / 'bin/java'
        if candidate.is_file():
            return str(candidate)
    if sys.platform == 'darwin':
        for prefix in ('/opt/homebrew/opt', '/usr/local/opt'):
            for formula in ('openjdk@21', 'openjdk@17', 'openjdk'):
                candidate = Path(prefix) / formula / 'bin/java'
                if candidate.is_file():
                    return str(candidate)
    executable = shutil.which('java')
    if not executable:
        raise ValueError('jdk_17_or_later_required')
    return executable
