"""Bounded getNonce composition on explicit JNI/file observations.

No host IO, Android context, installed files or clean checks are supplied.
Python owns computation buffers; native allocation failure and unsafe memory
accesses remain analysis boundaries, not fabricated successful/error returns.
"""
from dataclasses import dataclass
import hashlib

from .codeguard_effects import Effect, observed_bool
from .codeguard_native_io import FailedCmdlineRead, native_process_name
from .codeguard_native_jni import _jni, utf_chars_bytes
from .codeguard_nonce import cg_auth_code
from .codeguard_rule import AnalysisLimit


class NativeNonceBoundary(AnalysisLimit):
    def __init__(self, code=None):
        self.native_code = code
        super().__init__('native nonce branch needs unresolved runtime semantics')


def _int(value):
    if type(value) is not int or not -2**31 <= value < 2**31:
        raise AnalysisLimit('observed native integer required')
    return value


def _cstring(value):
    data = utf_chars_bytes(value, require_handle=True)
    if data is None:
        raise NativeNonceBoundary()  # strlen(NULL), not an empty path
    return data.split(b'\0', 1)[0]


def nonce_file_digest_steps(stream, *, null_code=None):
    """Hash actual fread bytes until observed feof; neither seek nor ferror.

    A short/zero read does not itself end this loop. Repeated reads with EOF
    unset are the native loop, not added retries. The driver may suspend an
    unresolved/nonterminating observation stream without inventing a result.
    """
    if stream is None:
        raise NativeNonceBoundary(null_code)  # native feof(NULL)
    digest = hashlib.sha256()
    while _int((yield Effect('native_feof', (stream,)))) == 0:
        data = yield Effect('native_fread', (stream, 1, 1024))
        if type(data) is not bytes or len(data) > 1024:
            raise AnalysisLimit('actual native fread bytes required')
        digest.update(data)
    result = digest.digest()
    yield Effect('native_fclose', (stream,))  # return status is not consulted
    return result


@dataclass(frozen=True, repr=False)
class NonceLookup:
    manager: object
    manager_class: object
    name_ref: object
    library_refs: tuple
    data_ref: object
    delete_refs: tuple
    code: int


def nonce_lookup_steps(service):
    """getNonce's lookup, distinct from start: no isInstance or path test.

    Null JNI observations are forwarded in source order, without clearing
    pending exceptions. The late code-14 test is not an early return.
    """
    service_class = yield _jni('GetObjectClass', service)
    app_class = yield _jni('FindClass', 'android/content/pm/ApplicationInfo')
    get_manager = yield _jni('GetMethodID', service_class, 'getPackageManager',
                            '()Landroid/content/pm/PackageManager;')
    manager = yield _jni('CallObjectMethod', service, get_manager)
    manager_class = yield _jni('GetObjectClass', manager)
    version_class = yield _jni('FindClass', 'android/os/Build$VERSION')
    sdk_field = yield _jni('GetStaticFieldID', version_class, 'SDK_INT', 'I')
    sdk = _int((yield _jni('GetStaticIntField', version_class, sdk_field)))
    expected_name = ('android/app/ApplicationContext$ApplicationPackageManager' if sdk <= 6 else
                     'android/app/ContextImpl$ApplicationPackageManager' if sdk <= 10 else
                     'android/app/ApplicationPackageManager')
    expected_class = yield _jni('FindClass', expected_name)
    class_class = yield _jni('FindClass', 'java/lang/Class')
    get_info = yield _jni('GetMethodID', manager_class, 'getApplicationInfo',
                         '(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;')
    process_class = yield _jni('FindClass', 'android/os/Process')
    get_pid = yield _jni('GetStaticMethodID', process_class, 'myPid', '()I')
    pid = _int((yield _jni('CallStaticIntMethod', process_class, get_pid)))
    code = 14 if pid == 0 or any(x is None for x in
        (get_pid, process_class, get_info, get_manager)) else 0
    stream = yield Effect('native_fopen', (b'/proc/' + str(pid).encode('ascii') + b'/cmdline', b'r'))
    if stream is None:
        raise NativeNonceBoundary(15)  # subsequent fgets(NULL) is not safe
    line = yield Effect('native_fgets', (stream, 256))
    if line is None or isinstance(line, FailedCmdlineRead):
        yield Effect('native_fclose', (stream,))
        raise NativeNonceBoundary(16)  # source closes again before using buffer
    yield Effect('native_fclose', (stream,))
    name = native_process_name(line, nonce=True)
    name_ref = yield _jni('NewStringUTF', name)
    info = yield _jni('CallObjectMethod', manager, get_info, name_ref, 0)
    library_field = yield _jni('GetFieldID', app_class, 'nativeLibraryDir', 'Ljava/lang/String;')
    library_one = yield _jni('GetObjectField', info, library_field)
    library_two = yield _jni('GetObjectField', info, library_field)
    data_field = yield _jni('GetFieldID', app_class, 'dataDir', 'Ljava/lang/String;')
    data_ref = yield _jni('GetObjectField', info, data_field)
    return NonceLookup(manager, manager_class, name_ref, (library_one, library_two), data_ref,
        (info, expected_class, process_class, service_class, app_class, class_class,
         version_class, manager, manager_class), code)


def _file_code(digest, challenge_utf, is_mix):
    if is_mix:
        digest = hashlib.sha256(digest + _cstring(challenge_utf)).digest()
    return digest.hex().upper().encode('ascii')


def nonce_file_codes_steps(lookup, challenge_utf, *, is_mix, is_split):
    """Five file codes and the ONE library UTF acquisition later released.

    Repeated dataDir/second library UTF acquisitions are not cached. There
    are no matching native releases for them in this entrypoint.
    """
    observed_bool(is_mix)
    observed_bool(is_split)
    codes = []
    first_utf = None
    for ref, name in zip(lookup.library_refs, (b'libCodeGuard.so', b'libImageDecoder.so')):
        acquired = yield _jni('GetStringUTFChars', ref)
        path = _cstring(acquired) + b'/' + name
        if not codes: first_utf = acquired
        stream = yield Effect('native_fopen', (path, b'rb'))
        if stream is None:
            data_utf = yield _jni('GetStringUTFChars', lookup.data_ref)
            stream = yield Effect('native_fopen', (_cstring(data_utf) + b'/files/lib/' + name, b'rb'))
        digest = yield from nonce_file_digest_steps(stream)
        codes.append(_file_code(digest, challenge_utf, is_mix))
    data_utf = yield _jni('GetStringUTFChars', lookup.data_ref)
    stream = yield Effect('native_fopen', (_cstring(data_utf) + b'/files/classes.dex', b'rb'))
    digest = yield from nonce_file_digest_steps(stream, null_code=82)
    codes.append(_file_code(digest, challenge_utf, is_mix))
    for name in (b'MANIFEST.MF', b'CERT.SF'):
        digest = bytes(32)
        if not is_split:
            data_utf = yield _jni('GetStringUTFChars', lookup.data_ref)
            stream = yield Effect('native_fopen', (_cstring(data_utf) + b'/files/META-INF/' + name, b'rb'))
            if stream is not None:
                digest = yield from nonce_file_digest_steps(stream)
        codes.append(_file_code(digest, challenge_utf, is_mix))
    return codes, first_utf


def nonce_signer_steps(lookup, challenge_utf, *, is_mix):
    """JNI signer lookup through observed digest bytes; no package substitution."""
    code = lookup.code
    method = yield _jni('GetMethodID', lookup.manager_class, 'getPackageInfo',
                       '(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;')
    info = yield _jni('CallObjectMethod', lookup.manager, method, lookup.name_ref, 64)
    info_class = yield _jni('GetObjectClass', info)
    field = yield _jni('GetFieldID', info_class, 'signatures', '[Landroid/content/pm/Signature;')
    if method is None: code = 14
    signatures = yield _jni('GetObjectField', info, field)
    signature = yield _jni('GetObjectArrayElement', signatures, 0)
    signature_class = yield _jni('GetObjectClass', signature)
    to_bytes = yield _jni('GetMethodID', signature_class, 'toByteArray', '()[B')
    encoded_signature = yield _jni('CallObjectMethod', signature, to_bytes)
    stream_class = yield _jni('FindClass', 'java/io/ByteArrayInputStream')
    init = yield _jni('GetMethodID', stream_class, '<init>', '([B)V')
    stream = yield _jni('NewObject', stream_class, init, encoded_signature)
    factory_class = yield _jni('FindClass', 'java/security/cert/CertificateFactory')
    factory_method = yield _jni('GetStaticMethodID', factory_class, 'getInstance',
                               '(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;')
    x509 = yield _jni('NewStringUTF', b'X.509')
    factory = yield _jni('CallStaticObjectMethod', factory_class, factory_method, x509)
    if any(x is None for x in (factory, x509, stream, to_bytes, signature_class)):
        code = 85  # assigned only here, and it overrides the earlier code
    generate = yield _jni('GetMethodID', factory_class, 'generateCertificate',
                          '(Ljava/io/InputStream;)Ljava/security/cert/Certificate;')
    cert = yield _jni('CallObjectMethod', factory, generate, stream)
    cert_class = yield _jni('GetObjectClass', cert)
    encode = yield _jni('GetMethodID', cert_class, 'getEncoded', '()[B')
    der = yield _jni('CallObjectMethod', cert, encode)
    digest_class = yield _jni('FindClass', 'java/security/MessageDigest')
    get_digest = yield _jni('GetStaticMethodID', digest_class, 'getInstance',
                           '(Ljava/lang/String;)Ljava/security/MessageDigest;')
    algorithm = yield _jni('NewStringUTF', b'SHA-256')
    digest_object = yield _jni('CallStaticObjectMethod', digest_class, get_digest, algorithm)
    digest_method = yield _jni('GetMethodID', digest_class, 'digest', '([B)[B')
    digest_ref = yield _jni('CallObjectMethod', digest_object, digest_method, der)
    length = _int((yield _jni('GetArrayLength', digest_ref)))
    if not 0 <= length < 2**30:
        raise AnalysisLimit('native signer allocation boundary')
    data = yield _jni('GetByteArrayElements', digest_ref)
    if length and (type(data) is not bytes or len(data) < length):
        raise AnalysisLimit('observed native signer array bytes required')
    if length >= 64:
        raise AnalysisLimit('native signer sprintf exceeds 128-byte buffer')
    raw = (data[:length] if length else b'').hex().upper().encode('ascii')
    if is_mix:
        if length < 32:
            raise AnalysisLimit('native signer mix reads unresolved format tail')
        raw = hashlib.sha256(raw[:64] + _cstring(challenge_utf)).hexdigest().upper().encode('ascii')
    # Nonmix strncpy copies 64 bytes, including zero padding for short strings.
    return raw[:64].ljust(64, b'\0'), code


def native_nonce_steps(service, key, challenge, is_mix, is_split):
    """Normal allocation path, returning final observed Java String/None.

    No process status/path match check or JNI cleanup absent from this entry
    point is added. This does not assert that unresolved JNI calls can work
    with null references or pending exceptions; the driver must observe each.
    """
    observed_bool(is_mix)
    observed_bool(is_split)
    challenge_utf = yield _jni('GetStringUTFChars', challenge)
    utf_chars_bytes(challenge_utf, require_handle=True)
    lookup = yield from nonce_lookup_steps(service)
    codes, first_utf = yield from nonce_file_codes_steps(lookup, challenge_utf,
                                                       is_mix=is_mix, is_split=is_split)
    signer, code = yield from nonce_signer_steps(lookup, challenge_utf, is_mix=is_mix)
    codes.append(signer)
    key_utf = yield _jni('GetStringUTFChars', key)
    result = cg_auth_code(utf_chars_bytes(key_utf, require_handle=True), codes).encode('ascii')
    if first_utf is not None:
        yield _jni('ReleaseStringUTFChars', lookup.library_refs[0], first_utf.handle)
    for ref in lookup.delete_refs:
        if ref is not None:
            yield _jni('DeleteLocalRef', ref)
    if key_utf is not None:
        yield _jni('ReleaseStringUTFChars', key, key_utf.handle)
    if challenge_utf is not None:
        yield _jni('ReleaseStringUTFChars', challenge, challenge_utf.handle)
    if code:
        result = b'E101_ENGINE_LOAD_ERROR0_' + str(code).encode('ascii') + b'_:lib2'
    returned = yield _jni('NewStringUTF', result)
    if returned is not None and type(returned) is not str:
        raise AnalysisLimit('observed final Java String value required')
    return returned


def project_native_nonce_steps(generator, *, service):
    """Expand native_get_nonce without providing a live effect executor."""
    value, pending = None, None
    while True:
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as finished:
            return finished.value
        pending = None
        try:
            if effect.kind == 'native_get_nonce':
                value = yield from native_nonce_steps(service, *effect.args)
            else:
                value = yield effect
        except Exception as fault:
            pending = fault
