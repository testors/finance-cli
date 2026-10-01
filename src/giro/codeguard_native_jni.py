"""Native PackageManager JNI ordering with explicit observations, offline.

The three lookups are separate native calls. No context/class/SDK value or
successful isInstance result is supplied here. This stage does not execute
JNI, implement a PackageManager, or return a complete native_start result.
"""
from dataclasses import dataclass

from .codeguard_effects import Effect, observed_bool
from .codeguard_native_io import native_cmdline_steps, native_paths_match
from .codeguard_rule import AnalysisLimit


class NativeLookupBoundary(AnalysisLimit):
    """Known native branch, stopped before unresolved cleanup/error rendering.

    native_code is a stage assignment, NOT a returned error string or an app
    failure. In particular, inner early exits can free uninitialized memory.
    """
    def __init__(self, phase, code):
        self.phase, self.native_code = phase, code
        super().__init__('native lookup branch requires later runtime semantics')


@dataclass(frozen=True, repr=False)
class NativeUtfChars:
    """One nonnull GetStringUTFChars acquisition, with its opaque pointer.

    Equal bytes/ref values do not identify an acquisition. Release must use
    this handle. An observation adapter supplies pointer identity; the pure
    string-value adapter instead uses an explicit Python ownership token.
    Neither is printed or dereferenced as a native address here.
    """
    handle: object
    data: bytes


@dataclass(frozen=True, repr=False, eq=False)
class NativeStringValue:
    """Known string contents owned by Python, not an Android object assertion.

    Platform paths/names must come from their actual provider. This wrapper
    only permits deterministic string conversion after the value is known.
    Identity equality keeps two equal strings distinct as local references.
    """
    text: str

    def __post_init__(self):
        if type(self.text) is not str:
            raise AnalysisLimit('known Java string contents required')


def native_return_text(value):
    if isinstance(value, NativeStringValue):
        return value.text
    if value is not None and type(value) is not str:
        raise AnalysisLimit('resolved final Java String value required')
    return value


def utf_chars_bytes(value, *, require_handle=False):
    if value is None:
        return None
    if isinstance(value, NativeUtfChars):
        if value.handle is None or type(value.data) is not bytes:
            raise AnalysisLimit('nonnull UTF acquisition handle and bytes required')
        return value.data
    if not require_handle and type(value) is bytes:
        return value  # earlier path-only models do not release these pointers
    raise AnalysisLimit('resolved UTF acquisition required')


@dataclass(frozen=True, repr=False)
class PackageManagerLookup:
    service_class: object
    application_class: object
    manager: object
    manager_class: object
    version_class: object
    expected_class: object
    class_class: object
    application_method: object


@dataclass(frozen=True, repr=False)
class PackagePathLookup:
    manager_lookup: PackageManagerLookup
    process_class: object
    process_name: bytes
    application_info: object
    source_ref: object
    source_bytes: bytes
    data_ref: object
    data_bytes: bytes | None
    source_utf: object
    data_utf: object


def _jni(name, *args):
    return Effect('native_jni', (name, *args))


def package_manager_lookup_steps(service, *, phase):
    """phase is start, getpath, or digest; never collapse these into a cache.

    start entry is AFTER its process/argument checks; digest entry is AFTER
    getpath. getpath returns zero even when isInstance returned false. Null
    observations without a native branch remain in subsequent JNI calls;
    this does not clear a pending JNI exception or assume those calls work.
    """
    if phase not in ('start', 'getpath', 'digest'):
        raise AnalysisLimit('explicit native lookup phase required')
    code = 110 if phase == 'start' else 13

    def require(value):
        if value is None:
            raise NativeLookupBoundary(phase, code)
        return value

    service_class = yield _jni('GetObjectClass', service)
    if phase == 'start': require(service_class)
    application_class = yield _jni('FindClass', 'android/content/pm/ApplicationInfo')
    if phase != 'getpath': require(application_class)
    method = yield _jni('GetMethodID', service_class, 'getPackageManager',
                        '()Landroid/content/pm/PackageManager;')
    if phase != 'getpath': require(method)
    manager = yield _jni('CallObjectMethod', service, method)
    if phase == 'start': require(manager)
    manager_class = yield _jni('GetObjectClass', manager)
    version_class = yield _jni('FindClass', 'android/os/Build$VERSION')
    field = yield _jni('GetStaticFieldID', version_class, 'SDK_INT', 'I')
    sdk = yield _jni('GetStaticIntField', version_class, field)
    if type(sdk) is not int or not -2**31 <= sdk < 2**31:
        raise AnalysisLimit('observed SDK integer required')
    expected_name = ('android/app/ApplicationContext$ApplicationPackageManager' if sdk <= 6 else
                     'android/app/ContextImpl$ApplicationPackageManager' if sdk <= 10 else
                     'android/app/ApplicationPackageManager')
    expected_class = yield _jni('FindClass', expected_name)
    class_class = yield _jni('FindClass', 'java/lang/Class')
    if expected_class is not None:
        if phase != 'getpath': require(class_class)
        method = yield _jni('GetMethodID', class_class, 'isInstance', '(Ljava/lang/Object;)Z')
        if phase != 'getpath': require(method)
        matches = yield _jni('CallBooleanMethod', expected_class, method, manager)
        if phase != 'getpath' and not observed_bool(matches):
            raise NativeLookupBoundary(phase, 131 if phase == 'start' else 14)
    application_method = yield _jni('GetMethodID', manager_class, 'getApplicationInfo',
                                    '(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;')
    if phase == 'getpath':
        return 0  # method ID and isInstance return are ignored; JNI effects are not.
    require(application_method)
    return PackageManagerLookup(service_class, application_class, manager, manager_class,
                                version_class, expected_class, class_class, application_method)


def package_path_lookup_steps(service, *, phase):
    """Expand a start/digest lookup through the last path substring check.

    For digest this includes its separate, discarded getpath call first.
    Caller still owns the subsequent PID conversion/stat (start only), local
    reference cleanup, digest IO and UTF release. No earlier lookup is reused.
    """
    if phase not in ('start', 'digest'):
        raise AnalysisLimit('explicit native path lookup phase required')
    if phase == 'digest':
        yield from package_manager_lookup_steps(service, phase='getpath')
    lookup = yield from package_manager_lookup_steps(service, phase=phase)
    # The inner path really assigns zero on these early exits. Cleanup then
    # reads uninitialized pointers; this is NOT successful digest completion.
    process_code = -1 if phase == 'start' else 0
    process_class = yield _jni('FindClass', 'android/os/Process')
    if process_class is None: raise NativeLookupBoundary(phase, process_code)
    method = yield _jni('GetStaticMethodID', process_class, 'myPid', '()I')
    if method is None: raise NativeLookupBoundary(phase, process_code)
    pid = yield _jni('CallStaticIntMethod', process_class, method)
    if type(pid) is not int or not -2**31 <= pid < 2**31:
        raise AnalysisLimit('observed Android process integer required')
    if pid == 0: raise NativeLookupBoundary(phase, process_code)
    read_code, process_name = yield from native_cmdline_steps(pid, outer=phase == 'start')
    if phase == 'digest' and read_code:
        raise NativeLookupBoundary(phase, read_code)
    name_ref = yield _jni('NewStringUTF', process_name)
    info = yield _jni('CallObjectMethod', lookup.manager, lookup.application_method, name_ref, 0)
    source_field = yield _jni('GetFieldID', lookup.application_class, 'sourceDir', 'Ljava/lang/String;')
    code = 110 if phase == 'start' else 13
    if source_field is None: raise NativeLookupBoundary(phase, code)
    if phase == 'start':
        data_field = yield _jni('GetFieldID', lookup.application_class, 'dataDir', 'Ljava/lang/String;')
        if data_field is None: raise NativeLookupBoundary(phase, code)
    if info is None: raise NativeLookupBoundary(phase, code)
    source_ref = yield _jni('GetObjectField', info, source_field)
    if source_ref is None: raise NativeLookupBoundary(phase, code)
    data_ref, data_bytes = None, None
    if phase == 'start':
        data_ref = yield _jni('GetObjectField', info, data_field)
        if data_ref is None: raise NativeLookupBoundary(phase, code)
    source_utf = yield _jni('GetStringUTFChars', source_ref)
    data_utf = None
    if phase == 'start':
        data_utf = yield _jni('GetStringUTFChars', data_ref)
    source_bytes = utf_chars_bytes(source_utf)
    if not native_paths_match(process_name, source_bytes):
        raise NativeLookupBoundary(phase, code)
    if phase == 'start':
        data_bytes = utf_chars_bytes(data_utf)
        if not native_paths_match(process_name, data_bytes):
            raise NativeLookupBoundary(phase, code)
    return PackagePathLookup(lookup, process_class, process_name, info,
                             source_ref, source_bytes, data_ref, data_bytes, source_utf, data_utf)


def delete_path_references_steps(paths, *, phase):
    """The successful-path DeleteLocalRef order before entering file IO.

    source/data String refs are retained for ReleaseStringUTFChars. The
    temporary name String and getpath's refs have no explicit delete here.
    """
    if not isinstance(paths, PackagePathLookup) or phase not in ('start', 'digest'):
        raise AnalysisLimit('resolved native path stage required')
    lookup = paths.manager_lookup
    refs = ((lookup.expected_class, True), (paths.process_class, False),
            (lookup.service_class, phase == 'digest'), (lookup.application_class, False),
            (lookup.class_class, True), (lookup.version_class, True),
            (paths.application_info, False), (lookup.manager, phase == 'digest'),
            (lookup.manager_class, True))
    for ref, conditional in refs:
        if not conditional or ref is not None:
            yield _jni('DeleteLocalRef', ref)
