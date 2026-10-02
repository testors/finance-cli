"""Declared, in-memory environment for offline CodeGuard experiments.

This is a simulator, not an Android observation or login provider. Every file,
package query and command outcome must be explicitly supplied. Missing entries
remain unknown; they never mean absent, uninstalled or a successful check.
No host identity, filesystem, subprocess, SDK or network is consulted.

Native string/certificate operations are composed using the existing value
backends. JNI tokens here model the selected normal API path only, not a VM's
class loading, pending exceptions, allocation failures or reference table.
"""
from dataclasses import dataclass
from itertools import count

from .codeguard_certificate_values import NativeByteArrayValue
from .codeguard_effects import JavaFault
from .codeguard_native_jni import NativeStringValue
from .codeguard_rule import AnalysisLimit


@dataclass(frozen=True, repr=False)
class PackageRecord:
    package_name: str
    source_dir: str
    data_dir: str
    library_dir: str
    signatures: tuple


@dataclass(frozen=True, repr=False)
class CommandOutcome:
    start_fault: JavaFault | None
    destroy_fault: JavaFault | None


@dataclass(repr=False, eq=False)
class _Stream:
    owner: object
    data: bytes
    position: int = 0
    eof: bool = False
    closed: bool = False


@dataclass(frozen=True, repr=False)
class _Class:
    name: str


@dataclass(frozen=True, repr=False)
class _Member:
    owner: _Class
    name: str
    descriptor: str


@dataclass(frozen=True, repr=False)
class _PackageInfo:
    package: PackageRecord


@dataclass(frozen=True, repr=False)
class _Signature:
    data: bytes


@dataclass(repr=False, eq=False)
class _Command:
    owner: object
    outcome: CommandOutcome


_CLASSES = {
    'android/content/pm/ApplicationInfo', 'android/content/pm/PackageInfo',
    'android/content/pm/Signature', 'android/os/Build$VERSION',
    'android/os/Process', 'java/lang/Class',
    'android/app/ApplicationContext$ApplicationPackageManager',
    'android/app/ContextImpl$ApplicationPackageManager',
    'android/app/ApplicationPackageManager',
}
_METHODS = {
    'getPackageManager': '()Landroid/content/pm/PackageManager;',
    'getApplicationInfo': '(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;',
    'getPackageInfo': '(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;',
    'isInstance': '(Ljava/lang/Object;)Z', 'myPid': '()I', 'toByteArray': '()[B',
}
_FIELDS = {'SDK_INT': 'I', 'signatures': '[Landroid/content/pm/Signature;',
           **{name: 'Ljava/lang/String;' for name in ('sourceDir', 'dataDir', 'nativeLibraryDir')}}


class EnvironmentSimulation:
    """Mutable declared inputs, read at each original effect boundary.

    packages uses (queried name, flags) keys so flags/visibility distinctions
    cannot be silently merged. A JavaFault explicitly represents an API
    exception; JNI continuation after it is outside this normal-path model.
    files uses byte paths and byte contents; None explicitly means fopen
    failed. An open stream retains its input bytes; in-place changes to an
    already open file are outside this experiment model.
    """
    def __init__(self, *, pid, sdk, manager_class, packages, files, stat_results,
                 build, commands, file_existence):
        if type(pid) is not int or type(sdk) is not int:
            raise AnalysisLimit('explicit simulation PID and SDK integers required')
        self.pid, self.sdk, self.manager_class = pid, sdk, manager_class
        self.packages, self.files, self.stat_results = dict(packages), dict(files), dict(stat_results)
        self.build, self.commands = dict(build), dict(commands)
        # File.exists and fopen have different semantics (e.g. access denied).
        self.file_existence = dict(file_existence)
        self.service, self.manager, self.runtime = object(), object(), object()
        self.events = []  # kinds only; no values, paths, commands or identifiers
        self._service_class = _Class('simulation.Service')

    @staticmethod
    def _read(mapping, key):
        if key not in mapping:
            raise AnalysisLimit('environment simulation input not supplied')
        value = mapping[key]
        if isinstance(value, JavaFault):
            raise value
        return value

    def _package(self, name, flags, *, jni=False):
        try:
            value = self._read(self.packages, (name, flags))
        except JavaFault:
            if jni:
                raise AnalysisLimit('pending JNI exception is outside environment simulation') from None
            raise
        if not isinstance(value, PackageRecord):
            raise AnalysisLimit('declared package record required')
        return value

    def _stream(self, stream):
        if not isinstance(stream, _Stream) or stream.owner is not self or stream.closed:
            raise AnalysisLimit('simulation stream lifetime mismatch')
        return stream

    def resolve(self, effect):
        kind, args = effect.kind, effect.args
        self.events.append(kind)
        if kind == 'native_jni':
            return self._jni(*args)
        if kind == 'native_fopen':
            path, mode = args
            if mode not in (b'r', b'rb'):
                raise AnalysisLimit('simulation supports read-only streams')
            data = self._read(self.files, path)
            if data is None:
                return None
            if type(data) is not bytes:
                raise AnalysisLimit('explicit simulation file bytes required')
            return _Stream(self, data)
        if kind == 'native_stat':
            return self._read(self.stat_results, args[0])
        if kind in ('native_fgets', 'native_fread', 'native_fclose', 'native_fseek',
                    'native_ftell', 'native_rewind', 'native_feof'):
            stream = self._stream(args[0])
            if kind == 'native_fgets':
                if args[1] <= 1:
                    raise AnalysisLimit('unsupported simulation fgets size')
                if stream.position >= len(stream.data):
                    stream.eof = True
                    return None
                end = min(stream.position + args[1] - 1, len(stream.data))
                newline = stream.data.find(b'\n', stream.position, end)
                if newline >= 0:
                    end = newline + 1
                elif end == len(stream.data) and end - stream.position < args[1] - 1:
                    stream.eof = True
                data = stream.data[stream.position:end]
                stream.position = end
                return data
            if kind == 'native_fread':
                _, size, count = args
                if size != 1 or count < 0:
                    raise AnalysisLimit('unsupported simulation fread size')
                data = stream.data[stream.position:stream.position + count]
                stream.position += len(data)
                if len(data) < count:
                    stream.eof = True
                return data
            if kind == 'native_fclose':
                stream.closed = True
                return 0
            if kind == 'native_feof':
                return int(stream.eof)
            if kind == 'native_ftell':
                return stream.position
            if kind == 'native_rewind':
                stream.position, stream.eof = 0, False
                return None
            _, offset, whence = args
            if (offset, whence) != (0, 2):
                raise AnalysisLimit('unsupported simulation seek')
            stream.position, stream.eof = len(stream.data), False
            return 0
        if kind in ('build_string_field', 'device_build_field'):
            return self._read(self.build, args[0])
        if kind == 'device_package_manager':
            return self.manager
        if kind == 'device_application_info' and args[0] is self.manager:
            return self._package(args[1], args[2])
        if kind == 'device_application_package_name' and isinstance(args[0], PackageRecord):
            return args[0].package_name
        if kind == 'device_file':
            return args[0]
        if kind == 'device_file_exists':
            value = self._read(self.file_existence, args[0])
            if type(value) is not bool:
                raise AnalysisLimit('explicit simulation file existence boolean required')
            return value
        if kind == 'device_runtime':
            return self.runtime
        if kind == 'device_runtime_exec' and args[0] is self.runtime:
            outcome = self._read(self.commands, args[1])
            if not isinstance(outcome, CommandOutcome):
                raise AnalysisLimit('explicit simulation command outcome required')
            if outcome.start_fault is not None:
                raise outcome.start_fault
            return _Command(self, outcome)
        if kind == 'device_process_destroy' and isinstance(args[0], _Command) and args[0].owner is self:
            if args[0].outcome.destroy_fault is not None:
                raise args[0].outcome.destroy_fault
            return None
        if kind == 'device_log':
            return None  # explicitly selected no-op logger for this simulation
        raise AnalysisLimit('unsupported environment simulation effect')

    def _jni(self, operation, *args):
        if operation == 'FindClass' and args[0] in _CLASSES:
            return _Class(args[0])
        if operation == 'GetObjectClass':
            value = args[0]
            if value is self.service: return self._service_class
            if value is self.manager: return _Class(self.manager_class)
            if isinstance(value, PackageRecord): return _Class('android/content/pm/ApplicationInfo')
            if isinstance(value, _PackageInfo): return _Class('android/content/pm/PackageInfo')
            if isinstance(value, _Signature): return _Class('android/content/pm/Signature')
        if operation in ('GetMethodID', 'GetStaticMethodID', 'GetFieldID', 'GetStaticFieldID'):
            owner, name, descriptor = args
            declarations = _METHODS if 'Method' in operation else _FIELDS
            if isinstance(owner, _Class) and declarations.get(name) == descriptor:
                return _Member(owner, name, descriptor)
        if operation == 'CallBooleanMethod':
            receiver, method, value = args
            if isinstance(method, _Member) and method.name == 'isInstance' and isinstance(receiver, _Class):
                return value is self.manager and receiver.name == self.manager_class
        if operation == 'GetStaticIntField':
            receiver, member = args
            if receiver == _Class('android/os/Build$VERSION') and member.name == 'SDK_INT':
                return self.sdk
        if operation == 'CallStaticIntMethod':
            receiver, member = args
            if receiver == _Class('android/os/Process') and member.name == 'myPid':
                return self.pid
        if operation == 'CallObjectMethod':
            receiver, member, *params = args
            if isinstance(member, _Member):
                if member.name == 'getPackageManager' and receiver is self.service and not params:
                    return self.manager
                if member.name in ('getApplicationInfo', 'getPackageInfo') and receiver is self.manager:
                    name, flags = params
                    if not isinstance(name, NativeStringValue):
                        raise AnalysisLimit('owned simulation package name required')
                    package = self._package(name.text, flags, jni=True)
                    return package if member.name == 'getApplicationInfo' else _PackageInfo(package)
                if member.name == 'toByteArray' and isinstance(receiver, _Signature) and not params:
                    return NativeByteArrayValue(receiver.data)
        if operation == 'GetObjectField':
            receiver, member = args
            fields = {'sourceDir': 'source_dir', 'dataDir': 'data_dir', 'nativeLibraryDir': 'library_dir'}
            if isinstance(receiver, PackageRecord) and member.name in fields:
                return NativeStringValue(getattr(receiver, fields[member.name]))
            if isinstance(receiver, _PackageInfo) and member.name == 'signatures':
                return tuple(_Signature(data) for data in receiver.package.signatures)
        if operation == 'GetObjectArrayElement' and isinstance(args[0], tuple):
            if not 0 <= args[1] < len(args[0]):
                raise AnalysisLimit('pending JNI array exception is outside simulation')
            return args[0][args[1]]
        if operation == 'DeleteLocalRef' and (isinstance(args[0], (_Class, PackageRecord, _PackageInfo))
                                             or args[0] is self.manager):
            return None
        raise AnalysisLimit('unsupported environment simulation JNI operation')


def run_simulation_steps(generator, resolve, *, max_effects=10000):
    """Drive effects; None explicitly removes the experimental step budget.

    The default bounds experiments. A full runtime can select None so file
    size does not cause an artificial processing failure. Unknowns still never
    become Java failures, and a finite exhausted budget never creates a token.
    """
    value, pending = None, None
    for _ in count() if max_effects is None else range(max_effects):
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as done:
            return done.value
        pending = None
        try:
            value = resolve(effect)
        except Exception as error:
            pending = error
    raise AnalysisLimit('environment simulation effect budget exhausted')
