"""Private portable inputs for explicitly recorded-state replay.

Loading creates a Python platform, never observes Android or starts HTTP. A
replayed process frame is labeled as such, not reported as a new observation.
Unknown policy paths still raise the normal missing-input boundary.
"""
import base64
from dataclasses import dataclass, fields
import json

from finance_cli.core import storage

from .codeguard_artifacts import FileDigests
from .codeguard_effects import JavaFault
from .codeguard_fingerprint_values import read_certificate_value
from .codeguard_prepared import ArchiveIndex, PreparedPlatform
from .codeguard_rule import AnalysisLimit
from .codeguard_simulation import CommandOutcome, EnvironmentSimulation, PackageRecord


SCHEMA = 'finance.giro.protection-profile'
MODE = 'recorded-state-replay'
_RECORDS = {c.__name__: c for c in (FileDigests, ArchiveIndex, PackageRecord, CommandOutcome)}
_ENV = ('pid', 'sdk', 'manager_class', 'packages', 'files', 'stat_results', 'build', 'commands', 'file_existence')
_PLATFORM = ('application', 'files_dir', 'directories', 'modified', 'preferences', 'abi', 'phone',
             'split_metadata', 'location', 'archives')


def _encode(value):
    if value is None or type(value) in (str, int, bool): return value
    if type(value) is bytes: return ['bytes', base64.b64encode(value).decode('ascii')]
    if type(value) in (list, tuple): return [type(value).__name__, [_encode(v) for v in value]]
    if type(value) is dict: return ['dict', [[_encode(k), _encode(v)] for k, v in value.items()]]
    if isinstance(value, JavaFault):
        return ['JavaFault', _encode(dict(kind=value.kind, message=value.message,
                                         java_string=value.java_string, bases=value.bases))]
    if type(value).__name__ in _RECORDS and type(value) is _RECORDS[type(value).__name__]:
        return [type(value).__name__, _encode({f.name: getattr(value, f.name) for f in fields(value)})]
    raise AnalysisLimit('unsupported private protection profile value')


def _decode(value, depth=0):
    if depth > 24: raise AnalysisLimit('private protection profile nesting limit')
    if value is None or type(value) in (str, int, bool): return value
    if type(value) is not list or len(value) != 2 or type(value[0]) is not str:
        raise AnalysisLimit('invalid private protection profile value')
    kind, body = value
    child = lambda v: _decode(v, depth + 1)
    if kind == 'bytes': return base64.b64decode(body, validate=True)
    if kind in ('list', 'tuple'):
        if type(body) is not list: raise AnalysisLimit('profile sequence required')
        result = [child(v) for v in body]
        return tuple(result) if kind == 'tuple' else result
    if kind == 'dict':
        if type(body) is not list: raise AnalysisLimit('profile mapping required')
        result = {}
        for pair in body:
            if type(pair) is not list or len(pair) != 2: raise AnalysisLimit('profile pair required')
            key = child(pair[0])
            if key in result: raise AnalysisLimit('duplicate profile key')
            result[key] = child(pair[1])
        return result
    if kind == 'JavaFault': return JavaFault(**child(body))
    if kind in _RECORDS: return _RECORDS[kind](**child(body))
    raise AnalysisLimit('unknown private protection profile record')


class RecordedEnvironment(EnvironmentSimulation):
    """Repeat an explicit recorded read frame; never consult the host's proc.

    Counts refer to replay operations, not fresh samples. Repeating the state
    is a declared model assumption. This is independent of fresh server keys,
    challenges, cookies, timestamps and token responses.
    """
    def __init__(self, *, read_frames, **kwargs):
        super().__init__(**kwargs)
        self.read_frames = read_frames
        self.replayed_reads = {path: 0 for path in read_frames}
        allowed = {b'/proc/self/status', f'/proc/{self.pid}/cmdline'.encode()}
        if (not isinstance(read_frames, dict) or set(read_frames) != allowed
                or any(type(values) is not tuple or not values
                       or any(type(v) is not bytes or len(v) > 65536 for v in values)
                       for values in read_frames.values())):
            raise AnalysisLimit('explicit status and cmdline replay frames required')

    def resolve(self, effect):
        if effect.kind == 'native_fopen' and effect.args[0] in self.read_frames:
            path = effect.args[0]
            values = self.read_frames[path]
            self.files[path] = values[self.replayed_reads[path] % len(values)]
            self.replayed_reads[path] += 1
        return super().resolve(effect)


@dataclass(repr=False)
class ProtectionProfile:
    platform: PreparedPlatform
    app_info: str
    version: str
    locale_language: str
    map_profile: str
    provenance: dict
    http_os_name: str | None = None
    http_os_name_source: str | None = None

    @classmethod
    def from_prepared(cls, platform, *, read_frames, app_info, version, locale_language,
                      map_profile, provenance):
        if not isinstance(platform, PreparedPlatform) or platform.process is not None:
            raise AnalysisLimit('unused prepared platform required')
        platform.environment = RecordedEnvironment(read_frames=read_frames,
            **{name: getattr(platform.environment, name) for name in _ENV})
        platform.service = platform.environment.service
        return cls(platform, app_info, version, locale_language, map_profile, provenance)

    def document(self):
        if self.platform.process is not None:
            raise AnalysisLimit('profile export must precede runtime use')
        return dict(schema=SCHEMA, schema_version=1, mode=MODE,
            app_info=self.app_info, version=self.version, locale_language=self.locale_language,
            map_profile=self.map_profile, provenance=self.provenance,
            http_os_name=self.http_os_name, http_os_name_source=self.http_os_name_source,
            environment=_encode({name: getattr(self.platform.environment, name) for name in _ENV}),
            platform=_encode({name: getattr(self.platform, name) for name in _PLATFORM}),
            read_frames=_encode(self.platform.environment.read_frames))

    def save(self, path):
        storage.write_new(path, (json.dumps(self.document(), ensure_ascii=False) + '\n').encode())

    @classmethod
    def load(cls, path):
        try:
            return cls.from_document(json.loads(storage.read(path, limit=16*1024*1024)))
        except (ValueError, TypeError, KeyError, AttributeError, AnalysisLimit):
            raise AnalysisLimit('private protection profile is invalid or unsupported') from None

    @classmethod
    def from_document(cls, document):
        if (document['schema'] != SCHEMA or document['schema_version'] != 1 or document['mode'] != MODE
                or any(type(document[k]) is not str or not document[k]
                       for k in ('app_info', 'version', 'locale_language', 'map_profile'))
                or type(document['provenance']) is not dict):
            raise AnalysisLimit('recorded-state profile with explicit provenance required')
        env_values, platform_values = _decode(document['environment']), _decode(document['platform'])
        if set(env_values) != set(_ENV) or set(platform_values) != set(_PLATFORM):
            raise AnalysisLimit('complete profile fields required')
        for path, data in env_values['files'].items():
            if type(path) is not bytes or (not path.startswith(b'/proc/') and
                                           data is not None and not isinstance(data, FileDigests)):
                raise AnalysisLimit('profile must contain immutable content summaries')
        for archive in platform_values['archives'].values():
            if not isinstance(archive, ArchiveIndex): raise AnalysisLimit('archive index required')
            if type(archive.names) is not tuple or len(set(archive.names)) != len(archive.names):
                raise AnalysisLimit('unique archive names required')
            if not set(archive.certificate_entries).issubset(archive.names):
                raise AnalysisLimit('certificate entry missing from archive index')
            for data in archive.certificate_entries.values(): read_certificate_value(data)
        environment = RecordedEnvironment(read_frames=_decode(document['read_frames']), **env_values)
        def no_write_time(): raise AnalysisLimit('immutable preparation cannot write files')
        platform = PreparedPlatform(environment=environment, write_time=no_write_time, **platform_values)
        os_name, source = document.get('http_os_name'), document.get('http_os_name_source')
        if ((os_name is None) != (source is None) or (os_name is not None and
                (type(os_name) is not str or not os_name or source not in ('observed', 'static-inference')))):
            raise AnalysisLimit('explicit business OS property provenance required')
        return cls(platform, *(document[k] for k in ('app_info', 'version', 'locale_language', 'map_profile', 'provenance')),
                   http_os_name=os_name, http_os_name_source=source)

    def business_user_agent(self):
        from .protocol import APP_VERSION
        from .user_agent import business_user_agent
        if self.http_os_name is None or self.http_os_name_source not in ('observed', 'static-inference'):
            raise AnalysisLimit('explicit business OS property required')
        build = self.platform.environment.build
        return business_user_agent(APP_VERSION, os_name=self.http_os_name,
                                   model=build.get('MODEL'), release=build.get('RELEASE'))

    def report(self):
        return dict(schema=SCHEMA, schema_version=1, mode=MODE, network_used=False,
                    fresh_device_observation=False, executable_content_required=False)
