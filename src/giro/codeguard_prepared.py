"""Immutable content preparation for a standalone Python platform.

Compilation reads explicit in-memory archive bytes once. Runtime retains file
digests, archive entry order and certificate-entry bytes, never executable
payloads. The preparation cache is this client's state, not observed Android
private storage. Process and policy inputs remain separately supplied values.
"""
from dataclasses import dataclass
from io import BytesIO
from zipfile import ZipFile, ZipInfo

from .codeguard_artifacts import FileDigests
from .codeguard_fingerprint_values import KnownCertificateStream
from .codeguard_lifecycle import GuardProcess
from .codeguard_memory import MemoryPlatform
from .codeguard_package import check_zip_steps
from .codeguard_rule import AnalysisLimit
from .codeguard_simulation import EnvironmentSimulation, run_simulation_steps


@dataclass(frozen=True, repr=False)
class ArchiveIndex:
    names: tuple
    certificate_entries: dict

    @classmethod
    def from_bytes(cls, data):
        with ZipFile(BytesIO(data)) as archive:
            entries = archive.infolist()
            names = tuple(entry.filename for entry in entries)
            if len(set(names)) != len(names):
                raise AnalysisLimit('immutable archive index requires unique entry names')
            certificates = {entry.filename: archive.read(entry) for entry in entries
                            if entry.filename.upper().endswith('.RSA')}
            return cls(names, certificates)


class PreparedPlatform(MemoryPlatform):
    def __init__(self, *, archives, **kwargs):
        super().__init__(**kwargs)
        self.archives = {self.path(path): value for path, value in archives.items()}

    def _package(self, name, *args):
        if name == 'zip.new':
            path = self.path(args[0])
            if path not in self.archives:
                raise AnalysisLimit('prepared archive index unavailable')
            return self.archives[path]
        if name in ('zip.size', 'zip.entries') and isinstance(args[0], ArchiveIndex):
            return len(args[0].names) if name == 'zip.size' else [[ZipInfo(n) for n in args[0].names], 0]
        if name == 'zip.getInputStream' and isinstance(args[0], ArchiveIndex):
            archive, entry = args
            if entry.filename not in archive.certificate_entries:
                raise AnalysisLimit('immutable content requires preparation before runtime')
            return KnownCertificateStream(archive.certificate_entries[entry.filename])
        # A cache miss is a preparation boundary, not a fabricated successful
        # extraction or permission to destroy/rewrite the compiled contents.
        if name == 'fileOutput.new':
            raise AnalysisLimit('immutable content preparation cache invalidated')
        return super()._package(name, *args)


def prepare_content(platform, *, version):
    """Compile an unused, explicit byte platform with no HTTP or host effects.

    The source platform is consumed for offline ZIP preparation only. A new
    platform owns fresh runtime state and the same explicitly declared inputs.
    This function does not turn missing process observations into a snapshot.
    """
    if platform.process is not None or type(platform.environment) is not EnvironmentSimulation:
        raise AnalysisLimit('unused explicit environment required for content preparation')
    env = platform.environment
    # Preserve every archive in the declared installation directory, including
    # entry ordering. Fingerprint comparison still executes for each token.
    parent = platform.application.source_dir.rsplit('/', 1)[0]
    if parent not in platform.directories:
        raise AnalysisLimit('complete installation directory listing required')
    archives = {}
    for name in platform.directories[parent]:
        if name.endswith('.apk'):
            path = platform.path(parent + '/' + name)
            archives[path] = ArchiveIndex.from_bytes(platform._bytes(path))
    process = GuardProcess()
    process.agent.context = platform.service
    process.agent.call.set_app_info('', version)
    platform.bind(process)
    def resolve(effect):
        if effect.kind == 'package_java' and effect.args[0] in ('monitor.enter', 'monitor.exit'):
            return None  # this private preparation has one synchronous caller
        return platform.resolve(effect)
    if run_simulation_steps(check_zip_steps(process.agent, os14=True), resolve, max_effects=None) is not True:
        raise AnalysisLimit('immutable content preparation did not complete')
    files = {path: FileDigests.from_bytes(data)
             if type(data) is bytes and not path.startswith(b'/proc/') else data
             for path, data in env.files.items()}
    new_env = EnvironmentSimulation(pid=env.pid, sdk=env.sdk, manager_class=env.manager_class,
        packages=env.packages, files=files, stat_results=env.stat_results, build=env.build,
        commands=env.commands, file_existence=env.file_existence)
    return PreparedPlatform(archives=archives, environment=new_env, application=platform.application,
        files_dir=platform.files_dir, directories=platform.directories, modified=platform.modified,
        preferences=platform.preferences, abi=platform.abi, phone=platform.phone,
        split_metadata=platform.split_metadata, location=platform.location, write_time=platform.write_time)
