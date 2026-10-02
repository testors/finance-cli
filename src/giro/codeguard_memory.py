"""Explicit memory platform for Python protection runtime experiments.

The supplied files/directories form a complete simulated filesystem namespace
for package preparation. Missing native input observations still remain unknown
in EnvironmentSimulation. No host files, commands, identifiers or SDK are read.
ZIP bytes and signer certificates are parsed, not replaced by successful checks.
Only normal file operations are implemented; unsupported IO/fallback failures
remain boundaries rather than invented Java exceptions.
"""
from dataclasses import dataclass
from io import BytesIO
from zipfile import ZipFile

from .codeguard_fingerprint_values import KnownCertificateStream
from .codeguard_artifacts import FileDigests, DigestStream, DigestRead
from .codeguard_effects import JavaFault
from .codeguard_platform import ReadOnce
from .codeguard_rule import AnalysisLimit


@dataclass(repr=False)
class _Output:
    path: str
    closed: bool = False


class MemoryPlatform:
    def __init__(self, *, environment, application, files_dir, directories,
                 modified, preferences, abi, phone, split_metadata, location, write_time):
        self.environment, self.application = environment, application
        self.service = environment.service
        self.files_dir = self.path(files_dir)
        self.directories = {self.path(k): list(v) for k, v in directories.items()}
        self.modified = {self.path(k): v for k, v in modified.items()}
        self.preferences = dict(preferences)
        self.abi, self.phone = abi, phone
        self.split_metadata, self.location, self.write_time = split_metadata, location, write_time
        self.process = None
        self.errors = {'UnZip': '', 'FingerPrint': ''}
        self.events = []  # operation names only

    @staticmethod
    def path(value):
        # Selected POSIX File path profile; do not resolve dot-dot or host paths.
        while '//' in value:
            value = value.replace('//', '/')
        return value.rstrip('/') or '/'

    def bind(self, process):
        if self.process is not None:
            raise AnalysisLimit('memory platform already belongs to a process')
        self.process = process

    def _bytes(self, path):
        value = self.environment._read(self.environment.files, self.path(path).encode())
        if type(value) is not bytes:
            raise AnalysisLimit('memory file bytes unavailable')
        return value

    def _exists(self, path):
        path = self.path(path)
        return path in self.directories or self.environment.files.get(path.encode()) is not None

    def _list_files(self, path):
        if path not in self.directories: return None
        children = [self.path(path+'/'+name) for name in self.directories[path]]
        # Preparation creates files/directories in this complete memory
        # namespace. Include those children without consulting host paths.
        candidates = [*self.directories, *(p.decode() for p,v in self.environment.files.items() if v is not None)]
        for child in candidates:
            if child != path and child.rsplit('/', 1)[0] == path and child not in children:
                children.append(child)
        return children

    def _delete(self, path):
        if not self._exists(path): return False
        if path in self.directories:
            if self._list_files(path): return False  # File.delete is not recursive
            del self.directories[path]
        else:
            del self.environment.files[path.encode()]
        self.modified.pop(path, None)
        parent, _, name = path.rpartition('/')
        if name in self.directories.get(parent, ()):
            self.directories[parent].remove(name)
        return True

    @staticmethod
    def _read(stream, count):
        data = stream.read(count)
        return ReadOnce(len(data), data) if data else ReadOnce(-1, b'')

    def resolve(self, effect):
        kind, args = effect.kind, effect.args
        self.events.append(kind if kind != 'package_java' else kind + ':' + args[0])
        if kind == 'package_java':
            return self._package(*args)
        if kind == 'process_pid': return self.environment.process_id()
        if kind == 'telephony_service': return self
        if kind == 'telephony_line1_number':
            if isinstance(self.phone, JavaFault): raise self.phone
            return self.phone
        if kind == 'cpu_abi': return self.abi
        if kind == 'native_library_dir': return self.application.library_dir
        if kind == 'application_info': return self.application
        if kind == 'application_native_library_dir': return args[0].library_dir
        if kind == 'preference_read': return self.preferences.get(args[1], args[2])
        if kind == 'preference_write':
            self.preferences[args[1]] = args[2]
            return True if args[3] == 'commit' else None
        if kind == 'file_exists': return self._exists(args[0])
        if kind == 'open_file_input':
            content = self.environment._read(self.environment.files, self.path(args[0]).encode())
            return DigestStream(self, content) if isinstance(content, FileDigests) else BytesIO(self._bytes(args[0]))
        if kind in ('file_available', 'file_read_once', 'close_file_input') and isinstance(args[0], DigestStream):
            stream = args[0]
            if stream.owner is not self or stream.closed:
                raise AnalysisLimit('immutable Java stream lifetime mismatch')
            if kind == 'close_file_input':
                stream.closed = True
                return None
            if kind == 'file_available': return stream.data.size - stream.position
            if stream.position != 0 or args[1] != stream.data.size:
                raise AnalysisLimit('immutable digest metadata requires one complete read')
            stream.position = stream.data.size
            return DigestRead(stream.data)
        if kind == 'file_available': return len(args[0].getbuffer()) - args[0].tell()
        if kind == 'file_read_once': return self._read(*args)
        if kind == 'close_file_input': return args[0].close()
        if kind == 'split_metadata_boolean': return self.split_metadata
        if kind == 'location_text': return self.location
        return self.environment.resolve(effect)

    def _package(self, name, *args):
        agent = self.process.agent
        if name == 'agent.getInstance': return agent
        if name == 'agent.context': return args[0].context
        if name == 'agent.version': return args[0].call.version
        if name == 'main.staticContext': return agent.main.context
        for category in ('UnZip', 'FingerPrint'):
            if name == 'agent.get' + category + 'ErrorMsg': return self.errors[category]
            if name == 'agent.set' + category + 'ErrorMsg':
                self.errors[category] = args[1]
                return None
        if name == 'context.getApplicationInfo': return self.application
        if name == 'applicationInfo.sourceDir': return args[0].source_dir
        if name == 'context.getFilesDir': return self.files_dir
        if name == 'context.getSharedPreferences':
            if args[1:] != ('CodeGuardPref', 0):
                raise AnalysisLimit('unknown memory preference namespace')
            return self.preferences
        if name in ('preferences.getLong', 'preferences.getString'): return args[0].get(args[1], args[2])
        if name == 'preferences.edit': return {}
        if name in ('editor.putLong', 'editor.putString', 'editor.remove'):
            args[0][args[1]] = None if name == 'editor.remove' else args[2]
            return args[0]
        if name == 'editor.commit':
            for key, value in args[0].items():
                if value is None: self.preferences.pop(key, None)
                else: self.preferences[key] = value
            return True  # selected in-memory storage always commits, no disk claim
        if name == 'log.DEBUG': return self.process.log_debug
        if name == 'file.separator': return '/'
        if name == 'file.new': return self.path(args[0])
        if name == 'file.getPath': return args[0]
        if name == 'file.getAbsolutePath':
            if not args[0].startswith('/'):
                raise AnalysisLimit('memory working directory unavailable')
            return args[0]
        if name == 'file.listFiles': return self._list_files(args[0])
        if name == 'file.delete': return self._delete(args[0])
        if name == 'file.exists': return self._exists(args[0])
        if name == 'file.isDirectory': return args[0] in self.directories
        if name == 'file.mkdirs':
            self.directories[args[0]] = []
            return True
        if name == 'file.getParentFile': return args[0].rsplit('/', 1)[0] or '/'
        if name == 'file.list':
            if args[0] not in self.directories:
                raise AnalysisLimit('memory directory listing unavailable')
            return list(self.directories[args[0]])
        if name == 'file.lastModified':
            if args[0] not in self.modified:
                raise AnalysisLimit('memory file timestamp unavailable')
            return self.modified[args[0]]
        if name == 'build.CPU_ABI': return self.abi
        if name == 'zip.new': return ZipFile(BytesIO(self._bytes(args[0])))
        if name == 'zip.size': return len(args[0].infolist())
        if name == 'zip.entries': return [args[0].infolist(), 0]
        if name == 'enumeration.hasMoreElements': return args[0][1] < len(args[0][0])
        if name == 'enumeration.nextElement':
            entries, index = args[0]
            args[0][1] += 1
            return entries[index]
        if name == 'cast.ZipEntry': return args[0]
        if name == 'zipEntry.getName': return args[0].filename
        if name == 'zipEntry.isDirectory': return args[0].is_dir()
        if name == 'zip.getInputStream':
            archive, entry = args
            data = archive.read(entry)
            return KnownCertificateStream(data) if entry.filename.upper().endswith('.RSA') else BytesIO(data)
        if name == 'fileOutput.new':
            path, append = args
            if append: raise AnalysisLimit('memory append not implemented')
            self.environment.files[path.encode()] = b''
            self.modified[path] = self.write_time()
            return _Output(path)
        if name == 'bufferedOutput.new': return args[0]
        if name == 'input.read': return self._read(args[0], args[2])
        if name == 'input.close': return args[0].close()
        if name in ('bufferedOutput.write', 'bufferedOutput.flush', 'bufferedOutput.close'):
            output = args[0]
            if output.closed: raise AnalysisLimit('memory output already closed')
            if name == 'bufferedOutput.write':
                _, data, offset, count = args
                self.environment.files[output.path.encode()] += data[offset:offset + count]
                self.modified[output.path] = self.write_time()
            if name == 'bufferedOutput.close': output.closed = True
            return None
        raise AnalysisLimit('unsupported memory package operation')
