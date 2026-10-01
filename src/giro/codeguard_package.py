"""Package preparation/fingerprint control flow over explicit Java effects.

This module opens no files and supplies no installed package observations.
It keeps provider/IO/monitor effects unresolved rather than assuming success.
Logging failures, allocation failures and unrepresented Java Error subclasses
remain outside this bounded model. Effects and state must not be logged raw.
"""
import base64

from .codeguard_effects import Effect, JavaFault, LinkFault, observed_bool, java_length
from .codeguard_flow import java_text, java_substring, JavaStageError
from .codeguard_platform import ReadOnce
from .codeguard_rule import AnalysisLimit
from .codeguard_updater import runtime_fault
from .codeguard_worker import java_split_literal


def _call(name, *args):
    return Effect('package_java', (name, *args))


def _text(value):
    if value is not None and type(value) is not str:
        raise AnalysisLimit('observed Java String or null required')
    return value


def _nonnull(value, site):
    _text(value)
    if value is None:
        yield from runtime_fault('NullPointerException', site)
    return value


def _long(value):
    if type(value) is not int or not -2**63 <= value < 2**63:
        raise AnalysisLimit('observed Java long required')
    return value


def _error_setter(kind, message):
    agent = yield _call('agent.getInstance')
    yield _call('agent.set'+kind+'ErrorMsg', agent, message)


def _source_dir(context):
    info = yield _call('context.getApplicationInfo', context)
    return _text((yield _call('applicationInfo.sourceDir', info)))


def _files_path(context):
    directory = yield _call('context.getFilesDir', context)
    return _text((yield _call('file.getPath', directory)))


def _destination(value):
    _text(value)
    separator = _text((yield _call('file.separator')))
    value = yield from _nonnull(value, 'package.destination.endsWith')
    separator = yield from _nonnull(separator, 'package.separator')
    if value.endswith(separator):
        return value
    # The append expression performs another static field read.
    return value+java_text(_text((yield _call('file.separator'))))


def _directory_entry(entry, target):
    if observed_bool((yield _call('zipEntry.isDirectory', entry))):
        if not observed_bool((yield _call('file.isDirectory', target))):
            yield _call('file.mkdirs', target)  # false ignored
        return True
    parent = yield _call('file.getParentFile', target)
    if parent is not None and not observed_bool((yield _call('file.isDirectory', parent))):
        yield _call('file.mkdirs', parent)
    return False


def _output(target):
    raw = yield _call('fileOutput.new', target, False)
    return (yield _call('bufferedOutput.new', raw, 1024))


def _copy_loop(source, output):
    while True:
        read = yield _call('input.read', source, 0, 1024)
        if (not isinstance(read, ReadOnce) or type(read.count) is not int
                or not -1 <= read.count <= 1024 or type(read.data) is not bytes
                or len(read.data) != max(read.count, 0)):
            raise AnalysisLimit('actual Java read count and written bytes required')
        if read.count == -1:
            return
        yield _call('bufferedOutput.write', output, read.data, 0, read.count)


def _close_input(source, *, ignore_io):
    if source is not None:
        try:
            yield _call('input.close', source)
        except JavaFault as fault:
            if not ignore_io or not fault.is_instance('IOException'):
                raise


def _copy_cleanup(source, output, mode):
    if mode != 'stream':
        yield from _close_input(source, ignore_io=mode == 'metadata')
    yield _call('bufferedOutput.flush', output)
    yield _call('bufferedOutput.close', output)


def _copy_entry(archive, entry, output, *, mode):
    source = archive if mode == 'stream' else None
    if mode == 'library':
        # Library open sits outside the per-entry read catch/finally.
        source = yield _call('zip.getInputStream', archive, entry)
    try:
        if mode == 'metadata':
            source = yield _call('zip.getInputStream', archive, entry)
        yield from _copy_loop(source, output)
        if mode == 'stream':
            yield _call('zipInput.closeEntry', source)
    except (JavaFault, LinkFault) as fault:
        if isinstance(fault, JavaFault):
            try:
                yield from _error_setter('UnZip', fault.message)
            except (JavaFault, LinkFault):
                yield from _copy_cleanup(source, output, mode)
                raise
            yield from _copy_cleanup(source, output, mode)
            return False
        yield from _copy_cleanup(source, output, mode)
        raise
    # Unknown Python/observation failures do not authorize invented cleanup.
    yield from _copy_cleanup(source, output, mode)
    return True


def _metadata_target(destination, name, *, stream=False):
    path = destination+java_text(_text(name))
    if not any(part in path for part in ('classes.dex', '.MF', '.SF')):
        return None
    if not stream:
        for part, suffix in (('libCodeGuard.so','/lib/libCodeGuard.so'),
                             ('libImageDecoder.so','/lib/libImageDecoder.so'),
                             ('.SF','/META-INF/CERT.SF')):
            if part in path:
                return destination+suffix
    return path


def library_entries_steps(archive, destination):
    """Preserve enumeration order/overwrites and per-entry sticky failure."""
    try:
        destination = yield from _destination(destination)
        directory = yield _call('file.new', destination)
        if not observed_bool((yield _call('file.isDirectory', directory))):
            yield _call('file.mkdirs', directory)
        abi = ''
        try:
            abi = _text((yield _call('build.CPU_ABI')))
        except JavaFault:
            pass
        entries = yield _call('zip.entries', archive)
        if entries is None:
            return True
        success = True
        while observed_bool((yield _call('enumeration.hasMoreElements', entries))):
            entry = yield _call('enumeration.nextElement', entries)
            entry = yield _call('cast.ZipEntry', entry)
            name = _text((yield _call('zipEntry.getName', entry)))
            path = destination+java_text(name)
            contains_abi = yield from _nonnull(abi, 'package.path.containsABI')
            if contains_abi not in path:
                continue
            library = next((x for x in ('libCodeGuard.so','libImageDecoder.so') if x in path), None)
            if library is None:
                continue
            target = yield _call('file.new', destination+'/lib/'+library)
            yield _call('file.getPath', target)  # evaluated for the original log
            if (yield from _directory_entry(entry, target)):
                continue
            output = yield from _output(target)
            copied = yield from _copy_entry(archive, entry, output, mode='library')
            success = success and copied
        return success
    except JavaFault as fault:
        yield from _error_setter('UnZip', fault.message)
        return False


def _directory_listing(path, *, require_directory):
    directory = yield _call('file.new', path)
    if not observed_bool((yield _call('file.exists', directory))):
        return None
    if require_directory and not observed_bool((yield _call('file.isDirectory', directory))):
        return None
    names = yield _call('file.list', directory)
    if names is not None and type(names) not in (list, tuple):
        raise AnalysisLimit('observed Java filename array or null required')
    return names


def prepare_libraries_steps(context, destination):
    source = yield from _nonnull((yield from _source_dir(context)), 'package.sourceDir.indexOf')
    if 'base.apk' not in source:
        return
    directory = source.split('base.apk', 1)[0]
    names = yield from _directory_listing(directory, require_directory=True)
    if names is None:
        return
    for name in names:
        name = yield from _nonnull(name, 'package.filename.contains')
        if '.apk' not in name:
            continue
        try:
            archive = yield _call('zip.new', directory+'/'+name)
            yield from library_entries_steps(archive, destination)  # bool ignored
        except JavaFault:
            pass


def _metadata_stream(source, destination):
    stream = None
    try:
        raw = yield _call('fileInput.new', source)
        buffered = yield _call('bufferedInput.new', raw, 1024)
        stream = yield _call('zipInput.new', buffered)
        while True:
            entry = yield _call('zipInput.getNextEntry', stream)
            if entry is None:
                break
            name = _text((yield _call('zipEntry.getName', entry)))
            path = _metadata_target(destination, name, stream=True)
            if path is None:
                continue
            target = yield _call('file.new', path)
            if (yield from _directory_entry(entry, target)):
                continue
            output = yield from _output(target)
            yield from _copy_entry(stream, entry, output, mode='stream')
    except (JavaFault, LinkFault) as fault:
        if isinstance(fault, JavaFault):
            try:
                yield from _error_setter('UnZip', fault.message)
            except (JavaFault, LinkFault):
                yield from _close_input(stream, ignore_io=True)
                raise
            yield from _close_input(stream, ignore_io=True)
            return False
        yield from _close_input(stream, ignore_io=True)
        raise
    yield from _close_input(stream, ignore_io=True)
    # Fallback inherits false from the primary attempt and never resets it.
    return False


def prepare_metadata_steps(source, destination):
    """Primary ZipFile then stream fallback, preserving partial writes.

    No filesystem rollback, added retries, path filtering or archive sorting.
    IO effects are descriptions only; they must not be auto-executed on a host.
    """
    try:
        if not _text(source) or not _text(destination):
            return True
        destination = yield from _destination(destination)
        directory = yield _call('file.new', destination)
        if not observed_bool((yield _call('file.exists', directory))):
            return False
        if not observed_bool((yield _call('file.isDirectory', directory))):
            yield _call('file.mkdirs', directory)
        try:
            archive = yield _call('zip.new', source)
            size = yield _call('zip.size', archive)
            if type(size) is not int or not -2**31 <= size < 2**31:
                raise AnalysisLimit('observed Java zip size required')
            if size <= 0:
                return False
            entries = yield _call('zip.entries', archive)
            if entries is None or not observed_bool((yield _call('enumeration.hasMoreElements', entries))):
                return False
            success = True
            while observed_bool((yield _call('enumeration.hasMoreElements', entries))):
                entry = yield _call('enumeration.nextElement', entries)
                entry = yield _call('cast.ZipEntry', entry)
                if entry is None:
                    continue
                name = _text((yield _call('zipEntry.getName', entry)))
                path = _metadata_target(destination, name)
                if path is None:
                    continue
                target = yield _call('file.new', path)
                yield _call('file.getPath', target)
                if (yield from _directory_entry(entry, target)):
                    continue
                output = yield from _output(target)
                copied = yield from _copy_entry(archive, entry, output, mode='metadata')
                success = success and copied
            if success:
                return True
        except JavaFault:
            pass  # primary outer failure does not set the error field here
        return (yield from _metadata_stream(source, destination))
    except JavaFault as fault:
        yield from _error_setter('UnZip', fault.message)
        return False


def _zip_body(agent, *, os14):
    context = yield _call('agent.context', agent)
    if context is None:
        return False
    context = yield _call('agent.context', agent)
    dex = yield _call('file.new', java_text((yield from _files_path(context)))+'/classes.dex')
    context = yield _call('agent.context', agent)
    source = yield from _source_dir(context)
    package = yield _call('file.new', source)
    modified = _long((yield _call('file.lastModified', package)))
    context = yield _call('agent.context', agent)
    prefs = yield _call('context.getSharedPreferences', context, 'CodeGuardPref', 0)
    saved = _long((yield _call('preferences.getLong', prefs, 'apk_last', 0)))
    dex_modified = 0
    if observed_bool((yield _call('file.exists', dex))):
        dex_modified = _long((yield _call('file.lastModified', dex)))
        yield _call('file.getPath', dex)
    version = _text((yield _call('preferences.getString', prefs, 'app_version', '0')))
    yield _call('agent.version', agent)  # read for the original log
    debug = observed_bool((yield _call('log.DEBUG')))
    if (not debug and observed_bool((yield _call('file.exists', dex)))
            and modified == saved and modified <= dex_modified):
        current = _text((yield _call('agent.version', agent)))
        version = yield from _nonnull(version, 'package.version.equals')
        if version == current:
            return True
    try:
        context = yield _call('agent.context', agent)
        destination = yield from _files_path(context)
        yield from prepare_libraries_steps(context, destination)
        context = yield _call('agent.context', agent)
        destination = yield from _files_path(context)
        prepared = yield from prepare_metadata_steps(source, destination)
        editor = yield _call('preferences.edit', prefs)
        if prepared:
            yield _call('editor.putLong', editor, 'apk_last', modified)
            current = _text((yield _call('agent.version', agent)))
            yield _call('editor.putString', editor, 'app_version', current)
        else:
            yield _call('editor.remove', editor, 'apk_last')
            yield _call('editor.remove', editor, 'app_version')
        return observed_bool((yield _call('editor.commit', editor)))
    except JavaFault:
        if not os14:
            raise
        return False


def check_zip_steps(agent, *, os14):
    """Same monitor for checkZip and checkZipOS14; no scheduling assumptions."""
    observed_bool(os14)
    yield _call('monitor.enter', agent)
    try:
        result = yield from _zip_body(agent, os14=os14)
    except (JavaFault, LinkFault):
        yield _call('monitor.exit', agent)
        raise
    yield _call('monitor.exit', agent)
    return result


def _ignore_case(value, expected):
    value = yield from _nonnull(value, 'package.entry.equalsIgnoreCase')
    if value.isascii():
        return value.lower() == expected.lower()
    return observed_bool((yield _call('string.equalsIgnoreCase', value, expected)))


def fingerprint_certificate_steps(stream):
    factory = yield _call('certificateFactory.getInstance', 'X.509')
    cert = yield _call('certificateFactory.generateCertificate', factory, stream)
    cert = yield _call('cast.X509Certificate', cert)
    digest = yield _call('messageDigest.getInstance', 'SHA256')
    encoded = yield _call('certificate.getEncoded', cert)
    yield _call('messageDigest.update', digest, encoded)
    value = yield _call('messageDigest.digest', digest)
    if value is None:
        yield from runtime_fault('NullPointerException', 'package.fingerprint.base64')
    if type(value) is not bytes:
        raise AnalysisLimit('observed Java digest array required')
    return base64.b64encode(value).decode('ascii')  # Android NO_WRAP, padding kept


def check_fingerprint_steps(context):
    source = yield from _nonnull((yield from _source_dir(context)), 'package.sourceDir.indexOf')
    if 'base.apk' not in source:
        return True
    directory = source.split('base.apk', 1)[0]
    if not directory:
        return True
    names = yield from _directory_listing(directory, require_directory=False)
    if names is None:
        return True
    first = None
    for name in names:
        name = yield from _nonnull(name, 'package.filename.contains')
        if '.apk' not in name:
            continue
        try:
            if not name.endswith('.apk'):
                continue
            archive = yield _call('zip.new', directory+'/'+name)
            entries = yield _call('zip.entries', archive)
            while observed_bool((yield _call('enumeration.hasMoreElements', entries))):
                entry = yield _call('enumeration.nextElement', entries)
                entry = yield _call('cast.ZipEntry', entry)
                text = yield from _nonnull((yield _call('zipEntry.getName', entry)), 'package.entry.split')
                parts = java_split_literal(text, '/')
                if not parts:
                    yield from runtime_fault('ArrayIndexOutOfBoundsException', 'package.entry.firstPart')
                if not (yield from _ignore_case(parts[0], 'META-INF')):
                    continue
                text = yield from _nonnull((yield _call('zipEntry.getName', entry)), 'package.entry.substring')
                other = yield from _nonnull((yield _call('zipEntry.getName', entry)), 'package.entry.indexOf')
                dot = other.find('.')
                start = 0 if dot < 0 else java_length(other[:dot])+1
                try:
                    suffix = java_substring(text, start)
                except JavaStageError:
                    yield from runtime_fault('StringIndexOutOfBoundsException', 'package.entry.substring')
                if not (yield from _ignore_case(suffix, 'RSA')):
                    continue
                stream = yield _call('zip.getInputStream', archive, entry)
                try:
                    fingerprint = yield from fingerprint_certificate_steps(stream)
                except JavaFault:
                    fingerprint = ''
                if first is None:
                    first = fingerprint
                elif first != fingerprint:
                    yield from _error_setter('FingerPrint', fingerprint)
                    return False
        except JavaFault:
            pass  # keep prior first fingerprint; proceed to the next archive
    return True


def _project_package_steps(generator):
    """Expand package checks without starting IO, JNI or a worker thread."""
    value, pending = None, None
    while True:
        try:
            effect = generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as finished:
            return finished.value
        pending = None
        try:
            if effect.kind == 'check_zip_os14':
                agent = yield _call('agent.getInstance')
                value = yield from check_zip_steps(agent, os14=True)
            elif effect.kind == 'check_fingerprint':
                context = yield _call('main.staticContext')
                value = yield from check_fingerprint_steps(context)
            elif effect.kind in ('zip_error_message', 'fingerprint_error_message'):
                agent = yield _call('agent.getInstance')
                kind = 'UnZip' if effect.kind == 'zip_error_message' else 'FingerPrint'
                value = yield _call('agent.get'+kind+'ErrorMsg', agent)
            else:
                value = yield effect
        except Exception as fault:
            pending = fault


def project_package_steps(generator, *, certificate_values=False):
    """Expand package checks, optionally calculating known certificate bytes.

    The value backend requires explicit KnownCertificateStream inputs from
    the caller. Installed archive/file observations remain external.
    """
    body = _project_package_steps(generator)
    if certificate_values:
        from .codeguard_fingerprint_values import project_fingerprint_values_steps
        return (yield from project_fingerprint_values_steps(body))
    return (yield from body)
