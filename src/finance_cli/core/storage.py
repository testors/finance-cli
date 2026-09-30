"""Private POSIX files, atomic replacement and explicit exclusive locks."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import tempfile


def no_symlinks(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('symlink_not_allowed')
    return path


def directory(path):
    path = no_symlinks(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError('private_directory_required')
    return path


def read(path, limit=32 * 1024 * 1024):
    path = no_symlinks(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError('private_file_required')
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('input_too_large')
    return data


def sync(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, data):
    path = no_symlinks(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    sync(path.parent)


def read_json(path):
    return json.loads(read(path))


def atomic_json(path, value):
    path = no_symlinks(path)
    fd, pending = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
        sync(path.parent)
    finally:
        if os.path.exists(pending):
            os.unlink(pending)


_held = set()


@contextmanager
def hold(path):
    """Keep a lock for a worker that already owns the resource.

    Only lock() calls on this exact path inside the same process reuse it;
    every other acquisition keeps failing immediately.
    """
    path = no_symlinks(path)
    if path in _held:
        raise ValueError('lock_already_held')
    with lock(path):
        _held.add(path)
        try:
            yield
        finally:
            _held.discard(path)


@contextmanager
def lock(path):
    import fcntl
    path = no_symlinks(path)
    if path in _held:
        yield
        return
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)
