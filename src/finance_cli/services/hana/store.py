"""Private, write-once Hana records below the user data home.

Sessions hold one app-auth identity, cookies and one directory per request.
Runs hold the draft, attempt and outcome of a single read-only operation.
A record is never rewritten and a failed or unknown attempt is never resumed.
"""
import hashlib
import json
from pathlib import Path
import re

from finance_cli.core import storage
from finance_cli.core.paths import data_home

NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')


def name(value):
    if not isinstance(value, str) or NAME.fullmatch(value) is None:
        raise ValueError('invalid_name')
    return value


def root(kind):
    return data_home().absolute() / 'hana' / kind


def session_path(value, *, new=False):
    path = root('sessions') / name(value)
    storage.no_symlinks(path)
    if new:
        if path.exists():
            raise ValueError('session_exists')
        for part in (data_home(), data_home() / 'hana', root('sessions')):
            storage.directory(part)
        path.mkdir(mode=0o700)
    elif not path.is_dir():
        raise ValueError('session_not_found')
    return path


def run_path(value):
    return root('runs') / name(value)


def child(directory, *parts):
    """A path inside a private record directory; never follows a symlink."""
    path = storage.no_symlinks(Path(directory).joinpath(*parts))
    if not path.is_relative_to(Path(directory).absolute()):
        raise ValueError('path_outside_record_directory')
    return path


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def write_new(path, value):
    data = value if isinstance(value, bytes) else (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    storage.write_new(path, data)


def read_json(path):
    return json.loads(storage.read(path))


def make_directory(path):
    """Create one record directory exclusively; an existing one marks an attempt."""
    path = storage.no_symlinks(path)
    parent = path.parent
    if not parent.is_dir():
        for part in reversed([p for p in (parent, *parent.parents) if not p.exists()]):
            part.mkdir(mode=0o700)
    path.mkdir(mode=0o700)
    return path


def lock(session):
    return storage.lock(child(session, 'operation.lock'))


def relative(path):
    return str(Path(path).absolute().relative_to(root('sessions').parent))


def read_input(path):
    """A user-supplied JSON input; it may live anywhere the user chooses."""
    return json.loads(Path(path).expanduser().read_text(encoding='utf-8'))
