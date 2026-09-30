"""User-supplied files for jobs, referenced by server-issued IDs only."""
import hashlib

from finance_cli.core import storage
from finance_cli.core.paths import data_home

from . import model
from .config import private_directory
from .db import new_id, now

KINDS = {'giro_bills': {'limit': 2 * 1024 * 1024, 'media_types': ('application/json', 'text/plain')}}


def store_upload(db, kind, data, origin, filename=None):
    if kind not in KINDS:
        raise ValueError('unsupported_upload_kind')
    if not data or len(data) > KINDS[kind]['limit']:
        raise ValueError('upload_size_not_accepted')
    upload_id = new_id('up')
    target = private_directory('uploads') / upload_id
    storage.write_new(target, data)
    name = filename if isinstance(filename, str) and 0 < len(filename) <= 120 and '/' not in filename else None
    with db.write() as con:
        con.execute('INSERT INTO uploads(id, kind, filename, location, size, sha256, origin, created_at)'
                    ' VALUES (?,?,?,?,?,?,?,?)', (upload_id, kind, name, str(target.relative_to(data_home().absolute())),
                                                  len(data), hashlib.sha256(data).hexdigest(), origin, now()))
    return {'id': upload_id, 'kind': kind, 'size': len(data), 'filename': name}


def read_upload(db, upload_id, kind):
    with db.read() as con:
        row = con.execute('SELECT * FROM uploads WHERE id=?', (upload_id,)).fetchone()
    if row is None or row['kind'] != kind:
        raise model.NotFound('upload_not_found')
    data = storage.read(data_home().absolute() / row['location'], limit=KINDS[kind]['limit'])
    if hashlib.sha256(data).hexdigest() != row['sha256']:
        raise ValueError('upload_changed')
    return data
