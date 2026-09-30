"""Registered, allowlist-checked documents. Session or raw exchange files never qualify."""
import hashlib

from finance_cli.core import storage
from finance_cli.core.paths import data_home

from . import model


def read_artifact(db, artifact_id):
    with db.read() as con:
        row = con.execute('SELECT * FROM artifacts WHERE id=?', (artifact_id,)).fetchone()
    if row is None:
        raise model.NotFound('artifact_not_found')
    base = data_home().absolute() / 'server' / 'artifacts'
    path = storage.no_symlinks(data_home().absolute() / row['location'])
    if path.parent != base:
        raise model.NotFound('artifact_not_found')
    data = storage.read(path, limit=64 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != row['sha256']:
        raise ValueError('artifact_changed')
    return dict(row), data


def listing(con, *, kind=None, profile_id=None, limit=500):
    """Registered documents with their job and fixed target; never file locations."""
    query = ('SELECT a.id, a.job_id, a.kind, a.filename, a.media_type, a.size, a.complete, a.created_at, j.name, j.result,'
             ' j.snapshot, j.target_id, j.profile_id FROM artifacts a JOIN jobs j ON j.id=a.job_id')
    clauses, args = [], []
    if kind:
        clauses.append('a.kind=?')
        args.append(kind)
    if profile_id:
        clauses.append('(j.profile_id=? OR j.target_id IN (SELECT target_id FROM profile_targets WHERE profile_id=?))')
        args += [profile_id, profile_id]
    if clauses:
        query += ' WHERE ' + ' AND '.join(clauses)
    from . import adapters
    from .db import loads
    rows = []
    for row in con.execute(query + ' ORDER BY a.created_at DESC LIMIT ?', (*args, limit)):
        result = loads(row['result'], {}) or {}
        snapshot = loads(row['snapshot'], {}) or {}
        document = next((index + 1 for index, item in enumerate(result.get('documents') or [])
                         if isinstance(item, dict) and item.get('artifact_id') == row['id']), None)
        adapter = adapters.get(row['name'])
        rows.append({'id': row['id'], 'job_id': row['job_id'], 'kind': row['kind'], 'filename': row['filename'],
                     'media_type': row['media_type'], 'size': row['size'], 'complete': row['complete'],
                     'created_at': row['created_at'], 'job_title': adapter.title if adapter else row['name'],
                     'target_name': (snapshot.get('target') or {}).get('display_name'), 'document': document})
    return rows
