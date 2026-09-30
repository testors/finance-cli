"""Institution logins, verified targets, business profiles and session metadata.

Targets are only registered from a finished verification job's stored result,
never from identifiers a browser sends. Profile names and types are display
data; nothing here infers a person, business or permission from them.
"""
import re
import unicodedata

from .db import dumps, loads, new_id, now
from .institutions import INSTITUTIONS, PURPOSES, institution

PROFILE_KINDS = ('personal', 'sole_proprietor', 'corporation')
SESSION_STATES = ('usable', 'consumed', 'expired', 'stale')
REGISTRATION_KEY = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')


class Conflict(ValueError):
    """The stored state changed; the caller must reload and decide again."""


class NotFound(ValueError):
    pass


def display_name(value, limit=60):
    if not isinstance(value, str):
        raise ValueError('invalid_display_name')
    value = unicodedata.normalize('NFC', value).strip()
    if not value or len(value) > limit or any(unicodedata.category(c).startswith('C') for c in value):
        raise ValueError('invalid_display_name')
    return value


def credential_ref(kind, ref):
    """A typed vault reference; secrets and file paths never enter the database."""
    if kind == 'joint':
        from finance_cli.credentials.registry import Registry, name
        entry = Registry().entry(name(ref))
        return {'type': 'joint', 'ref': ref, 'fingerprint': entry['certificate_id']}
    if kind == 'onesign':
        from finance_cli.services.hana import store
        if not (store.root('identities') / store.name(ref)).is_dir():
            raise ValueError('onesign_identity_not_found')
        return {'type': 'onesign', 'ref': ref, 'fingerprint': None}
    raise ValueError('unsupported_credential_type')


def login_row(row, pointer=None):
    if row is None:
        return None
    value = dict(row)
    for key in ('credential', 'signing', 'registration'):
        value[key] = loads(value[key], {} if key != 'credential' else None)
    value['disabled'] = bool(value['disabled'])
    value['registration'] = {k: {'configured': bool(v)} for k, v in value['registration'].items()}
    value['current_session_id'] = pointer
    return value


def get_login(con, login_id, *, raw=False):
    row = con.execute('SELECT * FROM logins WHERE id=?', (login_id,)).fetchone()
    if row is None:
        raise NotFound('login_not_found')
    if raw:
        return row
    pointer = con.execute('SELECT session_id FROM session_pointers WHERE login_id=?', (login_id,)).fetchone()
    return login_row(row, pointer[0] if pointer else None)


def list_logins(con):
    pointers = dict(con.execute('SELECT login_id, session_id FROM session_pointers').fetchall())
    return [login_row(r, pointers.get(r['id'])) for r in con.execute('SELECT * FROM logins ORDER BY created_at, id')]


def _method(spec, method):
    if method not in spec['methods']:
        raise ValueError('unsupported_login_method')
    return spec['methods'][method]


def _signing(spec, values):
    result = {}
    for purpose, value in (values or {}).items():
        if purpose not in PURPOSES or purpose == 'login' or purpose not in spec['purposes']:
            raise ValueError('unsupported_signing_purpose')
        if value is None:
            continue
        method = value.get('method') if isinstance(value, dict) else None
        if method not in spec['purposes'][purpose]:
            raise ValueError('unsupported_signing_method')
        result[purpose] = {'method': method, **credential_ref(spec['methods'][method]['credential'], value.get('credential'))}
    return result


def create_login(con, *, institution_name, method, name, credential=None, channel=None, signing=None, source=None):
    spec = institution(institution_name)
    item = _method(spec, method)
    if channel not in spec['channels']:
        raise ValueError('unsupported_channel')
    ref = credential_ref(item['credential'], credential) if credential is not None else None
    if source is not None and con.execute('SELECT 1 FROM logins WHERE source=?', (source,)).fetchone():
        raise Conflict('login_source_exists')
    login_id, at = new_id('lg'), now()
    con.execute('INSERT INTO logins(id, institution, channel, method, display_name, credential, signing, registration,'
                ' revision, disabled, source, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,1,0,?,?,?)',
                (login_id, institution_name, channel, method, display_name(name), dumps(ref),
                 dumps(_signing(spec, signing)), '{}', source, at, at))
    return get_login(con, login_id)


def update_login(con, login_id, *, expected_revision, name=None, credential=None, signing=None, channel=None,
                 disabled=None, registration=None):
    row = get_login(con, login_id, raw=True)
    if expected_revision != row['revision']:
        raise Conflict('revision_conflict')
    spec = INSTITUTIONS[row['institution']]
    changes, bump = {}, False
    if name is not None:
        changes['display_name'] = display_name(name)
    if credential is not None:
        changes['credential'] = dumps(credential_ref(_method(spec, row['method'])['credential'], credential))
        bump = True
    if signing is not None:
        merged = {**loads(row['signing'], {}), **_signing(spec, signing)}
        for purpose, value in signing.items():
            if value is None:
                merged.pop(purpose, None)
        changes['signing'] = dumps(merged)
        bump = True
    if channel is not None:
        if channel not in spec['channels']:
            raise ValueError('unsupported_channel')
        changes['channel'] = channel
        bump = True
    if registration is not None:
        allowed = _method(spec, row['method'])['registration']
        stored = loads(row['registration'], {})
        for key, value in registration.items():
            if key not in allowed or (value is not None and not REGISTRATION_KEY.fullmatch(str(value))):
                raise ValueError('unsupported_registration')
            if value is None:
                stored.pop(key, None)
            else:
                stored[key] = value
        changes['registration'] = dumps(stored)
        bump = True
    if disabled is not None:
        changes['disabled'] = 1 if disabled else 0
    if bump:
        changes['revision'] = _bump(con, login_id, row['revision'])
    if changes:
        changes['updated_at'] = now()
        con.execute('UPDATE logins SET ' + ', '.join(f'{k}=?' for k in changes) + ' WHERE id=?',
                    (*changes.values(), login_id))
    return get_login(con, login_id)


def _bump(con, login_id, revision):
    """Execution settings changed: sessions need re-checking, prepared drafts expire."""
    con.execute("UPDATE sessions SET state='stale', note='login_revision_changed' "
                "WHERE login_id=? AND state='usable'", (login_id,))
    con.execute("UPDATE jobs SET status='expired', local=json_set(local, '$.expired_reason', 'login_revision_changed'),"
                " awaiting=NULL, updated_at=? WHERE login_id=? AND status='awaiting_input'", (now(), login_id))
    return revision + 1


def registration_value(con, login_id, key):
    row = get_login(con, login_id, raw=True)
    return loads(row['registration'], {}).get(key)


# Targets

MASKED_IDENTITY = ('tin', 'account_number', 'business_number')


def masked_identity(identity):
    """Identity as shown to browsers; the stored value stays server-side."""
    from .adapters.base import mask_account
    if not isinstance(identity, dict):
        return identity
    return {k: (mask_account(v) if k in MASKED_IDENTITY and v and '•' not in str(v) else v) for k, v in identity.items()}


def target_row(row):
    if row is None:
        return None
    value = dict(row)
    value['identity'] = masked_identity(loads(value['identity'], {}))
    value['signing'] = loads(value['signing'], {})
    value['disabled'] = bool(value['disabled'])
    value.pop('identity_key', None)
    return value


def get_target(con, target_id, *, raw=False):
    row = con.execute('SELECT * FROM targets WHERE id=?', (target_id,)).fetchone()
    if row is None:
        raise NotFound('target_not_found')
    return row if raw else target_row(row)


def list_targets(con, login_id=None):
    query, args = 'SELECT * FROM targets', ()
    if login_id:
        query, args = query + ' WHERE login_id=?', (login_id,)
    return [target_row(r) for r in con.execute(query + ' ORDER BY created_at, id', args)]


def register_target(con, login_id, job, candidate_ref, name=None):
    """Register one candidate that a finished verification job observed."""
    login = get_login(con, login_id, raw=True)
    if job['login_id'] != login_id or job['status'] != 'finished':
        raise ValueError('verification_job_required')
    candidates = (loads(job['attempt'], {}) or {}).get('target_candidates') or []
    found = [c for c in candidates if isinstance(c, dict) and c.get('ref') == candidate_ref]
    if len(found) != 1:
        raise ValueError('candidate_not_found')
    candidate = found[0]
    if candidate.get('kind') not in INSTITUTIONS[login['institution']]['target_kinds']:
        raise ValueError('unsupported_target_kind')
    at = now()
    existing = con.execute('SELECT * FROM targets WHERE login_id=? AND identity_key=?',
                           (login_id, candidate['identity_key'])).fetchone()
    if existing:
        con.execute('UPDATE targets SET identity=?, verified_at=?, source_job_id=?, updated_at=? WHERE id=?',
                    (dumps(candidate['identity']), job['observed_at'] or at, job['id'], at, existing['id']))
        return get_target(con, existing['id'])
    target_id = new_id('tg')
    con.execute('INSERT INTO targets(id, login_id, kind, identity, identity_key, display_name, signing, verified_at,'
                ' source_job_id, disabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,0,?,?)',
                (target_id, login_id, candidate['kind'], dumps(candidate['identity']), candidate['identity_key'],
                 display_name(name or candidate['label']), '{}', job['observed_at'] or at, job['id'], at, at))
    return get_target(con, target_id)


def update_target(con, target_id, *, expected_revision=None, name=None, signing=None, disabled=None):
    row = get_target(con, target_id, raw=True)
    changes = {}
    if name is not None:
        changes['display_name'] = display_name(name)
    if disabled is not None:
        changes['disabled'] = 1 if disabled else 0
        if disabled:
            # A disabled target cannot be the subject of a pending confirmation.
            con.execute("UPDATE jobs SET status='expired', local=json_set(local, '$.expired_reason', 'target_disabled'),"
                        " awaiting=NULL, updated_at=? WHERE target_id=? AND status='awaiting_input'", (now(), target_id))
    if signing is not None:
        login = get_login(con, row['login_id'], raw=True)
        if expected_revision != login['revision']:
            raise Conflict('revision_conflict')
        merged = {**loads(row['signing'], {}), **_signing(INSTITUTIONS[login['institution']], signing)}
        for purpose, value in signing.items():
            if value is None:
                merged.pop(purpose, None)
        changes['signing'] = dumps(merged)
        # Target signing is part of the login revision.
        con.execute('UPDATE logins SET revision=?, updated_at=? WHERE id=?',
                    (_bump(con, login['id'], login['revision']), now(), login['id']))
    if changes:
        changes['updated_at'] = now()
        con.execute('UPDATE targets SET ' + ', '.join(f'{k}=?' for k in changes) + ' WHERE id=?',
                    (*changes.values(), target_id))
    return get_target(con, target_id)


def signing_for(con, login, target, purpose):
    """The explicit signing reference: target setting first, then the login default."""
    if purpose == 'login':
        return loads(login['credential'])
    if target is not None:
        value = loads(target['signing'], {}).get(purpose)
        if value:
            return value
    return loads(login['signing'], {}).get(purpose)


# Business profiles

def profile_row(con, row):
    value = dict(row)
    value['disabled'] = bool(value['disabled'])
    value['target_ids'] = [r[0] for r in con.execute(
        'SELECT target_id FROM profile_targets WHERE profile_id=? ORDER BY target_id', (row['id'],))]
    return value


def get_profile(con, profile_id):
    row = con.execute('SELECT * FROM profiles WHERE id=?', (profile_id,)).fetchone()
    if row is None:
        raise NotFound('profile_not_found')
    return profile_row(con, row)


def list_profiles(con):
    return [profile_row(con, r) for r in con.execute('SELECT * FROM profiles ORDER BY created_at, id')]


def _profile_kind(kind):
    if kind not in (None, *PROFILE_KINDS):
        raise ValueError('unsupported_profile_kind')
    return kind


def _set_targets(con, profile_id, target_ids):
    if not isinstance(target_ids, list) or len(set(target_ids)) != len(target_ids) or len(target_ids) > 200:
        raise ValueError('invalid_target_ids')
    for target_id in target_ids:
        get_target(con, target_id, raw=True)
    con.execute('DELETE FROM profile_targets WHERE profile_id=?', (profile_id,))
    con.executemany('INSERT INTO profile_targets(profile_id, target_id) VALUES (?, ?)',
                    [(profile_id, t) for t in target_ids])


def create_profile(con, *, name, kind=None, target_ids=()):
    profile_id, at = new_id('pf'), now()
    con.execute('INSERT INTO profiles(id, name, kind, disabled, created_at, updated_at) VALUES (?,?,?,0,?,?)',
                (profile_id, display_name(name), _profile_kind(kind), at, at))
    _set_targets(con, profile_id, list(target_ids))
    return get_profile(con, profile_id)


def update_profile(con, profile_id, *, name=None, kind=..., target_ids=None, disabled=None):
    get_profile(con, profile_id)
    changes = {}
    if name is not None:
        changes['name'] = display_name(name)
    if kind is not ...:
        changes['kind'] = _profile_kind(kind)
    if disabled is not None:
        changes['disabled'] = 1 if disabled else 0
    if target_ids is not None:
        _set_targets(con, profile_id, target_ids)
    changes['updated_at'] = now()
    con.execute('UPDATE profiles SET ' + ', '.join(f'{k}=?' for k in changes) + ' WHERE id=?',
                (*changes.values(), profile_id))
    return get_profile(con, profile_id)


# Sessions

def session_row(row):
    value = dict(row)
    value.pop('location', None)
    value.pop('name', None)
    value['current_target'] = masked_identity(loads(value['current_target']))
    value['verdict'] = loads(value['verdict'])
    return value


def list_sessions(con, login_id):
    get_login(con, login_id, raw=True)
    pointer = con.execute('SELECT session_id FROM session_pointers WHERE login_id=?', (login_id,)).fetchone()
    rows = [session_row(r) for r in con.execute(
        'SELECT * FROM sessions WHERE login_id=? ORDER BY created_at DESC, id', (login_id,))]
    return {'login_id': login_id, 'current_session_id': pointer[0] if pointer else None, 'sessions': rows,
            'current_validity': 'unverified_until_next_request'}


def add_session(con, *, login_id, location, revision, job_id, state='usable', verdict=None, current_target=None,
                name=None):
    if state not in SESSION_STATES:
        raise ValueError('invalid_session_state')
    session_id, at = new_id('ss'), now()
    con.execute('INSERT INTO sessions(id, login_id, state, location, login_revision, created_by_job, created_at,'
                ' checked_at, verdict, current_target, name) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                (session_id, login_id, state, location, revision, job_id, at, at, dumps(verdict), dumps(current_target),
                 name))
    return session_id


def set_pointer(con, login_id, session_id):
    con.execute('INSERT INTO session_pointers(login_id, session_id, updated_at) VALUES (?,?,?) '
                'ON CONFLICT(login_id) DO UPDATE SET session_id=excluded.session_id, updated_at=excluded.updated_at',
                (login_id, session_id, now()))


def mark_session(con, session_id, state, note=None):
    if state not in SESSION_STATES:
        raise ValueError('invalid_session_state')
    con.execute('UPDATE sessions SET state=?, note=COALESCE(?, note) WHERE id=?', (state, note, session_id))


def current_session(con, login_id):
    row = con.execute('SELECT s.* FROM session_pointers p JOIN sessions s ON s.id=p.session_id WHERE p.login_id=?',
                      (login_id,)).fetchone()
    return row


# Credentials (display information only)

def credentials():
    from finance_cli.credentials.registry import Registry
    rows = [{'type': 'joint', 'ref': r['name'], 'format': r['format'], 'fingerprint': r['certificate_id']}
            for r in Registry().list()]
    from finance_cli.services.hana import store
    base = store.root('identities')
    if base.is_dir() and not base.is_symlink():
        for item in sorted(base.iterdir()):
            if item.is_dir() and not item.is_symlink() and REGISTRATION_KEY.fullmatch(item.name):
                rows.append({'type': 'onesign', 'ref': item.name, 'format': 'onesign-state', 'fingerprint': None})
    return rows


# Certificate profile import (profiles.json stays unchanged)

def import_certificate_profiles(con):
    """Create login drafts from profiles.json; read-only, nothing inferred."""
    from finance_cli.core import profiles
    created, skipped = [], []
    for profile, services in sorted(profiles.load().items()):
        if not isinstance(services, dict):
            skipped.append({'profile': profile, 'reason': 'unsupported_entry'})
            continue
        for service, item in sorted(services.items()):
            source = f'profiles.json:{profile}:{service}'
            if service not in INSTITUTIONS:
                skipped.append({'profile': profile, 'service': service, 'reason': 'institution_without_login'})
                continue
            if con.execute('SELECT 1 FROM logins WHERE source=?', (source,)).fetchone():
                skipped.append({'profile': profile, 'service': service, 'reason': 'already_imported'})
                continue
            try:
                login = create_login(con, institution_name=service, method='joint_certificate',
                                     name=f'{profile} · {INSTITUTIONS[service]["name"]}', credential=item['credential'],
                                     source=source)
            except (ValueError, KeyError, TypeError) as error:
                skipped.append({'profile': profile, 'service': service,
                                'reason': str(error) if isinstance(error, ValueError) else 'invalid_entry'})
                continue
            if login['credential']['fingerprint'] != item.get('certificate_id'):
                # The certificate behind the alias changed; never select another one.
                con.execute('DELETE FROM logins WHERE id=?', (login['id'],))
                skipped.append({'profile': profile, 'service': service, 'reason': 'profile_credential_changed'})
                continue
            created.append({'profile': profile, 'service': service, 'login_id': login['id']})
    return {'created': created, 'skipped': skipped, 'profiles_json_modified': False, 'network_used': False,
            'inferred': {'type': False, 'owner': False, 'business': False, 'channel': False}}
