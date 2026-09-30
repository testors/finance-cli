"""Browser access: one-time enrollment codes, per-device tokens and CSRF.

Web access is separate from institution logins. Codes come only from the local
management command, expire, are single use and are stored as hashes. Device
tokens are stored as hashes; the CSRF token is derived from the device token
so no plaintext token is kept on the server.
"""
import hashlib
import hmac
import secrets

from .db import new_id, now

CODE_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'
CODE_LENGTH = 10
CODE_MINUTES = 10
FAILURE_WINDOW = 15 * 60
FAILURE_LIMIT = 10         # per client address
FAILURE_LIMIT_TOTAL = 50   # across all clients, so a code cannot be guessed from many addresses
COOKIE = 'finance_access'


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def normalize_code(value):
    if not isinstance(value, str):
        return None
    value = value.strip().upper().replace('-', '').replace(' ', '')
    if len(value) != CODE_LENGTH or any(c not in CODE_ALPHABET for c in value):
        return None
    return value


def create_code(con, config, device_name=None):
    code = ''.join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
    at = now()
    con.execute('INSERT INTO enrollment_codes(code_hash, device_name, public_origin, created_at, expires_at)'
                ' VALUES (?,?,?,?,?)', (digest(code), device_name, config.public_origin, at, at + CODE_MINUTES * 60))
    return {'code': code[:5] + '-' + code[5:], 'expires_in_seconds': CODE_MINUTES * 60,
            'public_origin': config.public_origin, 'single_use': True}


def enroll(con, config, code, device_name, client):
    """(device_id, token) or (None, reason). Refusals are recorded, so the
    caller commits instead of rolling back."""
    at = now()
    since = at - FAILURE_WINDOW
    total = con.execute('SELECT COUNT(*) FROM enrollment_failures WHERE at>?', (since,)).fetchone()[0]
    mine = con.execute('SELECT COUNT(*) FROM enrollment_failures WHERE at>? AND client IS ?', (since, client)).fetchone()[0]
    if mine >= FAILURE_LIMIT or total >= FAILURE_LIMIT_TOTAL:
        return None, 'enrollment_rate_limited'
    normalized = normalize_code(code)
    row = con.execute('SELECT * FROM enrollment_codes WHERE code_hash=?',
                      (digest(normalized),)).fetchone() if normalized else None
    if (row is None or row['used_at'] is not None or row['expires_at'] <= at
            or row['public_origin'] != config.public_origin):
        con.execute('INSERT INTO enrollment_failures(at, client) VALUES (?, ?)', (at, client))
        return None, 'enrollment_code_invalid'
    con.execute('UPDATE enrollment_codes SET used_at=? WHERE code_hash=?', (at, row['code_hash']))
    token = secrets.token_urlsafe(32)
    device_id = new_id('dv')
    name = (device_name or row['device_name'] or '새 브라우저').strip()[:60] or '새 브라우저'
    con.execute('INSERT INTO devices(id, name, token_hash, created_at, last_seen_at, expires_at) VALUES (?,?,?,?,?,?)',
                (device_id, name, digest(token), at, at, at + config.absolute_days * 86400))
    return device_id, token


def csrf_token(token):
    return hmac.new(token.encode('utf-8'), b'finance-csrf-v1', hashlib.sha256).hexdigest()


def authenticate(con, config, token):
    """The device for a token, or None. Updates idle time at most once a minute."""
    if not isinstance(token, str) or not 20 <= len(token) <= 200:
        return None
    row = con.execute('SELECT * FROM devices WHERE token_hash=?', (digest(token),)).fetchone()
    at = now()
    if row is None or row['revoked_at'] is not None or row['expires_at'] <= at:
        return None
    if row['last_seen_at'] + config.idle_minutes * 60 <= at:
        con.execute('UPDATE devices SET revoked_at=? WHERE id=?', (at, row['id']))
        return None
    if at - row['last_seen_at'] > 60:
        con.execute('UPDATE devices SET last_seen_at=? WHERE id=?', (at, row['id']))
    return dict(row)


def devices(con, current=None):
    rows = con.execute('SELECT id, name, created_at, last_seen_at, expires_at, revoked_at FROM devices '
                       'ORDER BY created_at DESC').fetchall()
    return [{**dict(r), 'current': r['id'] == current, 'active': r['revoked_at'] is None and r['expires_at'] > now()}
            for r in rows]


def revoke(con, device_id):
    if con.execute('UPDATE devices SET revoked_at=COALESCE(revoked_at, ?) WHERE id=?', (now(), device_id)).rowcount != 1:
        raise ValueError('device_not_found')
