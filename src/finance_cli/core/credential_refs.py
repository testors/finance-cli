"""Where a stored credential is referenced: certificate profiles and web logins.

Read-only. Never opens a vault, never rewrites a reference: profiles.json and the
server database cannot share one transaction, so removal and renaming are
refused while any reference exists and the user re-points those first.
"""
import json

from . import profiles


class CredentialInUse(ValueError):
    def __init__(self, references):
        super().__init__('credential_in_use')
        self.references = references


def _matches(value, kind, ref):
    return isinstance(value, dict) and value.get('type') == kind and value.get('ref') == ref


def scan_database(con, kind, ref):
    """References inside an open server database connection (sqlite3.Row rows)."""
    found = []
    for row in con.execute('SELECT id, display_name, credential, signing FROM logins ORDER BY created_at, id'):
        if _matches(json.loads(row['credential'] or 'null'), kind, ref):
            found.append({'source': 'login', 'login_id': row['id'], 'name': row['display_name']})
        for purpose, value in (json.loads(row['signing'] or '{}') or {}).items():
            if _matches(value, kind, ref):
                found.append({'source': 'login_signing', 'login_id': row['id'], 'name': row['display_name'],
                              'purpose': purpose})
    for row in con.execute('SELECT t.id, t.display_name, t.signing, l.display_name AS login_name FROM targets t'
                           ' JOIN logins l ON l.id=t.login_id ORDER BY t.created_at, t.id'):
        for purpose, value in (json.loads(row['signing'] or '{}') or {}).items():
            if _matches(value, kind, ref):
                found.append({'source': 'target_signing', 'target_id': row['id'], 'name': row['display_name'],
                              'login_name': row['login_name'], 'purpose': purpose})
    return found


def references(kind, ref):
    """All references to one credential: v1 certificate profiles, then the web server database if present."""
    found = []
    if kind == 'joint':
        for profile, services in profiles.load().items():
            for service, item in (services or {}).items():
                if isinstance(item, dict) and item.get('credential') == ref:
                    found.append({'source': 'profile', 'profile': profile, 'service': service})
    try:
        from finance_cli.server import db
    except ImportError:
        return found
    if not db.exists():
        return found
    with db.Database().read() as con:
        found.extend(scan_database(con, kind, ref))
    return found


def guard(kind, ref):
    found = references(kind, ref)
    if found:
        raise CredentialInUse(found)
    return found
