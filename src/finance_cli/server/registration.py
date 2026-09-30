"""Institution device/app registration material for a login (server-managed).

Files are copied into the private server store and referenced by name; the
database never holds their contents. Only the local CLI links them.
"""
import hashlib
import json
from pathlib import Path

from finance_cli.core import storage

from . import model
from .config import private_directory

SHAPES = {'app_profile': {'system_header', 'channel_header', 'secure_token', 'profile_provenance'},
          'login_input': {'push_token', 'fakefinder_install_id', 'input_provenance'}}


def directory(login_id):
    return private_directory('registrations', model.REGISTRATION_KEY.fullmatch(login_id).group(0))


def location(login_id, reference):
    return directory(login_id) / (model.REGISTRATION_KEY.fullmatch(reference).group(0) + '.json')


def copy(login_id, kind, source):
    data = Path(source).expanduser().read_bytes()
    try:
        value = json.loads(data)
    except ValueError:
        raise ValueError('registration_file_not_json') from None
    if not isinstance(value, dict) or set(value) != SHAPES[kind]:
        raise ValueError('registration_file_fields')
    reference = kind + '-' + hashlib.sha256(data).hexdigest()[:16]
    target = location(login_id, reference)
    if not target.exists():
        storage.write_new(target, data)
    return reference


def link(con, login_id, *, expected_revision, app_profile=None, login_input=None, onesign_settings=None):
    login = model.get_login(con, login_id, raw=True)
    if login['institution'] != 'hana':
        raise ValueError('registration_not_used_by_institution')
    changes = {}
    if app_profile:
        changes['app_profile'] = copy(login_id, 'app_profile', app_profile)
    if login_input:
        changes['login_input'] = copy(login_id, 'login_input', login_input)
    if onesign_settings:
        from finance_cli.services.hana import onesign_setup
        onesign_setup.load(onesign_settings)
        changes['onesign_settings'] = onesign_settings
    if not changes:
        raise ValueError('registration_change_required')
    row = model.update_login(con, login_id, expected_revision=expected_revision, registration=changes)
    return {'login': row, 'linked': sorted(changes), 'contents_stored_in_database': False, 'network_used': False}


def path_for(login_row, key):
    """Absolute path of a linked registration file for a worker; None when missing."""
    reference = json.loads(login_row['registration'] or '{}').get(key)
    return location(login_row['id'], reference) if reference else None
