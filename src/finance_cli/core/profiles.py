from .paths import data_home
from . import storage
from finance_cli.credentials.registry import Registry, name

SERVICES = ('hana', 'giro', 'hometax')


def load():
    path = data_home() / 'profiles.json'
    storage.no_symlinks(path)
    return storage.read_json(path) if path.exists() else {}


def set_certificate(profile, service, certificate):
    name(profile)
    if service not in SERVICES:
        raise ValueError('unsupported_service')
    identity = Registry().entry(certificate)['certificate_id']
    home = storage.directory(data_home())
    with storage.lock(home / 'profiles.lock'):
        state = load()
        state.setdefault(profile, {})[service] = {'credential': certificate, 'certificate_id': identity}
        storage.atomic_json(home / 'profiles.json', state)
    return {'profile': profile, 'service': service, 'credential': certificate, 'network_used': False}


def resolve(profile, service):
    name(profile)
    try:
        item = load()[profile][service]
    except KeyError:
        raise ValueError('profile_service_not_configured') from None
    if Registry().entry(item['credential'])['certificate_id'] != item['certificate_id']:
        raise ValueError('profile_credential_changed')
    return item['credential']
