"""Server settings: loopback binding and one explicit public origin.

Cookie security, CSRF origin checks and enrollment validity follow the
configured public origin, never request headers. A plain-HTTP origin is only
accepted on loopback (local development); remote browsers reach the server
through an HTTPS reverse proxy (Caddy) that forwards to the loopback port.
"""
from dataclasses import asdict, dataclass
import ipaddress
import json
from urllib.parse import urlsplit

from finance_cli.core import storage
from finance_cli.core.paths import data_home

DEFAULT_PORT = 8740
LOOPBACK_NAMES = ('localhost',)


def server_home():
    return data_home() / 'server'


def private_directory(*parts):
    """Create data_home()/server/... as private directories, one level at a time."""
    path = storage.directory(data_home())
    for part in ('server', *parts):
        path = storage.directory(path / part)
    return path


def loopback(host):
    host = host.strip('[]').lower()
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_origin(value):
    if not isinstance(value, str) or len(value) > 255:
        raise ValueError('invalid_public_origin')
    parts = urlsplit(value.strip())
    try:
        port = parts.port
    except ValueError:
        raise ValueError('invalid_public_origin') from None
    if (parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password
            or parts.path not in ('', '/') or parts.query or parts.fragment):
        raise ValueError('invalid_public_origin')
    host = parts.hostname.lower()
    if parts.scheme == 'http' and not loopback(host):
        raise ValueError('https_required_for_remote_origin')
    default = 443 if parts.scheme == 'https' else 80
    shown = f'[{host}]' if ':' in host else host
    return f'{parts.scheme}://{shown}' + (f':{port}' if port and port != default else '')


@dataclass(frozen=True)
class Config:
    port: int = DEFAULT_PORT
    public_origin: str = ''
    idle_minutes: int = 60 * 24 * 7
    absolute_days: int = 90

    def __post_init__(self):
        if not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise ValueError('invalid_port')
        origin = normalize_origin(self.public_origin or f'http://127.0.0.1:{self.port}')
        object.__setattr__(self, 'public_origin', origin)
        for name, low, high in (('idle_minutes', 5, 60 * 24 * 90), ('absolute_days', 1, 365)):
            value = getattr(self, name)
            if not isinstance(value, int) or not low <= value <= high:
                raise ValueError('invalid_' + name)

    @property
    def secure(self):
        return self.public_origin.startswith('https://')

    @property
    def mode(self):
        return 'proxy' if self.secure else 'local'

    def as_dict(self):
        return {**asdict(self), 'mode': self.mode, 'secure_cookies': self.secure}


def path():
    return server_home() / 'config.json'


def load():
    target = path()
    storage.no_symlinks(target)
    if not target.exists():
        return Config()
    value = storage.read_json(target)
    if not isinstance(value, dict) or value.get('format') != 'finance-server-config-v1':
        raise ValueError('unsupported_server_config')
    return Config(**{k: value[k] for k in ('port', 'public_origin', 'idle_minutes', 'absolute_days') if k in value})


def save(config):
    home = private_directory()
    with storage.lock(home / 'config.lock'):
        storage.atomic_json(home / 'config.json', {'format': 'finance-server-config-v1', **{
            k: v for k, v in config.as_dict().items() if k in ('port', 'public_origin', 'idle_minutes', 'absolute_days')}})
    return config


def dumps(config):
    return json.dumps(config.as_dict(), ensure_ascii=False)
