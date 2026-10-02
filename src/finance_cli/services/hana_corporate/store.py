"""Private corporate session records; certificates remain in their shared stores."""
import json
import secrets
import uuid

from finance_cli.core import storage
from finance_cli.core.paths import data_home
from finance_cli.services.hana.store import name
from .protocol import VERSION, require


def root():
    return data_home().absolute() / 'hana-corporate' / 'sessions'


def session_path(session):
    path = storage.no_symlinks(root() / name(session))
    require(path.is_dir(), 'corporate_session_not_found')
    return path


def record(path, value):
    storage.write_new(path, (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode())


def device(value):
    require(isinstance(value, dict) and set(value) <= {'custom_user_agent', 'push'}, 'invalid_corporate_device')
    agent = value.get('custom_user_agent')
    require(isinstance(agent, dict), 'corporate_user_agent_required')
    fields = {'platform', 'brand', 'model', 'version', 'deviceId', 'phoneNumber', 'countryIso',
              'timeZoneId', 'telecom', 'simSerialNumber', 'subscriberId', 'appVersion', 'phoneName',
              'appName', 'deviceWidth', 'deviceHeight', 'uid', 'hUid', 'terminalInfoId', 'etcStr', 'userAgent'}
    require(set(agent) == fields, 'corporate_user_agent_fields')
    require(all(isinstance(v, str) for k, v in agent.items() if k not in ('deviceWidth', 'deviceHeight')),
            'corporate_user_agent_types')
    require(all(type(agent[k]) is int and agent[k] > 0 for k in ('deviceWidth', 'deviceHeight')), 'corporate_screen_size')
    require(agent['platform'] == 'Android' and agent['appName'] == 'HanaNCBS'
            and agent['appVersion'] == VERSION, 'corporate_app_version_unsupported')
    require(all(agent[k] for k in ('deviceId', 'hUid', 'uid', 'model', 'version', 'userAgent')),
            'corporate_device_identity_required')
    require(agent['deviceId'] == agent['hUid'], 'corporate_device_identity_mismatch')
    require(all(32 <= ord(c) < 127 for c in agent['userAgent']), 'invalid_web_user_agent')
    push = value.get('push', {'is_push': 'N', 'token': '', 'management_number': ''})
    require(isinstance(push, dict) and set(push) == {'is_push', 'token', 'management_number'}
            and all(isinstance(v, str) for v in push.values()) and push['is_push'] in ('Y', 'N'), 'invalid_push_profile')
    return {'custom_user_agent': dict(agent), 'push': dict(push)}


def create(session, profile):
    profile = device(profile)
    name(session)
    storage.directory(root())
    path = storage.no_symlinks(root() / session)
    require(not path.exists(), 'corporate_session_exists')
    path.mkdir(mode=0o700)
    record(path / 'device.json', profile)
    return {'channel': 'corporate', 'session': session, 'created': True, 'network_used': False}


def app_uuid(advertising_id, model):
    def java_hash(text):
        raw = text.encode('utf-16-be')
        value = 0
        for offset in range(0, len(raw), 2):
            value = (31 * value + int.from_bytes(raw[offset:offset + 2], 'big')) & 0xffffffff
        return value if value < 0x80000000 else value - 0x100000000
    mask = (1 << 64) - 1
    return str(uuid.UUID(int=((java_hash(advertising_id) & mask) << 64) | (java_hash(model) & mask)))


def default_device():
    """Persist an isolated CLI client profile, never a copied phone identity."""
    directory = storage.directory(root().parent)
    with storage.lock(directory / 'client.lock'):
        path = directory / 'client.json'
        if path.exists():
            value = storage.read_json(path)
            require(value.get('format') == 'finance-hana-corporate-client-v1', 'unsupported_corporate_client')
            return device(value['device'])
        advertising_id = str(uuid.uuid4())
        model = 'FinanceCLI'
        identifier = app_uuid(advertising_id, model)
        profile = device({'custom_user_agent': {
            'platform': 'Android', 'brand': 'generic', 'model': model, 'version': '13',
            'deviceId': identifier, 'hUid': identifier, 'uid': secrets.token_hex(8),
            'terminalInfoId': advertising_id, 'appVersion': VERSION, 'appName': 'HanaNCBS',
            'phoneNumber': '', 'countryIso': '', 'telecom': '', 'simSerialNumber': '',
            'subscriberId': '', 'phoneName': '', 'etcStr': '', 'timeZoneId': 'Asia/Seoul',
            'deviceWidth': 1080, 'deviceHeight': 2400,
            'userAgent': 'Mozilla/5.0 (Linux; Android 13; FinanceCLI; wv) AppleWebKit/537.36 '
                         '(KHTML, like Gecko) Version/4.0 Chrome/120.0.0.0 Mobile Safari/537.36',
        }})
        record(path, {'format': 'finance-hana-corporate-client-v1', 'source': 'generated-cli', 'device': profile})
        return profile


def prepare_idpw(session=None):
    session = name(session) if session is not None else 'login-' + uuid.uuid4().hex
    path = storage.no_symlinks(root() / session)
    if not path.exists():
        create(session, default_device())
    return session, session_path(session)


def inspect(session):
    path = session_path(session)
    result = {'channel': 'corporate', 'session': session, 'network_used': False,
              'attempted': (path / 'login-attempt.json').exists(), 'session_current_validity': 'unverified'}
    if (path / 'outcome.json').exists():
        result['last_login'] = storage.read_json(path / 'outcome.json')
    return result
