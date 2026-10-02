"""Private corporate session records; certificates remain in their shared stores."""
import json

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


def inspect(session):
    path = session_path(session)
    result = {'channel': 'corporate', 'session': session, 'network_used': False,
              'attempted': (path / 'login-attempt.json').exists(), 'session_current_validity': 'unverified'}
    if (path / 'outcome.json').exists():
        result['last_login'] = storage.read_json(path / 'outcome.json')
    return result
