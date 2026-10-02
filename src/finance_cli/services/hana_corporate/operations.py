"""Serialized business operations over an existing corporate login."""
from contextlib import contextmanager
from datetime import datetime
import uuid

from finance_cli.core import storage
from finance_cli.services.hana.onesign_io import send_http
from . import protocol, store
from .transport import Client


def result(action, send):
    return {'channel': 'corporate', 'action': action, 'accepted': None, 'network_used': False,
            'automatic_retry': False, 'processing_status': 'preparing' if send else 'planned',
            'session_current_validity': 'unverified', 'stages': []}


def warning(output, code):
    if code not in output.setdefault('warnings', []):
        output['warnings'].append(code)


@contextmanager
def operation(output, session=None, *, exchange=send_http):
    """Hold the server session across every step, including secret input."""
    path = directory = None
    yielded = False
    try:
        path = store.select(session)
        output['session'] = path.name
        with storage.lock(path / 'operation.lock'):
            saved = storage.read_json(path / 'session.json')
            profile = store.device(storage.read_json(path / 'device.json'))
            parent = storage.directory(path / 'operations')
            directory = parent / uuid.uuid4().hex
            directory.mkdir(mode=0o700)
            output['operation'] = directory.name
            client = Client(directory, profile, output, exchange=exchange, state_directory=path, saved=saved)
            yielded = True
            yield client
            output['processing_status'] = 'completed'
    except KeyboardInterrupt:
        output.update(processing_status='stopped', error='interrupted')
        if not yielded:
            yield None
    except Exception as exc:
        output.update(processing_status='stopped', error=str(exc) if isinstance(exc, protocol.Stop) else 'local_processing_error')
        if not yielded:
            yield None
    finally:
        if directory is not None:
            try:
                store.record(directory / 'outcome.json', output)
            except (OSError, ValueError):
                warning(output, 'diagnostic_storage_failed')


def observe(output):
    def received(receipt, payload):
        verdict = receipt['service_status']
        if verdict == 'accepted':
            output['accepted'] = True
        elif verdict == 'rejected' and output['accepted'] is None:
            output['accepted'] = False
    return received


def save(client):
    try:
        storage.atomic_json(client.state_directory / 'session.json', client.saved)
        client.result['session_saved'] = True
    except (OSError, ValueError):
        warning(client.result, 'session_storage_failed')
        client.result['session_saved'] = False


def pick(value, fields):
    return {k: value[k] for k in fields if k in value}


def current_time(client, *, attempt_name='server-time'):
    """The display clock consumes data directly and falls back to local time."""
    try:
        value = client.request('server-time', assessor=protocol.assess_data, attempt_name=attempt_name)
        datetime.strptime(value['date'] + value['time'], '%Y%m%d%H%M%S')
        return value
    except (protocol.Stop, KeyError, TypeError, ValueError):
        warning(client.result, 'server_time_unavailable_using_local_time')
        now = datetime.now()
        return {'date': now.strftime('%Y%m%d'), 'time': now.strftime('%H%M%S'), 'bizDateYn': 'N'}
