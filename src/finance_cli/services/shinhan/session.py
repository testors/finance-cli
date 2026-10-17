"""Explicit startup/extension with private state and redacted per-attempt reports."""
import base64
from datetime import datetime, timezone
import json
import uuid

from finance_cli.core import storage
from . import menu, netfunnel, setup, transport
from .enrollment import Pending


class SessionRequired(ValueError):
    pass


def status():
    folder = setup.root()
    result = {'configured': (folder / 'settings.json').exists(), 'network_used': False,
              'authentication': 'unverified', 'session_saved': (folder / 'session.json').exists()}
    if result['session_saved']:
        saved = storage.read_json(folder / 'session.json')
        result['cookie_present'] = bool(saved.get('cookie'))
        result['last_operation'] = saved.get('last_operation')
        result['login_previously_accepted'] = bool(saved.get('authenticated'))
    return result


def execute(action, *, queue_input=None, queue_progress=None):
    settings = setup.load()
    folder = setup.prepare_directory()
    with storage.lock(folder / '.lock'):
        state_path = folder / 'session.json'
        state = storage.read_json(state_path) if state_path.exists() else {}
        if action == 'start':
            transaction = 'RSMCM0100C01'
            body = {'svcGS30': 'SBANK', 'osVerS20': settings['device']['os_version'],
                    'appVer': settings['version'], 'pgmVerS10': settings['menu_version']}
        elif action == 'extend':
            if not state.get('cookie'):
                raise SessionRequired()
            transaction = 'RSMCM9000E03'
            body = {'osGS10': '03', 'appVersion': settings['version'], 'osVer': settings['device']['os_version']}
        else:
            raise ValueError('invalid_operation')
        attempt = uuid.uuid4().hex
        runs = storage.directory(folder / 'runs')
        run = storage.directory(runs / attempt)
        result = {'operation': action, 'attempt': attempt, 'transaction': transaction,
                  'created_at': datetime.now(timezone.utc).isoformat(),
                  'bank_result': 'unknown', 'processing_status': 'prepared',
                  'authentication': 'unverified', 'network_used': False,
                  'automatic_retry': False}
        storage.write_new(run / 'report.json', (json.dumps(result)+'\n').encode())
        if action == 'start':
            try:
                netfunnel.start(result, run, state, choose=queue_input, progress=queue_progress)
            except Pending as error:
                result.update(processing_status='incomplete', required_action=error.action)
            except (KeyboardInterrupt, EOFError):
                result.update(processing_status='incomplete', error='interrupted')
            except Exception:
                result.update(processing_status='incomplete', error='netfunnel_processing_error')
            if result['processing_status'] == 'incomplete':
                try: storage.atomic_json(run/'report.json', result)
                except Exception:
                    result.setdefault('warnings', []).append('report_save_error')
                    result['local_status'] = 'incomplete'
                return result
        menus = menu.Store(settings, state, result, run) if action == 'start' else None
        if menus is not None:
            body['pgmVerS10'] = menus.before_start()
        payload = transport.encode(transaction, body, settings)
        # Reserve and persist before attempting network; never resume by resending.
        result.update(network_used=True, processing_status='sending')
        storage.atomic_json(run / 'report.json', result)
        reply = transport.post(payload, state.get('cookie', ''))
        judgement, document = transport.parse(reply)
        result.update(judgement)
        warnings = []
        try:
            transport.update_cookie(state, reply.headers)
        except Exception:
            warnings.append('cookie_update_error')
        if document is not None:
            try:
                transport.update_challenges(state, document)
            except Exception:
                warnings.append('challenge_update_error')
        if result['bank_result'] == 'success':
            data = document.get('dataBody')
            if (action == 'start' and not isinstance(data, dict)) or (action == 'extend' and data is not None and not isinstance(data, dict)):
                result.update(processing_status='incomplete', error='operation_body_unavailable')
            elif action == 'start':
                # Keep full configuration privately for subsequent authenticated calls.
                state['intro'] = data
                result['intro'] = {name: data.get(field) == 'Y' for name, field in (
                    ('notice', 'appNotiYnS1'), ('force_end', 'appNotiAfForcEndYnS1'),
                    ('force_update', 'appNotiAfForcUpdateYnS1'), ('menu_update', 'menuDownlYnS1'))}
                try:
                    menus.load(data)
                except (KeyboardInterrupt, EOFError):
                    result['menu']['status'] = 'interrupted'
                    result.update(processing_status='incomplete', error='interrupted')
                except Exception:
                    result['menu']['status'] = 'unavailable'
                    warnings.append('menu_processing_error')
        state['last_operation'] = action
        try:
            storage.atomic_json(state_path, state)
            result['session_saved'] = True
        except Exception:
            result['session_saved'] = False
            warnings.append('session_save_error')
        # Raw responses are private diagnostics, separate from the shareable report.
        try:
            storage.write_new(run / 'response.json', (json.dumps({
                'status': reply.status, 'headers': reply.headers,
                'body_base64': base64.b64encode(reply.body).decode('ascii')})+'\n').encode())
        except Exception:
            warnings.append('response_save_error')
        result['cookie_present'] = bool(state.get('cookie'))
        if warnings or result.get('warnings'):
            result.setdefault('warnings', []).extend(warnings)
            result['local_status'] = 'incomplete'
        else:
            result['local_status'] = 'complete'
        try:
            storage.atomic_json(run / 'report.json', result)
        except Exception:
            result.setdefault('warnings', []).append('report_save_error')
            result['local_status'] = 'incomplete'
        return result
