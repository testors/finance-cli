"""Release a long-unused transfer service through registered-phone ARS."""
import time

from finance_cli.core import storage
from . import additional_auth as auth, legacy_web as legacy, setup
from .accounts import LoginRequired
from .enrollment import Pending
from .exchange import Exchange
from .session import SessionRequired

PROGRAM = 'SM0705S0011F01'


def suspended(value):
    if isinstance(value, (list, dict)):
        value = auth.js_text(value)
    return value == '05' if isinstance(value, str) else type(value) in (int, float) and value == 5


def positive(value):
    if isinstance(value, (list, dict)):
        value = auth.js_text(value)
    try:
        if isinstance(value, str) and value.strip().lower().startswith(('0x', '0o', '0b')):
            return int(value.strip(), 0) > 0
        return float(value or 0) > 0
    except (ValueError, TypeError):
        return False


def parameters(account, data):
    clock = data['getCurrentDateFmt']['valueS20'][8:22]
    result = {'serviceSeq': '35', 'title': '장기미사용 정지해제', '서비스코드': 'D3352',
              '인증type': 0, 'noFaceMenuCode': '050050', 'noFaceMenuName': '장기 미사용 정지 해제',
              '주민번호': '', '영업시간내외': '1' if data['isOpDate'].get('valueS20') == 'true'
              and '090000' < clock < '180000' else '0'}
    if 'acno_originalValue' in account:
        result['계좌번호_상품코드'] = account['acno_originalValue']
    return result


def claim(exchange, pending):
    try:
        storage.write_new(exchange.folder/'runs'/pending['attempt']/'unlock-used.json', b'{"used":true}\n')
    except FileExistsError:
        raise Pending('transfer_unlock_auth_already_used') from None
    pending['status'] = 'used'
    storage.atomic_json(exchange.folder/'session.json', exchange.state)


def unlock(exchange, result):
    if result.get('인증여부') != 'Y':
        raise Pending('transfer_unlock_auth_incomplete')
    if not legacy.nullish(result.get('req_key')):
        raise Pending('transfer_unlock_identity_route_not_implemented')
    # Reserve the outcome before the final request; no retry on uncertainty.
    exchange.report['unlock_result'] = 'unknown'
    verdict, _ = legacy.call(exchange, 'transfer_unlock_execute', 'RSMDE0000A02',
                             {'dmyS1': '0'}, program=PROGRAM)
    exchange.report['unlock_result'] = verdict['bank_result']
    if not verdict['bridge_success']:
        raise Pending(verdict.get('required_action') or 'transfer_unlock_request_unavailable')
    # The success callback consumes no response body or extra success marker.
    exchange.report.update(processing_status='complete', unlock_result='success')
    exchange.state['login']['user']['cusSangtaeS2'] = 'OK'


def run(input_provider, *, ars_completed=False):
    folder = setup.prepare_directory()
    with storage.lock(folder/'.lock'):
        path = folder/'session.json'
        state = storage.read_json(path) if path.exists() else {}
        if not state.get('cookie'):
            raise SessionRequired()
        if not state.get('authenticated'):
            raise LoginRequired()
        exchange = Exchange(setup.load(), state, 'transfer_unlock')
        exchange.report['unlock_result'] = 'not_sent'
        try:
            if ars_completed:
                pending = state.get('transfer_unlock')
                if not pending:
                    raise Pending('transfer_unlock_ars_request_required')
                if pending['status'] != 'awaiting_ars':
                    raise Pending('transfer_unlock_auth_already_used')
                claim(exchange, pending)
                # The ARS page delays verification by at least three seconds.
                time.sleep(max(0, min(3, 3-(time.time()-pending['requested_at']))))
                result = auth.complete(exchange, pending['authentication'], True, logged_in=True)
                exchange.report['auth_attempt'] = pending['attempt']
            else:
                state.pop('transfer_unlock', None)
                exchange.save()
                user = (state.get('login') or {}).get('user') or {}
                if not suspended(user.get('cusSangtaeS2')):
                    raise Pending('transfer_unlock_not_suspended')
                data = legacy.request(exchange, 'transfer_unlock_accounts', 'RSMDE0000A01', {}, program=PROGRAM)
                if not positive(data.get('sub01Cnt')):
                    raise Pending('transfer_unlock_no_withdrawal_account')
                account = data['sub01'][0]
                data = legacy.request(exchange, 'transfer_unlock_server_time', 'RSMCM9000A03',
                    {'bdtInqrGS20': 'all', 'dtFrmtS20': 'yyyyMMddHHmmss'}, program=PROGRAM, show_message=False)
                params = parameters(account, data)

                def respond(method, remaining):
                    pending = {'attempt': exchange.attempt, 'status': 'awaiting_ars',
                               'requested_at': time.time(), 'authentication': state['additional_auth']}
                    state['transfer_unlock'] = pending
                    storage.atomic_json(folder/'session.json', state)
                    answer = input_provider('additional_response', {'method': method, 'remaining': remaining})
                    if answer is True:
                        claim(exchange, pending)
                    return answer

                result = auth.authenticate(exchange, params,
                    lambda options: input_provider('additional_select', options), respond, login_info=state['login'])
            unlock(exchange, result)
        except Pending as error:
            exchange.report.update(processing_status='incomplete', required_action=error.action)
        except (KeyboardInterrupt, EOFError):
            exchange.report.update(processing_status='incomplete', error='interrupted')
        except Exception:
            exchange.report.update(processing_status='incomplete', error='transfer_unlock_processing_error')
        if exchange.report['unlock_result'] == 'unknown':
            exchange.report['required_action'] = 'transfer_unlock_outcome_unverified'
        pending = state.get('transfer_unlock')
        if pending and pending.get('status') == 'awaiting_ars':
            exchange.report['ars_pending'] = True
        exchange.save()
        return exchange.report
