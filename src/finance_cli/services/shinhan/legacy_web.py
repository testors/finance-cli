"""Bank web callbacks used by additional telephone authentication."""
from . import transport, web
from .enrollment import Pending


def nullish(value):
    return web.nullish(value) or value == 'undefined'


def parse(reply, *, show_message):
    result, document = transport.parse(reply)
    result['bridge_success'] = result['bank_result'] == 'success'
    result['callback_ready'] = True
    header = document.get('dataHeader') if isinstance(document, dict) else None
    code = header.get('resultCode') if isinstance(header, dict) else None
    http_ok = reply.error is None and reply.status is not None and 200 <= reply.status < 300
    if not result['bridge_success'] and http_ok:
        if code in ('RIB80306', 'RIB80307', 'RIB96472'):
            result.update(callback_ready=False, required_action='additional_authentication',
                          service_sequence='81' if code == 'RIB96472' else '70')
        elif code in ('RIB00011', 'MCM00005', 'RIB00057'):
            result.update(callback_ready=False, required_action='session_notice')
        elif show_message and header is not None:
            result.update(callback_ready=False, required_action='bank_error_notice')
    if not result['callback_ready']:
        result['processing_status'] = 'incomplete'
    return result, document


def update_challenges(state, document):
    header, body = document.get('dataHeader'), document.get('dataBody')
    for group, prefix in ((header, 'secChal'), (body, 'comSecChal'), (body, 'COM_SEC_CHAL')):
        values = [group.get(prefix+str(i)) if isinstance(group, dict) else None for i in (1, 2)]
        if any(not nullish(value) for value in values):
            state['web_challenges'] = ['' if nullish(value) else value for value in values]
            return


def request(exchange, stage, transaction, body, *, program, header=None, show_message=True):
    payload = web.encode(transaction, body, exchange.settings, program, header=header)
    recorded = exchange.reserve(stage, transaction=transaction)
    reply = transport.post_web(payload, exchange.state.get('cookie', ''), show_message=show_message)
    verdict, document = parse(reply, show_message=show_message)
    recorded.update(verdict)
    recorded['result'] = verdict['bank_result']
    exchange.report['bank_result'] = verdict['bank_result']
    try:
        transport.update_cookie(exchange.state, reply.headers)
        if document is not None:
            transport.update_challenges(exchange.state, document)
    except Exception:
        exchange.warning('bank_state_update_error')
    try:
        if verdict['bridge_success']:
            update_challenges(exchange.state, document)
    except Exception:
        # Both challenge-storage callbacks deliver the original bank success.
        exchange.warning('web_state_update_error')
    exchange.record_response(reply)
    exchange.save()
    if not verdict['callback_ready']:
        raise Pending(verdict['required_action'])
    if not verdict['bridge_success']:
        raise Pending('additional_auth_request_unavailable')
    return document.get('dataBody')
