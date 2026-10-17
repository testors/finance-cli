"""Native account and program notice checks before opening a banking page."""
import json
import re

from finance_cli.core import storage
from . import account_protocol as codec, menu_protocol, netfunnel, transport
from .enrollment import Pending

NOTICE = codec.strings('notiType notiTitle notiMsg1 notiMsg2 notiMsg3 notiMsg4 notiMsg5 notiMsg6 imgUrl linkId')
NOTICE['notiSeq'] = ('int', 0)
INTRO_NOTICE = codec.strings('prId popType popLinkId') | {'notiSeq': ('int', 0)}
MESSAGE = {name: ('string', None) for name in
           [*[f'ERR_DEFAULT_MSG{n}' for n in range(1, 7)], 'ERR_USER_MSG1', 'ERR_USER_MSG2', 'ERR_ADDITIONAL_MSG']}
HEADER = {name: ('string', None) for name in 'trxCd result globId resultCode secChal1'.split()}
HEADER.update(resultMsg=(MESSAGE, None), resultDetail=('json_string', None))
RESPONSE = {'dataHeader': ('required_header', None), 'dataBody': (NOTICE, None)}


def tree_text(value):
    if isinstance(value, menu_protocol.Literal):
        return str(value)
    if isinstance(value, dict):
        return '{'+','.join(json.dumps(k, ensure_ascii=False)+':'+tree_text(v) for k, v in value.items())+'}'
    if isinstance(value, list):
        return '['+','.join(map(tree_text, value))+']'
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


class Reader(menu_protocol.Reader):
    def value(self, kind):
        if kind == 'required_header':
            value = super().value(HEADER)
            if value is None:
                raise ValueError('notice_header_null')
            return value
        if kind == 'json_string':
            value = self.tree()
            return None if value is None else tree_text(value)
        return super().value(kind)


def decode_response(text):
    reader = Reader(text)
    result = reader.value(RESPONSE)
    if reader.peek() or result is None or result['dataHeader'] is None:
        raise ValueError('notice_json_document')
    return result


def parse_reply(reply):
    # Keep an observed bank verdict even if the typed DTO later cannot decode.
    try:
        text = reply.body.decode('utf-8-sig')
        header = codec.decode(text, {'dataHeader': (codec.HEADER, None)})
        verdict, _ = transport.parse(transport.Reply(reply.status, reply.headers, json.dumps(header).encode(), reply.error))
    except (ValueError, UnicodeError, RecursionError):
        verdict, _ = transport.parse(reply)
    verdict['notice_result'] = 'error'
    if reply.error:
        # Only transport errors have a native onFailure counterpart. A local
        # size limit does not prove the repository would return DataResult.Error.
        if reply.error != 'transport_error':
            verdict['notice_result'] = 'unverified'
        return verdict, None
    if reply.status is None or not 200 <= reply.status < 300 or reply.status in (204, 205):
        return verdict, None
    try:
        document = decode_response(reply.body.decode('utf-8-sig'))
    except (ValueError, UnicodeError, RecursionError):
        # Retrofit's serialization onFailure is a NetworkResponse.Error; the
        # notice guard permits navigation after that repository result.
        verdict.update(processing_status='incomplete', error='notice_response_decode_error')
        return verdict, None
    if document is not None and (document.get('dataHeader') or {}).get('result') == 'SUCCESS':
        if document['dataBody'] is None:
            verdict.update(notice_result='unverified', processing_status='incomplete', error='notice_body_missing')
        else:
            verdict['notice_result'] = 'success'
    return verdict, document


def has_account(user):
    values = codec.decode(json.dumps(user if user is not None else {}),
                          {'ipjiAmtAcntN5': ('int', 0), 'opbAcnoCnt': ('int', 0)})
    # The repository adds two Java ints before comparing against zero.
    total = (values['ipjiAmtAcntN5']+values['opbAcnoCnt']+2**31) % 2**32-2**31
    return total > 0


def account(found, user, exchange=None):
    if found.get('ACCOUNT_CHECK_YN') != 'Y':
        return
    try:
        present = has_account(user)
    except (ValueError, TypeError, RecursionError):
        raise Pending('loan_account_state_unverified') from None
    if exchange is not None:
        exchange.report['account_guard'] = 'passed' if present else 'blocked'
    if not present:
        raise Pending('loan_account_required')


def notice_info(intro, name):
    try:
        value = codec.decode(json.dumps({'programNotiList': intro.get('programNotiList')}),
                             {'programNotiList': ([INTRO_NOTICE], [])})
    except (ValueError, TypeError, RecursionError):
        raise Pending('loan_program_notice_state_unverified') from None
    return {row['prId']: row for row in value['programNotiList']}.get(name)


def notice(exchange, intro, name, done, acknowledge, *, stage="loan_program_notice"):
    info = notice_info(intro, name)
    if info is None:
        return False
    if info['popType'] == '99':
        raise Pending('loan_netfunnel_required')
    if exchange is None:
        raise Pending('loan_program_notice_required')
    verdict, document = exchange.bank(stage, 'RSMCM9007A11', {'notiSeq': info['notiSeq']}, response_parser=parse_reply)
    exchange.report.update(bank_result=verdict['bank_result'], notice_lookup_result=verdict['bank_result'],
                           notice_result=verdict['notice_result'])
    if verdict['notice_result'] == 'unverified':
        raise Pending('loan_program_notice_unverified')
    if verdict['notice_result'] == 'error' or done:
        exchange.report['notice_navigation'] = 'allowed'
        return False
    value = document['dataBody']
    content = value['notiTitle']+'\n'+' '.join(value[f'notiMsg{n}'] for n in range(1, 7) if value[f'notiMsg{n}'])+'\n'
    path = exchange.run/'program-notice.txt'
    try:
        storage.write_new(path, content.encode())
        exchange.report['notice_file'] = str(path)
    except Exception:
        exchange.warning('program_notice_save_error')
    blocking = value['notiType'] == 'BLOCK'
    exchange.report['notice_navigation'] = 'blocked' if blocking else 'confirmation_required'
    # Supply the content in memory too: a diagnostic file write failure must
    # not change the bank's confirmation/continuation condition.
    confirmed = acknowledge(content, path if 'notice_file' in exchange.report else None, blocking) if acknowledge else None
    if blocking:
        raise Pending('loan_program_notice_blocks_service')
    if confirmed is not True:
        raise Pending('loan_program_notice_confirmation_required' if confirmed is None else 'loan_program_notice_dismissed')
    exchange.report['notice_acknowledged'] = True
    # The native navigator checks the same copied ProgramEntity again. Notice
    # lookup is performed again, even with donePreCheckNotice=true.
    return True


def prechecks(settings, state, found, exchange):
    minimum = found.get('AND_MIN_APP_VER', '')
    if minimum:
        versions = [value.replace('.', '') for value in (settings['version'], minimum)]
        if any(not re.fullmatch(r'[+-]?[0-9]+', value) or not -2**31 <= int(value) < 2**31 for value in versions) or int(versions[0]) < int(versions[1]):
            raise Pending('loan_program_version_required')
    user = (state.get('login') or {}).get('user')
    if user is None:
        user = {}
    if not isinstance(user, dict):
        raise Pending('loan_login_state_unverified')
    if state.get('emergency'):
        raise Pending('loan_banking_login_required')
    grade = found.get('LOGIN_LEVEL', '')
    if grade != '0':
        if grade != '1' and user.get('membGdS2') == '01':
            raise Pending('loan_banking_grade_required')
        if user.get('loginLevS2') == '2' and found.get('ID_USABLE_YN') != 'Y':
            raise Pending('loan_other_login_required')
    if found.get('LONGTERM_TRANSFER_CHK_YN') == 'Y' and user.get('cusSangtaeS2') == '05':
        raise Pending('loan_long_term_transfer_notice')
    account(found, user, exchange)


def open_program(settings, state, found, exchange=None, acknowledge=None, queue_progress=None, *, scope="loan"):
    intro = state.get("intro") or {}
    name = found.get("PR_ID")
    try:
        done = False
        while True:
            prechecks(settings, state, found, exchange)
            info = notice_info(intro, name)
            if info is not None and info['popType'] == '99' and exchange is not None:
                netfunnel.program(exchange, info['popLinkId'], progress=queue_progress)
                # The native NetFunnel reason resumes this destination directly,
                # without running the remaining group guard or repeating checks.
                return name
            if notice(exchange, intro, name, done, acknowledge, stage=scope+"_program_notice"):
                done = True
                continue
            user = (state.get('login') or {}).get('user') or {}
            if found.get('GRP_AGREE_YN') == '1' and user.get('superAgreeYn') != 'Y':
                raise Pending('loan_group_agreement_required')
            return name
    except Pending as error:
        if scope != "loan" and error.action.startswith("loan_"):
            raise Pending(scope+error.action[4:]) from None
        raise
