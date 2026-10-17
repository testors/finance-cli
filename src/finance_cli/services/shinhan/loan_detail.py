"""Selected loan account information, preserving each page's request order."""
import copy
import json

from finance_cli.core import storage
from . import account_protocol, legacy_web, menu as navigation, menu_protocol, navigation_guard, setup
from .accounts import LoginRequired
from .enrollment import Pending
from .exchange import Exchange
from .session import SessionRequired
from .navigation_guard import prechecks

PROGRAMS = {'BM0302S0404F01': 'installment', 'BM0310S0402F01': 'overdraft', 'BM0302S0403F01': 'current'}


def select(state, index):
    saved = state.get('accounts')
    if not saved or 'credential' not in saved or saved['credential'] != state.get('credential'):
        raise Pending('loan_list_required')
    rows = [row for category in account_protocol.visible(saved['categories'], loans=True) for row in category['assetList']]
    if index is None and len(rows) == 1:
        index = 1
    if index is None or not 1 <= index <= len(rows):
        raise Pending('loan_selection_required')
    return rows[index-1], saved['attempt']


def program(settings, state, row, exchange=None, acknowledge=None, queue_progress=None):
    # Only the selected row supplies navigation. Buttons and account prefixes
    # do not substitute for a row's destination.
    identity = row.get('programId', '').strip().upper().replace(' ', '')
    if not identity:
        raise Pending('loan_row_has_no_destination')
    intro = state.get('intro') or {}
    if exchange is not None:
        found = navigation.resolve(exchange, identity)
    else:
        value = (state.get('menu') or {}).get('value')
        if value is None:
            if 'menu' not in settings:
                raise Pending('loan_menu_settings_refresh_required')
            if intro.get('menuDownlYnS1') == 'Y':
                raise Pending('loan_menu_download_required')
            value = menu_protocol.decode(json.dumps(settings['menu']))
        found = menu_protocol.local(value, identity)
        if len(identity.encode('utf-16-le', errors='surrogatepass')) // 2 > 20:
            raise Pending('loan_destination_unavailable')
        if found is None or not found['PR_ID']:
            raise Pending('loan_destination_server_lookup_required')
    name = found.get('PR_ID')
    if name not in PROGRAMS or found.get('PR_TYPE') != 'W':
        raise Pending('loan_destination_not_implemented')
    if found.get('MOVE_URL') != f'/web/pages/BM/BM03/{name[:6]}/{name}.html':
        raise Pending('loan_destination_path_not_implemented')
    return navigation_guard.open_program(settings, state, found, exchange, acknowledge, queue_progress)


def parameters(value, kind):
    if value is None or value == '':
        source = {}
    else:
        try:
            source = json.loads(value)
        except (ValueError, TypeError):
            # Extended Android object syntax has not been interpreted here.
            raise Pending('loan_parameters_not_supported') from None
    if not isinstance(source, dict):
        raise Pending('loan_parameters_not_supported')
    source = copy.deepcopy(source)
    selected = source.get('P')
    if legacy_web.nullish(selected):
        selected = source if kind == 'installment' else {}
    if not legacy_web.nullish(source.get('GP')) and legacy_web.nullish(selected):
        selected = source['GP']
    if not isinstance(selected, dict):
        raise Pending('loan_parameters_not_supported')
    return selected


def request(exchange, name, stage, transaction, body, *, show=True):
    verdict, document = legacy_web.call(exchange, stage, transaction, body, program=name, show_message=show)
    if not verdict['callback_ready']:
        raise Pending(verdict['required_action'])
    if not verdict['bridge_success']:
        raise Pending('loan_detail_request_unavailable')
    return document.get('dataBody')


def date(exchange, name):
    result = request(exchange, name, 'loan_detail_server_date', 'RSMCM9000A03',
                     {'bdtInqrGS20': 'getCurrentDateFmt', 'dtFrmtS20': 'yyyyMMdd'}, show=False)
    return result['getCurrentDateFmt']['valueS20']


def account_number(value):
    # sbReplaceAll/sbTransAcctNo: null, numeric zero and false become empty.
    if not value:
        return ''
    if not isinstance(value, str):
        if isinstance(value, bool): value = 'true'
        elif isinstance(value, (float, int)): value = str(int(value)) if int(value) == value else str(value)
        else: raise Pending('loan_parameters_not_supported')
    return value.strip().replace('-', '')


def inquiry(exchange, name, params):
    kind = PROGRAMS[name]
    data = {'program': name, 'kind': kind, 'account': None}
    if kind == 'installment':
        account = params.get('acno')
        if legacy_web.nullish(account):
            for field in ('acnoS12', '계좌번호'):
                if not legacy_web.nullish(params.get(field)):
                    account = params[field]
                    break
        body = {'대량거래여부': '2', '실행번호': '0', '조회구분': '1'}
        if account is not None or 'acno' in params:
            body['ysAcno'] = account
        value = request(exchange, name, 'loan_account_detail', 'RSMLO1002A01', body)
        data['account'] = value
        exchange.report['detail_result'] = 'success'
        save(exchange, data)
        # The page reads acno.substr before asking for the date.
        if not isinstance(value, dict) or not isinstance(value.get('acno'), str):
            raise ValueError('loan_detail_body_unavailable')
        data['as_of'] = date(exchange, name)
    else:
        today = date(exchange, name)
        body = {'acno': account_number(params.get('acnoS12')), 'inqrSjdt': today, 'inqrEndt': today, 'procGL1': '0', 'sortGL1': '1'}
        if kind == 'current':
            body.update(trxbrBnkGL1='1', ysLotTrxG='2', jhcnt=10, trxGL3='3', kwaG='1', masS='0', bnkG='1')
        value = request(exchange, name, 'loan_account_detail', 'RSMLO0101A01' if kind == 'overdraft' else 'RSMDE0105A08', body, show=False)
        data.update(account=value, as_of=today)
        exchange.report['detail_result'] = 'success'
        save(exchange, data)
        if kind == 'overdraft':
            if not isinstance(value, dict):
                raise ValueError('loan_detail_body_unavailable')
            extra = request(exchange, name, 'loan_account_rate_details', 'RSMLO1003A01',
                {'acno': account_number(params.get('acnoS12')), 'bnkG': '1', 'upmuG': '1', 'jkwInqrYnS1': '1', 'imptdocProcG': '1', 'trxbrBnkGL1': '1'})
            data['rate_details'] = extra
            exchange.report['rate_details_result'] = 'success'
    data['fields'] = fields(data, params)
    exchange.report.update(detail_available=True, processing_status='complete')
    save(exchange, data)


def fields(data, params):
    value, kind = data['account'], data['kind']
    if not isinstance(value, dict):
        raise ValueError('loan_detail_body_unavailable')
    if kind == 'installment':
        mapping = {'product_name': 'prdtCNmS100', 'account_number': 'acno', 'loan_amount': 'dcTamt', 'balance': 'dcJan',
                   'interest_rate': 'aplIyul', 'rate_description': 'iyulCtntS500', 'started_on': 'fstYakjSjdt',
                   'matures_on': 'exeDudt', 'next_interest_on': 'nxtIntIpDt', 'interest_account': 'icheAcno', 'branch': 'grbrNm', 'collateral_account': 'dmbAcno1'}
        if params.get('prdtC') == '711130009':
            mapping.pop('loan_amount'); mapping.pop('next_interest_on')
            mapping['agreed_amount'] = 'yakjAmt'
    else:
        mapping = {'account_number': 'acno', 'limit_amount': 'dcHdamt', 'interest_rate': 'dcIyul', 'matures_on': 'dcDudt', 'branch': 'grbrNmS20'}
        if kind == 'current':
            mapping.update(product_name='prdtBkkpNm', balance='masJan', cheque_bill_amount='mikjTjumAmt')
        else:
            mapping.update(interest_amount='dcInt', balance='masJan', available_amount='jibulPsbJan')
    result = {label: value.get(field) for label, field in mapping.items()}
    if kind == 'overdraft':
        result['product_name'] = params.get('prdtname') if not legacy_web.nullish(params.get('prdtname')) else params.get('dcPrdtNmS80')
        extra = data.get('rate_details')
        if not isinstance(extra, dict):
            raise ValueError('loan_rate_details_unavailable')
        result['rate_description'] = extra.get('filler') if not legacy_web.nullish(extra.get('filler')) else value.get('filler')
    return result


def save(exchange, data):
    path = exchange.run/'loan-detail.json'
    try:
        storage.atomic_json(path, data)
        exchange.report['data_file'] = str(path)
    except Exception:
        exchange.warning('loan_detail_data_save_error')


def run(index=None, *, acknowledge=None, queue_progress=None):
    settings = setup.load()
    folder = setup.prepare_directory()
    with storage.lock(folder/'.lock'):
        path = folder/'session.json'
        state = storage.read_json(path) if path.exists() else {}
        if not state.get('cookie'):
            raise SessionRequired()
        if not state.get('authenticated'):
            raise LoginRequired()
        exchange = Exchange(settings, state, 'loan_detail')
        try:
            row, attempt = select(state, index)
            exchange.report['list_attempt'] = attempt
            name = program(settings, state, row, exchange, acknowledge, queue_progress)
            params = parameters(row.get('programParam'), PROGRAMS[name])
            inquiry(exchange, name, params)
        except Pending as error:
            exchange.report.update(processing_status='incomplete', required_action=error.action)
        except (KeyboardInterrupt, EOFError):
            exchange.report.update(processing_status='incomplete', error='interrupted')
        except Exception:
            exchange.report.update(processing_status='incomplete', error='loan_detail_processing_error')
        state['last_operation'] = exchange.report['operation']
        exchange.save()
        return exchange.report
