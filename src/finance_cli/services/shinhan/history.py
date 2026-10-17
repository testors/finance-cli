"""Transaction history for a bank-selected native account destination."""
from dataclasses import asdict

from finance_cli.core import storage
from . import account_protocol, history_header, history_protocol, history_screen, menu, navigation_guard, setup
from .accounts import LoginRequired
from .enrollment import Pending
from .exchange import Exchange
from .session import SessionRequired


def select(state, index):
    saved = state.get('accounts') or {}
    if saved.get('selection_scope') != 'visible_shinhan_accounts' or saved.get('credential') != state.get('credential'):
        raise Pending('history_account_list_required')
    rows = [row for category in account_protocol.visible(saved['categories']) for row in category['assetList']]
    if index is None and len(rows) == 1:
        index = 1
    if index is None or not 1 <= index <= len(rows):
        raise Pending('history_account_selection_required')
    return rows[index-1], index, saved['attempt']


def destination(row):
    def identity(value):
        return value.strip().upper().replace(' ', '')
    if identity(row['programId']) == history_screen.PROGRAM:
        return row['programId'], row['programParam']
    # The all-account UI exposes only its first button. Do not select a later
    # hidden action or bypass a confirmation attached to the visible button.
    button = next(iter(row['buttonList']), None)
    if button is not None and identity(button['programId']) == history_screen.PROGRAM:
        if button['isShowPopup']:
            raise Pending('history_account_button_confirmation_required')
        return button['programId'], button['programParam']
    # A server-resolved row can still identify the native screen. Its result
    # is checked before any history request; no account-number substitution.
    if row['programId']:
        return row['programId'], row['programParam']
    raise Pending('history_destination_unavailable')


def open_program(exchange, identity, acknowledge, queue_progress):
    try:
        found = menu.resolve(exchange, identity.strip().upper().replace(' ', ''))
        if found['PR_ID'] != history_screen.PROGRAM or found['PR_TYPE'] != 'N' or found['MOVE_URL'] != history_screen.PROGRAM:
            raise Pending('history_destination_not_implemented')
        return navigation_guard.open_program(exchange.settings, exchange.state, found, exchange,
                                             acknowledge, queue_progress, scope='history')
    except Pending as error:
        if error.action.startswith('loan_'):
            raise Pending('history'+error.action[4:]) from None
        raise


def combined(results):
    if all(value == 'success' for value in results):
        return 'success'
    if 'success' in results:
        return 'partial_success'
    if all(value == 'failure' for value in results):
        return 'failure'
    return 'unknown'


def header(exchange, saved):
    report = exchange.report
    saved['header_result'] = 'unknown'
    saved['header_processing_status'] = 'incomplete'
    try:
        step, document = exchange.bank('history_header', history_header.TRANSACTION, saved['parameters'],
            path=history_protocol.ENDPOINT, response_parser=history_header.parse_reply)
        saved['header_result'] = step['bank_result']
        report['header_result'] = step['bank_result']
        if step['bank_result'] == 'success' and step['processing_status'] == 'complete':
            saved['header'] = history_header.mapped(document['dataBody'])
            saved['header_processing_status'] = 'complete'
    except (KeyboardInterrupt, EOFError):
        raise
    except Exception:
        report['header_error'] = 'history_header_processing_error'
    report['header_processing_status'] = saved['header_processing_status']


def page(exchange, saved):
    query = history_protocol.Query(**saved['query'])
    cursor = history_protocol.Cursor(**saved['cursor'])
    report = exchange.report
    step, document = exchange.bank('history_page', history_protocol.TRANSACTION, cursor.request(query),
        path=history_protocol.ENDPOINT, response_parser=history_protocol.parse_reply)
    report['page_result'] = step['bank_result']
    if step['bank_result'] != 'success' or step['processing_status'] != 'complete':
        report.update(processing_status='incomplete', error=step.get('error', 'history_page_unavailable'))
        return
    def date_error():
        report['unparsed_dates'] = report.get('unparsed_dates', 0)+1
    value = cursor.page(query, document['dataBody'], saved['next_key'], date_error)
    saved['pages'].append(value)
    saved.update(cursor=asdict(cursor), next_key=value['nextKey'])
    report.update(processing_status='complete', page_count=len(value['data'])-1)


def save_data(exchange, saved):
    report = exchange.report
    if saved['pages']:
        report.update(count=sum(len(page['data'])-1 for page in saved['pages']),
                      pages_available=len(saved['pages']), has_next=saved['cursor']['has_next'])
    if saved.get('header') is not None or saved['pages']:
        path = exchange.run/'history.json'
        try:
            storage.atomic_json(path, {'parameters': saved['parameters'], 'query': saved['query'],
                'header': saved.get('header'), 'pages': saved['pages']})
            report['data_file'] = str(path)
        except Exception:
            exchange.warning('history_data_save_error')


def run(index=None, *, next_page=False, start=None, end=None, transaction_type='DEFAULT', sort='LATEST_ORDER',
        min_amount=history_protocol.MIN_AMOUNT, max_amount=history_protocol.MAX_AMOUNT, keyword='',
        acknowledge=None, queue_progress=None):
    settings = setup.load()
    folder = setup.prepare_directory()
    with storage.lock(folder/'.lock'):
        path = folder/'session.json'
        state = storage.read_json(path) if path.exists() else {}
        if not state.get('cookie'):
            raise SessionRequired()
        if not state.get('authenticated'):
            raise LoginRequired()
        exchange = Exchange(settings, state, 'transactions_next' if next_page else 'transactions')
        report = exchange.report
        saved = None
        try:
            if next_page:
                saved = state.get('history')
                if not saved or saved['credential'] != state.get('credential') or saved['list_attempt'] != (state.get('accounts') or {}).get('attempt'):
                    saved = None
                    raise Pending('history_query_required')
                if not saved['pages']:
                    raise Pending('history_first_page_required')
                if not saved['cursor']['has_next']:
                    report.update(processing_status='complete', page_result='not_requested')
                report['header_result'] = saved['header_result']
                report['header_processing_status'] = saved['header_processing_status']
            else:
                state.pop('history', None)
                row, index, attempt = select(state, index)
                identity, text = destination(row)
                open_program(exchange, identity, acknowledge, queue_progress)
                params = history_screen.parameters(text)
                first, last = history_screen.period(start, end)
                query = history_protocol.Query(params['acno'], start=first, end=last, transaction_type=transaction_type,
                    sort=sort, min_amount=min_amount, max_amount=max_amount, keyword=keyword)
                saved = {'credential': state.get('credential'), 'list_attempt': attempt, 'account_index': index,
                    'parameters': params, 'query': asdict(query), 'cursor': asdict(history_protocol.Cursor()),
                    'next_key': 1, 'header': None, 'header_result': 'unknown', 'header_processing_status': 'incomplete', 'pages': []}
                state['history'] = saved
                user = (state.get('login') or {}).get('user') or {}
                if params['assetK'] == '1' and user.get('checkCddDsynS1') == 'Y':
                    saved['customer_verification_notice'] = True
                header(exchange, saved)
            report.update(account_index=saved['account_index'], list_attempt=saved['list_attempt'])
            if report.get('page_result') != 'not_requested':
                page(exchange, saved)
        except Pending as error:
            report.update(processing_status='incomplete', required_action=error.action)
        except (KeyboardInterrupt, EOFError):
            report.update(processing_status='incomplete', error='interrupted')
        except Exception:
            report.update(processing_status='incomplete', error='history_processing_error')
        if saved is not None:
            # Keep previous page/header acceptance when a later page or local
            # mapper/save fails. Current page status is reported separately.
            results = [saved['header_result']]
            if report.get('page_result') != 'not_requested':
                results.append(report.get('page_result', 'unknown'))
            if saved['pages']:
                results.append('success')
            report['bank_result'] = combined(results)
            if saved['header_processing_status'] != 'complete':
                report['processing_status'] = 'incomplete'
            if saved.get('customer_verification_notice'):
                report.update(required_action='history_customer_verification_notice', processing_status='incomplete')
            save_data(exchange, saved)
        state['last_operation'] = report['operation']
        exchange.save()
        return report
