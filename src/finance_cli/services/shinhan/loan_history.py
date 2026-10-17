"""Date-filtered installment loan transactions selected from the loan list."""
import json

from finance_cli.core import storage
from . import loan_detail, loan_history_protocol as protocol, loan_react, setup
from .accounts import LoginRequired
from .enrollment import Pending
from .exchange import Exchange
from .history import combined
from .session import SessionRequired


def save(exchange, data):
    try:
        path = exchange.run/'loan-transactions.json'
        storage.atomic_json(path, data)
        exchange.report['data_file'] = str(path)
    except Exception:
        exchange.warning('loan_history_data_save_error')


def pages(exchange, data, account, start, end):
    cursor = protocol.MISSING
    seen = set()
    results = []
    while True:
        key = json.dumps(protocol.request(account, start, end, cursor), sort_keys=True)
        if key in seen:
            raise Pending('loan_history_cursor_repeated')
        seen.add(key)
        step, document = exchange.web('loan_history_page', protocol.TRANSACTION,
            protocol.request(account, start, end, cursor), program=loan_react.PROGRAM)
        results.append(step['bank_result'])
        exchange.report.update(bank_result=combined(results), page_result=step['bank_result'])
        if not step['callback_ready']:
            raise Pending(step['required_action'])
        if not step['bridge_success']:
            raise Pending('loan_history_request_unavailable')
        data['pages'].append(document.get('dataBody') if isinstance(document, dict) else None)
        exchange.report['pages_available'] = len(data['pages'])
        save(exchange, data)
        cursor = protocol.next_cursor(data['pages'][-1])
        exchange.report['has_next'] = cursor is not protocol.MISSING
        if cursor is protocol.MISSING:
            data['query_complete'] = True
            return


def run(index=None, *, year=None, start=None, end=None, order='OLDEST', acknowledge=None, queue_progress=None):
    first, last = protocol.period(year, start, end)
    settings = setup.load()
    folder = setup.prepare_directory()
    with storage.lock(folder/'.lock'):
        path = folder/'session.json'
        state = storage.read_json(path) if path.exists() else {}
        if not state.get('cookie'):
            raise SessionRequired()
        if not state.get('authenticated'):
            raise LoginRequired()
        exchange = Exchange(settings, state, 'loan_transactions')
        data = {'program': loan_react.PROGRAM, 'query': {'start': first, 'end': last, 'order': order},
                'pages': [], 'query_complete': False}
        try:
            row, attempt = loan_detail.select(state, index)
            exchange.report['list_attempt'] = attempt
            name = loan_detail.program(settings, state, row, exchange, acknowledge, queue_progress)
            if name != loan_react.PROGRAM:
                raise Pending('loan_history_destination_not_implemented')
            params = loan_detail.parameters(row.get('programParam'), 'react')
            account = params.get('acnoS12', '')
            # Header/summary queries are independent of the ledger. The explicit
            # period also needs no current-date/default-period UI preparation.
            data['query']['account'] = account
            pages(exchange, data, account, first, last)
        except Pending as error:
            exchange.report.update(processing_status='incomplete', required_action=error.action)
        except (KeyboardInterrupt, EOFError):
            exchange.report.update(processing_status='incomplete', error='interrupted')
        except Exception:
            exchange.report.update(processing_status='incomplete', error='loan_history_processing_error')
        if data['pages']:
            try:
                data['transactions'] = protocol.transactions(data['pages'], order)
                data['months'] = protocol.monthly(data['pages'], data['transactions'], first, last, data['query_complete'])
                exchange.report.update(count=sum(len(rows) for _, rows in data['transactions']),
                                       query_complete=data['query_complete'], monthly_available=True)
                if data['query_complete']:
                    exchange.report['processing_status'] = 'complete'
            except Exception:
                exchange.report.update(processing_status='incomplete', error='loan_history_mapping_error')
            save(exchange, data)
        state['last_operation'] = exchange.report['operation']
        exchange.save()
        return exchange.report
