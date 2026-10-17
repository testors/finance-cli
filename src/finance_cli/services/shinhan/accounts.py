"""Single authenticated list inquiry with private account data and public counts."""
import json

from finance_cli.core import storage
from . import account_protocol as protocol, setup
from .exchange import Exchange
from .session import SessionRequired


class LoginRequired(ValueError):
    pass


def run(*, loans=False, refresh=False):
    settings = setup.load()
    folder = setup.prepare_directory()
    with storage.lock(folder / '.lock'):
        path = folder / 'session.json'
        state = storage.read_json(path) if path.exists() else {}
        if not state.get('cookie'):
            raise SessionRequired()
        if not state.get('authenticated'):
            raise LoginRequired()
        exchange = Exchange(settings, state, 'loans' if loans else 'accounts')
        report = exchange.report
        state.pop('accounts', None)
        try:
            step, document = exchange.bank('account_list', 'RSMDE0101A20',
                {'inqrGN2': 9, 'refreshYn': int(refresh)}, path='/serviceEndpoint/httpDigital/',
                response_parser=protocol.parse_reply)
            report['bank_result'] = step['result']
            if step['result'] != 'success' or step['processing_status'] != 'complete':
                report.update(processing_status='incomplete', error=step.get('error', 'account_list_unavailable'))
                state.pop('accounts', None)
            else:
                body = document['dataBody']
                categories = protocol.categories(body)
                selected = protocol.visible(categories, loans=loans)
                scope = 'visible_shinhan_loans' if loans else 'visible_shinhan_accounts'
                state['accounts'] = {'attempt': exchange.attempt, 'credential': state.get('credential'),
                                     'selection_scope': scope, 'categories': categories, 'summary': protocol.summary(body['totalSummary'])}
                count = sum(len(category['assetList']) for category in selected)
                index = 0
                selected = [{**category, 'assetList': [dict(row) for row in category['assetList']]} for category in selected]
                for category in selected:
                    for row in category['assetList']:
                        index += 1
                        row['index'] = index
                report.update(processing_status='complete', selection_scope=scope, count=count)
                # Product data stays separate from the shareable diagnostic report.
                output = exchange.run / 'accounts.json'
                try:
                    storage.write_new(output, (json.dumps({'categories': selected}, ensure_ascii=False)+'\n').encode())
                    report['data_file'] = str(output)
                except Exception:
                    exchange.warning('account_data_save_error')
            state['last_operation'] = report['operation']
        except (KeyboardInterrupt, EOFError):
            report.update(processing_status='incomplete', error='interrupted')
        except Exception:
            report.update(processing_status='incomplete', error='account_processing_error')
        exchange.save()
        return report
