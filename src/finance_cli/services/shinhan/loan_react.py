"""Loan overview queries needed by its account-management action."""
from finance_cli.core import storage
from . import web
from .additional_auth import js_text
from .enrollment import Pending

PROGRAM = 'BM1509S0801T02'
MANAGEMENT = 'BM0302S0404F01'
PATH = '/react/BM/BM15/BM1509/BM1509S0801T02'


def summary(body, account):
    # The page uses find and strict equality, converting only the row number.
    for row in body['grid01']:
        value = row['dcAcnoN12_originalValue']
        if value is None:
            raise ValueError('loan_summary_number_unavailable')
        if js_text(value) == account:
            due = row.get('dcDueDdS8')
            due = due if web.truthy(due) else ''
            return {**row, 'accountDueDate': due, 'loanAmount': due}
    return None


def management(header, selected, account):
    if not web.truthy(header) or not web.truthy(selected):
        raise Pending('loan_management_unavailable')
    # Empty/missing optional header fields are not a reason to reject navigation.
    params = {'acnoS12': account, 'acnoS12_originalValue': account,
              'dcPrdtNmS80': '', 'dueDdS8': selected['accountDueDate'].replace('.', '')}
    for source, mapping in ((header, {'bnkGN2': 'bnkGN2', 'guAcno': 'guAcno',
                                      'kwaNmS80': 'kwaNmS80', 'newAcCvtYnN1': 'newAcCvtYnN1'}),
                            (selected, {'lstIntIpDdS8_originalValue': 'lstIntipDdS8_originalValue',
                                        'mkDdS8_originalValue': 'mkdt_originalValue'})):
        if isinstance(source, dict):
            params.update({target: source[field] for target, field in mapping.items() if field in source})
    return params


def prepare(exchange, params):
    account = params.get('acnoS12', '')
    values, verdicts = {}, []
    # These are independent queries in the page. Neither bank rejection suppresses
    # the other query. The transaction ledger is not needed by this action.
    for key, transaction, body in (
            ('header', 'RSMDE0105A21', {'acno': account, 'bnkCdS3': '088', 'assetK': ''}),
            ('summary', 'RSMLO1001A04', {'acno': account})):
        verdict, document = exchange.web('loan_overview_'+key, transaction, body, program=PROGRAM)
        exchange.report.update(bank_result=verdict['bank_result'])
        exchange.report['overview_'+key+'_result'] = verdict['bank_result']
        verdicts.append(verdict)
        values[key] = document.get('dataBody') if isinstance(document, dict) else None
        try:
            path = exchange.run/'loan-entry.json'
            storage.atomic_json(path, {'program': PROGRAM, **values})
            exchange.report['entry_data_file'] = str(path)
        except Exception:
            exchange.warning('loan_entry_data_save_error')
    for verdict in verdicts:
        if not verdict['callback_ready']:
            raise Pending(verdict['required_action'])
        if not verdict['bridge_success']:
            raise Pending('loan_overview_request_unavailable')
    selected = summary(values['summary'], account)
    return management(values['header'], selected, account)
