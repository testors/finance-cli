"""Read-only ledger/inquiry using an existing OneSign login and sealed receipts.

The joint-login query planners retain endpoint, account, scope and cursor checks.
Only their receipt/account source changes. No login, refresh, signing or retry.
The caller holds the identity operation lock and supplies an explicit send flag.
"""
import base64
import gzip

from . import inquiry, ledger, ledger_protocol, store, request_activity
from .evidence import account
from .hana_protocol import API
from .onesign_codec import encode
from .onesign_crypto import ProtocolError
from .onesign_io import Client, send_http
from .onesign_transfer import binding

PATHS = frozenset(ledger_protocol.PATHS.values()) | {inquiry.PATHS[k] for k in ('history', 'detail')}


class Queries:
    def __init__(self, state, session, *, exchange=None):
        self.state, self.session = state, session
        self.bound = binding(state, session)
        self.exchange = exchange or send_http

    def headers(self):
        return {k.lower(): v for k, v in self.state.snapshot()['sessions'][self.session]['headers'].items()}

    def accounts(self):
        rows = (self.state.snapshot()['sessions'][self.session].get('accounts') or {}).get('mainAcctList')
        if not isinstance(rows, list):
            raise ValueError('accounts_query_required_in_session')
        return rows

    def account_index(self, number):
        matches = [i for i, row in enumerate(self.accounts(), 1)
                   if isinstance(row, dict) and str(row.get('acctNo')) == number]
        if len(matches) != 1:
            raise ValueError('account_not_in_session_accounts')
        return matches[0]

    def authenticated_account(self, config):
        rows, index = self.accounts(), config['account_index']
        if type(index) is not int or not 1 <= index <= len(rows):
            raise ValueError('expected_a_positive_account_index')
        selected = rows[index - 1]
        if not isinstance(selected, dict) or account(selected.get('acctNo')) is None or selected.get('curCd') != 'KRW':
            raise ValueError('expected_a_krw_account')
        if self.account_index(str(selected['acctNo'])) != index:
            raise ValueError('account_selection_is_not_unique')
        return {'method': 'POST', 'headers': self.headers()}, selected

    def metadata(self, run):
        saved = self.state.read_record(run, 'query')
        if saved['binding'] != self.bound or self.bound != binding(self.state, self.session):
            raise ValueError('query_login_identity_changed')
        return saved

    def read_receipt(self, run):
        saved = self.metadata(run)
        response = self.state.read_record(run, 'http-0001-response')
        raw = base64.b64decode(response['body'], validate=True)
        if dict((k.lower(), v) for k, v in response['headers']).get('content-encoding', '').lower() == 'gzip':
            raw = gzip.decompress(raw)
        return saved['request'], response, raw

    def perform(self, request, receipt_key, config, observation, *, send=False):
        if not send:
            raise ValueError('explicit_send_required')
        path = request['url'][len(API):] if request.get('url', '').startswith(API) else None
        if request.get('method') != 'POST' or path not in PATHS:
            raise ValueError('read_only_query_endpoint_required')
        if self.bound != binding(self.state, self.session):
            raise ValueError('query_login_identity_changed')
        # Same continuation, even in another web job, cannot be sent a second time.
        run = 'query-' + store.digest([self.bound, observation, receipt_key])[:40]
        scope = self.state.begin_run(run, 'query')
        self.state.record(run, 'query', {'binding': self.bound, 'request': request, 'config': config,
                                        'observation': observation})
        client = Client(self.state, run, self.session, send=True, exchange=self.exchange)
        client.query_paths = PATHS
        meta = request.get('account_history') or request['inquiry']
        kind = meta['kind']
        result = {'accepted': None, 'receipt_directory': run, 'automatic_retry': False,
                  'transfer_confirmed': False, 'processing_status': 'not_started'}
        try:
            raw = client.request('bank', 'POST', path, request['headers'], encode(request['body']), web=kind != 'clock')
            assessed = (ledger.assess(kind, client.last['http_status'], client.response_headers, raw)
                        if 'account_history' in request else inquiry.assess(kind, client.last['http_status'],
                            client.response_headers, raw, request['body'], (meta.get('previous') or {}).get('history_total')))
            result.update(assessed, processing_status='completed')
        except (ValueError, OSError) as error:
            result['reason'] = str(error) if isinstance(error, (ProtocolError, request_activity.RequestBlocked)) else 'local_processing_error'
            # Common-header verdict survives response decoding/storage failure.
            result.update(accepted={'accepted': True, 'rejected': False}.get(client.last['service_status']),
                          processing_status=client.last['processing_status'])
        result.update(network_used=client.sent > 0, service_status=client.last['service_status'])
        try:
            with scope.transaction() as value:
                value.update(outcome=client.last['service_status'], halted=result['processing_status'] != 'completed')
        except (ValueError, OSError):
            result['processing_status'] = 'result_storage_failed'
        return result
