"""Read-only loan and certificate commands using an existing personal login."""
import uuid

from . import inquiry, ledger, ledger_protocol, login, store, transport
from . import loan_evidence_protocol as protocol
from .hana_protocol import API, decode_header, encode_header


def add_parsers(sub):
    loans = sub.add_parser('loans', help='대출 금액·기간·금리·거래내역 및 이자 상세 조회')
    loans.add_argument('action', nargs='?', default='history', choices=('history', 'executions', 'interest'))
    loans.add_argument('--account', help='대출 계좌번호')
    loans.add_argument('--execution', type=int, help='실행번호; 생략하면 계좌의 기본 실행번호')
    certificates = sub.add_parser('certificates', help='금융거래확인서·부채증명원 신청내역 및 문서 링크 조회')
    certificates.add_argument('action', nargs='?', default='list', choices=('list', 'link'))
    certificates.add_argument('--type', choices=tuple(protocol.CERTIFICATES),
                              help='financial: 금융거래확인서, debt: 부채증명원; list에 필요')
    for item in (loans, certificates):
        item.add_argument('--name', help='하나인증서 저장소 이름')
        item.add_argument('--session', help='기존 로그인 세션; 호환 세션이 하나면 자동 선택')
        item.add_argument('--password-stdin', action='store_true', help='하나인증서 저장소 암호 한 줄')
        item.add_argument('--start', help='조회 시작일 YYYY-MM-DD 또는 YYYYMMDD')
        item.add_argument('--end', help='조회 종료일; 기본 서버 오늘')
        item.add_argument('--previous', help='interest/link: 선택할 행이 저장된 조회 receipt')
        item.add_argument('--row', type=int, help='interest/link: 저장된 조회 결과의 1부터 시작하는 행')
        item.add_argument('--send', action='store_true', help='은행 조회 허용; 자동 로그인·재시도 없음')


def controls(args):
    detail = args.action in ('interest', 'link')
    if detail:
        if not args.previous or args.row is None or args.row < 1:
            raise ValueError('saved_receipt_and_positive_row_required')
        store.name(args.previous)
        if args.start or args.end or getattr(args, 'account', None) or getattr(args, 'execution', None) is not None or getattr(args, 'type', None):
            raise ValueError('detail_uses_saved_query_selection')
    elif args.previous or args.row is not None:
        raise ValueError('row_selection_is_only_for_interest_or_link')
    if args.operation == 'loans' and not detail:
        from .evidence import account
        if account(args.account) is None:
            raise ValueError('loan_account_required')
        args.account = account(args.account)
        if args.execution is not None and args.execution < 1:
            raise ValueError('positive_execution_number_required')
        if args.action == 'executions' and (args.start or args.end or args.execution is not None):
            raise ValueError('execution_list_needs_only_account')
    if args.operation == 'certificates' and not detail and not args.type:
        raise ValueError('certificate_type_required')
    if args.password_stdin and not args.name:
        raise ValueError('password_stdin_requires_onesign_name')
    start, end = (v.replace('-', '') if v else None for v in (args.start, args.end))
    try:
        protocol.period(inquiry.today_kst().strftime('%Y%m%d'), start, end,
                        certificates=args.operation == 'certificates')
    except ValueError:
        raise ValueError('invalid_query_period') from None
    return start, end


def prepare(headers, kind, body, observation, **context):
    headers = {k.lower(): v for k, v in headers.items()}
    for key in login.IDENTITY:
        headers[key] = headers[key].strip()
    if kind != 'clock':
        common = decode_header(headers['hana-com-header'])
        common['CNL_HDPT']['SCRN_ID'] = ('INQB0806002001' if kind == 'link' else
            'INQB0806001001' if kind == 'certificates' else 'INQB0201001001')
        headers['hana-com-header'] = encode_header(common)
    headers['content-type'] = 'application/json;charset=utf-8'
    meta = {'kind': kind, 'observation': observation, **context}
    request = {'method': 'POST', 'url': API + protocol.PATHS[kind], 'headers': headers,
               'body': body, 'loan_evidence': meta, 'live_verified': False,
               'mode': 'prepared read-only loan or certificate query; no request sent'}
    return request, 'loan-query-' + kind + '-' + store.digest([body, meta])[:20]


def joint_perform(session):
    def perform(request, receipt_key, config, observation, *, send=False):
        if not send:
            raise ValueError('explicit_send_required')
        observed = {'accepted': None, 'network_used': False, 'receipt_directory': receipt_key}

        def assess(_, status, headers, raw):
            verdict = ledger.assess(request['loan_evidence']['kind'], status, headers, raw)
            observed.update(verdict)  # Preserve the verdict before any receipt/cookie write.
            return verdict

        try:
            store.write_new(store.child(session, receipt_key + '-prepared.json'), request)
            observed.update(transport.send(session, receipt_key, request, assess), processing_status='completed')
        except (ValueError, OSError):
            observed.update(processing_status='stopped', reason='query_processing_error')
            observed['network_used'] |= store.child(session, receipt_key, 'attempt.json').exists()
        observed['service_status'] = {True: 'accepted', False: 'rejected', None: 'unconfirmed'}[observed['accepted']]
        return observed
    return perform


class Stopped(Exception):
    pass


class Reader:
    def __init__(self, source, headers, perform):
        self.source, self.headers, self.perform = source, headers, perform
        self.observation = uuid.uuid4().hex
        self.result = {'accepted': None, 'service_status': 'unconfirmed', 'network_used': False,
                       'automatic_retry': False, 'state_change_requested': False, 'complete': False,
                       'processing_status': 'running', 'stages': [], 'warnings': [],
                       'live_verified': False}

    def saved(self, name, kind):
        request, response, raw = transport.read_receipt(self.source, name)
        if (request.get('method') != 'POST' or request.get('url') != API + protocol.PATHS[kind]
                or request.get('loan_evidence', {}).get('kind') != kind):
            raise ValueError('unexpected_loan_or_certificate_receipt')
        old = {k.lower(): v for k, v in request['headers'].items()}
        if any(not old.get(k) or old[k].strip() != self.headers[k].strip() for k in login.IDENTITY):
            raise ValueError('receipt_belongs_to_another_login')
        if not ledger.assess(kind, response['status'], response['headers'], raw)['accepted']:
            raise ValueError('saved_query_was_not_accepted')
        return request, ledger.payload(kind, raw)

    def query(self, kind, body, *, primary=False, **context):
        draft = prepare(self.headers, kind, body, self.observation, **context)
        observed = self.perform(*draft, {}, self.observation, send=True)
        stage = {'stage': kind, **{k: observed[k] for k in
                 ('accepted', 'service_status', 'processing_status', 'reason', 'receipt_directory') if k in observed}}
        self.result['stages'].append(stage)
        self.result['network_used'] |= observed.get('network_used', False)
        self.result['warnings'].extend(observed.get('warnings', []))
        if primary and self.result['accepted'] is not True:
            self.result.update(accepted=observed.get('accepted'),
                               service_status=observed.get('service_status', 'unconfirmed'))
        if observed.get('accepted') is not True or observed.get('processing_status') != 'completed':
            if self.result['accepted'] is not True:
                self.result.update(accepted=observed.get('accepted'),
                                   service_status=observed.get('service_status', 'unconfirmed'))
            raise Stopped()
        receipt = observed['receipt_directory']
        try:
            _, value = self.saved(receipt, kind)
            # Certificates use optional chaining even for a null result.
            if kind == 'certificates' and value is None:
                self.result['warnings'].append('certificate_response_null')
                value = {}
            if not isinstance(value, dict):
                raise ValueError('response_object_unavailable')
        except (ValueError, OSError, KeyError, TypeError, AttributeError):
            stage['processing_status'] = 'response_unusable'
            raise Stopped() from None
        return value, receipt

    def finish(self):
        self.result.update(complete=True, processing_status='completed')
        return self.result


def selected_account(source, headers, number):
    if hasattr(source, 'accounts'):
        rows = source.accounts()
    else:
        _, value = inquiry.saved(source, 'accounts', 'accounts', headers)
        rows = value['mainAcctList']
    matches = [row for row in rows if isinstance(row, dict) and str(row.get('acctNo')) == number]
    if len(matches) != 1:
        raise ValueError('account_not_unique_in_saved_accounts')
    return matches[0]


def loans(reader, args, start, end):
    selected = selected_account(reader.source, reader.headers, args.account)
    if args.action == 'executions':
        value, receipt = reader.query('executions', {'sefAcmlAmtAcctNo': args.account,
            'inqRqreNcnt': '15', 'actDvCd': '2'}, primary=True)
        reader.result.update(executions=[{'execution': i, 'reported_sequence': row.get('acctSeqNo')}
                            for i, row in enumerate(protocol.rows(value, 'grid'), 1)], receipt=receipt)
        return reader.finish()
    kind, body = protocol.account_request(selected)
    value, _ = reader.query(kind, body)
    info = value['acctInfo']
    if ledger_protocol.account_screen(info) != 'loan':
        raise ValueError('selected_account_does_not_use_loan_history')
    clock, _ = reader.query('clock', {'bussDt': '', 'tgtDt': ''})
    query_period = protocol.period(clock['dt'], start, end)
    execution = args.execution if args.execution is not None else protocol.execution_number(info)
    # These independent screen queries do not gate the transaction query in the app.
    for kind, body, field in (
        ('loan-accounts', {'acctNo': args.account}, 'lonAccountList'),
        ('executions', {'sefAcmlAmtAcctNo': args.account, 'inqRqreNcnt': '15', 'actDvCd': '2'}, 'grid')):
        try:
            value, _ = reader.query(kind, body)
            rows = protocol.rows(value, field)
            if kind == 'loan-accounts':
                reader.result['loan_accounts'] = [dict(execution=row.get('accountSequentialNo'),
                                                      **protocol.loan_summary(row, {})) for row in rows]
                matches = [row for row in rows if protocol.js_string(row.get('accountSequentialNo')) == str(execution)]
                if matches:
                    info = matches[0]
            else:
                reader.result['executions'] = [{'execution': i, 'reported_sequence': row.get('acctSeqNo')}
                                              for i, row in enumerate(rows, 1)]
        except (Stopped, ValueError, KeyError, TypeError, AttributeError):
            reader.result['warnings'].append(kind + '_unavailable')
    first = protocol.page_body(args.account, execution, query_period)
    body, seen = first, set()
    reader.result.update(transactions=[], pages=[], query_period=query_period, execution=execution,
                         atomic_snapshot_verified=False)
    while body is not None:
        key = store.digest(body)
        if key in seen:
            reader.result['warnings'].append('repeated_continuation_cursor')
            raise Stopped()
        seen.add(key)
        value, receipt = reader.query('page', body, primary=True)
        if not reader.result['pages']:
            reader.result['loan'] = protocol.loan_summary(info, value)
        rows = protocol.rows(value, 'grid1')
        reader.result['transactions'].extend(dict(protocol.transaction(row), receipt=receipt, row=i)
                                              for i, row in enumerate(rows, 1))
        reader.result['pages'].append({'receipt': receipt, 'received': len(rows)})
        body = protocol.next_body(first, value)
    return reader.finish()


def detail(reader, args):
    kind = 'page' if args.action == 'interest' else 'certificates'
    request, value = reader.saved(args.previous, kind)
    rows = protocol.rows(value, 'grid1') if kind == 'page' else protocol.certificate_rows(value)
    if args.row > len(rows):
        raise ValueError('saved_query_row_out_of_range')
    row = rows[args.row - 1]
    reader.result.update(source_receipt=args.previous, row=args.row)
    if kind == 'page':
        reader.result.update(transaction=protocol.transaction(row), interest_periods=[])
        body = protocol.interest_body(request['body'], row)
        if body is None:
            reader.result.update(detail_status='not_applicable', period=None)
            return reader.finish()
        value, receipt = reader.query('interest', body, primary=True, previous=args.previous, row=args.row)
        reader.result.update(receipt=receipt, detail_status='queried', interest_periods=[{
            'start_date': item.get('intCalcStrDt'), 'end_date': item.get('intCalcEndDt'),
            'rate': item.get('apclIrrt'), 'interest': item.get('orgnInt'), 'remark': item.get('rmrk')
        } for item in protocol.interest_rows(value, row)])
    else:
        reader.result.update(document_status='unconfirmed', download_status='not_attempted')
        value, receipt = reader.query('link', protocol.link_body(row), primary=True,
                                      previous=args.previous, row=args.row)
        url = value.get('rducUrlAdr')
        reader.result.update(receipt=receipt, document_url=url,
                             document_status='link_available' if ledger_protocol.nonempty(url) else 'not_ready')
        if ledger_protocol.nonempty(url) and not isinstance(url, str):
            reader.result['warnings'].append('document_link_is_not_text')
    return reader.finish()


def certificates(reader, args, start, end):
    clock, _ = reader.query('clock', {'bussDt': '', 'tgtDt': ''})
    query_period = protocol.period(clock['dt'], start, end, certificates=True)
    value, receipt = reader.query('certificates', protocol.certificate_body(args.type, query_period), primary=True)
    reader.result.update(receipt=receipt, query_period=query_period,
                         display_count=protocol.certificate_count(value), certificates=[{
        'row': i, 'type_code': row.get('vcertDvCd'), 'application_date': row.get('apcDt'),
        'application_time': row.get('apcTm'), 'base_date': row.get('bascDt'),
        'fee': row.get('issuComm'), 'delivery_method': row.get('custSrveApcCd')
    } for i, row in enumerate(protocol.certificate_rows(value), 1)])
    return reader.finish()


def collect(reader, args, start, end):
    try:
        if args.action in ('interest', 'link'):
            return detail(reader, args)
        return (loans if args.operation == 'loans' else certificates)(reader, args, start, end)
    except (Stopped, ValueError, OSError, KeyError, TypeError, AttributeError, OverflowError):
        reader.result.update(processing_status='stopped', error='loan_evidence_processing_stopped')
        return reader.result


def dispatch(args):
    start, end = controls(args)
    if not args.send:
        return {'operation': args.operation, 'action': args.action, 'network_used': False,
                'processing_status': 'planned', 'automatic_retry': False, 'state_change_requested': False,
                'next': 'same_command_with_send'}
    if args.name:
        from .onesign_cli import password
        from .onesign_queries import Queries
        from .onesign_state import State
        with State(args.name, password(args)) as state:
            candidates = [name for name, value in state.snapshot()['sessions'].items() if value.get('signed_login') is True]
            session = args.session or (candidates[0] if len(candidates) == 1 else None)
            if session not in candidates:
                raise ValueError('select_one_signed_login_session')
            source = Queries(state, session)
            return collect(Reader(source, source.headers(), source.perform), args, start, end)
    session = args.session
    if session is None:
        from .cli import list_sessions
        candidates = [row['session'] for row in list_sessions()['sessions']
                      if row.get('user_login_verified') is True and row.get('app_auth_accepted') is True]
        if len(candidates) != 1:
            raise ValueError('select_one_authenticated_session')
        session = candidates[0]
    path = store.session_path(session)
    with store.lock(path):
        headers = login.authenticated_session(path)['headers']
        return collect(Reader(path, headers, joint_perform(path)), args, start, end)
