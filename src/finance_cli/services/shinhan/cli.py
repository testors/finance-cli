"""Shinhan command entry point. All transmission requires explicit --send."""
import getpass
import json
import sys

from finance_cli.cli.output import ArgumentParser, emit
from finance_cli.core import storage
from finance_cli.credentials.shinhan import Registry, SelectionRequired
from . import accounts, device_phone, history, history_protocol, history_screen, issuance, issuance_input, loan_detail, loan_documents, login, session, setup


class Parser(ArgumentParser):
    def error(self, message):
        # Also protect legacy mode from argparse echoing arbitrary input values.
        emit({'error': 'invalid_arguments', 'network_used': False,
              'message': '인자가 올바르지 않습니다. --help로 사용법을 확인하세요.'}, 2)
        raise SystemExit(2)


def device_input(path):
    if path:
        value = storage.read_json(path)
        if not isinstance(value, dict) or set(value) != {'android_id', 'model', 'os_version'}:
            raise ValueError('invalid_device_input')
        return value
    return None


def queue_progress(remaining, count):
    print(f'접속 대기: {count}명, 예상 {remaining}초', file=sys.stderr)


def queue_choice(notice, path):
    if not sys.stdin.isatty():
        return None
    print(notice['message'], file=sys.stderr)
    button = notice['button']
    if button['type'] not in ('continue', 'exit'):
        return None
    selected = getpass.getpass(f"{button['title']} 선택: 1 (취소: Enter): ").strip()
    return button['type'] if selected == '1' else None


def acknowledge_program_notice(content, path, blocking):
    if not sys.stdin.isatty():
        return None
    if path is not None:
        print(f'은행 안내를 확인하세요: {path}', file=sys.stderr)
    else:
        print(content, file=sys.stderr)
    if blocking:
        getpass.getpass('은행 안내로 조회가 중단됩니다. 확인 후 Enter를 누르세요. ')
        return False
    return getpass.getpass('안내를 확인하고 조회를 계속할까요? [y/n]: ').strip().lower() == 'y'


def main(argv=None):
    parser = Parser(prog='fin shinhan', description='신한은행 기동·인증서 로그인·계좌·대출·거래내역 (실서버 미검증)')
    commands = parser.add_subparsers(dest='command', required=True)
    install = commands.add_parser('setup', help='서비스 자료와 새 형식 기기 정보를 로컬에 설치')
    install.add_argument('--apk', required=True, help='버전 20.0.40 기본 설치 패키지')
    install.add_argument('--device-input', help='선택 사항: 소유자만 읽을 수 있는 기기 JSON; 기본은 자동 생성')
    install.add_argument('--refresh', action='store_true', help='기존 기기 정보를 유지하고 공통 설정만 갱신')
    certificates = commands.add_parser('certificate').add_subparsers(dest='action', required=True)
    certificates.add_parser('list', help='공통 저장소의 신한인증서 참조 목록')
    issuing = certificates.add_parser('issue', help='계좌·보안카드/실물 OTP로 최초 신한인증서 발급')
    issuing.add_argument('--send', action='store_true')
    issuing.add_argument('--apk', help='첫 설정 또는 발급 설정 갱신에 사용할 기본 설치 패키지')
    issuing.add_argument('--device-input', help='선택 사항: 최초 설정용 기기 JSON; 기본은 자동 생성')
    auth = commands.add_parser('login', help='공통 저장소의 발급된 신한인증서로 PIN 로그인')
    auth.add_argument('--credential', help='인증서 참조; 하나만 있으면 자동 선택')
    auth.add_argument('--password-stdin', action='store_true', help='보관 암호 한 줄만 stdin으로 입력')
    auth.add_argument('--pin-file', help='소유자만 읽을 수 있는 PIN 한 줄 파일; 생략 시 숨김 입력')
    auth.add_argument('--send', action='store_true')
    phone = commands.add_parser('phone', help='문자 발신으로 휴대폰 번호 확인').add_subparsers(dest='action', required=True)
    phone.add_parser('verify', help='본인 휴대폰으로 안내된 문자를 전송하고 은행 확인').add_argument('--send', action='store_true')
    for name, description in (('accounts', '표시 가능한 신한 계좌 목록'), ('loans', '표시 가능한 신한 대출 목록')):
        item = commands.add_parser(name, help=description)
        item.add_argument('--send', action='store_true')
        item.add_argument('--refresh', action='store_true', help='은행에 목록 새로고침을 요청')
    transactions = commands.add_parser('transactions', help='최근 계좌 목록에서 선택한 계좌의 거래내역')
    transactions.add_argument('--account', type=int, help='accounts 목록의 순번; 한 건이면 자동 선택')
    transactions.add_argument('--next', action='store_true', help='직전 조회 조건을 유지하고 다음 페이지 조회')
    transactions.add_argument('--start-date', help='조회 시작일 YYYY-MM-DD; 기간 생략 시 최근 3개월')
    transactions.add_argument('--end-date', help='조회 종료일 YYYY-MM-DD; 시작일과 함께 지정')
    transactions.add_argument('--type', choices=('all', 'deposit', 'withdrawal', 'atm'), default='all')
    transactions.add_argument('--sort', choices=('latest', 'oldest'), default='latest')
    transactions.add_argument('--min-amount', type=int)
    transactions.add_argument('--max-amount', type=int)
    transactions.add_argument('--keyword', default='')
    transactions.add_argument('--send', action='store_true')
    detail = commands.add_parser('loan-detail', help='최근 대출 목록에서 선택한 계좌의 금액·금리·기간 조회')
    detail.add_argument('--loan', type=int, help='대출 목록의 순번; 한 건이면 자동 선택')
    detail.add_argument('--send', action='store_true')
    documents = commands.add_parser('loan-documents', help='발급된 대출 증빙 조회').add_subparsers(dest='action', required=True)
    document_list = documents.add_parser('list', help='금리산정내역서 또는 여신증명서 신청 목록')
    document_list.add_argument('--type', choices=('rate', 'credit'), default='rate', help='기본: rate(금리산정내역서); credit(여신증명서 신청내역)')
    document_list.add_argument('--start-date', help='조회 시작일 YYYY-MM-DD; 기간 생략 시 최근 1주일')
    document_list.add_argument('--end-date', help='조회 종료일 YYYY-MM-DD')
    document_list.add_argument('--send', action='store_true')
    document_download = documents.add_parser('download', help='조회한 금리산정내역서를 선택해 PDF 저장')
    document_download.add_argument('--document', type=int, help='최근 금리산정내역서 목록의 순번; 한 건이면 자동 선택')
    document_download.add_argument('--send', action='store_true')
    sessions = commands.add_parser('session').add_subparsers(dest='action', required=True)
    sessions.add_parser('status', help='로컬 상태만 확인; 은행 로그인 유효성 확인 아님')
    for action in ('start', 'extend'):
        item = sessions.add_parser(action)
        item.add_argument('--send', action='store_true')
        if action == 'start':
            item.add_argument('--apk', help='설정이 없을 때 사용할 버전 20.0.40 기본 설치 패키지')
            item.add_argument('--device-input', help='선택 사항: 최초 설정용 기기 JSON; 기본은 자동 생성')
    args = parser.parse_args(argv)
    issue_requested = args.command == 'certificate' and args.action == 'issue'
    if (issue_requested or args.command in ('login', 'accounts', 'loans', 'transactions', 'phone', 'loan-documents', 'loan-detail') or args.command == 'session' and args.action != 'status') and not args.send:
        emit({'error': 'send_required', 'network_used': False,
              'message': '기관 연결에는 --send가 필요합니다.'}, 2)
        return 2
    network_used = False
    try:
        if args.command == 'setup':
            if args.refresh and args.device_input:
                parser.error('conflicting_device_input')
            result = setup.refresh(args.apk) if args.refresh else setup.install(args.apk, device_input(args.device_input))
        elif args.command == 'certificate':
            if args.action == 'list':
                result = {'certificates': Registry().list(), 'network_used': False}
            elif not sys.stdin.isatty():
                result = {'error': 'interactive_input_required', 'network_used': False,
                          'processing_status': 'incomplete', 'message': '최초 발급은 터미널에서 실행하세요.'}
            else:
                configured = (setup.root()/'settings.json').exists()
                if args.apk:
                    if configured:
                        setup.refresh(args.apk)
                    else:
                        setup.install(args.apk, device_input(args.device_input))
                elif not configured:
                    emit({'error': 'settings_required', 'network_used': False,
                          'message': '첫 실행에는 --apk로 기본 설치 패키지를 지정하세요.'}, 2)
                    return 2
                network_used = None
                result = issuance.run(issuance_input.factory, queue_input=queue_choice, queue_progress=queue_progress)
        elif args.command == 'login':
            reference = login.select(args.credential)
            password = sys.stdin.buffer.readline().removesuffix(b'\n').removesuffix(b'\r') if args.password_stdin else getpass.getpass('신한인증서 보관 암호: ').encode()
            def pin_input():
                if args.pin_file:
                    return storage.read(args.pin_file, limit=64).removesuffix(b'\n').removesuffix(b'\r')
                return getpass.getpass('신한인증서 PIN (6자리): ').encode()
            network_used = None
            result = login.run(reference, password, pin_input)
        elif args.command in ('accounts', 'loans'):
            network_used = None
            result = accounts.run(loans=args.command == 'loans', refresh=args.refresh)
        elif args.command == 'transactions':
            if args.account is not None and args.account < 1:
                parser.error('invalid_account_index')
            if args.next and (args.account is not None or args.start_date is not None or args.end_date is not None or
                             args.type != 'all' or args.sort != 'latest' or args.min_amount is not None or
                             args.max_amount is not None or args.keyword):
                parser.error('conflicting_history_page_options')
            options = {'transaction_type': {'all': 'DEFAULT', 'deposit': 'DEPOSIT', 'withdrawal': 'WITHDRAWAL', 'atm': 'SHINHAN_ATM'}[args.type],
                       'sort': 'LATEST_ORDER' if args.sort == 'latest' else 'PAST_ORDER',
                       'min_amount': history_protocol.MIN_AMOUNT if args.min_amount is None else args.min_amount,
                       'max_amount': history_protocol.MAX_AMOUNT if args.max_amount is None else args.max_amount,
                       'keyword': args.keyword}
            history_protocol.Query('', **options)
            if args.start_date is not None or args.end_date is not None:
                history_screen.period(args.start_date, args.end_date)
            network_used = None
            result = history.run(args.account, next_page=args.next, start=args.start_date, end=args.end_date,
                                 acknowledge=acknowledge_program_notice, queue_progress=queue_progress, **options)
        elif args.command == 'loan-detail':
            if args.loan is not None and args.loan < 1:
                parser.error('invalid_loan_index')
            network_used = None
            result = loan_detail.run(args.loan, acknowledge=acknowledge_program_notice, queue_progress=queue_progress)
        elif args.command == 'loan-documents':
            def acknowledge(path):
                if not sys.stdin.isatty():
                    return False
                print(f'은행 안내를 확인하세요: {path}', file=sys.stderr)
                return getpass.getpass('안내를 확인하고 조회를 계속할까요? [y/n]: ').strip().lower() == 'y'
            if args.action == 'list':
                loan_documents.dates(args.start_date, args.end_date)
                network_used = None
                result = loan_documents.run('list', kind=args.type, start=args.start_date, end=args.end_date, acknowledge=acknowledge)
            else:
                if args.document is not None and args.document < 1:
                    parser.error('invalid_document_index')
                network_used = None
                result = loan_documents.run('download', index=args.document)
        elif args.command == 'phone':
            if not sys.stdin.isatty():
                emit({'error': 'interactive_input_required', 'network_used': False,
                      'message': '문자 발신 확인을 위해 터미널에서 실행하세요.'}, 2)
                return 2
            network_used = None
            result = device_phone.run(issuance_input.send_phone_sms)
        elif args.action == 'status':
            result = session.status()
        else:
            if args.action == 'start' and not (setup.root() / 'settings.json').exists():
                if not args.apk:
                    emit({'error': 'settings_required', 'network_used': False,
                          'message': '첫 실행에는 --apk로 기본 설치 패키지를 지정하세요.'}, 2)
                    return 2
                setup.install(args.apk, device_input(args.device_input))
            network_used = None  # An unexpected exception cannot prove no request was sent.
            result = session.execute(args.action, queue_input=queue_choice, queue_progress=queue_progress)
        code = 0 if result.get('bank_result', 'success') == 'success' and result.get('processing_status', 'complete') == 'complete' and result.get('local_status', 'complete') == 'complete' else 2
        if issue_requested:
            code = 0 if (result.get('certificate_issuance') == 'success' and result.get('certificate_registration') == 'success'
                         and result.get('processing_status') == 'complete' and result.get('local_status', 'complete') == 'complete') else 2
        if result.get('error') == 'interrupted':
            code = 130
    except SelectionRequired as exc:
        result, code = {'error': 'credential_selection_required', 'network_used': False,
                        'message': ('보관된 신한인증서가 필요합니다. certificate issue --send로 최초 발급을 진행하세요.' if exc.count == 0 else
                                    '인증서가 여러 개입니다. certificate list에서 확인하고 --credential로 선택하세요.')}, 2
    except session.SessionRequired:
        result, code = {'error': 'session_required', 'network_used': False,
                        'message': '저장된 신한 세션이 없습니다. 먼저 session start를 실행하세요.'}, 2
    except accounts.LoginRequired:
        result, code = {'error': 'login_required', 'network_used': False,
                        'message': '조회에는 로그인된 세션이 필요합니다. 먼저 login을 실행하세요.'}, 2
    except (ValueError, OSError, TypeError, KeyError):
        result, code = {'error': 'local_input_or_processing_error', 'network_used': network_used,
                        'bank_result': 'unknown',
                        'message': '설치 자료·입력값·파일 권한을 확인하세요. 입력값은 출력하지 않습니다.'}, 2
    except (EOFError, KeyboardInterrupt):
        # Cancellation does not establish whether a bank request was accepted.
        result, code = {'error': 'interrupted', 'bank_result': 'unknown',
                        'message': '중단했습니다. 진행 중 전송의 결과를 추정하거나 자동 재시도하지 않습니다.'}, 130
    emit(result, code)
    return code
