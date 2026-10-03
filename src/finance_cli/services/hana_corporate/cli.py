"""Corporate CLI entry, with separate secret providers and a pre-I/O send gate."""
import getpass
import json
import os
from pathlib import Path
import sys
import warnings

from finance_cli.cli.credentials import add_selection, resolve
from . import idpw, keypad, login, store, protocol, queries, transfers


def add_parser(sub):
    parser = sub.add_parser('corporate', help='기업뱅킹 로그인·계좌·거래내역·원화 이체')
    commands = parser.add_subparsers(dest='corporate_action', required=True)
    session = commands.add_parser('session', help='기업 채널 세션 준비·관측 결과').add_subparsers(dest='corporate_session_action', required=True)
    item = session.add_parser('new', help='사용자가 지정한 기업 앱 기기 정보로 새 세션 생성; 무통신')
    item.add_argument('--session', required=True)
    item.add_argument('--device-file', type=Path, required=True)
    item = session.add_parser('show', help='로그인 관측 요약; 서버 유효성 확인 없음')
    item.add_argument('--session', required=True)
    item = session.add_parser('extend', help='기존 기업 로그인 연장 1회; 재로그인 없음')
    item.add_argument('--session', help='선택: 다른 기업 로그인 기록 사용')
    item.add_argument('--send', action='store_true')
    item = commands.add_parser('login', help='공통 공동인증서로 기업 로그인')
    item.add_argument('--session', required=True)
    add_selection(item)
    item.add_argument('--send', action='store_true')
    item = commands.add_parser('accounts', help='기업 보유계좌 조회; 최근 성공한 로그인 자동 사용')
    item.add_argument('--category', choices=(*queries.TABS, 'all'), default='withdrawal', help='기본 출금계좌; all은 모든 계좌 탭')
    item.add_argument('--session', help='선택: 다른 기업 로그인 기록 사용')
    item.add_argument('--send', action='store_true')
    item = commands.add_parser('history', help='계좌 거래내역 조회; 기간 내 다음 페이지 자동 수집')
    item.add_argument('--account', required=True)
    item.add_argument('--start', help='YYYY-MM-DD 또는 YYYYMMDD; 기본 오늘을 포함한 최근 7일')
    item.add_argument('--end', help='YYYY-MM-DD 또는 YYYYMMDD; 기본 오늘')
    item.add_argument('--direction', choices=('all', 'deposit', 'withdrawal'), default='all')
    item.add_argument('--order', choices=('latest', 'oldest'), default='latest')
    item.add_argument('--search-type', choices=('all', 'summary', 'amount', 'recipient', 'memo'), default='all')
    item.add_argument('--search', default='')
    item.add_argument('--currency', help='선택: 외화계좌 조회 통화; ALL은 전체')
    item.add_argument('--sequence', help='선택: 대출 실행번호')
    item.add_argument('--session', help='선택: 다른 기업 로그인 기록 사용')
    item.add_argument('--send', action='store_true')
    transfer = commands.add_parser('transfer', help='일반 원화 이체 준비·실행·결과').add_subparsers(dest='corporate_transfer_action', required=True)
    item = transfer.add_parser('prepare', help='수취인·금액 확인 후 이체 준비; 송금 실행은 execute')
    item.add_argument('--from-account', required=True)
    item.add_argument('--to-bank', required=True, help='입금은행 코드 3자리')
    item.add_argument('--to-account', required=True)
    item.add_argument('--amount', required=True, help='원화 정수 금액')
    item.add_argument('--memo', default='')
    item.add_argument('--debit-memo', help='출금통장 표시; 기본 수취인명')
    item.add_argument('--credit-memo', help='입금통장 표시; 기본 출금계좌 예금주명')
    item.add_argument('--cms-code', default='')
    item.add_argument('--delayed', action='store_true', help='지연이체 선택')
    item.add_argument('--session', help='선택: 다른 기업 로그인 기록 사용')
    item.add_argument('--send', action='store_true')
    item = transfer.add_parser('execute', help='확인한 준비 이체 실행; 필요한 비밀번호·OTP만 숨김 입력')
    add_selection(item, required=False)
    item.add_argument('--allow-duplicate', action='store_true', help='은행이 표시한 중복 이체를 확인하고 계속')
    item.add_argument('--account-password-fd', type=int, help='계좌 비밀번호 한 줄을 읽을 파일 디스크립터')
    item.add_argument('--otp-fd', type=int, help='일반 OTP 한 줄을 읽을 파일 디스크립터')
    item.add_argument('--ars-completed', action='store_true', help='이미 요청된 전화 인증을 마쳐 결과 확인 진행')
    item.add_argument('--ars-phone', help='선택: 등록된 ARS 전화의 선택 번호')
    item.add_argument('--session', help='선택: 다른 기업 로그인 기록 사용')
    item.add_argument('--send', action='store_true')
    for command, help_text in [('result', '마지막 제출 이체 결과 재조회; 재송금 없음'), ('cancel', '아직 제출하지 않은 이체 준비 취소')]:
        item = transfer.add_parser(command, help=help_text)
        item.add_argument('--session', help='선택: 다른 기업 로그인 기록 사용')
        item.add_argument('--send', action='store_true')
    item = commands.add_parser('login-idpw', help='기업 ID·로그인 비밀번호로 로그인')
    item.add_argument('--user-id', required=True, help='기업 인터넷뱅킹 ID')
    item.add_argument('--password-stdin', action='store_true', help='기업 로그인 비밀번호 한 줄만 읽음')
    item.add_argument('--send', action='store_true')
    item.add_argument('--session', help='선택: 로그인 기록 이름 직접 지정; 기본값 자동 생성')
    item.add_argument('--settings', help='선택: 공통 키패드 설정 직접 지정; 기본값 자동 선택')
    setup = commands.add_parser('setup', help='기업 키패드 설정 준비; 무통신').add_subparsers(dest='corporate_setup_action', required=True)
    item = setup.add_parser('extract', help='사용자 설치 패키지에서 기업 6.2.2 키패드 설정만 추출')
    item.add_argument('--package', required=True, type=Path)
    item.add_argument('--settings', required=True)
    item = commands.add_parser('login-onesign', help='공통 하나인증서로 개인사업자 기업 로그인; 기존 연결 ID 사용')
    item.add_argument('--session', required=True)
    item.add_argument('--name', required=True, help='기존 하나인증서 identity 이름')
    item.add_argument('--password-stdin', action='store_true', help='저장소 암호 한 줄만 읽음; PIN은 별도 숨김 입력')
    item.add_argument('--send', action='store_true')


def password(args, joint):
    if args.password_stdin:
        value = sys.stdin.buffer.readline().removesuffix(b'\n').removesuffix(b'\r')
        return value if joint else value.decode('utf-8')
    value = hidden('공동인증서 비밀번호: ' if joint else '하나인증서 저장소 암호: ')
    return value.encode('utf-8') if joint else value


def hidden(label):
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        return getpass.getpass(label)


def pin_provider():
    # A piped vault password must not become the PIN, and unavailable terminal
    # input must be detected before opening a remote authentication transaction.
    try:
        descriptor = os.open('/dev/tty', os.O_RDWR)
        os.close(descriptor)
    except OSError:
        raise protocol.Stop('pin_terminal_required') from None
    return lambda: hidden('하나인증서 PIN 6자리: ')


def fd_secret(descriptor, prompt):
    if descriptor is None:
        return hidden(prompt)
    protocol.require(descriptor >= 0, 'invalid_secret_descriptor')
    with os.fdopen(os.dup(descriptor), 'rb') as stream:
        return stream.readline(256).removesuffix(b'\n').removesuffix(b'\r').decode('utf-8')


def ars_completed(code):
    protocol.require(isinstance(code, str) and code.isascii() and code.isdigit(), 'ars_number_unavailable')
    with open('/dev/tty', 'r+') as terminal:
        terminal.write('전화 인증번호: ' + code + '. 전화 인증을 마친 뒤 Enter를 누르세요: ')
        terminal.flush()
        return bool(terminal.readline())


def dispatch(args):
    try:
        if args.corporate_action == 'transfer':
            action = args.corporate_transfer_action
            if action == 'prepare':
                return transfers.prepare(args.from_account, args.to_bank, args.to_account, args.amount,
                    memo=args.memo, sender_text=args.credit_memo, recipient_text=args.debit_memo,
                    cms_code=args.cms_code, delayed=args.delayed, session=args.session, send=args.send)
            if action in ('result', 'cancel'):
                return getattr(transfers, action)(session=args.session, send=args.send)
            if not args.send:
                return transfers.execute()
            descriptors = [fd for fd in (args.account_password_fd, args.otp_fd, 0 if args.password_stdin else None) if fd is not None]
            protocol.require(len(descriptors) == len(set(descriptors)), 'secret_descriptors_must_be_distinct')
            return transfers.execute(session=args.session, send=True, credential=resolve(args, 'hana'),
                allow_duplicate=args.allow_duplicate, phone=args.ars_phone, ars_completed=args.ars_completed,
                inputs={'password': lambda: password(args, True),
                        'account_password': lambda: fd_secret(args.account_password_fd, '출금계좌 비밀번호 4자리: '),
                        'otp': lambda: fd_secret(args.otp_fd, 'OTP 6자리: '), 'ars_completed': ars_completed})
        if args.corporate_action == 'accounts':
            return queries.accounts(category=args.category, session=args.session, send=args.send)
        if args.corporate_action == 'history':
            return queries.history(args.account, start=args.start, end=args.end,
                direction={'all': '', 'deposit': '1', 'withdrawal': '2'}[args.direction], order=args.order,
                search_type={'all': '', 'summary': '04', 'amount': '03', 'recipient': '05', 'memo': '02'}[args.search_type],
                search=args.search, currency=args.currency, sequence=args.sequence, session=args.session, send=args.send)
        if args.corporate_action == 'setup':
            return keypad.install(args.package, args.settings)
        if args.corporate_action == 'session':
            if args.corporate_session_action == 'extend':
                from . import session
                return session.extend(session=args.session, send=args.send)
            if args.corporate_session_action == 'show':
                return store.inspect(args.session)
            return store.create(args.session, json.loads(args.device_file.read_text(encoding='utf-8')))
        if args.corporate_action == 'login-idpw':
            if not args.send:
                return idpw.plan()
            def login_password():
                if args.password_stdin:
                    return sys.stdin.buffer.readline().removesuffix(b'\n').removesuffix(b'\r').decode('utf-8')
                return hidden('기업 로그인 비밀번호: ')
            return idpw.login(args.session, args.user_id, args.settings, send=True, inputs={'password': login_password})
        joint = args.corporate_action == 'login'
        method = '2' if joint else 'S'
        if not args.send:
            return login.plan(method)
        inputs = {'password': lambda: password(args, joint)}
        if not joint:
            inputs['pin'] = pin_provider()
        return login.login(args.session, method, resolve(args, 'hana') if joint else args.name, send=True, inputs=inputs)
    except protocol.Stop as exc:
        return {'channel': 'corporate', 'accepted': None, 'network_used': False,
                'processing_status': 'stopped', 'error': str(exc)}
    except (OSError, ValueError, KeyError, TypeError):
        return {'channel': 'corporate', 'accepted': None, 'network_used': False,
                'processing_status': 'stopped', 'error': 'local_input_or_processing_error'}
