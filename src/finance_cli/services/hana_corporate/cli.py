"""Corporate CLI entry, with separate secret providers and a pre-I/O send gate."""
import getpass
import json
import os
from pathlib import Path
import sys
import warnings

from finance_cli.cli.credentials import add_selection, resolve
from . import idpw, keypad, login, store, protocol


def add_parser(sub):
    parser = sub.add_parser('corporate', help='기업뱅킹 로그인 (ID/PW 실사용 성공 확인; 인증서 경로는 합성 검증)')
    commands = parser.add_subparsers(dest='corporate_action', required=True)
    session = commands.add_parser('session', help='기업 채널 세션 준비·관측 결과').add_subparsers(dest='corporate_session_action', required=True)
    item = session.add_parser('new', help='사용자가 지정한 기업 앱 기기 정보로 새 세션 생성; 무통신')
    item.add_argument('--session', required=True)
    item.add_argument('--device-file', type=Path, required=True)
    item = session.add_parser('show', help='로그인 관측 요약; 서버 유효성 확인 없음')
    item.add_argument('--session', required=True)
    item = commands.add_parser('login', help='공통 공동인증서로 기업 로그인')
    item.add_argument('--session', required=True)
    add_selection(item)
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


def dispatch(args):
    try:
        if args.corporate_action == 'setup':
            return keypad.install(args.package, args.settings)
        if args.corporate_action == 'session':
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
