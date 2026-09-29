"""The Hana interface: offline contracts, certificate signing and recorded read-only queries.

Every command that contacts the bank prepares first and sends only with --send.
A request is never repeated automatically, and an attempt that was started is
recorded and never replayed. OTP changes and limit changes are absent.
"""
import argparse
import getpass
import json
from pathlib import Path
import sys

from . import hana_protocol as protocol
from . import security_protocol


def password(args):
    return (sys.stdin.buffer.readline().rstrip(b'\r\n') if args.password_stdin
            else getpass.getpass('인증서 비밀번호: ').encode())


def passphrase(args):
    if args.password_stdin:
        return sys.stdin.buffer.readline().rstrip(b'\r\n').decode('utf-8')
    return getpass.getpass('번들 암호: ')


def credential(args):
    if args.profile:
        from finance_cli.core.profiles import resolve
        return resolve(args.profile, 'hana')
    return args.credential


def selection_arguments(parser):
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--credential', help='금고의 인증서 별칭')
    selection.add_argument('--profile', help='fin profile set으로 연결한 하나은행 프로필')
    parser.add_argument('--password-stdin', action='store_true')


def build():
    parser = argparse.ArgumentParser(prog='fin hana', description=(
        '하나은행 로그인·조회·하나인증서 발급·원화 이체. '
        '은행에 연결하는 명령은 --send가 있어야 전송합니다. 실서버 검증 전입니다.'))
    sub = parser.add_subparsers(dest='operation', required=True)
    sub.add_parser('plan', help='로그인 계약과 공개 패키지 이전 범위; 접속 없음')
    for command in ('encode-header', 'decode-header', 'joint-cert-tbs', 'joint-cert-body', 'login-body'):
        sub.add_parser(command, help='표준입력으로 받은 로컬 자료 변환; 접속 없음')
    sign = sub.add_parser('sign-login', help='공통 저장소의 인증서로 주어진 nonce 서명; 로그인 전송 없음')
    selection_arguments(sign)
    sign.add_argument('--nonce', required=True, help='사용자가 확보한 서버 nonce; 자동 취득하지 않음')
    sign.add_argument('--output', required=True)

    session = sub.add_parser('session', help='세션 만들기·앱 인증·로그인 연장').add_subparsers(dest='action', required=True)
    item = session.add_parser('new', help='새 세션과 격리된 앱 식별자 생성; 접속 없음')
    item.add_argument('--session', required=True)
    item = session.add_parser('authenticate', help='앱 인증 3단계(register→first-access→access-token)')
    item.add_argument('--session', required=True)
    item.add_argument('--profile-file', type=Path, required=True,
                      help='system_header, channel_header, secure_token, profile_provenance를 담은 JSON')
    item.add_argument('--send', action='store_true')
    item = session.add_parser('extend', help='저장된 로그인의 연장 1회')
    item.add_argument('--session', required=True)
    item.add_argument('--run', required=True, help='이번 연장의 새 기록 이름')
    item.add_argument('--send', action='store_true')
    session.add_parser('list', help='저장된 세션과 기록된 로그인 여부; 접속 없음')

    onesign = sub.add_parser('onesign', help='하나인증서 발급·로그인·암호화 번들 관리').add_subparsers(
        dest='action', required=True)
    item = onesign.add_parser('import', help='다른 도구가 내보낸 번들을 검증해 암호화된 채로 보관')
    item.add_argument('--name', required=True)
    item.add_argument('--bundle', type=Path, required=True)
    item.add_argument('--password-stdin', action='store_true')
    item = onesign.add_parser('export', help='보관한 번들을 새 파일로 복사(암호는 그대로)')
    item.add_argument('--name', required=True)
    item.add_argument('--output', type=Path, required=True)
    item = onesign.add_parser('show', help='번들을 열어 인증서 지문·등록 상태 확인')
    item.add_argument('--name', required=True)
    item.add_argument('--password-stdin', action='store_true')
    onesign.add_parser('list', help='보관한 번들 이름')
    from .onesign_cli import add_parsers
    add_parsers(sub, onesign)

    item = sub.add_parser('login', help='공동인증서 로그인: nonce→금고 인증서 서명→로그인')
    item.add_argument('--session', required=True)
    selection_arguments(item)
    item.add_argument('--login-input', type=Path, required=True,
                      help='push_token, fakefinder_install_id, input_provenance를 담은 JSON')
    item.add_argument('--send', action='store_true')

    item = sub.add_parser('accounts', help='메인 계좌 목록 조회 1회')
    item.add_argument('--session', required=True)
    item.add_argument('--send', action='store_true')

    item = sub.add_parser('inquiry', help='이체 내역·상세·원장 조회')
    item.add_argument('kind', choices=('history', 'detail', 'ledger'))
    item.add_argument('--session', required=True)
    item.add_argument('--input', type=Path, required=True, help='account_index, start_date, end_date JSON')
    item.add_argument('--previous', help='이전 페이지 기록 이름')
    item.add_argument('--row', type=int, help='detail: 이전 history 기록의 1부터 시작하는 행')
    item.add_argument('--snapshot')
    item.add_argument('--send', action='store_true')

    item = sub.add_parser('history', help='일반 원화 계좌 거래내역: clock→account→page→detail·export')
    item.add_argument('stage', choices=('clock', 'account', 'page', 'detail', 'export'))
    item.add_argument('--session', required=True)
    item.add_argument('--input', type=Path)
    item.add_argument('--clock', help='서버 시각 기록 이름')
    item.add_argument('--account-info', help='계좌 정보 기록 이름')
    item.add_argument('--previous', help='이전 페이지 기록 이름')
    item.add_argument('--row', type=int)
    item.add_argument('--snapshot')
    item.add_argument('--output', type=Path, help='export: 새 .json 경로(같은 이름의 .csv도 만듦)')
    item.add_argument('--send', action='store_true')

    item = sub.add_parser('security', help='한도·보안매체·OTP 상태 읽기 전용 조회')
    item.add_argument('kind', choices=tuple(security_protocol.QUERIES))
    item.add_argument('--session', required=True)
    item.add_argument('--run', required=True, help='이번 조회의 새 기록 이름(준비와 전송에 같은 값)')
    item.add_argument('--send', action='store_true')
    return parser


def list_sessions():
    from . import store
    rows = []
    base = store.root('sessions')
    for path in sorted(base.iterdir()) if base.is_dir() else []:
        if path.is_symlink() or not path.is_dir():
            continue
        row = {'session': path.name}
        for filename, flag in (('app-session.json', 'app_auth_accepted'), ('login-session.json', 'user_login_verified')):
            try:
                value = store.read_json(path / filename)
                row[flag] = value.get(flag) is True
                if flag == 'user_login_verified':
                    row['login_method'] = value.get('login_method')
                    row['file_modified'] = path.joinpath(filename).stat().st_mtime
            except (OSError, ValueError):
                row[flag] = False
        rows.append(row)
    return {'sessions': rows, 'network_used': False, 'session_current_validity': 'unverified'}


def dispatch(args):
    if args.operation in ('setup','transfer') or (args.operation=='onesign' and args.action not in ('import','export','show','list')):
        from .onesign_cli import dispatch as run
        return run(args)
    if args.operation == 'plan':
        result = protocol.auth_plan()
        result['migration'] = {'network_execution': False, 'shared_credentials': True,
            'remaining': ['cloud certificate download', 'exceptional enrollment branches',
                          'financial certificate issuance', 'OTP and limit changes'],
            'onesign': 'setup → init/enroll or activate → new-session/login → transfer',
            'live_tested': False}
        return result
    if args.operation == 'decode-header':
        return protocol.decode_header(sys.stdin.read())
    if args.operation == 'sign-login':
        from finance_cli.credentials.registry import Registry
        from finance_cli.credentials.joint import cms
        from finance_cli.core.storage import write_new
        from Crypto.PublicKey import RSA
        secret = password(args)
        cert, private, _ = Registry().material(credential(args), secret)
        signature = cms.sign_cms(cert, RSA.import_key(private), protocol.joint_cert_tbs(args.nonce).encode())
        write_new(Path(args.output), signature)
        return {'signed': True, 'output': args.output, 'network_used': False, 'bank_accepted': None}
    if args.operation == 'session':
        from . import auth, extend
        if args.action == 'new':
            return auth.new_session(args.session)
        if args.action == 'authenticate':
            return auth.authenticate(args.session, args.profile_file, send=args.send)
        if args.action == 'extend':
            return extend.extend(args.session, args.run, send=args.send)
        return list_sessions()
    if args.operation == 'onesign':
        from . import onesign_bundle as bundle
        if args.action == 'import':
            return bundle.import_bundle(args.name, args.bundle, passphrase(args))
        if args.action == 'export':
            return bundle.export_bundle(args.name, args.output)
        if args.action == 'show':
            return bundle.show(args.name, passphrase(args))
        return bundle.list_bundles()
    if args.operation == 'login':
        from . import login
        return login.login(args.session, credential(args), args.login_input,
                           password(args) if args.send else None, send=args.send)
    if args.operation == 'accounts':
        from . import login
        return login.accounts(args.session, send=args.send)
    if args.operation == 'inquiry':
        from . import inquiry
        return inquiry.run(args.session, args.kind, args.input, previous=args.previous, row=args.row,
                           send=args.send, snapshot=args.snapshot)
    if args.operation == 'history':
        from . import ledger
        if args.stage == 'export':
            if args.send or not args.previous or not args.output:
                raise ValueError('offline_export_needs_previous_and_output')
            return ledger.export(args.session, args.previous, args.output)
        if not args.input:
            raise ValueError('input_required')
        return ledger.run(args.session, args.stage, args.input, send=args.send, clock=args.clock,
                          account_info=args.account_info, previous=args.previous, row=args.row,
                          snapshot=args.snapshot)
    if args.operation == 'security':
        from . import security
        return security.query(args.session, args.run, args.kind, send=args.send)
    value = json.load(sys.stdin)
    functions = {'encode-header': protocol.encode_header, 'joint-cert-body': protocol.joint_cert_body,
                 'login-body': protocol.login_body, 'joint-cert-tbs': lambda v: protocol.joint_cert_tbs(v['nnce'])}
    return functions[args.operation](value)


def main(argv=None):
    args = build().parse_args(argv)
    try:
        result = dispatch(args)
    except (KeyError, TypeError, AttributeError, IndexError) as error:
        # Never echo values from saved records or bank responses.
        raise ValueError('inspect_saved_records_and_inputs: ' + type(error).__name__) from None
    print(json.dumps(result, ensure_ascii=False, indent=2))
    # A sent request the service did not accept is a refusal, not a local error.
    if isinstance(result,dict) and result.get('processing_status')=='stopped':
        return 2
    return 1 if isinstance(result, dict) and result.get('network_used') and result.get('accepted') is False else 0
