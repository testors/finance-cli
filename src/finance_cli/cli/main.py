"""One entry point; institution response rules and exit statuses stay intact."""
import getpass
import os
from pathlib import Path
import sys

from .output import ArgumentParser, emit, error, rendering, structured


def output(value):
    emit(value)


def capabilities():
    return {'schema_version': 1, 'services': {
        'hana': {'offline': ['protocol', 'shared-certificate-login-signature', 'onesign-vault-bundle',
                            'user-package-settings-extraction', 'onesign-identity-initialization'],
                 'live': ['app-authentication', 'joint-certificate-login', 'accounts', 'transfer-history-query',
                          'ledger-history', 'security-inquiry', 'login-extension', 'onesign-new-issuance',
                          'onesign-signed-login', 'onesign-krw-transfer'],
                 'requirements': ['user-supplied service settings for version 1.0.27',
                                  'domestic adult existing Hana customer for new issuance',
                                  'server-approved authentication branch for transfers'],
                 'not_included': ['cloud certificate download', 'exceptional enrollment branches',
                                  'financial certificate issuance', 'OTP and limit changes'],
                 'live_tested': False},
        'hometax': {'offline': ['auth-replay', 'certificate-prepare'],
                    'live': ['certificate-login', 'session', 'account', 'business', 'tax-query',
                             'returns', 'report', 'invoice'],
                    'requirements': ['Node runtime', 'JDK 17+ for invoice signing'],
                    'migration_live_tested': False},
        'giro': {'offline': ['auth-plan', 'request-plan', 'bills', 'certificate-validation', 'codeguard'],
                 'live': ['explicit PIN-free bootstrap probes'], 'live_login': False}},
        'credentials': {'joint': ['import-npki', 'import-pfx', 'list', 'show', 'export', 'hometax-selection', 'hana-signing'],
                        'financial': {'scope': 'offline crypto library', 'remote_management': False}},
        'web': {'optional_dependency': 'finance-cli[web]', 'command': 'fin server',
                'scope': ['browser-enrollment', 'business-profiles', 'institution-logins-and-targets', 'jobs',
                          'hana', 'hometax', 'giro-bills'],
                'server_managed': ['certificate-import-export', 'onesign-issuance-and-setup', 'runtime-install',
                                   'device-registration-files'],
                'binding': 'loopback', 'remote_access': 'https reverse proxy', 'live_tested': False},
        'network_used': False}


def password(args):
    if args.password_stdin:
        return sys.stdin.buffer.readline().removesuffix(b'\n').removesuffix(b'\r')
    return getpass.getpass('인증서 비밀번호: ').encode('utf-8')


def cert_main(argv):
    from finance_cli.credentials.registry import Registry
    parser = ArgumentParser(prog='fin cert', description='공통 암호화 인증서 저장소; 금융 서버 통신 없음')
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('list')
    sub.add_parser('capabilities')
    for operation in ('show', 'export'):
        item = sub.add_parser(operation)
        item.add_argument('name')
        item.add_argument('--password-stdin', action='store_true')
        if operation == 'export':
            item.add_argument('--output', type=Path, required=True, help='가져온 파일 내용을 복원할 새 디렉터리')
    joint = sub.add_parser('joint').add_subparsers(dest='joint_action', required=True)
    item = joint.add_parser('import')
    item.add_argument('--name', required=True)
    source = item.add_mutually_exclusive_group(required=True)
    source.add_argument('--cert', type=Path)
    source.add_argument('--pfx', type=Path)
    item.add_argument('--key', type=Path)
    item.add_argument('--pfx-index', type=int)
    item.add_argument('--compatibility', choices=('hana', 'hometax'), default='hana', help='NPKI 암호 바이트·복호화 규칙')
    item.add_argument('--password-stdin', action='store_true')
    args = parser.parse_args(argv)
    registry = Registry()
    if args.action == 'list':
        result = {'certificates': registry.list(), 'network_used': False}
    elif args.action == 'capabilities':
        result = capabilities()['credentials']
    elif args.action == 'show':
        result = registry.inspect(args.name, password(args))
    elif args.action == 'export':
        result = registry.export(args.name, password(args), args.output)
    elif args.pfx:
        if args.key:
            parser.error('--pfx와 --key는 함께 사용할 수 없습니다.')
        result = registry.import_pfx(args.name, args.pfx.read_bytes(), password(args), index=args.pfx_index)
    else:
        if not args.key:
            parser.error('--cert에는 --key가 필요합니다.')
        result = registry.import_npki(args.name, args.cert.read_bytes(), args.key.read_bytes(), password(args), compatibility=args.compatibility)
    output(result)
    return 0


def profile_main(argv):
    from finance_cli.core import profiles
    parser = ArgumentParser(prog='fin profile')
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('list')
    item = sub.add_parser('set')
    item.add_argument('name')
    item.add_argument('--service', choices=profiles.SERVICES, required=True)
    item.add_argument('--cert', required=True)
    args = parser.parse_args(argv)
    output(profiles.load() if args.action == 'list' else profiles.set_certificate(args.name, args.service, args.cert))
    return 0


def hometax_main(argv):
    from hometax_cli.__main__ import main as run
    if argv[:1] == ['login']:
        argv = ['auth', 'login-cert', *argv[1:]]
    live = bool(argv and (argv[0] in ('session', 'account', 'business', 'tax', 'returns', 'report', 'invoice')
                         or argv[:2] == ['auth', 'login-cert']))
    help_requested = not argv or any(v in argv for v in ('--help', '-h'))
    if live and not help_requested and '--send' not in argv:
        emit({'error': 'send_required', 'network_used': False,
              'message': '기관 연결 명령에는 --send가 필요합니다. 도움말로 입력을 확인하세요.'}, 2)
        return 2
    return run([v for v in argv if v != '--send'] or ['--help'])


def record_history(service, argv, code):
    """Link a CLI or agent run to the web server's shared history, if one exists.

    Only the command words are kept (no option values, inputs or results), and
    a recording failure never changes the command's JSON output or exit code.
    """
    if not argv or any(value in ('-h', '--help') for value in argv):
        return code
    try:
        from finance_cli.server import db as server_db
        if not server_db.exists():
            return code
        from finance_cli.server.jobs import record_cli
        words = []
        for value in argv:
            if value.startswith('-') or len(words) == 4:
                break
            words.append(value)
        origin = 'agent' if os.environ.get('FINANCE_REQUEST_ORIGIN') == 'agent' else 'cli'
        record_cli(server_db.Database(), origin=origin, command=[service, *words], exit_code=code, service=service)
    except Exception:
        pass
    return code


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    format_name, home, option_error = 'legacy', None, None
    # Global options precede the command. Never scan or rewrite command values.
    while argv and argv[0].split('=', 1)[0] in ('--home', '--format'):
        option, separator, value = argv.pop(0).partition('=')
        if not separator:
            if not argv or argv[0].startswith('--'):
                option_error = 'global_option_value_required'
                break
            value = argv.pop(0)
        if option == '--home':
            home = value
        elif value in ('legacy', 'json-v1'):
            format_name = value
        else:
            option_error = 'unsupported_output_format'
            break
    service = argv[0] if argv and argv[0] in ('hana', 'hometax', 'giro') else 'fin'
    with rendering(format_name, service):
        if option_error:
            return error(option_error, '전역 옵션은 --home 경로와 --format legacy|json-v1을 지원합니다.')
        if home is not None:
            os.environ['FINANCE_HOME'] = str(Path(home).expanduser().absolute())
        try:
            return dispatch(argv)
        except EOFError:
            if not structured():
                raise
            return error('input_required', '필요한 입력을 받지 못했습니다. 명령의 입력 방식을 확인하세요.')
        except KeyboardInterrupt:
            if not structured():
                raise
            return error('interrupted', '사용자가 중단했습니다. 업무 전송 여부와 결과는 별도로 확인하세요.', 130)


def dispatch(argv):
    if not argv or argv in (['--help'], ['-h']):
        print('''사용법: fin [--home DATA_DIRECTORY] [--format legacy|json-v1] <명령> ...

  cert        공동인증서 NPKI/PFX 암호화 보관·조회·내보내기
  profile     프로필·기관별 인증서 선택
  hana        하나은행 로그인·조회·하나인증서 발급·원화 이체 (통신 시 --send)
  hometax     홈택스 로그인·조회·보고서·세금계산서 (통신 시 --send)
  giro        지로 오프라인 도구·명시적 초기 프로브 (--send/--live)
  runtime     홈택스 Node 런타임 status/install
  server      웹앱 서버 설정·시작·브라우저 등록 (선택 설치 finance-cli[web])
  capabilities  구현 범위와 기관별 경계 (JSON)
  paths       사용자 데이터 위치 (읽기 전용)
  --version   패키지 버전

기관별 명령의 인자·JSON 결과·업무 판정은 기존 계약을 유지합니다.
--format json-v1은 기존 결과를 버전·기관·종료코드와 함께 출력합니다.
비밀번호·PIN·OTP는 명령행이나 환경변수로 전달하지 않습니다.''')
        return 0
    try:
        command, rest = argv[0], argv[1:]
        if command == '--version':
            from importlib.metadata import version
            print(version('finance-cli'))
        elif command == 'capabilities':
            output(capabilities())
        elif command == 'paths':
            from finance_cli.core.paths import data_home, runtime_home
            output({'data': str(data_home()), 'hometax_runtime': str(runtime_home()), 'network_used': False})
        elif command == 'cert':
            return cert_main(rest)
        elif command == 'profile':
            return profile_main(rest)
        elif command == 'hana':
            from finance_cli.services.hana.cli import main as run
            return record_history('hana', rest, run(rest or ['--help']))
        elif command == 'hometax':
            return record_history('hometax', rest, hometax_main(rest))
        elif command == 'giro':
            from giro.__main__ import main as run
            return record_history('giro', rest, run(['--live' if value == '--send' else value for value in rest] or ['--help']))
        elif command == 'server':
            from finance_cli.server.cli import main as run
            return run(rest or ['--help'])
        elif command == 'runtime':
            from finance_cli.core import runtime
            parser = ArgumentParser(prog='fin runtime')
            parser.add_argument('action', choices=('status', 'install'))
            parser.add_argument('service', choices=('hometax',))
            args = parser.parse_args(rest)
            output(runtime.install() if args.action == 'install' else runtime.status())
        else:
            if structured():
                return error('invalid_arguments', '알 수 없는 명령입니다. --help로 사용법을 확인하세요.')
            raise ValueError('unknown_command')
        return 0
    except (ValueError, OSError, ImportError) as exc:
        emit({'error': type(exc).__name__, 'message':
              '로컬 입력 또는 처리 오류입니다. 설정과 입력을 확인하세요.' if structured() else str(exc)}, 2)
        return 2
