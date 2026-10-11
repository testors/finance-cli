"""One entry point; institution response rules and exit statuses stay intact."""
import getpass
import os
from pathlib import Path
import sys

from .output import ArgumentParser, emit, error, rendering, structured
from finance_cli.core.credential_refs import CredentialInUse


def output(value):
    emit(value)


def capabilities():
    from giro.bill_catalog import catalog as giro_bill_catalog
    from finance_cli.core.live_verification import HANA_LEVEL, REVIEWED_ON, hana_report, giro_report
    return {'schema_version': 1, 'services': {
        'hana': {'offline': ['protocol', 'shared-certificate-login-signature', 'onesign-vault-bundle',
                            'user-package-settings-extraction', 'onesign-identity-initialization', 'onesign-identity-removal', 'onesign-identity-rename', 'personal-transfer-csv-check'],
                 'live': ['app-authentication', 'joint-certificate-login', 'accounts', 'transfer-history-query',
                          'ledger-history', 'automatic-history-pagination', 'security-inquiry', 'login-extension', 'onesign-new-issuance',
                          'onesign-signed-login', 'onesign-login-extension', 'onesign-krw-transfer', 'onesign-krw-multi-transfer'],
                 'multi_transfer': {'command': 'fin hana transfer prepare-batch', 'max_items': 15,
                                    'withdrawal_accounts': 1, 'verification': 'implemented_live_untested',
                                    'csv': True, 'partial_results': True, 'automatic_retry': False,
                                    'not_included': ['scheduled and recurring transfers', 'MMDA', 'open banking',
                                                     'additional OTP/ARS authentication', 'web batch entry']},
                 'session_extension': {'onesign': 'live_partial', 'joint_certificate': 'implemented_live_untested',
                                       'idle_limit_observed_seconds': {'kept_after': 595, 'ended_after': 600},
                                       'automatic_retry': False},
                 'requirements': ['user-supplied service settings for version 1.0.27',
                                  'domestic adult existing Hana customer for new issuance',
                                  'server-approved authentication branch for transfers'],
                 'not_included': ['cloud certificate download', 'exceptional enrollment branches',
                                  'financial certificate issuance', 'OTP and limit changes'],
                 'live_tested': False, 'verification': HANA_LEVEL, 'live_verification': hana_report(),
                 'corporate': {'command': 'fin hana corporate', 'verification': 'live_partial', 'live_tested': False,
                    'live_verification': {'reviewed_at': '2026-10-10', 'source': 'user_reported_cli_output_and_saved_session_trial',
                        'live_tested_scope': 'all_supported_remote_paths',
                        'verified': ['id-password-login', 'saved-session-reuse', 'login-extension'],
                        'unverified': ['joint-certificate-login', 'sole-proprietor-onesign-login',
                                       'accounts', 'ledger-history', 'krw-transfer', 'krw-batch-transfer'],
                        'note': 'ID/PW 로그인·출금계좌 정보·고객 확인 후속 응답과 세션 저장 성공 확인. 저장한 ID/PW 세션의 재사용과 로그인 연장의 은행 수락·세션 유지, 끝난 세션의 연장 거절 응답 확인(2026-10-10; 요청 없이 605초 뒤 유지, 610초 뒤 종료). 관측한 로그인 경로에 한함.'},
                    'session_extension': {'verification': 'live_partial', 'server_session_timeout_minutes_reported': 10,
                                          'web_idle_limit': 'server_session_timeout',
                                          'idle_limit_observed_seconds': {'kept_after': 605, 'ended_after': 610},
                                          'automatic_retry': False},
                    'implemented': ['joint-certificate-login', 'sole-proprietor-onesign-login', 'id-password-login',
                                    'keypad-settings-install', 'isolated-corporate-session', 'automatic-id-password-session', 'login-extension',
                                    'accounts', 'krw-fund-foreign-loan-history', 'automatic-history-pagination',
                                    'krw-transfer-prepare-execute-result', 'csv-batch-check-and-prepare', 'account-password', 'standard-otp', 'ars',
                                    'shared-joint-certificate-transfer-signing'],
                    'requirements': ['corporate device profile for certificate login', 'shared registered certificate for certificate login',
                                     'corporate ID/password and installed keypad settings for ID/password login',
                                     'existing corporate ID link for OneSign', 'successful corporate login for banking',
                                     'bank-selected authentication for transfers', 'explicit --send'],
                    'not_included': ['corporate ID registration', 'app FDS collection', 'financial certificate login',
                                     'corporate approver actions', 'dedicated payroll and file-transfer services',
                                     'scheduled and recurring transfers', 'tax transfers', 'mobile OTP generation',
                                     'financial and private certificate transfer signing', 'OTP and limit changes']}},
        'hometax': {'offline': ['auth-replay', 'certificate-prepare'],
                    'live': ['certificate-login', 'session', 'account', 'business', 'tax-query',
                             'returns', 'report', 'invoice'],
                    'requirements': ['Node runtime', 'JDK 17+ for invoice signing'],
                    'session': {'extension_request': None, 'idle_basis': 'observed', 'session_check_extends': True,
                                'session_refresh_extends': True,
                                'idle_limit_observed_seconds': {'kept_after': 1800, 'ended_after': 1805}},
                    'session_extension': {'command': 'fin hometax session extend', 'method': 'session-check',
                                          'verification': 'implemented_live_untested',
                                          'extension_effect': 'idle_limit_reset_observed'},
                    'migration_live_tested': False},
        'giro': {'offline': ['auth-plan', 'registration-plan', 'request-plan', 'bills', 'payment-accounts', 'payment-plan',
                            'payment-result', 'certificate-validation', 'codeguard'],
                 'live': ['explicit PIN-free bootstrap probes', 'pinned-public-root-preparation',
                          'device-registration', 'pin-login', 'own-tax-queries', 'utility-bill-queries', 'integrated-bill-summary', 'bill-detail', 'single-national-account-payment',
                          'single-local-account-payment', 'single-customs-account-payment', 'payment-review',
                          'registered-account-list', 'receipt-list', 'receipt-detail', 'session-extension-query'],
                 'session_extension': {'command': 'fin giro session extend', 'method': 'registered-accounts-query',
                                       'verification': 'live_partial', 'extension_effect': 'idle_limit_reset_observed',
                                       'idle_limit_observed_seconds': {'kept_after': 295, 'ended_after': 300}},
                 'live_login': True, 'live_tested': False, 'verification': 'live_partial',
                 'live_verification': giro_report(),
                 'bill_queries': giro_bill_catalog(),
                 'public_material_refresh': 'cache-first issuer/CRL lookup from ds.yessign.or.kr:389 during authentication',
                 'requirements': ['private prepared protection profile', 'pinned recipient roots in public cache',
                                  'existing personal member; SKT/SKM/LGT/LGM for registration',
                                  'own UID already registered for tax lists', 'explicit --send'],
                 'not_included': ['KT registration', 'new membership', 'UID registration',
                                  'certificate/FIDO payment authentication', 'web device registration']}},
        'credentials': {'joint': ['import-npki', 'import-pfx', 'list', 'show', 'export', 'remove', 'rename', 'hometax-selection', 'hana-signing'],
                        'id_cards': ['add', 'list', 'show', 'export', 'rename', 'remove', 'hana-onesign-issuance-selection'],
                        'financial': {'scope': 'offline crypto library', 'remote_management': False}},
        'web': {'optional_dependency': 'finance-cli[web]', 'command': 'fin server',
                'scope': ['browser-enrollment', 'business-profiles', 'institution-logins-and-targets', 'jobs',
                          'hana', 'hometax', 'giro-bills', 'giro-pin-login', 'giro-own-tax-queries',
                          'giro-reviewed-account-payment', 'giro-accounts-and-receipts', 'joint-certificate-import', 'id-card-storage',
                          'onesign-staged-issuance', 'onesign-shared-session-queries', 'onesign-security-inquiry'],
                'server_managed': ['certificate-export', 'onesign-settings-and-bundle-transfer', 'runtime-install',
                                   'device-registration-files', 'giro-device-registration-and-protection-setup'],
                'giro': {'implemented': True, 'verification': 'live_partial',
                         'live_verification': giro_report()['jobs'],
                         'registration': 'reuse existing CLI device',
                         'session_storage': 'isolated encrypted web sessions',
                         'payment_reservation': 'shared with CLI', 'automatic_login_or_retry': False},
                'binding': 'loopback', 'remote_access': 'https reverse proxy', 'live_tested': False,
                'verification': HANA_LEVEL, 'verification_scope': 'hana-onesign',
                'verification_reviewed_at': REVIEWED_ON},
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
    item = joint.add_parser('remove', help='보관한 인증서 삭제; 프로필·웹 로그인이 참조 중이면 거절')
    item.add_argument('name')
    item = joint.add_parser('rename', help='별칭 변경; 참조 중이면 거절, 지문·개인키는 그대로')
    item.add_argument('name')
    item.add_argument('new_name')
    args = parser.parse_args(argv)
    registry = Registry()
    if args.action == 'joint' and args.joint_action in ('remove', 'rename'):
        from finance_cli.core.credential_refs import guard
        guard('joint', args.name)
        result = registry.remove(args.name) if args.joint_action == 'remove' else registry.rename(args.name, args.new_name)
    elif args.action == 'list':
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

    Only the command words and whether transmission was approved (--send, or
    Giro's --live) are kept: no option values, inputs or results. A recording
    failure never changes the command's JSON output or exit code.
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
        record_cli(server_db.Database(), origin=origin, command=[service, *words], exit_code=code, service=service,
                   send='--send' in argv or '--live' in argv)
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
  idcard      신분증 사진·정보 암호화 보관·확인·내보내기 (발급 단계에서 선택)
  profile     프로필·기관별 인증서 선택
  hana        하나은행 로그인·조회·하나인증서 발급·원화 이체 (통신 시 --send)
  hometax     홈택스 로그인·조회·보고서·세금계산서 (통신 시 --send)
  giro        지로 기기 등록·인증·조회·납부 (--send/--live)
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
        elif command == 'idcard':
            from .id_cards import main as run
            return run(rest)
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
    except CredentialInUse as exc:
        emit({'error': 'credential_in_use', 'references': exc.references, 'network_used': False,
              'message': '프로필이나 웹 로그인이 이 인증서를 참조하고 있습니다. 먼저 해당 설정의 인증서를 바꾸세요.'}, 2)
        return 2
    except (ValueError, OSError, ImportError) as exc:
        emit({'error': type(exc).__name__, 'message':
              '로컬 입력 또는 처리 오류입니다. 설정과 입력을 확인하세요.' if structured() else str(exc)}, 2)
        return 2
