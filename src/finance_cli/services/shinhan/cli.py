"""Shinhan command entry point. All transmission requires explicit --send."""
import getpass
import sys

from finance_cli.cli.output import ArgumentParser, emit
from finance_cli.core import storage
from . import session, setup


class DeviceInputRequired(ValueError):
    pass


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
    if not sys.stdin.isatty():
        raise DeviceInputRequired()
    return {name: getpass.getpass(prompt) for name, prompt in (
        ('android_id', 'Android ID (숨김): '), ('model', '기기 모델명 (숨김): '),
        ('os_version', 'Android 버전 (숨김): '))}


def main(argv=None):
    parser = Parser(prog='fin shinhan', description='신한은행 기동·세션 연결 (실서버 미검증)')
    commands = parser.add_subparsers(dest='command', required=True)
    install = commands.add_parser('setup', help='서비스 자료와 새 형식 기기 정보를 로컬에 설치')
    install.add_argument('--apk', required=True, help='버전 20.0.40 기본 설치 패키지')
    install.add_argument('--device-input', help='소유자만 읽을 수 있는 기기 JSON; 생략 시 숨김 입력')
    sessions = commands.add_parser('session').add_subparsers(dest='action', required=True)
    sessions.add_parser('status', help='로컬 상태만 확인; 은행 로그인 유효성 확인 아님')
    for action in ('start', 'extend'):
        item = sessions.add_parser(action)
        item.add_argument('--send', action='store_true')
        if action == 'start':
            item.add_argument('--apk', help='설정이 없을 때 사용할 버전 20.0.40 기본 설치 패키지')
            item.add_argument('--device-input', help='기기 JSON; 최초 설정 시 생략하면 숨김 입력')
    args = parser.parse_args(argv)
    if args.command == 'session' and args.action != 'status' and not args.send:
        emit({'error': 'send_required', 'network_used': False,
              'message': '기관 연결에는 --send가 필요합니다.'}, 2)
        return 2
    network_used = False
    try:
        if args.command == 'setup':
            result = setup.install(args.apk, device_input(args.device_input))
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
            result = session.execute(args.action)
        code = 0 if result.get('bank_result', 'success') == 'success' and result.get('processing_status', 'complete') == 'complete' and result.get('local_status', 'complete') == 'complete' else 2
    except DeviceInputRequired:
        result, code = {'error': 'device_input_required', 'network_used': False,
                        'message': '터미널에서 숨김 입력하거나 --device-input으로 기기 JSON 파일을 지정하세요.'}, 2
    except session.SessionRequired:
        result, code = {'error': 'session_required', 'network_used': False,
                        'message': '저장된 신한 세션이 없습니다. 먼저 session start를 실행하세요.'}, 2
    except (ValueError, OSError, TypeError, KeyError):
        result, code = {'error': 'local_input_or_processing_error', 'network_used': network_used,
                        'bank_result': 'unknown',
                        'message': '설치 자료·기기 입력·파일 권한을 확인하세요. 입력값은 출력하지 않습니다.'}, 2
    except (EOFError, KeyboardInterrupt):
        # Cancellation does not establish whether a bank request was accepted.
        result, code = {'error': 'interrupted', 'bank_result': 'unknown',
                        'message': '중단했습니다. 진행 중 전송의 결과를 추정하거나 자동 재시도하지 않습니다.'}, 130
    emit(result, code)
    return code
