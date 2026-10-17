"""Transfer arguments and deferred terminal/file input; no business requests."""
import getpass
import sys

from finance_cli.core import storage
from .enrollment import Pending


def add_arguments(commands):
    actions = commands.add_parser('transfer', help='신한 출금계좌의 즉시 이체 준비·실행').add_subparsers(dest='action', required=True)
    unlock = actions.add_parser('unlock', help='등록 전화번호 ARS로 장기미사용 이체 정지 해제')
    unlock.add_argument('--send', action='store_true')
    unlock.add_argument('--auth-phone', choices=('0', '1', '2'), help='ARS 수신: 휴대폰 0, 자택 1, 회사 2')
    unlock.add_argument('--ars-completed', action='store_true', help='직전 unlock의 ARS 응답 완료 후 검증·해제만 실행')
    unlock.add_argument('--no-input', action='store_true', help='ARS를 요청해 저장하고 완료 입력을 기다리지 않음')
    unlock.set_defaults(auth_method='ars')
    actions.add_parser('show', help='직전 이체 준비의 계좌·예금주·금액·수수료를 로컬에서 표시')
    accounts = actions.add_parser('accounts', help='이체 가능한 출금계좌 목록 조회')
    accounts.add_argument('--send', action='store_true')
    prepare = actions.add_parser('prepare', help='출금계좌·수취인·수수료·필요 인증 조회; 이체 실행 안 함')
    prepare.add_argument('--to-bank', required=True, help='은행 코드 3자리 또는 하나은행/신한은행')
    prepare.add_argument('--to-account', required=True)
    prepare.add_argument('--amount', required=True, type=int, help='원 단위 정수')
    prepare.add_argument('--from-account', help='생략 시 은행이 지정한 기본 출금계좌')
    prepare.add_argument('--withdrawal-memo', default='')
    prepare.add_argument('--receiver-memo', default='')
    prepare.add_argument('--send', action='store_true')
    execute = actions.add_parser('execute', help='직전 준비 내용을 사용해 인증 후 실제 이체; 한 번만 실행')
    execute.add_argument('--send', action='store_true')
    for field, description in (('account-password', '출금계좌 비밀번호 4자리'), ('otp', '실물 OTP 6자리'),
                               ('pin', '신한인증서 PIN 6자리'), ('auth-code', '추가 인증 SMS 코드')):
        execute.add_argument('--'+field+'-file', help=description+' 한 줄이 담긴 소유자 전용 파일')
    execute.add_argument('--password-stdin', action='store_true', help='인증서 보관 암호 한 줄만 stdin에서 읽음')
    execute.add_argument('--auth-method', choices=('sms', 'ars'))
    execute.add_argument('--auth-phone', choices=('0', '1', '2'), help='ARS 수신: 휴대폰 0, 자택 1, 회사 2')
    execute.add_argument('--ars-completed', action='store_true', help='ARS 요청 뒤 본인 응답을 마쳤을 때 사용')
    execute.add_argument('--no-input', action='store_true', help='필요 입력이 인자로 제공되지 않았으면 중단')


def factory(args):
    # Files/stdin are consumed only if the bank's A12 requires this auth step.
    def read(stage, context):
        if stage == 'storage_password' and args.password_stdin:
            return sys.stdin.buffer.readline().removesuffix(b'\n').removesuffix(b'\r')
        labels = {'storage_password': '신한인증서 보관 암호', 'pin': '신한인증서 PIN 6자리',
                  'account_password': '출금계좌 비밀번호 4자리', 'otp': '실물 OTP 6자리',
                  'auth_code': '수신한 추가 인증 SMS 코드'}
        if stage in labels:
            path = getattr(args, stage+'_file', None)
            if path:
                return storage.read(path, limit=4096).removesuffix(b'\n').removesuffix(b'\r')
            if args.no_input:
                raise Pending(stage+'_input_required')
            return getpass.getpass(labels[stage]+': ').encode()
        if stage == 'additional_select':
            method = args.auth_method
            if method is None and len(context['methods']) == 1:
                method = context['methods'][0]
            if method is None:
                if args.no_input:
                    raise Pending('additional_auth_method_required')
                print('추가 인증 방식: '+', '.join(context['methods']), file=sys.stderr)
                method = input_stderr('방식 (sms/ars): ')
            phones = context['phones']
            kind = args.auth_phone
            if kind is None and len(phones) == 1:
                kind = phones[0]['kind']
            if method == 'ars' and kind is None:
                if args.no_input:
                    raise Pending('additional_auth_phone_selection_required')
                for phone in phones:
                    print(phone['kind']+': '+phone['number'], file=sys.stderr)
                kind = input_stderr('수신 전화 구분: ')
            return {'method': method, 'kind': kind}
        if stage == 'additional_response':
            if context['method'] == 'sms':
                return read('auth_code', {}).decode()
            if args.ars_completed:
                return True
            if args.no_input:
                raise Pending('additional_ars_response_required')
            input_stderr('전화 인증을 마친 뒤 Enter를 누르세요: ')
            return True
        raise Pending('transfer_input_unavailable')
    return read


def input_stderr(prompt):
    print(prompt, end='', file=sys.stderr, flush=True)
    return input()
