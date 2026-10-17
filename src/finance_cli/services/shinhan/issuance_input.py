"""CLI arguments, visible ordinary inputs and hidden secrets for issuance."""
import getpass
import json
import re
import sys

from finance_cli.core import storage
from .enrollment import Pending


FIELDS = {
    'name': '성명', 'birth': '생년월일 6자리', 'gender': '주민번호 뒷부분의 첫 1자리',
    'telecom': '통신사 코드: SKT 1, KT 2, LGU+ 3, SKT 알뜰 5, KT 알뜰 6, LGU+ 알뜰 7',
    'account_number': '본인확인에 사용할 신한 계좌번호',
    'identity_sms_code': '수신한 본인확인 문자 인증번호',
    'resident_identity': '주민번호 뒷부분 7자리', 'account_password': '선택한 계좌의 비밀번호 4자리',
    'otp': '실물 OTP 6자리', 'card_serial': '파일에 지정된 일련번호 위치의 숫자 3자리',
    'card_first': '파일의 첫 보안카드 질문에 해당하는 앞 2자리',
    'card_second': '파일의 두 번째 보안카드 질문에 해당하는 뒤 2자리',
    'pin': '새 신한인증서 PIN 6자리', 'pin_repeat': '같은 PIN을 다시 입력',
    'storage_password': '인증서 파일을 보호할 보관 암호',
    'additional_method': '추가 인증 방법(파일에 표시된 ars 또는 sms)',
    'additional_phone_kind': 'ARS 인증에 사용할 전화의 kind 번호',
    'additional_sms_code': '추가 인증 문자 인증번호',
}
FLAGS = {'sms_sent': '이번 실행에서 안내된 문자를 발송 완료', 'ars_completed': '이번 실행의 ARS 인증 완료'}
IDENTITY = ('name', 'birth', 'gender', 'telecom')


def add_arguments(parser, *, phone_only=False):
    parser.add_argument('--input-file', help='입력값 JSON 파일(0600); 옵션 이름의 -를 _로 바꾼 키 사용')
    parser.add_argument('--no-input', action='store_true', help='누락된 값을 묻지 않고 required_action으로 반환')
    if not phone_only:
        for name, prompt in FIELDS.items():
            parser.add_argument('--'+name.replace('_', '-'), help=prompt)
    for name, prompt in FLAGS.items():
        if not phone_only or name == 'sms_sent':
            parser.add_argument('--'+name.replace('_', '-'), action='store_true', default=None, help=prompt)


def identity_error(name, value):
    if name == 'name' and not value:
        return '성명을 입력하세요.'
    if name == 'birth' and not re.fullmatch('[0-9]{6}', value):
        return '생년월일은 숫자 6자리(YYMMDD)로 입력하세요.'
    if name == 'gender' and not re.fullmatch('[0-9]', value):
        return '주민번호 뒷부분의 첫 숫자 1자리만 입력하세요.'
    if name == 'telecom' and value not in ('1', '2', '3', '5', '6', '7'):
        return '통신사는 1, 2, 3, 5, 6, 7 중 코드 하나를 입력하세요.'
    return None


def options(args):
    values = storage.read_json(args.input_file) if args.input_file else {}
    if not isinstance(values, dict) or set(values) - (FIELDS.keys() | FLAGS.keys()):
        raise Pending('issuance_input_file_invalid')
    for name, value in values.items():
        if not isinstance(value, bool if name in FLAGS else str):
            raise Pending('issuance_input_file_invalid')
    values.update({name: getattr(args, name) for name in FIELDS.keys() | FLAGS.keys()
                   if getattr(args, name, None) is not None})
    for name in IDENTITY:
        if name in values:
            values[name] = values[name].strip()
            error = identity_error(name, values[name])
            if error:
                print(error, file=sys.stderr)
                raise Pending('identity_'+name+'_input_invalid')
    return values


def read_line(prompt, *, secret=False, no_input=False, action='issuance_input_required'):
    if no_input:
        raise Pending(action)
    if secret and sys.stdin.isatty():
        return getpass.getpass(prompt+' (숨김): ')
    # input(prompt) would contaminate JSON stdout. A pipe can supply each line
    # as its challenge arrives, without a controlling terminal.
    print(prompt+': ', end='', file=sys.stderr, flush=True)
    try:
        return input()
    except EOFError:
        raise Pending(action) from None


def send_phone_sms(exchange, destination, message, *, confirm=None):
    try:
        path = exchange.run/'sms-instructions.json'
        storage.write_new(path, (json.dumps({'destination': destination, 'message': message}, ensure_ascii=False)+'\n').encode())
    except Exception:
        exchange.warning('phone_sms_instructions_save_error')
    prompt = ('본인 휴대폰의 문자메시지 앱에서 아래 문자를 보내세요.\n'
              f'받는 번호: {destination}\n'
              '문자 본문 (다음 한 줄만 그대로 보내세요):\n'
              f'{message}\n'
              '문자 발송을 완료한 뒤 Enter를 누르세요. 취소: Ctrl+C ')
    if confirm is not None:
        return confirm(prompt)
    getpass.getpass(prompt)
    return True


def factory(exchange, values=None, *, no_input=False):
    values = {} if values is None else values
    sequence = 0

    def review(label, value):
        nonlocal sequence
        sequence += 1
        path = exchange.run/f'input-{sequence}-{label}.json'
        try:
            storage.write_new(path, (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode())
        except Exception:
            exchange.warning('issuance_input_details_save_error')
            return
        print(f'입력에 필요한 자료: {path} (개인 자료이므로 공유하지 마세요)', file=sys.stderr)

    def read(name, *, secret=False, prompt=None):
        if name in values:
            return values[name]
        return read_line(prompt or FIELDS[name], secret=secret, no_input=no_input,
                         action=name+'_input_required')

    def completed(name, prompt):
        if name in values:
            return values[name]
        if no_input:
            print(prompt, file=sys.stderr)
        answer = read_line(prompt, no_input=no_input, action=name+'_input_required').strip().lower()
        return answer in ('', 'y', 'yes')

    def ask(kind, value):
        if kind == 'send_phone_sms':
            return send_phone_sms(exchange, value['destination'], value['message'],
                                  confirm=lambda prompt: completed('sms_sent', prompt))
        if kind == 'terms':
            review('terms', value)
            print('발급 약관에 자동 동의하고 계속합니다.', file=sys.stderr)
            return True
        if kind == 'identity':
            result = {}
            for name in IDENTITY:
                while True:
                    item = read(name).strip()
                    error = identity_error(name, item)
                    if not error:
                        result[name] = item
                        break
                    print(error, file=sys.stderr)
                    if name in values or no_input:
                        raise Pending('identity_'+name+'_input_invalid')
            return result
        if kind == 'identity_sms':
            return read('identity_sms_code', secret=True).strip()
        if kind in ('name_changed', 'phone_changed'):
            review(kind, value)
            print('등록 정보와 다른 항목이 있습니다. 발급을 계속합니다.', file=sys.stderr)
            return True
        if kind == 'download_cloud_certificate':
            review('cloud', value)
            print('새 인증서 발급을 계속합니다.', file=sys.stderr)
            return False
        if kind == 'account_security_route':
            return True
        if kind == 'network_info':
            return {'useVPN': False, 'countryCode': ''}
        if kind == 'account':
            if 'account_number' in values:
                return read('account_number').strip()
            selection = '0'
            if value and not no_input:
                review('accounts', {str(index+1): row for index, row in enumerate(value)})
                selection = read_line('본인확인에 사용할 신한 계좌의 순번 (직접 입력: 0)',
                                      action='issuance_account_selection_required').strip()
            if selection == '0':
                account = read('account_number').strip()
                if not account:
                    raise Pending('issuance_account_input_required')
                return account
            if not selection.isascii() or not selection.isdigit() or not 1 <= int(selection) <= len(value):
                raise Pending('issuance_account_selection_required')
            return value[int(selection)-1]['accountNumber']
        if kind in ('card_serial', 'card_first', 'card_second'):
            review('card-question', value)
        if kind == 'pin_repeat' and 'pin' in values and 'pin_repeat' not in values:
            return values['pin'].encode()
        if kind in ('resident_identity', 'account_password', 'otp', 'card_serial', 'card_first', 'card_second', 'pin', 'pin_repeat'):
            return read(kind, secret=True).encode()
        if kind == 'additional_select':
            review('additional-auth', value)
            method = read('additional_method').strip().lower()
            phone = read('additional_phone_kind').strip() if method == 'ars' else ''
            return {'method': method, 'kind': phone}
        if kind == 'additional_response':
            if value['method'] == 'ars':
                return completed('ars_completed', 'ARS 전화 인증을 완료한 뒤 Enter를 누르세요')
            return read('additional_sms_code', secret=True).strip()
        if kind == 'storage_password':
            password = read('storage_password', secret=True).encode()
            if not password:
                raise Pending('storage_password_confirmation_required')
            if 'storage_password' not in values:
                repeated = read_line('보관 암호를 다시 입력', secret=True, no_input=no_input,
                                     action='storage_password_confirmation_required').encode()
                if password != repeated:
                    raise Pending('storage_password_confirmation_required')
            return password
        raise Pending('issuance_input_unavailable')
    return ask
