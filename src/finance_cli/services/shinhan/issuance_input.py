"""Terminal inputs for certificate issuance; private choices stay off stdout."""
import getpass
import json
import re
import sys

from finance_cli.core import storage
from .enrollment import Pending


def yes(prompt):
    value = getpass.getpass(prompt+' [y/n]: ').strip().lower()
    if value not in ('y', 'n'):
        raise Pending('confirmation_input_required')
    return value == 'y'


def factory(exchange):
    sequence = 0
    def review(label, value):
        nonlocal sequence
        sequence += 1
        path = exchange.run/f'input-{sequence}-{label}.json'
        storage.write_new(path, (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode())
        print(f'입력에 필요한 자료: {path} (개인 자료이므로 공유하지 마세요)', file=sys.stderr)

    def ask(kind, value):
        if kind == 'send_phone_sms':
            review('sms', value)
            getpass.getpass('파일의 번호로 내용을 그대로 본인 휴대폰에서 전송한 뒤 Enter를 누르세요. 취소: Ctrl+C ')
            return True
        if kind == 'terms':
            review('terms', value)
            return yes('파일에 안내된 약관 문서를 확인하고 동의하나요?')
        if kind == 'identity':
            review('phone', value)
            fields = [('name', '성명'), ('birth', '생년월일 6자리'), ('gender', '주민번호 뒷부분의 첫 1자리'),
                      ('telecom', '통신사 코드: SKT 1, KT 2, LGU+ 3, SKT 알뜰 5, KT 알뜰 6, LGU+ 알뜰 7')]
            result = {name: getpass.getpass(prompt+' (숨김): ').strip() for name, prompt in fields}
            if not re.fullmatch('[0-9]{6}', result['birth']) or not re.fullmatch('[0-9]', result['gender']):
                raise Pending('identity_input_invalid')
            if result['telecom'] not in ('1', '2', '3', '5', '6', '7') or not result['name']:
                raise Pending('identity_input_invalid')
            return result
        if kind == 'identity_sms':
            return getpass.getpass('수신한 본인확인 문자 인증번호: ').strip()
        if kind in ('name_changed', 'phone_changed'):
            review(kind, value)
            return yes('입력 정보가 은행 등록 정보와 다릅니다. 확인 후 계속할까요?')
        if kind == 'download_cloud_certificate':
            review('cloud', value)
            return not yes('기존 클라우드 인증서가 있습니다. 새 인증서 발급을 계속할까요?')
        if kind == 'account_security_route':
            return yes('계좌 비밀번호와 보안카드 또는 실물 OTP로 인증을 진행할까요?')
        if kind == 'network_info':
            return {'useVPN': yes('휴대폰에서 현재 VPN을 사용 중인가요?'),
                    'countryCode': getpass.getpass('휴대폰 통신망 국가코드(예: kr, 확인할 수 없으면 빈칸): ').strip().lower()}
        if kind == 'account':
            selection = '0'
            if value:
                review('accounts', {str(index+1): row for index, row in enumerate(value)})
                selection = getpass.getpass('본인확인에 사용할 신한 계좌의 순번 (직접 입력: 0): ').strip()
            if selection == '0':
                account = getpass.getpass('본인확인에 사용할 신한 계좌번호 (- 없이, 숨김): ').strip()
                if not account:
                    raise Pending('issuance_account_input_required')
                return account
            if not selection.isascii() or not selection.isdigit() or not 1 <= int(selection) <= len(value):
                raise Pending('issuance_account_selection_required')
            return value[int(selection)-1]['accountNumber']
        if kind in ('card_serial', 'card_first', 'card_second'):
            review('card-question', value)
        prompts = {'resident_identity': '주민번호 뒷부분 7자리', 'account_password': '선택한 계좌의 비밀번호 4자리',
                   'otp': '실물 OTP 6자리', 'card_serial': '파일에 지정된 일련번호 위치의 숫자 3자리',
                   'card_first': '파일의 첫 보안카드 질문에 해당하는 앞 2자리',
                   'card_second': '파일의 두 번째 보안카드 질문에 해당하는 뒤 2자리',
                   'pin': '새 신한인증서 PIN 6자리', 'pin_repeat': '같은 PIN을 다시 입력'}
        if kind in prompts:
            return getpass.getpass(prompts[kind]+' (숨김): ').encode()
        if kind == 'additional_select':
            review('additional-auth', value)
            method = getpass.getpass('추가 인증 방법(파일에 표시된 ars 또는 sms): ').strip().lower()
            phone = getpass.getpass('ARS 인증에 사용할 전화의 kind 번호: ').strip() if method == 'ars' else ''
            return {'method': method, 'kind': phone}
        if kind == 'additional_response':
            if value['method'] == 'ars':
                return yes('ARS 전화 인증을 완료했나요?')
            return getpass.getpass('추가 인증 문자 인증번호: ').strip()
        if kind == 'storage_password':
            password = getpass.getpass('인증서 파일을 보호할 보관 암호: ').encode()
            if not password or password != getpass.getpass('보관 암호를 다시 입력: ').encode():
                raise Pending('storage_password_confirmation_required')
            return password
        raise Pending('issuance_input_unavailable')
    return ask
