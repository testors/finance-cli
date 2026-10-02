"""Terminal input adapters for the standalone authentication workflow."""
import getpass
from html.parser import HTMLParser
import http.client
import sys
import warnings

from finance_cli.core import storage
from finance_cli.core.paths import data_home

from .auth_flow import authenticate
from .bootstrap import _tls_context
from .errors import GiroError
from .protection_profile import ProtectionProfile
from .registration import IdentityInput
from .registration_flow import TERMS


def private_terminal():
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise GiroError('등록·로그인 비밀 입력에는 대화형 터미널이 필요합니다.')


def secret(prompt):
    private_terminal()
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        return getpass.getpass(prompt, stream=sys.stderr)


def answer(prompt):
    private_terminal()
    print(prompt, file=sys.stderr, flush=True)
    return input()


class _TermsText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts, self.hidden = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'): self.hidden += 1
        if tag in ('p', 'br', 'li', 'tr', 'div', 'h1', 'h2', 'h3'): self.parts.append('\n')

    def handle_endtag(self, tag):
        if tag in ('script', 'style') and self.hidden: self.hidden -= 1

    def handle_data(self, value):
        if not self.hidden: self.parts.append(value)


def review_terms():
    for term in TERMS:
        connection = http.client.HTTPSConnection('m.giro.or.kr', timeout=30, context=_tls_context())
        try:
            connection.request('POST', '/girohelp/guide/mobileProvision.m',
                body=('provisionType='+term['provisionType']).encode(),
                headers={'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'FinanceCLI/0.1'})
            response = connection.getresponse()
            data = response.read(1024*1024 + 1)
            if response.status != 200 or len(data) > 1024*1024:
                raise GiroError('등록 약관을 불러오지 못했습니다.')
            parser = _TermsText()
            parser.feed(data.decode(response.headers.get_content_charset() or 'utf-8'))
            text = ''.join(parser.parts).strip()
            if not text: raise GiroError('등록 약관의 본문을 확인하지 못했습니다.')
            if answer(term['name']+'\n'+text+'\n이 약관에 동의하면 "동의"를 입력하세요:') != '동의':
                return False
        finally:
            connection.close()
    return True


def enrollment_inputs(profile, carrier):
    def consent():
        if answer('CLI 기기를 등록하면 기존 휴대폰 등록이 바뀔 수 있습니다. 계속하려면 "기기 등록"을 입력하세요:') != '기기 등록':
            return False
        return review_terms()
    def identity():
        selected = carrier or answer('통신사: SKT / SKM(SKT 알뜰폰) / LGT(LG U+) / LGM(LG U+ 알뜰폰):').strip()
        phone = profile.platform.phone
        if isinstance(phone, str) and phone:
            phone = phone.replace('+82', '0')
            print('준비된 기기 자료의 본인 휴대전화번호를 사용합니다.', file=sys.stderr)
        else:
            phone = secret('본인 명의 휴대전화번호: ')
        return IdentityInput(secret('이름: '), secret('생년월일 8자리: '),
            secret('내국인 0 / 외국인 1: '), secret('남성 0 / 여성 1: '), selected, phone)
    return dict(consent_provider=consent, identity_provider=identity,
        sms_provider=lambda: secret('SMS 인증번호 6자리: '),
        existing_pin_provider=lambda: secret('기존 지로 로그인 PIN 6자리: '),
        new_pin_provider=lambda: secret('등록할 로그인 PIN 6자리: '),
        confirmation_provider=lambda: secret('등록할 PIN 다시 입력: '))


def run_auth(args):
    if args.action == 'install-profile':
        try:
            profile = ProtectionProfile.load(args.input)
            root = storage.directory(data_home()/'giro')
            profile.save(root/'protection.json')
            return dict(profile.report(), installed=True), 0
        except Exception:
            return dict(error='protection_profile_install_incomplete', network_used=False), 2
    if args.live: private_terminal()
    result = authenticate(register=args.action == 'register', send=args.live,
        retry=getattr(args, 'retry', False),
        pin_provider=lambda: secret('로그인 PIN 6자리: '),
        enrollment_providers=lambda profile: enrollment_inputs(profile, getattr(args, 'carrier', None)),
        profile_path=args.protection_profile, public_cache=args.public_cache)
    rejected = any(report.get(field) == 'failure'
        for report in [result, *result.get('steps', []), result.get('login') or {}]
        for field in ('service_decision', 'last_response_service_decision',
                      'registration_service_decision', 'login_service_decision'))
    status = (0 if result.get('plan_only') or result.get('login_service_decision') == 'success' else
              2 if result.get('processing_issues') or rejected else 4)
    return result, status
