"""Account-payment preparation and result interpretation, without transport.

Callers supply decoded service data and payment fields. This module does not
authenticate, register accounts, accept terms, send a payment or retry one.
"""
from dataclasses import dataclass, field

from .compat import read_model, string_value
from .crypto import encode_account_password, encode_pin, encrypt_text
from .errors import GiroError
from .protocol import build_query, encrypted_form
from .response import Received, SESSION_END_CODES

ADDITIONAL_AUTH_AMOUNT = 1_000_000


def payment_plan():
    return {
        'offline': True, 'network_used': False, 'live_payment_ready': False,
        'live_payment_implemented': True, 'live_payment_verified': False,
        'tax_types': ['national', 'local', 'customs'],
        'registered_account_steps': [
            'auth.pin', 'national.list', 'national.detail', 'accounts.payable',
            'account_selection', 'account_password', 'auth.datetime',
            'conditional_additional_auth', 'national.payment', 'payment_result',
        ],
        'hometax_link_steps': [
            'hometax.detail', 'accounts.banks', 'account_input', 'account_password',
            'auth.datetime', 'conditional_link_certificate_auth',
            'hometax.payment', 'payment_result',
        ],
        'passwords': {'login_pin_digits': 6, 'account_password_digits': 4},
        'registered_account_settings_required': False,
        'hometax_link_uses_registered_account_list': False,
        'implemented': ['account_models', 'payable_account_selection',
                        'account_password_codec', 'national_account_request_preparation',
                        'conditional_auth_routing', 'payment_response_models',
                        'authenticated_session_http_client', 'single_national_bill_workflow',
                        'additional_pin_encryption', 'durable_single_payment_dispatch',
                        'receipt_query_transport', 'cli_registration_and_pin_login',
                        'encrypted_session_reuse', 'cli_reviewed_national_account_payment',
                        'local_and_customs_single_account_payment', 'read_only_payment_review',
                        'certificate_only_branch', 'registered_account_and_receipt_detail_queries'],
        'remaining': ['current_recipient_material_provisioning',
                      'certificate_fido_additional_auth', 'web_login_and_payment_integration',
                      'live_payment_server_acceptance'],
    }


def _payable(document):
    query = read_model(document, 'accounts.payable')
    if query is None:
        raise GiroError('납부 가능 계좌 응답 객체가 필요합니다.')
    return query


def _bank_status(banks, bank_code):
    if not bank_code:
        return 'bank_not_selected'
    if banks is None:
        return 'unobserved'
    for bank in banks:
        if bank is None:
            continue
        if bank.get('bankCode') is None:
            # The UI's equals call throws here, before reaching later rows.
            return 'unobserved'
        if bank['bankCode'] != bank_code:
            continue
        status = bank.get('bankStatus')
        if status is None:
            return 'unsupported_bank'
        if status.lower() != 'true':
            return 'bank_unavailable'
        if bank.get('disableCode') == '91':
            return 'unsupported_bank'
        if bank.get('disableCode') == '92':
            return 'outside_bank_hours'
        return 'available'
    return 'bank_not_listed'


def _mask_account(number):
    if number is None:
        return None
    return '*' * len(number) if len(number) <= 4 else '*' * (len(number) - 4) + number[-4:]


def account_options(document):
    """Project the payment screen's registered accounts, retaining null/empty.

    Account order and duplicates are preserved; null entries are skipped by the
    screen. Bank availability is separate from the service response verdict.
    """
    query = _payable(document)
    code = query.get('responseCode')
    result = {'offline': True, 'network_used': False, 'app_success': code == '000',
              'response_code': code, 'clear_session': code in SESSION_END_CODES,
              'accounts': None, 'list_state': 'unobserved', 'loaded_count': None}
    if code != '000':
        return result
    accounts = query.get('myValidAccountList')
    if accounts is None:
        result['list_state'] = 'null_or_missing'
        return result
    rows = []
    for account in accounts:
        if account is None:
            continue
        rows.append({'index': len(rows) + 1, 'bank_code': account.get('bankCode'),
                     'bank_name': account.get('bankName'),
                     'account_alias': account.get('manageName'),
                     'account_masked': _mask_account(account.get('accountNo')),
                     'availability': _bank_status(query.get('bankServiceList'), account.get('bankCode'))})
    result.update(accounts=rows, loaded_count=len(rows), list_state='list')
    return result


def _amount(value):
    value = string_value(value)
    if value is None:
        raise GiroError('추가 인증 판단에 필요한 납부금액이 없습니다.')
    text = value.replace(',', '')
    # Long.parseLong after comma removal, rather than a float conversion.
    digits = text[1:] if text.startswith(('+', '-')) else text
    if not digits or any(not c.isdecimal() or ord(c) > 0xFFFF for c in digits):
        raise GiroError('납부금액을 정수로 해석할 수 없습니다.')
    number = int(text)
    if not -(2**63) <= number < 2**63:
        raise GiroError('납부금액이 정수 처리 범위를 벗어났습니다.')
    return number


def authentication_route(total_amount, *, cert_only=False, link=False, verify_cert_yn=None):
    """Confirmation-screen branch. No authentication is performed here."""
    if link:
        return 'none' if verify_cert_yn == 'N' else 'link_certificate'
    if cert_only:
        return 'certificate'
    return 'additional' if _amount(total_amount) > ADDITIONAL_AUTH_AMOUNT else 'none'


@dataclass(frozen=True)
class AccountPayment:
    """Private in-memory request fields; intentionally absent from repr."""
    fields: dict = field(repr=False)
    authentication: str
    account_masked: str | None
    tax_type: str = 'national'


def prepare_registered_payment(fields, payable_response, account_index, *, login_type='PIN',
                               tax_type='national', cert_only=False):
    """Bind one returned account to already prepared single-tax payment fields.

    Bill selection, amount editing, payer and server time must be supplied by
    the caller's workflow. This does not invent them or create a live draft.
    """
    if tax_type not in ('national', 'local', 'customs'):
        raise GiroError('지원하는 납부 세목을 선택하세요.')
    query = _payable(payable_response)
    if query.get('responseCode') != '000':
        raise GiroError('성공한 납부 가능 계좌 조회 결과가 필요합니다.')
    accounts = query.get('myValidAccountList')
    if accounts is None:
        raise GiroError('납부 가능 계좌 목록을 확인하지 못했습니다.')
    accounts = [account for account in accounts if account is not None]
    if type(account_index) is not int or not 1 <= account_index <= len(accounts):
        raise GiroError('조회 결과의 계좌 번호를 선택해 주세요.')
    account = accounts[account_index - 1]
    if _bank_status(query.get('bankServiceList'), account.get('bankCode')) != 'available':
        raise GiroError('선택한 계좌의 금융기관에서 납부할 수 있는지 확인해 주세요.')
    if not account.get('accountNo'):
        raise GiroError('계좌번호를 확인하지 못했습니다.')
    payment = read_model(fields, tax_type+'.payment')
    if payment is None:
        raise GiroError('납부 요청 필드 객체가 필요합니다.')
    payment.update(bankCode=account.get('bankCode'), 납부은행=account.get('bankName'),
                   계좌번호=account['accountNo'], acntPwd=None,
                   addUserAcntYn=None, manageName=None)
    auth = authentication_route(payment.get('납부금액'), cert_only=cert_only)
    # Input-screen amount fields and confirmation-screen certificate routing
    # are separate decisions. A small cert-only bill still needs a certificate.
    if authentication_route(payment.get('납부금액')) == 'none':
        payment.update(acntPaymentType='1', addCertMethod='0')
    else:
        payment['addCertMethod'] = {'PIN': '2', 'CERT': '1', 'FIDO': '7', 'FINCERT': '3'}.get(login_type, '')
    return AccountPayment(payment, auth, _mask_account(account['accountNo']), tax_type)


def encode_registered_payment(prepared, *, account_password_provider, key, device_id,
                              additional_pin_provider=None):
    """Create an encrypted body in memory. Never send, persist or log it.

    Additional PIN authentication uses six digits and the same session key.
    Certificate/FIDO branches require their own authentication implementation.
    """
    pin_auth = (prepared.authentication == 'additional'
                and prepared.fields.get('addCertMethod') == '2')
    if prepared.authentication != 'none' and not (pin_auth and additional_pin_provider is not None):
        raise GiroError('추가 인증 실행은 아직 지원하지 않습니다.')
    if not isinstance(key, bytes) or len(key) != 16:
        raise GiroError('SEED 세션 키는 정확히 16바이트여야 합니다.')
    fields = dict(prepared.fields)
    fields['acntPwd'] = encode_account_password(account_password_provider(), key)
    if pin_auth:
        fields['encAddCertValue'] = encode_pin(additional_pin_provider(), key)
    text = build_query(prepared.tax_type+'.payment', fields, device_id=device_id)
    return encrypted_form(encrypt_text(text, key))


def payment_result(received: Received):
    """Keep service success even if receipt rendering data is missing."""
    receipt = received.query.get('receiptItem') if received.query is not None else None
    # A transport/decode failure is an application failure, but it does not
    # establish whether a submitted payment reached the service.
    decision = ('success' if received.app_success else 'failure') if received.origin == 'response' else 'unobserved'
    return {'app_success': received.app_success, 'response_code': received.code,
            'callback': received.callback, 'callback_code': received.callback_code,
            'clear_session': received.clear_session,
            'service_decision': decision, 'automatic_retry': False,
            'receipt_state': 'unobserved' if not received.app_success else
                'null_or_missing' if receipt is None else 'list',
            'receipt_count': len(receipt) if received.app_success and receipt is not None else None}
