"""Single-tax account payment on an already authenticated session.

No authentication bypass, login retry, account registration or automatic
reconciliation. Callers must display the returned draft before explicit send.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import uuid

from finance_cli.core import storage
from finance_cli.core.paths import data_home

from .compat import omit_null_fields, read_model
from .errors import GiroError
from .payment import (_amount, _mask_account, account_options, encode_registered_payment,
                      payment_result, prepare_registered_payment)


class WorkflowStopped(GiroError):
    def __init__(self, stage, response):
        self.stage, self.response = stage, response
        super().__init__('기관 응답으로 납부 준비를 중단했습니다.')


def _success(stage, response):
    if not response.app_success:
        raise WorkflowStopped(stage, response)
    return response.query


def tax_payment_fields(detail, *, tax_type='national', session_info, current_datetime, amount=None):
    """Flatten single-bill detail, then apply the account confirmation fields."""
    labels = {'national': '국세(조회납부)', 'local': '지방세', 'customs': '관세(조회납부)'}
    if tax_type not in labels:
        raise GiroError('지원하는 납부 세목을 선택하세요.')
    detail = read_model(detail, tax_type+'.detail')
    if detail is None or detail.get('responseCode') != '000':
        raise GiroError('성공한 고지 상세 조회 응답이 필요합니다.')
    data = detail.get('paymentData')
    if data is None:
        raise GiroError('조회는 성공했지만 납부 상세 자료를 확인하지 못했습니다.')
    # The detail query is serialized with Gson's serializeNulls=false before
    # the screen flattens it. A null child must not erase a top-level value.
    merged = {**omit_null_fields(detail), **omit_null_fields(data)}
    value = data.get('payMny')
    if amount is not None:
        if data.get('mnyEditYn') not in ('Y', 'P'):
            raise GiroError('이 고지는 납부금액을 변경할 수 없습니다.')
        edited = _amount(amount)
        # The input widget accepts positive decimal amounts; zero restores the
        # original amount. Do not silently change an explicitly supplied amount.
        if edited <= 0 or edited % 10:
            raise GiroError('변경할 납부금액은 10원 이상의 10원 단위여야 합니다.')
        maximum = data.get('remainPayMny')
        if maximum is None:
            maximum = data.get('payMny')
        if data.get('mnyEditYn') == 'P' and edited > _amount(maximum):
            raise GiroError('남은 납부금액을 초과했습니다.')
        value = str(edited)
    total = _amount(value)  # Missing amount is a local boundary, not a service rejection.
    if data.get('mnyEditYn') in ('Y', 'P') and (0 < total < 10 or total > 10 and total % 10):
        raise GiroError('납부금액은 10원 단위여야 합니다.')
    fields = {key: merged.get(key) for key in
              ('serviceCode', 'sortCode', 'giroNo', 'key', 'when', 'mnyEditYn', 'feeGroup',
               'isCardPayableTime', 'isCardPayableTimeMsg', 'isMemberOwnGoji')}
    fields.update(거래구분='즉시납부', 거래일시=current_datetime, 요금종류=labels[tax_type],
                  청구기관명=data.get('companyName'), 납부자명=session_info.get('payer'),
                  납부금액=value, 납부세액=value, 거래번호=merged.get('elecNo'), 세목=data.get('taxName'))
    return fields


def national_payment_fields(detail, *, session_info, current_datetime, amount=None):
    return tax_payment_fields(detail, session_info=session_info,
                              current_datetime=current_datetime, amount=amount)


@dataclass(repr=False)
class _Draft:
    payment: object
    bill_id: str
    used: bool = False


class PaymentJournal:
    """Durable, exclusive reservation per bill, across sessions and processes.

    There is deliberately no reset/retry method. A timeout or crash leaves the
    reservation in place. Receipt queries are separate read-only operations.
    """
    def __init__(self, root=None):
        self.root = Path(root) if root is not None else data_home() / 'giro' / 'payments'

    def reserve(self, bill_id):
        root = storage.directory(self.root)
        path = root / (bill_id + '.json')
        try:
            storage.write_new(path, b'{"state":"reserved","service_decision":"unobserved"}\n')
        except FileExistsError:
            raise GiroError('이미 납부 전송을 예약한 고지입니다. 납부내역을 확인해 주세요.') from None
        return path

    def check_available(self, bill_id):
        if storage.no_symlinks(self.root / (bill_id + '.json')).exists():
            raise GiroError('이미 납부 전송을 예약한 고지입니다. 납부내역을 확인해 주세요.')

    def finish(self, reservation, result):
        storage.atomic_json(reservation, {'state': 'completed', **result})


class PaymentWorkflow:
    def __init__(self, client, *, journal=None):
        self.client = client
        self.journal = journal if journal is not None else PaymentJournal()
        self._drafts = {}

    def prepare(self, bill, *, account_selector, amount=None, tax_type='national', send=False):
        """Selected list item -> detail -> registered accounts -> server time.

        account_selector receives masked account options and returns a 1-based
        index. No password is collected and no payment is sent by this method.
        """
        if not send:
            raise GiroError('기관 통신에는 명시적인 전송 승인이 필요합니다.')
        if tax_type not in ('national', 'local', 'customs'):
            raise GiroError('지원하는 납부 세목을 선택하세요.')
        with self.client.session.lock:
            self.client.require_active()
            endpoint = tax_type+'.detail'
            detail = _success(endpoint, self.client.query(endpoint, bill, send=True))
            accounts = _success('accounts.payable', self.client.query('accounts.payable',
                {'serviceCode': detail.get('serviceCode'), 'isReserve': 'N'}, send=True))
            options = account_options(accounts)
            options.update(offline=False, network_used=True)
            selected = account_selector(options)
            clock = _success('auth.datetime', self.client.query('auth.datetime', {}, send=True))
            fields = tax_payment_fields(detail, tax_type=tax_type, session_info=self.client.session.info,
                current_datetime=clock.get('currentDateTime'), amount=amount)
            prepared = prepare_registered_payment(fields, accounts, selected,
                login_type=self.client.session.login_type, tax_type=tax_type,
                cert_only=detail['paymentData'].get('certOnlyYn') == 'Y')
            # Use the electronic bill number, not a potentially refreshed query
            # key, amount or bank. None of those changes permits a replay.
            identity = [tax_type, fields.get('거래번호')]
            if not identity[-1]:
                raise GiroError('중복 전송 방지에 필요한 고지 식별자를 확인하지 못했습니다.')
            bill_id = hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).hexdigest()
            token = uuid.uuid4().hex
            review = {'draft_id': token, 'tax_type': tax_type, 'amount': _amount(fields['납부금액']),
                      'issuer': fields.get('청구기관명'),
                      'tax_name': detail['paymentData'].get('taxName'),
                      'bill_number_masked': _mask_account(fields['거래번호']),
                      'bank_name': prepared.fields.get('납부은행'), 'account_masked': prepared.account_masked,
                      'authentication': prepared.authentication,
                      'additional_pin_required': prepared.authentication == 'additional'
                          and prepared.fields.get('addCertMethod') == '2',
                      'network_used': True, 'payment_sent': False}
            self._drafts[token] = _Draft(prepared, bill_id)
            return dict(review)

    def pay(self, draft_id, *, account_password_provider, additional_pin_provider=None, send=False):
        if not send:
            raise GiroError('납부 전송에는 명시적인 승인이 필요합니다.')
        with self.client.session.lock:
            self.client.require_active()
            draft = self._drafts.get(draft_id)
            if draft is None or draft.used:
                raise GiroError('사용할 수 있는 납부 확인 내역이 없습니다.')
            self.journal.check_available(draft.bill_id)
            body = encode_registered_payment(draft.payment,
                account_password_provider=account_password_provider,
                additional_pin_provider=additional_pin_provider,
                key=self.client.session.key, device_id=self.client.session.device_id)
            reservation = self.journal.reserve(draft.bill_id)
            draft.used = True  # Before the first possible write to the socket.
            try:
                received = self.client._exchange(draft.payment.tax_type+'.payment', body)
                result = payment_result(received)
                result['processing_issues'] = list(received.issues)
            except Exception:
                # Bytes may have reached the bank. Keep the reservation; do not
                # turn an unknown result into success/failure or retry a request.
                result = {'app_success': None, 'service_decision': 'unobserved',
                          'automatic_retry': False, 'processing_issues': ['response_processing_failed']}
            result.update(payment_attempted=True, result_saved=False)
            try:
                self.journal.finish(reservation, {**result, 'result_saved': True})
                result['result_saved'] = True
            except Exception:
                result['processing_issues'].append('result_save_failed')
            return result
