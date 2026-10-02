"""Explicit terminal review before a single national-tax account payment."""
from .auth_cli import answer, private_terminal, secret
from .client import AuthenticatedClient
from .errors import GiroError
from .payment_flow import PaymentWorkflow, WorkflowStopped
from .query_flow import collect_bills, response_report
from .session_store import SessionStore


def _choose(rows, label, display):
    if not rows: raise GiroError(label+' 항목을 확인하지 못했습니다.')
    choices = [(index, row) for index, row in enumerate(rows, 1) if row is not None]
    if not choices: raise GiroError(label+' 항목을 확인하지 못했습니다.')
    if len(choices) == 1: return choices[0][0]
    text = '\n'.join(str(index)+'. '+display(row) for index, row in choices)
    value = answer(text+'\n'+label+' 번호:').strip()
    if not value.isascii() or not value.isdigit() or int(value) not in [index for index, _ in choices]:
        raise GiroError('선택한 번호를 확인하세요.')
    return int(value)


def run_payment(args):
    if not args.live:
        return dict(plan_only=True, network_used=False, payment_attempted=False,
            sequence=['existing session', 'own national bills', 'detail', 'registered accounts',
                      'server time', 'review and confirmation', 'account password', 'one payment request'],
            automatic_login=False, automatic_retry=False), 0
    private_terminal()
    result = dict(payment_attempted=False, service_decision='unobserved', processing_issues=[])
    try:
        with SessionStore().use() as (session, issues):
            client = AuthenticatedClient(session)
            result['session_processing_issues'] = issues
            bills = collect_bills(client, 'national')
            if not bills.get('app_success') or bills.get('bills') is None:
                result['bill_query'] = bills
                return result, 4
            rows = bills['bills']
            if not rows:
                result.update(bill_query=bills, next_action='no_bills_returned')
                return result, 0
            selected = _choose(rows, '납부할 고지', lambda row:
                f"{row['issuer']} · {row['amount_raw']}원 · 기한 {row['due_date_raw']}")
            workflow = PaymentWorkflow(client)
            def account(options):
                return _choose(options['accounts'], '납부계좌', lambda row:
                    f"{row['bank_name']} {row['account_masked']}")
            review = workflow.prepare(rows[selected-1]['identifiers'], account_selector=account,
                                      amount=args.amount, send=True)
            result['review'] = review
            prompt = (f"{review['issuer']} / {review['tax_name'] or '국세'} / 고지 {review['bill_number_masked']}\n"
                      f"납부액 {review['amount']:,}원\n{review['bank_name']} {review['account_masked']}\n"
                      '이 금액을 납부하려면 "납부"를 입력하세요:')
            if answer(prompt) != '납부':
                result['next_action'] = 'payment_cancelled'
                return result, 0
            result.update(workflow.pay(review['draft_id'],
                account_password_provider=lambda: secret('계좌 비밀번호 4자리: '),
                additional_pin_provider=lambda: secret('추가 인증용 지로 로그인 PIN 6자리: '), send=True))
            result['events'] = list(client.events)
    except WorkflowStopped as stopped:
        result.update(stage=stopped.stage, preparation_response=response_report(stopped.response))
    except (Exception, KeyboardInterrupt):
        result['processing_issues'].append('payment_processing_incomplete')
    return result, 0 if result.get('app_success') else 2
