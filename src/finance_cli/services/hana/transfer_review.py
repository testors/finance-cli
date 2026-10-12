"""Duplicate notice and offline reference for the bank's original questionnaire.

Runtime automatically acknowledges the client-only fraud popup per user policy;
questions/answers/session_body remain reference inputs for the research source
comparison, and are not called by the CLI or web transfer workflow.
"""
from .ledger_protocol import number

DUPLICATE_MESSAGE = '같은 내용의 이체가 있을 수 있습니다. 기존 이체 내역과 받는 계좌·금액을 확인한 뒤 계속하시겠습니까?'
FRAUD_WARNING = '보이스피싱이 의심돼요. 다시 한번 확인해 주세요.'
QUESTIONS = {
    '1': ('취업된 회사 또는 고액 아르바이트 업체에서 입금된 돈을 송금해달라고 요구하였나요?', 'no'),
    '2': ('링크뿐 아니라 공식 앱스토어를 통한 어플 설치 요구 시 보이스피싱 사기입니다. 이해하셨나요?', 'yes'),
    '3': ('비상장주식, 해외주식, 코인 투자를 목적으로 거래하시나요?', 'no'),
    '4': ('텔레그램, 전화 등을 통해 대환대출을 제안받고 이체하고 계신가요?', 'no'),
    '5': ('검찰이 범죄 연루를 언급하며, 주변에 알리면 가족까지 구속시킨다고 협박하였나요?', 'no'),
    '6': ('금감원, 검찰, 국세청 등은 어떤 경우에도 직접 이체를 요구하지 않습니다. 이해하셨나요?', 'yes'),
    '7': ('타인의 지시로 공식 앱스토어나 링크를 통해 새로운 어플을 설치한 후 이체하고 계신가요?', 'no'),
}


def questions(age):
    # Original Number(manAge ?? "0"), including missing/blank and NaN branches.
    age = number(age)
    ids = ('1', '2', '3') if age < 30 else ('4', '2', '5') if age < 40 else (
        ('2', '4', '3') if age < 60 else ('4', '6', '7') if age >= 60 else ())
    return [{'id': key, 'text': QUESTIONS[key][0], 'continue_on': QUESTIONS[key][1]} for key in ids]


def answers_complete(rows, answers):
    return (bool(rows) and isinstance(answers, dict) and set(answers) == {row['id'] for row in rows}
            and all(answers.get(row['id']) == row['continue_on'] for row in rows))


def session_body():
    body = dict.fromkeys(('lginYn', 'custInfoYn', 'custInfoAdtnYn', 'lginTmpAllYn', 'allAcctPrdYn',
                          'allAcctOpbkYn', 'allAcctRtpnsYn', 'allAcctMyDatYn', 'exhgRtYn', 'usrAthtMap'), 'N')
    return {**body, 'lginYn': 'Y', 'custInfoAdtnYn': 'Y', 'lginTmpList': []}
