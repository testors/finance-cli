"""Reviewed capability evidence, not runtime financial data or a success predictor.

The 2026-09-30–2026-10-01 web job review kept institution verdicts separate
from local completion. CLI command names/exit codes alone are not evidence.
Only supported paths actually observed are marked; no receipts or identifiers
are distributed. See docs/banking-verification.md for scope and limitations.
"""

REVIEWED_ON = '2026-10-01'
HANA_LEVEL = 'live_partial'
PREFLIGHT_NOTE = '하나인증서 조회 성공 확인. 재로그인 후 계좌 자동 확인은 합성 검증 완료, 실사용 재확인 전.'
HISTORY_NOTE = ('하나인증서 조회 성공 확인(한 페이지씩 조회하던 때의 기록). 최근·과거 구간과 다음 페이지를 한 작업에서 이어 받는 '
                '통합 조회와 재로그인 후 계좌 자동 확인은 합성 검증 완료, 실사용 재확인 전.')
TRANSFER_NOTE = '은행의 이체 실행 성공 응답 확인. 연결된 결과 상세도 조회했으나 최종 이체 확정은 미확인.'

HANA_JOBS = {
    'hana.onesign.login': ('live_verified', '하나인증서 서명 로그인 성공 확인.'),
    'hana.onesign.accounts': ('live_verified', '하나인증서 로그인으로 계좌 목록·잔액 응답 확인.'),
    'hana.onesign.history.list': ('live_partial', HISTORY_NOTE),
    'hana.onesign.history.detail': ('live_verified', '하나인증서 거래 내역의 은행 상세 응답 확인. 상세 유형 전체를 검증한 것은 아님.'),
    'hana.onesign.inquiry.history': ('live_partial', PREFLIGHT_NOTE),
    'hana.onesign.security.query': ('live_partial', '하나인증서 이체한도 조회 성공 확인. 한도 예외·보안매체·OTP 세부 조회는 미확인.'),
    'hana.onesign.session.extend': ('live_partial', '하나인증서 로그인 연장의 은행 수락과 연장만으로 세션이 유지되는 것을 저장된 CLI 세션에서 확인(2026-10-10; 요청 없이 595초 뒤 유지, 600초 뒤 종료). 이 웹 작업 자체의 실사용은 미확인.'),
    'hana.transfer.prepare': ('live_partial', TRANSFER_NOTE),
    'hana.transfer.reconcile': ('live_partial', '계좌·금액과 연결된 상세 후보 확인. 최종 이체 확정은 미확인.'),
}
for _stage in ('authenticate', 'request-sms', 'verify-sms', 'begin-id', 'identity', 'list-accounts', 'account',
               'issue', 'complete'):
    HANA_JOBS['hana.onesign.issue.' + _stage] = (
        'live_verified', '신규 발급의 해당 단계 성공 확인. 관찰한 발급 경로 기준이며 모든 인증 분기를 뜻하지 않음.')
for _stage in ('init', 'inspect', 'profile', 'consent', 'prepare-id'):
    HANA_JOBS['hana.onesign.issue.' + _stage] = ('offline', '기관 요청 없는 로컬 발급 준비·상태 확인 단계.')

HANA_FEATURE_NOTES = {
    'hana-accounts': '하나인증서 계좌·잔액 조회 성공 확인. 공동인증서 경로는 최근 기록에서 미확인.',
    'hana-history': '하나인증서 목록(한 페이지)·은행 상세 조회 성공 확인. 최근·과거 구간과 다음 페이지의 자동 연결·JSON/CSV 저장·공동인증서 경로와 재로그인 후 계좌 자동 확인은 실사용 미확인.',
    'hana-inquiry': '하나인증서 이체 내역 목록 성공 확인. 상세·공동인증서 경로와 재로그인 후 계좌 자동 확인은 실사용 미확인.',
    'hana-transfer': TRANSFER_NOTE,
    'hana-security': '하나인증서 이체한도 조회 성공 확인. 공동인증서·한도 예외·보안매체·OTP 세부 조회는 실사용 미확인.',
    'hana-login': '하나인증서 서명 로그인 성공 확인. 공동인증서 경로는 최근 기록에서 미확인.',
    'hana-extend': '하나인증서 로그인 연장의 은행 수락과 세션 유지를 저장된 CLI 세션에서 확인(2026-10-10). 공동인증서 경로와 웹 연장 작업 자체의 실사용은 미확인.',
    'hana-issuance': 'SMS·신분증·본인계좌 확인부터 인증서 발급·완료까지 성공 확인. 신분증 종류별·예외 인증 분기는 별도 확인 필요.',
}


def hana_job(name):
    level, note = HANA_JOBS.get(name, ('live_untested', '최근 이용 기록에 기관 성공 판정의 근거가 없음. 합성 검증 범위는 유지.'))
    return {'verification': level, 'verification_note': note, 'verification_reviewed_at': REVIEWED_ON}


def combined_level(levels):
    remote = set(levels) - {None, 'offline'}
    if not remote:
        return 'offline'
    return next(iter(remote)) if len(remote) == 1 else 'live_partial'


def hana_report():
    return {'reviewed_at': REVIEWED_ON, 'period': ['2026-09-30', '2026-10-01'],
            'source': 'reviewed_web_job_verdicts', 'verification': HANA_LEVEL,
            'live_tested_scope': 'all_supported_remote_paths',
            'jobs': {name: hana_job(name) for name in HANA_JOBS},
            'unverified': ['joint-certificate-paths', 'login-extension-web-job', 'history-next-page-and-export',
                           'transfer-history-detail', 'security-queries-other-than-onesign-limits',
                           'final-transfer-confirmation', 'fresh-session-account-preflight',
                           'all-issuance-and-transfer-authentication-branches']}


# Reviewed CLI and web service verdicts, not an automatic promotion based on
# local job completion. No account, bill, session or receipt contents belong here.
GIRO_REVIEWED_ON = '2026-10-10'
GIRO_JOBS = {
    'giro.login': ('live_verified', '웹 PIN 로그인·암호화 세션 저장 성공 확인.'),
    'giro.bills.list': ('live_partial', '국세 목록·상세는 CLI에서 성공 확인. 웹 국세·지방세·관세 조회는 “고지내용 없음”(311) 응답 확인. 고지가 있는 웹 목록과 추가 공과금 항목은 미확인.'),
    'giro.bills.regions': ('live_untested', '지역 목록 작업은 구현·합성 검증. 같은 시도·지자체 목록 요청은 지방세 조회 과정에서 수락 확인, 웹 지역 선택과 환경개선부담금·세외수입 목록은 미확인.'),
    'giro.bills.summary': ('live_untested', '통합조회는 구현·합성 검증. 실사용 미확인.'),
    'giro.bills.search': ('live_untested', '번호 기반 공과금 조회는 구현·합성 검증. 실사용 미확인.'),
    'giro.bills.detail': ('live_untested', '독립 고지 상세 조회는 구현·합성 검증. 실사용 미확인.'),
    'giro.payment.options': ('live_partial', '국세 상세·납부 가능 계좌 조회는 CLI에서 성공 확인. 웹 납부계좌 선택과 지방세·관세 상세는 미확인.'),
    'giro.payment.prepare': ('live_partial', '국세 단건 계좌 납부·추가 PIN 인증은 CLI에서 성공 확인. 웹 납부 실행과 지방세·관세 납부는 미확인.'),
    'giro.accounts.list': ('live_verified', '웹 등록계좌 목록·계좌 별칭 조회 성공 확인.'),
    'giro.session.extend': ('live_partial', '이 연장 요청이 저장된 CLI 세션에서 수락되고 유휴 만료를 늦추는 것을 확인(요청 없이 295초 뒤 유지, 300초 뒤 종료). 웹 작업 자체의 실사용은 미확인.'),
    'giro.receipts.list': ('live_verified', '웹 납부내역 목록 조회 성공 확인. 관측한 기간·페이지 기준.'),
    'giro.receipts.detail': ('live_verified', '웹 납부내역 상세 조회 성공 확인. 관측한 납부내역 기준.'),
}


def giro_job(name):
    default = ('offline', '기관 통신 없는 로컬 자료 처리.') if name in ('giro.bills.parse', 'giro.readiness') \
        else ('live_untested', '해당 경로의 실사용 확인 기록이 없습니다.')
    level, note = GIRO_JOBS.get(name, default)
    return {'verification': level, 'verification_note': note, 'verification_reviewed_at': GIRO_REVIEWED_ON}


def giro_report():
    return {'reviewed_at': GIRO_REVIEWED_ON, 'source': 'observed_cli_and_web_service_verdicts',
            'verified': ['device-registration', 'pin-login', 'encrypted-session-save', 'saved-session-reuse',
                         'own-national-tax-query', 'payment-review', 'single-national-account-payment',
                         'registered-account-list', 'receipt-list', 'receipt-detail'],
            'unverified': ['own-local-tax-query', 'own-customs-query', 'utility-bill-queries',
                           'bill-query-regions', 'integrated-bill-summary', 'bill-detail',
                           'single-local-account-payment', 'single-customs-account-payment',
                           'web-query-with-bills', 'web-payment-execution'],
            'jobs': {name: giro_job(name) for name in GIRO_JOBS},
            'note': 'CLI 기기 등록·국세 조회·단건 계좌 납부·추가 PIN 인증 성공 확인. 웹 PIN 로그인·세션 저장·등록계좌·납부내역 목록/상세 조회 성공 확인. 웹 세금 목록은 고지내용 없음(311) 응답 확인. 웹 납부 실행과 지방세·관세 납부는 미확인.'}
