"""Feature status: implementation, setup, verification level and readiness.

Every CLI feature is placed on a work screen, in common settings, as a
server-managed local tool, or as planned. ``available`` never promises a live
login or a verified target; the server re-checks readiness when a job runs.
"""
from . import adapters, model

FEATURES = (
    # area, id, title, placement, jobs
    ('banking', 'hana-accounts', '계좌·잔액 조회', 'work', ('hana.accounts.list', 'hana.onesign.accounts')),
    ('banking', 'hana-history', '거래 내역·상세·내보내기', 'work',
     ('hana.history.list', 'hana.history.more', 'hana.history.detail', 'hana.history.export')),
    ('banking', 'hana-inquiry', '이체 내역·상세', 'work', ('hana.inquiry.history', 'hana.inquiry.detail')),
    ('banking', 'hana-transfer', '원화 이체 준비·확인·실행·결과 조회', 'work',
     ('hana.transfer.prepare', 'hana.transfer.reconcile')),
    ('banking', 'hana-security', '보안매체·한도 조회', 'work', ('hana.security.query',)),
    ('banking', 'hana-login', '앱 인증·공동인증서·하나인증서 로그인', 'settings', ('hana.login', 'hana.onesign.login')),
    ('banking', 'hana-extend', '로그인 연장', 'settings', ('hana.session.extend',)),
    ('banking', 'hana-issuance', '하나인증서 신규 발급', 'settings',
     tuple('hana.onesign.issue.' + stage for stage in ('init', 'inspect', 'profile', 'authenticate', 'request-sms',
                                                   'verify-sms', 'consent', 'begin-id', 'prepare-id', 'identity',
                                                   'account', 'issue', 'complete'))),
    ('banking', 'hana-issuance-tools', '하나인증서 번들 이전·설정 추출', 'local', ()),
    ('banking', 'hana-tools', '인증 순서·서명·전문 인코딩 도구', 'local', ()),
    ('banking', 'hana-otp-limit', 'OTP 발급·한도 변경', 'planned', ()),
    ('tax', 'hometax-login', '인증서 로그인·세션 확인·갱신', 'settings', ('hometax.login', 'hometax.session.refresh')),
    ('tax', 'hometax-targets', '사용자·사업장 확인·등록', 'settings', ('hometax.targets.discover',)),
    ('tax', 'hometax-tax', '납부할 세액·납부 내역·환급금·전자고지', 'work',
     ('hometax.tax.dues', 'hometax.tax.payments', 'hometax.tax.refunds', 'hometax.tax.notices')),
    ('tax', 'hometax-returns', '신고 내역·접수 결과·제출서식', 'work',
     ('hometax.returns.list', 'hometax.returns.status', 'hometax.returns.forms')),
    ('tax', 'hometax-reports', '접수증·신고서·보고서 저장', 'work',
     ('hometax.returns.receipt', 'hometax.returns.document', 'hometax.report.resave')),
    ('tax', 'hometax-invoice-query', '계산서 매출·매입 조회·상세', 'work', ('hometax.invoice.list', 'hometax.invoice.detail')),
    ('tax', 'hometax-invoice-issue', '계산서 초안·수정 초안·발급', 'work', ('hometax.invoice.prepare', 'hometax.invoice.amend')),
    ('tax', 'hometax-tools', '인증 응답 처리·서명 준비', 'local', ()),
    ('tax', 'hometax-file-pay', '새 세금 신고·세금 납부', 'planned', ()),
    ('giro', 'giro-bills', '고지서 자료·납부 기한 해석', 'work', ('giro.bills.parse',)),
    ('giro', 'giro-readiness', '인증·조회 요청 계획', 'work', ('giro.readiness',)),
    ('giro', 'giro-tools', '실행 환경·인증서·인증 처리 점검', 'local', ()),
    ('giro', 'giro-probe', '초기 연결 점검', 'local', ()),
    ('giro', 'giro-live', '실제 로그인·실시간 조회·납부', 'planned', ()),
    ('common', 'credentials', '공동인증서 목록·표시 정보', 'settings', ()),
    ('common', 'certificate-import', '공동인증서 NPKI·PFX 가져오기', 'settings', ('cert.joint.import',)),
    ('common', 'certificate-files', '인증서 내보내기·프로필 가져오기', 'local', ()),
    ('common', 'joint-issuance', '공동인증서 신규 발급', 'planned', ()),
    ('common', 'financial-issuance', '금융인증서 신규 발급·클라우드 연결', 'planned', ()),
    ('common', 'financial-crypto', '금융인증서 암호 연산', 'local', ()),
    ('common', 'runtime', '런타임 상태·설치·데이터 경로', 'local', ()),
    ('common', 'activity', '웹·CLI·에이전트 작업 기록', 'settings', ()),
)

PLACEMENT_LABEL = {'work': '웹 업무', 'settings': '공통 설정', 'local': '서버에서 관리', 'planned': '준비 중'}


def verification_levels():
    """Live verification flags from ``fin capabilities``, kept separate from availability."""
    from finance_cli.cli.main import capabilities
    services = capabilities()['services']
    return {'hana': 'live_verified' if services['hana'].get('live_tested') else 'live_untested',
            'hometax': 'live_verified' if services['hometax'].get('migration_live_tested') else 'live_untested',
            'giro': 'offline'}


def setup_reasons(service, job_name=None):
    reasons = []
    if service == 'hometax':
        from finance_cli.core import runtime
        status = runtime.status()
        if not status['node']:
            reasons.append('node_not_found')
        if not status['installed']:
            reasons.append('hometax_runtime_not_installed')
        if job_name in ('hometax.invoice.prepare', 'hometax.invoice.amend'):
            from finance_cli.core.native import java_executable
            try:
                java_executable()
            except ValueError:
                reasons.append('jdk_17_or_later_required')
    return reasons


def job_state(adapter):
    reasons = setup_reasons(adapter.service, adapter.name)
    return {'status': 'setup_required' if reasons else 'available', 'reasons': reasons}


def feature_state(feature, levels, cache):
    area, feature_id, title, placement, names = feature
    registered = [adapters.get(n) for n in names]
    row = {'id': feature_id, 'area': area, 'title': title, 'placement': placement,
           'placement_label': PLACEMENT_LABEL[placement], 'jobs': [], 'reasons': []}
    if placement == 'planned':
        row['status'] = 'planned'
    elif placement == 'local':
        row['status'] = 'local_only'
    elif names and not all(registered):
        row['status'] = 'planned'
        row['reasons'] = ['web_job_not_implemented']
    else:
        row['status'] = 'available'
        for adapter in registered:
            if adapter.service not in cache:
                cache[adapter.service] = setup_reasons(adapter.service)
            reasons = setup_reasons(adapter.service, adapter.name) if adapter.name.startswith('hometax.invoice') \
                else cache[adapter.service]
            row['jobs'].append({**adapter.describe(), 'status': 'setup_required' if reasons else 'available',
                                'reasons': reasons, 'verification': levels.get(adapter.service)})
            if reasons:
                row['status'] = 'setup_required'
                row['reasons'] = sorted(set(row['reasons']) | set(reasons))
    service = next((r.service for r in registered if r), {'banking': 'hana', 'tax': 'hometax', 'giro': 'giro'}.get(area))
    row['verification'] = levels.get(service)
    row['service'] = service
    return row


def global_capabilities():
    levels = verification_levels()
    cache = {}
    return {'features': [feature_state(f, levels, cache) for f in FEATURES], 'verification': levels,
            'jobs': adapters.names(), 'states': ['available', 'setup_required', 'planned', 'local_only'],
            'readiness': ['ready', 'login_required', 'input_required', 'target_unverified']}


def login_readiness(con, login):
    session = model.current_session(con, login['id'])
    if login['disabled']:
        return 'login_disabled'
    if session is None or session['state'] != 'usable':
        return 'login_required'
    return 'ready'


def profile_capabilities(con, profile_id):
    profile = model.get_profile(con, profile_id)
    targets = [model.get_target(con, t, raw=True) for t in profile['target_ids']]
    rows = []
    for target in targets:
        login = model.get_login(con, target['login_id'], raw=True)
        readiness = login_readiness(con, login)
        if readiness == 'ready' and target['disabled']:
            readiness = 'target_disabled'
        signing = {p: bool(model.signing_for(con, login, target, p)) for p in ('invoice_sign', 'transfer_sign')}
        rows.append({'target_id': target['id'], 'login_id': login['id'], 'institution': login['institution'],
                     'target_kind': target['kind'], 'readiness': readiness, 'signing_configured': signing,
                     'verified_at': target['verified_at']})
    logins = {r['login_id'] for r in rows}
    return {'profile_id': profile_id, 'targets': rows, 'login_ids': sorted(logins),
            'features': global_capabilities()['features']}

