"""Feature status: implementation, setup, verification level and readiness.

Every CLI feature is placed on a work screen, in common settings, as a
server-managed local tool, or as planned. ``available`` never promises a live
login or a verified target; the server re-checks readiness when a job runs.
"""
from . import adapters, model
from finance_cli.core.live_verification import HANA_FEATURE_NOTES, REVIEWED_ON, GIRO_REVIEWED_ON, combined_level, hana_job, giro_job

FEATURES = (
    # area, id, title, placement, jobs
    ('corporate', 'corporate-login', '기업 ID/PW·공동인증서·하나인증서 로그인', 'settings',
     ('hana.corporate.login-idpw', 'hana.corporate.login', 'hana.corporate.login-onesign')),
    ('corporate', 'corporate-extend', '기업 로그인 연장', 'settings', ('hana.corporate.session.extend',)),
    ('corporate', 'corporate-accounts', '기업 계좌·잔액 조회', 'work', ('hana.corporate.accounts',)),
    ('corporate', 'corporate-history', '기업 거래내역 조회', 'work', ('hana.corporate.history',)),
    ('corporate', 'corporate-transfer', '기업 원화 이체·인증·결과 확인', 'work',
     ('hana.corporate.transfer.prepare', 'hana.corporate.transfer.result', 'hana.corporate.transfer.cancel')),
    ('banking', 'hana-accounts', '계좌·잔액 조회', 'work', ('hana.accounts.list', 'hana.onesign.accounts')),
    ('banking', 'hana-history', '거래 내역·상세·내보내기', 'work',
     ('hana.history.list', 'hana.history.detail', 'hana.history.export',
      'hana.onesign.history.list', 'hana.onesign.history.detail', 'hana.onesign.history.export')),
    ('banking', 'hana-inquiry', '이체 내역·상세', 'work',
     ('hana.inquiry.history', 'hana.inquiry.detail', 'hana.onesign.inquiry.history', 'hana.onesign.inquiry.detail')),
    ('banking', 'hana-transfer', '원화 이체 준비·확인·실행·결과 조회', 'work',
     ('hana.transfer.prepare', 'hana.transfer.reconcile')),
    ('banking', 'hana-security', '보안매체·한도 조회', 'work', ('hana.security.query', 'hana.onesign.security.query')),
    ('banking', 'hana-login', '앱 인증·공동인증서·하나인증서 로그인', 'settings', ('hana.login', 'hana.onesign.login')),
    ('banking', 'hana-extend', '로그인 연장', 'settings', ('hana.session.extend', 'hana.onesign.session.extend')),
    ('banking', 'hana-issuance', '하나인증서 신규 발급', 'settings',
     tuple('hana.onesign.issue.' + stage for stage in ('init', 'inspect', 'profile', 'authenticate', 'request-sms',
                                                   'verify-sms', 'consent', 'begin-id', 'prepare-id', 'identity',
                                                   'list-accounts', 'account', 'issue', 'complete'))),
    ('banking', 'hana-issuance-tools', '하나인증서 번들 이전·설정 추출', 'local', ()),
    ('banking', 'hana-tools', '인증 순서·서명·전문 인코딩 도구', 'local', ()),
    ('banking', 'hana-otp-limit', 'OTP 발급·한도 변경', 'planned', ()),
    ('tax', 'hometax-login', '인증서 로그인·세션 확인·갱신', 'settings', ('hometax.login', 'hometax.session.refresh')),
    ('tax', 'hometax-extend', '로그인 연장', 'settings', ('hometax.session.extend',)),
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
    ('giro', 'giro-readiness', '서버 준비·지원 상태', 'work', ('giro.readiness',)),
    ('giro', 'giro-tools', '실행 환경·인증서·인증 처리 점검', 'local', ()),
    ('giro', 'giro-probe', '초기 연결 점검', 'local', ()),
    ('giro', 'giro-login', '간편비밀번호 로그인', 'settings', ('giro.login',)),
    ('giro', 'giro-extend', '로그인 연장', 'settings', ('giro.session.extend',)),
    ('giro', 'giro-live', '세금·공과금 통합·고지·상세 조회', 'work',
     ('giro.bills.list', 'giro.bills.search', 'giro.bills.summary', 'giro.bills.detail')),
    ('giro', 'giro-pay', '등록계좌 선택·단건 세금 납부', 'work', ('giro.payment.options', 'giro.payment.prepare')),
    ('giro', 'giro-accounts', '등록계좌·별칭 조회', 'work', ('giro.accounts.list',)),
    ('giro', 'giro-receipts', '납부내역·상세 조회', 'work', ('giro.receipts.list', 'giro.receipts.detail')),
    ('giro', 'giro-register', 'CLI 기기 등록·보호 자료 설치', 'local', ()),
    ('common', 'credentials', '공동인증서 목록·표시 정보', 'settings', ()),
    ('common', 'certificate-import', '공동인증서 NPKI·PFX 가져오기', 'settings', ('cert.joint.import',)),
    ('common', 'id-cards', '신분증 보관·발급 시 선택', 'settings', ('idcard.add',)),
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
    return {'hana': services['hana']['verification'], 'hana_corporate': 'live_partial',
            'hometax': 'live_verified' if services['hometax'].get('migration_live_tested') else 'live_untested',
            'giro': services['giro']['verification']}


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
                                'reasons': reasons, **(hana_job(adapter.name) if adapter.service == 'hana'
                                                      else giro_job(adapter.name) if adapter.service == 'giro'
                                                      else {'verification': adapter.verification or levels.get(adapter.service)})})
            if reasons:
                row['status'] = 'setup_required'
                row['reasons'] = sorted(set(row['reasons']) | set(reasons))
    service = next((r.service for r in registered if r), {'banking': 'hana', 'tax': 'hometax', 'giro': 'giro'}.get(area))
    row['verification'] = levels.get(service)
    if service == 'hana_corporate':
        row['verification'] = combined_level(j['verification'] for j in row['jobs'])
        row['verification_note'] = '웹 경로는 합성 검증했습니다. ID/PW의 실사용 확인은 기존 CLI 로그인 기록 기준이며 인증서 로그인·이체의 웹 실사용은 미확인입니다.'
    if service == 'giro':
        row['verification'] = combined_level(j['verification'] for j in row['jobs'])
        row['verification_reviewed_at'] = GIRO_REVIEWED_ON
        row['verification_note'] = ' '.join(dict.fromkeys(j['verification_note'] for j in row['jobs']))
    if service == 'hana':
        row['verification'] = (None if placement == 'planned' else 'offline' if placement == 'local' else
                               combined_level(j['verification'] for j in row['jobs']))
        if feature_id in HANA_FEATURE_NOTES:
            row['verification_note'] = HANA_FEATURE_NOTES[feature_id]
            row['verification_reviewed_at'] = REVIEWED_ON
    row['service'] = service
    return row


def global_capabilities():
    levels = verification_levels()
    cache = {}
    return {'features': [feature_state(f, levels, cache) for f in FEATURES], 'verification': levels,
            'verification_reviewed_at': max(REVIEWED_ON, GIRO_REVIEWED_ON),
            'jobs': adapters.names(), 'states': ['available', 'setup_required', 'planned', 'local_only'],
            'readiness': ['ready', 'query_only', 'login_required', 'input_required', 'target_unverified']}


def login_readiness(con, login):
    from . import session_activity
    session = model.current_session(con, login['id'])
    if login['disabled']:
        return 'login_disabled'
    if login['institution'] in session_activity.SERVICES and session is not None \
            and session_activity.metadata(con, session, login['institution'])['idle_expired']:
        return 'login_required'
    if login['institution'] == 'hana' and login['method'] == 'onesign' and session is not None \
            and session['state'] != 'usable' and adapters.get('hana.onesign.accounts').accepts_session(session):
        return 'query_only'
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
        if readiness in ('ready', 'query_only') and target['disabled']:
            readiness = 'target_disabled'
        signing = {p: bool(model.signing_for(con, login, target, p)) for p in ('invoice_sign', 'transfer_sign')}
        rows.append({'target_id': target['id'], 'login_id': login['id'], 'institution': login['institution'],
                     'target_kind': target['kind'], 'readiness': readiness, 'signing_configured': signing,
                     'verified_at': target['verified_at']})
    logins = {r['login_id'] for r in rows}
    return {'profile_id': profile_id, 'targets': rows, 'login_ids': sorted(logins),
            'features': global_capabilities()['features']}
