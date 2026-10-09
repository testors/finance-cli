"""JSON CLI; explicit --send/--live for institution operations."""
from datetime import date, datetime
import getpass
from pathlib import Path
import sys
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from finance_cli.cli.output import ArgumentParser, emit

from .bills import TAX_TYPES, due_bills, normalize_detail, normalize_pages
from .compat import loads
from .errors import GiroError, ResponseError
from .protocol import ENDPOINTS, auth_plan, request_plan


def _load(path):
    try:
        text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
        return loads(text)
    except (OSError, UnicodeError, ValueError):
        raise GiroError("UTF-8 JSON 입력을 읽을 수 없습니다.") from None


def parser():
    root = ArgumentParser(prog='fin giro', description="모바일지로 CLI (기본 무통신; 실제 업무는 명시적 --send/--live)")
    sub = root.add_subparsers(dest="command", required=True)
    runtime = sub.add_parser("runtime", help="서버 배포용 로컬 점검; 기기 보안 검사/통신 아님")
    runtime.add_subparsers(dest="action", required=True).add_parser("check", help="패키지 리소스·합성 암호·문자셋·시간대 점검")
    api = sub.add_parser("api", help="인증·조회·납부 요청 모델 목록; 통신 없음")
    api.add_subparsers(dest="action", required=True).add_parser("list")
    session = sub.add_parser('session', help='저장된 로그인 연장 요청')
    item = session.add_subparsers(dest='action', required=True).add_parser(
        'extend', aliases=['keepalive'], help='등록계좌 조회 1회로 로그인 연장; 계좌 정보는 출력하지 않음')
    item.add_argument('--send', '--live', dest='live', action='store_true')
    auth = sub.add_parser("auth", help="인증 순서 또는 로컬 PIN 코덱")
    auth_sub = auth.add_subparsers(dest="action", required=True)
    auth_sub.add_parser("plan", help="확인된 인증 흐름과 미해결 항목")
    auth_sub.add_parser('registration-plan', help='기존 개인 회원 신규 기기 등록 순서·입력·검증 범위; 무통신')
    for action in ('login', 'register'):
        item = auth_sub.add_parser(action, help='PIN 로그인' if action == 'login' else '기존 개인 회원의 CLI 기기 등록 후 로그인')
        item.add_argument('--live', '--send', dest='live', action='store_true', help='명시한 인증 요청 실행; 기본은 무통신 계획')
        item.add_argument('--protection-profile', help='설치된 기본 자료 대신 사용할 보호 입력 자료')
        item.add_argument('--public-cache', help='수신자 인증서·CRL의 공개 자료 캐시')
        if action == 'register':
            item.add_argument('--carrier', choices=('SKT', 'SKM', 'LGT', 'LGM'))
            item.add_argument('--retry', action='store_true', help='초기 조회·SMS 요청 실패·등록 동의 전 종료 기록을 보존하고 같은 기기로 다시 시작')
    install = auth_sub.add_parser('install-profile', help='개인 보호 입력 자료 설치; 기관 통신 없음')
    install.add_argument('--input', required=True)
    trust = auth_sub.add_parser('prepare-trust', help='고정 해시의 공개 루트 2개 준비; 기본은 무통신 계획')
    trust.add_argument('--cache', help='명시적인 기존 절대경로 디렉터리; 공개 인증서·폐지목록 전용')
    trust.add_argument('--live', '--send', dest='live', action='store_true',
                       help='캐시에 없는 공개 루트만 LDAP 조회; 최대 2회, 로그인·PIN 없음')
    bootstrap = auth_sub.add_parser("bootstrap", help="PIN 없는 공개 서버 인증서 조회; 기본은 계획만 출력")
    bootstrap.add_argument("--live", action="store_true", help="고정 HTTPS 경로에 단발 POST; 응답 전문/쿠키 저장 안 함")
    cg_probe=auth_sub.add_parser('codeguard-bootstrap',help='PIN 없는 CMD101 단발 검사; 기본 계획만, CMD200/300 없음')
    cg_probe.add_argument('--abi',required=True,choices=('arm64-v8a','armeabi-v7a','armeabi'),help='접속에 사용할 ABI; 서버 CPU와 독립적으로 지정')
    cg_probe.add_argument('--live',action='store_true',help='고정 HTTPS 경로에 CMD101 GET 1회')
    cg_challenge=auth_sub.add_parser('codeguard-challenge',help='PIN 없는 CMD101→200 검사; 기본 계획만, CMD300 없음')
    cg_challenge.add_argument('--abi',required=True,choices=('arm64-v8a','armeabi-v7a','armeabi'),help='접속에 사용할 ABI; 서버 CPU와 독립적으로 지정')
    cg_challenge.add_argument('--live',action='store_true',help='별도 승인 필요: CMD101 1회 후 CMD200 1회, 최대 GET 2회')
    cg_challenge.add_argument('--inspect-material',action='store_true',help='추가 요청 없이 쿠키 값/세 번째 인증서/규칙 계획의 메모리 내 진단')
    cg_challenge.add_argument('--locale',help='material 쿠키 처리에 필요한 명시적 Android 기본 locale 언어 (예: ko)')
    rule = auth_sub.add_parser("inspect-rule", help="로컬 CodeGuard 규칙 복호화·연산 계획; 입력값/응답/토큰 출력 안 함")
    rule.add_argument("--input", required=True, help="encoded_rule/encoded_challenge/app_info/version JSON 또는 -")
    nonce = auth_sub.add_parser("inspect-nonce", help="로컬 nonce 산술 검사; 키/입력 digest/결과 출력 안 함")
    nonce.add_argument("--input", required=True, help="key_hex/codes(문자열/null 배열) JSON 또는 -")
    cert = auth_sub.add_parser("inspect-cert", help="로컬 수신자 인증서 선택·용도 부분검사; 신뢰 검증 아님")
    cert.add_argument("--input", required=True, help="사용자가 준비한 공개 DER/PEM/CMS 파일; 원문 출력 안 함")
    crl = auth_sub.add_parser('inspect-crl', help='로컬 발급자·서명·CRL 후보 부분검사; 전체 신뢰/폐지 검증 아님')
    crl.add_argument('--target', required=True, help='대상 공개 인증서 DER/PEM/CMS')
    crl.add_argument('--issuer', required=True, help='발급자 후보 공개 인증서 DER/PEM/CMS')
    crl.add_argument('--crl', required=True, help='공개 CRL DER 파일')
    crl.add_argument('--at', required=True, type=datetime.fromisoformat, help='명시적 시간대가 있는 검사 시각 ISO 8601')
    crl.add_argument('--locale', required=True, help='대상 Android 기본 locale 언어, 예: ko')
    path = auth_sub.add_parser('inspect-path', help='공개 인증서/CRL 경로의 오프라인 규칙 재생; 신뢰 자동 취득/설치 아님')
    path.add_argument('--input', required=True, help='path/trust_anchor/crls/at/locale를 담은 로컬 JSON manifest 또는 -')
    recipient = auth_sub.add_parser('inspect-recipient', help='명시적 공개 자료에서 발급자 탐색·필수 경로/CRL 검사; 접속/쓰기 없음')
    recipient.add_argument('--input', required=True, help='대상 공개 인증서 DER/PEM/CMS')
    recipient.add_argument('--trust-anchor', action='append', required=True, help='명시적 공개 신뢰 앵커; 반복 가능')
    recipient.add_argument('--issuer', action='append', default=[], help='공개 발급자 후보; 반복 가능')
    recipient.add_argument('--crl', action='append', default=[], help='공개 CRL DER; 반복 가능')
    recipient.add_argument('--at', required=True, type=datetime.fromisoformat, help='시간대가 있는 검사 시각')
    recipient.add_argument('--locale', required=True, help='대상 Android locale 언어')
    ctl = auth_sub.add_parser('inspect-ctl', help='로컬 공개 CTL의 서명·포함 여부 검사; 신뢰 설치/로그인 아님')
    ctl.add_argument('--input', required=True, help='공개 CMS SignedData CTL 파일')
    ctl.add_argument('--target', required=True, help='CTL에서 찾을 공개 인증서 파일')
    ctl.add_argument('--trust-anchor', action='append', required=True, help='명시적 공개 신뢰 앵커 인증서; 반복 가능')
    ctl.add_argument('--at', required=True, type=datetime.fromisoformat, help='시간대가 있는 검사 시각')
    ctl.add_argument('--locale', required=True, help='대상 Android locale 언어')
    ldap = auth_sub.add_parser('inspect-ldap', help='로컬 공개 LDAP 응답 바이트 재생; 접속/신뢰 설치 안 함')
    ldap.add_argument('--input', required=True, help='bind/첫 검색 결과/완료 응답을 이어 붙인 로컬 바이너리 파일')
    ldap.add_argument('--uri', required=True, help='인증서의 LDAP URI; 파싱 문맥만 제공하며 접속하지 않음')
    ldap.add_argument('--message-id', required=True, type=int, help='재생할 최초 요청 message ID')
    ldap.add_argument('--locale', required=True, help='대상 Android locale 언어, 예: ko')
    pin = auth_sub.add_parser("encode-pin", help="테스트용 로컬 변환; 로그인 아님, PIN을 인자로 받지 않음")
    pin.add_argument("--key-file", required=True, help="사용자가 제공한 16바이트 키의 32자리 hex 파일")
    request = sub.add_parser("request", help="오프라인 요청 스키마")
    request.add_argument("endpoint", choices=tuple(ENDPOINTS))
    accounts = sub.add_parser('accounts', help='등록계좌 조회 또는 로컬 납부 가능 계좌 응답 해석')
    accounts_sub = accounts.add_subparsers(dest='action', required=True)
    account_list = accounts_sub.add_parser('list')
    account_source = account_list.add_mutually_exclusive_group()
    account_source.add_argument('--input', help='로컬 납부 가능 계좌 응답 JSON 파일 또는 -')
    account_source.add_argument('--live', '--send', dest='live', action='store_true')
    receipts = sub.add_parser('receipts', help='저장된 세션으로 납부내역 조회; 재납부·취소 없음')
    receipt_sub = receipts.add_subparsers(dest='action', required=True)
    receipt_list = receipt_sub.add_parser('list')
    receipt_list.add_argument('--start-date', type=date.fromisoformat, required=True)
    receipt_list.add_argument('--end-date', type=date.fromisoformat, required=True)
    receipt_list.add_argument('--page', type=int, default=1)
    receipt_list.add_argument('--live', '--send', dest='live', action='store_true')
    receipt_show = receipt_sub.add_parser('show', help='납부내역 목록에서 선택한 영수증 상세 조회')
    receipt_show.add_argument('--input', help='목록 항목의 identifiers 객체를 담은 JSON 파일 또는 -')
    receipt_show.add_argument('--live', '--send', dest='live', action='store_true')
    payment = sub.add_parser('payment', help='납부 준비·등록계좌 단건 납부·결과 해석')
    payment_sub = payment.add_subparsers(dest='action', required=True)
    payment_sub.add_parser('plan', help='등록계좌·홈택스 연계 납부의 지원 범위')
    for action in ('prepare', 'pay'):
        pay = payment_sub.add_parser(action, help='고지·계좌·금액 확인까지만 조회' if action == 'prepare'
                                     else '고지 조회 후 계좌·금액 확인 및 단건 납부')
        pay.add_argument('--type', choices=TAX_TYPES, default='national')
        pay.add_argument('--live', '--send', dest='live', action='store_true')
        pay.add_argument('--amount', help='금액 변경이 가능한 고지에만 적용할 납부액')
    payment_result = payment_sub.add_parser('result', help='복호화된 납부 응답의 판정; 추가 조회 없음')
    payment_result.add_argument('--type', choices=(*TAX_TYPES, 'hometax'), required=True)
    payment_result.add_argument('--input', required=True, help='납부 응답 JSON 파일 또는 -')
    bills = sub.add_parser("bills", help="복호화된 로컬 JSON에서 고지/기한 읽기")
    bill_sub = bills.add_subparsers(dest="action", required=True)
    for action in ("list", "due", "show"):
        item = bill_sub.add_parser(action)
        item.add_argument("--type", choices=TAX_TYPES, required=True)
        item.add_argument("--input", required=action == 'show', help="로컬 JSON 파일 또는 표준입력(-)")
        if action != 'show':
            item.add_argument('--live', '--send', dest='live', action='store_true', help='저장된 로그인으로 본인 고지 조회')
        if action == "due":
            item.add_argument("--within-days", type=int, default=7)
            item.add_argument("--today", type=date.fromisoformat, help="기준일 YYYY-MM-DD; 기본 Asia/Seoul")
            item.add_argument("--include-overdue", action="store_true")
    return root


def run(args):
    if args.command == 'session':
        from .session import extend
        result = extend(send=args.live)
        code = 130 if result.get('error') == 'interrupted' else 0 if result.get('plan_only') or result.get('app_success') else 2
        return result, code
    if args.command == "runtime":
        from .runtime import check_runtime
        # Deployment diagnostics, never an application/authentication verdict.
        return check_runtime(), 0
    if args.command == "api":
        return {"offline": True, "endpoints": [ep.describe() for ep in ENDPOINTS.values()]}, 0
    if args.command == "request":
        return request_plan(args.endpoint), 0
    if args.command == 'accounts':
        if args.input is not None:
            from .payment import account_options
            result = account_options(_load(args.input))
        else:
            from .query_flow import registered_accounts
            result = registered_accounts(send=args.live)
        return result, 0 if result.get('plan_only') or result.get('app_success') else 2
    if args.command == 'receipts':
        from .query_flow import list_receipts, receipt_detail
        if args.action == 'show':
            if args.live and args.input is None:
                raise GiroError('--send에는 목록 항목의 identifiers를 담은 --input이 필요합니다.')
            result = receipt_detail(_load(args.input) if args.live else None, send=args.live)
        else:
            result = list_receipts(args.start_date, args.end_date, page=args.page, send=args.live)
        return result, 0 if result.get('plan_only') or result.get('app_success') else 2
    if args.command == 'payment':
        if args.action in ('prepare', 'pay'):
            from .payment_cli import run_payment
            return run_payment(args)
        from .payment import payment_plan, payment_result
        if args.action == 'plan':
            return payment_plan(), 0
        from .response import receive
        # Keep duplicate JSON members intact for Gson-compatible decoding.
        try:
            body = sys.stdin.read() if args.input == '-' else Path(args.input).read_text(encoding='utf-8')
        except (OSError, UnicodeError):
            raise GiroError('UTF-8 JSON 입력을 읽을 수 없습니다.') from None
        received = receive(args.type + '.payment', 200, (), body)
        result = payment_result(received)
        result.update(offline=True, network_used=False, source='local-decoded-response')
        return result, 0 if received.app_success else 2
    if args.command == "auth":
        if args.action == "plan":
            return auth_plan(), 0
        if args.action == 'registration-plan':
            from .registration_flow import registration_plan
            return registration_plan(), 0
        if args.action in ('login', 'register', 'install-profile'):
            from .auth_cli import run_auth
            return run_auth(args)
        if args.action == 'prepare-trust':
            from .recipient_trust import prepare_trust
            result = prepare_trust(args.cache, send=args.live)
            return result, 2 if result['processing_issues'] else 0
        if args.action == "bootstrap":
            from .bootstrap import plan, probe_server_cert
            result = probe_server_cert() if args.live else plan()
            return result, 2 if result['app_success'] is False else 0
        if args.action=='codeguard-bootstrap':
            from .codeguard_probe import plan,probe_cmd101
            return (probe_cmd101(args.abi) if args.live else plan(args.abi)),0
        if args.action=='codeguard-challenge':
            from .codeguard_challenge_probe import plan,probe_challenge
            if args.inspect_material:
                options=dict(inspect_material=True,locale_language=args.locale)
                return (probe_challenge(args.abi,**options) if args.live else plan(args.abi,**options)),0
            return (probe_challenge(args.abi) if args.live else plan(args.abi)),0
        if args.action == "inspect-rule":
            from .codeguard_codec import derive_rule_plan
            from .codeguard_rule import AnalysisLimit, NativeRuleError
            document = _load(args.input)
            fields = ('encoded_rule', 'encoded_challenge', 'app_info', 'version')
            if not isinstance(document, dict) or any(document.get(k) is not None and not isinstance(document[k], str) for k in fields):
                raise GiroError("로컬 규칙 입력은 문자열/null 필드로 이루어진 JSON 객체여야 합니다.")
            result = {'offline': True, 'live_login_ready': False, 'server_token_generated': False,
                      'analysis_status': 'rule_plan_only'}
            try:
                plan = derive_rule_plan(*(document.get(k) for k in fields))
                result['plan'] = plan.describe()
                return result, 0
            except NativeRuleError as exc:
                return {**result, 'analysis_status': 'native_stage_error', 'native_code': exc.native_code}, 2
            except AnalysisLimit:
                return {**result, 'analysis_status': 'unmodeled_memory_boundary'}, 0
        if args.action == "inspect-nonce":
            from .codeguard_codec import jni_modified_utf8
            from .codeguard_nonce import cg_auth_code
            from .codeguard_rule import AnalysisLimit
            document = _load(args.input)
            if (not isinstance(document, dict) or not isinstance(document.get('codes'), list)
                    or any(v is not None and type(v) is not str for v in [document.get('key_hex'), *document['codes']])):
                raise GiroError('로컬 nonce 입력은 key_hex(문자열/null), codes(문자열/null 배열) 객체여야 합니다.')
            result = {'offline': True, 'network_attempted': False, 'live_login_ready': False,
                      'server_token_generated': False, 'input_collection_implemented': False}
            try:
                cg_auth_code(jni_modified_utf8(document.get('key_hex')),
                             [jni_modified_utf8(v) for v in document['codes']])
                return {**result, 'analysis_status': 'arithmetic_completed', 'digest_inputs_consumed': 6,
                        'dispatch_functions_implemented': 100}, 0
            except AnalysisLimit:
                return {**result, 'analysis_status': 'unmodeled_memory_boundary'}, 0
        if args.action == "inspect-cert":
            from .cert_factory import inspect_recipient, CertificateBackendLimit
            try:
                data = Path(args.input).read_bytes()
            except OSError:
                raise GiroError("인증서 입력 파일을 읽을 수 없습니다.") from None
            try:
                return inspect_recipient(data), 0
            except CertificateBackendLimit as exc:
                return {"offline": True, "analysis_status": "unmodeled", "message": str(exc),
                        "certificate_validation_performed": False, "live_login_ready": False}, 0
        if args.action == 'inspect-crl':
            from .cert_crl import inspect_crl_candidate
            if args.at.tzinfo is None:
                raise GiroError('검사 시각에는 시간대가 필요합니다. 예: 2026-09-28T12:00:00+09:00')
            try:
                materials = [Path(path).read_bytes() for path in (args.target,args.issuer,args.crl)]
            except OSError:
                raise GiroError('공개 인증서/CRL 입력 파일을 읽을 수 없습니다.') from None
            return inspect_crl_candidate(*materials,at=args.at,locale_language=args.locale), 0
        if args.action == 'inspect-path':
            from .cert_path import inspect_path_manifest
            return inspect_path_manifest(_load(args.input)), 0
        if args.action == 'inspect-recipient':
            from .cert_pipeline import inspect_recipient_material
            if args.at.tzinfo is None: raise GiroError('검사 시각에는 시간대가 필요합니다.')
            try:
                target=Path(args.input).read_bytes()
                anchors=[Path(path).read_bytes() for path in args.trust_anchor]
                issuers=[Path(path).read_bytes() for path in args.issuer]
                crls=[Path(path).read_bytes() for path in args.crl]
            except OSError:
                raise GiroError('공개 인증서/CRL 입력 파일을 읽을 수 없습니다.') from None
            return inspect_recipient_material(target,anchors,issuers,crls,at=args.at,locale_language=args.locale), 0
        if args.action == 'inspect-ctl':
            from .cert_ctl import inspect_ctl_candidate
            if args.at.tzinfo is None: raise GiroError('검사 시각에는 시간대가 필요합니다.')
            try:
                data,target = Path(args.input).read_bytes(),Path(args.target).read_bytes()
                anchors = [Path(path).read_bytes() for path in args.trust_anchor]
            except OSError:
                raise GiroError('공개 CTL/인증서 입력 파일을 읽을 수 없습니다.') from None
            return inspect_ctl_candidate(data,target,anchors,at=args.at,locale_language=args.locale), 0
        if args.action == 'inspect-ldap':
            from .ldap_codec import inspect_responses
            try: data = Path(args.input).read_bytes()
            except OSError: raise GiroError('공개 LDAP 응답 파일을 읽을 수 없습니다.') from None
            return inspect_responses(data,args.uri,message_id=args.message_id,locale_language=args.locale), 0
        if not sys.stdin.isatty():
            raise GiroError("PIN 입력은 에코 없는 대화형 터미널에서만 받습니다. 자동화 테스트는 Python 코덱을 사용하세요.")
        from .crypto import encode_pin
        try:
            raw_key = Path(args.key_file).read_text(encoding="ascii").strip()
            if len(raw_key) != 32:
                raise ValueError()
            key = bytes.fromhex(raw_key)
        except (OSError, ValueError, UnicodeError):
            raise GiroError("키 파일은 16바이트 키를 나타내는 32자리 hex여야 합니다.") from None
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            try:
                pin = getpass.getpass("테스트용 간편비밀번호 (6자리): ")
            except (getpass.GetPassWarning, EOFError):
                raise GiroError("안전한 PIN 입력 터미널을 열 수 없습니다.") from None
        cipher = encode_pin(pin, key)
        return {"offline": True, "live_login_verified": False, "pin_ciphertext": cipher}, 0
    if args.input is not None:
        if getattr(args, 'live', False): raise GiroError('--input과 --send는 함께 사용할 수 없습니다.')
        document = _load(args.input)
        if args.action == 'show': return normalize_detail(document, args.type), 0
        result = normalize_pages(document, args.type)
    else:
        from .query_flow import list_bills
        result = list_bills(args.type, send=args.live)
        if result.get('plan_only'): return result, 0
        if not result.get('app_success'): return result, 2 if result.get('app_success') is False else 4
    if args.action == "due":
        try:
            today = args.today or datetime.now(ZoneInfo("Asia/Seoul")).date()
        except ZoneInfoNotFoundError:
            return {**result, "as_of": None, "through": None,
                    "include_overdue": args.include_overdue, "bills": None,
                    "unfiltered_bills": result["bills"], "filter_applied": False,
                    "filter_complete": False,
                    "issues": result["issues"] + [
                        "Asia/Seoul 시간대 자료 없음: 기한 필터 미수행; "
                        "unfiltered_bills에 받은 목록 보존. tzdata 설치 또는 --today 지정 필요"]}, 0
        result = due_bills(result, today=today, within_days=args.within_days, include_overdue=args.include_overdue)
        return result, 0
    return result, 0


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        result, status = run(args)
    except ResponseError as exc:
        result, status = {"error": "response_error", "app_success": False,
                          "response_code": exc.code, "callback_code": exc.callback_code,
                          "error_info": exc.error_info, "origin": exc.origin, "message": str(exc)}, 2
    except GiroError as exc:
        result, status = {"error": "validation_error", "message": str(exc)}, 2
    emit(result, status)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
