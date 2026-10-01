"""Offline tools and explicit certificate login over Node HTTP."""

import argparse
import base64
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys

from finance_cli.core.runtime import node_environment
from finance_cli.cli.credentials import add_selection, resolve
from finance_cli.cli.output import ArgumentParser, emit, error, structured

from . import auth
from . import serial
from . import web_auth


def secret_file(path: str, content: dict):
    destination = Path(path)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Never overwrite a saved credential or follow an existing symlink.
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(content, stream, ensure_ascii=False, indent=2)


def prepare(args):
    from finance_cli.credentials.registry import Registry
    from .certificate import SignedCertificate, sign_empty, vid_random
    if args.password_stdin:
        password = sys.stdin.buffer.readline().removesuffix(b"\n").removesuffix(b"\r")
    else:
        password = getpass.getpass("인증서 비밀번호: ").encode("utf-8")
    cert, private, notes = Registry().material(args.credential, password)
    result = SignedCertificate(sign_empty(cert, private), vid_random(private), notes)
    del private
    for warning in result.warnings:
        print("경고: " + warning, file=sys.stderr)
    return result


def read_json(path: str):
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(Path(path).read_text(encoding="utf-8"))


def run_node(adapter, config):
    # Capture only this child process's summary in the opt-in format. The
    # private output file is never opened to manufacture a missing result.
    options = {'stdout': subprocess.PIPE} if structured() else {}
    process = subprocess.run(["node", "--require", str(Path(__file__).with_name("jsdom_compat.cjs")),
                              str(Path(__file__).with_name(adapter))],
                             input=json.dumps(config), text=True, check=False,
                             env=node_environment(), **options)
    if structured():
        try:
            result = json.loads(process.stdout)
        except (ValueError, TypeError):
            emit(None, process.returncode, output_error='invalid_result_json' if process.stdout else 'missing_result_json')
        else:
            emit(result, process.returncode)
    return process.returncode


def main(argv=None) -> int:
    parser = ArgumentParser(
        prog="fin hometax", description="손택스 CLI. 기관 연결에는 fin 명령의 --send가 필요합니다. 공동 인증서 선택은 --credential 별칭.")
    commands = parser.add_subparsers(dest="command", required=True)
    session_parser = commands.add_parser("session", help="저장한 Node 세션 재사용·SSO 재확인; 실제 접속")
    session_commands = session_parser.add_subparsers(dest="operation", required=True)
    for operation, description in (("resume", "저장 쿠키와 storage 복구·서비스 세션 확인"),
                                   ("refresh", "복구 후 서비스 SSO 토큰 재취득·재바인딩")):
        session_command = session_commands.add_parser(operation, help=description)
        session_command.add_argument("--session", required=True, help="Node 로그인 또는 이전 session 명령의 JSON")
        session_command.add_argument("--output", required=True, help="갱신 상태를 저장할 새 파일; 기존 파일 덮어쓰기 없음")
        session_command.add_argument("--timeout", type=float, default=60, help="단계별 관찰 제한 시간(초)")
    for command, operations in (("account", ("show",)), ("business", ("list", "select"))):
        group = commands.add_parser(command, help="현재 사용자·사업장 조회/선택; 실제 접속")
        operation_parsers = group.add_subparsers(dest="operation", required=True)
        for operation in operations:
            item = operation_parsers.add_parser(operation)
            item.add_argument("--session", required=True, help="저장한 Node 세션 JSON")
            item.add_argument("--output", required=True, help="결과 data와 갱신 세션을 저장할 새 0600 JSON")
            item.add_argument("--timeout", type=float, default=60)
            if command == "account":
                item.add_argument("--domain", default="pp", choices=["pp", "ht"], help="포털 pp 또는 조회 업무 ht의 SSO·사용자 확인")
            if command == "business" and operation == "list":
                item.add_argument("--status", help="서비스 상태 선택값: 1 전체, 2 계속사업자(기본), 3 휴업, 4 폐업")
            if command == "business" and operation == "select":
                item.add_argument("--tin", required=True, help="business list의 tin; 개인 복귀는 ORIGIN")
    tax_parser = commands.add_parser("tax", help="세액·납부·환급·고지 조회; 실제 접속")
    tax_operations = tax_parser.add_subparsers(dest="operation", required=True)
    for operation in ("dues", "payments", "refunds", "notices"):
        item = tax_operations.add_parser(operation)
        item.add_argument("--session", required=True)
        item.add_argument("--output", required=True, help="서비스 조회 결과와 갱신 세션을 저장할 새 0600 JSON")
        item.add_argument("--timeout", type=float, default=60)
        item.add_argument("--tin", help="같은 실행에서 선택·확인할 사업장 TIN; 개인은 ORIGIN, 생략 시 현재 세션 대상")
        item.add_argument("--timings", action="store_true", help="요약 JSON에 세션 초기화·사업장 전환·조회 소요 시간 포함")
        if operation != "dues":
            item.add_argument("--from", default=argparse.SUPPRESS, help="조회 시작일; 서비스 기본값 사용 가능")
            item.add_argument("--to", default=argparse.SUPPRESS, help="조회 종료일")
        if operation in ("payments", "refunds"):
            item.add_argument("--page", default=argparse.SUPPRESS, help="서비스 페이지 번호")
            item.add_argument("--all-pages", action="store_true", help="서비스 페이지 흐름으로 전체 조회")
        if operation == "payments":
            item.add_argument("--payment-type", default=argparse.SUPPRESS, help="01 전체(기본), 03 홈택스")
        if operation == "refunds":
            item.add_argument("--refund-status", default=argparse.SUPPRESS, help="빈 문자열 전체, 1 지급완료, 2 미수령, 3 1년경과 미수령")
        if operation == "notices":
            item.add_argument("--notice-type", default=argparse.SUPPRESS, help="01 고지서, 02 독촉장")
            item.add_argument("--read-status", default=argparse.SUPPRESS, help="all 전체, 01 열람, 02 미열람(기본)")
            item.add_argument("--tax-code", default=argparse.SUPPRESS, help="서비스 세목 코드")
    returns_parser = commands.add_parser("returns", help="신고내역·접수 상태·제출서식 조회; 실제 접속")
    returns_operations = returns_parser.add_subparsers(dest="operation", required=True)
    for operation in ("list", "status", "forms", "receipt", "document"):
        item = returns_operations.add_parser(operation)
        item.add_argument("--session", required=True)
        item.add_argument("--output", required=True, help="새 저장 경로; receipt/document는 디렉터리, 나머지는 JSON")
        item.add_argument("--timeout", type=float, default=60)
        item.add_argument("--tax-code", help="서비스 세목 코드; list/forms 생략 시 종합소득세 메뉴")
        item.add_argument("--taxpayer", help="서비스 납세자 선택값(TIN/사업자번호); 생략 시 서비스 기본 선택")
        item.add_argument("--page", default=argparse.SUPPRESS, help="서비스 페이지 번호; 신고내역은 한 페이지에 한 건")
        if operation in ("list", "status"):
            item.add_argument("--all-pages", action="store_true")
        else:
            item.add_argument("--return-id", help="조회 결과의 rtnCvaId; 서비스 페이지를 찾아 해당 신고의 서식 조회")
        if operation in ("forms", "receipt", "document"):
            item.add_argument("--query-source", choices=["list", "status"], default="list", help="신고내역 또는 납세자 기준 월별 접수 결과")
        if operation != "list":
            item.add_argument("--year", help="접수 연도; 서비스 선택 목록 사용")
            item.add_argument("--month", help="접수 월; 생략 시 현재 월")
        if operation != "status":
            item.add_argument("--from", default=argparse.SUPPRESS)
            item.add_argument("--to", default=argparse.SUPPRESS)
            item.add_argument("--department-user", help="서비스 부서사용자 ID 조회 조건")
            item.add_argument("--disclose", help="서비스 개인정보 공개 선택 Y/N; 생략 시 해당 화면의 기본값")
        if operation == "document":
            selection = item.add_mutually_exclusive_group()
            selection.add_argument("--form-code", help="서비스 화면에 표시된 서식 코드 선택")
            selection.add_argument("--all-forms", action="store_true", help="서비스 화면의 모든 서식과 자료 묶음 저장")
    invoice_parser = commands.add_parser("invoice", help="전자(세금)계산서 조회·초안·발급; 실제 접속")
    invoice_operations = invoice_parser.add_subparsers(dest="operation", required=True)
    issue = invoice_operations.add_parser("issue", help="검토한 일반·수정 초안을 실제 발급; 서비스 완료 흐름 사용")
    issue.add_argument("--prepared", required=True, help="invoice prepare/amend의 결과 JSON; 초안당 1회 실행")
    issue.add_argument("--session", help="갱신 세션; 생략하면 --prepared의 세션 재사용")
    issue.add_argument("--output", required=True)
    issue.add_argument("--timeout", type=float, default=60)
    add_selection(issue)
    for operation in ("list", "detail", "prepare", "amend"):
        item = invoice_operations.add_parser(operation)
        item.add_argument("--session", required=True)
        item.add_argument("--output", required=True, help="서비스 결과와 갱신 세션을 저장할 새 0600 JSON")
        item.add_argument("--timeout", type=float, default=60)
        if operation == "amend":
            item.add_argument("--approval-number", required=True, help="수정할 수정 대상 승인번호")
            item.add_argument("--reason", required=True, help="correction(01), amount-change(02), return(03), cancellation(04), local-credit(05), duplicate(06)")
            item.add_argument("--input", help="변경할 내용 JSON; 서비스 수정 미리보기까지 준비하며 발급하지 않음")
        elif operation == "prepare":
            item.add_argument("--input", required=True, help="일반 과세·사업자 거래의 초안 JSON; 서비스 미리보기까지 입력, 발급하지 않음")
        elif operation == "detail":
            item.add_argument("--approval-number", required=True, help="수정 대상 승인번호 24자리")
        else:
            item.add_argument("--direction", help="sales 매출(기본), purchases 매입; 서비스 코드도 허용")
            item.add_argument("--from", default=argparse.SUPPRESS)
            item.add_argument("--to", default=argparse.SUPPRESS)
            item.add_argument("--date-type", help="서비스 조회일자 구분")
            item.add_argument("--invoice-type", help="01 전자세금계산서(기본), 03 전자계산서")
            item.add_argument("--classification", help="all 전체(기본), 01/02 세금계산서/수정, 03/04 계산서/수정")
            item.add_argument("--kind", help="all 전체(기본), 01 일반, 02 영세율 등 서비스 코드")
            item.add_argument("--issuance-type", help="서비스 발급유형 코드; all 기본")
            item.add_argument("--counterparty-type", help="01 사업자(기본), 02 개인, 03 외국인")
            item.add_argument("--counterparty-number")
            item.add_argument("--counterparty-name")
            item.add_argument("--branch-number")
            item.add_argument("--page", default=argparse.SUPPRESS)
            item.add_argument("--all-pages", action="store_true")
    report_parser = commands.add_parser("report", help="확보한 서비스 보고서를 독립 HTML/SVG로 저장; 실제 접속")
    report_operations = report_parser.add_subparsers(dest="operation", required=True)
    report_save = report_operations.add_parser("save")
    report_save.add_argument("--capture", required=True, help="서비스 보고서 화면 확보의 capture.json")
    report_save.add_argument("--output", required=True, help="보고서와 갱신 상태를 저장할 소유자만 접근할 새 디렉터리")
    report_save.add_argument("--timeout", type=float, default=60)
    auth_parser = commands.add_parser("auth", help="정적으로 확인된 인증 부분 기능")
    subcommands = auth_parser.add_subparsers(dest="operation", required=True)
    replay = subcommands.add_parser("replay", help="디코딩된 응답 또는 SDK 콜백의 서비스 분기 재현")
    replay.add_argument("flow", choices=["cert-register", "cert-login", "logout", "qr-confirm", "fido-auth"])
    replay.add_argument("--input", default="-", help="JSON 파일 경로; 기본값은 stdin")
    callback = subcommands.add_parser("encode-cert-callback", help="SDK Base64 출력 문자열의 콜백 인코딩")
    callback.add_argument("--input", default="-", help="signDataBase64, vidRandomBase64를 담은 JSON")
    context = subcommands.add_parser("fido-context", help="FIDO SDK에 전달할 context 구성")
    context.add_argument("--input", default="-", help="authCode, deviceModel, androidRelease를 담은 JSON")
    request = subcommands.add_parser("cert-request", help="보안 스크립트 처리 전의 논리 요청 구성; 접속 없음")
    request.add_argument("--input", default="-", help="signDataBase64, vidRandomBase64 JSON")
    for name, description in (("prepare-cert", "인증서 복호화·서명 및 요청 파일 생성; 접속 없음"),
                              ("login-cert", "서비스 웹 페이지와 연결한 실제 공동인증서 로그인")):
        cert_command = subcommands.add_parser(name, help=description)
        add_selection(cert_command)
        cert_command.add_argument("--app-version", default="14.3")
        cert_command.add_argument("--output", required=True, help="새 private/ 파일 경로; 기존 파일 덮어쓰기 없음")
        if name == "login-cert":
            cert_command.add_argument("--timeout", type=float, default=180, help="페이지 초기화·대기열 관찰 시간(초)")
    args = parser.parse_args(argv)
    try:
        return run(args)
    except BlockingIOError:
        return error('resource_busy', '다른 홈택스 작업이 실행 중입니다. 끝난 뒤 다시 실행하세요.')
    except ImportError:
        return error('dependency_unavailable', '필요한 실행 의존성을 확인하세요. 설치 안내와 fin runtime status hometax를 참고하세요.')
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        # Never include input values, tokens or credentials in error logs.
        if type(exc).__module__ == "hometax_cli.certificate":
            # CertificateError messages are static, written by this module;
            # third-party parser exceptions must never be echoed.
            return error('certificate_error', str(exc))
        else:
            return error('local_input_or_processing_error', '로컬 입력을 읽거나 변환할 수 없습니다. 명령의 입력 형식을 확인하세요.')


def run(args):
    if getattr(args, 'profile', None):
        args.credential = resolve(args, 'hometax')
    if args.command in ("session", "account", "business", "tax", "returns", "report", "invoice"):
        Path(args.output).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        config = {key: value for key, value in vars(args).items() if value is not None and key != 'profile'}
        if args.command == "tax" and args.tin is not None:
            config["target"] = {"tin": config.pop("tin"), "kind": "personal" if args.tin == "ORIGIN" else "business"}
        if args.command == "invoice" and args.operation == "issue":
            config["session"] = args.session or args.prepared
            password = (sys.stdin.buffer.readline().removesuffix(b"\n").removesuffix(b"\r")
                        if args.password_stdin else getpass.getpass("발급용 인증서 비밀번호: ").encode())
            config["password"] = base64.b64encode(password).decode("ascii")
        adapter = "session.mjs" if args.command == "session" else "report.mjs" if args.command == "report" else "business.mjs"
        if args.command == "returns" and args.operation in ("receipt", "document"):
            adapter = "returns_report.mjs"
        with serial.operation():
            return run_node(adapter, config)
    if args.operation in ("prepare-cert", "login-cert"):
        if Path(args.output).exists():
            raise ValueError("Output already exists")
        result = prepare(args)
        callback = result.callback()
        if args.operation == "prepare-cert":
            request = web_auth.certificate_request(
                base64.b64encode(result.signed_data).decode("ascii"),
                base64.b64encode(result.random).decode("ascii"), args.app_version)
            secret_file(args.output, {"callback": callback, "logical_request": request})
            emit({"scope": "offline_certificate_prepare", "prepared": True,
                  "output": args.output, "network_requests": 0}, indent=None)
            return 0
        Path(args.output).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        config = {"callback": callback, "appVersion": args.app_version,
                  "output": args.output, "timeout": args.timeout}
        with serial.operation():
            return run_node('browserless.mjs', config)
    data = read_json(args.input)
    if args.operation == "encode-cert-callback":
        output = auth.certificate_callback(data["signDataBase64"], data["vidRandomBase64"])
    elif args.operation == "fido-context":
        output = {"scope": "fido_sdk_context", "context": auth.fido_context(
            data["authCode"], data["deviceModel"], data["androidRelease"], data.get("policyId"))}
    elif args.operation == "cert-request":
        output = web_auth.certificate_request(data["signDataBase64"], data["vidRandomBase64"],
                                             data.get("appVersion", "14.3"),
                                             data.get("osNm", "Android"), data.get("departmentId"))
    else:
        if args.flow == "cert-register":
            decision = auth.certificate_registration(data)
        elif args.flow == "cert-login":
            decision = web_auth.certificate_login(data)
        elif args.flow == "qr-confirm":
            decision = auth.qr_confirmation(data)
        elif args.flow == "logout":
            if not isinstance(data, list):
                raise ValueError("로그아웃 입력은 서비스 도메인 순서의 응답 배열이어야 합니다.")
            decision = auth.logout(data)
        else:
            decision = auth.fido_auth_callback(
                data.get("original", {}), data["requestCode"], data["errorCode"],
                data.get("description"), data.get("token"))
        for warning in decision.warnings:
            print("경고: " + warning, file=sys.stderr)
        code = 1 if decision.branch == "failure" else 0
        emit(decision.as_dict(), code, indent=None)
        return code
    emit(output, indent=None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
