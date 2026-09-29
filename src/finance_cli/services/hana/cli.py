"""The migrated Hana interface: offline contracts and shared certificate signing."""
import argparse
import base64
import getpass
import json
from pathlib import Path
import sys

from . import hana_protocol as protocol


def main(argv=None):
    parser = argparse.ArgumentParser(prog='fin hana', description='하나은행 오프라인 계약·서명. 기존 업무 실행기는 연구 기준본에 보존됩니다.')
    sub = parser.add_subparsers(dest='operation', required=True)
    sub.add_parser('plan', help='로그인 계약과 공개 패키지 이전 범위; 접속 없음')
    for command in ('encode-header', 'decode-header', 'joint-cert-tbs', 'joint-cert-body', 'login-body'):
        sub.add_parser(command, help='표준입력으로 받은 로컬 자료 변환; 접속 없음')
    sign = sub.add_parser('sign-login', help='공통 저장소의 인증서로 주어진 nonce 서명; 로그인 전송 없음')
    selection = sign.add_mutually_exclusive_group(required=True)
    selection.add_argument('--credential')
    selection.add_argument('--profile')
    sign.add_argument('--nonce', required=True, help='사용자가 확보한 서버 nonce; 자동 취득하지 않음')
    sign.add_argument('--output', required=True)
    sign.add_argument('--password-stdin', action='store_true')
    args = parser.parse_args(argv)
    if args.operation == 'plan':
        result = protocol.auth_plan()
        result['migration'] = {'network_execution': False, 'shared_credentials': True,
            'remaining': ['source-bound session/transfer/issuance workflows', 'institution configuration and terms resources']}
    elif args.operation == 'decode-header':
        result = protocol.decode_header(sys.stdin.read())
    elif args.operation == 'sign-login':
        from finance_cli.credentials.registry import Registry
        from finance_cli.credentials.joint import cms
        from finance_cli.core.storage import write_new
        from Crypto.PublicKey import RSA
        password = (sys.stdin.buffer.readline().rstrip(b'\r\n') if args.password_stdin
                    else getpass.getpass('인증서 비밀번호: ').encode())
        if args.profile:
            from finance_cli.core.profiles import resolve
            args.credential = resolve(args.profile, 'hana')
        cert, private, _ = Registry().material(args.credential, password)
        signature = cms.sign_cms(cert, RSA.import_key(private), protocol.joint_cert_tbs(args.nonce).encode())
        write_new(Path(args.output), signature)
        result = {'signed': True, 'output': args.output, 'network_used': False, 'bank_accepted': None}
    else:
        value = json.load(sys.stdin)
        functions = {'encode-header': protocol.encode_header, 'joint-cert-body': protocol.joint_cert_body,
                     'login-body': protocol.login_body, 'joint-cert-tbs': lambda v: protocol.joint_cert_tbs(v['nnce'])}
        result = functions[args.operation](value)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0
