"""``fin server``: local management of the web server. Never contacts an institution."""
import sys

from finance_cli.cli.output import ArgumentParser, emit


def parser():
    root = ArgumentParser(prog='fin server', description='웹앱 서버 관리; 루프백 바인딩, 기관 통신 없음')
    sub = root.add_subparsers(dest='action', required=True)
    item = sub.add_parser('config', help='공개 출처·포트·접속 만료 설정 저장')
    item.add_argument('--public-origin', help='브라우저가 여는 주소; 원격은 https (Caddy 프록시)')
    item.add_argument('--port', type=int, help='루프백 포트')
    item.add_argument('--idle-minutes', type=int, help='유휴 만료(분)')
    item.add_argument('--absolute-days', type=int, help='기기 접속 최대 유효 기간(일)')
    sub.add_parser('status', help='설정·데이터베이스·런타임 상태')
    sub.add_parser('start', help=f'127.0.0.1에서 API와 웹앱 제공')
    item = sub.add_parser('enroll', help='새 브라우저 등록용 일회성 코드 생성')
    item.add_argument('--device-name', help='등록할 기기 표시 이름')
    sub.add_parser('devices', help='등록한 브라우저 목록')
    item = sub.add_parser('revoke', help='브라우저 접속 철회')
    item.add_argument('device_id')
    sub.add_parser('import-profiles', help='profiles.json(인증서 프로필)을 읽어 기관 로그인 초안 생성; 파일은 수정하지 않음')
    item = sub.add_parser('registration', help='하나은행 로그인의 기기·앱 등록 파일 연결(서버 관리)')
    item.add_argument('--login', required=True)
    item.add_argument('--app-profile', help='앱 프로필 파일(system_header·channel_header·secure_token)')
    item.add_argument('--login-input', help='로그인 입력 파일(push_token 등)')
    item.add_argument('--onesign-settings', help='hana onesign setup의 설정 이름')
    item.add_argument('--expected-revision', type=int, required=True)
    return root


def main(argv):
    try:
        from . import config as settings
    except ImportError:
        return emit_error('web_dependencies_missing', "웹 서버 의존성이 필요합니다: pip install 'finance-cli[web]'")
    args = parser().parse_args(argv)
    if args.action == 'config':
        current = settings.load()
        values = {'port': current.port, 'public_origin': current.public_origin, 'idle_minutes': current.idle_minutes,
                  'absolute_days': current.absolute_days}
        if args.port is not None:
            if args.public_origin is None and current.public_origin == f'http://127.0.0.1:{current.port}':
                values['public_origin'] = ''
            values['port'] = args.port
        for key in ('public_origin', 'idle_minutes', 'absolute_days'):
            if getattr(args, key) is not None:
                values[key] = getattr(args, key)
        config = settings.save(settings.Config(**values))
        emit({'config': config.as_dict(), 'network_used': False})
        return 0
    if args.action == 'status':
        from finance_cli.core import runtime
        from . import db
        config = settings.load()
        emit({'config': config.as_dict(), 'database': db.exists(), 'hometax_runtime_installed': runtime.status()['installed'],
              'network_used': False})
        return 0
    if args.action == 'start':
        try:
            import uvicorn
            from .app import create_app
        except ImportError:
            return emit_error('web_dependencies_missing', "웹 서버 의존성이 필요합니다: pip install 'finance-cli[web]'")
        config = settings.load()
        print(f'Finance 서버: {config.public_origin} (루프백 127.0.0.1:{config.port}, {config.mode})', file=sys.stderr)
        uvicorn.run(create_app(config), host='127.0.0.1', port=config.port, proxy_headers=False, server_header=False,
                    access_log=False, log_level='warning')
        return 0
    from .db import Database
    from . import access, model
    db = Database()
    if args.action == 'enroll':
        config = settings.load()
        with db.write() as con:
            value = access.create_code(con, config, args.device_name)
        print('이 코드는 한 번만 사용할 수 있고 10분 뒤 만료됩니다. 로그나 메신저에 남기지 마세요.', file=sys.stderr)
        emit({**value, 'network_used': False})
        return 0
    if args.action == 'devices':
        with db.read() as con:
            emit({'devices': access.devices(con), 'network_used': False})
        return 0
    if args.action == 'revoke':
        with db.write() as con:
            access.revoke(con, args.device_id)
        emit({'revoked': True, 'device_id': args.device_id, 'network_used': False})
        return 0
    if args.action == 'import-profiles':
        with db.write() as con:
            emit(model.import_certificate_profiles(con))
        return 0
    if args.action == 'registration':
        from .registration import link
        with db.write() as con:
            emit(link(con, args.login, expected_revision=args.expected_revision, app_profile=args.app_profile,
                      login_input=args.login_input, onesign_settings=args.onesign_settings))
        return 0
    return 2


def emit_error(code, message):
    emit({'error': code, 'message': message}, 2)
    return 2
