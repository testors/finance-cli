"""Certificate selection shared by institution CLI parsers."""


def add_selection(parser, *, required=True):
    group = parser.add_mutually_exclusive_group(required=required)
    group.add_argument('--credential', help='공통 금고의 인증서 별칭')
    group.add_argument('--profile', help='fin profile set의 기관별 인증서 선택 설정')
    parser.add_argument('--password-stdin', action='store_true',
                        help='인증서 비밀번호 한 줄을 표준입력으로 받음; PIN 입력과 별개')


def resolve(args, service):
    if args.profile:
        from finance_cli.core.profiles import resolve as profile_certificate
        return profile_certificate(args.profile, service)
    return args.credential
