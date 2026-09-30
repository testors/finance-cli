"""fin idcard: save and manage identity cards for later use; no institution connection.

Card text, numbers and passphrases are read from the terminal, never from argv.
"""
import getpass
from pathlib import Path
import sys
import warnings

from .output import ArgumentParser, emit
from finance_cli.credentials.id_cards import IMAGE_LIMIT, KINDS, IdCards, prepare_jpeg
from finance_cli.credentials.registry import name as valid_name


def terminal():
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        raise ValueError('interactive_terminal_required')


def hidden(prompt):
    terminal()
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        return getpass.getpass(prompt)


def text(prompt):
    terminal()
    print(prompt, end='', file=sys.stderr, flush=True)
    return input()


def passphrase(args, *, confirm=False):
    if getattr(args, 'password_stdin', False):
        return sys.stdin.buffer.readline().removesuffix(b'\n').removesuffix(b'\r').decode('utf-8')
    value = hidden('신분증 보관 암호: ')
    if confirm and hidden('신분증 보관 암호 확인: ') != value:
        raise ValueError('passphrase_confirmation_mismatch')
    return value


def collect(kind):
    fields = {'name': text('신분증 이름: '), 'issueDate': text('발급일 YYYY.MM.DD: '),
              'birthDate': hidden('주민번호 앞 6자리: '), 'resident': hidden('주민번호 뒤 7자리: ')}
    if kind == 'driver':
        fields['regionCode'] = text('면허번호 지역 2자리: ')
        for i, size in enumerate((2, 6, 2), 1):
            fields['driver' + str(i)] = hidden(f'면허번호 지역 뒤 {i}번째 구간 {size}자리: ')
    return fields


def read_image(path):
    from finance_cli.core.storage import no_symlinks
    path = no_symlinks(path.expanduser())
    if not path.is_file() or path.stat().st_size > IMAGE_LIMIT:
        raise ValueError('identity_image_file_required')
    raw = path.read_bytes()
    prepare_jpeg(raw)  # Refuse an unreadable photo before asking for any card text.
    return raw


def main(argv):
    parser = ArgumentParser(prog='fin idcard', description='신분증 사진·정보 암호화 보관·확인·내보내기; 기관 통신 없음')
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('list', help='이름·종류·발급일·보관 시각')
    item = sub.add_parser('add', help='신분증 카드 영역 JPEG와 확인한 정보를 새 이름으로 보관')
    item.add_argument('name')
    item.add_argument('--image', type=Path, required=True, help='본인의 마스킹하지 않은 신분증 카드 영역 JPEG (8 MiB 이하)')
    item.add_argument('--kind', choices=KINDS, default='resident')
    for operation in ('show', 'export'):
        item = sub.add_parser(operation, help={'show': '보관 암호로 열어 가린 정보 확인',
                                               'export': '보관한 사진과 정보를 새 디렉터리에 저장'}[operation])
        item.add_argument('name')
        item.add_argument('--password-stdin', action='store_true', help='신분증 보관 암호 한 줄만 표준입력으로 받음')
        if operation == 'export':
            item.add_argument('--output', type=Path, required=True, help='만들 새 디렉터리')
    item = sub.add_parser('rename', help='이름만 변경; 복호화 없음')
    item.add_argument('name')
    item.add_argument('new_name')
    item = sub.add_parser('remove', help='보관한 신분증 삭제; 복호화 없음')
    item.add_argument('name')
    args = parser.parse_args(argv)
    cards = IdCards()
    if args.action == 'list':
        result = {'id_cards': cards.list(), 'network_used': False}
    elif args.action == 'add':
        valid_name(args.name)
        if any(row['name'] == args.name for row in cards.list()):
            raise ValueError('id_card_name_exists')
        raw = read_image(args.image)
        if text('본인의 마스킹하지 않은 신분증 카드 영역 사진이면 "본인 신분증" 입력: ') != '본인 신분증':
            raise ValueError('identity_not_confirmed')
        fields = collect(args.kind)
        result = cards.add(args.name, args.kind, fields, raw, passphrase(args, confirm=True))
    elif args.action == 'show':
        cards.entry(args.name)
        result = cards.show(args.name, passphrase(args))
    elif args.action == 'export':
        cards.entry(args.name)
        result = cards.export(args.name, passphrase(args), args.output)
    elif args.action == 'rename':
        result = cards.rename(args.name, args.new_name)
    else:
        result = cards.remove(args.name)
    emit(result)
    return 0
