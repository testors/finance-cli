"""Interactive setup, issuance and signing commands; secrets never use argv."""
import getpass
import json
from pathlib import Path
import re
import sys
import warnings

from . import onesign, onesign_setup, onesign_bundle, onesign_transfer
from .onesign_state import State
from .onesign_crypto import require


def terminal():
    require(sys.stdin.isatty() and sys.stderr.isatty(),'interactive_terminal_required')


def hidden(prompt):
    terminal()
    with warnings.catch_warnings():
        warnings.simplefilter('error',getpass.GetPassWarning)
        return getpass.getpass(prompt)


def password(args):
    if args.password_stdin:
        return sys.stdin.buffer.readline().removesuffix(b'\n').removesuffix(b'\r').decode()
    return hidden('암호화 저장소 암호: ')


def text(prompt):
    terminal()
    print(prompt,end='',file=sys.stderr,flush=True)
    return input()


def agree(terms,title):
    print(title,file=sys.stderr)
    for row in terms:
        print(row['title']+'\n  '+'\n  '.join(row['urls']),file=sys.stderr)
    return text('약관을 읽고 동의하면 "동의" 입력: ')=='동의'


def choose_account(rows):
    for i,row in enumerate(rows,1):
        print(f"{i}: {row.get('acctSubjNm','')} / 끝 네 자리 {str(row.get('acctNo',''))[-4:]}",file=sys.stderr)
    chosen = text('본인 계좌 순번: ')
    require(chosen.isdecimal() and 1<=int(chosen)<=len(rows),'account_selection_invalid')
    return rows[int(chosen)-1]['acctNo']


def inputs():
    return {'phone':lambda:{'name':text('이름: '),'birth7':hidden('생년월일 6자리와 주민번호 뒤 첫 자리: '),
                'phone':hidden('본인 휴대폰 번호: '),'carrier':text('통신사 SKT=4 KT=6 LGU+=5 / 알뜰 SKT=7 KT=8 LGU+=A: ')},
        'agree':agree,'sms':lambda:hidden('SMS 인증번호 6자리: '),'account':choose_account,
        'account_password':lambda *args:hidden('계좌 비밀번호 4자리: '),
        'new_pin':lambda:(hidden('새 하나인증서 PIN 6자리: '),hidden('새 PIN 확인: ')),
        'confirm_issue':lambda:text('하나인증서를 새로 발급하려면 "발급" 입력: ')=='발급',
        'pin':lambda:hidden('하나인증서 PIN 6자리: '),'confirm':confirm_transfer}


def confirm_transfer(preview):
    print(json.dumps(preview,ensure_ascii=False,indent=2),file=sys.stderr)
    return text(f"위 수취인·계좌·금액·수수료로 송금하려면 \"이체 {preview['amount_krw']}원\" 입력: ")==f"이체 {preview['amount_krw']}원"


def prepare_id(state,args):
    require(args.image is not None,'identity_image_required')
    from finance_cli.core.storage import no_symlinks
    path = no_symlinks(args.image.expanduser())
    require(path.is_file() and path.stat().st_size<=8*1024*1024,'identity_image_file_required')
    jpeg = path.read_bytes()
    onesign.jpeg_size(jpeg)
    require(text('본인의 마스킹하지 않은 신분증 카드 영역 사진이면 "본인 신분증" 입력: ')=='본인 신분증','identity_not_confirmed')
    fields = {'name':text('신분증 이름: '),'issueDate':text('발급일 YYYY.MM.DD: '),
        'birthDate':hidden('주민번호 앞 6자리: '),'resident':hidden('주민번호 뒤 7자리: ')}
    require(re.fullmatch('[0-9]{6}',fields['birthDate']) is not None and re.fullmatch('[0-9]{7}',fields['resident']) is not None,'resident_number_format')
    if args.kind=='driver':
        fields['regionCode']=text('면허번호 지역 앞 2자리: ')
        for i,size in enumerate((2,6,2),1):
            value=hidden(f'면허번호 지역 뒤 {i}번째 구간 {size}자리: ')
            require(re.fullmatch('[0-9]{'+str(size)+'}',value) is not None,'driver_number_format')
            fields['driver'+str(i)]=value
    return onesign.prepare_identity(state,args.kind,jpeg,fields)


def common(parser):
    parser.add_argument('--name',required=True,help='암호화된 하나인증서 이름')
    parser.add_argument('--password-stdin',action='store_true',help='저장소 암호 한 줄만 표준입력으로 받음')


def add_parsers(sub,onesign_sub):
    setup=sub.add_parser('setup',help='사용자 자료에서 서비스 설정 추출·기기 프로필 설정; 접속 없음').add_subparsers(dest='action',required=True)
    item=setup.add_parser('extract',help='지원 버전의 설치 패키지에서 공통 자료 추출')
    item.add_argument('--apk',type=Path,action='append',required=True,help='base와 arm64 분할 패키지 각각 지정')
    item.add_argument('--name',required=True)
    item=setup.add_parser('configure',help='사용자가 지정한 기기 속성으로 공통 헤더 구성')
    item.add_argument('--name',required=True)
    item.add_argument('--android-sdk',type=int,required=True)
    item.add_argument('--model',required=True)
    item.add_argument('--width',type=int,required=True)
    item.add_argument('--height',type=int,required=True)
    item.add_argument('--webview-user-agent',required=True)
    item.add_argument('--timezone',default='Asia/Seoul')
    item=setup.add_parser('status',help='설정 준비 여부와 지원 버전 확인')
    item.add_argument('--name',required=True)
    item=onesign_sub.add_parser('init',help='새 기기 식별자·키와 암호화 저장소 생성; 접속 없음')
    common(item); item.add_argument('--settings',required=True)
    for action in ('enroll','issue','login','accounts','new-session','inspect','export-identity','activate'):
        item=onesign_sub.add_parser(action,help={'enroll':'SMS·신분증·계좌 확인부터 신규 발급까지 순서대로 진행',
            'issue':'신규 발급의 한 단계 실행','login':'새 세션에서 앱 인증과 하나인증서 서명 로그인',
            'accounts':'서명 로그인한 세션의 계좌 조회','new-session':'같은 인증서의 새 로그인 세션 생성',
            'inspect':'암호화 상태·시도 결과 요약','export-identity':'사용 가능한 인증서를 새 v2 번들로 내보내기',
            'activate':'번들을 사용 가능한 인증서 저장소로 가져오기'}[action])
        common(item)
        if action in ('enroll','issue','login','accounts'):
            item.add_argument('--run',required=True,help='새 실행 이름; 이미 시작한 실행은 재사용하지 않음')
            item.add_argument('--send',action='store_true')
        if action in ('login','accounts','new-session'):
            item.add_argument('--session',required=True)
        if action in ('enroll','issue'):
            item.add_argument('--image',type=Path)
            item.add_argument('--kind',choices=('resident','driver'),default='resident')
        if action=='issue':
            item.add_argument('--stage',choices=(*onesign.PHONE,'begin-id','prepare-id',*onesign.ISSUE[1:]),required=True)
        if action=='export-identity':
            item.add_argument('--output',type=Path,required=True)
        if action=='activate':
            item.add_argument('--bundle',type=Path,required=True)
            item.add_argument('--settings',required=True)
    transfer=sub.add_parser('transfer',help='하나인증서 원화 이체: 준비→내용 확인·전송→결과 대조').add_subparsers(dest='action',required=True)
    for action in ('prepare','show','execute','reconcile'):
        item=transfer.add_parser(action)
        common(item)
        item.add_argument('--transaction',required=True)
        if action!='show':
            item.add_argument('--session',required=True)
            item.add_argument('--run',required=True)
            item.add_argument('--send',action='store_true')
        if action=='prepare':
            item.add_argument('--input',type=Path,required=True,help='출금·수취계좌·은행·금액 JSON')


def dispatch(args):
    if args.operation=='setup':
        if args.action=='extract':
            return onesign_setup.install(args.apk,args.name)
        if args.action=='configure':
            return onesign_setup.configure(args.name,android_sdk=args.android_sdk,model=args.model,width=args.width,
                height=args.height,webview_user_agent=args.webview_user_agent,timezone=args.timezone)
        value=onesign_setup.load(args.name)
        return {'settings':args.name,'version':value['version'],'configured':'service_profile' in value,'network_used':False}
    # Planning does not open stores, prompt for secrets or create attempts.
    if args.operation=='transfer' and args.action!='show' and not args.send:
        return {'operation':'transfer-'+args.action,'network_used':False,'next':'same_command_with_send'}
    if args.operation=='onesign' and args.action in ('enroll','issue','login','accounts') and not args.send:
        local=args.action=='issue' and args.stage in ('profile','consent','prepare-id')
        if not local:
            return {'operation':args.action,'stages':[*onesign.PHONE,'begin-id','prepare-id',*onesign.ISSUE[1:]] if args.action=='enroll' else [],'network_used':False,'next':'same_command_with_send'}
    secret=password(args)
    if args.operation=='onesign' and args.action=='init':
        return onesign.initialize(args.name,args.settings,secret)
    if args.operation=='onesign' and args.action=='activate':
        return onesign_bundle.activate(args.name,args.bundle,secret,args.settings)
    with State(args.name,secret) as state:
        if args.operation=='transfer':
            intent=json.loads(args.input.read_text()) if args.action=='prepare' else None
            return onesign_transfer.operate(state,args.action,args.transaction,getattr(args,'run',None),getattr(args,'session',None),
                send=getattr(args,'send',False),intent=intent,inputs=inputs())
        if args.action=='new-session':
            return onesign.new_session(state,args.session)
        if args.action=='inspect':
            value=state.snapshot()
            return {'enrollment':value['profile']['enrollment']['state'],'issuance':value['issuance']['state'],
                'certificate_issued':value['issuance'].get('certificate_issued',False),
                'runs':{k:{'operation':v['operation'],'outcome':v['outcome']} for k,v in value['runs'].items()},'network_used':False}
        if args.action=='export-identity':
            return onesign_bundle.export_identity(state,args.output,secret)
        if args.action=='enroll':
            require(state.snapshot()['signup']['state']=='new','use_stage_commands_for_existing_issuance')
            require(args.image is not None,'identity_image_required')
            from .store import name as valid_name
            for stage in (*onesign.PHONE,*onesign.ISSUE):
                valid_name(args.run+'-'+stage)
            for stage in (*onesign.PHONE,'begin-id','prepare-id',*onesign.ISSUE[1:]):
                print('진행: '+stage,file=sys.stderr)
                if stage=='prepare-id':
                    result=prepare_id(state,args)
                else:
                    result=onesign.operate(state,stage,args.run+'-'+stage,send=True,inputs=inputs())
                if result.get('processing_status')=='stopped':
                    return {**result,'stopped_at':stage}
            return result
        if args.action=='issue':
            if args.stage=='prepare-id':
                return prepare_id(state,args)
            return onesign.operate(state,args.stage,args.run,send=args.send,inputs=inputs())
        return onesign.operate(state,args.action,args.run,session=args.session,send=args.send,inputs=inputs())
