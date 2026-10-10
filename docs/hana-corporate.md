# 하나은행 기업뱅킹

`fin hana corporate`는 로그인, 계좌·거래내역 조회, 일반 원화 이체를 제공합니다. 2026-10-03 사용자가 제공한 CLI 실행 결과에서 ID/PW 로그인, 출금계좌 정보·고객 확인 후속 응답, 세션 저장 성공을 확인했습니다. 공동인증서·하나인증서 기업 로그인과 조회·이체는 합성 검증 단계이며 실서버 수락은 아직 확인하지 않았습니다.

공동인증서는 공통 금고의 기존 `--credential` 또는 하나은행용 `--profile`을 선택합니다. 하나인증서는 기존 `fin hana onesign`의 identity를 `--name`으로 선택합니다. 인증서·개인키를 기업용으로 복제하거나 다시 가져오지 않습니다. 하나인증서는 은행에 연결된 기업 ID를 사용하며 신규 연결·변경이 필요하면 `corporate_id_link_required`로 중단합니다.

## 웹앱에서 사용하기

업무 선택에서 **하나기업뱅킹**을 고릅니다. 기존 개인 채널은 **하나개인뱅킹**으로 구분합니다. 웹 접속 등록 이후 기업뱅킹용 가입·프로필·세션 생성 절차는 없습니다.

1. **기업 계좌 → 기업뱅킹 로그인**에서 기업 ID와 비밀번호를 입력하고 **로그인하고 계좌 보기**를 누릅니다. 인증서 로그인은 같은 화면에서 방법을 바꾸고 공통 보관함의 기존 인증서를 선택합니다. 로그인 성공 후 출금계좌를 자동으로 조회·연결합니다.
2. **기업 거래내역**에서 계좌와 기간을 선택합니다. 기간을 비우면 최근 7일을 조회하며 다음 페이지도 자동으로 가져옵니다. 원화·펀드·외화·대출은 계좌 종류에 맞춰 처리합니다. 계좌 분류, 검색·통화·대출 실행번호는 필요할 때만 선택합니다.
3. **기업 이체**에서 출금계좌·받는 은행·받는 계좌·금액을 입력하고 **받는 분·금액 확인**을 누릅니다. 은행의 확인 내용을 검토한 뒤 이체를 진행합니다. 계좌 비밀번호·일반 OTP·공동인증서·ARS는 은행이 요구할 때만 묻습니다. 전화 인증을 완료하면 사용자가 계속 버튼을 누릅니다.

인증 도중 창을 닫아도 **기업 이체 작업 → 이어하기**로 돌아올 수 있습니다. 준비 취소는 아직 보내지 않은 이체에만 적용합니다. 전송한 건은 **이체 결과 조회**로 확인하며 다시 전송하지 않습니다. 결재 요청·지연·일부 성공·미확인 결과를 각각 표시하고, 후속 조회나 저장 오류로 은행의 수락을 취소하지 않습니다.

인증서는 공통 보관함을 그대로 참조하지만 개인·기업 로그인과 계좌는 분리합니다. 인증서 로그인도 웹에서 연결 정보를 자동 준비하므로 아래 CLI의 기기 파일·세션 지정 절차가 필요하지 않습니다. 잠금 해제한 하나인증서 저장소의 암호는 다시 묻지 않고 PIN은 해당 로그인에만 전달합니다. ID/PW용 키패드 설정이 서버에 이미 설치되어 있으면 자동 재사용합니다. 설정이 없거나 서로 다른 호환 설정이 여러 개일 때만 준비·선택 안내를 표시합니다.

웹 경로는 합성 응답과 로컬 화면으로 검증했습니다. 기존 CLI의 실사용 증거와 웹에서의 실제 은행 실행 검증은 별개입니다. 인증서 로그인·이체의 실서버 수락을 이 검증으로 보장하지 않습니다.

## ID/PW 로그인

기업 인터넷뱅킹 ID와 로그인 비밀번호를 사용합니다. ID는 영문·숫자 4–20자이며 대문자로 변환합니다. 비밀번호는 대소문자·공백을 그대로 보존하는 6–16자 입력입니다. 영문·숫자·출력 가능한 ASCII 특수문자를 지원하며, 실제 비밀번호 등록 정책은 은행에 따릅니다. 인증서·인증서 암호·개인뱅킹 로그인을 요구하지 않습니다. 시스템 OpenSSL 3가 필요합니다.

이미 하나은행 키패드 설정이 설치되어 있다면 다음 한 명령으로 로그인합니다. 비밀번호는 숨김 입력합니다.

```sh
fin hana corporate login-idpw --user-id YOURID --send
```

로그인 기록과 쿠키를 담는 로컬 세션은 자동 생성합니다. `session new`나 기기 JSON 작성, 휴대폰 연결이 필요하지 않습니다. CLI 전용 연결 정보를 최초 실행 시 만들고 이후에도 유지합니다. 실제 휴대폰의 식별자·개인뱅킹 쿠키·인증서를 복사하지 않습니다. 이 자동 준비 경로의 ID/PW 로그인 성공이 관측됐습니다.

호환되는 공통 키패드 설정을 자동으로 사용합니다. 여러 설정의 키패드 재료가 같으면 같은 설정으로 취급합니다. 서로 다른 재료가 있다면 `--settings 이름`으로 선택할 수 있습니다. `--session 이름`은 로그인 기록 이름을 직접 정하고 싶을 때만 사용하며, 없는 이름이면 자동으로 준비합니다. 이미 로그인 요청을 시작한 이름은 덮어쓰거나 재사용하지 않습니다.

자동화에서는 `--format json-v1`과 `--password-stdin`을 사용할 수 있습니다. 결과의 `session`은 이후 관측 결과 확인에 쓰는 로컬 기록 이름이며 기업 ID가 아닙니다. `--send`를 빼면 파일·비밀번호 접근 없이 계획만 반환합니다.

키패드 설정이 없는 첫 설치에서는 한 번만 준비합니다. 이미 `fin hana setup extract`로 설치한 1.0.27 설정이 있으면 자동으로 재사용하며, identity 생성이나 인증서 발급은 필요 없습니다. 기업 앱만 사용하는 경우에는 기업 6.2.2의 ARM64 분할 설치 패키지에서 키패드 설정만 설치합니다. 알려진 버전의 데이터만 읽으며 앱 코드를 실행하지 않고 기존 설정을 덮어쓰지 않습니다.

```sh
# 최초 설정 준비; 은행 통신 없음
fin hana corporate setup extract --package /path/to/split_config.arm64_v8a.apk --settings company-keypad

# 이후에는 ID와 숨김 입력 비밀번호로 로그인
fin hana corporate login-idpw --user-id YOURID --send
```

`--password-stdin`은 **기업 로그인 비밀번호 한 줄만** 읽습니다. 다른 금고 암호·인증서 암호·PIN을 입력하지 않습니다. 비밀번호를 명령줄 인자로 넘기는 옵션은 없습니다. 푸시 등록 여부는 `management_number`의 존재 여부와 일치해야 합니다.

로그인 요청은 한 번만 제출합니다. 비밀번호 오류 횟수는 응답에 있을 때만 `password_failures_reported`로 표시하고 자동 재시도하지 않습니다. `agreement_required`는 약관 절차가 필요하다는 뜻이며 자동 동의하지 않습니다. ID/PW 로그인에는 인증서 로그인과 다른 성공 판정을 적용합니다.

초기 연결 정보는 로그인 응답과 별도로 해석합니다. 선택적 앱 업데이트·안내 공지·판정에 쓰이지 않는 값의 차이는 단계별 `warnings`에 기록하고 진행합니다. 실제 긴급 중단이나 필수 최소 버전 미달은 해당 상태에서 멈춥니다. 경고는 로그인 실패를 뜻하지 않습니다.

ID/PW 후속 고객 확인 결과의 `follow_up.customer_guidance`는 `none`, `visit_branch_notice`, `customer_verification_choice_required`, `certificate_login_required`, `unconfirmed`로 구분합니다. 고객확인 등록은 자동 실행하지 않습니다. 은행 내부 조직의 인증서 로그인 제한에 해당하면 로그아웃을 요청하고 최초 로그인 수락과 별도로 결과를 기록합니다. `session_usage=certificate_login_required`인 세션은 계속 사용하지 않습니다. `session_current_validity=logged_out`은 로그아웃 수락까지 관측한 경우입니다.

`visit_branch_notice`는 고객확인 이행주기 경과에 따른 영업점 방문 안내입니다. 앱은 안내 확인 뒤 계속 진행하며, 이 상태가 로그인 성공을 취소하지 않습니다. `follow_up.app_fds=not_implemented`는 앱 설치 정보 수집의 구현 상태이며 로그인 실패 판정이 아닙니다.

로그인 이후 개별 업무가 요구하는 권한·인증서는 별개입니다. ID/PW로 인증서 서명을 대신하지 않으며, 공동인증서가 필요한 기능은 공통 저장소를 사용합니다.

## 계좌·거래내역 조회

기존 기업 로그인 연장은 `fin hana corporate session extend --send`로 요청합니다. ID/PW·공동인증서·하나인증서 로그인에 동일하게 사용할 수 있으며 비밀번호를 다시 입력하지 않습니다. 2026-10-10 저장한 ID/PW 로그인 세션에서 연장 요청의 은행 수락과 세션 유지를 확인했습니다. 요청이 없는 세션은 590초 뒤에는 유지됐고 620초 뒤에는 끝나 있었습니다. [세션 연장 안내](session-extension.md)를 참고하세요.

최근 성공한 기업 로그인을 자동으로 사용합니다. 별도 세션 생성이나 계좌별 설정이 필요하지 않습니다. 다른 로그인 기록을 지정할 때만 `--session`을 사용합니다. 만료된 로그인은 은행 응답으로 확인하며 자동으로 재로그인하지 않습니다.

```sh
fin hana corporate accounts --send
fin hana corporate accounts --category all --send
fin hana corporate history --account ACCOUNT --send
fin hana corporate history --account ACCOUNT --start 2026-09-01 --end 2026-09-30 --send
```

계좌 조회의 기본값은 출금계좌입니다. `--category`로 `withdrawal`, `deposits`, `fund`, `loans`, `foreign`, `payroll`, `favorites`를 선택합니다. `all`은 즐겨찾기를 제외한 여섯 분류를 조회합니다. 확인된 계좌는 같은 로그인 기록에 자동 연결합니다.

거래내역은 계좌 종류에 맞춰 원화·펀드·외화·대출 경로를 사용합니다. 기본 기간은 오늘을 포함한 최근 7일, 순서는 최신순입니다. `--order oldest`, `--direction deposit|withdrawal`, 원화 검색 `--search-type summary|amount|recipient|memo --search 값`을 지원합니다. 대출은 입출금 구분을 지정하지 않습니다. 외화는 `--currency USD` 또는 `--currency ALL`, 대출 실행번호는 필요한 경우에만 `--sequence`로 선택합니다.

한 번의 조회 기간은 최대 365일 차이입니다. 날짜는 `YYYY-MM-DD`와 `YYYYMMDD`를 받습니다. 다음 페이지와 과거 거래 저장 구간은 자동으로 이어서 조회합니다. 금액·거래번호의 문자열을 보존하며 과거 거래의 화면 표시 값은 `display`에 둡니다. 중간 페이지에서 멈추면 이미 받은 `transactions`와 `accepted`를 유지하고 `complete: false`로 반환합니다. 빈 목록은 정상 결과일 수 있습니다.

## 일반 원화 이체

먼저 은행에서 수취인과 금액을 확인하고 준비 결과의 `preview`를 검토합니다. 이어지는 `execute`가 실제 이체 요청입니다. 준비 이름과 세션은 자동으로 이어집니다.

```sh
fin hana corporate transfer prepare --from-account FROM_ACCOUNT --to-bank 081 --to-account TO_ACCOUNT --amount 1000 --send
fin hana corporate transfer execute --send
fin hana corporate transfer result --send
```

`--to-bank`는 3자리 은행 코드, `--amount`는 원화 정수입니다. `prepare`는 필요하면 `--memo`, `--debit-memo`, `--credit-memo`, `--cms-code`, `--delayed`를 받습니다. 은행의 기존 지연이체 설정도 유지합니다. 중복 이체 표시가 있으면 내용을 확인한 뒤 `execute --allow-duplicate --send`를 사용합니다. 실행 전 준비만 취소하려면 `transfer cancel --send`를 사용합니다. 이 명령은 제출한 송금을 취소하는 기능이 아닙니다.

서버가 요구하는 경우에만 출금계좌 비밀번호 4자리, 일반 OTP 6자리, 공동인증서 암호를 각각 숨김 입력합니다. 공동인증서는 로그인에 연결된 공통 인증서 또는 금고의 단일 인증서를 자동 선택합니다. 선택이 모호하면 `--credential 이름` 또는 `--profile 이름`을 지정합니다. 같은 인증서를 기업용으로 다시 가져오지 않습니다. ID/PW 로그인 뒤 공동인증서 서명이 필요한 경우에도 이 경로를 사용합니다.

ARS가 필요하면 등록된 번호로 한 번 요청하고 제어 터미널에 인증번호를 표시합니다. 전화 인증 후 Enter를 누르면 결과를 한 번 확인합니다. 아직 완료되지 않았다면 전화 인증을 마친 뒤 `execute --ars-completed --send`로 확인을 이어갈 수 있습니다. 자동 발신 반복이나 결과 폴링은 하지 않습니다. `--ars-phone`은 은행에 등록된 전화의 선택 번호입니다.

자동화 입력은 분리합니다. `--password-stdin`은 공동인증서 암호 한 줄만, `--account-password-fd`는 계좌 비밀번호 한 줄, `--otp-fd`는 OTP 한 줄을 읽습니다. 같은 파일 디스크립터를 여러 비밀에 사용할 수 없습니다. 은행이 요구하지 않으면 해당 입력을 읽지 않습니다.

최종 이체 요청은 준비 건당 한 번만 보냅니다. 응답이 끊겼거나 결과 조회가 실패하면 `transfer result --send`로 확인하며 `execute`를 재송신하지 않습니다. 은행이 확인한 인증 단계는 이어서 사용합니다. 비밀번호·OTP 검증 요청의 응답이 미확인인 경우도 자동 재제출하지 않습니다.

- `accepted`는 최종 요청 수락 관측이며 송금 확정을 대신하지 않습니다. `prepare`에서는 준비 응답의 수락입니다.
- `transfer_status`는 `prepared`, `submitted`, `completed`, `approval_requested`, `delayed`, `partial`, `rejected`, `unconfirmed` 등을 구분합니다. 결재 요청·지연·일부 성공을 즉시 송금 완료로 합치지 않습니다. 비동기 내역은 별도 목록과 처리 상태를 제공합니다.
- `transfer_sent: true`는 전송 시도가 있었다는 뜻입니다. 성공을 뜻하지 않습니다. 이후 결과 조회 실패나 로그 저장 실패도 이미 확인한 수락을 취소하지 않습니다.
- 같은 기업 로그인에서는 한 번에 하나의 업무를 처리합니다. 미완료 준비 건이 있으면 먼저 실행·결과 확인·준비 취소를 마칩니다. 통신 명령은 `--send`가 없으면 통신·저장소·비밀 입력 없이 계획만 반환합니다.

계좌 비밀번호·일반 OTP·ARS·공동인증서 서명을 지원합니다. 은행이 모바일 OTP 생성, 금융인증서 또는 민간인증서 전자서명을 요구하면 필요한 인증을 표시하고 멈춥니다. 인증을 생략하여 이체하지 않습니다. 급여 전용·은행 파일이체 서비스, 예약·자동 반복 이체, 세금 납부, 다른 결재자의 승인, OTP 발급·변경 및 한도 변경은 지원 범위에 포함되지 않습니다.

## CSV 명단으로 월 급여 등 다건 이체하기

CLI는 하나의 출금계좌에서 여러 수취인에게 보내는 일반 원화 다건 이체를 지원합니다. 직원별 은행·계좌·실지급액을 UTF-8 CSV로 준비합니다. 월별로 파일을 복사해 금액과 통장 표시를 갱신할 수 있습니다. 다음은 실제 계좌가 아닌 형식 예입니다.

```csv
employee,to_bank,to_account,amount,credit_memo
직원A,081,000201,2500000,10월급여
직원B,004,000202,2700000,10월급여
```

필수 열은 `to_bank`, `to_account`, `amount`입니다. 은행 코드는 3자리, 계좌는 앞자리 0을 보존한 문자열, 금액은 쉼표 없는 양의 원화 정수입니다. 선택 열은 `employee`, `credit_memo`(입금통장 표시), `debit_memo`(출금통장 표시), `memo`, `cms_code`입니다. `employee`는 파일 관리용이며 은행에 전송하지 않습니다. 실제 명의는 은행이 반환한 준비 내역에서 확인합니다. 표시를 비우면 단건 이체와 같은 기본값을 사용합니다. UTF-8 BOM과 CSV 따옴표를 지원합니다.

```sh
# 로컬 파일 전체 검사: 은행·인증서·세션 접근 없음
fin hana corporate transfer check-batch --file payroll-2026-10.csv

# 수취인별 검증·준비 후 전체 금액·수수료·수취인 확인
fin hana corporate transfer prepare-batch --from-account 출금계좌 --file payroll-2026-10.csv --send

# 위 준비 내역을 검토한 뒤 한 번 실행
fin hana corporate transfer execute --send
fin hana corporate transfer result --send
```

`check-batch`는 건수·총액·중복 행 번호만 반환하며 은행 확인을 뜻하지 않습니다. 중복 행을 자동 삭제하지 않습니다. `prepare-batch`는 파일 전체를 검사한 뒤 같은 세션에서 순서대로 준비하고, 마지막에 전체 명단을 반환합니다. 각 직원별로 최종 송금을 반복하지 않으며 `execute`가 전체 준비 내역을 인증·서명해 한 번 제출합니다. 은행이 중복으로 표시한 건은 기존 `--allow-duplicate`로 확인합니다.

준비 중 오류가 나면 `prepared_items`와 `preparing_item`으로 진행 위치를 표시합니다. 준비된 일부만 실행하지 않으며 `transfer cancel --send`로 준비 상태를 정리할 수 있습니다. 이미 제출했다면 `result`로 확인합니다. 한 번의 제출에서도 일부 건만 성공할 수 있습니다. 일부 성공이나 결과 미확인 상태에서 같은 명단을 다시 실행하지 말고 건별 결과를 확인해야 합니다.

매월 새 명단을 검토하고 새로 준비·실행합니다. 예약일이나 매월 자동 송금은 설정하지 않습니다. 원화 다건 이체의 은행 최대 허용 건수·권한·실서버 수락은 미확인이며 서버 제한을 피해 자동으로 분할하지 않습니다. 은행의 급여 전용 서비스·파일 업로드·결재자 승인과 웹 화면의 명단 업로드는 아직 지원하지 않습니다. 결재가 필요한 결과는 `approval_requested`로 표시하며 지급 완료로 간주하지 않습니다.

## 인증서 로그인용 기업 세션 준비

기업 앱 6.2.2의 기기 정보를 사용자가 지정한 JSON 파일로 준비합니다. 개인 앱의 기기 정보를 자동으로 복사하지 않습니다. 다음은 형식 예이며 `YOUR_*`와 기기 속성을 실제 사용할 값으로 바꿉니다. 예시 값의 서버 수락을 보장하지 않습니다.

```json
{
  "custom_user_agent": {
    "platform": "Android",
    "brand": "YOUR_DEVICE_BRAND",
    "model": "YOUR_DEVICE_MODEL",
    "version": "YOUR_ANDROID_VERSION",
    "deviceId": "YOUR_CORPORATE_APP_UUID",
    "phoneNumber": "",
    "countryIso": "",
    "timeZoneId": "Asia/Seoul",
    "telecom": "YOUR_NETWORK_OPERATOR",
    "simSerialNumber": "",
    "subscriberId": "",
    "appVersion": "6.2.2",
    "phoneName": "",
    "appName": "HanaNCBS",
    "deviceWidth": 1080,
    "deviceHeight": 2400,
    "uid": "YOUR_ANDROID_ID",
    "hUid": "YOUR_CORPORATE_APP_UUID",
    "terminalInfoId": "YOUR_ADVERTISING_ID",
    "etcStr": "",
    "userAgent": "YOUR_WEBVIEW_USER_AGENT"
  },
  "push": {"is_push": "N", "token": "", "management_number": ""}
}
```

`deviceId`와 `hUid`는 같은 기업 앱 UUID입니다. 푸시 미등록 상태의 기본값은 위와 같으며 `push`는 생략할 수 있습니다. 기기 파일과 세션 자료는 사용자 데이터로 관리합니다.

```sh
fin hana corporate session new --session company-joint --device-file /path/to/corporate-device.json
fin hana corporate login --session company-joint --credential existing-cert
```

두 번째 명령은 전송 계획만 반환하며 인증서·암호·저장된 프로필에 접근하지 않습니다. 실제 사용자가 로그인하려면 같은 명령에 `--send`를 붙입니다.

```sh
fin hana corporate login --session company-joint --credential existing-cert --send
# 공통 선택 프로필도 사용 가능
fin hana corporate login --session another-session --profile existing-hana-profile --send
```

공동인증서는 현재 RSA2048/SHA256 프로필을 지원합니다. `--password-stdin`은 공동 금고와 인증서 해제에 사용하는 암호 한 줄만 읽습니다. PIN·계좌 비밀번호·OTP를 같은 입력으로 읽지 않습니다.

## 하나인증서 로그인

기존 identity에 인증서·PIN 등록 정보·고객번호·개인 앱 서비스 설정이 있어야 합니다. 기업 기기 UUID로 인증서의 기존 device binding을 바꾸지 않습니다. 기업뱅킹에 개인사업자 하나인증서와 기업 ID가 이미 연결되어 있어야 합니다.

```sh
fin hana corporate session new --session company-one --device-file /path/to/corporate-device.json
fin hana corporate login-onesign --session company-one --name existing-identity
# 사용자가 실제 로그인을 실행할 때
fin hana corporate login-onesign --session company-one --name existing-identity --send
```

저장소 암호와 하나인증서 PIN은 각각 숨김 입력합니다. `--password-stdin`은 저장소 암호 한 줄만 읽으며 PIN은 제어 터미널(`/dev/tty`)에서 별도로 받습니다. PIN 입력 터미널이 없으면 통신 전에 중단합니다. 업무 함수에는 별도 입력 제공자를 전달할 수 있습니다.

기업 nonce·외부 인증 요청 → 개인 앱 인증·외부 인증 API → 기존 키로 서명·제출 → 기업 확인·로그인 순서입니다. 개인뱅킹 로그인을 추가로 수행하지 않습니다. 개인 API·기업 API·인증서 PIN 검증 서버의 쿠키를 분리합니다. 외부 인증 서버가 지정한 원문에 개인 로그인 nonce를 덧붙이지 않습니다.

## 결과와 현재 제한

```sh
fin --format json-v1 hana corporate session show --session company-one
```

- `accepted: true`, `user_login_verified: true`는 기업 로그인 성공을 관측했다는 뜻입니다. `session_current_validity: unverified`는 저장 세션의 이후 유효성을 별도 확인하지 않았다는 뜻이며, 로그인 성공을 미확인으로 바꾸지 않습니다. 세션을 자동 확인·갱신하지 않습니다.
- `accepted: false`는 기업 로그인 요청의 명시적 업무 오류입니다. `accepted: null`은 로그인 성공·실패가 확정되지 않은 상태입니다.
- `external_auth_status`는 하나인증서 외부 인증 단계의 판정입니다. 외부 인증 성공만으로 기업 로그인 성공이 되지 않습니다.
- `processing_status: stopped`나 `session_saved: false`가 로그인 성공과 함께 반환될 수 있습니다. 후속 처리·저장 실패가 확인된 은행 성공을 지우지 않습니다. 중단의 종료코드는 `2`이며 업무 판정을 대신하지 않습니다.
- ID/PW 요청 기록에서는 사용자 ID·로그인 암호문·푸시 토큰을 제거합니다. 단계별 요청·응답과 쿠키는 데이터 홈의 `hana-corporate/sessions/<이름>/`에 0600 파일로 저장합니다. 이 기업 세션 파일에는 금고 암호화가 적용되지 않습니다. 하나인증서의 개인 API·PIN 검증 기록은 기존 identity에 암호화 보관합니다. 일반 출력에는 토큰·쿠키·서명·고객번호·응답 원문을 내보내지 않습니다.
- 시작한 로그인은 같은 기업 세션으로 재전송하지 않습니다. timeout·대기 상태·PIN 오류를 자동 재시도하지 않습니다. 결과를 확인한 뒤 사용자가 별도 새 세션을 준비할 수 있습니다.

기업 서비스 가입, 기업 ID 연결, 다중 서명 요청, 필수 앱 업데이트가 필요하면 해당 상태에서 중단합니다. 휴대폰 앱 설치 정보 FDS 수집은 미구현이며 로그인 후 결과에 표시합니다. 출금계좌 정보·고객 확인의 로그인 후속 요청은 수행하며 ID/PW의 위 고객 확인 분기를 해석합니다. 인증서 로그인 경로의 추가 안내 분기는 아직 해석하지 않습니다. 금융인증서 로그인, 별도 결재자 승인, 자동 발급·다운로드·등록·OTP 변경·한도 변경은 제공하지 않습니다.
