# 하나은행 기업 로그인

`fin hana corporate`는 ID/PW·공동인증서·개인사업자용 하나인증서 로그인을 제공합니다. 합성 테스트를 통과한 구현이며 실제 은행 서버 수락은 아직 검증하지 않았습니다. 개인 채널의 기존 실사용 확인 결과가 기업 채널에도 적용되지는 않습니다.

공동인증서는 공통 금고의 기존 `--credential` 또는 하나은행용 `--profile`을 선택합니다. 하나인증서는 기존 `fin hana onesign`의 identity를 `--name`으로 선택합니다. 인증서·개인키를 기업용으로 복제하거나 다시 가져오지 않습니다. 하나인증서는 은행에 연결된 기업 ID를 사용하며 신규 연결·변경이 필요하면 `corporate_id_link_required`로 중단합니다.

## ID/PW 로그인

기업 인터넷뱅킹 ID와 로그인 비밀번호를 사용합니다. ID는 영문·숫자 4–20자이며 대문자로 변환합니다. 비밀번호는 대소문자·공백을 그대로 보존하는 6–16자 입력입니다. 영문·숫자·출력 가능한 ASCII 특수문자를 지원하며, 실제 비밀번호 등록 정책은 은행에 따릅니다. 인증서·인증서 암호·개인뱅킹 로그인을 요구하지 않습니다. 시스템 OpenSSL 3가 필요합니다.

이미 하나은행 키패드 설정이 설치되어 있다면 다음 한 명령으로 로그인합니다. 비밀번호는 숨김 입력합니다.

```sh
fin hana corporate login-idpw --user-id YOURID --send
```

로그인 기록과 쿠키를 담는 로컬 세션은 자동 생성합니다. `session new`나 기기 JSON 작성, 휴대폰 연결이 필요하지 않습니다. CLI 전용 연결 정보를 최초 실행 시 만들고 이후에도 유지합니다. 실제 휴대폰의 식별자·개인뱅킹 쿠키·인증서를 복사하지 않습니다. CLI 연결 정보의 은행 서버 수락은 아직 검증하지 않았습니다.

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

ID/PW 후속 고객 확인 결과의 `follow_up.customer_guidance`는 `none`, `visit_branch_notice`, `customer_verification_choice_required`, `certificate_login_required`, `unconfirmed`로 구분합니다. 고객확인 등록은 자동 실행하지 않습니다. 은행 내부 조직의 인증서 로그인 제한에 해당하면 로그아웃을 요청하고 최초 로그인 수락과 별도로 결과를 기록합니다. `session_usage=certificate_login_required`인 세션은 계속 사용하지 않습니다. `session_current_validity=logged_out`은 로그아웃 수락까지 관측한 경우입니다.

로그인 이후 개별 업무가 요구하는 권한·인증서는 별개입니다. ID/PW로 인증서 서명을 대신하지 않으며, 공동인증서가 필요한 기능은 공통 저장소를 사용합니다.

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

- `accepted: true`, `user_login_verified: true`는 기업 로그인 성공을 관측했다는 뜻입니다. 현재 서버 세션의 유효성은 별도이며 자동 확인·갱신하지 않습니다.
- `accepted: false`는 기업 로그인 요청의 명시적 업무 오류입니다. `accepted: null`은 로그인 성공·실패가 확정되지 않은 상태입니다.
- `external_auth_status`는 하나인증서 외부 인증 단계의 판정입니다. 외부 인증 성공만으로 기업 로그인 성공이 되지 않습니다.
- `processing_status: stopped`나 `session_saved: false`가 로그인 성공과 함께 반환될 수 있습니다. 후속 처리·저장 실패가 확인된 은행 성공을 지우지 않습니다. 중단의 종료코드는 `2`이며 업무 판정을 대신하지 않습니다.
- ID/PW 요청 기록에서는 사용자 ID·로그인 암호문·푸시 토큰을 제거합니다. 단계별 요청·응답과 쿠키는 데이터 홈의 `hana-corporate/sessions/<이름>/`에 0600 파일로 저장합니다. 이 기업 세션 파일에는 금고 암호화가 적용되지 않습니다. 하나인증서의 개인 API·PIN 검증 기록은 기존 identity에 암호화 보관합니다. 일반 출력에는 토큰·쿠키·서명·고객번호·응답 원문을 내보내지 않습니다.
- 시작한 로그인은 같은 기업 세션으로 재전송하지 않습니다. timeout·대기 상태·PIN 오류를 자동 재시도하지 않습니다. 결과를 확인한 뒤 사용자가 별도 새 세션을 준비할 수 있습니다.

기업 서비스 가입, 기업 ID 연결, 다중 서명 요청, 앱 업데이트/공지 확인이 필요하면 해당 상태에서 중단합니다. 휴대폰 앱 설치 정보 FDS 수집은 미구현이며 로그인 후 결과에 표시합니다. 출금계좌 정보·고객 확인의 로그인 후속 요청은 수행하며 ID/PW의 위 고객 확인 분기를 해석합니다. 인증서 로그인 경로의 추가 안내 분기는 아직 해석하지 않습니다. 기업 계좌·거래내역 조회 명령, 금융인증서 로그인, 결재·이체 명령은 아직 제공하지 않습니다. 자동 발급·다운로드·등록·OTP 변경·한도 변경도 수행하지 않습니다.
