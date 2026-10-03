# 하나인증서 설정·발급·이체

`fin`에서 하나인증서를 새로 발급하고, 암호화 저장소에 보관한 뒤 로그인·이체에 사용할 수 있는 경로입니다. **최근 웹 이용 기록에서 신규 발급·로그인·조회 성공과 원화 이체의 은행 실행 성공 응답을 확인했습니다.** 결과 재조회는 연결된 후보를 확인했지만 최종 이체 확정은 미확인입니다. 인증 분기·조회별 범위는 [실사용 확인표](banking-verification.md)를 참고하세요. 은행이 추가 화면이나 다른 인증을 요구하면 계속 진행하지 않습니다.

지원 범위는 1.0.27 서비스 설정, 국내 성인 기존 하나은행 고객(`regTyp=A`), 본인 휴대폰 SMS, 주민등록증 또는 운전면허증, 본인 하나은행 계좌 확인, 클라우드 업로드 없는 신규 발급입니다. 등록된 다른 기기와의 관계, 은행의 현재 발급 정책과 수락 여부는 확인되지 않았습니다. 공동인증서·OTP 발급이나 한도 변경을 대신 실행하지 않습니다.

## 1. 사용자 설치 패키지에서 공통 설정 추출

설치 패키지에는 사용자별 OneSign vault가 없습니다. 여기서 추출하는 것은 앱 인증 토큰, 숫자 키패드 MAC 상수, 발급 CA 공개 인증서와 SMS 앱 해시입니다. 사용자의 개인키·PIN·인증서는 발급 과정에서 별도로 생성됩니다.

본인이 확보한 `com.hanabank.oqf` 1.0.27 설치 패키지의 `base.apk`와 arm64 분할 파일을 준비합니다. 합쳐진 패키지에 필요한 세 항목이 모두 있으면 한 파일만 지정해도 됩니다. 추출기는 지정한 파일을 읽기만 하며 실행·휴대폰 접속·다운로드를 하지 않습니다. 내부 항목의 해시와 서명 인증서 식별자가 지원 버전과 다르면 거부합니다. 다른 버전을 강제로 사용하는 옵션은 없습니다.

```sh
fin hana setup extract --name hana-1027 \
  --apk /path/to/base.apk --apk /path/to/split_config.arm64_v8a.apk
fin hana setup configure --name hana-1027 \
  --android-sdk 35 --model YOUR_DEVICE_MODEL --width 1080 --height 2400 \
  --webview-user-agent 'YOUR_ANDROID_WEBVIEW_USER_AGENT' --timezone Asia/Seoul
fin hana setup status --name hana-1027
```

기기 속성 값은 본인 환경의 Android SDK 번호·모델·화면 픽셀·WebView User-Agent로 바꿉니다. 예시 값이 서버에서 허용된다는 뜻은 아닙니다. 기기 식별자와 앱 RSA 키는 `init`에서 새로 만들며 실제 휴대폰의 앱 저장소를 복사하지 않습니다. 숫자 키패드 암호화에는 OpenSSL 3가 필요합니다. Python HTTP·암호 연산만 사용하며 브라우저·Android 런타임은 필요하지 않습니다.

설정 파일은 `FINANCE_HOME/hana/settings/<이름>.json`에 0600 권한으로 저장됩니다. 사용자 비밀을 담는 인증서 저장소와 달리 공통 설정은 암호화하지 않습니다. 추출 파일을 공유하거나 제품 소스에 넣지 마세요.

## 2. 신규 발급

```sh
fin hana onesign init --name main --settings hana-1027
fin hana onesign enroll --name main --run enroll-1 \
  --kind resident --image /path/to/my-id-card.jpg
# 위 명령은 계획만 출력합니다. 실제 발급 절차를 시작할 때:
fin hana onesign enroll --name main --run enroll-1 \
  --kind resident --image /path/to/my-id-card.jpg --send
```

`init`에서 4자 이상의 저장소 암호를 입력합니다. 발급은 약관 확인 → 앱 인증 → SMS 요청·확인 → 가입 동의 → 신분증 확인 → 본인 계좌 확인 → 새 PIN 확인 → 인증서 발급·등록 → 가입 완료 순서입니다. SMS·계좌 비밀번호·PIN은 숨김 입력받으며, 인증서 발급 직전에 `발급`을 입력해야 합니다. SMS 확인은 180초 안에 진행합니다. 선택 상품은 신청하지 않고 기존 마케팅 동의가 없으면 미동의로 처리합니다.

신분증을 `fin idcard add`로 먼저 보관했다면 `--image` 대신 `--id-card 이름`을 지정합니다. `enroll`은 첫 원격 단계 전에 신분증 보관 암호와 현재 유효한 본인 신분증인지 확인을 받아 신분증을 열어 두므로, SMS 확인 뒤 신분증 입력을 기다리지 않습니다. 신분증 종류는 보관한 신분증을 따르며 `--kind`는 무시합니다. 자세한 보관 방법은 [신분증 보관](guide.md#신분증-보관)을 참고하세요.

```sh
fin hana onesign enroll --name main --run enroll-1 --id-card resident-card --send
```

이미지는 본인의 마스킹하지 않은 신분증 카드 영역 JPEG(가로 1024픽셀 이하, 8 MiB 이하)여야 합니다. CLI가 OCR을 수행하지 않으므로 카드의 이름·발급일·주민번호를 직접 확인해 입력합니다. 운전면허증은 `--kind driver`를 선택하고 면허번호도 입력합니다. 서버의 이미지·신원 확인을 통과해야 다음 단계로 진행합니다. 준비한 이미지 자체는 CLI가 삭제하지 않습니다.

단계별 실행이 필요하면 `onesign issue --stage STAGE --name main --run 새이름`을 사용합니다. 원격 단계에는 `--send`를 붙입니다.

```text
profile → authenticate → request-sms → verify-sms → consent → begin-id
→ prepare-id → identity → account → issue → complete
```

`identity`와 `account` 사이에 `list-accounts`를 따로 실행하면 발급용 본인계좌 목록을 암호화 저장합니다. 이후 `account`는 이 목록에서 선택하고 다시 조회하지 않습니다. `account`를 바로 실행하는 기존 방식도 유지하며, 이때는 목록을 한 번 조회한 뒤 선택합니다. 웹앱은 신분증 확인 후 목록을 불러와 같은 계좌 확인 화면에서 선택하게 합니다.

`prepare-id`에는 `--kind`와 `--image`, 또는 보관한 신분증의 `--id-card`를 지정합니다. 이미 시도한 원격 단계·실행 이름은 다시 사용할 수 없습니다. 정상적으로 완료된 단계 다음부터 진행할 수 있지만, 시간 초과·중단·실패한 단계를 자동으로 이어 보내지 않습니다. 새 이름으로 실행해도 같은 인증서의 중단된 발급을 재시도할 수 없습니다.

```sh
fin hana onesign inspect --name main
```

## 3. 새 세션 로그인과 계좌 확인

로그인한 세션은 `fin hana onesign extend --name main --send`로 한 번 연장할 수 있습니다. 저장소 암호만 사용하고 PIN을 다시 요구하지 않습니다. 세션이 여럿이면 `--session`으로 선택합니다. [명령·결과·검증 범위](session-extension.md)를 참고하세요.

가입 완료와 일반 서명 로그인은 별개입니다. 발급을 마친 뒤 새 세션에서 PIN으로 서명 로그인합니다.

```sh
fin hana onesign new-session --name main --session login-1
fin hana onesign login --name main --session login-1 --run login-1 --send
fin hana onesign accounts --name main --session login-1 --run accounts-1 --send
```

저장소 암호와 하나인증서 PIN은 서로 다릅니다. `--password-stdin`은 저장소 암호 한 줄만 받습니다. SMS·PIN·계좌 비밀번호·약관과 거래 확인은 대화형 터미널에서 받습니다.

`fin --format json-v1 hana ...`은 결과의 기계 판독 형식만 바꿉니다. PIN·확인 입력을 생략하거나 자동화하지 않습니다. 입력 제공자를 사용하는 프로그램은 CLI의 터미널 함수를 호출하지 않고 업무 함수에 해당 단계의 입력을 전달해야 합니다.

## 4. 단일 원화 즉시이체

PIN이 필요한 이체에서는 거래 확인과 PIN 입력을 마친 뒤 실행을 예약합니다. PIN 입력 중 Ctrl-C로 중단하면 준비 상태를 유지하고 서명 nonce나 이체 요청을 보내지 않습니다. 다시 확인할 때는 새 `--run` 이름을 사용합니다. nonce 요청 이후 중단이나 응답 유실은 재실행 사유가 아니며 기존 결과 확인 절차를 따릅니다.

이체 의도를 JSON 파일에 적습니다. 아래 계좌와 금액은 예시이므로 본인의 실제 의도로 바꿉니다.

```json
{
  "source_account": "12345678901234",
  "recipient_bank_code": "004",
  "recipient_account_number": "23456789012345",
  "amount_krw": 100
}
```

```sh
fin hana transfer prepare --name main --session login-1 --transaction payment-1 \
  --run prepare-1 --input /path/to/intent.json --send
fin hana transfer show --name main --transaction payment-1
fin hana transfer execute --name main --session login-1 --transaction payment-1 \
  --run execute-1 --send
fin hana transfer reconcile --name main --session login-1 --transaction payment-1 \
  --run reconcile-1 --send
```

`prepare`는 은행에서 수취인·수수료·계좌 분류·필요 인증을 받아 저장합니다. 타인 계좌 분기에서는 계좌 비밀번호를 확인합니다. `execute`는 수취인·출금 및 입금 계좌·금액·수수료를 표시하고 `이체 100원`처럼 금액을 포함한 확인을 받은 다음 한 번만 전송합니다.

- 서버가 허용한 `noAuth`는 등록된 외부 인증키로 서명합니다. PIN 재입력은 없지만 하나인증서 서명은 수행합니다.
- `pinHalf`는 PIN을 다시 입력받아 서명합니다.
- 서버가 본인계좌로 분류한 경로는 해당 전용 실행 요청을 사용합니다.
- OTP·SMS·ARS 등 추가 인증 요구는 `authentication_review`로 남기고 실행을 막습니다. 무OTP 여부를 사용자가 강제로 지정할 수 없습니다.

한 로그인 세션으로 한 이체만 준비합니다. 다음 이체에는 새 세션에서 로그인합니다. 실행 중 연결이 끊겼다면 완료 여부가 미확인일 수 있으므로 송금을 다시 보내지 마세요. `reconcile`은 같은 세션에서 실행일의 첫 20개 이체 내역과 연결된 상세를 한 번 조회합니다. 계좌·금액이 일치하는 완료 후보를 찾더라도 준비 거래번호와의 연결을 입증하지 못하면 `transfer_confirmed=false`로 남깁니다. `original_result_success`와 대조 결과는 별도입니다.

## 5. 다른 설치 환경으로 옮기기

```sh
fin hana onesign export-identity --name main --output /path/to/main.bundle
# 새 환경에서 공통 설정을 먼저 추출·구성한 후:
fin hana onesign activate --name restored --settings hana-1027 --bundle /path/to/main.bundle
fin hana onesign new-session --name restored --session login-1
```

v2 번들에는 앱 기기 식별자·앱 개인키·인증서의 보호된 키 기록이 들어갑니다. 클라우드 키는 선택 사항입니다. 저장소 암호로 봉인하며 PIN 평문·기존 쿠키·토큰·실행 기록·추출 설정은 넣지 않습니다. v1 호환 번들도 활성화할 수 있습니다. `import`·`export`는 기존 번들의 보관·바이트 복사 용도로 유지합니다.

인증서·신분증 입력·요청과 응답·세션은 `FINANCE_HOME/hana/identities/<이름>/`에 암호화해 저장합니다. 은행의 판정(`accepted`/`service_status`)과 CLI 처리 상태(`processing_status`)를 따로 기록합니다. `certificate_issued=true` 뒤 저장·등록이 중단되었다면 인증서가 이미 발급된 상태일 수 있습니다. 어느 경우에도 중단을 자동 재발급·재송금의 근거로 사용하지 않습니다.

## 웹앱에서 신규 발급

서버 설정을 준비한 뒤 웹앱 **연결·인증서 → 인증서 발급·가져오기 → 하나인증서**에서 저장소 초기화와 위 단계별 발급을 진행할 수 있습니다. 각 원격 단계의 통신 승인, 약관·SMS·신분증·본인 계좌·새 PIN·`발급` 확인은 웹 입력으로 받습니다. 저장소 암호와 계좌 비밀번호·PIN은 구별하며 기존 요청 순서와 재시도 금지를 유지합니다. 기존 저장소는 발급 진행 확인으로 다음 정상 단계만 확인할 수 있습니다. 중단된 발급을 자동 재개하지 않습니다. 상세한 입력·저장 경계는 [웹 인증서 안내](guide.md#웹앱에서-인증서-발급가져오기)를 참고하세요.
