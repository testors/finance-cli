# Finance CLI 사용자 가이드

`fin` 명령으로 공동인증서를 보관하고 홈택스·하나은행 작업을 실행하는 방법을 설명합니다. 설치와 지원 범위 표는 [README](../README.md)를 참고하세요. 현재 구현 범위는 `fin capabilities`로도 확인할 수 있습니다.

하나은행 기업 채널의 ID/PW·공동인증서·개인사업자 하나인증서 로그인은 `fin hana corporate`로 제공합니다. 공통 인증서 저장소를 재사용하고 개인 채널과 세션을 분리합니다. 현재 합성 검증 단계이며 [기업 로그인 사용법과 제한](hana-corporate.md)을 참고하세요.

기업 ID/PW 로그인은 `fin hana corporate login-idpw --user-id YOURID --send`로 실행하고 비밀번호를 숨김 입력합니다. 로컬 세션은 자동 생성하며 설치된 공통 키패드 설정을 재사용합니다.

> **먼저 알아둘 점**
> - 홈택스 명령은 현재 버전에서 **실서버 검증 전**입니다. 조회는 결과를 직접 대조하며 쓰고, 세금계산서 **발급은 실제 발급**이므로 특히 주의하세요.
> - 하나은행은 공동인증서 로그인·조회와 하나인증서 신규 발급·서명 로그인·원화 이체를 지원합니다. 하나인증서에는 사용자 서비스 설정이 필요하며, 최근 웹 이용 기록의 [기능별 실사용 확인 범위](banking-verification.md)를 제공합니다. → [하나은행](#하나은행), [하나인증서 시작하기](hana-onesign.md)

## 목차

1. [공통 규칙](#공통-규칙)
2. [인증서 관리](#인증서-관리) · [신분증 보관](#신분증-보관)
3. [하나은행](#하나은행)
4. [홈택스](#홈택스)
   - [준비](#준비) · [로그인](#로그인) · [세션 재사용](#세션-재사용) · [사용자·사업장](#사용자사업장) · [세금 조회](#세금-조회) · [신고 조회](#신고-조회) · [전자세금계산서](#전자세금계산서)
5. [웹앱](#웹앱)

## 공통 규칙

- **출력:** 업무 명령은 JSON을 표준출력으로 냅니다. 기본 형식은 기관별 기존 결과이며, 도움말·버전과 기본 형식의 인자 사용법 오류는 텍스트입니다. 자동화에는 아래의 `--format json-v1`을 사용할 수 있습니다. 경고·진행 안내는 stderr로 나갑니다.
- **종료코드:** 홈택스의 서비스 연결 명령은 서비스가 성공으로 판정하면 `0`, 실패로 판정하면 `1`, 입력·저장 경로 오류면 `2`, 판정을 관찰하지 못했으면 `3`입니다. 인증서 관리 명령의 오류는 `2`입니다. `3`은 실패가 아니라 **미확인**이므로 결과 파일을 보고 판단하세요.
- **비밀번호:** 숨김 입력으로 받습니다. `--password-stdin`은 공동인증서 명령에서는 인증서 비밀번호, 하나인증서 명령에서는 저장소/번들 암호 한 줄을 받습니다. 하나인증서 PIN·SMS·계좌 비밀번호와 거래 확인까지 받는 옵션은 아닙니다. 명령행 인자와 환경변수로는 비밀을 넘기지 않습니다.
- **연결 확인 `--send`:** 홈택스의 서비스 연결 명령(`login`, `session`, `account`, `business`, `tax`, `returns`, `report`, `invoice`)은 `--send`를 붙여야 실제로 접속합니다. 없으면 접속 없이 `send_required`로 멈춥니다.
- **출력 파일:** `--output`에는 항상 **아직 없는 새 경로**를 지정합니다. 덮어쓰지 않으며, 파일은 소유자만 읽고 쓰는 `0600` 권한으로 만들어집니다. 세션·결과 파일에는 쿠키와 개인정보가 들어 있으므로 Git 저장소 밖에 두세요.
- **데이터 위치:** `fin paths`로 확인합니다. 바꾸려면 `fin --home /절대/경로 ...` 또는 `FINANCE_HOME`을 씁니다.
- **도움말:** `fin --help`, `fin hometax <명령> --help`.

### 기계 판독용 출력

전역 옵션은 기관·명령 이름 앞에 둡니다. `--home`과 `--format`의 순서는 자유롭습니다. 기본값은 `--format legacy`이며, 기존 명령의 JSON 결과와 종료코드는 유지합니다.

```sh
fin --format json-v1 capabilities
fin --format json-v1 hana session list
fin --format json-v1 hometax tax dues --session /path/to/session.json --output /path/to/new-result.json --send
fin --format json-v1 giro bills list --type national --input /path/to/bills.json
```

`json-v1`은 다음 외곽 구조로 기존 결과를 감쌉니다. 아래는 홈택스 명령에서 `--send`를 생략한 예입니다.

```json
{
  "schema_version": 1,
  "service": "hometax",
  "exit_code": 2,
  "result": {
    "error": "send_required",
    "network_used": false,
    "message": "기관 연결 명령에는 --send가 필요합니다. 도움말로 입력을 확인하세요."
  }
}
```

- `service`는 `hana`, `hometax`, `giro` 또는 공통 명령의 `fin`입니다. `result`는 기존 JSON 값이며 객체·배열·문자열 등 원래 유형을 보존합니다.
- `exit_code`는 명령의 종료코드입니다. 업무 성공을 나타내는 공통 상태값이 아닙니다. 새 형식도 네트워크 동작·확인 절차·재시도 정책을 바꾸지 않습니다.
- 인자 사용법 오류는 `result.error: invalid_arguments`로 반환하며 잘못 입력한 값은 되풀이하지 않습니다. 홈택스의 처리 가능한 로컬 오류는 `local_input_or_processing_error`, `certificate_error`, `dependency_unavailable`로 구별합니다. 도움말과 `--version`은 이 형식에서도 텍스트입니다.
- 자식 프로세스가 결과 JSON을 반환하지 않으면 `result: null`과 `output_error.code: missing_result_json` 또는 `invalid_result_json`을 제공합니다. 자식의 종료코드를 보존하며, 파일이나 과거 결과로 업무 판정을 만들어 내지 않습니다. 종료코드가 0이어도 출력 오류가 있으면 업무 성공을 추정하지 않습니다.
- Ctrl-C는 이 형식에서 `result.error: interrupted`, 종료코드 `130`으로 표시합니다. 이는 업무 취소나 미전송을 보장하지 않습니다. 전송 가능성이 있으면 기록과 기관 결과를 확인하고 자동으로 재시도하지 않습니다.

| 기관·경로 | 업무 판정 | 종료코드 해석 |
| --- | --- | --- |
| 하나은행 | `accepted`, `service_status`, `execution_result`; `processing_status`는 별도 처리 상태 | 명시적 서비스 거절은 보통 `1`; 로컬 중단은 `2`이며 이미 받은 기관 성공과 함께 나타날 수 있음 |
| 홈택스 서비스 연결 | `branch`, `reason`; 문서·세션 저장 상태는 별도 | 성공 `0`, 실패 `1`, 입력·처리 오류 `2`, 판정 미관측 `3` |
| 홈택스 오프라인 응답 해석 | `branch`, `reason` 등 | `no_action`도 `0`일 수 있으므로 종료코드만으로 성공 판단 금지 |
| 지로 | `app_success`, `response_code`, `callback_code`, `origin`; 등록·로그인·저장 상태는 별도 | 응답 거절·입력 오류 `2`; 추가 준비 필요 `4`; 무통신 계획도 `0`을 반환하므로 업무 판정을 함께 확인 |

하나은행의 `accepted: true`와 `processing_status: stopped`를 모순으로 처리하지 않습니다. 이체 재조회에서 `candidate_complete: true`이더라도 `transfer_confirmed: false`이면 거래 연결은 미확인입니다. 기존 실행 판정은 재조회와 따로 보존합니다.

`json-v1`은 CLI의 기계 판독 형식이며 웹에 공개해도 되는 응답을 보장하지 않습니다. 홈택스 stdout은 요약이고, `--output` 파일은 결과와 쿠키·storage를 포함한 사용자 세션 자료입니다. 웹 API와 다운로드는 별도의 허용 목록을 거쳐야 합니다.

### 기관별 입력 차이

- 하나은행·홈택스의 `--credential`과 `--profile`은 하나만 지정합니다. 동시에 지정하면 인증서를 읽거나 암호를 묻기 전에 거절합니다. `--profile=personal` 형식도 지원합니다.
- 하나은행 `--session`은 저장소의 세션 이름이고 홈택스 `--session`은 사용자 세션 JSON 파일 경로입니다. 서로 바꿔 사용할 수 없습니다. 지로는 마지막으로 저장한 자체 로그인 세션을 사용하며 만료 시 자동 재로그인하지 않습니다.
- `--send` 생략 시 홈택스는 `send_required`로 중단하고, 하나은행·지로의 일부 명령은 계획·준비 결과를 반환합니다. 지로의 기존 `--live`도 유지합니다. 새 출력 형식이 준비나 업무 단계를 자동으로 실행하지 않습니다.

## 인증서 관리

인증서는 공통 금고 하나에 보관하고 홈택스·하나은행이 함께 씁니다. 홈택스는 인증서 **파일 경로를 직접 받지 않으므로** 먼저 금고에 가져와야 합니다. 금고는 scrypt와 AES-GCM으로 인증서를 다시 암호화하고, 인덱스에는 별칭·형식·인증서 지문만 남깁니다.

### 가져오기

```sh
# PFX 파일
fin cert joint import --name personal --pfx /path/to/certificate.pfx

# NPKI 파일 (signCert.der + signPri.key)
fin cert joint import --name personal --cert /path/to/signCert.der --key /path/to/signPri.key --compatibility hometax
```

- 입력한 비밀번호가 인증서 비밀번호이자 금고 암호화 비밀번호입니다. 이후 `show`, `export`, 로그인 때 같은 비밀번호로 엽니다.
- `--name`은 별칭입니다. 영문자·숫자로 시작하고 `_ . -`를 쓸 수 있으며 64자까지입니다. **인증서마다 다른 별칭**을 씁니다. 같은 별칭이나 이미 가져온 같은 인증서는 거부됩니다(`credential_name_exists`, `certificate_already_imported`).
- PFX 안에 서명용 인증서가 여러 개면 `--pfx-index 0`처럼 번호(0부터)를 지정합니다. 번호는 금고에 기록되어 이후 다시 지정하지 않습니다.
- NPKI의 암호 규칙은 `--compatibility hana`(기본) 또는 `hometax`로 고릅니다. 홈택스에서 쓸 인증서면 `hometax`를 붙입니다. 가져올 때 복호화를 검증하므로 잘못 고르면 저장 없이 오류가 납니다.
- 가져올 때 인증서와 개인키가 서로 맞는지 로컬에서 확인합니다. 서버와는 통신하지 않습니다. **유효기간은 확인하지 않습니다.** 가져온 파일은 수정하지 않습니다.

### 확인

```sh
fin cert list              # 별칭·형식·인증서 지문
fin cert show personal     # 비밀번호로 열어 인증서 정보와 유효기간 확인
```

`show`는 `expireDate`, `status`(`VALID`, `EXPIRE_IMMINENT`(30일 이내), `EXPIRED`), 정책 OID 등을 보여줍니다. 세금계산서 발급용 인증서는 쓰기 전에 `status`를 확인하세요. 폐기·CA 신뢰는 확인하지 않습니다(`revocation_checked: false`).

### 내보내기

```sh
fin cert export personal --output /path/to/new-export
```

가져온 파일을 **없는 새 디렉터리**에 가져온 그대로(바이트 단위로) 복원합니다. NPKI는 `signCert.der`와 `signPri.key`, PFX는 `certificate.pfx`가 만들어지며 PFX 내부 보호 형식도 그대로입니다. 복원된 파일은 개인키가 들어 있으니 용도가 끝나면 안전하게 지우세요.

### 프로필: 기관별 인증서 선택

같은 프로필 이름으로 기관마다 쓸 인증서를 지정해 두면 `--profile`만으로 선택할 수 있습니다.

```sh
fin profile set personal --service hometax --cert personal   # 로그인용
fin profile set tax --service hometax --cert invoice         # 세금계산서 발급용
fin profile set personal --service hana --cert personal
fin profile list
```

프로필 하나에는 기관별로 인증서 하나만 연결됩니다. 로그인용과 발급용 인증서가 다르면 프로필을 나눕니다. 프로필은 인증서 선택 설정일 뿐이며 세션을 만들거나 공유하지 않습니다. 명령에서는 `--profile 이름` 대신 `--credential 별칭`으로 직접 지정할 수도 있습니다.

위 설명은 현재 CLI의 동작입니다. 여러 은행과 개인·사업장·법인을 다루는 기관 로그인·업무 대상·업무 프로필은 [확장 설계](profiles-and-connections.md)에 정리되어 있으며 아직 구현되지 않았습니다. 확장 후에도 이 인증서 프로필과 `profiles.json` 형식은 그대로 유지됩니다.

별칭 변경과 삭제는 비밀번호 없이 인덱스만 다루며 인증서를 복호화하지 않습니다. 인증서 프로필이나 웹앱의 기관 로그인·서명 설정이 별칭을 참조하고 있으면 `credential_in_use`로 거절하고 참조 목록을 보여 줍니다. 먼저 그 설정의 인증서를 바꾸거나 연결을 지운 뒤 다시 실행하세요. 참조를 자동으로 고쳐 쓰지는 않습니다.

```sh
fin cert joint rename personal personal-2024   # 지문·개인키는 그대로, 별칭만 변경
fin cert joint remove personal-2024            # 인덱스 항목과 봉인된 파일 삭제
fin hana onesign rename --name main --new-name main2   # 하나인증서 저장소 이름만 변경; 실행 중이면 거절
fin hana onesign remove --name main            # 하나인증서 저장소 디렉터리 삭제; 실행 중이면 거절
```

### 신분증 보관

신분증도 인증서처럼 보관해 두고, 발급 단계에서 신분증을 요구하면 보관한 것을 골라 씁니다. 인증문자를 확인한 뒤에 사진을 찾고 번호를 입력하는 동안 기관 세션이 기다리다 시간이 초과되는 일을 막습니다. 현재는 하나인증서 신규 발급의 신분증 확인 단계에서 선택할 수 있습니다.

```sh
fin idcard add resident-card --image /path/to/my-id-card.jpg                # 주민등록증
fin idcard add driver-card --image /path/to/my-license.jpg --kind driver    # 운전면허증
fin idcard list                    # 이름·종류·신분증 발급일·보관 시각
fin idcard show resident-card      # 보관 암호로 열어 가린 정보 확인
fin idcard export resident-card --output /path/to/new-export
fin idcard rename resident-card card-2020
fin idcard remove card-2020
```

- `add`는 본인의 마스킹하지 않은 신분증 카드 영역 JPEG(8 MiB 이하)를 받고, "본인 신분증" 확인과 카드의 이름·발급일·주민번호(운전면허증은 면허번호도)를 터미널에서 입력받습니다. 번호와 보관 암호는 숨김 입력입니다. 이름이 이미 있거나 사진을 읽을 수 없으면 입력을 받기 전에 거절합니다.
- 보관할 때 번호·날짜 형식과 사진을 먼저 검사합니다. 사진은 회전 정보를 반영해 가로 1024픽셀 이하로 줄이고 EXIF 등 부가정보를 뺀 JPEG로 다시 만듭니다. 원본 파일은 수정하지 않습니다.
- 보관 암호(4자 이상)로 scrypt·AES-GCM 봉인합니다. 인덱스에는 이름·종류·신분증 발급일·보관 시각만 남고, 카드의 이름·주민번호·면허번호·사진은 봉인 안에만 있습니다. 인덱스의 종류나 발급일을 고치면 열리지 않습니다.
- `show`는 이름 첫 글자와 번호 일부만 보여 주고 사진은 크기만 표시합니다. `export`는 **없는 새 디렉터리**에 `card.jpg`(보관한 사진)와 `card.json`(종류·입력 정보)을 소유자 전용 권한으로 씁니다. 번호가 그대로 들어 있으니 용도가 끝나면 지우세요. `show`·`export`의 `--password-stdin`은 보관 암호 한 줄만 받습니다.
- `rename`·`remove`는 봉인을 열지 않으며 암호가 필요 없습니다. 기관 연결이 신분증을 참조하지 않으므로 참조 확인 없이 처리합니다.
- 발급 단계는 보관한 신분증을 쓸 때마다 보관 암호와 "보관 후 재발급받지 않은 현재 유효한 본인 신분증" 확인을 다시 받습니다. 신분증을 재발급받았다면 새로 보관하세요. 신분증 확인은 한 번만 보내는 단계라 옛 정보로 실패하면 그 발급을 이어갈 수 없습니다.

## 하나은행

`fin hana`는 공동인증서 로그인·조회와 하나인증서 발급·로그인·원화 이체를 제공합니다. 하나인증서는 별도의 암호화된 기기·인증서 저장소를 사용합니다.

| 기능 | 명령 | 통신 |
| --- | --- | --- |
| 세션 만들기 | `session new` | 없음 |
| 앱 인증 | `session authenticate` | `--send` |
| 공동인증서 로그인 | `login` | `--send` |
| 메인 계좌 목록 | `accounts` | `--send` |
| 이체 내역·상세·원장 | `inquiry history` / `detail` / `ledger` | `--send` |
| 일반 원화 계좌 거래내역 | `history clock` / `account` / `page` / `detail` / `export` | `detail`·`export`는 없음, 나머지 `--send` |
| 한도·보안매체·OTP 상태 | `security` + `limits`, `limit-exception`, `security-media`, `otp`, `otp-accident`, `mobile-otp` | `--send` |
| 로그인 연장 | `session extend` | `--send` |
| 하나인증서 vault 번들 | `onesign import` / `export` / `show` / `list` | 없음 |
| 하나인증서 설정·저장소 | `setup extract` / `configure`, `onesign init` / `activate` / `export-identity` / `rename` / `remove` | 없음 |
| 하나인증서 신규 발급 | `onesign enroll` 또는 `onesign issue` | 원격 단계에 `--send` |
| 하나인증서 로그인·조회 | `onesign new-session` / `login` / `accounts` | `login`·`accounts`에 `--send` |
| 하나인증서 원화 이체 | `transfer prepare` / `show` / `execute` / `reconcile` | `show` 외 `--send`; 실행 직전 내용 확인 |
| 오프라인 도구 | `plan`, `sign-login`, `encode-header`, `decode-header`, `joint-cert-tbs`, `joint-cert-body`, `login-body` | 없음 |

**하나인증서:** [설정·발급·이체 안내](hana-onesign.md)에 따라 새 인증서를 발급하거나 `activate`로 호환 번들을 가져와 사용합니다. 기존 `import`·`export`는 암호화 번들의 보관·복사 명령입니다. [번들 형식](onesign-bundle.md)은 v1과 클라우드 키가 선택 사항인 v2를 지원합니다.

**지원하지 않는 경로:** 클라우드 인증서 다운로드, 예외 가입·재발급 화면, 금융인증서 발급, OTP 발급·한도 변경. 이체는 단일 일반 원화 즉시이체를 지원하며 은행이 OTP·추가 인증을 요구하면 중단합니다.

**검증 상태:** 2026-09-30~2026-10-01 웹 작업 기록에서 하나인증서 발급·로그인·계좌·내역·이체한도 조회 성공과 이체 실행 성공 응답을 확인했습니다. 최종 이체 확정, 공동인증서 경로, 로그인 연장 등은 구분해 [실사용 확인표](banking-verification.md)에 기록했습니다. CLI 종료코드만으로 기관 성공을 추정하지 않습니다. 자동 테스트는 계속 합성 자료와 로컬 전송 계층만 사용합니다.

### 원칙

- 은행에 연결하는 명령은 `--send` 없이 실행하면 **준비만** 하고 접속하지 않습니다(`network_used: false`). 같은 명령에 `--send`를 붙여야 전송합니다. 준비 후 입력이 바뀌었으면 전송하지 않습니다.
- 요청은 **한 번만** 보냅니다. 자동 재시도, 자동 페이지 넘김, 로그인 갱신이 없습니다. 시도한 요청은 기록이 남아 같은 요청을 다시 보내지 않으며, 응답을 받지 못한 경우도 결과를 추정하지 않고 `failure.json`으로 남깁니다.
- 결과의 `accepted`는 서비스가 그 요청을 받아들였는지를 뜻합니다. 저장된 로그인이 지금도 유효한지는 확인하지 않습니다(`session_current_validity: unverified`).
- 종료코드는 `0`(준비 또는 서비스 수락), `1`(보낸 요청을 서비스가 받아들이지 않음), `2`(입력·기록 오류)입니다.
- 세션과 요청·응답 원문은 `fin paths`의 데이터 위치 아래 `hana/sessions/<이름>/`에 `0600` 권한으로 저장됩니다. 조회의 실행 기록은 `hana/runs/<이름>/`에 남습니다. 세션 하나는 로그인 하나에 대응하며, 만료되면 새 세션을 만들어 처음부터 진행합니다.

### 준비물

1. **금고의 공동인증서:** [인증서 관리](#인증서-관리)로 가져오고 `fin profile set personal --service hana --cert personal`로 연결합니다.
2. **앱 인증 프로필 파일:** 앱 인증 요청의 헤더 값을 담은 JSON입니다. 네 필드가 정확히 있어야 합니다.
   ```json
   {"system_header": {"CHNL_SYS_HDPT": {"...": "..."}},
    "channel_header": {"CNL_HDPT": {"...": "..."}},
    "secure_token": "앱 설정의 문자열",
    "profile_provenance": {"source": "값을 얻은 곳"}}
   ```
   `system_header`는 서비스 전문 공통 필드(`TRMS_SYS_CD`, `CHNL_TYP_CD` 등), `channel_header`는 단말·앱 정보(OS 버전, 모델명, 화면 크기, User-Agent, 앱 이름·버전, 시간대 등), `secure_token`은 앱 설정에 들어 있는 상수입니다. 이 값들은 패키지에 들어 있지 않고 추측해서 채우지도 않으므로, 앱 인증에 성공했던 프로필을 그대로 지정합니다. 인증 자료가 들어 있으니 Git 저장소 밖에 두세요.
3. **로그인 입력 파일:** `{"push_token": "...", "fakefinder_install_id": "...", "input_provenance": {"source": "..."}}`.

### 로그인부터 계좌 조회까지

```sh
fin hana session new --session main
fin hana session authenticate --session main --profile-file /path/to/app-profile.json
fin hana session authenticate --session main --profile-file /path/to/app-profile.json --send
fin hana login --session main --profile personal --login-input /path/to/login-input.json
fin hana login --session main --profile personal --login-input /path/to/login-input.json --send
fin hana accounts --session main
fin hana accounts --session main --send
fin hana session list
```

- `session authenticate --send`는 register → first-access → access-token을 차례로 보내며, 서비스가 받아들이지 않은 단계에서 멈춥니다(`stopped_at`).
- `login --send`는 nonce 요청 → 금고 인증서로 로컬 서명 → 로그인을 차례로 보냅니다. 인증서 비밀번호는 전송 직전에 물어보며(`--password-stdin` 가능) nonce를 요청하기 전에 인증서를 먼저 열어 확인합니다. 로그인이 수락되면 세션에 로그인 기록이 저장됩니다.
- `accounts --send`는 메인 계좌 목록을 조회해 `account-selection.json`을 만듭니다. 이후 조회는 이 목록의 `index`(1부터)로 계좌를 고릅니다.
- `session list`는 세션 이름과 앱 인증·로그인 기록 여부만 보여 줍니다(토큰은 출력하지 않음).

### 거래내역 조회

조회 조건 파일(`query.json`)을 만듭니다.

```json
{"account_index": 1, "start_date": "20260901", "end_date": "20260929"}
```

**이체 내역 (`inquiry`)** — 기간은 오늘(KST) 기준 최근 2년 이내여야 합니다.

```sh
fin hana inquiry history --session main --input query.json
fin hana inquiry history --session main --input query.json --send
fin hana inquiry history --session main --input query.json --previous <이전 기록 이름>   # 다음 페이지 준비
fin hana inquiry detail  --session main --input query.json --previous <history 기록 이름> --row 1
```

**일반 원화 계좌 거래내역 (`history`)** — 서버 시각과 계좌 정보를 먼저 조회한 뒤 페이지를 넘깁니다. 조건 파일에 `direction`(`all`, `deposit`, `withdrawal`), `order`(`desc`, `asc`), `search`(25자 이내)를 더할 수 있습니다.

```sh
fin hana history clock   --session main --input query.json --send
fin hana history account --session main --input query.json --send
fin hana history page    --session main --input query.json --clock <clock 기록> --account-info <account 기록> --send
fin hana history page    --session main --input query.json --clock <clock 기록> --account-info <account 기록> --previous <page 기록> --send
fin hana history detail  --session main --input query.json --clock <clock 기록> --account-info <account 기록> --previous <page 기록> --row 1
fin hana history export  --session main --previous <마지막 page 기록> --output /path/to/new-history.json
```

- 각 명령은 먼저 `--send` 없이 실행해 준비 결과를 확인하고, 출력의 `receipt_directory`가 다음 명령의 `--clock`, `--account-info`, `--previous`에 넣는 **기록 이름**입니다.
- 다음 페이지는 저장된 응답의 커서에서만 만들어집니다. 마지막 페이지이거나 커서가 이상하면 준비 단계에서 멈춥니다.
- `history detail`은 저장된 행에서 은행 조회 없이 상세를 만들 수 있는 경우가 있고, 그때는 통신하지 않습니다.
- `history export`는 통신 없이 저장된 페이지를 `.json`과 같은 이름의 `.csv`로 내보냅니다. 중복 행은 지우지 않고, 수식으로 읽힐 수 있는 문자열 셀에는 `'`를 붙입니다. 한 시점의 스냅샷임을 보장하지는 않습니다(`atomic_snapshot_verified: false`).

### 보안매체·한도 상태와 로그인 연장

```sh
fin hana security limits --session main --run limits-1
fin hana security limits --session main --run limits-1 --send
fin hana session extend --session main --run extend-1 --send
```

- `security`는 `limits`(이체한도), `limit-exception`, `security-media`, `otp`, `otp-accident`, `mobile-otp` 중 하나를 조회하며 상태를 바꾸지 않습니다. `--run` 이름은 준비와 전송에 같은 값을 쓰고, 결과는 `hana/runs/<이름>/observation.json`에 저장됩니다.
- `session extend`는 저장된 로그인의 연장을 한 번 요청합니다. 새 `--run`에 `--send`를 붙이면 준비와 전송을 한 번에 합니다. 서버의 만료 시각은 추정하지 않으며 저장된 로그인 기록을 바꾸지 않습니다.

#### 이체한도 결과 읽기

CLI stdout은 조회 판정과 결과 파일 위치를 알려주는 JSON입니다. `--format json-v1`도 같은 결과를 감쌀 뿐, 금액을 한국어 문장으로 바꾸지는 않습니다. 결과 파일의 `observation.fields`는 은행 조회값, `observation.display`는 원본 앱의 표시 규칙으로 계산한 안내입니다. 두 객체를 합쳐서 개인 한도로 해석하지 마세요.

| 결과 파일의 필드 | 의미 |
| --- | --- |
| `observation.fields.bot1TrnsLimAmt` | 은행에서 조회한 **1회 이체한도**, 원 단위 |
| `observation.fields.dd1TrnsLimAmt` | 은행에서 조회한 **1일 이체한도**, 원 단위 |
| `observation.fields.scrtMdclDvCd` | 보안매체 구분. 문자열 `"1"`은 보안카드(자물쇠카드), `"2"`는 OTP 구분 |
| `observation.fields.mbphOtpYn` | 모바일 OTP 여부. `"Y"`는 해당, `"N"`은 해당하지 않음 |
| `observation.fields.trnsLimRslt` | 문자열 `"true"`일 때 이체한도 예외신청 안내 표시. 조회 실패나 예외신청 완료 여부가 아님 |
| `observation.display.medium` | 안내 기준: `card`는 보안카드, `mobile`은 모바일 OTP, `otp`는 OTP |
| `observation.display.once_ceiling_text` | 해당 보안매체의 **1회 기본 안내 한도**, 원 단위 |
| `observation.display.daily_ceiling_text` | 해당 보안매체의 **1일 기본 안내 한도**, 원 단위 |
| `observation.display.exception_prompt` | 예외신청 안내를 표시할 조건. `false`는 조회 실패가 아님 |

금액의 숫자·문자열 형태와 누락·`null`은 그대로 보존합니다. 누락·`null`을 0원으로 해석하지 않습니다. 안내 한도는 원본 앱에 정해진 보안매체별 값이므로 은행 조회값을 잘라내거나 단위를 나누는 근거로 사용하지 않습니다. 조회값이 안내 한도보다 커도 실제 이체 가능 금액이 그만큼이라고 확정할 수 없습니다. `accepted: true` 역시 조회 응답의 수용을 뜻하며 그 금액의 이체 승인을 뜻하지 않습니다.

`display.medium`은 원본 앱의 기본 분기를 보존하므로 보안매체 필드가 누락되어도 `otp`가 될 수 있습니다. 실제 등록 매체는 `fields`로 확인해야 합니다. 웹앱은 이런 경우 **확인 안 됨**으로 표시하며 안내 한도를 개인 한도와 구분합니다. `trnsLimRslt`의 문자열 `"true"`와 JSON 불리언 `true`도 원본 앱과 같이 구별합니다.

### 오프라인 도구

```sh
fin hana plan
fin hana sign-login --profile personal --nonce SERVER_NONCE --output /path/to/new-signature.der
```

- `plan`은 로그인 요청 순서와 이 패키지에 없는 항목을 출력합니다(접속 없음). 출력의 `live_verified: false`는 오프라인 조립 결과에 붙는 표시입니다.
- `sign-login`은 사용자가 직접 확보한 nonce를 금고 인증서로 CMS 서명해 DER 파일로 저장합니다. 결과는 `signed: true`, `network_used: false`, `bank_accepted: null`이며 은행이 받아들였는지는 확인하지 않습니다.
- `encode-header`, `decode-header`, `joint-cert-tbs`, `joint-cert-body`, `login-body`는 표준입력의 JSON·문자열을 요청 헤더·본문 형식으로 바꿉니다.

## 홈택스

### 준비

홈택스의 서비스 연결은 Node.js로 실행하며 세금계산서 발급의 XML 서명에는 JDK가 필요합니다.

```sh
fin runtime status hometax    # Node·npm 위치와 런타임 설치 여부 (접속 없음)
fin runtime install hometax   # 고정된 npm 의존성을 사용자 데이터 영역에 설치 (npm 다운로드 통신)
```

- Node.js 22.22.2 이상(22.x), 24.15 이상(24.x), 또는 26 이상과 npm.
- 세금계산서 발급에는 JDK 17 이상.
- Chromium 같은 브라우저는 실행하지 않습니다. 다만 Node의 jsdom(DOM 에뮬레이터)이 홈택스가 내려주는 페이지 스크립트를 수정 없이 실행합니다. 로그인의 보안 본문과 화면 함수가 이 스크립트에 있어 현재는 Node·npm 없이 홈택스를 쓸 수 없습니다. 하나은행·모바일지로는 Node가 필요하지 않습니다.
- 보고서 이미지 검사와 HTML 파일 생성은 Python/Pillow로 처리합니다. Pillow는 자동 설치되며 npm의 `pngjs`·`jpeg-js`는 필요하지 않습니다. 서비스 뷰어의 SVG 생성에는 계속 Node/jsdom이 필요합니다.

### 로그인

```sh
fin hometax login --profile personal --output /path/to/new-session.json --send
# 또는 --credential personal
```

- 인증서 비밀번호를 물어봅니다(`--password-stdin` 가능). `--timeout`(기본 180초)으로 대기 시간을 조절합니다.
- 표준출력에는 요약(`branch`, `session_file`, `session_binding_observed`, `session_file_saved`)만 나오고, 세션은 `--output` 파일에 저장됩니다.
- 판정은 서비스 응답 그대로입니다. 로그인이 `success`여도 후속 세션 바인딩을 관찰하지 못하면 경고가 붙습니다. 자동 재시도는 하지 않습니다.
- 접속 없이 서명 요청만 미리 만들어 보려면 `fin hometax auth prepare-cert --profile personal --output /path/to/new-preparation.json`을 씁니다(`--send` 불필요, 네트워크 요청 0건). 두 명령 모두 `--app-version`(기본 `14.3`)으로 서비스에 알리는 앱 버전을 바꿀 수 있습니다.
- 서버와 통신하지 않고 로그인 흐름을 검토하는 도구도 있습니다. `fin hometax auth replay {cert-register|cert-login|logout|qr-confirm|fido-auth} --input 응답.json`은 저장해 둔 응답 JSON에서 서비스의 성공·실패 분기를 재현하고, `auth encode-cert-callback`, `auth fido-context`, `auth cert-request`는 각각 `--input` JSON을 콜백 문자열·FIDO context·논리 요청으로 변환합니다(`--input` 생략 시 stdin).

### 세션 재사용

이후 명령은 로그인 결과 파일을 `--session`으로 받습니다. 세션이 만료됐을 수 있으면 먼저 확인합니다.

```sh
fin hometax session resume  --session /path/to/session.json --output /path/to/new-session2.json --send   # 저장 쿠키로 세션 확인
fin hometax session refresh --session /path/to/session.json --output /path/to/new-session2.json --send   # 복구 후 SSO 토큰 재취득
```

조회·발급 명령의 `--output` 파일에도 갱신된 세션(쿠키·저장소)이 함께 저장됩니다. 세션을 자동으로 고르거나 갱신하지 않으므로, 어느 파일을 다음 `--session`으로 쓸지는 직접 지정합니다. 명령마다 `--output`은 새 경로여야 하므로 결과 파일 이름을 순서대로 붙이면 편합니다.

### 사용자·사업장

```sh
fin hometax account show   --session S.json --output /path/to/new-account.json --send [--domain pp|ht]
fin hometax business list  --session S.json --output /path/to/new-business.json --send [--status 1|2|3|4]
fin hometax business select --session S.json --output /path/to/new-selected.json --send --tin TIN
```

- `business list`의 `--status`: `1` 전체, `2` 계속사업자(기본), `3` 휴업, `4` 폐업.
- `business select`는 조회한 사업장의 `tin`을 지정하며, 개인으로 돌아갈 때는 `--tin ORIGIN`입니다. 선택 결과의 세션 파일을 이후 명령에 넘겨야 사업장이 유지됩니다.

### 세금 조회

```sh
fin hometax tax dues     --session S.json --output /path/to/new-dues.json --send
fin hometax tax payments --session S.json --output /path/to/new-payments.json --send --from 20260101 --to 20260930 --all-pages
fin hometax tax refunds  --session S.json --output /path/to/new-refunds.json --send
fin hometax tax notices  --session S.json --output /path/to/new-notices.json --send
```

| 명령 | 내용 | 주요 옵션 |
| --- | --- | --- |
| `tax dues` | 납부할 세액 | — |
| `tax payments` | 납부 내역 | `--from`/`--to`(`YYYYMMDD`), `--page`, `--all-pages`, `--payment-type`(`01` 전체(기본), `03` 홈택스) |
| `tax refunds` | 환급금 | `--from`/`--to`, `--page`, `--all-pages`, `--refund-status`(빈 값 전체, `1` 지급완료, `2` 미수령, `3` 1년 경과 미수령) |
| `tax notices` | 전자고지 | `--from`/`--to`, `--notice-type`(`01` 고지서, `02` 독촉장), `--read-status`(`all`, `01` 열람, `02` 미열람(기본)), `--tax-code` |

- 표준출력 요약의 `item_count`와 `branch`를 먼저 보고, 자세한 내용(`data`)은 `--output` 파일에서 확인합니다.
- 기간을 생략하면 서비스 화면의 기본값을 씁니다. `--timeout`(기본 60초)은 단계별 대기 시간입니다.
- 네 명령 모두 `--tin TIN`을 지정하면 같은 실행에서 사업장을 확인·전환한 뒤 조회합니다. 개인으로 돌아가려면 `--tin ORIGIN`을 사용합니다. 생략하면 현재 세션의 대상으로 조회합니다. 같은 대상이면 전환하지 않으며, 지정한 대상을 확인하지 못하면 세액 조회를 시작하지 않습니다.
- `--timings`를 추가하면 요약 JSON의 `timings`에 `session.open`(초기화), 필요한 경우 `business.select`(전환), `tax.dues` 등 조회 단계의 `duration_ms`가 표시됩니다. 조회 시간에는 서비스 화면 진입·권한 확인이 포함됩니다. 이 시간은 결과 파일에도 기록되며, 옵션을 생략한 표준출력 형식은 그대로입니다.

```sh
fin hometax tax dues --session S.json --output /path/to/new-dues.json --tin TIN --timings --send
```

웹앱의 세액·납부 내역·환급금·전자고지 조회도 이 경로를 사용합니다. 사용자 확인과 조회를 한 실행에서 처리해 반복 초기화를 줄이며, 작업의 `local.timings`에 단계별 시간을 남깁니다.

### 신고 조회

```sh
fin hometax returns list   --session S.json --output /path/to/new-returns.json --send [--tax-code CODE] [--all-pages]
fin hometax returns status --session S.json --output /path/to/new-status.json --send [--year 2026 --month 5]
fin hometax returns forms  --session S.json --output /path/to/new-forms.json  --send --return-id ID
fin hometax returns receipt  --session S.json --output /path/to/new-receipt-dir  --send ...
fin hometax returns document --session S.json --output /path/to/new-document-dir --send [--form-code CODE | --all-forms] ...
```

- `list`는 신고내역, `status`는 전자신고 접수 결과, `forms`는 제출서식 목록입니다. 신고내역은 서비스가 한 페이지에 한 건씩 보여 주므로 전체가 필요하면 `--all-pages`를 씁니다.
- `--taxpayer`(납세자 선택), `--query-source list|status`, `--from`/`--to`, `--department-user`, `--disclose Y|N`으로 조회 조건을 좁힙니다. 생략한 조건은 서비스 화면의 기본값을 씁니다.
- `receipt`, `document`는 `--output`에 **새 디렉터리**를 만들고 서비스 보고서를 이미지가 포함된 독립 HTML로 저장합니다(`index.html`, `result.json`). 파일마다 `완전`/`확인 필요` 표시가 있으니 저장 결과를 확인하세요.
- 확보해 둔 보고서 화면 캡처가 있으면 `fin hometax report save --capture capture.json --output /path/to/new-dir --send`로 HTML 보고서만 다시 저장할 수 있습니다.

### 전자세금계산서

조회, 초안 작성, 실제 발급이 분리되어 있습니다.

| 단계 | 명령 | 발급 여부 |
| --- | --- | --- |
| 목록 조회 | `invoice list` | 조회만 |
| 상세 조회 | `invoice detail` | 조회만 |
| 초안 작성 | `invoice prepare` / `invoice amend` | 서비스 미리보기까지, **발급하지 않음** |
| 발급 | `invoice issue` | **실제 발급** |

#### 조회

```sh
fin hometax invoice list   --session S.json --output /path/to/new-list.json --send --direction sales --from 20260901 --to 20260930 --all-pages
fin hometax invoice detail --session S.json --output /path/to/new-detail.json --send --approval-number 승인번호24자리
```

`invoice list` 옵션:

| 옵션 | 의미 |
| --- | --- |
| `--direction` | `sales` 매출(기본), `purchases` 매입. 서비스 코드도 허용 |
| `--from`, `--to` | 조회 기간(`YYYYMMDD`) |
| `--date-type` | 서비스 조회일자 구분 |
| `--invoice-type` | `01` 전자세금계산서(기본), `03` 전자계산서 |
| `--classification` | `all` 전체(기본), `01`/`02` 세금계산서/수정, `03`/`04` 계산서/수정 |
| `--kind` | `all` 전체(기본), `01` 일반, `02` 영세율 등 서비스 코드 |
| `--issuance-type` | 서비스 발급유형 코드(`all` 기본) |
| `--counterparty-type` | `01` 사업자(기본), `02` 개인, `03` 외국인 |
| `--counterparty-number`, `--counterparty-name`, `--branch-number` | 거래 상대방 조건 |
| `--page`, `--all-pages` | 페이지 지정 또는 전체 조회 |

#### 초안 작성: `invoice prepare`

초안 내용을 JSON으로 만들어 넘깁니다. 명령은 서비스 화면의 단계(공급자 저장 → 공급받는자 사업자번호 확인·저장 → 품목 저장 → 결제구분 저장)를 실제로 진행하고 발급 직전 미리보기에서 멈춥니다.

```json
{
  "supplier": {"name": "상호", "representative": "대표자", "address": "주소",
               "business_type": "업태", "business_item": "종목", "branch_number": "", "email": "a@example.com"},
  "buyer": {"business_number": "123-45-67891", "name": "상호", "representative": "대표자", "address": "주소",
            "business_type": "업태", "business_item": "종목", "branch_number": "",
            "email": "b@example.com", "secondary_email": ""},
  "date": "20260901",
  "remark": "비고",
  "items": [
    {"month": "09", "day": "01", "name": "품목", "specification": "", "quantity": 1,
     "unit_price": 100, "supply_amount": 100, "tax_amount": 10, "remark": ""}
  ],
  "settlement": {"cash": "", "check": "", "note": "", "credit": "110", "type": "receipt"}
}
```

- 모든 항목이 선택 사항이지만 공급받는자 `business_number`는 서비스가 사업자번호를 조회하므로 사실상 필요합니다. 생략한 항목은 서비스 화면의 기본값을 씁니다.
- `settlement.type`: `claim`(또는 `02`)이면 청구, 그 밖의 값은 영수입니다.
- 서비스가 금액 계산을 화면에서 하므로 `tax_amount`를 넣으면 화면 입력처럼 그대로 들어가며, CLI가 반올림하지 않습니다.

```sh
fin hometax invoice prepare --session S.json --input /path/to/draft.json --output /path/to/new-prepared.json --send
```

- 성공하면 결과의 `reason`이 `original_preview_ready`이고 `data.draft`에 서비스 초안이 들어 있습니다. **발급 전에 `--output` 파일의 `data.draft`(공급자·공급받는자·품목·금액)를 직접 검토하세요.**
- 서비스 대화상자가 뜨면 그 내용이 결과 파일의 `original_dialog`에 남고 명령은 멈춥니다. `data.stage`는 멈춘 화면입니다.

#### 수정 초안: `invoice amend`

```sh
fin hometax invoice amend --session S.json --approval-number 승인번호 --reason amount-change --input /path/to/changes.json --output /path/to/new-amend.json --send
```

- `--reason`: `correction`(01), `amount-change`(02), `return`(03), `cancellation`(04), `local-credit`(05), `duplicate`(06). 서비스 코드도 허용합니다. `--approval-number`는 수정할 당초 계산서의 승인번호입니다.
- `--input`은 선택 사항이며 `prepare`와 같은 형식에서 바꿀 항목만 넣습니다. 서비스 화면에서 잠긴 항목은 바꾸지 않고 경고를 남깁니다.
- 이 명령도 미리보기에서 멈추며 발급하지 않습니다. `correction`(01)과 `local-credit`(05)은 서비스가 두 건(취소·재발급)으로 진행하며 결과 파일의 `document_count`가 `2`입니다. 발급하면 결과에 `cancellation_approval_number`와 `replacement_approval_number`가 나옵니다. 나머지는 한 건입니다.

#### 발급: `invoice issue`

```sh
fin hometax invoice issue --prepared /path/to/new-prepared.json --profile tax --output /path/to/new-issued.json --send
# 또는 --credential invoice
```

- `--prepared`는 `prepare` 또는 `amend`의 결과 파일입니다. 세션은 그 파일의 것을 쓰며, 다른 세션을 쓰려면 `--session`을 지정합니다.
- **명령을 실행하면 서비스의 발급 확인을 진행하고 실제로 발급합니다.** 발급을 되돌리는 명령은 없으며, 이미 발급한 계산서를 바로잡으려면 위의 `invoice amend`로 수정 발급을 따로 진행해야 합니다.
- 발급용 인증서 비밀번호를 물어봅니다(`--password-stdin` 가능). 인증서는 전자세금계산서 발급용이어야 하고 유효기간이 남아 있어야 합니다. 조건에 맞지 않으면 `original_certificate_not_selectable`로 발급 요청 전에 멈춥니다.
- **초안 파일당 한 번만 시도합니다.** 요청 전에 `<prepared 파일>.issue-attempt` 표시 파일을 만들고, 이미 있으면 서버에 접속하지 않고 `previous_issuance_attempt`로 끝납니다. 결과가 불확실해도 자동 재시도는 없습니다.
- 초안이 서비스 미리보기(`original_preview_ready`)가 아니거나 현재 사업장이 초안 작성 때와 다르면 발급하지 않습니다(`original_preview_required`, `prepared_business_context_changed`).

결과 파일의 `branch`와 `reason`은 서비스가 준 판정을 따릅니다.

| `reason` | 의미 |
| --- | --- |
| `original_email_result` | 서비스의 메일 발송 결과까지 관찰됨(그 판정이 `branch`). 승인번호는 `data.approval_number` |
| `original_storage_result` | 서비스의 저장 결과 판정(메일 단계가 없는 수정 발급 포함) |
| `original_certificate_rejected`, `original_xml_result`, `original_xml_signature_missing`, `original_xml_empty` | 인증서·XML 서명 단계에서 서비스가 실패로 판정 |
| `local_certificate_preflight_incomplete` | 인증서·비밀번호·로컬 XML 서명을 확인하지 못해 **발급 요청 전에** 중단 |
| `issuance_completion_unobserved` | 발급 완료 여부를 관찰하지 못함. 실패로 단정하지 않음 |

`issuance_completion_unobserved`처럼 결과가 불확실하면 **다시 발급하지 말고** `invoice list`나 `invoice detail`로 승인번호가 생겼는지 먼저 확인하세요. 같은 초안을 다시 시도하려 해도 표시 파일 때문에 막히며, 새 초안을 `prepare`로 다시 만들면 중복 발급될 수 있습니다.

### 지원 범위와 검증 상태

| 기능 | 상태 |
| --- | --- |
| 공동인증서 로그인 | 공통 금고의 RSA 인증서 경로를 지원하며 현재 패키지의 실서버 검증 전입니다. ID/비밀번호, 간편인증, FIDO, RSA가 아닌 인증서는 지원하지 않습니다. |
| 세션 확인·갱신, 사용자·사업장, 세금 조회 | 구현되어 있으며 현재 패키지의 실서버 검증 전입니다. |
| 신고 조회·접수증·신고서 저장 | 구현되어 있으며 현재 패키지의 실서버 검증 전입니다. 세목과 서식별 지원 차이가 있을 수 있습니다. |
| 세금계산서 조회 | 매출·매입 조회가 구현되어 있으며 현재 패키지의 실서버 검증 전입니다. |
| 세금계산서 초안·수정·발급 | 로컬 TLS 서버로만 검증했고 **실서버 발급은 검증하지 않았습니다.** 일반 과세, 사업자 간 거래, 공동인증서 경로만 다룹니다. 영세율·면세, 위수탁, 종사업장 선택, 휴폐업 구매자 안내, 개인 구매자, 금융인증서·간편인증 발급은 지원하지 않습니다. 수정 발급도 일반 과세·사업자 거래의 여섯 사유만 다루며, 서비스가 품목 4개 초과와 위수탁 거래의 수정을 막습니다. |
| 신고·납부·현금영수증 | 지원하지 않습니다. |

`tax dues`는 서비스 중지 시간대(00:00–06:59, 23:30–23:59)에 서비스가 중지 응답을 보내며, 업무 조회 전에 멈춥니다. 이는 로그인 실패나 납부 대상 0건이 아닙니다. 세션은 유지되므로 시간대를 피해 다시 실행하세요.

### 문제 해결

| 증상 | 확인할 것 |
| --- | --- |
| `send_required` | 서비스 연결 명령에 `--send`를 붙였는지 |
| `credential_not_found`, `profile_service_not_configured` | `fin cert list`, `fin profile list`로 별칭·프로필 확인 |
| `incorrect_password_or_damaged_credential` | 가져올 때 입력한 비밀번호와 같은지 |
| `symlink_not_allowed` | 데이터 위치(`--home`, `FINANCE_HOME`) 경로에 심볼릭 링크가 없는지. macOS의 `/var/...` 대신 `/private/var/...`처럼 실제 경로를 쓰세요 |
| 종료코드 `2` | 입력·저장 경로 오류. `--output`이 이미 있는 경로인지 확인 |
| `resource_busy` | 다른 홈택스 작업(웹앱·에이전트 포함)이 실행 중입니다. 홈택스 명령은 기관 단위로 하나씩 실행하며 CLI는 기다리지 않고 바로 멈춥니다 |
| 종료코드 `3` | 서비스 판정을 관찰하지 못함. 결과 파일의 `warnings`, `reason` 확인 |
| Node 관련 오류 | `fin runtime status hometax` 후 필요하면 `fin runtime install hometax` |

## 모바일지로

CLI에 기기 등록·PIN 로그인·세금 조회·등록계좌 국세 단건 납부를 연결했습니다. **실서버 업무 수락은 아직 검증하지 않았습니다.** 준비된 개인 보호 입력 자료와 현재 유효한 수신자 인증서·CRL 캐시가 필요합니다. 웹앱의 지로 인증·납부는 아직 지원하지 않습니다.

등록은 SKT·LG U+ 계열(알뜰폰 포함)의 기존 개인 회원을 지원합니다. SMS 본인확인, 필요한 경우 기존 로그인 PIN 확인, 새 PIN 등록을 거친 뒤 로그인 PIN을 입력받아 같은 연결에서 로그인합니다. KT 계열 인증서 추가 확인·신규 회원가입은 지원하지 않습니다. CLI 기기를 등록하면 기존 휴대폰 등록이 바뀔 수 있습니다.

먼저 준비된 개인 자료를 설치합니다. 보호 입력 자료는 저장된 기기 상태를 재사용하므로 현재 휴대폰의 새로운 관측을 뜻하지 않습니다. 설치본은 Android 실행 환경 없이 Python으로 계산합니다. 자료와 세션은 공통 데이터 디렉터리의 `giro` 아래에 두며, 기존 자료를 자동 덮어쓰지 않습니다.

업무 HTTP 헤더에는 자료에 저장된 기기 모델·Android 버전과 명시적인 `http_os_name`을 사용합니다. `http_os_name_source`는 직접 관측한 값(`observed`)과 정적 분석으로 추정한 값(`static-inference`)을 구별합니다. 실행 서버의 OS를 자동 대입하지 않습니다. 이 항목이 없는 기존 자료는 업무 인증 전에 다시 준비해야 합니다.

```sh
fin giro auth install-profile --input /path/to/private-protection.json
fin giro auth register                         # 무통신 계획
fin giro auth register --carrier SKT --send     # 약관·SMS·PIN을 터미널에서 입력
fin giro auth login --send                     # 이미 CLI를 등록했다면 PIN 로그인만
fin giro bills list --type national --send
fin giro bills due --type local --within-days 7 --send
fin giro bills list --type customs --send
fin giro payment pay --send                    # 국세 선택·계좌/금액 확인 후 단건 납부
fin giro receipts list --start-date 2026-10-01 --end-date 2026-10-03 --send
```

기본 공개 자료 캐시는 `giro/public-trust`입니다. 다른 캐시는 인증 명령의 `--public-cache`로 지정합니다. `--send`를 생략한 인증·조회·납부 명령은 입력·세션 접근 없이 계획만 반환합니다. 개인정보·SMS·로그인 PIN 6자리와 계좌 비밀번호 4자리는 대화형 터미널에서 숨겨 입력하며 인자나 환경변수로 받지 않습니다.

CLI 식별자는 첫 요청 전에 생성해 `giro/enrollment`에 보관합니다. 같은 등록 시도 기록에서 자동 재전송하지 않습니다. 등록 성공 뒤 로그인 실패나 저장 오류가 발생해도 등록 성공은 유지합니다. 로그인 세션의 키·쿠키는 AES-GCM으로 암호화하고, 저장용 키와 세션 파일 모두 0600 권한으로 보관합니다. 저장용 키도 같은 사용자 계정에서 접근할 수 있으므로 계정 자체가 탈취된 경우까지 보호하지는 않습니다. PIN과 보호 토큰은 저장하지 않습니다.

등록 성공 후 로그인만 실패했다면 `fin giro auth login --send`로 같은 CLI 식별자의 로그인을 직접 다시 시도합니다. 이 명령은 SMS·기기 등록을 반복하지 않습니다. 등록·로그인 도중 기관이 명시적으로 거절한 응답은 종료코드 `2`, 회원가입 등 별도 준비가 필요한 분기는 `4`로 구별합니다. 로그인 전 단계의 응답 판정은 `last_response_service_decision`에 기록하며, 이를 PIN 로그인 성공으로 해석하지 않습니다.

등록의 첫 단계인 인증서·기기 상태·일시 조회에서 기관의 확정 실패를 받고 종료했다면 `fin giro auth register --retry --send`로 직접 다시 시작할 수 있습니다. 이전 기록은 별도 보존하고 기존 CLI 식별자를 재사용합니다. 매번 정상 기기 상태 조회부터 시작하므로 이미 등록된 기기라면 로그인으로 진행합니다. SMS 이후 기록, 등록 성공·결과 미확인 기록, 실행 중 예약은 이 옵션으로 초기화하지 않습니다. 기본 명령은 기존 시도를 자동 반복하지 않습니다.

본인 세금 목록은 계정의 본인정보 등록 상태가 확인된 경우에 조회합니다. 등록이 필요하면 `identity_registration_required`로 중단하며 주민등록번호 등록을 자동 실행하지 않습니다. 페이지 오류·건수 불일치·누락은 이미 받은 성공 자료와 구별합니다. 세션 만료 시 다시 로그인해야 하며 조회 과정에서 보호 초기화·로그인을 반복하지 않습니다.

`receipts list`는 지정한 기간의 납부내역 한 페이지를 조회합니다. 다음 페이지는 `--page 2`처럼 지정합니다. 빈 목록이나 조회 실패로 기존 납부 예약을 해제하거나 납부 실패를 추정하지 않습니다.

수신자 검증에 사용할 공개 루트 자료는 다음 명령으로 준비합니다. 기본 실행은 통신·파일 접근 없이 계획만 보여 줍니다. 실제 준비에는 공개 자료 전용 디렉터리를 먼저 만들고 절대경로와 `--send`를 지정합니다.

```sh
fin giro auth prepare-trust
fin giro auth prepare-trust --cache /absolute/public-material-cache --send
```

고정된 공개 LDAP 서버에서 캐시에 없는 루트 인증서를 최대 2회 조회하고, 미리 지정된 SHA-256과 일치하는 자료만 저장합니다. 이미 일치하는 자료가 있으면 다시 조회하지 않습니다. 사용자 인증서·비밀번호·PIN은 사용하지 않습니다. 루트 외에 현재 발급자 인증서와 CRL도 필요하며 루트 준비 성공만으로 수신자 검증이나 로그인이 완료되지는 않습니다.

아래 명령은 로컬 JSON 자료를 읽으며 서비스에 접속하지 않습니다.

```sh
fin giro payment plan
fin giro accounts list --input /path/to/payable-accounts.json
fin giro payment result --type national --input /path/to/payment-response.json
```

`accounts list`는 납부 가능 계좌 응답의 등록계좌를 순서대로 보여 줍니다. 계좌번호는 가리고 금융기관의 납부 가능 상태를 별도로 표시합니다. 조회가 성공해도 계좌 목록을 받지 못했다면 0건으로 표시하지 않습니다. 계좌별 인증서·프로필 설정은 필요하지 않습니다.

`payment plan`은 등록계좌 납부와 홈택스 연계 납부의 지원 범위를 보여 줍니다. 로그인용 간편비밀번호 6자리와 납부용 계좌 비밀번호 4자리는 서로 다른 입력입니다. 이 명령들은 비밀번호를 받거나 납부를 실행하지 않습니다.

`payment result`는 복호화된 납부 응답을 해석합니다. 홈택스 연계 응답은 `--type hometax`를 사용합니다. 성공 응답에 영수증 항목이 없어도 확인된 성공은 유지합니다. 파일 해석 결과가 현재 납부 상태를 다시 조회한 결과는 아닙니다.

`payment pay --send`는 저장된 세션으로 국세 상세·등록계좌·서버시각을 조회한 뒤 금액·은행·마스킹 계좌를 표시합니다. 사용자가 터미널에서 `납부`라고 확인한 다음 계좌 비밀번호를 받아 한 번 전송합니다. 확인을 취소하면 비밀번호를 받거나 납부하지 않습니다. Python 호출자는 `giro.payment_flow.PaymentWorkflow.prepare()`로 확인 내역을 받고 별도 `pay(send=True)`를 호출합니다.

계좌 비밀번호는 입력 제공자로부터 4자리를 받아 메모리에서 암호화합니다. PIN 로그인 세션의 100만 원 초과 납부에는 별도 제공자로 간편비밀번호 6자리를 받아 추가 인증 값을 만듭니다. 인증서·FIDO 추가 인증은 아직 연결하지 않았습니다. 전송 전에 공통 데이터 디렉터리의 `giro/payments`에 고지별 예약을 배타적으로 기록합니다. 응답 단절·프로세스 종료·저장 실패 뒤에도 같은 고지의 재전송을 허용하지 않습니다. 이는 부분 납부 후 같은 고지를 다시 납부하는 경우에도 적용되는 현재 실행 모듈의 제한입니다. 납부내역 조회에서 빈 목록을 받았다는 이유로 예약을 해제하거나 납부 실패를 추정하지 않습니다. 기관 성공과 결과 저장 상태는 별도로 반환합니다.

## 웹앱

CLI와 같은 데이터 디렉터리·인증서 금고를 쓰는 웹 서버입니다. 브라우저에는 CLI나 Python이 들어가지 않고, 기관 업무는 서버의 작업 프로세스가 실행합니다. 웹 서버와 같은 데이터 디렉터리를 쓰는 CLI·에이전트는 같은 버전으로 갱신하세요. 새 잠금에는 구버전 CLI가 참여하지 않습니다.

### 설치와 시작

```sh
python -m pip install '.[web]'
fin server config --port 8740                      # 로컬 개발: http://127.0.0.1:8740
fin server start                                   # 127.0.0.1에서만 대기
fin server enroll --device-name "내 노트북"        # 일회성 등록 코드(10분, 1회)
```

브라우저에서 공개 주소를 열고 등록 코드를 입력하면 그 브라우저에 접속 토큰(HttpOnly 쿠키)이 발급됩니다. 가입 기능은 없고, 기기 목록·철회는 웹의 연결·인증서 화면이나 `fin server devices`, `fin server revoke <기기 ID>`로 관리합니다.

### 휴대폰 등 원격 접속

서버는 TLS를 직접 제공하지 않습니다. 같은 호스트의 Caddy가 HTTPS를 종단하고 루프백으로 전달합니다. 패키지에 포함된 `finance_cli/server/Caddyfile.example`을 복사해 호스트 이름을 바꾸세요.

```sh
fin server config --public-origin https://finance.example.ts.net --port 8740
caddy run --config /path/to/Caddyfile
```

- 쿠키의 `Secure`, CSRF 출처 검사, 등록 코드는 설정한 **공개 출처**만 기준으로 합니다. `X-Forwarded-*` 헤더는 루프백에서 온 요청에서 클라이언트 주소로만 읽습니다.
- 원격 주소는 `https`만 설정할 수 있습니다. 사설망·VPN 안에서 쓰는 구성을 기본으로 하며, 공용 인터넷 노출은 기본 설정에 없습니다.
- Caddy 내부 CA(`tls internal`)를 쓰면 그 루트 인증서를 접속 기기에 설치해야 합니다.

### 처음 설정

1. 웹의 **연결·인증서 → 인증서 발급·가져오기**에서 공동인증서를 가져오거나 하나인증서를 신규 발급합니다. CLI의 `fin cert joint import …`도 그대로 쓸 수 있습니다. 하나인증서 서비스 설정은 서버에서 먼저 준비합니다. 공동·금융인증서 신규 발급은 미지원입니다.
2. 기존 인증서 프로필이 있으면 `fin server import-profiles`로 기관 로그인 초안을 만듭니다. `profiles.json`은 수정하지 않고, 명의·유형·사업장은 추정하지 않습니다.
3. 웹의 연결·인증서 화면에서 기관 로그인을 추가하거나 확인합니다. 하나은행 공동인증서 로그인은 기기·앱 등록 파일이 필요하며 서버에서 연결합니다.

   ```sh
   fin server registration --login <로그인 ID> --expected-revision 1 \
     --app-profile /path/to/profile.json --login-input /path/to/login-input.json
   ```

4. 로그인한 뒤 하나은행은 **계좌 조회**만 하면 은행이 돌려준 계좌를 자동으로 연결합니다. 계좌마다 등록하거나 이체 인증서를 지정할 필요 없이 거래 내역·이체에서 선택할 수 있습니다. 홈택스는 **사용자·사업장 확인** 결과에서 사용할 대상을 선택합니다.
5. **전체**에서 바로 사용할 수 있으며 업무 프로필은 선택 사항입니다. 필요하면 계좌·사업장을 묶고 상단에서 전환합니다. 그 탭의 표시 대상만 바뀝니다.

하나인증서 이체에는 기본으로 로그인에 선택한 하나인증서를 사용합니다. 이전에 별도 이체 인증서를 명시한 설정은 유지되며, 연결의 더보기에서 **별도 이체 인증서 → 로그인 인증서 사용**으로 되돌릴 수 있습니다. 홈택스 계산서 발급용 인증서는 로그인용과 용도가 다를 수 있어 별도로 지정합니다.

서버를 다시 시작하면 현재 로그인 설정에서 성공한 마지막 계좌 조회 기록도 기관 통신 없이 연결합니다. 기존 계좌의 이름·사용 중지·프로필 묶음을 유지하며, 목록에서 사라진 계좌를 자동 삭제하거나 계좌가 없다고 추정하지 않습니다. 이후 업무 때는 현재 세션에서 계좌를 다시 확인합니다.

연결 카드의 더보기에서 **연결 해제**를 고르면 그 연결과 대상, 프로필 묶음, 이 서버가 만든 세션 파일을 지웁니다. 작업 기록과 저장 문서, 인증서는 남고 기관에서 로그아웃하지는 않습니다. 실행 중인 작업이 있으면 해제하지 않고, 확인을 기다리는 이체·계산서는 취소됩니다. 인증서 보관함의 **이름 변경**과 **삭제**는 어떤 연결·인증서 프로필도 쓰지 않는 인증서에만 됩니다. 이름 변경은 인증서와 키를 그대로 두고 이름만 바꾸며, 삭제는 이름을 입력해 확인합니다. 되돌릴 수 없으니 필요하면 먼저 `fin cert export`나 `fin hana onesign export-identity`로 백업하세요.

### 작업과 결과 읽기

- **보안매체·한도**는 공동인증서 또는 하나인증서로 로그인한 연결을 선택해 이체한도·한도 예외·보안매체·OTP·OTP 사고·모바일 OTP 상태를 조회합니다. 계좌를 먼저 조회하거나 등록할 필요는 없습니다. 하나인증서는 기존 로그인 세션과 기억 중인 저장소 암호를 함께 사용하며, 세션 만료 시 재로그인으로 안내합니다. OTP 발급·등록·해제나 한도 변경은 지원하지 않습니다.
- 하나은행 웹 세션은 **마지막 은행 요청 후 10분 이상** 지나면 다음 요청 전에 로컬에서 만료로 처리하고 해당 연결의 로그인 창으로 안내합니다. 조회·이체는 보내지 않으며 재로그인 후 직접 다시 실행합니다. 은행 요청 시각은 세션별로 저장되어 서버를 재시작해도 유지됩니다. 화면 새로고침·작업 상태 확인·저장소 잠금 해제는 기한을 늘리지 않습니다. 기존 세션에 요청 시각 기록이 없으면 세션 생성 시각을 기준으로 합니다. 이는 웹앱의 사전 차단 규칙이며 은행이 반환한 판정을 변경하지 않습니다.
- 조회·준비·실행은 모두 작업으로 접수되어 서버가 순서대로 실행합니다. 브라우저를 닫아도 작업은 취소되지 않으며, 작업 기록에서 다시 확인할 수 있습니다.
- 작업 결과는 **기관 판정(원문 필드)**, **결과 재조회**, **로컬 처리 상태**, 화면 요약용 **업무 결과**(`성공`·`부분 성공`·`기관 거절`·`결과 미확인`·`시작 안 함`)를 따로 보여 줍니다. 판정을 관찰하지 못한 경우 실패나 0건으로 바꾸지 않습니다.
- 홈택스 조회는 대상 확인(필요하면 사업장 전환)과 업무 조회를 한 작업에서 직렬로 실행하고, 결과에 확인한 대상을 표시합니다. 조회 행은 서비스의 필드명을 그대로 보여 주며 식별번호류는 가립니다.
- 인증서 비밀번호·PIN·계좌 비밀번호는 해당 단계에 한 번 전달하고 저장하지 않습니다. 같은 기관 자원을 쓰는 작업이 실행 중이면 비밀번호를 전달하지 않고 요청을 거절합니다.
- 하나인증서 저장소 암호는 서버 메모리에 기억해 둘 수 있습니다. 웹의 연결·인증서 화면에서 **잠금 해제**하거나, 입력 창의 "서버를 끌 때까지 기억"을 선택하거나, 서버를 켤 때 `fin server start --unlock <저장소 이름>`으로 입력합니다. 서버가 꺼지거나 **잠그기**를 누를 때까지 인증서 발급·로그인·계좌·내역 조회·이체에서 다시 묻지 않으며, 디스크에는 저장하지 않습니다. 잠금 해제된 동안에는 등록한 브라우저로 이체까지 진행되므로 필요할 때만 해제하세요.
- 웹의 하나인증서 로그인은 **내 계좌·거래 내역·이체 내역·이체**에서 함께 사용합니다. 거래 내역(일반 원화 입출금 계좌)의 다음 페이지·상세·JSON/CSV 저장도 지원합니다. 이체를 준비한 뒤에도 같은 세션으로 조회할 수 있고 **조회용 세션 있음**으로 표시합니다. 현재 은행 세션이 유효하다는 보장은 아닙니다. 세션 만료 등으로 조회가 되지 않으면 **내 계좌** 또는 **연결·인증서**의 **다시 로그인**을 누릅니다. 거래 내역·이체 내역·이체 화면에서도 선택한 계좌의 **다시 로그인**을 사용할 수 있습니다. 로그인 후 필요한 조회를 직접 실행합니다. 만료되거나 새 로그인으로 교체된 세션은 재사용하지 않습니다. 은행 요청을 자동으로 재시도하거나 로그인하지 않습니다.
- 공동인증서·하나인증서로 재로그인한 뒤 **거래 내역·이체 내역**을 조회하면, 새 로그인에서 필요한 계좌 확인을 같은 작업 안에서 먼저 처리합니다. 이미 등록한 계좌는 **내 계좌**로 돌아가 따로 조회할 필요가 없습니다. 현재 로그인에서 선택한 계좌가 확인되지 않으면 내역 조회를 중단하고 계좌 확인 결과를 남깁니다.
- 계산서 발급과 원화 이체는 준비 → 확인 → 한 번 실행으로 나뉩니다. 확인 화면에는 대상·인증 수단·검증 수준(**실사용 확인·일부 실사용 확인·실서버 미검증**)이 표시됩니다. 세부 확인 범위는 **전체 기능·지원 상태**에서 볼 수 있습니다. 이체 확인에는 기한(10분)이 있고, 이체 한 건마다 새 하나인증서 로그인이 필요합니다. 결과가 불확실하면 다시 실행하지 말고 결과 조회로 확인하세요.
- CLI·에이전트로 실행한 명령도 서버 데이터베이스가 있으면 작업 기록에 명령 단어와 종료코드만 남습니다. 에이전트 실행은 `FINANCE_REQUEST_ORIGIN=agent`로 구분합니다. 기록 실패는 CLI 결과를 바꾸지 않습니다.

### 웹앱에서 인증서 발급·가져오기

**연결·인증서 → 인증서 발급·가져오기**에서 종류를 선택합니다. 기관 연결 추가 화면에도 같은 진입 버튼이 있습니다.

- 공동인증서: 발급기관에서 받은 NPKI(`signCert.der`·`signPri.key`) 또는 PFX/P12를 선택하고 인증서 비밀번호로 암호화 보관합니다. 파일당 2 MiB 이하이며, PFX에 인증서가 여러 개면 0부터 시작하는 순번을 지정합니다. NPKI 암호 호환 규칙은 CLI와 같은 하나은행(기본)·홈택스를 선택합니다. 신규 발급은 지원하지 않습니다.
- 금융인증서: 신규 발급·클라우드 연결·관리는 아직 지원하지 않습니다. 오프라인 암호 라이브러리를 발급 기능으로 표시하지 않습니다.
- 하나인증서: 서버에서 `fin hana setup extract`·`configure`로 준비한 1.0.27 설정을 선택하고 새 저장소를 만듭니다. 국내 성인 기존 하나은행 고객의 SMS·주민등록증/운전면허증·본인 하나은행 계좌 확인을 통한 신규 발급을 지원합니다. 설정 추출·번들 이전은 서버 CLI로 관리합니다. 최근 웹 기록에서 신규 발급·완료 성공을 확인했으며 신분증 종류별·예외 분기 전체를 확인한 것은 아닙니다([실사용 확인 범위](banking-verification.md)).

하나인증서 발급 화면은 다음 4단계입니다.

1. **휴대폰 인증:** 이름·휴대폰 정보·필수 약관을 입력하고 **인증문자 요청**을 누릅니다. 저장소 준비 → 정보 저장 → 앱 인증 → SMS 요청을 자동으로 이어갑니다. 같은 단계에서 요청 후 180초 안에 인증번호를 입력합니다.
2. **신분증 확인:** 가입 상태에 따른 필수 약관을 확인하고 보관한 신분증을 고르거나 사진·정보를 직접 입력한 뒤 **신분증 확인**을 누릅니다. 약관 저장 → 확인 준비 → 사진 준비 → 은행의 신분증 확인 → 발급용 본인계좌 목록 조회까지 이어갑니다.
3. **계좌 확인:** 신분증 확인 후 은행이 제공한 발급용 본인계좌 목록에서 전체 계좌번호를 확인해 계좌를 선택하고 계좌 비밀번호를 입력합니다. 평생계좌번호 등을 직접 입력하지 않습니다. 목록 조회와 비밀번호 확인은 각각 한 번 실행하며, 화면을 다시 열 때는 저장된 목록을 사용합니다.
4. **PIN 설정·발급:** 새 PIN과 PIN 확인을 입력하고 **하나인증서 발급**을 누릅니다. 인증서 발급과 가입 완료를 순서대로 진행합니다.

각 버튼 아래에 전송 범위를 안내하며, 버튼을 누르면 해당 화면에 포함된 원격 작업에 명시적 전송 승인(`send: true`)을 전달합니다. 내부 요청 순서는 그대로 유지하고, 성공과 예상한 다음 단계가 모두 확인되어야 다음 요청을 실행합니다. 중간 완료 화면이나 반복 통신 승인 체크는 표시하지 않습니다. 오류·부분 성공·결과 미확인·예상하지 못한 진행 상태가 나타나면 후속 요청을 중단하며 자동 재전송하지 않습니다. 창을 닫으면 이미 접수된 요청은 계속 처리되지만 이후 요청은 보내지 않습니다. **진행 중인 발급 이어하기**는 저장된 상태를 읽고 해당 화면을 열며, 남은 기관 요청은 그 화면의 버튼을 다시 눌러야 진행됩니다. 작업 기록에는 각 내부 단계의 판정이 그대로 남습니다.

신분증은 미리 보관해 두는 것을 권장합니다. **연결·인증서 → 인증서·신분증 보관함 → 신분증 보관**(또는 발급 첫 화면의 **신분증 먼저 보관**)에서 보관할 이름·보관 암호·신분증 사진과 정보를 입력하면 `idcard.add` 작업이 기관 접속 없이 `fin idcard add`와 같은 검사·봉인을 합니다. 보관한 신분증이 있으면 신분증 확인 화면에서 기본으로 선택되며, 보관 암호와 현재 유효한 본인 신분증인지 확인만 입력합니다. 이때 작업 입력에는 신분증 이름(`id_card`)만 남고 보관 암호는 작업자 파이프로만 전달됩니다. 보관 암호가 틀리거나 확인을 선택하지 않으면 은행에 보내기 전에 멈추며 **신분증 입력 수정**으로 다시 입력할 수 있습니다. 보관함에서는 신분증의 종류·발급일·보관 시각을 보고 이름 변경·삭제를 할 수 있습니다. 내보내기는 서버의 `fin idcard export`로 합니다.

보관하지 않은 신분증은 **직접 입력**을 골라 본인의 마스킹하지 않은 카드 영역 JPEG(8 MiB 이하)와 확인한 정보를 직접 입력합니다. 웹앱은 사진의 회전 정보를 반영한 뒤 가로 1024픽셀을 넘으면 비율을 유지해 축소하고, EXIF 등 부가정보를 제외한 JPEG를 암호화 보관합니다. 원본 파일은 수정하지 않으며 사진 준비 단계에서는 기관에 접속하지 않습니다. CLI의 `prepare-id`는 기존처럼 가로 1024픽셀 이하의 JPEG를 받습니다. 필수 약관은 링크로 열어 확인하며, 통신사를 바꾸면 기존 동의를 해제합니다. SMS 요청 완료는 휴대폰 도착을 보장하지 않습니다.

저장소 암호 입력 시 기본 선택된 **서버를 끌 때까지 이 저장소 암호 기억**을 유지하면 처음 한 번만 입력하고 발급을 계속할 수 있습니다. 새 저장소는 생성 성공 후 암호를 기억하며, 기존 저장소도 발급 상태 확인에서 한 번 입력하면 됩니다. 잠그거나 서버를 재시작하면 다시 입력합니다. SMS 인증번호·계좌 비밀번호·새 PIN은 저장소 암호와 별개로 해당 단계에서 받습니다.

신분증 입력의 **성명**에는 신분증에 적힌 본인 이름을 입력합니다. 보관함에서 구분하는 이름과 별개입니다. 신분증 확인이 중단되면 사진 업로드와 정보 확인의 은행 판정·오류 코드를 구분해 보여 줍니다. **진행 상태 확인**은 암호화된 기존 기록만 읽으며 은행에 재전송하지 않습니다. 휴대폰 인증 이름과 전송된 성명이 다른 경우에는 그 사실만 표시하고 실제 이름·주민번호·응답 원문은 작업 기록에 남기지 않습니다.

저장소 암호·휴대폰 정보·SMS·신분증·계좌 비밀번호·PIN·인증서 파일은 작업 입력/결과·이벤트·산출물에 저장하지 않고 메모리와 작업자 파이프로 전달합니다. 보관할 인증서와 신분증 자료는 기존 암호화 저장소와 신분증 보관함에만 남습니다. 신분증 파일과 인증서 파일은 일반 업로드 API에 올리지 않습니다. 웹 요청이 끊기면 작업 기록에서 확인하며 자동 재전송하지 않습니다. 중단되거나 미확인인 발급은 새 작업 이름으로도 재시도하지 않습니다. 발급 뒤 등록·저장 오류가 발생하면 `certificate_issued`와 서비스 판정을 보존하고 CLI 처리 상태를 별도로 표시합니다. 성공한 다음 단계만 계속할 수 있으며 기존 저장소의 발급 상태 확인은 기관 통신 없이 읽습니다.

발급·가져오기 완료 후 기관 연결을 별도로 추가합니다. 신규 발급 완료는 일반 서명 로그인·이체 성공을 의미하지 않습니다. 인증서 내보내기와 런타임 설치는 서버 CLI에서 관리합니다.
