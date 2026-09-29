# Finance CLI 사용자 가이드

`fin` 명령으로 공동인증서를 보관하고 홈택스·하나은행 작업을 실행하는 방법을 설명합니다. 설치와 지원 범위 표는 [README](../README.md)를 참고하세요. 현재 구현 범위는 `fin capabilities`로도 확인할 수 있습니다.

> **먼저 알아둘 점**
> - 홈택스 명령은 현재 버전에서 **실서버 검증 전**입니다. 조회는 결과를 직접 대조하며 쓰고, 세금계산서 **발급은 실제 발급**이므로 특히 주의하세요.
> - 하나은행은 공동인증서 로그인·조회와 하나인증서 신규 발급·서명 로그인·원화 이체를 지원합니다. 하나인증서에는 사용자 서비스 설정이 필요하며 실서버 검증 전입니다. → [하나은행](#하나은행), [하나인증서 시작하기](hana-onesign.md)

## 목차

1. [공통 규칙](#공통-규칙)
2. [인증서 관리](#인증서-관리)
3. [하나은행](#하나은행)
4. [홈택스](#홈택스)
   - [준비](#준비) · [로그인](#로그인) · [세션 재사용](#세션-재사용) · [사용자·사업장](#사용자사업장) · [세금 조회](#세금-조회) · [신고 조회](#신고-조회) · [전자세금계산서](#전자세금계산서)

## 공통 규칙

- **출력:** 모든 명령은 JSON을 표준출력으로 냅니다. 오류는 `{"error": ..., "message": ...}` 형태입니다.
- **종료코드:** 홈택스의 서비스 연결 명령은 서비스가 성공으로 판정하면 `0`, 실패로 판정하면 `1`, 입력·저장 경로 오류면 `2`, 판정을 관찰하지 못했으면 `3`입니다. 인증서 관리 명령의 오류는 `2`입니다. `3`은 실패가 아니라 **미확인**이므로 결과 파일을 보고 판단하세요.
- **비밀번호:** 숨김 입력으로 받습니다. 자동화에서는 `--password-stdin`으로 한 줄을 stdin에 넘길 수 있습니다. 명령행 인자와 환경변수로는 넘기지 않습니다.
- **연결 확인 `--send`:** 홈택스의 서비스 연결 명령(`login`, `session`, `account`, `business`, `tax`, `returns`, `report`, `invoice`)은 `--send`를 붙여야 실제로 접속합니다. 없으면 접속 없이 `send_required`로 멈춥니다.
- **출력 파일:** `--output`에는 항상 **아직 없는 새 경로**를 지정합니다. 덮어쓰지 않으며, 파일은 소유자만 읽고 쓰는 `0600` 권한으로 만들어집니다. 세션·결과 파일에는 쿠키와 개인정보가 들어 있으므로 Git 저장소 밖에 두세요.
- **데이터 위치:** `fin paths`로 확인합니다. 바꾸려면 `fin --home /절대/경로 ...` 또는 `FINANCE_HOME`을 씁니다.
- **도움말:** `fin --help`, `fin hometax <명령> --help`.

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

별칭 삭제·이름 변경 명령은 아직 없습니다.

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
| 하나인증서 설정·저장소 | `setup extract` / `configure`, `onesign init` / `activate` / `export-identity` | 없음 |
| 하나인증서 신규 발급 | `onesign enroll` 또는 `onesign issue` | 원격 단계에 `--send` |
| 하나인증서 로그인·조회 | `onesign new-session` / `login` / `accounts` | `login`·`accounts`에 `--send` |
| 하나인증서 원화 이체 | `transfer prepare` / `show` / `execute` / `reconcile` | `show` 외 `--send`; 실행 직전 내용 확인 |
| 오프라인 도구 | `plan`, `sign-login`, `encode-header`, `decode-header`, `joint-cert-tbs`, `joint-cert-body`, `login-body` | 없음 |

**하나인증서:** [설정·발급·이체 안내](hana-onesign.md)에 따라 새 인증서를 발급하거나 `activate`로 호환 번들을 가져와 사용합니다. 기존 `import`·`export`는 암호화 번들의 보관·복사 명령입니다. [번들 형식](onesign-bundle.md)은 v1과 클라우드 키가 선택 사항인 v2를 지원합니다.

**지원하지 않는 경로:** 클라우드 인증서 다운로드, 예외 가입·재발급 화면, 금융인증서 발급, OTP 발급·한도 변경. 이체는 단일 일반 원화 즉시이체를 지원하며 은행이 OTP·추가 인증을 요구하면 중단합니다.

**검증 상태:** 이 패키지의 테스트는 합성 자료와 가짜 전송 계층만 사용하므로 서버에는 접속하지 않습니다. 같은 절차는 이전 전의 CLI에서 실서버로 확인한 기록이 있습니다(로그인 연장은 서버 수락을 확인하지 못했습니다). `fin hana`로 하는 첫 실행은 결과를 직접 대조하며 진행하세요.

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
| 공동인증서 로그인 | RSA 인증서의 PFX 경로로 실서버 로그인에 성공했습니다. NPKI 파일 경로는 로컬 TLS 서버로만 검증했습니다. ID/비밀번호, 간편인증, FIDO, RSA가 아닌 인증서는 지원하지 않습니다. |
| 세션 확인·갱신, 사용자·사업장, 세금 조회 | 실서버에서 성공을 확인했습니다. |
| 신고 조회·접수증·신고서 저장 | 개인 종합소득세(2026년 6월 신고)에서만 실서버로 확인했습니다. 다른 세목과 서식은 확인 전입니다. |
| 세금계산서 조회 | 실서버에서 성공을 확인했습니다(매출·매입). |
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
| 종료코드 `3` | 서비스 판정을 관찰하지 못함. 결과 파일의 `warnings`, `reason` 확인 |
| Node 관련 오류 | `fin runtime status hometax` 후 필요하면 `fin runtime install hometax` |
