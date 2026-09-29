# Finance CLI 사용자 가이드

`fin` 명령으로 공동인증서를 보관하고 홈택스·하나은행 작업을 실행하는 방법을 설명합니다. 설치와 지원 범위 표는 [README](../README.md)를 참고하세요. 현재 구현 범위는 `fin capabilities`로도 확인할 수 있습니다.

> **먼저 알아둘 점**
> - 홈택스 명령은 현재 버전에서 **실서버 검증 전**입니다. 조회는 결과를 직접 대조하며 쓰고, 세금계산서 **발급은 실제 발급**이므로 특히 주의하세요.
> - 하나은행은 **로그인·조회·이체를 지원하지 않습니다.** 지금 가능한 것은 오프라인 계약 변환과 로그인 nonce 서명뿐입니다. → [하나은행](#하나은행)

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
- 가져올 때 인증서와 개인키가 서로 맞는지 로컬에서 확인합니다. 서버와는 통신하지 않습니다. **유효기간은 확인하지 않습니다.** 원본 파일은 수정하지 않습니다.

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

가져온 파일을 **없는 새 디렉터리**에 원본 그대로 복원합니다. NPKI는 `signCert.der`와 `signPri.key`, PFX는 `certificate.pfx`가 만들어지며 PFX 내부 보호 형식도 그대로입니다. 복원된 파일은 개인키가 들어 있으니 용도가 끝나면 안전하게 지우세요.

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

**로그인·조회·이체는 지원하지 않습니다.** 서버에 접속하는 하나은행 명령은 이 패키지에 없습니다. 기존 업무 실행기(로그인·계좌·이체·OTP·인증서 발급)는 연구 저장소의 고정 기준본에 보관되어 있고 `fin hana`에 이전되지 않았습니다. 지금 `fin hana`는 서버와 통신하지 않는 오프라인 도구만 제공합니다.

| 명령 | 입력 | 하는 일 |
| --- | --- | --- |
| `fin hana plan` | 없음 | 로그인 계약(요청 순서·헤더·본문 필드)과 이전 범위를 출력합니다. 분석 자료이며 실서버 검증 전입니다. |
| `fin hana sign-login` | `--nonce`, `--output`, `--profile` 또는 `--credential` | 금고의 인증서로 서버 nonce를 CMS 서명해 DER 파일로 저장합니다. |
| `fin hana joint-cert-tbs` | stdin JSON `{"nnce": "..."}` | 서명할 문자열(`delfinoNonce=...&login=true`)을 만듭니다. |
| `fin hana joint-cert-body` | stdin JSON `signed_data`, `push_token`, `fakefinder_install_id` | 공동인증서 로그인 요청 본문을 만듭니다. |
| `fin hana login-body` | stdin JSON `user_id`, `password_enc`, `push_token`, `fakefinder_install_id` | 아이디·비밀번호 로그인 요청 본문을 만듭니다. |
| `fin hana encode-header` / `decode-header` | stdin | 하나은행 요청 헤더 JSON ↔ 인코딩 문자열 변환. |

### 로그인 nonce 서명

```sh
fin hana sign-login --profile personal --nonce SERVER_NONCE --output /path/to/new-signature.der
```

- nonce는 직접 확보한 값을 넣습니다. 자동으로 가져오지 않습니다.
- 결과는 `signed: true`, `network_used: false`, `bank_accepted: null`입니다. **은행이 이 서명을 받아들였는지는 확인하지 않습니다.**
- 서명 파일을 은행에 전송하거나 로그인을 완료하는 기능은 없습니다.

## 홈택스

### 준비

홈택스의 서비스 연결은 Node.js로 실행하며 세금계산서 발급의 XML 서명에는 JDK가 필요합니다.

```sh
fin runtime status hometax    # Node·npm 위치와 런타임 설치 여부 (접속 없음)
fin runtime install hometax   # 고정된 npm 의존성을 사용자 데이터 영역에 설치 (npm 다운로드 통신)
```

- Node.js 22.22.2 이상(22.x), 24.15 이상(24.x), 또는 26 이상과 npm.
- 세금계산서 발급에는 JDK 17 이상.
- Chromium은 필요하지 않습니다. `--cdp`는 이미 떠 있는 브라우저에 붙는 선택 옵션입니다.

### 로그인

```sh
fin hometax login --profile personal --output /path/to/new-session.json --send
# 또는 --credential personal
```

- 인증서 비밀번호를 물어봅니다(`--password-stdin` 가능). `--timeout`(기본 180초)으로 대기 시간을 조절합니다.
- 표준출력에는 요약(`branch`, `session_file`, `session_binding_observed`, `session_file_saved`)만 나오고, 세션은 `--output` 파일에 저장됩니다.
- 판정은 서비스 응답 그대로입니다. 로그인이 `success`여도 후속 세션 바인딩을 관찰하지 못하면 경고가 붙습니다. 자동 재시도는 하지 않습니다.
- 접속 없이 서명 요청만 미리 만들어 보려면 `fin hometax auth prepare-cert --profile personal --output /path/to/new-preparation.json`을 씁니다(`--send` 불필요, 네트워크 요청 0건).

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

- `--reason`: `correction`(01), `amount-change`(02), `return`(03), `cancellation`(04), `local-credit`(05), `duplicate`(06). 서비스 코드도 허용합니다. `--approval-number`는 수정할 원본의 승인번호입니다.
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
