# Finance CLI

하나은행·홈택스·모바일지로를 위한 Python CLI입니다. `fin` 명령과 공통 인증서 저장소로 금융·세무 작업을 실행합니다. 기관별 지원 기능은 아래 표와 `fin capabilities`에서 확인할 수 있습니다. 명령별 사용법은 [사용자 가이드](docs/guide.md)를 참고하세요.

같은 기능을 모바일·PC 브라우저에서 쓰는 웹앱(`fin server`)을 선택 설치로 제공합니다. 서버는 루프백에서만 대기하고, 원격 접속은 Caddy HTTPS 프록시 뒤에서 일회성 코드로 등록한 브라우저만 허용합니다. 하나인증서 로그인은 웹의 계좌·거래 내역·이체 내역·보안매체·한도 조회와 이체에서 함께 사용하며, 이체 후에도 같은 세션으로 조회할 수 있습니다. 기관 업무는 서버의 작업으로 실행하며 쿠키·세션 파일은 응답으로 내보내지 않습니다. 설치와 사용은 [가이드의 웹앱](docs/guide.md#웹앱), 구조와 계약은 [웹앱 구현 계획](docs/web-app-plan.md)을 참고하세요. [UI 시안](web/preview/README.md)은 가상 데이터 시안으로 따로 보존합니다.

여러 은행과 개인·개인사업자·법인, 기관 로그인과 업무 대상을 다루는 [업무 프로필·기관 로그인·대상 설계](docs/profiles-and-connections.md)도 구현 계획에 포함합니다. 현재 CLI의 기관별 인증서 선택 프로필과는 구별합니다.

## 현재 지원 범위

| 영역 | 이 패키지에서 실행 가능한 기능 | 현재 경계 |
| --- | --- | --- |
| 공통 인증서 | NPKI·PFX 가져오기, 목록·정보, 내보내기, 프로필별 선택 | 비밀번호로 암호화한 저장소; CA 신뢰·폐기·기관 등록 확인과 별개 |
| 하나은행 | 앱·공동인증서 로그인, 계좌·거래·보안매체 조회, 로그인 연장, 하나인증서 신규 발급·서명 로그인·원화 이체, 암호화 번들 이전, 사용자 설치 패키지에서 설정 추출 | 지원 버전 1.0.27; 사용자 서비스 자료 필요; 하나인증서 발급·로그인·조회 성공 및 이체 실행 성공 응답 확인; 세부 미확인 범위는 [실사용 확인표](docs/banking-verification.md) 참고 |
| 홈택스 | 인증서 로그인, 세션, 사용자·사업장, 세액·신고 조회, 보고서 저장, 전자세금계산서 관련 명령 | Node 런타임 필요; XML 서명은 JDK 17+ 필요; 현재 버전의 실서버 검증 전 |
| 하나은행 기업 | ID/PW·공동인증서·개인사업자 하나인증서 로그인, 계좌·거래내역 조회, 일반 원화 단건·CSV 다건 이체 준비·실행·결과 | ID/PW 로그인·후속 응답·세션 저장 실사용 성공 확인; 조회·이체·인증서 로그인은 합성 검증; 일반 OTP·ARS·공동인증서 이체 인증 지원, 급여 전용·예약 이체·모바일 OTP 생성·별도 결재·세금 납부 미지원; [사용법](docs/hana-corporate.md) |
| 모바일지로 | CLI 기기 등록, CLI·웹 PIN 로그인·세금 조회·등록계좌 단건 납부·납부내역, 암호화 세션 재사용, 로컬 자료 해석 | 개인 보호 입력 자료·현재 인증서/CRL 필요; 기기 등록·PIN 로그인·세션 재사용·국세 조회·단건 계좌 납부 성공 확인; 웹 PIN 로그인·등록계좌·납부내역 목록/상세 조회 성공 확인; 웹 세금 목록은 고지내용 없음 응답 확인; 웹 납부 실행·지방세/관세 납부는 미확인; 비KT 기존 개인 회원 등록; 최초 기기 등록·보호 자료 준비는 CLI |
| 금융인증서 | JWE·PIN KDF·키 포장 등 오프라인 암호 라이브러리 | 발급·클라우드 연결·관리 CLI는 아직 미지원 |
| 웹앱 (`[web]` 선택 설치) | 위 기관 업무의 웹 작업(조회·준비·확인·실행·결과 조회), 업무 프로필·기관 로그인·대상, 작업 기록, 브라우저 등록·철회, 공동인증서 가져오기·하나인증서 단계별 발급 | 공동·금융인증서 신규 발급은 미지원; 루프백 서버와 Caddy HTTPS 프록시 구성; 설정 추출·인증서 내보내기·런타임 설치는 서버의 CLI로 관리; 하나인증서 뱅킹 일부 실사용 확인, 전체 기능 화면에 세부 범위 표시 |

웹앱은 **하나개인뱅킹**과 **하나기업뱅킹**을 별도 영역으로 제공합니다. 기업 ID/PW는 로그인 화면에서 바로 시작하며 계좌가 자동 연결됩니다. 인증서 로그인·거래내역·일반 원화 이체도 기존 공통 보관함과 CLI 서비스를 사용합니다. [기업뱅킹 웹 사용법](docs/hana-corporate.md#웹앱에서-사용하기)을 참고하세요.

## 설치

Python 3.10 이상. macOS와 Linux에서 사용하며 POSIX 파일 잠금과 권한이 필요합니다. 자동 테스트는 macOS·Ubuntu에서 실행합니다. Windows 저장소 지원은 아직 제공하지 않습니다.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
fin --help
fin capabilities
```

PyPI에 배포한 상태는 아니므로 현재는 이 저장소에서 설치합니다. 웹앱까지 쓰려면 `python -m pip install '.[web]'`로 FastAPI·uvicorn을 함께 설치합니다.

하나인증서 발급과 이체는 [설정·발급·이체 안내](docs/hana-onesign.md)를 따릅니다. 사용자별 인증서와 키는 CLI가 생성하고 암호화해 저장합니다. 공통 서비스 자료는 사용자가 설치 패키지에서 추출하며 제품에 포함하지 않습니다.

NPKI SEED 처리·PFX 읽기·하나은행 숫자/문자 키패드 암호화에는 시스템 OpenSSL 3가 필요합니다. macOS에서는 Homebrew의 `openssl@3`를 먼저 찾으며, 다른 설치 위치는 `FINANCE_OPENSSL_LIB`에 라이브러리 경로만 지정할 수 있습니다. 실제 XML 서명에는 JDK 17 이상을 설치합니다.

홈택스의 네트워크·보고서 기능에는 Node.js 22.22.2 이상(22.x), 24.15 이상(24.x), 또는 26 이상과 npm이 필요합니다. 명시적으로 다음 명령을 실행하면 고정한 npm 의존성을 사용자 데이터 영역에 설치합니다.

```sh
fin runtime status hometax
fin runtime install hometax
```

홈택스의 로그인·조회·보고서 SVG 생성은 Node HTTP·jsdom으로 실행합니다. Chromium 같은 브라우저는 실행하지 않지만, jsdom(DOM 에뮬레이터)이 홈택스가 내려주는 페이지 스크립트를 수정 없이 실행합니다. 로그인 보안 본문과 화면 함수가 이 스크립트에 있어 현재는 Node·npm 없이 홈택스를 쓸 수 없습니다. 하나은행·모바일지로·공통 인증서는 Node가 필요하지 않습니다. 보고서 이미지 검사·HTML 파일 생성은 Python으로 처리하며 Pillow는 패키지 설치 시 함께 설치됩니다. npm 직접 의존성은 `jsdom` 하나입니다.

## 공통 인증서

비밀번호는 숨김 입력받습니다. 자동화에서 명시적으로 `--password-stdin`을 사용할 수 있으며 argv·환경변수에는 비밀번호를 넣지 않습니다.

```sh
fin cert joint import --name personal --pfx /path/to/certificate.pfx
# 또는 NPKI 인증서·개인키 파일
fin cert joint import --name personal --cert /path/to/signCert.der --key /path/to/signPri.key

fin cert list
fin cert show personal
fin profile set personal --service hometax --cert personal
fin profile set personal --service hana --cert personal
fin profile list
```

NPKI의 암호 인코딩·복호화 규칙은 `--compatibility hana`(기본) 또는 `hometax`로 선택합니다. 저장된 규칙으로 공통 계층에서 복호화하므로, 같은 인증서를 다른 기관의 서명 프로필로 사용할 때도 암호 바이트 규칙과 PKCS#8 VID 속성을 보존합니다. 각 기관의 인증서 용도·서명 지원 조건은 계속 적용합니다.

공통 저장소는 scrypt와 AES-GCM으로 가져온 NPKI/PFX를 추가 암호화합니다. 인덱스에는 별칭·형식·인증서 지문만 남습니다. 가져오기 전의 파일과 기존 기관별 저장소는 수정하지 않습니다. `export`는 가져온 파일 내용을 새 디렉터리에 복원하며 PFX의 내부 보호 형식도 그대로 유지합니다.

```sh
fin cert export personal --output /path/to/new-export
fin cert joint rename personal personal-2024   # 별칭만 변경
fin cert joint remove personal-2024            # 프로필·웹 로그인이 참조 중이면 거절
```

신분증도 같은 방식으로 보관해 두고 발급 단계에서 골라 씁니다. 사진과 확인한 정보를 보관 암호로 봉인하며, 인덱스에는 이름·종류·신분증 발급일만 남습니다. 현재는 하나인증서 신규 발급의 신분증 확인에서 선택할 수 있습니다([신분증 보관](docs/guide.md#신분증-보관)).

```sh
fin idcard add resident-card --image /path/to/my-id-card.jpg
fin idcard list
```

개인키 평문과 비밀번호를 파일로 저장하지 않습니다. 프로세스 메모리의 완전 소거를 보장하지는 않습니다. 현재 공통 저장소는 사용자가 입력한 비밀번호를 사용하며 키체인 암호 자동 저장·조회는 연결하지 않았습니다.

## 기관 명령

기존 로그인 세션의 단발 연장 요청은 `fin hana onesign extend --name 이름 --send`, `fin hana corporate session extend --send`, `fin giro session extend --send`로 실행합니다. 지로는 암호화 시간 조회를 통한 활동 요청이며 서버 만료 연장 효과는 미확인입니다. [세션 선택·출력·검증 범위](docs/session-extension.md)를 참고하세요.

명령은 JSON 결과와 종료코드를 반환합니다. 도움말은 `fin <기관> ... --help`로 확인합니다. 홈택스의 실제 접속 명령에는 `--send`를 붙여야 합니다.

자동화에서는 `fin --format json-v1 <기관> ...`으로 버전·기관·종료코드와 기존 결과를 함께 받을 수 있습니다. 기본 출력은 유지하며 종료코드만으로 업무 성공을 판단하지 않습니다. [출력 계약과 기관별 입력 차이](docs/guide.md#기계-판독용-출력)를 참고하세요.

```sh
# 접속 없이 공통 인증서의 홈택스 서명 준비
fin hometax auth prepare-cert --profile personal --output /path/to/new-preparation.json

# 사용자가 실제 로그인을 실행할 때
fin hometax login --profile personal --output /path/to/new-session.json --send
fin hometax tax dues --session /path/to/session.json --output /path/to/new-result.json --send

# 하나은행 nonce 서명만 생성; 전송하지 않음
fin hana sign-login --profile personal --nonce SERVER_NONCE --output /path/to/new-signature.der
fin hana plan

# 지로 로컬 계획·자료 해석
fin giro auth plan
fin giro auth registration-plan  # 신규 기기 등록 순서·입력·현재 지원 범위; 통신 없음
fin giro auth prepare-trust   # 공개 루트 준비 계획; 통신·파일 접근 없음
fin giro request national.list
fin giro bills due --type national --input /path/to/local-response.json --today 2026-09-29
fin giro payment plan
fin giro accounts list --input /path/to/payable-accounts.json
fin giro payment result --type national --input /path/to/payment-response.json
```

홈택스의 로그인·`auth prepare-cert`·`invoice issue`는 인증서 파일 경로를 받지 않고 공통 `--credential`/`--profile`로만 인증서를 선택합니다. 인증서 파일은 먼저 `fin cert joint import`로 가져옵니다(PFX에 인증서가 여럿이면 가져올 때 `--pfx-index`로 선택). 기관별 등록·용도·만료 조건을 충족하는 인증서를 사용해야 합니다. 지로 초기 프로브의 `--send`는 `--live`와 같은 의미이며, 로그인이나 납부 기능을 추가하지 않습니다.

프로필은 인증서 선택 설정입니다. 세션을 자동 선택·갱신하거나 기관 간 쿠키를 공유하지 않습니다. 홈택스 세션·보고서 파일은 지정한 새 경로에 소유자만 읽고 쓸 수 있는 0600 권한으로 저장합니다. 이 파일에는 공통 인증서 금고의 암호화가 적용되지 않습니다.

## 사용자 데이터

`fin paths`로 기본 위치를 확인합니다. macOS는 `~/Library/Application Support/finance-cli`, Linux는 `$XDG_DATA_HOME/finance-cli` 또는 `~/.local/share/finance-cli`를 사용합니다.

`fin --home /absolute/path ...` 또는 `FINANCE_HOME`으로 데이터 위치를 명시할 수 있습니다. 이 환경변수에는 경로만 넣습니다. 인증서·세션·실사용자 응답은 Git 저장소 밖에 보관합니다.

## 개발과 검증

```sh
python -m pip install -e '.[test]'
npm ci --ignore-scripts
python tools/test.py
python -m build
python tools/check_distribution.py dist/finance_cli-0.1.0-py3-none-any.whl --node-runtime
```

합성 Python·Node 테스트를 기관별 독립 프로세스에서 실행합니다. 설치 점검은 새 가상환경에서 wheel의 명령·리소스를 확인합니다. `--node-runtime`은 임시 데이터 영역에 npm 패키지를 설치하므로 패키지 다운로드 통신이 있지만 금융·세무 서버는 호출하지 않습니다.
