# 신한은행 연결

현재 기동 요청과 명시적 세션 연장을 구현했으며 실서버 수락은 확인 전입니다. PIN 인증·서명 로그인 명령은 합성 검증 단계이며 발급된 인증서를 준비하는 경로는 아직 연결 중입니다. 계좌·대출 상세·증빙·거래내역·이체는 아직 제공하지 않습니다. `fin capabilities`에도 같은 범위를 표시합니다.

Python HTTP와 암호 연산만 사용합니다. 처음 연결할 때 버전 20.0.40 기본 APK와 기기 정보를 입력합니다. 필요한 공통 설정만 사용자 데이터 폴더에 설치하며, 이후에는 설치 패키지 경로를 다시 지정하지 않습니다.

```sh
fin --format json-v1 shinhan session start --apk /path/to/base.apk --send
fin --format json-v1 shinhan session status
```

첫 실행은 Android ID, 기기 모델명, Android 버전을 숨김 입력받습니다. 새 형식 기기 ID는 Android ID와 모델명을 이어 SHA-256으로 계산합니다. Android ID는 앱에 제공되는 값이며 다른 앱이나 셸에서 읽은 값과 같다고 가정하지 않습니다. 기존 앱의 저장된 식별자·인증서·로그인을 가져오는 명령은 아닙니다. 기기 정보를 모른다면 값을 임의로 만들어 기존 등록 기기의 정보로 사용하지 마세요.

자동화에서는 `--device-input /path/to/device.json`을 사용할 수 있습니다. 이 JSON은 문자열 `android_id`, `model`, `os_version` 세 필드를 가지며 파일 권한은 `0600`이어야 합니다. 기기 식별자를 명령 인자나 환경변수로 전달하지 않습니다. 네트워크 없이 설정만 설치하려면 `fin shinhan setup --apk /path/to/base.apk`을 사용합니다. 이미 설치된 설정은 덮어쓰지 않습니다.

기동 요청이 성공해도 로그인 성공을 뜻하지 않습니다. `session status`는 로컬 파일의 존재만 읽고, 세션의 서버 유효성을 확인하지 않습니다. 기동 시 받은 공지·강제 종료·강제 업데이트·메뉴 갱신 여부를 결과의 `intro`에 표시합니다. 이 명령은 전체 앱 기동이나 공지 처리·메뉴 다운로드를 대신하지 않습니다.

```sh
fin --format json-v1 shinhan session extend --send
```

연장은 저장된 쿠키를 사용합니다. 서버가 연장을 성공으로 응답해도 별도 로그인 성공이나 이후 요청의 수락을 보장하지 않습니다. 자동 연장·재로그인·HTTP 재시도는 없습니다.

출력의 `bank_result`는 `success`, `failure`, `unknown` 중 하나이며 `processing_status`와 `local_status`는 별개입니다. 저장 실패가 앞선 은행 성공을 덮어쓰지 않습니다. 응답을 해석할 수 없거나 통신이 중단되면 은행 실패로 추정하지 않습니다. 현재 표준 JSON 응답을 처리하며 해석하지 못한 형식은 `unknown`으로 남깁니다.

사용자 데이터 폴더의 `shinhan/runs/<attempt>/report.json`에는 공유 가능한 단계·상태만 기록합니다. 같은 폴더의 `response.json`과 `shinhan/session.json`, `shinhan/settings.json`에는 민감한 자료가 들어 있으므로 공유하지 마세요. 디렉터리는 `0700`, 파일은 `0600`으로 저장합니다. `--send`가 없으면 설정·기기 입력을 읽거나 서버에 요청하지 않습니다.

## 인증서 로그인 연결

`fin shinhan login --send`는 현재 은행 연결의 인증서를 우선 선택하고, 연결이 없으면 사용 중지되지 않은 인증서가 하나일 때 자동 선택합니다. 선택이 모호하면 `fin shinhan certificate list`로 확인해 `--credential`로 선택합니다. 기존 SOL뱅크 앱의 인증서를 PIN만으로 가져올 수는 없습니다. 신규 발급 경로가 연결되기 전까지 이 명령을 첫 로그인용으로 사용할 수 있다고 보장하지 않습니다.

보관 암호와 6자리 PIN은 각각 숨김 입력합니다. `--password-stdin`은 보관 암호 한 줄만 읽습니다. 자동화의 `--pin-file`은 소유자만 읽을 수 있는 파일의 PIN 한 줄을 읽으며, PIN을 암호 입력에서 추정하지 않습니다. 개인키·PIN salt·인증서 자료는 공통 사용자 보관함에서 scrypt/AES-GCM으로 암호화합니다. 은행 세션에는 인증서 참조만 저장합니다.

로그인은 E2E 초기화·health 확인, 인증서 서버 PIN 인증, 은행 nonce 요청, RSA 서명, 은행 로그인 순서입니다. 인증서 서버의 `RA0000`과 은행의 `SUCCESS`를 별도로 기록합니다. nonce가 없으면 새 난수로 대체하지 않습니다. 서버가 인증서 재발급을 요구하면 해당 앱 연결의 기존 인증서 사용을 중지하며, 공통 보관함의 암호화된 자료를 자동 삭제하지 않습니다.

초기 설정에 E2E 자료가 없는 경우 아래 명령으로 기기 정보를 유지하면서 갱신합니다.

```sh
fin shinhan setup --apk /path/to/base.apk --refresh
```

현재 로그인은 PIN·RSA 경로이며 생체·패턴·E2E 자동 재초기화는 포함하지 않습니다. `phoneNo`, `phoneCom`, `phoneInfo`, `pushToken`은 자료가 없으면 빈 문자열, VPN 상태는 `X`로 보내며 Android 기기 자료를 자동 수집하지 않습니다. 실제 서버에서 이 입력으로 로그인을 수락하는지는 확인 전입니다. 로그인 작업의 `response-*.json`은 민감한 원문이며 공유 대상에서 제외합니다.
