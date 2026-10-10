# 로그인 세션 연장

로그인해 둔 세션으로 유지 요청을 한 번 보냅니다. 하나은행·지로 명령은 `--send`를 생략하면 저장소를 열거나 비밀번호를 묻지 않고 계획만 출력합니다.

```sh
fin hana onesign extend --name main --send
fin hana corporate session extend --send
fin giro session extend --send
fin hometax session extend --session 세션.json --output 새세션.json --send
```

| 명령 | 세션 선택과 입력 | 결과 |
| --- | --- | --- |
| `hana onesign extend` | 하나인증서 이름과 저장소 암호. 로그인 세션이 하나면 자동 선택; 여러 개면 `--session 이름` | `login_extension_accepted`로 은행의 연장 수락 표시 |
| `hana corporate session extend` | 최근 성공한 기업 로그인; 선택적으로 `--session 이름` | 은행의 연장 수락 또는 세션 종료 관측 |
| `giro session extend` | 저장된 지로 로그인 자동 사용 | 등록계좌 조회 성공(`login_extension_accepted=true`) 또는 세션 종료 관측. 계좌 정보는 출력하지 않음 |
| `hometax session extend` | 로그인이나 이전 명령이 저장한 세션 파일 `--session`, 새 파일 `--output` | 세션 확인의 `tokenOK`(`login_extension_accepted=true`) 또는 로그인 종료 관측. 확인한 세션은 `--output`에 저장 |

하나인증서는 인증서 PIN·재서명을 요구하지 않습니다. `--password-stdin`은 저장소 암호 한 줄만 읽습니다. 실행 기록 이름은 자동 생성하며, 필요하면 `--run 새이름`으로 지정할 수 있습니다. 시도한 이름은 다시 쓰지 않습니다. 파일형 공동인증서 로그인은 기존 `fin hana session extend --session 이름 --run 새이름 --send`를 사용합니다.

기업뱅킹은 ID/PW·공동인증서·하나인증서로 만든 기업 세션에 같은 명령을 사용합니다. 새 인증서 선택이나 비밀번호 입력이 필요하지 않습니다. 세션 종료가 확인되면 그 상태를 저장하고 이후 해당 세션을 사용하지 않습니다.

지로에는 전용 연장 요청이 없어 로그인이 필요한 등록계좌 조회를 한 번 보냅니다. `session keepalive`는 `session extend`의 별칭입니다. 기존 세션 키와 쿠키만 사용하며 PIN·추가 로그인·납부 요청을 하지 않습니다. 조회한 계좌 정보는 결과와 기록에 포함하지 않습니다.

- 조회가 성공하면 `request_accepted=true`, `login_extension_accepted=true`, `session_current_validity=valid`, `extension_effect=idle_limit_reset_observed`입니다. 지로는 연장을 따로 알려 주지 않습니다. 이 값은 같은 조회가 유휴 만료를 늦추는 것을 실서버에서 관측한 결과(2026-10-10)에 근거합니다.
- 로그인이 끝난 세션이면 `session_ended=true`, `login_extension_accepted=false`, `session_current_validity=ended`이며 그 상태를 저장합니다.
- 그 밖의 응답이나 응답을 받지 못한 경우는 `login_extension_accepted=null`, `extension_effect=unverified`로 둡니다.

지로 세션은 요청 없이 295초가 지난 뒤에는 유지됐고 300초가 지난 뒤에는 끝났습니다. 서버가 만료 시각을 알려 주지 않으므로 `server_expires_at=null`입니다.

2026-10-10 실서버 관측에서 하나인증서 세션은 요청 없이 595초가 지난 뒤에는 유지됐고 600초가 지난 뒤에는 끝났습니다. 기업뱅킹 세션은 605초가 지난 뒤에는 유지됐고 610초가 지난 뒤에는 끝났습니다. 두 연장 요청은 2회씩 수락됐고, 연장 요청만 보낸 약 21분 뒤의 조회가 수락됐습니다. 끝난 기업 세션에 보낸 연장 요청은 은행이 로그아웃 상태로 답했고 `session_ended=true`로 저장됩니다. 기업뱅킹은 로그인 준비 응답에서 세션 제한을 10분으로 알려 주며 로그인 결과의 `server_session_timeout_minutes`에 그 값이 나옵니다. 만료 시각을 알려 주는 응답은 없으므로 두 경로도 `server_expires_at=null`, `session_current_validity=unverified`를 유지합니다.

하나인증서·기업뱅킹·지로의 세 경로는 합성 검증을 마쳤고, 2026-10-10에 저장된 CLI 로그인 세션에서 세 연장 요청의 실서버 수락과 세션 유지를 확인했습니다. 기업뱅킹은 ID/PW 로그인 세션에서 확인했습니다. 파일형 공동인증서 로그인의 `fin hana session extend`, 인증서로 만든 기업 세션, 웹 연장 작업 자체의 실사용은 아직 확인하지 않았습니다. 만료된 세션을 복구하거나 자동으로 재로그인하지 않습니다. 주기 실행이나 오류 후 자동 재시도도 하지 않습니다. `server_expires_at=null`이며 로컬 타이머 값으로 서버 만료시각을 추정하지 않습니다.

웹앱은 같은 요청을 `hana.session.extend`, `hana.onesign.session.extend`, `hana.corporate.session.extend`, `giro.session.extend`, `hometax.session.extend` 작업으로 실행합니다. **자동 로그인 연장**을 켠 브라우저에서 웹앱을 열어 둔 동안에만, 세션의 유휴 제한(지로 4분 50초, 하나은행 9분 50초, 하나기업뱅킹 10분, 홈택스 29분 50초) 1분 30초 전에 한 번 보냅니다. 연장이 성공하지 않으면 다시 보내지 않으며 세션은 제한 시각에 로그아웃 처리됩니다. 지로·하나은행·홈택스의 제한은 요청 없이 그만큼 지난 세션이 유지되는 것을 실서버에서 확인한 값이고, 하나기업뱅킹의 제한은 은행이 로그인 때 알려 준 세션 제한입니다. 자세한 동작은 [가이드의 작업과 결과 읽기](guide.md#작업과-결과-읽기)를 참고하세요.

홈택스에는 전용 연장 요청이 없어 세션 확인을 한 번 보냅니다. `session extend`는 `session resume`과 같은 확인(메인 화면 진입, 서비스의 토큰 검증과 세션 바인딩)을 한 번 실행하고 그 판정을 연장 결과로 함께 출력합니다. `session refresh`가 더 보내는 SSO 토큰 재취득은 하지 않습니다. 가벼운 전용 요청이 아니어서 메인 화면의 초기 조회(메뉴·공지·알림 수 등)도 함께 나갑니다. 인증서와 비밀번호는 쓰지 않으며, 다음 명령은 `--output`에 저장된 새 세션 파일을 사용합니다. 홈택스 명령은 계획 출력이 없어 `--send`를 생략하면 `send_required`(종료코드 2)로 끝납니다.

- 서비스가 `tokenOK`로 답하면 `login_extension_accepted=true`, `session_current_validity=valid`, `extension_effect=idle_limit_reset_observed`입니다(종료코드 0). 홈택스는 연장을 따로 알려 주지 않습니다. 이 값은 같은 세션 확인이 무활동 만료를 늦추는 것을 실서버에서 관측한 결과(2026-10-10)에 근거합니다.
- 서비스가 로그인이 끝났다고 답하면(`sso_ended`, `no_sso_token`) `session_ended=true`, `login_extension_accepted=false`, `session_current_validity=ended`입니다(종료코드 1).
- 그 밖에는 `login_extension_accepted=null`, `extension_effect=unverified`입니다(종료코드 3). 만료 직후의 첫 확인은 이 상태로 끝날 수 있으며 실패로 추정하지 않습니다.

`session extend` 명령과 웹의 `hometax.session.extend` 작업은 합성 검증을 마쳤고 실서버에서 실행한 적은 없습니다. 아래 실서버 관측은 같은 확인을 실행한 `session resume` 경로의 것입니다. 2026-10-10 실서버 관측에서 요청 없이 1,800초가 지난 세션은 유지됐고 1,805초가 지난 세션은 로그인 상태가 사라져 있었습니다. 만료는 마지막 요청부터 세는 무활동 기준입니다. 로그인 뒤 요청 없이 1,900초가 지난 세션은 끝나 있었고, 세션 확인(`session resume`)을 이어 보낸 세션은 로그인 뒤 5,846초까지 유지됐습니다. 세션 확인은 만료를 늦춥니다. 갱신(`session refresh`)도 만료를 늦춥니다. 로그인 1,200초 뒤에 갱신만 한 번 보낸 세션은 그로부터 1,200초 뒤에도 유지됐습니다. 웹앱은 홈택스 세션을 마지막 요청 후 29분 50초가 지나면 로그아웃으로 처리하며, 자동 로그인 연장을 켠 경우에만 그 1분 30초 전에 이 확인을 한 번 보냅니다. `session refresh`는 자동으로 보내지 않습니다.

기관 수락과 저장·출력 처리는 별개입니다. 은행이 수락한 뒤 파일 저장이 실패해도 `accepted`/`login_extension_accepted`는 유지하고 `processing_status`, `cookies_saved`, `session_saved` 또는 `processing_issues`에 처리 상태를 표시합니다. 지로는 `app_success`와 `session_processing_issues`를 따로 봅니다. 자동화에서는 `fin --format json-v1 ...`을 사용할 수 있습니다.
