# 로그인 세션 연장

로그인해 둔 세션으로 유지 요청을 한 번 보냅니다. `--send`를 생략하면 저장소를 열거나 비밀번호를 묻지 않고 계획만 출력합니다.

```sh
fin hana onesign extend --name main --send
fin hana corporate session extend --send
fin giro session extend --send
```

| 명령 | 세션 선택과 입력 | 결과 |
| --- | --- | --- |
| `hana onesign extend` | 하나인증서 이름과 저장소 암호. 로그인 세션이 하나면 자동 선택; 여러 개면 `--session 이름` | `login_extension_accepted`로 은행의 연장 수락 표시 |
| `hana corporate session extend` | 최근 성공한 기업 로그인; 선택적으로 `--session 이름` | 은행의 연장 수락 또는 세션 종료 관측 |
| `giro session extend` | 저장된 지로 로그인 자동 사용 | 암호화 서버 시간 조회 성공과 세션 종료 관측. 실제 만료 연장 효과는 미확인 |

하나인증서는 인증서 PIN·재서명을 요구하지 않습니다. `--password-stdin`은 저장소 암호 한 줄만 읽습니다. 실행 기록 이름은 자동 생성하며, 필요하면 `--run 새이름`으로 지정할 수 있습니다. 시도한 이름은 다시 쓰지 않습니다. 파일형 공동인증서 로그인은 기존 `fin hana session extend --session 이름 --run 새이름 --send`를 사용합니다.

기업뱅킹은 ID/PW·공동인증서·하나인증서로 만든 기업 세션에 같은 명령을 사용합니다. 새 인증서 선택이나 비밀번호 입력이 필요하지 않습니다. 세션 종료가 확인되면 그 상태를 저장하고 이후 해당 세션을 사용하지 않습니다.

지로의 `session keepalive`는 `session extend`의 별칭입니다. 기존 세션 키와 쿠키로 시간 조회를 한 번 보내며 PIN·추가 로그인·납부 요청을 하지 않습니다. `request_accepted=true`는 조회 응답의 성공입니다. `login_extension_accepted=null`, `extension_effect=unverified`는 서버가 만료시간을 늘렸는지 확인하지 못했다는 뜻입니다. 조회한 시간 값이나 다른 개인정보는 결과에 포함하지 않습니다.

세 경로는 합성 검증을 마쳤으며 실서버 연장 수락은 아직 확인하지 않았습니다. 만료된 세션을 복구하거나 자동으로 재로그인하지 않습니다. 주기 실행이나 오류 후 자동 재시도도 하지 않습니다. `server_expires_at=null`이며 로컬 타이머 값으로 서버 만료시각을 추정하지 않습니다.

웹앱은 같은 요청을 `hana.session.extend`, `hana.onesign.session.extend`, `hana.corporate.session.extend`, `giro.session.extend` 작업으로 실행합니다. **자동 로그인 연장**을 켠 브라우저에서 웹앱을 열어 둔 동안에만, 세션의 10분 유휴 제한 1분 30초 전에 한 번 보냅니다. 연장이 성공하지 않으면 다시 보내지 않으며 세션은 제한 시각에 로그아웃 처리됩니다. 자세한 동작은 [가이드의 작업과 결과 읽기](guide.md#작업과-결과-읽기)를 참고하세요.

기관 수락과 저장·출력 처리는 별개입니다. 은행이 수락한 뒤 파일 저장이 실패해도 `accepted`/`login_extension_accepted`는 유지하고 `processing_status`, `cookies_saved`, `session_saved` 또는 `processing_issues`에 처리 상태를 표시합니다. 지로는 `app_success`와 `session_processing_issues`를 따로 봅니다. 자동화에서는 `fin --format json-v1 ...`을 사용할 수 있습니다.
