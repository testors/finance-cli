# OneSign vault 번들 형식

하나인증서(OneSign)로 로그인·서명하는 데 필요한 vault를 **암호로 잠근 파일 하나**에 담아 도구 사이에서 옮기는 형식입니다. 이 문서는 번들 파일의 바이트 배치와 검증 규칙만 정하며, 은행·RA·클라우드에는 접속하지 않습니다. `fin hana onesign`은 번들을 읽고 보관하고 복사합니다. 번들을 만드는 쪽은 별도 도구입니다.

## 번들은 계정 접근 자료입니다

번들에는 앱 식별자와 앱 RSA 키, 클라우드 개인키, 하나인증서 기록이 들어 있습니다. 암호를 아는 사람이 파일을 가지면 이 기기로 등록된 하나인증서의 서명 경로를 재현할 수 있습니다(PIN이 필요한 서명은 PIN도 필요). 다음을 지키세요.

- 암호는 12자 이상으로, 다른 곳에 쓰지 않는 값을 씁니다. 암호를 잊으면 복구할 수 없습니다.
- 가져온 뒤 원본 번들 파일은 안전하게 지웁니다. `fin`은 가져온 파일을 지우지 않습니다.
- 번들을 Git 저장소·클라우드 동기화 폴더·메신저에 두지 않습니다.

## 파일

UTF-8 JSON 객체이며 키는 정확히 다음 네 개입니다. 다른 키·다른 값은 `unsupported_bundle_format`으로 거부합니다. 크기는 1 MiB 이하입니다.

```json
{
  "format": "finance-onesign-bundle-v1",
  "kdf": {"name": "scrypt", "n": 131072, "r": 8, "p": 1, "salt": "<base64url 16바이트>"},
  "cipher": {"name": "aes-256-gcm", "nonce": "<base64url 12바이트>"},
  "sealed": "<base64url 암호문 ‖ 16바이트 태그>"
}
```

- base64url은 `+`·`/` 대신 `-`·`_`를 쓰고 `=` 패딩을 붙이지 않습니다.
- 키: `scrypt(NFC(암호).encode('utf-8'), salt, dklen=32)`. `n`·`r`·`p`는 위 값만 허용합니다(가져올 때 임의 비용 값으로 자원을 소모시키지 못하게).
- AAD: `format`·`kdf`·`cipher` 세 항목을 `json.dumps(..., sort_keys=True, separators=(',', ':'), ensure_ascii=True)`로 직렬화한 ASCII 바이트. `sealed`는 넣지 않습니다. 바깥 파일의 공백·키 순서는 의미가 없고 AAD에는 위 정규형만 쓰입니다.
- 암호가 틀렸거나 파일이 변조되면 `incorrect_passphrase_or_damaged_bundle`입니다. 두 경우를 구분하지 않으며, 16바이트보다 짧은 `sealed`도 같은 오류입니다.

## 평문

복호화한 바이트는 같은 정규형(`sort_keys`, 최소 구분자, `ensure_ascii=True`)의 JSON 객체입니다. 읽는 쪽은 정규형 여부에 의존하지 않습니다. 최상위 키는 정확히 `version`, `created_at`, `device_id`, `profile`, `cloud`, `records`입니다.

| 필드 | 내용 |
|---|---|
| `version` | `1` |
| `created_at` | 번들을 만든 UTC 시각(ISO 8601 문자열) |
| `device_id` | CLI 기기 UUID |
| `profile` | `device_id`, `app_identity`(`android_id`, `key_sha256`, `provenance`, `user_agent`), `app_key`(앱 RSA 개인키 DER, base64url), `enrollment`(`state`, 선택 `alias`·`origin`), 그 밖의 원본 필드 |
| `cloud` | `device_id`, `private_key`(클라우드 RSA 개인키 DER, base64url), 선택 `pubkId`·`userInfoHash` |
| `records` | 인증서 별칭 → 기록. 기록은 `alias`, `device_id`, `certificate`(DER, base64url), `fingerprint`(인증서 SHA-256 16진), 봉인된 키와 PIN·외부인증 포장 값을 담으며 이 형식에서는 불투명한 값입니다. |

**담지 않는 것:** 실행 기록(ledger)·중단 표시, PIN, 은행 세션·쿠키·토큰, 만든 쪽의 로컬 경로(`customer_source*`, `enrollment.run`). 가져오는 쪽은 새 기록으로 시작합니다.

## 가져올 때 검증

복호화 뒤 다음을 모두 확인하고 하나라도 어긋나면 저장하지 않습니다. 인증서와 키의 내용은 해석하지 않으며 은행에 묻지 않습니다.

- 최상위 키가 위 여섯 개와 정확히 같고 `version`이 `1`입니다(`invalid_bundle_content`).
- `app_identity.android_id`가 16자리 소문자 16진이고, `device_id`가 Java `UUID.nameUUIDFromBytes(android_id + "OQF")`와 같으며 `profile.device_id`와도 같습니다(`bundle_device_binding_failed`).
- `SHA-256(app_key)`가 `app_identity.key_sha256`과 같습니다(`bundle_app_key_mismatch`).
- `profile.enrollment.state`가 `ready`입니다(`bundle_enrollment_not_ready`).
- `cloud.device_id`가 `device_id`와 같고 `private_key`가 비어 있지 않습니다(`bundle_cloud_binding_failed`).
- `records`가 비어 있지 않고, 각 기록의 `alias`가 키와 같고 `device_id`가 같으며 `SHA-256(certificate)`가 `fingerprint`와 같습니다(`bundle_record_binding_failed`).

## `fin hana onesign`

```sh
fin hana onesign import --name main --bundle /path/to/vault.bundle   # 암호를 물음(--password-stdin 가능)
fin hana onesign list                                                # 보관한 번들 이름
fin hana onesign show --name main                                    # 인증서 지문·등록 상태(암호 필요)
fin hana onesign export --name main --output /path/to/new.bundle     # 봉인된 바이트를 그대로 복사
```

- `import`는 번들을 열어 검증한 뒤 **봉인된 바이트를 그대로** `fin paths`의 데이터 위치 아래 `hana/onesign/<이름>/bundle.json`(0600, 디렉터리 0700)에 보관합니다. 같은 이름이나 이미 있는 출력 경로는 덮어쓰지 않습니다. 평문은 디스크에 쓰지 않습니다.
- `export`는 암호를 다시 묻지 않고 봉인된 파일을 복사하므로 가져올 때의 암호가 그대로 유지됩니다.
- `show`는 고객번호·별칭·키를 출력하지 않습니다.
- 이 명령들은 로그인·서명·이체를 하지 않습니다. 보관한 번들을 로그인에 쓰는 명령은 아직 없습니다.

## 고정 벡터

`tests/fixtures/onesign-bundle-v1.json`은 합성 자료로 만든 번들이고 암호는 `Synthetic-Bundle-Pass-01`입니다. 솔트·nonce가 고정되어 있어 다른 구현이 같은 바이트를 만들고 열 수 있는지 대조하는 데 씁니다. 테스트는 표준 라이브러리(`hashlib.scrypt`)와 `cryptography`의 AES-GCM으로 형식 문서만 보고 이 파일을 다시 만들어 바이트가 같은지 확인합니다.
