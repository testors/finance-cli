"""Ports of confirmed native boundaries, not a complete login implementation.

Response functions accept already decoded JSON, after G2.b.r has returned.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Decision:
    scope: str
    branch: str
    native: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"scope": self.scope, "branch": self.branch, "native": self.native}


def _get(obj: Any, key: str) -> Any:
    if not isinstance(obj, dict) or key not in obj:
        raise KeyError(key)
    return obj[key]


def _object(obj: Any, key: str) -> dict:
    value = _get(obj, key)
    if not isinstance(value, dict):
        raise KeyError(key)
    return value


def _matches(obj: Any, key: str, expected: str, *, lower: bool = False) -> bool:
    # Android JSONObject.getString coerces present non-string JSON values.
    # None, booleans, numbers, arrays and objects cannot coerce to S/s/F/f/Y.
    # Compare only these string sentinels without rejecting other values.
    value = _get(obj, key)
    if not isinstance(value, str):
        return False
    return (value.lower() if lower else value) == expected


def certificate_registration(response: Any) -> Decision:
    """XSignCertListActivity$l.doInBackground + onPostExecute, in read order."""
    result: Any = "F"
    message: Any = "Error"
    warnings: list[str] = []
    try:
        body = _object(response, "RESULT")
        message = _get(body, "msg")
        result = _get(body, "result")
        _get(body, "code")  # Read for side effect only; its value is ignored.
    except KeyError as error:
        warnings.append(f"서비스의 {error.args[0]} 읽기 예외: 이미 읽은 값을 유지합니다.")
    branch = "no_action"
    if isinstance(result, str):
        if result.lower() == "s":
            branch = "success"
        elif result.lower() == "f":
            branch = "failure"
    if branch == "no_action":
        warnings.append("성공·실패 대화상자 분기가 없는 result 값입니다.")
    # Keep input JSON values; do not impose a schema or discard unknown values.
    return Decision("certificate_registration", branch,
                    {"result": result, "message_value": message}, warnings)


def logout(responses: list[Any]) -> Decision:
    """MainActivity$r: six reads, but only codes[0] controls local logout."""
    warnings: list[str] = []
    first_success = False
    for index in range(6):
        try:
            response = responses[index] if index < len(responses) else None
            body = _object(response, "resultMsg")
            success = _matches(body, "code", "S")
            if index == 0:
                first_success = success
            elif not success:
                warnings.append(f"도메인 {index + 1} 응답이 S가 아닙니다. 첫 도메인의 판정은 유지합니다.")
        except KeyError:
            warnings.append(f"도메인 {index + 1}의 resultMsg.code 읽기 예외입니다.")
    if len(responses) > 6:
        warnings.append("서비스는 6개 도메인만 처리하므로 추가 응답은 판정에 사용하지 않습니다.")
    # Original has no explicit failure callback; do not fabricate one.
    return Decision("logout", "success" if first_success else "no_action",
                    {"clear_cookies": first_success, "load_home": first_success}, warnings)


def qr_confirmation(response: Any) -> Decision:
    """MainActivity$t$a$a: transactionState then lbdyVrfYn, case-sensitive."""
    transaction_ok = False
    identity_ok = False
    warnings: list[str] = []
    try:
        transaction_ok = _matches(response, "transactionState", "S")
        identity_ok = _matches(response, "lbdyVrfYn", "Y")
    except KeyError as error:
        warnings.append(f"서비스의 {error.args[0]} 읽기 예외입니다.")
    return Decision("qr_confirmation", "success" if transaction_ok and identity_ok else "failure",
                    warnings=warnings)


def fido_auth_callback(original: dict, request_code: int, error_code: int,
                       description: str | None, token: str | None) -> Decision:
    """X4.c$d.onFIDOResult. The SDK boolean is intentionally not an input."""
    if request_code != 178:
        return Decision("fido_auth_callback", "no_action")
    result = dict(original)
    warnings: list[str] = []
    if error_code == 0:
        if token is None:
            result.pop("token", None)  # JSONObject.put(key, (Object) null).
        else:
            result["token"] = token
        if not token:
            warnings.append("SDK 성공의 token이 비어 있습니다. 서비스의 result=true를 유지합니다.")
    result["errorCode"] = error_code
    if description is None:
        result.pop("message", None)
    else:
        result["message"] = description
    result["result"] = error_code == 0
    return Decision("fido_auth_callback", "success" if error_code == 0 else "failure",
                    result, warnings)


def java_form_encode(value: str) -> str:
    """Java URLEncoder UTF-8 safe alphabet; unlike Python, ~ is escaped."""
    safe = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-*_"
    return "".join(chr(byte) if byte in safe else "+" if byte == 32 else f"%{byte:02X}"
                   for byte in value.encode("utf-8", errors="replace"))


def certificate_callback(sign_data_base64: str, vid_random_base64: str) -> dict:
    """Encode already-produced SDK strings. Does not generate or validate CMS."""
    sign_data = java_form_encode(sign_data_base64.replace("+", "%2B"))
    random = java_form_encode(vid_random_base64.replace("+", "%2B"))
    payload = {"certResult": "SUCC", "signData": sign_data, "randomEnc": random}
    javascript = ("javascript:nts_calledByNative({'certResult':'SUCC', 'signData':'"
                  + sign_data + "', 'randomEnc':'" + random + "'})")
    return {"scope": "certificate_callback_encoding", "payload": payload,
            "javascript": javascript}


def fido_context(auth_code: str, device_model: str, android_release: str,
                 policy_id: str | None = None) -> dict:
    """X4.a.a input boundary; SDK may further transform this before sending."""
    context = {"userName": "", "deviceModel": device_model,
               "deviceOS": "A|" + android_release, "authcode": auth_code}
    if policy_id is not None:
        context["policyId"] = policy_id
    return context
