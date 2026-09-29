"""Logical web boundary of UTBMPBAA01F001, before security-script transport."""

import json
import re
from urllib.parse import quote, unquote

from .auth import Decision, certificate_callback


def javascript_payload(native_callback: dict) -> dict:
    # WebView.loadUrl executes a javascript: URL after percent decoding once.
    # This is not form decoding: literal + must not become a space here.
    return {key: unquote(value) if isinstance(value, str) else value
            for key, value in native_callback["payload"].items()}


def certificate_request(sign_data_base64: str, vid_random_base64: str,
                        app_version="14.3", os_name="Android", department_id=None) -> dict:
    payload = javascript_payload(certificate_callback(sign_data_base64, vid_random_base64))
    params = {"pkcLoginYn": "Y", "mobOsNm": os_name, "mobPgmVrsnNm": app_version,
              "signData": re.sub(r"[+\s]", "%2B", payload["signData"]),
              "scrnId": "UTBMPBAA01",
              "randomEnc": re.sub(r"[+\s]", "%2B", payload["randomEnc"])}
    if department_id is not None:
        params.update(dprtLoginId=department_id, dprtLoginYn="Y")
    serialized = json.dumps(params, ensure_ascii=False, separators=(",", ":"))
    return {"scope": "logical_web_request_before_security_script", "method": "POST",
            "url": "https://mob.hometax.go.kr/pubcMobLogin.do",
            "content_type": "application/x-www-form-urlencoded;charset=UTF-8",
            "params": params,
            "body": "datas=" + quote(serialized, safe="~()*!.'-_") + "&m="}


_UNDEFINED = object()


def _property(value, key):
    if value is None or value is _UNDEFINED:
        raise TypeError("JavaScript null/undefined property access")
    return value.get(key, _UNDEFINED) if isinstance(value, dict) else _UNDEFINED


def _js_string(value):
    if isinstance(value, list):
        return ",".join("" if child is None else _js_string(child) for child in value)
    if isinstance(value, dict):
        if "toString" in value:
            # JSON cannot contain a callable override. An own non-function
            # toString prevents OrdinaryToPrimitive from producing a value.
            raise TypeError("JavaScript object conversion")
        return "[object Object]"
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def certificate_login(response) -> Decision:
    """Original `msgCode.result.resultMsg.code != 'S'` loose comparison.

    No response-cookie, rtnVal or session-field requirements added to success.
    """
    try:
        result = _property(response, "result")
        result_message = _property(result, "resultMsg")
        code = _property(result_message, "code")
    except TypeError:
        return Decision("web_certificate_login", "no_action", {"callback_exception": True},
                        ["서비스 JavaScript가 상위 응답 객체 접근 중 예외로 중단되는 형태입니다."])
    # With a string sentinel S, only strings and arrays' primitive strings can
    # compare equal. Numbers/bools/null/undefined cannot equal nonnumeric S.
    try:
        success = isinstance(code, (str, list, dict)) and _js_string(code) == "S"
    except TypeError:
        return Decision("web_certificate_login", "no_action", {"callback_exception": True},
                        ["서비스 JavaScript의 코드 비교 중 객체 변환 예외가 발생하는 형태입니다."])
    warnings = []
    if success:
        if code != "S":
            warnings.append("코드가 문자열은 아니지만 서비스 JS의 느슨한 비교에서 S와 같습니다.")
        if not isinstance(result, dict) or not isinstance(result.get("rtnVal"), dict):
            warnings.append("후속 세션 분기에 쓰는 rtnVal이 없습니다. 로그인 성공 판정은 유지합니다.")
    return Decision("web_certificate_login", "success" if success else "failure",
                    {"recentLoginClCd": "certifi"} if success else {}, warnings)
