"""Gson-compatible model handling, separate from CLI diagnostics.

Model metadata is extracted from DEX; unknown fields are ignored. Token rules
and duplicate-member preservation are implemented in json_reader.
"""
from functools import lru_cache
from importlib.resources import files
import json
import math
import re

from .errors import GiroError, ResponseError
from .json_reader import JsonNumber, JsonObject, loads


def string_value(value):
    """Gson TypeAdapters.STRING: null, boolean, string, number; not containers."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return str(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float) and math.isfinite(value):
        return str(value)
    raise GiroError("Gson String 어댑터에서 읽을 수 없는 값 형식")


def json_value(value):
    """Compact JsonElement rendering (non-HTML-safe, preserves number tokens)."""
    if isinstance(value, JsonNumber):
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(json_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(json_value(str(key)) + ":" + json_value(item)
                              for key, item in value.items()) + "}"
    try:
        rendered = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        raise GiroError("Gson 기본 직렬화에서 지원하지 않는 값") from None
    return rendered.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


@lru_cache(maxsize=1)
def schema():
    return json.loads(files("giro").joinpath("model_schema.json").read_text(encoding="utf-8"))


def _read_model(value, name):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise GiroError("Gson 객체 어댑터에서 읽을 수 없는 값 형식")
    fields, result = {}, {}
    while name:
        model = schema()["models"][name]
        fields.update(model['fields'])
        result.update({field: model.get('defaults', {}).get(field) for field in model['fields']})
        name = model.get('parent')
    # Gson reads every occurrence in order; invalid earlier duplicates cannot
    # be hidden by overwriting the dict with a later valid value.
    for field, item in value.pairs if isinstance(value, JsonObject) else value.items():
        if field not in fields:
            continue
        kind = fields[field]
        if item is None:
            result[field] = None
        elif kind == "string":
            result[field] = string_value(item)
        elif "model" in kind:
            result[field] = _read_model(item, kind["model"])
        elif "list" in kind:
            if not isinstance(item, list):
                raise GiroError("Gson List 어댑터에서 읽을 수 없는 값 형식")
            result[field] = [_read_model(element, kind["list"]) for element in item]
        elif "list_scalar" in kind:
            if not isinstance(item, list):
                raise GiroError("Gson List 어댑터에서 읽을 수 없는 값 형식")
            result[field] = [string_value(element) for element in item]
    return result


def read_model(value, endpoint):
    return _read_model(value, schema()["entrypoints"][endpoint])


def omit_null_fields(value):
    # Gson's default serializeNulls=false skips object members, not array slots.
    if isinstance(value, dict):
        return {key: omit_null_fields(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [omit_null_fields(item) for item in value]
    return value


def successful_response(document, endpoint):
    try:
        response = read_model(document, endpoint)
        if response is None:
            raise GiroError("null query")
    except GiroError:
        # QueryClientImpl catches model/decode exceptions as code 605.
        raise ResponseError(None, callback_code="605", origin="model_decode") from None
    if response.get("responseCode") != "000":
        raise ResponseError(response.get("responseCode"), error_info=response.get("errorInfo"))
    return response


def java_int(value):
    """Integer.parseInt decimal / signed 32-bit, for the app's next-page path."""
    text = string_value(value)
    if text is None or not re.fullmatch(r"[+-]?\d+", text):
        raise ValueError("not a Java integer")
    # Java iterates UTF-16 chars, so supplementary-plane digits are not digits.
    if any(ord(char) > 0xFFFF for char in text):
        raise ValueError("not a Java char digit")
    negative = text.startswith("-")
    digits = text[1:] if text[0] in "+-" else text
    result = 0
    limit = 2**31 if negative else 2**31 - 1
    for digit in digits:
        result = result * 10 + int(digit)
        if result > limit:
            raise ValueError("outside Java int range")
    return -result if negative else result
