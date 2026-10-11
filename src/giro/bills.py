"""Normalize already-decrypted response JSON, preserving uncertain data."""
from datetime import date, timedelta
from itertools import islice
import re

from .compat import java_int, string_value, successful_response
from .errors import GiroError

from .bill_catalog import BILL_TYPES, SIMPLE_TYPES
TAX_TYPES = BILL_TYPES


def _tax_type(tax_type):
    if tax_type not in TAX_TYPES:
        raise GiroError("지원하지 않는 세목")


def _string(item, key):
    return string_value(item.get(key))


def parse_date(raw):
    raw = string_value(raw)
    if raw is None:
        return None
    # Tolerant import formats, not a claim about the live server's date format.
    match = re.fullmatch(r"([0-9]{4})([0-9]{2})([0-9]{2})", raw.strip())
    if match:
        parts = match.groups()
    else:
        match = re.fullmatch(r"([0-9]{4})([-./])([0-9]{2})\2([0-9]{2})", raw.strip())
        if not match:
            return None
        parts = (match[1], match[3], match[4])
    try:
        return date(*map(int, parts)).isoformat()
    except ValueError:
        return None


def _bill(item, tax_type):
    if not isinstance(item, dict):
        raise GiroError("paymentList 항목은 객체여야 합니다.")
    due_raw = _string(item, "payLimitDate")
    amount_raw = _string(item, "napbuMny" if tax_type in ('kepco', 'ktcomm', 'tv', 'giro')
                         and 'napbuMny' in item else "payMny")
    amount = None
    if amount_raw is not None:
        value = amount_raw.strip()
        if re.fullmatch(r"[0-9]+|[0-9]{1,3}(?:,[0-9]{3})+", value):
            try:
                amount = int(value.replace(",", ""))
            except ValueError:
                # E.g. Python's integer digit limit: normalization only.
                pass
    identifiers = {k: _string(item, k) for k in ("elecNo", "giroNo", "sortCode", "key")}
    if tax_type in ('social', 'annuity'):
        identifiers['customerNo'] = _string(item, 'customerNo')
    return {
        "tax_type": tax_type,
        "identifiers": identifiers,
        "issuer": _string(item, "companyName"), "tax_name": _string(item, "taxName"),
        "amount": amount, "amount_raw": amount_raw,
        "due_date": parse_date(due_raw), "due_date_raw": due_raw,
    }


def normalize_pages(document, tax_type):
    """App query success and optional collection diagnostics are independent.

    The UI appends lists as received; it does not reject duplicate pages or
    changing totals. Null lists are accepted by Gson / QueryClient, though the
    UI's addAll(null) may throw. Preserve that distinction, do not invent [].
    """
    _tax_type(tax_type)
    pages = document if isinstance(document, list) else [document]
    if not pages:
        raise GiroError("빈 응답 배열은 조회 성공을 증명하지 않습니다.")
    if tax_type in SIMPLE_TYPES:
        if len(pages) != 1:
            raise GiroError('이 항목은 페이지 구분 없는 단일 목록 응답입니다.')
        response = successful_response(pages[0], tax_type + '.list')
        items = response.get('paymentList')
        rows = None if items is None else [None if r is None else _bill(r, tax_type) for r in items]
        issues = ['paymentList null/누락'] if rows is None else []
        if rows is not None and any(r is None for r in rows): issues.append('null 항목 유지')
        if rows is not None and any(r and r['amount_raw'] is not None and r['amount'] is None for r in rows):
            issues.append('금액 정규화 불가; 원문 유지')
        return dict(source='offline-json', tax_type=tax_type, app_success=True, response_code='000',
            complete=not issues, issues=issues, bills=rows, pages=[], page_navi_raw=[],
            total_count=None, loaded_count=None if rows is None else len(rows),
            list_states=['list' if items is not None else 'null' if 'paymentList' in pages[0] else 'missing'],
            missing_pages=[], missing_page_count=None, missing_pages_truncated=False)
    bills, page_info, issues, raw_nav, list_states = [], [], [], [], []
    for document_page in pages:
        response = successful_response(document_page, f"{tax_type}.list")
        items = response.get("paymentList")
        list_states.append("list" if items is not None else "null" if "paymentList" in document_page else "missing")
        if items is None:
            issues.append("paymentList null/누락: 앱 전송 계층은 성공이나 UI addAll은 처리하지 못할 수 있음")
        else:
            for item in items:
                bill = _bill(item, tax_type) if item is not None else None
                bills.append(bill)
                if item is None:
                    issues.append("paymentList의 null 항목을 그대로 유지함")
                elif bill["amount_raw"] is not None and bill["amount"] is None:
                    issues.append("금액 정규화 불가; 원문을 유지함")
        nav = response.get("pageNaviMap")
        raw_nav.append(nav)
        if nav is None:
            issues.append("pageNaviMap 누락: 전체 페이지 수를 확인할 수 없음")
        info = {}
        for key in ("currentPage", "totalPage", "totalCount"):
            try:
                info[key] = java_int((nav or {}).get(key))
            except ValueError:
                info[key] = None
                if nav is not None:
                    issues.append(f"{key} 정수 해석 불가 (조회 성공 판정과 별개)")
        current, total = info["currentPage"], info["totalPage"]
        info["next_page"] = current + 1 if current is not None and total is not None and current < total else None
        if total is not None and (total < 0 or current is not None and
                (total == 0 and (current not in (0, 1) or items or info["totalCount"])
                 or total > 0 and not 1 <= current <= total)):
            issues.append("현재 페이지/전체 페이지/건수의 범위가 일관되지 않음")
        page_info.append(info)
    missing = []
    missing_count = None
    if len({(p["totalPage"], p["totalCount"]) for p in page_info}) != 1:
        issues.append("페이지별 전체 건수/페이지 수 변경; 앱처럼 수신 순서대로 목록을 유지함")
    numbers = [p["currentPage"] for p in page_info if p["currentPage"] is not None]
    if len(set(numbers)) != len(numbers):
        issues.append("중복 페이지; 앱처럼 중복 항목도 유지함")
    # Activity replaces its paging model with the most recently received one.
    last = page_info[-1]
    expected_count, total = last["totalCount"], last["totalPage"]
    if total is not None and total >= 0:
        seen = {number for number in numbers if 1 <= number <= total}
        missing_count = total - len(seen)
        # Bound diagnostic output size, not the accepted page range or success.
        missing = list(islice((number for number in range(1, total + 1) if number not in seen), 1000))
        if missing_count:
            issues.append("수집되지 않은 페이지가 있음")
    if expected_count is not None and len(bills) != expected_count:
        issues.append("목록 건수와 totalCount가 일치하지 않음")
    return {
        "source": "offline-json", "tax_type": tax_type, "app_success": True,
        "response_code": "000", "list_states": list_states,
        "complete": not issues, "issues": issues, "missing_pages": missing,
        "missing_page_count": missing_count, "missing_pages_truncated": missing_count is not None and missing_count > len(missing),
        "total_count": expected_count, "loaded_count": len(bills),
        "pages": page_info, "page_navi_raw": raw_nav,
        "bills": bills if "list" in list_states else None,
    }


def due_bills(result, *, today, within_days, include_overdue=False):
    if not isinstance(today, date) or isinstance(within_days, bool) or not isinstance(within_days, int) or not 0 <= within_days <= 36500:
        raise GiroError("기한 범위는 0~36500일이어야 합니다.")
    try:
        end = today + timedelta(days=within_days)
    except OverflowError:
        raise GiroError("날짜 범위를 벗어났습니다.") from None
    selected, unknown = [], []
    for bill in result["bills"] or []:
        if bill is None or bill["due_date"] is None:
            unknown.append(bill)
            continue
        due = date.fromisoformat(bill["due_date"])
        if due <= end and (include_overdue or due >= today):
            selected.append({**bill, "days_until_due": (due - today).days})
    selected.sort(key=lambda bill: bill["due_date"])
    return {**result, "as_of": today.isoformat(), "through": end.isoformat(),
            "issues": result["issues"] + (["납부기한 정규화 불가 항목은 unparsed_bills에 보존함"] if unknown else []),
            "include_overdue": include_overdue, "bills": selected if result["bills"] is not None else None,
            "unparsed_bills": unknown, "filter_applied": True,
            "filter_complete": result["complete"] and not unknown}


def normalize_detail(response, tax_type):
    _tax_type(tax_type)
    response = successful_response(response, f"{tax_type}.detail")
    item = response.get("paymentData")
    bill = _bill(item, tax_type) if item is not None else None
    issues = [] if item is not None else ["paymentData null/누락; 조회 성공 판정과 별개"]
    if bill is not None and bill["amount_raw"] is not None and bill["amount"] is None:
        issues.append("금액 정규화 불가; 원문을 유지함")
    return {"source": "offline-json", "app_success": True, "response_code": "000",
            "issues": issues, "bill": bill,
            "detail_raw": {key: _string(item or {}, key) for key in (
                "pay1date", "pay2date", "payInMny", "payOutMny", "remainPayMny", "prePaidMny")},
            "note": "pay1date/pay2date를 payLimitDate로 추정하지 않습니다."}
