"""Read-only, allowlisted evidence from sealed identity-verification receipts."""
import base64
import gzip
import json
import re

from Crypto.Cipher import AES

from finance_cli.services.hana import hana_protocol, onesign_issue_protocol as protocol


def code(value):
    return value if isinstance(value, str) and re.fullmatch(r'[A-Z0-9_]{1,40}', value) else None


def response_summary(receipt):
    result = {}
    if type(receipt.get('status')) is int:
        result['http_status'] = receipt['status']
    verdict = receipt.get('service_status')
    if verdict in ('accepted', 'rejected', 'unconfirmed'):
        result['service_status'] = verdict
    headers = {k.lower(): v for k, v in receipt.get('headers', [])}
    system = hana_protocol.decode_header(headers['hana-sys-header']) if 'hana-sys-header' in headers else {}
    common = hana_protocol.decode_header(headers['hana-com-header']) if 'hana-com-header' in headers else {}
    system = system.get('CHNL_SYS_HDPT', {})
    for source, target in (('PROC_RSLT_DV_CD', 'processing_code'), ('STD_TMSG_ERR_CD', 'standard_error_code')):
        value = code(system.get(source))
        if value:
            result[target] = value
    messages = common.get('STD_MSGPT') or []
    if isinstance(messages, list):
        messages = [item for row in messages if isinstance(row, dict)
                    for item in [row, *(row.get('MSG_INFO_REPT') or [])] if isinstance(item, dict)]
        result['error_codes'] = list(dict.fromkeys(value for row in messages if isinstance(row, dict)
            for key in ('OGN_ERR_CD', 'MSG_CD') if (value := code(row.get(key)))))[:10]
        # Only fixed categories and clock times leave the encrypted record. Bank
        # message text may contain names, IDs, or other private request values.
        text = ' '.join(row['MSG_CTT'] for row in messages if isinstance(row.get('MSG_CTT'), str))
        hints = []
        if re.search(r'(이용|가능|운영|서비스|업무)\s*시간|시간\s*(외|이후)|점검', text):
            hints.append('service_hours')
            result['service_times'] = list(dict.fromkeys(re.findall(r'(?<!\d)(?:[01]?\d|2[0-4]):[0-5]\d(?!\d)', text)))[:4]
        if re.search(r'불일치|일치하지|잘못\s*입력|정보를?\s*확인', text):
            hints.append('identity_information_check')
        if re.search(r'재발급|분실|유효하지|유효기간', text):
            hints.append('identity_validity_check')
        if re.search(r'일시적|장애|응답.*없|기관.*연결', text):
            hints.append('service_unavailable')
        if hints:
            result['message_hints'] = hints
        result['information_mismatch_reported'] = bool(re.search(r'불일치|일치하지', text))
        fields = {'name': r'이름|성명', 'resident_number': r'주민', 'birth_date': r'생년월일',
                  'driver_number': r'면허번호|운전면허', 'issue_date': r'발급일',
                  'image': r'사진|이미지|촬영', 'decryption': r'암호|복호',
                  'application': r'신청번호', 'customer': r'고객|본인', 'identity': r'신분증'}
        mentioned = [key for key, pattern in fields.items() if re.search(pattern, text)]
        if mentioned:
            result['message_fields'] = mentioned
    raw = base64.b64decode(receipt.get('body') or '', validate=True)
    if headers.get('content-encoding', '').lower() == 'gzip':
        raw = gzip.decompress(raw)
    try:
        body = json.loads(raw)
    except (ValueError, UnicodeError):
        body = None
    if isinstance(body, dict):
        if type(body.get('scss')) is bool:
            result['image_accepted'] = body['scss']
        if code(body.get('rspsCd')):
            result['identity_response_code'] = body['rspsCd']
    return result


def identity_diagnostics(state, snapshot):
    """Inspect the last identity attempt without changing its verdict or state."""
    run = next((key for key, value in reversed(list(snapshot.get('runs', {}).items()))
                if value.get('operation') == 'identity'), None)
    if not run:
        return None
    result = {'network_used': False, 'requests': []}
    try:
        request = state.read_record(run, 'http-0002-request')
        body = json.loads(base64.b64decode(request['body'], validate=True))
        phone = snapshot['signup']['phone']
        capture = snapshot['issuance']['capture']
        application = snapshot['issuance']['application']
        raw = base64.b64decode(body['resRegNo2'], validate=True)
        tail = AES.new(protocol.ocr_key(application), AES.MODE_GCM, nonce=raw[:12]).decrypt_and_verify(raw[12:-16], raw[-16:]).decode()
        result['input_checks'] = {
            'name_matches_phone': body.get('custNm') == phone['name'],
            'name_is_document_label': body.get('custNm') in ('운전면허증', '운전면허', '면허증', '주민등록증', '신분증'),
            'birth_matches_phone': body.get('resRegNo1') == phone['birth7'][:6],
            'resident_prefix_matches_phone': tail[:1] == phone['birth7'][6:],
            'resident_tail_seven_digits': bool(re.fullmatch(r'[0-9]{7}', tail)),
            'request_matches_capture': body == protocol.id_body(application, snapshot['issuance']['capture_kind'], capture),
        }
    except Exception:
        result['input_checks'] = {'available': False}
    for number, stage in ((1, 'image'), (2, 'identity')):
        try:
            receipt = state.read_record(run, f'http-{number:04d}-response')
            result['requests'].append({'stage': stage, **response_summary(receipt)})
        except FileNotFoundError:
            result['requests'].append({'stage': stage, 'receipt': 'not_available'})
        except Exception:
            result['requests'].append({'stage': stage, 'receipt': 'unreadable'})
    return result
