"""Read-only security-management contracts from the archived web application.

Unknown/empty data is retained as an observation, never used to authorize a
mutation. Numeric/string state distinctions follow the original JS predicates.
"""
from decimal import Decimal
import math

from .compat import MISSING, truthy

# path, body omitted, original screen
QUERIES = {
    'limits': ('/api/pcm/trns01/capi/trnsLimUpd/retrieveTrnsLim', False, 'TRNB1001001001'),
    'limit-exception': ('/api/pcm/trns01/capi/trnsLimExcApcMgnt/retrieveTrnsLimExcApc', False, 'TRNB1005001001'),
    'security-media': ('/api/pcm/lgin01/capi/scrtMdclCom/retrieveScrtMdclInfo', False, 'COMB0401001001'),
    'otp': ('/api/pcm/lgin01/capi/otp/retrieveOtpInfo', True, 'COMB0403002002'),
    'otp-accident': ('/api/pcm/lgin01/capi/otp/retrieveOtpAcdtDcl', True, 'COMB0403003001'),
    'mobile-otp': ('/public/pcm/lgin01/capi/mbleOtp/retrieveMbleOtpApc', True, 'COMB0402004001'),
}
INACTIVE_OTP = ('111', '112', '130', '131', '132', '', '120', '140', '902', '903', '906')
LIMIT_MAXIMA = {'card': ('10,000,000', '10,000,000'),
                'mobile': ('50,000,000', '10,000,000'),
                'otp': ('500,000,000', '100,000,000')}


def limit_display(value):
    """Snapshot UI ceiling and exception prompt, not the customer's entitlement."""
    medium = ('card' if value.get('scrtMdclDvCd') == '1' else
              'mobile' if value.get('mbphOtpYn') == 'Y' else 'otp')
    daily, once = LIMIT_MAXIMA[medium]
    return {'medium': medium, 'daily_ceiling_text': daily, 'once_ceiling_text': once,
            'exception_prompt': value.get('trnsLimRslt') == 'true'}


def display_text(value):
    """JS string coercion for the JSON values used in status labels."""
    if value is MISSING: return 'undefined'
    if value is None: return 'null'
    if isinstance(value, str): return value
    if type(value) is bool: return 'true' if value else 'false'
    if isinstance(value, list):
        return ','.join('' if item is None else display_text(item) for item in value)
    if isinstance(value, dict): return '[object Object]'
    number = float(value)
    if not math.isfinite(number):
        return 'NaN' if math.isnan(number) else 'Infinity' if number > 0 else '-Infinity'
    if number == 0: return '0'
    decimal = Decimal(repr(number)).normalize()
    if 1e-6 <= abs(number) < 1e21: return format(decimal, 'f')
    mantissa, exponent = format(decimal, 'e').split('e')
    return mantissa + 'e' + ('+' if int(exponent) >= 0 else '-') + str(abs(int(exponent)))


def otp_display(row):
    serial, state = row.get('otpSeqNo'), row.get('scrtMdclStCd')
    label = row.get('scrtMdclStNm', MISSING)
    return {'mobile': isinstance(serial, str) and serial.startswith(('910', '810')),
            'original_status_indicator': state not in INACTIVE_OTP if state is not None else False,
            'status_name': '금결원 조회 오류' if label == '' else display_text(label)}


def observe(kind, value):
    """Keep server values unchanged. Diagnostics do not reject accepted queries."""
    if kind not in QUERIES:
        raise ValueError('Unknown inquiry')
    result = {'fields': {}, 'rows': [], 'display': {}, 'diagnostics': []}
    if not isinstance(value, dict):
        result['diagnostics'].append('empty_body' if value == '' else 'non_object_body')
        return result
    keys = {
        'limits': ('dd1TrnsLimAmt', 'bot1TrnsLimAmt', 'scrtMdclDvCd', 'mbphOtpYn', 'trnsLimRslt'),
        'limit-exception': ('oldDd1TrnsLimAmt', 'oldBot1TrnsLimAmt', 'dd1TrnsLimAmt',
                            'bot1TrnsLimAmt', 'dd1TrnsPossLimAmt', 'bot1TrnsPossLimAmt'),
        'security-media': ('errNcnt', 'scrtCrdInfoSvcRecOutDto'),
        'otp': ('allNcnt',), 'otp-accident': ('acdtRcvryPoss',), 'mobile-otp': ('issu', 'lgin'),
    }[kind]
    result['fields'] = {k: value[k] for k in keys if k in value}
    if not result['fields']:
        result['diagnostics'].append('display_fields_absent')
    if kind == 'limits':
        result['display'] = limit_display(value)
    dto = {'security-media': 'otpInfoSvcRecOutDto', 'otp': 'otpInfoInqSvcRecOutDto',
           'otp-accident': 'otpAcdtRcvryInqSvcOutRecDto', 'mobile-otp': 'mbleOtpApcInqSvcOutRecDto'}.get(kind)
    if dto:
        rows = value.get(dto)
        if isinstance(rows, list):
            result['rows'] = rows  # Preserve order and unexpected entries, including null.
            if any(not isinstance(row, dict) for row in rows):
                result['diagnostics'].append('non_object_row')
        elif rows is not None:
            result['diagnostics'].append('non_array_rows')
        first = rows[0] if isinstance(rows, list) and rows else None
        if kind == 'otp':
            selected = first if truthy(value.get('allNcnt')) else None
            result['display']['original_selected_row'] = selected
            if truthy(value.get('allNcnt')) and first is None:
                result['diagnostics'].append('original_first_row_unavailable')
        elif kind == 'otp-accident':
            result['display'] = {'accident_reported': isinstance(first, dict) and first.get('scrtMdclStCd') == '120',
                                 'recovery_offered': truthy(value.get('acdtRcvryPoss'))}
        elif kind == 'mobile-otp':
            result['display'] = {'issued': truthy(value.get('issu')),
                                 'locked': isinstance(first, dict) and first.get('scrtMdclStCd') == '903'}
        elif isinstance(first, dict):
            result['display'] = otp_display(first)
            if not isinstance(first.get('otpSeqNo'), str):
                result['diagnostics'].append('original_serial_render_unavailable')
    return result
