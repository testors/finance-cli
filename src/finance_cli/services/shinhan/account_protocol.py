"""Account response decoding, reference assembly and Shinhan display selection."""
import copy
from decimal import Decimal
import json
import math
import re
import unicodedata

from . import transport


class Reader:
    """Typed lenient JSON with optional-null skipping and ordered duplicates."""
    def __init__(self, text):
        self.text, self.pos = text, 0

    def peek(self):
        while self.pos < len(self.text) and self.text[self.pos] in ' \r\n\t':
            self.pos += 1
        return self.text[self.pos:self.pos+1]

    def take(self, char):
        if self.peek() != char:
            raise ValueError('account_json_syntax')
        self.pos += 1

    def token(self):
        if self.peek() == '"':
            value, self.pos = json.JSONDecoder().raw_decode(self.text, self.pos)
            return value, True
        start = self.pos
        while self.pos < len(self.text) and self.text[self.pos] not in '{}[],: \r\n\t':
            self.pos += 1
        if start == self.pos:
            raise ValueError('account_json_token')
        return self.text[start:self.pos], False

    def skip(self):
        # Unknown values are skipped structurally; nested trailing commas are
        # not subjected to a known DTO's field/list decoding rules.
        char = self.peek()
        if char in ('{', '['):
            self.pos += 1
            end = '}' if char == '{' else ']'
            while self.peek() != end:
                if not self.peek():
                    raise ValueError('account_json_unclosed')
                if self.peek() in (',', ':'):
                    self.pos += 1
                else:
                    self.skip()
            self.pos += 1
        else:
            self.token()

    def value(self, kind):
        char = self.peek()
        if self.text.startswith('null', self.pos) and self.text[self.pos+4:self.pos+5] in ('', ',', '}', ']', ' ', '\r', '\n', '\t'):
            self.pos += 4
            return None
        if isinstance(kind, dict):
            self.take('{')
            result = {key: copy.deepcopy(default) for key, (_, default) in kind.items()}
            if self.peek() != '}':
                while True:
                    key, _ = self.token()
                    self.take(':')
                    if key in kind:
                        spec, default = kind[key]
                        value = self.value(spec)
                        if value is not None or default is None or spec == 'nullable_string':
                            result[key] = value
                    else:
                        self.skip()
                    if self.peek() == '}':
                        break
                    self.take(',')
            self.take('}')
            return result
        if isinstance(kind, list):
            self.take('[')
            result = []
            if self.peek() != ']':
                while True:
                    value = self.value(kind[0])
                    if value is None:
                        raise ValueError('account_null_list_item')
                    result.append(value)
                    if self.peek() == ']':
                        break
                    self.take(',')
            self.take(']')
            return result
        value, _ = self.token()
        if kind in ('string', 'nullable_string'):
            return value
        if kind == 'int':
            if not re.fullmatch(r'-?[0-9]+(?:[eE][+-]?[0-9]+)?', value):
                raise ValueError('account_integer')
            number = Decimal(value)
            if not number.is_finite() or number < -2**31 or number > 2**31-1 or number != number.to_integral_value():
                raise ValueError('account_integer_range')
            return int(number)
        if kind == 'double':
            value = value.strip(''.join(map(chr, range(33))))
            if not re.fullmatch(r'[+-]?(?:(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|0[xX][0-9a-fA-F]+(?:\.[0-9a-fA-F]*)?[pP][+-]?[0-9]+)[dDfF]?', value):
                raise ValueError('account_double')
            value = value[:-1] if value[-1:] in 'dDfF' else value
            number = float.fromhex(value) if 'x' in value.lower() else float(value)
            if not math.isfinite(number):
                raise ValueError('account_double_range')
            return number
        raise ValueError('account_json_type')


def strings(names):
    return {name: ('string', '') for name in names.split()}


REF = strings('assetRefKey')
BUTTON = strings('assetBtnNm assetBtnNmColtn assetBtnPrgId assetBtnParam assetBtnPopYn assetBtnPopTitle assetBtnPopMsg')
BUTTON['assetBtnNmColtn'] = ('string', 'tertiary')
ROW = strings('assetRefKey assetU assetK assetCtgrId assetNoDisp assetSMsg assetSMsgColtn assetExtraMsg assetExtraMsgColtn assetOrgNm assetScrAmt assetNm assetCalcG assetOrgC assetOrgFullNm assetCurC assetTrnNo assetSuikrDispYn assetRepYn assetRepPosbYn assetHideYn assetPrgId assetPrgParam assetOrgC_display assetOrgFullNm_display assetNo_originalValue assetPrdtC assetEncNo mydataOutOrgC')
ROW.update(assetSno=('int', 0), assetAmt=('double', 0.0), assetSuikrV=('double', 0.0),
           assetBtnList=([BUTTON], []), subAssetRefKeyList=([REF], []), assetCalcG=('string', '3'),
           assetSMsgColtn=('string', 'text-secondary'), assetExtraMsgColtn=('string', 'text-secondary'))
CATEGORY = strings('ctgrId ctgrType ctgrNm ctgrPrgId ctgrPrgParam')
CATEGORY.update(ctgrDefaultSno=('int', 999), ctgrCustomSno=('int', 999), ctgrAssetAmtSum=('double', 0.0), assetRefKeyList=([REF], []))
SUMMARY = strings('mydaLstUpdIlsi notiMsgCtnt notiMsgTypC notiPageId notiPageParam')
BROKER = strings('prdtUC brkrMsgCtnt brkrColtnCtnt brkrIconPathCtnt pageId')
BODY = {'totalSummary': (SUMMARY, {key: '' for key in SUMMARY}), 'assetList': ([ROW], []),
        'mainCtgrList': ([CATEGORY], []), 'brkrMsgList': ([BROKER], [])}
HEADER = {key: ('string', None) for key in ('result', 'resultCode', 'secChal1', 'secChal2')}
CATEGORY_TYPES = dict(zip(('C'+str(n) for n in range(1, 21)),
    'CHECKING_ACCOUNT SAVINGS_ACCOUNT CLUB_ACCOUNT FOREIGN_CURRENCY GOLD_SILVER FUND TRUST ISA INVESTMENT RETIREMENT_PENSION BOND CONTRIBUTION INSURANCE DEDUCTION LOAN PAY_POINT DORMANT REAL_ESTATE CAR INPUT'.split()))
SHINHAN = ('088', '021', '026')


def decode(text, schema=BODY):
    reader = Reader(text)
    result = reader.value(schema)
    if reader.peek() or result is None:
        raise ValueError('account_json_document')
    return result


def parse_reply(reply):
    # Read the header independently so later body-processing errors cannot
    # overwrite an observed SUCCESS with an inferred bank failure.
    try:
        text = reply.body.decode('utf-8-sig')
        document = decode(text, {'dataHeader': (HEADER, None)})
    except (ValueError, UnicodeError, RecursionError):
        return transport.parse(reply)
    verdict, _ = transport.parse(transport.Reply(reply.status, reply.headers, json.dumps(document).encode(), reply.error))
    if verdict['bank_result'] == 'success':
        try:
            document = decode(text, {'dataHeader': (HEADER, None), 'dataBody': (BODY, None)})
            if document['dataBody'] is None:
                raise ValueError('account_body_null')
        except (ValueError, ArithmeticError, RecursionError):
            verdict.update(processing_status='incomplete', error='account_body_unavailable')
            document['dataBody'] = None
    return verdict, document


def category_type(code):
    return CATEGORY_TYPES.get(code, 'UNKNOWN')


def mapped(value, fields):
    return {target: value[source] for source, target in fields.items()}


def button(value):
    result = mapped(value, dict(zip(BUTTON, ('buttonName', 'buttonType', 'programId', 'programParam', 'flag', 'popupTitle', 'popupMessage'))))
    blank = all(ch in '\t\n\v\f\r\x1c\x1d\x1e\x1f' or unicodedata.category(ch) in ('Zs', 'Zl', 'Zp') for ch in result['popupMessage'])
    result['isShowPopup'] = result.pop('flag') == 'Y' and not blank
    return result


def row(value):
    fields = {'assetRefKey': 'key', 'assetU': 'assetU', 'assetK': 'assetK', 'assetCtgrId': 'categoryCode',
              'assetNoDisp': 'accountNumber', 'assetNo_originalValue': 'accountNumberOriginal', 'assetSno': 'seqNum',
              'assetSMsg': 'state', 'assetSMsgColtn': 'stateColor', 'assetExtraMsg': 'extraMessage',
              'assetExtraMsgColtn': 'extraMessageColor', 'assetAmt': 'amount', 'assetScrAmt': 'amountScreen',
              'assetNm': 'accountName', 'assetCalcG': 'assetCalcG', 'assetOrgC': 'orgCode', 'assetCurC': 'currency',
              'assetTrnNo': 'trnNo', 'assetSuikrV': 'yield', 'assetPrgId': 'programId', 'assetPrgParam': 'programParam',
              'assetPrdtC': 'productCode', 'assetEncNo': 'assetEncNumber', 'mydataOutOrgC': 'myDataOrgCode'}
    result = mapped(value, fields)
    result['categoryType'] = category_type(result['categoryCode'])
    insurance = result['categoryType'] in ('INSURANCE', 'DEDUCTION')
    result['orgName'] = value['assetOrgNm' if insurance else 'assetOrgC_display']
    result['orgFullName'] = value['assetOrgFullNm' if insurance else 'assetOrgFullNm_display']
    result.update({target: value[source] == 'Y' for source, target in
        [('assetSuikrDispYn', 'isShowYield'), ('assetHideYn', 'isHide'), ('assetRepYn', 'isRepresent'), ('assetRepPosbYn', 'isRepresentPossible')]})
    result['buttonList'] = [button(item) for item in value['assetBtnList']]
    result['subAccountList'] = []
    balance = {'assetKey': result['key'], 'kind': 'Loading'}
    if result['orgCode'] in SHINHAN or result['assetU'] in ('3', '4') or insurance:
        balance.update(kind='Success', amount=result['amount'], amountScreen=result['amountScreen'], **{'yield': None, 'buttonList': []})
    result['balanceUpdate'] = balance
    return result


def summary(value):
    return mapped(value, dict(zip(SUMMARY, ('myDataLastUpdateTime', 'notiMsgContent', 'notiMsgType', 'notiProgramId', 'notiProgramParam'))))


def broker(value):
    return mapped(value, dict(zip(BROKER, ('categoryId', 'message', 'bgColorType', 'iconPath', 'programId'))))


def categories(body):
    rows = [row(value) for value in body['assetList']]
    def resolve(refs, candidates):
        selected = []
        for ref in refs:
            match = next((item for item in candidates if item['key'] == ref['assetRefKey']), None)
            if match is not None:
                selected.append(match)
        return sorted(selected, key=lambda item: item['seqNum'])
    linked = [{**item, 'subAccountList': resolve(value['subAssetRefKeyList'], rows)} for item, value in zip(rows, body['assetList'])]
    messages = [broker(value) for value in body['brkrMsgList']]
    result = []
    for value in body['mainCtgrList']:
        item = mapped(value, {'ctgrId': 'categoryCode', 'ctgrNm': 'categoryName', 'ctgrDefaultSno': 'defaultSeqNum',
                             'ctgrCustomSno': 'seqNum', 'ctgrPrgId': 'programId', 'ctgrPrgParam': 'programParam'})
        item.update(categoryType=category_type(item['categoryCode']), assetList=resolve(value['assetRefKeyList'], linked),
                    brokerage=next((message for message in messages if message['categoryId'] == item['categoryCode']), None))
        result.append(item)
    return result


def visible(categories, *, loans=False):
    result = []
    for category in sorted(categories, key=lambda item: (item['seqNum'], item['defaultSeqNum'])):
        if loans and category['categoryType'] != 'LOAN':
            continue
        # Institution/hidden filtering affects top-level rows only.
        rows = [item for item in category['assetList'] if item['orgCode'] in SHINHAN and not item['isHide']]
        if rows:
            result.append({**category, 'assetList': rows})
    return result
