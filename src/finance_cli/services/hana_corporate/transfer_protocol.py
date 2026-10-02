"""Instant KRW transfer fields, signing text and distinct completion states."""
from datetime import datetime
import re

from finance_cli.services.hana.signing_text import signing_text
from . import operations as op, protocol

FIELDS = (('거래접수번호', 'E_CHNL_TRSC_ACPN_NO'), ('출금계좌번호', 'ACCT_NO'), ('입금은행', 'RCV_BNK_CD'),
          ('입금은행명', 'RCV_BNK_NM'), ('입금계좌번호', 'RCV_ACCT_NO'), ('이체금액', 'TRNS_AMT'),
          ('수수료', 'COMM'), ('출금통장표시내용', 'WDRW_PSBK_MARK_CTT'), ('입금통장표시내용', 'RCV_PSBK_MARK_CTT'),
          ('수취인명', 'RMTE_NM'), ('CMS코드', 'CMSV_NO'), ('메모', 'MEMO'),
          ('채널수수료구분코드', 'CHNL_COMM_DV_CD'), ('공동망전문고유번호', 'CMNW_TMSG_UNQ_NO'))
VISIBLE_FIELDS = tuple(key for _, key in FIELDS[:12]) + ('DUP_YN', 'RCV_ACCT_SEF_YN', 'ERR_CD', 'ERR_MSG',
                  'OWAC_NM', 'TRSC_DT', 'TRSC_TM', 'TRNS_EXEC_YN', 'TRSC_AMT')


def check_notes(body, output):
    code = body['CMSV_NO']
    protocol.require(not code or re.fullmatch('[A-Za-z0-9-]+', code), 'invalid_cms_code')
    for field in ('WDRW_PSBK_MARK_CTT', 'RCV_PSBK_MARK_CTT', 'MEMO'):
        text = body[field]
        if not text or not re.fullmatch('[0-9]+', text):
            continue
        protocol.require(len(text) < 2 or len(set(text)) != 1, 'repeated_numeric_transfer_note')
        if len(text) >= 13:
            total = sum(int(c) * weight for c, weight in zip(text, (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)))
            check = ((13 if '4' < text[6] < '9' else 11) - total % 11) % 10
            if check == int(text[12]):
                op.warning(output, 'personal_number_in_transfer_note_notice')


def signed_fields(confirmation):
    rows = confirmation.get('cts0004InRec')
    protocol.require(isinstance(rows, list) and rows, 'transfer_confirmation_unavailable')
    common = confirmation.get('cts0003Output') or {}
    result = []
    for index, row in enumerate(rows, 1):
        protocol.require(isinstance(row, dict), 'transfer_confirmation_unavailable')
        for position, (label, key) in enumerate(FIELDS):
            source = common if position >= 12 else row
            item = {'signedId': label, 'name': key + '_' + str(index)}
            # Missing JS values are omitted on the wire, but escape(undefined) in TBS.
            if key in source:
                item['val'] = source[key]
            result.append(item)
    return result


def text_value(value):
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def signing_bytes(fields, server_time):
    moment = datetime.strptime(server_time['date'] + server_time['time'], '%Y%m%d%H%M%S')
    form = [{'signid': field['signedId'], 'name': field['name'],
             'value': text_value(field['val']) if 'val' in field else 'undefined'} for field in fields]
    form.append({'signid': '전자서명데이터생성시간', 'name': 'sign_sslsignctime',
                 'value': moment.strftime('%Y-%m-%d %H:%M:%S')})
    return signing_text(form).encode('euc-kr', errors='replace')


def preview(data):
    result = op.pick(data, ('acctNo', 'acctNm', 'totlTrnsAmt', 'totalRduAfComm', 'comm', 'dlayTrnsYn', 'toDayTrnListYn'))
    rows = data.get('cts0004InRec')
    result['items'] = [op.pick(row, VISIBLE_FIELDS) for row in rows if isinstance(row, dict)] if isinstance(rows, list) else None
    return result


def completion(data):
    output = op.pick(data, ('allErrYn', 'errYn', 'sussCnt', 'errCnt', 'suessTotlTrnsAmt', 'errorTotlTrnsAmt',
                          'totlTrnsAmt', 'totalRduAfComm', 'comm', 'dlayTrnsYn', 'dlayTrnsTime'))
    detail = data.get('cts0004Output')
    output['transfer_status'] = 'unconfirmed'
    if not isinstance(detail, dict):
        return output
    output.update(op.pick(detail, ('SYNC_YN', 'TRNS_EXEC_YN')))
    for source, name in ((data.get('cts0004InRec'), 'submitted'), (data.get('cts0004OutRec1'), 'synchronous'),
                         (data.get('cts0004OutRec2'), 'asynchronous'), (detail.get('BIZ.CTS0004.OUT.REC'), 'records')):
        if isinstance(source, list):
            output[name] = [op.pick(row, VISIBLE_FIELDS) for row in source if isinstance(row, dict)]
    if detail.get('SYNC_YN') in (None, ''):
        output['transfer_status'] = 'approval_requested'
        return output
    submitted = data.get('cts0004InRec') or []
    synchronous = (data.get('cts0004OutRec1') or []) if detail.get('BIZ.CTS0004.OUT.REC1') else []
    if data.get('cts0004OutRec1') and not synchronous:
        output.setdefault('warnings', []).append('transfer_result_list_metadata_unavailable')
    if detail.get('BIZ.CTS0004.OUT.REC2'):
        for row in output.get('asynchronous', []):
            row['processing_status'] = 'delayed' if data.get('dlayTrnsYn') == 'Y' and row.get('RCV_ACCT_SEF_YN') == 'N' else 'processing'
    if len(submitted) == 1:
        if not synchronous or 'ERR_CD' not in synchronous[0]:
            return output
        code = synchronous[0]['ERR_CD']
        if code not in ('NCOM10058', ''):
            output['transfer_status'] = 'rejected'
        else:
            output['transfer_status'] = 'delayed' if data.get('dlayTrnsYn') == 'Y' and submitted[0].get('RCV_ACCT_SEF_YN') != 'Y' else 'completed'
            if code == '':
                output.setdefault('warnings', []).append('empty_item_error_code_has_multiple_display_branches')
    elif data.get('allErrYn') == 'Y':
        output['transfer_status'] = 'rejected'
    elif data.get('errYn') == 'Y':
        output['transfer_status'] = 'partial'
    elif submitted:
        output['transfer_status'] = 'delayed' if data.get('dlayTrnsYn') == 'Y' else (
            'completed' if detail.get('TRNS_EXEC_YN') == 'Y' else 'approval_requested')
    return output
