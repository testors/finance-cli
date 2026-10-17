"""Existing loan documents: period inquiry, selected rate statement and PDF."""
import base64
from datetime import datetime, timedelta
from functools import cmp_to_key
import html
import json
import re

from finance_cli.core import storage
from . import legacy_web as legacy, setup, web
from .accounts import LoginRequired
from .enrollment import Pending
from .exchange import Exchange
from .session import SessionRequired

PROGRAMS = {'rate': 'BM0320S0101F01', 'credit': 'BM0329S0004F01'}
CREDIT_TYPES = {'3': '연체유무확인서', '4': '대출금상환(한도해지)증명서', '6': '대출이자납입확인서'}
CREDIT_STATES = {'1': '신청완료', '2': '취소완료', '3': '영업점확인중', '4': '영업점확인중',
                 '5': '발송가능', '6': '미리보기완료', '7': '발송완료', '9': '발급거절'}


def request(exchange, stage, transaction, body, *, kind='rate', show=True, allow_failure=False):
    # The loan common module redirects the PDF transaction before transport.
    if transaction == 'RSMCM9000D02':
        transaction = 'RSMCM9000D82'
    verdict, document = legacy.call(exchange, stage, transaction, body, program=PROGRAMS[kind], show_message=show)
    if not verdict['callback_ready']:
        raise Pending(verdict['required_action'])
    if not verdict['bridge_success'] and not allow_failure:
        raise Pending('loan_document_request_unavailable')
    if not verdict['bridge_success']:
        # fncCallTransaction resolves its error callback, including the marker.
        data = document.get('dataHeader') if isinstance(document, dict) else None
        return {**(data if isinstance(data, dict) else {}), '거래실패': True}
    return document.get('dataBody')


def current_time(exchange, *, kind='rate'):
    data = request(exchange, 'loan_document_server_time', 'RSMCM9000A03',
                   {'bdtInqrGS20': 'all', 'dtFrmtS20': 'yyyyMMddHHmmss'}, kind=kind, show=False)
    value = data['getCurrentDateFmt']['valueS20']
    return {'sbdate': value[:8], 'sbtime': value[8:22], 'isOPDate': data['isOpDate'].get('valueS20')}


def notice_active(info, clock):
    parts = info.split('/')
    def field(index):
        return parts[index] if index < len(parts) else None
    if field(4) != 'Y':
        return field(4) != 'N'
    if field(5) != 'Y':
        return True
    now = clock()
    hhmm = now['sbtime'][:4]
    timestamp = now['sbdate']+hhmm
    if field(6) is None or field(7) is None or not field(6) <= timestamp <= field(7):
        return False
    if field(8) == 'N':
        return True
    if field(10) is None or field(11) is None or not field(10) <= hhmm <= field(11):
        return False
    if field(12) == 'Y' and now['isOPDate'] == 'true':
        return False
    weekday = (datetime.strptime(now['sbdate'], '%Y%m%d').weekday()+1) % 7
    return field(9)[weekday:weekday+1] == '1'


def notice(exchange, acknowledge):
    value = request(exchange, 'loan_document_notice', 'RSMLO0000D04',
                    {'trxG': '04', 'cdvalTableNameC30': 'LOAN_NOTICE', 'cdvalCodeDesc1C1000': PROGRAMS['rate']},
                    allow_failure=True)
    if value.get('resultYn') != 'Y' or legacy.nullish(value.get('grid00')):
        return
    def order(row):
        value = text(row.get('cdvalCodeNameC30')).replace(',', '') or '0'
        match = re.match(r'^[\s]*([+-]?[0-9]+)', value)
        return int(match[1]) if match else None
    def compare(left, right):
        left, right = order(left), order(right)
        return left-right if left is not None and right is not None else 0
    for row in reversed(sorted(value['grid00'], key=cmp_to_key(compare))):
        info = row['cdvalCodeDesc2C1000']
        if not notice_active(info, lambda: current_time(exchange)):
            continue
        simple = info.split('/')[2:3] == ['1']
        content = ''.join(row.get(f'cdvalCodeDesc{i}C1000', '') for i in (3, 4, 5))
        markup = base64.b64decode(content).decode('utf-8', errors='replace')
        plain = html.unescape(re.sub(r'<[^>]*>', '\n', markup))
        path = exchange.run/'loan-notice.txt'
        storage.write_new(path, plain.encode())
        exchange.report.update(notice_file=str(path), notice_kind='information' if simple else 'blocking')
        if not simple:
            raise Pending('loan_notice_blocks_service')
        if acknowledge is None or not acknowledge(path):
            raise Pending('loan_notice_confirmation_required')
        exchange.report['notice_acknowledged'] = True
        return


def dates(start, end):
    if start is None and end is None:
        return None
    if start is None or end is None:
        raise ValueError('loan_document_date_pair_required')
    values = []
    for value in (start, end):
        if not re.fullmatch(r'[0-9]{8}|[0-9]{4}-[0-9]{2}-[0-9]{2}', value):
            raise ValueError('loan_document_date_invalid')
        compact = value.replace('-', '')
        datetime.strptime(compact, '%Y%m%d')
        values.append(compact)
    if values[0] > values[1]:
        raise ValueError('loan_document_date_order')
    return values


def text(value):
    if not web.truthy(value):
        return ''
    if isinstance(value, bool):
        return 'true'
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()


def has_rows(items):
    if legacy.nullish(items):
        return False
    length = len(items) if isinstance(items, (list, str)) else items.get('length', 0) if isinstance(items, dict) else 0
    try:
        return float(length) > 0
    except (TypeError, ValueError):
        return False


def rows(value, kind):
    items = value.get('grid00')
    if not has_rows(items):
        return []
    if not isinstance(items, list):
        raise ValueError('loan_document_rows_unavailable')
    return [row for row in reversed(items) if kind == 'rate' or text(row.get('lonInetProfdK')) in CREDIT_TYPES]


def display_rows(items, kind, today):
    output = []
    for index, row in enumerate(items, 1):
        item = {'index': index, 'data': row}
        if kind == 'rate':
            item.update(issued_on=row.get('balDt'), product_name=row.get('prdtNmS128'),
                        delivery={'2': 'SMS', '3': 'E-MAIL'}.get(text(row.get('irtcrBalMth')), '직접교부'))
        else:
            code = text(row.get('lonInetProfdK'))
            state = text(row.get('lonInetProfdS'))
            expired = state in ('5', '6', '7') and re.sub(r'[-.:]', '', text(row.get('sincdt'))) != today
            item.update(document_name=CREDIT_TYPES[code],
                        status='발송가능기간만료' if expired else CREDIT_STATES.get(state, state))
        output.append(item)
    return output


def save_data(exchange, filename, value):
    path = exchange.run/filename
    try:
        storage.write_new(path, (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode())
        exchange.report['data_file'] = str(path)
    except Exception:
        exchange.warning('loan_document_data_save_error')


def listing(exchange, kind, period, acknowledge):
    # Clear stale selections before a new inquiry, never turn a failed query into zero rows.
    cache = exchange.state.setdefault('loan_documents', {})
    cache.pop(kind, None)
    if kind == 'rate':
        notice(exchange, acknowledge)
    today = current_time(exchange, kind=kind)['sbdate']
    start, end = period or [(datetime.strptime(today, '%Y%m%d')-timedelta(days=7)).strftime('%Y%m%d'), today]
    if kind == 'rate':
        transaction, body = 'RSMLO1101A08', {'upmuG1L2': '5', 'balSjdtS8': start, 'balEndtS8': end}
    else:
        transaction, body = 'RSMLO1101A09', {'trxG': '14', 'lonInetProfdK': '99', 'inqSjdt': start, 'inqEndt': end}
    value = request(exchange, 'loan_document_list', transaction, body, kind=kind, show=False)
    items = rows(value, kind)
    cache[kind] = {'attempt': exchange.attempt, 'credential': exchange.state.get('credential'), 'rows': items}
    exchange.report.update(list_result='success', count=len(items), processing_status='complete')
    save_data(exchange, 'loan-documents.json', {'kind': kind, 'start': start, 'end': end,
              'server_count': value.get('grid00Cnt'), 'documents': display_rows(items, kind, today)})


def decode_pdf(value):
    # Android Base64.DEFAULT skips non-alphabet bytes and permits omitted padding.
    if value is None or value == '':
        raise ValueError('loan_pdf_data_unavailable')
    clean = re.sub(rb'[^A-Za-z0-9+/=]', b'', str(value).encode())
    if re.fullmatch(rb'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}(?:==)?|[A-Za-z0-9+/]{3}=?)?', clean) is None:
        raise ValueError('loan_pdf_base64_invalid')
    return base64.b64decode(clean+b'='*(-len(clean) % 4), validate=True)


def download(exchange, index):
    saved = exchange.state.get('loan_documents', {}).get('rate')
    if saved is None or saved.get('credential') != exchange.state.get('credential'):
        raise Pending('loan_document_list_required')
    items = saved['rows']
    if index is None and len(items) == 1:
        index = 1
    if index is None or not 1 <= index <= len(items):
        exchange.report['count'] = len(items)
        raise Pending('loan_document_selection_required')
    row = items[index-1]
    exchange.report['list_attempt'] = saved['attempt']
    detail = request(exchange, 'loan_document_detail', 'RSMLO1101A03', {'grid00Cnt': 1, 'grid00': [{
        target: row[source] for target, source in (('dbsAprvnoL10', 'aprvnoL10'),
                                                  ('dbsAprvSerL7', 'aprvSerL7'), ('dbsSerL6', 'serL6')) if source in row}]})
    values = detail.get('grid00')
    exchange.report.update(detail_result='success', document_available=False)
    save_data(exchange, 'loan-document-detail.json', detail)
    if not has_rows(values):
        exchange.report.update(detail_empty=True, processing_status='complete')
        return
    user = (exchange.state.get('login') or {}).get('user') or {}
    body = {'apdfViewCS20': 'LOAN', 'docFormC': '01', 'cusnmS30': user.get('cusSungNmS30') or '', 'subChanS8': '03'}
    if isinstance(values, (list, str)) or '0' in values:
        body['apdfPrmtS4000'] = json.dumps(values[0] if isinstance(values, (list, str)) else values['0'],
                                         ensure_ascii=False, separators=(',', ':'))
    pdf = request(exchange, 'loan_document_pdf', 'RSMCM9000D02', body)
    if pdf.get('rstCS10') == 'FAIL':
        exchange.report.update(document_result='failure', processing_status='incomplete')
        return
    exchange.report['document_result'] = 'viewer_requested'
    data = decode_pdf(pdf.get('apdfDataB20000'))
    exchange.report.update(document_available=True, processing_status='complete')
    try:
        path = exchange.run/'rate-statement.pdf'
        storage.write_new(path, data)
        exchange.report.update(document_saved=True, document_file=str(path))
    except Exception:
        exchange.report['document_saved'] = False
        exchange.warning('loan_document_pdf_save_error')


def run(action, *, kind='rate', start=None, end=None, index=None, acknowledge=None):
    period = dates(start, end)
    settings = setup.load()
    folder = setup.prepare_directory()
    with storage.lock(folder/'.lock'):
        path = folder/'session.json'
        state = storage.read_json(path) if path.exists() else {}
        if not state.get('cookie'):
            raise SessionRequired()
        if not state.get('authenticated'):
            raise LoginRequired()
        exchange = Exchange(settings, state, 'loan_documents_'+action)
        exchange.report['document_kind'] = kind
        try:
            if action == 'list':
                listing(exchange, kind, period, acknowledge)
            elif action == 'download' and kind == 'rate':
                download(exchange, index)
            else:
                raise Pending('loan_document_action_unavailable')
        except Pending as error:
            exchange.report.update(processing_status='incomplete', required_action=error.action)
        except (KeyboardInterrupt, EOFError):
            exchange.report.update(processing_status='incomplete', error='interrupted')
        except Exception:
            exchange.report.update(processing_status='incomplete', error='loan_document_processing_error')
        state['last_operation'] = exchange.report['operation']
        exchange.save()
        return exchange.report
