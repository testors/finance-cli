"""Own-tax collection on the existing session; never implicit authentication."""
from .bills import TAX_TYPES, normalize_pages, normalize_detail
from .bill_catalog import INPUTS, OWN_TYPES, REGION_TYPES, SIMPLE_TYPES, SUMMARY_KEYS, LABELS
from .protocol import endpoint
from .client import AuthenticatedClient
from .errors import GiroError
from .session_store import SessionStore
from .payment import _mask_account


def response_report(received):
    return dict(app_success=received.app_success, response_code=received.code,
        callback=received.callback, callback_code=received.callback_code, origin=received.origin,
        service_decision=('success' if received.app_success else 'failure')
            if received.origin == 'response' else 'unobserved',
        processing_issues=list(received.issues),
        no_bills_reported=received.origin == 'response' and received.code == '311'
            and ((received.query or {}).get('errorInfo') or {}).get('errorName') == '고지내용 없음')


def validate_search(tax_type, search=None, *, require_inputs=True):
    if tax_type not in TAX_TYPES:
        raise GiroError('지원하지 않는 고지 종류입니다.')
    search = {} if search is None else search
    allowed = set(INPUTS[tax_type])
    if tax_type == 'water': allowed.add('manage_no')
    if tax_type in REGION_TYPES: allowed.update(('area_code', 'district_code', 'district_giro_no'))
    if not isinstance(search, dict) or set(search) - allowed:
        raise GiroError('선택한 고지 종류의 조회 입력을 확인하세요.')
    if any(not isinstance(v, str) or not v or len(v) > 100 for v in search.values()):
        raise GiroError('조회 번호 형식을 확인하세요.')
    required = INPUTS[tax_type]
    if tax_type == 'water' and search.get('manage_no'): required = ()
    if require_inputs and any(not search.get(k) for k in required):
        raise GiroError('선택한 고지의 조회 번호가 필요합니다.')
    if tax_type == 'water' and search.get('manage_no') and search.get('elec_water_no'):
        raise GiroError('전자수용가번호 또는 고객관리번호 하나를 입력하세요.')
    return search


def collect_bills(client, tax_type, *, max_pages=100, search=None):
    if tax_type not in TAX_TYPES or type(max_pages) is not int or max_pages < 1:
        raise GiroError('세목과 조회할 페이지 범위를 확인하세요.')
    search = validate_search(tax_type, search)
    client.require_active()
    # The personal SSN selector is enabled only for registered own UID data.
    # Do not send an unregistered identifier or manufacture storage consent.
    if tax_type in OWN_TYPES and client.session.info.get('hasUIDInfoYn') != 'Y':
        return dict(network_used=False, app_success=None, service_decision='unobserved',
            next_action='identity_registration_required', tax_type=tax_type,
            bills=None, complete=False, processing_issues=[])
    region_fields, region = {}, None
    if tax_type in REGION_TYPES:
        # The screen selects the first returned province/district initially.
        # Fetch each once and carry the selected fields across every bill page.
        fields = {}
        region = {}
        for name, list_key in ((tax_type+'.provinces', 'provinceList'), (tax_type+'.districts', 'districtList')):
            response = client.query(name, fields, send=True)
            rows = response.query.get(list_key) if response.app_success else None
            if not rows or rows[0] is None:
                return dict(tax_type=tax_type, network_used=True, bills=None, complete=False,
                    app_success=None, service_decision='unobserved', stage=name,
                    next_action='local_region_unavailable', preparation_response=response_report(response),
                    processing_issues=[])
            selected = rows[0]
            selection = (('area_code', 'areaCode'),) if list_key == 'provinceList' else (
                ('district_code', 'sortCode'), ('district_giro_no', 'giroNo'))
            if any(search.get(k) for k, _ in selection):
                selected = next((r for r in rows if r is not None and all(
                    not search.get(k) or r.get(wire) == search[k] for k, wire in selection)), None)
                if selected is None:
                    return dict(tax_type=tax_type, network_used=True, bills=None, complete=False,
                        app_success=None, service_decision='unobserved', next_action='local_region_unavailable',
                        preparation_response=response_report(response), processing_issues=[])
            if list_key == 'provinceList':
                fields = dict(areaCode=selected.get('areaCode'))
                region['province'] = selected.get('areaName')
            else:
                region_fields = {key: selected.get(key) for key in ('sortCode', 'giroNo')}
                region['district'] = selected.get('sigunguName')
    base_fields = dict(region_fields)
    if tax_type in OWN_TYPES:
        base_fields.update(useUIDInfoYn='Y', agreeUIDInfoSaveYn='Y', showUIDInfoNoticeYn='N')
    for key, wire in (('number', 'elecNo'), ('giro_no', 'giroNo'), ('insure_no', 'insureNo'),
                      ('elec_water_no', 'elecWaterNo'), ('manage_no', 'manageNo')):
        if key in search: base_fields[wire] = search[key]
    if tax_type == 'nontax': base_fields['tongYn'] = 'Y'
    if tax_type == 'annuity':
        base_fields.update(searchType='E', agreeUIDInfoSaveYn='Y', showUIDInfoNoticeYn='N')
    if tax_type == 'giro':
        lookup = client.query('giro.lookup', {'giroNo': search['giro_no']}, send=True)
        if not lookup.app_success:
            return dict(response_report(lookup), tax_type=tax_type, network_used=True, bills=None, complete=False)
        if lookup.query.get('searchPayYn') != 'Y':
            return dict(response_report(lookup), tax_type=tax_type, network_used=True, bills=None,
                complete=False, next_action='direct_input_payment_required')
        base_fields['giroNo'] = lookup.query.get('giroNo')
    pages, requested, result = [], set(), None
    number = 1
    for _ in range(max_pages):
        if number in requested: break
        requested.add(number)
        try:
            fields = dict(base_fields)
            if tax_type not in SIMPLE_TYPES:
                fields['page'] = str(number)
                if tax_type != 'giro': fields['pageSize'] = '10'
            response = client.query(tax_type+'.list', fields, send=True)
        except Exception:
            if result is None:
                return dict(app_success=None, service_decision='unobserved', tax_type=tax_type,
                    network_used=True, bills=None, complete=False,
                    processing_issues=['query_processing_incomplete'])
            result['complete'] = False
            result['service_decision'] = 'partial_success'
            result['processing_issues'].append('query_processing_incomplete')
            break
        report = response_report(response)
        if not response.app_success:
            if result is None:
                return dict(report, tax_type=tax_type, network_used=True, bills=None, complete=False)
            result['complete'] = False
            result['issues'].append('후속 페이지 조회를 완료하지 못했습니다. 수신한 목록은 유지합니다.')
            result['last_request'] = report
            result['service_decision'] = 'partial_success'
            break
        pages.append(response.query)
        try:
            normalized = normalize_pages(pages, tax_type)
        except Exception:
            # Receiving a successful page is independent of CLI presentation.
            # Retain earlier normalized rows and the latest service verdict.
            if result is None:
                result = dict(report, tax_type=tax_type, network_used=True,
                              bills=None, issues=[])
            result.update(complete=False, last_request=report)
            result['processing_issues'].append('bill_normalization_incomplete')
            break
        result = normalized
        result.update(network_used=True, source='authenticated-query', service_decision='success',
                      processing_issues=list(response.issues), last_request=report)
        if region is not None:
            result['query_region'] = region
        # Collection diagnostics never alter the successful service response.
        if tax_type in SIMPLE_TYPES: break
        number = result['pages'][-1]['next_page']
        if number is None: break
        if tax_type == 'giro':
            # This screen's next-page factory returns a non-IPage query. Its
            # cast fails before transmission; do not invent a second request.
            result['complete'] = False
            result['processing_issues'].append('giro_next_page_unavailable')
            break
    return result


def list_bills(tax_type, *, send=False, store=None, max_pages=100, search=None):
    validate_search(tax_type, search, require_inputs=send)
    if type(max_pages) is not int or max_pages < 1:
        raise GiroError('조회할 페이지 범위를 확인하세요.')
    if not send:
        return dict(plan_only=True, network_used=False, tax_type=tax_type,
                    maximum_pages=1 if tax_type in SIMPLE_TYPES else max_pages,
                    maximum_requests=(1 if tax_type in SIMPLE_TYPES else max_pages)+(2 if tax_type in REGION_TYPES else 1 if tax_type == 'giro' else 0),
                    required_inputs=INPUTS[tax_type],
                    initialization=[tax_type+'.provinces', tax_type+'.districts'] if tax_type in REGION_TYPES else ['giro.lookup'] if tax_type == 'giro' else [],
                    automatic_login=False, payment=False)
    store = store if store is not None else SessionStore()
    with store.use() as (session, issues):
        client = AuthenticatedClient(session)
        result = collect_bills(client, tax_type, max_pages=max_pages, search=search)
        result['session_processing_issues'] = issues
        result['events'] = list(client.events)
    return result


def collect_detail(client, tax_type, identifiers):
    if tax_type not in TAX_TYPES or not isinstance(identifiers, dict):
        raise GiroError('고지 종류와 목록의 identifiers 객체를 확인하세요.')
    fields = {key: identifiers.get(key) for key in endpoint(tax_type+'.detail').fields}
    if tax_type in REGION_TYPES or tax_type == 'water':
        fields = {'elecNo': identifiers.get('elecNo')}
        if tax_type == 'nontax': fields['tongYn'] = 'Y'
    response = client.query(tax_type+'.detail', fields, send=True)
    result = dict(response_report(response), network_used=True, tax_type=tax_type, bill=None)
    if response.app_success:
        try:
            result.update(normalize_detail(response.query, tax_type))
            result['source'] = 'authenticated-query'
        except Exception:
            result['processing_issues'].append('bill_normalization_incomplete')
    return result


def bill_detail(tax_type, identifiers=None, *, send=False, store=None):
    if tax_type not in TAX_TYPES: raise GiroError('지원하지 않는 고지 종류입니다.')
    if not send:
        return dict(plan_only=True, network_used=False, tax_type=tax_type, operation='bills.detail', payment=False)
    store = store if store is not None else SessionStore()
    with store.use() as (session, issues):
        client = AuthenticatedClient(session)
        result = collect_detail(client, tax_type, identifiers)
        result.update(session_processing_issues=issues, events=list(client.events))
    return result


def collect_summary(client):
    client.require_active()
    if client.session.info.get('hasUIDInfoYn') != 'Y':
        return dict(network_used=False, app_success=None, service_decision='unobserved',
            next_action='identity_registration_required', categories=None)
    initial = client.query('integrated.initialize', {}, send=True)
    if initial.clear_session:
        return dict(response_report(initial), network_used=True, categories=None)
    if initial.app_success and initial.query.get('busyDayYn') == 'Y':
        return dict(app_success=None, service_decision='unobserved', network_used=True,
            categories=None, next_action='integrated_busy_day', preparation_response=response_report(initial))
    # Initialization failure falls back to an empty selector in the UI.
    response = client.query('integrated.summary', {'juminNo': '', 'useUIDInfoYn': 'Y'}, send=True)
    result = dict(response_report(response), network_used=True, categories=None,
                  preparation_response=response_report(initial))
    if response.app_success:
        result['categories'] = [dict(tax_type=kind, label=LABELS[kind],
            summary=response.query.get(key)) for kind, key in SUMMARY_KEYS.items()]
        result['totals'] = {key: response.query.get(key) for key in ('local', 'ntax', 'total')}
    return result


def integrated_summary(*, send=False, store=None):
    if not send:
        return dict(plan_only=True, network_used=False, operation='integrated.summary',
                    maximum_requests=2, payment=False, automatic_login=False)
    store = store if store is not None else SessionStore()
    with store.use() as (session, issues):
        client = AuthenticatedClient(session)
        result = collect_summary(client)
        result.update(session_processing_issues=issues, events=list(client.events))
    return result


def list_receipts(start_date, end_date, *, page=1, send=False, store=None):
    """One explicitly selected receipt page; never release a payment journal."""
    if start_date > end_date or type(page) is not int or page < 1:
        raise GiroError('납부내역 조회 기간과 페이지를 확인하세요.')
    if not send:
        return dict(plan_only=True, network_used=False, operation='receipts.list', automatic_retry=False)
    store = store if store is not None else SessionStore()
    with store.use() as (session, issues):
        client = AuthenticatedClient(session)
        response = client.query('receipts.list', dict(startDate=start_date.isoformat(),
            endDate=end_date.isoformat(), page=str(page), pageSize='10'), send=True)
        result = dict(response_report(response), network_used=True, session_processing_issues=issues,
                      receipts=None, page_navi=None, events=list(client.events), payment_reservation_changed=False)
        if response.app_success:
            result['page_navi'] = response.query.get('pageNaviMap')
            rows = response.query.get('receiptList')
            if rows is not None:
                result['receipts'] = [None if row is None else dict(
                    paid_date=row.get('paidDate'), amount_raw=row.get('paidMny'), issuer=row.get('companyName'),
                    payment_type=row.get('strNapbuType'), payment_system=row.get('strNapbuSystem'),
                    cancelled=row.get('isNapbuCancel'),
                    identifiers={key:row.get(key) for key in ('sortCode', 'giroNo', 'key', 'paidDate')}) for row in rows]
    return result


def registered_accounts(*, send=False, store=None):
    if not send:
        return dict(plan_only=True, network_used=False, operation='accounts.registered', automatic_login=False)
    store = store if store is not None else SessionStore()
    with store.use() as (session, issues):
        client = AuthenticatedClient(session)
        response = client.query('accounts.registered', {}, send=True)
        result = dict(response_report(response), network_used=True, accounts=None,
                      session_processing_issues=issues, events=list(client.events))
        if response.app_success:
            rows = response.query.get('userAcntList')
            if rows is not None:
                result['accounts'] = [None if row is None else dict(bank_code=row.get('bankCode'),
                    bank_name=row.get('bankName'), account_masked=_mask_account(row.get('acntNo')),
                    account_status=row.get('acntStatus'), name=row.get('manageName')) for row in rows]
    return result


def receipt_detail(identifiers=None, *, send=False, store=None):
    if not send:
        return dict(plan_only=True, network_used=False, operation='receipts.detail', automatic_retry=False)
    if not isinstance(identifiers, dict):
        raise GiroError('납부내역 목록의 identifiers 객체가 필요합니다.')
    fields = {key: identifiers.get(key) for key in ('sortCode', 'giroNo', 'key', 'paidDate')}
    store = store if store is not None else SessionStore()
    with store.use() as (session, issues):
        client = AuthenticatedClient(session)
        response = client.query('receipts.detail', fields, send=True)
        result = dict(response_report(response), network_used=True, items=None,
                      session_processing_issues=issues, events=list(client.events),
                      payment_reservation_changed=False)
        if response.app_success:
            rows = response.query.get('receiptItem')
            if rows is not None:
                result['items'] = [None if row is None else dict(name=row.get('n'), value=row.get('v'))
                                   for row in rows]
    return result
