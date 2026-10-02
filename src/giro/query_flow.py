"""Own-tax collection on the existing session; never implicit authentication."""
from .bills import TAX_TYPES, normalize_pages
from .client import AuthenticatedClient
from .errors import GiroError
from .session_store import SessionStore


def response_report(received):
    return dict(app_success=received.app_success, response_code=received.code,
        callback=received.callback, origin=received.origin,
        service_decision=('success' if received.app_success else 'failure')
            if received.origin == 'response' else 'unobserved',
        processing_issues=list(received.issues))


def collect_bills(client, tax_type, *, max_pages=100):
    if tax_type not in TAX_TYPES or type(max_pages) is not int or max_pages < 1:
        raise GiroError('세목과 조회할 페이지 범위를 확인하세요.')
    client.require_active()
    # The personal SSN selector is enabled only for registered own UID data.
    # Do not send an unregistered identifier or manufacture storage consent.
    if client.session.info.get('hasUIDInfoYn') != 'Y':
        return dict(network_used=False, app_success=None, service_decision='unobserved',
            next_action='identity_registration_required', tax_type=tax_type,
            bills=None, complete=False, processing_issues=[])
    pages, requested, result = [], set(), None
    number = 1
    for _ in range(max_pages):
        if number in requested: break
        requested.add(number)
        response = client.query(tax_type+'.list', dict(page=str(number), pageSize='10',
            useUIDInfoYn='Y', agreeUIDInfoSaveYn='Y', showUIDInfoNoticeYn='N'), send=True)
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
        result = normalize_pages(pages, tax_type)
        result.update(network_used=True, source='authenticated-query', service_decision='success',
                      processing_issues=list(response.issues), last_request=report)
        # Collection diagnostics never alter the successful service response.
        number = result['pages'][-1]['next_page']
        if number is None: break
    return result


def list_bills(tax_type, *, send=False, store=None, max_pages=100):
    if not send:
        return dict(plan_only=True, network_used=False, tax_type=tax_type,
                    maximum_pages=max_pages, automatic_login=False, payment=False)
    store = store if store is not None else SessionStore()
    with store.use() as (session, issues):
        client = AuthenticatedClient(session)
        result = collect_bills(client, tax_type, max_pages=max_pages)
        result['session_processing_issues'] = issues
        result['events'] = list(client.events)
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
        response = client.query('receipts.list', dict(startDate=start_date.strftime('%Y%m%d'),
            endDate=end_date.strftime('%Y%m%d'), page=str(page), pageSize='10'), send=True)
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
