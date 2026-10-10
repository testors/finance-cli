"""OneSign read-only queries on the login used for accounts and transfers."""
import json
import time

from finance_cli.services.hana import inquiry, ledger, onesign, onesign_queries, security
from .base import InputError, Step, StepResult, Stop, mask_account, pick
from .hana import (OneSignReadAdapter, History, HistoryDetail, TransferHistory, Security, account_number,
                   collect_history, compact, history_row, observe_accounts, outcome, require_accounts_result,
                   safe_code, validate_history_controls, verdict, DISPLAY_FIELDS, ROW_LIMIT)
from .hometax import scalar_row

# Fields displayed by the original ledger detail / TRNB0701001001 screens.
# Receipts and authentication metadata are never a browser response schema.
BANK_FIELDS = (
    'trscDt', 'trscTm', 'trscAmt', 'trnsAmt', 'curCd', 'trscAfBal', 'trscStNm', 'trscKindNm',
    'trnsDt', 'trnsScheDt', 'trnsScheTm', 'lstTrscDt', 'lstTrscTm', 'rsvAcpnDt', 'rsvAcpnTm',
    'canDt', 'canTm', 'chnlTrscStCd', 'achvChnlNm', 'opbkProcStCd', 'rduAfComm', 'commAmt',
    'wdrwAcctNo', 'rcvAcctNo', 'thrAcctNo', 'acctNo', 'wdrwBnkCd', 'rcvBnkCd', 'rcvBnkNm',
    'rmteNm', 'rmtrNm', 'wdrwPsbkMarkCtt', 'rcvPsbkMarkCtt', 'wdrwAcctRmrkCtt', 'rcvAcctRmrkCtt',
    'atfBizKindCd', 'atfBizKindNm', 'utlzInstNm', 'atfDudtDt', 'fstBegDt', 'ctfcTrnsYn',
    'eChnlTrscAcpnNo', 'chnlSvcCd', 'eChnlTrscUnqNo', 'memoCtt', 'rmrk',
)


def bank_row(value):
    return scalar_row(pick(value, BANK_FIELDS))


SUMMARY_FIELDS = ('network_used', 'page_count', 'row_count', 'pagination_complete', 'atomic_snapshot_verified',
                  'transfer_confirmed')


class Query(OneSignReadAdapter):
    requires_target = True

    def run(self, ctx, step):
        state = self.state(ctx)
        try:
            return self.query(ctx, onesign_queries.Queries(state, self.session(ctx)))
        except (ValueError, OSError) as error:
            raise Stop(safe_code(error), sent=ctx.sent_in_step()) from None
        finally:
            ctx.secrets = None
            state.__exit__(None, None, None)

    def config(self, ctx, source):
        result = {**ctx.input, 'account_index': source.account_index(account_number(ctx.snapshot['target']))}
        for key in ('start_date', 'end_date'):
            result[key] = compact(result[key])
        if not result.get('search'):
            result.pop('search', None)
        return result

    def ensure_accounts(self, ctx, source):
        if 'accounts' in source.state.snapshot()['sessions'][source.session]:
            return []
        ctx.reserve()
        result = onesign.operate(source.state, 'accounts', 'web-' + ctx.job['id'] + '-accounts',
                                 session=source.session, send=True)
        stages = observe_accounts(ctx, result)
        require_accounts_result(result)
        return stages


def perform(ctx, source, draft, config, observation):
    ctx.reserve()
    ctx.observe(outcome='unknown')
    return source.perform(*draft, config, observation, send=True)


class OneSignHistory(Query):
    name = 'hana.onesign.history.list'
    title = History.title
    validate = History.validate

    def query(self, ctx, source):
        validate_history_controls(ctx)
        stages = self.ensure_accounts(ctx, source)
        return collect_history(ctx, source, self.config(ctx, source),
                               lambda draft, config, label: source.perform(*draft, config, label, send=True), stages)


class HistoryFollowUp(Query):
    session_from_parent = True
    # Single-page jobs recorded before the unified query remain valid parents.
    parents = ('hana.onesign.history.list', 'hana.onesign.history.more')

    def check_parent(self, parent, value):
        if parent['name'] not in self.parents or parent['status'] != 'finished' \
                or parent['outcome'] not in ('success', 'partial_success'):
            raise InputError('parent_history_job_required')
        if not json.loads(parent['attempt']).get('history', {}).get('receipts', {}).get('page'):
            raise InputError('parent_history_page_required')

    def history(self, ctx, source):
        saved = json.loads(ctx.parent['attempt'])['history']
        metadata = source.metadata(saved['receipts']['page'])
        return saved, metadata['config'], metadata['observation']


class OneSignHistoryDetail(HistoryFollowUp):
    name = 'hana.onesign.history.detail'
    title = '거래 상세'
    validate = HistoryDetail.validate

    def query(self, ctx, source):
        saved, config, observation = self.history(ctx, source)
        receipts = saved['receipts']
        page, row = history_row(saved, ctx.input['row'])
        draft = ledger.prepare(source, 'detail', config, clock=receipts['clock'], account_info=receipts['account'],
                               previous=page, row=row, snapshot=saved.get('snapshot'))
        meta = draft[0]['account_history']
        if meta['kind'] == 'local':
            return StepResult(outcome='success', observed=False, result={'source': 'saved_ledger_row',
                              'network_used': False, 'detail': scalar_row(meta['local_detail']['display'])})
        result = perform(ctx, source, draft, config, observation)
        ctx.observe(service_verdict=verdict(result), outcome=outcome(result['accepted']))
        detail, local = None, {}
        if result['accepted'] is True:
            try:
                detail = ledger.receipt(source, result['receipt_directory'], source.headers())[1]
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                local['saved_rows_unreadable'] = True
        return StepResult(service_verdict=verdict(result), outcome=outcome(result['accepted']), local=local,
                          result={'source': 'bank_detail', 'detail': bank_row(detail) if isinstance(detail, dict)
                                  else None, 'transfer_confirmed': False})


class OneSignHistoryExport(HistoryFollowUp):
    name = 'hana.onesign.history.export'
    title = '거래 내역 저장'
    steps = {'run': Step('run', secrets=('vault_passphrase',), sends=False)}

    def query(self, ctx, source):
        saved, _, _ = self.history(ctx, source)
        report, csv_bytes = ledger.export_report(source, saved['receipts']['page'])
        filtered = pick(report, (*SUMMARY_FIELDS, 'duplicates_removed', 'issues', 'csv_text_cells_escaped'))
        filtered['rows'] = [pick(row, ('page', 'row', 'kind', *DISPLAY_FIELDS)) for row in report['rows']]
        stamp = time.strftime('%Y%m%d-%H%M%S')
        artifacts = [ctx.add_artifact('hana_history_' + ext, f'history-{stamp}.{ext}', mime, content,
                                     complete=report['pagination_complete']) for ext, mime, content in (
                        ('json', 'application/json', json.dumps(filtered, ensure_ascii=False, indent=2).encode('utf-8')),
                        ('csv', 'text/csv; charset=utf-8', csv_bytes))]
        return StepResult(outcome='success', observed=False,
                          result={**pick(report, SUMMARY_FIELDS), 'artifact_ids': artifacts})


def inquiry_result(ctx, source, result, kind, stages=None):
    service, rows, local = verdict(result), None, {}
    if stages:
        service['stages'] = stages
    ctx.observe(service_verdict=service, outcome=outcome(result['accepted']))
    if result['accepted'] is True:
        try:
            _, payload = inquiry.saved(source, result['receipt_directory'], kind, source.headers())
            rows = payload.get('rec') if isinstance(payload, dict) else None
            if kind == 'history':
                ctx.remember(inquiry={'receipt': result['receipt_directory']})
        except (ValueError, OSError, KeyError, TypeError, AttributeError):
            local['saved_rows_unreadable'] = True
    return StepResult(service_verdict=service, outcome=outcome(result['accepted']), local=local,
                      result={'rows': [bank_row(row) for row in rows[:ROW_LIMIT]] if isinstance(rows, list) else None,
                              'transfer_confirmed': False})


class OneSignTransferHistory(Query):
    name = 'hana.onesign.inquiry.history'
    title = TransferHistory.title
    validate = TransferHistory.validate

    def query(self, ctx, source):
        validate_history_controls(ctx, transfer=True)
        stages = self.ensure_accounts(ctx, source)
        config = self.config(ctx, source)
        result = perform(ctx, source, inquiry.prepare(source, 'history', config), config, ctx.job['id'])
        return inquiry_result(ctx, source, result, 'history', stages)


class OneSignTransferDetail(Query):
    name = 'hana.onesign.inquiry.detail'
    title = '이체 상세'
    session_from_parent = True
    validate = HistoryDetail.validate

    def check_parent(self, parent, value):
        if parent['name'] != 'hana.onesign.inquiry.history' or parent['status'] != 'finished' \
                or parent['outcome'] != 'success' or not json.loads(parent['attempt']).get('inquiry', {}).get('receipt'):
            raise InputError('parent_inquiry_job_required')

    def query(self, ctx, source):
        previous = json.loads(ctx.parent['attempt'])['inquiry']['receipt']
        metadata = source.metadata(previous)
        draft = inquiry.prepare(source, 'detail', metadata['config'], previous=previous, row=ctx.input['row'])
        result = perform(ctx, source, draft, metadata['config'], metadata['observation'])
        return inquiry_result(ctx, source, result, 'detail')


class OneSignSecurity(Query):
    name = 'hana.onesign.security.query'
    title = Security.title
    requires_target = False  # Customer-level inquiry; no prior account query is needed.
    validate = Security.validate

    def query(self, ctx, source):
        from finance_cli.services.hana.compat import web_value
        kind = ctx.input['kind']
        request = security.prepare_request({'headers': source.headers()}, kind)
        result = perform(ctx, source, (request, 'security-' + kind), ctx.input, ctx.job['id'])
        service = verdict(result, ('accepted', 'reason', 'processing_status', 'service_status', 'diagnostics', 'warnings'))
        ctx.observe(service_verdict=service, outcome=outcome(result['accepted']))
        view, local = None, {}
        if result['accepted'] is True:
            try:
                _, _, raw = source.read_receipt(result['receipt_directory'])
                observed = security.protocol.observe(kind, web_value(raw))
                rows = []
                for row in observed['rows'][:ROW_LIMIT]:
                    safe = scalar_row(pick(row, ('otpSeqNo', 'scrtMdclStCd', 'scrtMdclStNm',
                                                 'otpVndrEntrNm', 'otpVndrEntrCd', 'issuDt')))
                    if safe is not None and safe.get('otpSeqNo') is not None:
                        safe['otpSeqNo'] = mask_account(safe['otpSeqNo'])
                    rows.append(safe)
                view = {'fields': scalar_row(observed['fields']), 'display': scalar_row(observed['display']),
                        'rows': rows, 'diagnostics': observed['diagnostics']}
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                local['saved_rows_unreadable'] = True
        return StepResult(service_verdict=service, outcome=outcome(result['accepted']), local=local,
                          result={'kind': kind, 'observation': view, 'state_change_requested': False})


ADAPTERS = (OneSignHistory(), OneSignHistoryDetail(), OneSignHistoryExport(),
            OneSignTransferHistory(), OneSignTransferDetail(), OneSignSecurity())
