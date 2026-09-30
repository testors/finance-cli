"""OneSign read-only queries on the login used for accounts and transfers."""
import json
import time

from finance_cli.services.hana import inquiry, ledger, ledger_protocol as protocol, onesign_queries, security
from .base import InputError, Step, StepResult, Stop, mask_account, pick
from .hana import (OneSignReadAdapter, History, HistoryDetail, TransferHistory, Security, account_number,
                   compact, outcome, safe_code, verdict, ROW_LIMIT)
from .hometax import scalar_row

DISPLAY_FIELDS = ('date', 'time', 'type', 'name', 'amount', 'balance', 'currency', 'variation', 'extra', 'memo')
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


def perform(ctx, source, draft, config, observation):
    ctx.reserve()
    return source.perform(*draft, config, observation, send=True)


def stage_verdict(stage, result):
    return {'stage': stage, **verdict(result, ('accepted', 'reason', 'processing_status', 'service_status',
                                              'row_count', 'diagnostics', 'warnings'))}


def page_result(ctx, source, receipts, result, stages):
    rows, complete, more, local = None, None, False, {}
    service = {'stages': stages}
    ctx.observe(service_verdict=service, outcome=outcome(result['accepted']))
    if result['accepted'] is True:
        receipts['page'] = result['receipt_directory']
        try:
            pages, position = ledger.chain(source, receipts['page'], source.headers())
            request, value, _ = pages[-1]
            rows = [pick(protocol.display_row(row), DISPLAY_FIELDS)
                    for row in protocol.rows(request['account_history']['kind'], value)][:ROW_LIMIT]
            complete, more = position is None, position not in (None, 'invalid')
            ctx.remember(history={'receipts': receipts, 'more': more})
        except (ValueError, OSError, KeyError, TypeError, AttributeError):
            local['saved_rows_unreadable'] = True
    return StepResult(service_verdict=service, outcome=outcome(result['accepted']), local=local,
                      result={'rows': rows, 'pagination_complete': complete, 'more_available': more,
                              'transfer_confirmed': False})


class OneSignHistory(Query):
    name = 'hana.onesign.history.list'
    title = History.title
    validate = History.validate

    def query(self, ctx, source):
        config, receipts, stages = self.config(ctx, source), {}, []
        for stage in ('clock', 'account', 'page'):
            draft = ledger.prepare(source, stage, config, clock=receipts.get('clock'), account_info=receipts.get('account'))
            result = perform(ctx, source, draft, config, ctx.job['id'])
            stages.append(stage_verdict(stage, result))
            if stage == 'page':
                return page_result(ctx, source, receipts, result, stages)
            ctx.observe(service_verdict={'stages': stages}, outcome=outcome(result['accepted'], completed=False))
            if result['accepted'] is not True or result['processing_status'] != 'completed':
                return StepResult(service_verdict={'stages': stages}, outcome=outcome(result['accepted'], completed=False))
            receipts[stage] = result['receipt_directory']


class HistoryFollowUp(Query):
    session_from_parent = True
    parents = ('hana.onesign.history.list', 'hana.onesign.history.more')

    def check_parent(self, parent, value):
        if parent['name'] not in self.parents or parent['status'] != 'finished' or parent['outcome'] != 'success':
            raise InputError('parent_history_job_required')
        if not json.loads(parent['attempt']).get('history', {}).get('receipts', {}).get('page'):
            raise InputError('parent_history_page_required')

    def history(self, ctx, source):
        receipts = dict(json.loads(ctx.parent['attempt'])['history']['receipts'])
        metadata = source.metadata(receipts['page'])
        return receipts, metadata['config'], metadata['observation']


class OneSignHistoryMore(HistoryFollowUp):
    name = 'hana.onesign.history.more'
    title = '거래 내역 다음 페이지'

    def query(self, ctx, source):
        receipts, config, observation = self.history(ctx, source)
        draft = ledger.prepare(source, 'page', config, clock=receipts['clock'], account_info=receipts['account'],
                               previous=receipts['page'])
        result = perform(ctx, source, draft, config, observation)
        return page_result(ctx, source, receipts, result, [stage_verdict('page', result)])


class OneSignHistoryDetail(HistoryFollowUp):
    name = 'hana.onesign.history.detail'
    title = '거래 상세'
    validate = HistoryDetail.validate

    def query(self, ctx, source):
        receipts, config, observation = self.history(ctx, source)
        draft = ledger.prepare(source, 'detail', config, clock=receipts['clock'], account_info=receipts['account'],
                               previous=receipts['page'], row=ctx.input['row'])
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
        receipts, _, _ = self.history(ctx, source)
        report, csv_bytes = ledger.export_report(source, receipts['page'])
        filtered = pick(report, (*SUMMARY_FIELDS, 'duplicates_removed', 'issues', 'csv_text_cells_escaped'))
        filtered['rows'] = [pick(row, ('page', 'row', 'kind', *DISPLAY_FIELDS)) for row in report['rows']]
        stamp = time.strftime('%Y%m%d-%H%M%S')
        artifacts = [ctx.add_artifact('hana_history_' + ext, f'history-{stamp}.{ext}', mime, content,
                                     complete=report['pagination_complete']) for ext, mime, content in (
                        ('json', 'application/json', json.dumps(filtered, ensure_ascii=False, indent=2).encode('utf-8')),
                        ('csv', 'text/csv; charset=utf-8', csv_bytes))]
        return StepResult(outcome='success', observed=False,
                          result={**pick(report, SUMMARY_FIELDS), 'artifact_ids': artifacts})


def inquiry_result(ctx, source, result, kind):
    service, rows, local = verdict(result), None, {}
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
        config = self.config(ctx, source)
        result = perform(ctx, source, inquiry.prepare(source, 'history', config), config, ctx.job['id'])
        return inquiry_result(ctx, source, result, 'history')


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


ADAPTERS = (OneSignHistory(), OneSignHistoryMore(), OneSignHistoryDetail(), OneSignHistoryExport(),
            OneSignTransferHistory(), OneSignTransferDetail(), OneSignSecurity())
