"""Collect the personal ledger in wire order across periods and pages."""
from datetime import timedelta
import uuid

from . import inquiry, ledger, ledger_protocol as protocol, store, transport


def controls(args):
    if not args.account or not (args.name or args.session):
        raise ValueError('history_needs_account_and_name_or_session')
    if any((args.input, args.clock, args.account_info, args.previous, args.row,
            args.snapshot, args.output)):
        raise ValueError('history_list_does_not_use_stage_options')
    today = inquiry.today_kst()
    config = {'start_date': (args.start or (today - timedelta(days=6)).strftime('%Y%m%d')).replace('-', ''),
              'end_date': (args.end or today.strftime('%Y%m%d')).replace('-', ''),
              'direction': args.direction, 'order': 'asc' if args.order == 'oldest' else 'desc',
              'search': args.search}
    protocol.plan(config, today.strftime('%Y%m%d'), args.account)
    return config


def collect(source, config, perform):
    """The caller holds the session lock; perform sends exactly one prepared request."""
    result = {'accepted': None, 'network_used': False, 'automatic_retry': False,
              'complete': False, 'transactions': [], 'pages': [], 'stages': [], 'warnings': [],
              'processing_status': 'running', 'atomic_snapshot_verified': False}
    receipts = {}
    snapshot = 'history-' + uuid.uuid4().hex
    stage = 'clock'
    try:
        while True:
            draft = ledger.prepare(source, stage, config, clock=receipts.get('clock'),
                                   account_info=receipts.get('account'), previous=receipts.get('page'),
                                   snapshot=snapshot)
            observed = perform(draft, config, snapshot)
            result['network_used'] |= observed.get('network_used', False)
            result['stages'].append({'stage': stage, **{k: observed[k] for k in
                ('accepted', 'processing_status', 'reason', 'receipt_directory') if k in observed}})
            result['warnings'].extend(observed.get('warnings', []))
            if stage == 'page' and observed.get('accepted') is True:
                result['accepted'] = True
            if observed.get('accepted') is not True or observed.get('processing_status', 'completed') != 'completed':
                if result['accepted'] is not True:
                    result['accepted'] = observed.get('accepted')
                result['processing_status'] = 'stopped'
                return result
            receipts[stage] = observed['receipt_directory']
            if stage != 'page':
                stage = 'account' if stage == 'clock' else 'page'
                continue
            # Append each accepted page before inspecting its continuation.
            request, _, _ = transport.read_receipt(source, receipts['page'])
            headers = {k.lower(): v for k, v in request['headers'].items()}
            request, value, _ = ledger.receipt(source, receipts['page'], headers)
            kind = request['account_history']['kind']
            rows = protocol.rows(kind, value)
            result['transactions'].extend({**protocol.display_row(row), 'kind': kind, 'raw': row} for row in rows)
            result['pages'].append({'kind': kind, 'received': len(rows), 'receipt': receipts['page']})
            _, position = ledger.chain(source, receipts['page'], headers)
            if position == 'invalid':
                result['warnings'].append('continuation_cursor_requires_review')
                result['processing_status'] = 'stopped'
                return result
            if position is None:
                result.update(complete=True, processing_status='completed')
                return result
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        result.update(processing_status='stopped', error='history_processing_error')
        return result


def joint_perform(session):
    def perform(draft, config, observation):
        request, name = draft
        observed = {'accepted': None, 'network_used': False, 'receipt_directory': name}

        def assess(_, status, headers, raw):
            verdict = ledger.assess(request['account_history']['kind'], status, headers, raw)
            observed.update(verdict)
            return verdict

        try:
            store.write_new(store.child(session, name + '-prepared.json'), request)
            observed.update(transport.send(session, name, request, assess), processing_status='completed')
        except (ValueError, OSError):
            observed.update(processing_status='stopped', reason='query_processing_error')
            observed['network_used'] |= store.child(session, name, 'attempt.json').exists()
        return observed
    return perform


def dispatch(args):
    config = controls(args)
    if not args.send:
        return {'operation': 'history', 'network_used': False, 'processing_status': 'planned',
                'automatic_retry': False, 'next': 'same_command_with_send'}
    if args.name:
        from .onesign_cli import password
        from .onesign_state import State
        from .onesign_queries import Queries
        with State(args.name, password(args)) as state:
            sessions = state.snapshot()['sessions']
            candidates = [name for name, value in sessions.items() if value.get('signed_login') is True]
            session = args.session
            if session is None:
                if len(candidates) != 1:
                    raise ValueError('select_one_signed_login_session')
                session = candidates[0]
            if session not in candidates:
                raise ValueError('onesign_signed_login_required')
            source = Queries(state, session)
            config['account_index'] = source.account_index(args.account)
            return collect(source, config, lambda draft, cfg, obs: source.perform(*draft, cfg, obs, send=True))
    session = store.session_path(args.session)
    with store.lock(session):
        selection = store.read_json(store.child(session, 'account-selection.json'))
        matches = [row['index'] for row in selection['accounts'] if row.get('acctNo') == args.account]
        if len(matches) != 1:
            raise ValueError('account_not_in_session_accounts')
        config['account_index'] = matches[0]
        return collect(session, config, joint_perform(session))
