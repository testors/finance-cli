"""Job store: fixed targets, idempotency, state transitions and API views.

A job fixes its login, target, session, login revision and signing reference
when it is accepted. Later pointer or setting changes never move it. Secrets
are not part of any job row, event or response.
"""
import hashlib
import json

from . import model, session_activity
from . import adapters as registry
from .adapters.base import InputError, OUTCOMES
from .db import dumps, loads, new_id, now

STATUSES = ('queued', 'running', 'awaiting_input', 'finished', 'cancelled', 'expired')
ORIGINS = ('web', 'cli', 'agent')


class NotReady(ValueError):
    """The request is valid but the login, target or session is not ready."""

    def __init__(self, code, *, reasons=()):
        super().__init__(code)
        self.reasons = reasons


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def origin_kind(origin):
    return origin.split(':', 1)[0]


def adapter_for(name):
    adapter = registry.get(name)
    if adapter is None:
        raise model.NotFound('job_name_not_registered')
    return adapter


def submit(db, *, name, origin, login_id=None, target_id=None, profile_id=None, input=None,
           idempotency_key=None, parent_job_id=None):
    adapter = adapter_for(name)
    from .capabilities import job_state
    state = job_state(adapter)
    if state['status'] != 'available':
        raise NotReady('capability_unavailable', reasons=state['reasons'])
    if idempotency_key is not None and (not isinstance(idempotency_key, str) or not 8 <= len(idempotency_key) <= 100):
        raise InputError('invalid_idempotency_key')
    for value in (login_id, target_id, profile_id, parent_job_id):
        if value is not None and (not isinstance(value, str) or not model.REGISTRATION_KEY.fullmatch(value)):
            raise InputError('invalid_reference')
    with db.write() as con:
        login = target = profile = parent = None
        if adapter.requires_login:
            if not login_id:
                raise InputError('login_id_required')
            login = model.get_login(con, login_id, raw=True)
            if login['institution'] != adapter.service:
                raise InputError('login_institution_mismatch')
            if login['disabled']:
                raise NotReady('login_disabled')
            adapter.ready(login)
        elif login_id:
            raise InputError('login_not_accepted')
        if parent_job_id:
            parent = con.execute('SELECT * FROM jobs WHERE id=?', (parent_job_id,)).fetchone()
            if parent is None or parent['login_id'] != login_id:
                raise InputError('parent_job_mismatch')
            # A follow-up belongs to its parent's target; it cannot be filed under another one.
            if target_id is None:
                target_id = parent['target_id']
            elif parent['target_id'] != target_id:
                raise InputError('parent_target_mismatch')
        if target_id:
            target = model.get_target(con, target_id, raw=True)
            if login is None or target['login_id'] != login['id']:
                raise InputError('target_login_mismatch')
            if target['disabled']:
                raise NotReady('target_disabled')
        elif adapter.requires_target:
            raise NotReady('target_required')
        if profile_id:
            profile = model.get_profile(con, profile_id)
            if profile['disabled']:
                raise NotReady('profile_disabled')
            if target is not None and target['id'] not in profile['target_ids']:
                raise InputError('target_not_in_profile')
        normalized = adapter.validate(input, login)
        request = {'name': name, 'login_id': login_id, 'target_id': target_id, 'input': normalized,
                   'parent_job_id': parent_job_id}
        request_digest = digest(request)
        if idempotency_key is not None:
            existing = con.execute('SELECT * FROM jobs WHERE origin=? AND idempotency_key=?',
                                   (origin, idempotency_key)).fetchone()
            if existing is not None:
                if existing['request_digest'] != request_digest:
                    raise model.Conflict('idempotency_key_conflict')
                return dict(existing), False
        session_id = None
        if adapter.uses_session:
            if adapter.session_from_parent:
                if parent is None:
                    raise InputError('parent_job_required')
                session = con.execute('SELECT * FROM sessions WHERE id=?', (parent['session_id'],)).fetchone()
            else:
                session = model.current_session(con, login['id'])
            if session is None:
                raise NotReady('login_required')
            if not adapter.accepts_session(session):
                raise NotReady('session_' + session['state'])
            session_id = session['id']
            reason = session_activity.refusal(con, adapter, session)
            if reason:
                raise NotReady(reason)
        signing = None
        if adapter.purpose:
            signing = model.signing_for(con, login, target, adapter.purpose)
            if not signing:
                raise NotReady('signing_not_configured')
        if hasattr(adapter, 'check_parent') and parent is not None:
            adapter.check_parent(dict(parent), normalized)
        snapshot = {
            'login': None if login is None else {k: login[k] for k in ('id', 'institution', 'method', 'revision',
                                                                         'display_name', 'channel')},
            'target': None if target is None else {'id': target['id'], 'kind': target['kind'],
                                                   'identity': loads(target['identity']),
                                                   'display_name': target['display_name']},
            'profile': None if profile is None else {'id': profile['id'], 'name': profile['name'],
                                                     'kind': profile['kind']},
            'signing': signing, 'session_id': session_id}
        job_id, at = new_id('jb'), now()
        con.execute('INSERT INTO jobs(id, name, origin, profile_id, login_id, target_id, session_id, login_revision,'
                    ' snapshot, input, idempotency_key, request_digest, status, step, local, outcome, attempt,'
                    ' parent_job_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (job_id, name, origin, profile_id, login_id, target_id, session_id,
                     None if login is None else login['revision'], dumps(snapshot), dumps(normalized),
                     idempotency_key, request_digest, 'queued', adapter.first_step, '{}', 'not_started', '{}',
                     parent_job_id, at, at))
        db.event(con, job_id, 'submitted', origin=origin_kind(origin), step=adapter.first_step)
        return dict(con.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()), True


def get(con, job_id):
    row = con.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
    if row is None:
        raise model.NotFound('job_not_found')
    return dict(row)


def expire_due(con):
    at = now()
    rows = con.execute("SELECT id FROM jobs WHERE status='awaiting_input' AND expires_at IS NOT NULL AND expires_at<=?",
                       (at,)).fetchall()
    for (job_id,) in rows:
        con.execute("UPDATE jobs SET status='expired', awaiting=NULL, updated_at=?,"
                    " local=json_set(local, '$.expired_reason', 'confirmation_deadline_passed') WHERE id=?", (at, job_id))
        con.execute('INSERT INTO job_events(job_id, at, kind, detail) VALUES (?, ?, ?, ?)',
                    (job_id, at, 'expired', dumps({'reason': 'confirmation_deadline_passed'})))
    return len(rows)


def accept_confirmation(db, job_id, confirmation, origin):
    """Move a prepared job to its execution step. Repeating it never re-executes.

    Expiry and revision checks are committed before a refusal is raised.
    """
    with db.write() as con:
        expire_due(con)
    with db.write() as con:
        job = get(con, job_id)
        awaiting = loads(job['awaiting'], {}) or {}
        if job['status'] != 'awaiting_input':
            if job['status'] in ('queued', 'running', 'finished') and loads(job['attempt'], {}).get('confirmed_digest'):
                return job, False
            refusal = NotReady('job_not_awaiting_confirmation' if job['status'] != 'expired' else 'job_expired')
        elif awaiting.get('kind') != 'confirm':
            refusal = NotReady('job_not_awaiting_confirmation')
        elif confirmation != awaiting.get('digest'):
            refusal = InputError('confirmation_mismatch')
        else:
            login = model.get_login(con, job['login_id'], raw=True)
            target = con.execute('SELECT disabled FROM targets WHERE id=?', (job['target_id'],)).fetchone() \
                if job['target_id'] else None
            profile = con.execute('SELECT disabled FROM profiles WHERE id=?', (job['profile_id'],)).fetchone() \
                if job['profile_id'] else None
            reason = ('login_revision_changed' if login['revision'] != job['login_revision'] else
                      'login_disabled' if login['disabled'] else
                      'target_disabled' if target is not None and target['disabled'] else
                      'profile_disabled' if profile is not None and profile['disabled'] else None)
            if reason is None and job['session_id']:
                session = con.execute('SELECT * FROM sessions WHERE id=?', (job['session_id'],)).fetchone()
                reason = session_activity.refusal(con, adapter_for(job['name']), session, awaiting['next_step'])
            if reason:
                con.execute("UPDATE jobs SET status='expired', awaiting=NULL, updated_at=?,"
                            " local=json_set(local, '$.expired_reason', ?) WHERE id=?", (now(), reason, job_id))
                db.event(con, job_id, 'expired', reason=reason)
                refusal = NotReady(reason)
            else:
                attempt = {**loads(job['attempt'], {}), 'confirmed_digest': confirmation, 'confirmed_at': now(),
                           'confirmed_by': origin_kind(origin)}
                con.execute("UPDATE jobs SET status='queued', step=?, attempt=?, updated_at=? WHERE id=?",
                            (awaiting['next_step'], dumps(attempt), now(), job_id))
                db.event(con, job_id, 'confirmed', origin=origin_kind(origin), step=awaiting['next_step'])
                return get(con, job_id), True
    raise refusal


def revert_confirmation(db, job_id, reason):
    """The execution step could not start (resource busy); nothing was sent."""
    with db.write() as con:
        job = get(con, job_id)
        if job['status'] != 'queued':
            return
        attempt = loads(job['attempt'], {})
        attempt.pop('confirmed_digest', None)
        attempt.pop('confirmed_at', None)
        attempt.pop('confirmed_by', None)
        awaiting = loads(job['awaiting'], {})
        con.execute("UPDATE jobs SET status='awaiting_input', step=?, attempt=?, updated_at=? WHERE id=?",
                    (awaiting.get('step', job['step']), dumps(attempt), now(), job_id))
        db.event(con, job_id, 'confirmation_not_started', reason=reason)


def cancel(db, job_id, origin, reason='user_cancelled'):
    with db.write() as con:
        job = get(con, job_id)
        attempt = loads(job['attempt'], {})
        # Only a request that may already have left in the current step blocks cancelling.
        sent_here = attempt.get('sent') and attempt.get('reserved_step') == job['step'] and job['status'] == 'queued'
        if job['status'] not in ('queued', 'awaiting_input') or sent_here:
            if job['status'] == 'cancelled':
                return job
            raise NotReady('job_not_cancellable')
        local = {**loads(job['local'], {}), 'cancelled_reason': reason}
        con.execute("UPDATE jobs SET status='cancelled', awaiting=NULL, local=?, updated_at=?, finished_at=? WHERE id=?",
                    (dumps(local), now(), now(), job_id))
        db.event(con, job_id, 'cancelled', origin=origin_kind(origin), reason=reason)
        return get(con, job_id)


def record_cli(db, *, origin, command, exit_code, service):
    """A CLI or agent run in the shared history. Values and results are not stored."""
    at = now()
    with db.write() as con:
        job_id = new_id('jb')
        con.execute('INSERT INTO jobs(id, name, origin, snapshot, input, request_digest, status, step, local,'
                    ' outcome, attempt, created_at, updated_at, finished_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (job_id, 'cli.' + service, origin, dumps({'command': command}), '{}', digest([command, at]),
                     'finished', 'run', dumps({'exit_code': exit_code, 'result_recorded': False}), 'unknown', '{}',
                     at, at, at))
    return job_id


# API views ----------------------------------------------------------------

def account_numbers_view(value, candidates, snapshot):
    """Restore display numbers from the same job's saved identities, offline.

    Old result rows may already be masked. Do not match on their last digits or
    rewrite stored results/confirmation digests; use the fixed candidate ref and
    target. Never project other private attempt or bank-response fields.
    """
    result = value.get('result')
    if value['name'] in ('hana.accounts.list', 'hana.onesign.accounts') and isinstance(result, dict):
        numbers = {c['ref']: c['identity']['account_number'] for c in candidates or []
                   if isinstance(c, dict) and c.get('kind') == 'account' and isinstance(c.get('ref'), str)
                   and isinstance(c.get('identity'), dict) and isinstance(c['identity'].get('account_number'), str)}
        for row in result.get('accounts') or []:
            if isinstance(row, dict) and row.get('ref') in numbers:
                old, number = row.get('account_number'), numbers[row['ref']]
                row['account_number'] = number
                if row.get('label') == f'계좌 {old}':
                    row['label'] = f'계좌 {number}'
        for index, row in enumerate(result.get('rows') or [], 1):
            number = numbers.get(f'account-{index}')
            if isinstance(row, dict) and number is not None and 'acctNo' in row:
                row['acctNo'] = number
    if value['name'] == 'hana.transfer.prepare':
        number = ((snapshot.get('target') or {}).get('identity') or {}).get('account_number')
        if isinstance(number, str):
            for preview in (result, (value.get('awaiting') or {}).get('preview')):
                if isinstance(preview, dict) and 'source_account' in preview:
                    preview['source_account'] = number


def artifacts_for(con, job_id):
    return [dict(r) for r in con.execute(
        'SELECT id, kind, filename, media_type, size, complete, created_at FROM artifacts WHERE job_id=? ORDER BY created_at',
        (job_id,))]


def public(con, job, *, listing=False):
    adapter = registry.get(job['name'])
    snapshot = loads(job['snapshot'], {})
    value = {
        'id': job['id'], 'name': job['name'],
        'title': adapter.title if adapter else ('CLI 실행' if job['name'].startswith('cli.') else job['name']),
        'area': adapter.area if adapter else None, 'service': adapter.service if adapter else job['name'][4:],
        'origin': origin_kind(job['origin']), 'status': job['status'], 'step': job['step'],
        'outcome': job['outcome'], 'service_verdict': loads(job['service_verdict']),
        'reconciliation': loads(job['reconciliation']), 'local': loads(job['local'], {}),
        'login_id': job['login_id'], 'target_id': job['target_id'], 'profile_id': job['profile_id'],
        'session_id': job['session_id'], 'login_revision': job['login_revision'],
        'fixed': {'login': snapshot.get('login'), 'profile': snapshot.get('profile'),
                  'target': None if not snapshot.get('target') else {
                      **snapshot['target'], 'identity': model.masked_identity(snapshot['target'].get('identity')),
                      'display_name': model.account_display_name(snapshot['target'].get('display_name'),
                                                                  snapshot['target'].get('identity'))}},
        'confirmed_target': loads(job['confirmed_target']), 'parent_job_id': job['parent_job_id'],
        'created_at': job['created_at'], 'started_at': job['started_at'], 'finished_at': job['finished_at'],
        'observed_at': job['observed_at'], 'expires_at': job['expires_at'],
        'verification': adapter.verification if adapter else None,
    }
    if adapter and adapter.service == 'hana':
        from finance_cli.core.live_verification import hana_job
        value.update(hana_job(job['name']))
    if adapter and adapter.service == 'giro':
        from finance_cli.core.live_verification import giro_job
        value.update(giro_job(job['name']))
    if job['name'].startswith('cli.'):
        value['command'] = snapshot.get('command')
    attempt = loads(job['attempt'], {})
    value['attempt'] = {k: attempt[k] for k in ('sent', 'confirmed_at', 'reserved_at') if k in attempt}
    if listing:
        value['input'] = adapter.masked_input(loads(job['input'], {})) if adapter else {}
        return value
    value['input'] = loads(job['input'], {})
    value['result'] = loads(job['result'])
    candidates = attempt.get('target_candidates')
    if isinstance(value['result'], dict) and isinstance(candidates, list) and job['login_id']:
        # Which observed candidates are registered now; private attempt fields stay server-side.
        registered = dict(con.execute('SELECT identity_key, id FROM targets WHERE login_id=?', (job['login_id'],)).fetchall())
        value['result']['candidate_targets'] = {c['ref']: registered[c['identity_key']] for c in candidates
                                                if isinstance(c, dict) and c.get('identity_key') in registered}
    value['awaiting'] = loads(job['awaiting'])
    account_numbers_view(value, candidates, snapshot)
    value['artifacts'] = artifacts_for(con, job['id'])
    value['events'] = [{'at': r['at'], 'kind': r['kind'], 'detail': loads(r['detail'], {})} for r in con.execute(
        'SELECT at, kind, detail FROM job_events WHERE job_id=? ORDER BY id', (job['id'],))]
    return value


def listing(con, *, profile_id=None, area=None, limit=100, before=None, hide_extensions=False):
    query, args = 'SELECT * FROM jobs', []
    clauses = []
    if hide_extensions:
        # Login extensions can run every few minutes. Left out before the limit applies, they
        # cannot push other results out of the listing. Every such job is named *.session.extend.
        clauses.append("name NOT LIKE '%.session.extend'")
    if profile_id:
        clauses.append('(profile_id=? OR target_id IN (SELECT target_id FROM profile_targets WHERE profile_id=?))')
        args += [profile_id, profile_id]
    if before:
        clauses.append('created_at<?')
        args.append(before)
    if clauses:
        query += ' WHERE ' + ' AND '.join(clauses)
    rows = con.execute(query + ' ORDER BY created_at DESC LIMIT ?', (*args, min(max(int(limit), 1), 500))).fetchall()
    values = [public(con, dict(r), listing=True) for r in rows]
    return [v for v in values if area is None or v['area'] == area]


def validate_outcome(value):
    if value not in OUTCOMES:
        raise ValueError('invalid_outcome')
    return value
