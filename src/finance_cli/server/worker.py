"""Job worker: one process runs one step of one job.

Order: hold the job's worker lock, check the job is queued for this step,
acquire the adapter's resource locks without waiting, mark the step running,
report ``ready`` and only then read the step's secrets from stdin. A worker
that cannot get its locks reports ``busy`` and leaves the job queued. Nothing
here retries an institution request.
"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import sys

from finance_cli.core import storage
from finance_cli.core.paths import data_home

from . import model
from . import adapters as registry
from .adapters.base import Stop, StepResult
from .config import private_directory
from .db import Database, dumps, loads, new_id, now


def job_directory(job_id):
    return private_directory('jobs', model.REGISTRATION_KEY.fullmatch(job_id).group(0))


class Context:
    """What an adapter may use while running one step."""

    def __init__(self, db, job, adapter, step, secrets=None):
        self.db, self.job, self.adapter, self.step = db, job, adapter, step
        self.secrets = secrets or {}
        self.snapshot = loads(job['snapshot'], {})
        self.input = loads(job['input'], {})
        self.attempt = loads(job['attempt'], {})
        self.partial = {}
        self.previous = None
        if step != adapter.first_step:
            self.previous = {'step': (loads(job['awaiting'], {}) or {}).get('step'), 'outcome': job['outcome'],
                             'service_verdict': loads(job['service_verdict']), 'local': loads(job['local'], {})}
        with db.read() as con:
            self.login = dict(model.get_login(con, job['login_id'], raw=True)) if job['login_id'] else None
            self.target = dict(model.get_target(con, job['target_id'], raw=True)) if job['target_id'] else None
            row = con.execute('SELECT * FROM sessions WHERE id=?', (job['session_id'],)).fetchone() \
                if job['session_id'] else None
            self.session = dict(row) if row else None
            self.parent = None
            if job['parent_job_id']:
                self.parent = dict(con.execute('SELECT * FROM jobs WHERE id=?', (job['parent_job_id'],)).fetchone())

    @property
    def directory(self):
        return job_directory(self.job['id'])

    def event(self, kind, **detail):
        with self.db.write() as con:
            self.db.event(con, self.job['id'], kind, step=self.step, **detail)

    def sent_in_step(self):
        """Requests may have left in this step (a previous step's reservation does not count)."""
        return bool(self.attempt.get('sent')) and self.attempt.get('reserved_step') == self.step

    def reserve(self, **detail):
        """Persist that an institution request may be sent from now on."""
        self.attempt.update(sent=True, reserved_at=now(), reserved_step=self.step, **detail)
        with self.db.write() as con:
            con.execute('UPDATE jobs SET attempt=?, updated_at=? WHERE id=?', (dumps(self.attempt), now(), self.job['id']))
            self.db.event(con, self.job['id'], 'request_reserved', step=self.step)

    def remember(self, **values):
        """Store non-secret step data the next step needs (e.g. a draft path)."""
        self.attempt.update(values)
        with self.db.write() as con:
            con.execute('UPDATE jobs SET attempt=?, updated_at=? WHERE id=?', (dumps(self.attempt), now(), self.job['id']))

    def observe(self, **values):
        """Keep a verdict or result as soon as it is known; later errors keep it."""
        self.partial.update(values)
        with self.db.write() as con:
            fields = {k: dumps(v) for k, v in values.items() if k in ('service_verdict', 'result', 'reconciliation',
                                                                      'confirmed_target')}
            if 'outcome' in values:
                fields['outcome'] = values['outcome']
            if fields:
                fields['observed_at'] = now()
                con.execute('UPDATE jobs SET ' + ', '.join(f'{k}=?' for k in fields) + ' WHERE id=?',
                            (*fields.values(), self.job['id']))

    # Sessions -------------------------------------------------------------

    def session_file(self):
        if self.session is None:
            raise Stop('session_not_fixed')
        return resolve_private(self.session['location'])

    def new_session_path(self, institution, suffix='.json'):
        directory = private_directory('sessions', institution)
        return directory / (new_id('sf') + suffix)

    def register_session(self, location, *, move_pointer, verdict=None, current_target=None, state='usable',
                         supersede=None, name=None):
        relative = str(Path(location).absolute().relative_to(data_home().absolute()))
        with self.db.write() as con:
            session_id = model.add_session(con, login_id=self.login['id'], location=relative,
                                           revision=self.job['login_revision'], job_id=self.job['id'], state=state,
                                           verdict=verdict, current_target=current_target, name=name)
            if supersede:
                model.mark_session(con, supersede, 'consumed', 'superseded_by_' + session_id)
            if move_pointer:
                model.set_pointer(con, self.login['id'], session_id)
            self.db.event(con, self.job['id'], 'session_registered', step=self.step, session_id=session_id,
                          pointer_moved=bool(move_pointer), state=state)
        return session_id

    def mark_session(self, session_id, state, note=None):
        with self.db.write() as con:
            model.mark_session(con, session_id, state, note)
            self.db.event(con, self.job['id'], 'session_marked', step=self.step, session_id=session_id, state=state,
                          note=note)

    # Artifacts ------------------------------------------------------------

    def add_artifact(self, kind, filename, media_type, data, complete=None):
        import hashlib
        artifact_id = new_id('af')
        directory = private_directory('artifacts')
        target = directory / artifact_id
        storage.write_new(target, data)
        relative = str(target.relative_to(data_home().absolute()))
        with self.db.write() as con:
            con.execute('INSERT INTO artifacts(id, job_id, kind, filename, media_type, location, size, sha256, complete,'
                        ' created_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
                        (artifact_id, self.job['id'], kind, filename, media_type, relative, len(data),
                         hashlib.sha256(data).hexdigest(), None if complete is None else int(bool(complete)), now()))
            self.db.event(con, self.job['id'], 'artifact_registered', step=self.step, artifact_id=artifact_id,
                          artifact_kind=kind)
        return artifact_id


def resolve_private(relative):
    base = data_home().absolute()
    path = storage.no_symlinks(base / relative)
    if not path.is_relative_to(base / 'server') and not path.is_relative_to(base / 'hana'):
        raise Stop('private_path_outside_store')
    return path


def send(control, event, **detail):
    if control is None:
        return
    try:
        control.write(json.dumps({'event': event, **detail}) + '\n')
        control.flush()
    except (OSError, ValueError):
        pass


def read_secrets(stream, names):
    if not names:
        return {}
    line = stream.readline() if stream is not None else ''
    try:
        value = json.loads(line) if line else {}
    except ValueError:
        value = {}
    if not isinstance(value, dict) or set(value) != set(names) or not all(isinstance(v, str) and v for v in value.values()):
        return None
    return value


# Stops before anything was sent in a confirmation step that the user can fix
# by confirming again (wrong or malformed secret); the prepared state is kept.
RETRY_CONFIRMATION = {'step_input_missing', 'pin_six_digits_required', 'account_password_four_digits_required',
                      'store_authentication_failed', 'onesign_store_not_opened',
                      'incorrect_password_or_damaged_credential', 'certificate_not_usable'}


def code_of(error, fallback):
    text = str(error)
    return text if isinstance(error, (Stop, ValueError)) and model.REGISTRATION_KEY.fullmatch(text) and \
        text.replace('_', '').isalnum() else fallback


def precheck(con, job, adapter, step):
    """Re-read what the job fixed, now that its resources are held."""
    if job['login_id']:
        login = con.execute('SELECT * FROM logins WHERE id=?', (job['login_id'],)).fetchone()
        if login is None or login['disabled']:
            return 'login_disabled'
        if login['revision'] != job['login_revision']:
            return 'login_revision_changed'
    if job['target_id']:
        target = con.execute('SELECT disabled FROM targets WHERE id=?', (job['target_id'],)).fetchone()
        if target is None or target['disabled']:
            return 'target_disabled'
    if job['profile_id']:
        profile = con.execute('SELECT disabled FROM profiles WHERE id=?', (job['profile_id'],)).fetchone()
        if profile is None or profile['disabled']:
            return 'profile_disabled'
    if adapter.uses_session and step == adapter.first_step and job['session_id']:
        session = con.execute('SELECT * FROM sessions WHERE id=?', (job['session_id'],)).fetchone()
        if not adapter.accepts_session(session):
            return 'fixed_session_not_usable'
    return None


def finish_unstarted(db, job, step, code, first_step):
    """Close a queued step that never started; a later step of a prepared job expires instead."""
    with db.write() as con:
        current = con.execute('SELECT status, step, local FROM jobs WHERE id=?', (job['id'],)).fetchone()
        if tuple(current[:2]) != ('queued', step):
            return 'skipped'
        status = 'finished' if step == first_step else 'expired'
        local = {**loads(current['local'], {}), 'stopped': code}
        con.execute('UPDATE jobs SET status=?, awaiting=NULL, local=?, updated_at=?, finished_at=? WHERE id=?',
                    (status, dumps(local), now(), now(), job['id']))
        db.event(con, job['id'], 'step_not_started', step=step, reason=code)
    return status


def run(db, job_id, step, *, control=None, stdin=None):
    """Run one step. Returns 'busy', 'skipped' or the final job status."""
    directory = job_directory(job_id)
    with ExitStack() as stack:
        try:
            stack.enter_context(storage.lock(directory / 'worker.lock'))
        except BlockingIOError:
            send(control, 'skipped', reason='worker_running')
            return 'skipped'
        with db.read() as con:
            row = con.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
        job = dict(row) if row else None
        if job is None or job['status'] != 'queued' or job['step'] != step:
            send(control, 'skipped', reason='job_not_queued_for_step')
            return 'skipped'
        adapter = registry.get(job['name'])
        spec = adapter.steps[step]
        try:
            ctx = Context(db, job, adapter, step)
            for path in sorted(set(map(str, adapter.resources(ctx, step)))):
                storage.directory(Path(path).parent)
                stack.enter_context(storage.hold(Path(path)))
        except BlockingIOError:
            with db.write() as con:
                last = con.execute('SELECT kind FROM job_events WHERE job_id=? ORDER BY id DESC LIMIT 1',
                                   (job_id,)).fetchone()
                if not last or last[0] != 'waiting_for_resource':
                    db.event(con, job_id, 'waiting_for_resource', step=step)
            send(control, 'busy')
            return 'busy'
        except Exception as error:
            # A missing session directory or unreadable store: nothing was sent; never respawn forever.
            status = finish_unstarted(db, job, step, code_of(error, 'resource_unavailable'), adapter.first_step)
            send(control, 'skipped', reason='resource_unavailable')
            return status
        with db.write() as con:
            current = dict(con.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone())
            if (current['status'], current['step']) != ('queued', step):
                send(control, 'skipped', reason='job_changed')
                return 'skipped'
            refusal = precheck(con, current, adapter, step)
            if refusal is None:
                con.execute("UPDATE jobs SET status='running', worker_pid=?, started_at=COALESCE(started_at, ?),"
                            " updated_at=? WHERE id=?", (os.getpid(), now(), now(), job_id))
                db.event(con, job_id, 'step_started', step=step, resources_held=True)
        if refusal is not None:
            status = finish_unstarted(db, job, step, refusal, adapter.first_step)
            send(control, 'skipped', reason=refusal)
            return status
        try:
            ctx = Context(db, current, adapter, step)  # Rows as they are while the locks are held.
        except Exception as error:
            result = StepResult(outcome='not_started', local={'stopped': code_of(error, 'resource_unavailable')})
            return persist(db, None, result, job=current, step=step, adapter=adapter)
        send(control, 'ready', needs=list(spec.secrets))
        secrets = read_secrets(stdin, spec.secrets)
        try:
            if secrets is None:
                raise Stop('step_input_missing')
            ctx.secrets = secrets
            result = adapter.run(ctx, step)
            if not isinstance(result, StepResult):
                raise TypeError('adapter_result_type')
        except Stop as stop:
            result = stopped(ctx, stop.code, stop.sent or ctx.sent_in_step(), stop.detail)
        except Exception as error:
            # Only the exception type is kept; messages can echo values.
            result = stopped(ctx, 'local_processing_error', ctx.sent_in_step(), {'error_type': type(error).__name__})
        finally:
            secrets = ctx.secrets = None
        return persist(db, ctx, result)


def stopped(ctx, code, sent, detail):
    """A stop keeps what was already observed; no verdict means not started or unknown."""
    partial = ctx.partial
    local = {'stopped': code, **({'detail': detail} if detail else {})}
    outcome = partial.get('outcome') or ('unknown' if sent else 'not_started')
    return StepResult(service_verdict=partial.get('service_verdict'), result=partial.get('result'),
                      outcome=outcome, local=local, reconciliation=partial.get('reconciliation'),
                      confirmed_target=partial.get('confirmed_target'), observed=bool(partial))


def persist(db, ctx, result, *, job=None, step=None, adapter=None):
    job_id = (ctx.job if ctx else job)['id']
    step = ctx.step if ctx else step
    adapter = ctx.adapter if ctx else adapter
    attempt = ctx.attempt if ctx else loads(job['attempt'], {})
    at = now()
    with db.write() as con:
        current = dict(con.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone())
        previous_local = loads(current['local'], {})
        awaiting_before = loads(current['awaiting'])
        code = result.local.get('stopped')
        sent_here = bool(attempt.get('sent')) and attempt.get('reserved_step') == step
        if (step != adapter.first_step and awaiting_before and code in RETRY_CONFIRMATION and not sent_here
                and result.service_verdict is None):
            # Nothing left in this step: keep the prepared job so the user can confirm again.
            for key in ('confirmed_digest', 'confirmed_at', 'confirmed_by'):
                attempt.pop(key, None)
            local = {**previous_local, 'last_confirmation_refused': code}
            con.execute("UPDATE jobs SET status='awaiting_input', step=?, attempt=?, local=?, updated_at=?,"
                        " worker_pid=NULL WHERE id=?", (awaiting_before.get('step'), dumps(attempt), dumps(local), at,
                                                        job_id))
            db.event(con, job_id, 'confirmation_refused_before_sending', step=step, reason=code)
            return 'awaiting_input'
        awaiting, expires = result.awaiting, None
        if awaiting is not None:
            awaiting = {**awaiting, 'step': step}
            expires = awaiting.get('expires_at')
        status = 'awaiting_input' if awaiting is not None else 'finished'
        if step != adapter.first_step and ctx is not None and ctx.previous is not None:
            # Keep the earlier step's evidence next to this step's own state.
            local = {'previous_steps': [*previous_local.get('previous_steps', []), ctx.previous], **result.local}
        else:
            local = {**previous_local, **result.local}
        con.execute('UPDATE jobs SET status=?, service_verdict=?, result=?, outcome=?, local=?, reconciliation=?,'
                    ' awaiting=?, expires_at=?, confirmed_target=COALESCE(?, confirmed_target), attempt=?,'
                    ' updated_at=?, observed_at=COALESCE(observed_at, ?), finished_at=?, worker_pid=NULL WHERE id=?',
                    (status, dumps(result.service_verdict), dumps(result.result), result.outcome, dumps(local),
                     dumps(result.reconciliation), dumps(awaiting), expires, dumps(result.confirmed_target),
                     dumps(attempt), at, at if result.observed else None,
                     at if status == 'finished' else None, job_id))
        db.event(con, job_id, 'step_finished', step=step, status=status, outcome=result.outcome, stopped=code)
    return status


def recover(db):
    """Mark running jobs whose worker is gone. Never re-sends; unknown stays unknown."""
    changed = []
    with db.read() as con:
        rows = [dict(r) for r in con.execute("SELECT * FROM jobs WHERE status='running'")]
    for job in rows:
        try:
            # Hold the worker lock while updating, so a new worker cannot start in between.
            with storage.lock(job_directory(job['id']) / 'worker.lock'), db.write() as con:
                current = con.execute('SELECT status, step, attempt, outcome, local FROM jobs WHERE id=?',
                                      (job['id'],)).fetchone()
                if current['status'] != 'running':
                    continue
                attempt = loads(current['attempt'], {})
                outcome = current['outcome']
                if outcome == 'not_started' and attempt.get('sent') and attempt.get('reserved_step') == current['step']:
                    outcome = 'unknown'
                local = {**loads(current['local'], {}), 'interrupted': True, 'automatic_retry': False}
                con.execute("UPDATE jobs SET status='finished', outcome=?, local=?, updated_at=?, finished_at=?,"
                            " worker_pid=NULL WHERE id=?", (outcome, dumps(local), now(), now(), job['id']))
                db.event(con, job['id'], 'worker_interrupted', outcome=outcome)
                changed.append(job['id'])
        except BlockingIOError:
            continue
    return changed


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        return 2
    control = os.fdopen(os.dup(1), 'w', buffering=1)
    os.dup2(2, 1)  # Business code output goes to the worker log, never the control channel.
    status = run(Database(), argv[0], argv[1], control=control, stdin=sys.stdin)
    send(control, 'done', status=status)
    return 0


def remove_directory(path):
    shutil.rmtree(path, ignore_errors=True)


if __name__ == '__main__':
    raise SystemExit(main())
