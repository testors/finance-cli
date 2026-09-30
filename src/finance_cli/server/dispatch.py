"""Start worker processes, hand secrets only to a worker that holds its locks.

Steps without secrets are started by a background loop; a worker that cannot
get its locks leaves the job queued and the loop tries again later (the job
has not started, so this is waiting, not retrying a request). Steps with
secrets start synchronously from the request that carries them; if the worker
cannot start at once the secrets are not sent and the request is refused.
"""
import json
import os
import select
import subprocess
import sys
import threading
import time

from . import jobs
from . import adapters as registry
from .config import private_directory
from .db import loads
from .worker import job_directory, recover


def worker_environment():
    # A copy for the child only; the server's own environment is not modified.
    env = dict(os.environ)
    env.pop('PYTHONINSPECT', None)
    return env


def spawn(job_id, step, *, with_secrets):
    directory = job_directory(job_id)
    log = open(directory / 'worker.log', 'ab', buffering=0)
    os.chmod(directory / 'worker.log', 0o600)
    try:
        return subprocess.Popen([sys.executable, '-m', 'finance_cli.server.worker', job_id, step],
                                stdin=subprocess.PIPE if with_secrets else subprocess.DEVNULL,
                                stdout=subprocess.PIPE if with_secrets else subprocess.DEVNULL,
                                stderr=log, env=worker_environment(), close_fds=True, start_new_session=True)
    finally:
        log.close()


def read_event(process, timeout):
    deadline = time.monotonic() + timeout
    buffer = b''
    while time.monotonic() < deadline:
        ready, _, _ = select.select([process.stdout], [], [], max(deadline - time.monotonic(), 0))
        if not ready:
            break
        chunk = os.read(process.stdout.fileno(), 4096)
        if not chunk:
            break
        buffer += chunk
        if b'\n' in buffer:
            try:
                return json.loads(buffer.split(b'\n', 1)[0])
            except ValueError:
                return {'event': 'invalid'}
    return {'event': 'timeout'}


def start_with_secrets(job_id, step, secrets, *, timeout=20):
    """'started' after the worker holds its locks and received the secrets, else 'busy' or 'failed'."""
    process = spawn(job_id, step, with_secrets=True)
    try:
        event = read_event(process, timeout)
        if event.get('event') != 'ready':
            process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            process.stdout.close()
            return 'busy' if event.get('event') == 'busy' else 'failed'
        process.stdin.write((json.dumps(secrets) + '\n').encode('utf-8'))
        process.stdin.flush()
        process.stdin.close()
        threading.Thread(target=drain, args=(process,), daemon=True).start()
        return 'started'
    except (OSError, ValueError):
        process.kill()
        process.wait()
        return 'failed'
    finally:
        secrets = None


def drain(process):
    try:
        while process.stdout.read(4096):
            pass
    except (OSError, ValueError):
        pass
    process.wait()
    process.stdout.close()


class Dispatcher:
    def __init__(self, db, *, interval=0.5, retry_seconds=2.0):
        self.db, self.interval, self.retry_seconds = db, interval, retry_seconds
        self.running = {}
        self.backoff = {}
        self.stop_event = threading.Event()
        self.thread = None

    def start(self):
        private_directory('jobs')
        recover(self.db)
        self.thread = threading.Thread(target=self.loop, name='finance-dispatcher', daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)

    def loop(self):
        while not self.stop_event.wait(self.interval):
            try:
                self.run_once()
            except Exception:
                # The loop never dies on a local error; jobs stay as stored.
                continue

    def run_once(self):
        for job_id, process in list(self.running.items()):
            if process.poll() is not None:
                del self.running[job_id]
                self.backoff[job_id] = time.monotonic() + self.retry_seconds
        with self.db.write() as con:
            jobs.expire_due(con)
        recover(self.db)
        self.release_stranded()
        with self.db.read() as con:
            rows = con.execute("SELECT id, name, step FROM jobs WHERE status='queued' ORDER BY created_at").fetchall()
        started = []
        for job_id, name, step in rows:
            adapter = registry.get(name)
            if adapter is None or job_id in self.running or self.backoff.get(job_id, 0) > time.monotonic():
                continue
            if adapter.steps[step].secrets:
                continue  # Only a request carrying the secrets may start this step.
            self.running[job_id] = spawn(job_id, step, with_secrets=False)
            started.append(job_id)
        return started


    def release_stranded(self, age=60):
        """A secret step whose request died before handing over the secrets: nothing was sent."""
        from .db import now
        with self.db.read() as con:
            rows = [dict(r) for r in con.execute("SELECT * FROM jobs WHERE status='queued' AND updated_at<?",
                                                 (now() - age,))]
        for job in rows:
            if not queued_step_needs_secrets(job):
                continue
            if loads(job['attempt'], {}).get('confirmed_digest'):
                jobs.revert_confirmation(self.db, job['id'], 'secrets_not_delivered')
            else:
                try:
                    jobs.cancel(self.db, job['id'], 'server', 'secrets_not_delivered')
                except ValueError:
                    pass


def queued_step_needs_secrets(job):
    adapter = registry.get(job['name'])
    return bool(adapter and adapter.steps[job['step']].secrets)


def awaiting_secrets(job):
    awaiting = loads(job['awaiting'], {}) or {}
    return awaiting.get('requires', [])
