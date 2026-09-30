"""One private SQLite database for logins, targets, profiles, sessions and jobs.

Only the standard library is used. A connection is opened per operation so the
API threads, the dispatcher and worker processes never share one. Secrets are
never stored here; session files, vaults and institution requests stay outside
SQLite transactions.
"""
from contextlib import contextmanager
import json
import os
import secrets
import sqlite3
import time

from finance_cli.core import storage
from .config import private_directory, server_home

SCHEMA_VERSION = 1
SCHEMA = '''
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS logins(
  id TEXT PRIMARY KEY, institution TEXT NOT NULL, channel TEXT, method TEXT NOT NULL,
  display_name TEXT NOT NULL, credential TEXT, signing TEXT NOT NULL DEFAULT '{}',
  registration TEXT NOT NULL DEFAULT '{}', revision INTEGER NOT NULL DEFAULT 1,
  disabled INTEGER NOT NULL DEFAULT 0, source TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS logins_source ON logins(source) WHERE source IS NOT NULL;
CREATE TABLE IF NOT EXISTS targets(
  id TEXT PRIMARY KEY, login_id TEXT NOT NULL REFERENCES logins(id), kind TEXT NOT NULL,
  identity TEXT NOT NULL, identity_key TEXT NOT NULL, display_name TEXT NOT NULL,
  signing TEXT NOT NULL DEFAULT '{}', verified_at REAL NOT NULL, source_job_id TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL, updated_at REAL NOT NULL,
  UNIQUE(login_id, identity_key));
CREATE TABLE IF NOT EXISTS profiles(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT, disabled INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL, updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS profile_targets(
  profile_id TEXT NOT NULL REFERENCES profiles(id), target_id TEXT NOT NULL REFERENCES targets(id),
  PRIMARY KEY(profile_id, target_id));
CREATE TABLE IF NOT EXISTS sessions(
  id TEXT PRIMARY KEY, login_id TEXT NOT NULL REFERENCES logins(id), state TEXT NOT NULL,
  location TEXT NOT NULL, login_revision INTEGER NOT NULL, created_by_job TEXT,
  created_at REAL NOT NULL, checked_at REAL, verdict TEXT, current_target TEXT, note TEXT, name TEXT);
CREATE TABLE IF NOT EXISTS session_pointers(
  login_id TEXT PRIMARY KEY REFERENCES logins(id), session_id TEXT NOT NULL REFERENCES sessions(id),
  updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS session_activity(
  session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE, last_request_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, origin TEXT NOT NULL, profile_id TEXT, login_id TEXT,
  target_id TEXT, session_id TEXT, login_revision INTEGER, snapshot TEXT NOT NULL DEFAULT '{}',
  input TEXT NOT NULL DEFAULT '{}', idempotency_key TEXT, request_digest TEXT NOT NULL,
  status TEXT NOT NULL, step TEXT NOT NULL, awaiting TEXT, expires_at REAL,
  service_verdict TEXT, reconciliation TEXT, local TEXT NOT NULL DEFAULT '{}',
  outcome TEXT NOT NULL DEFAULT 'not_started', result TEXT, confirmed_target TEXT,
  attempt TEXT NOT NULL DEFAULT '{}', parent_job_id TEXT, worker_pid INTEGER,
  created_at REAL NOT NULL, updated_at REAL NOT NULL, started_at REAL, finished_at REAL, observed_at REAL);
CREATE UNIQUE INDEX IF NOT EXISTS jobs_idempotency ON jobs(origin, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status, created_at);
CREATE TABLE IF NOT EXISTS job_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL, at REAL NOT NULL, kind TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS job_events_job ON job_events(job_id, id);
CREATE TABLE IF NOT EXISTS artifacts(
  id TEXT PRIMARY KEY, job_id TEXT NOT NULL, kind TEXT NOT NULL, filename TEXT NOT NULL,
  media_type TEXT NOT NULL, location TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
  complete INTEGER, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS uploads(
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, filename TEXT, location TEXT NOT NULL, size INTEGER NOT NULL,
  sha256 TEXT NOT NULL, origin TEXT NOT NULL, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS cursors(
  id TEXT PRIMARY KEY, job_id TEXT NOT NULL, data TEXT NOT NULL, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS devices(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, created_at REAL NOT NULL,
  last_seen_at REAL NOT NULL, expires_at REAL NOT NULL, revoked_at REAL);
CREATE TABLE IF NOT EXISTS enrollment_codes(
  code_hash TEXT PRIMARY KEY, device_name TEXT, public_origin TEXT NOT NULL, created_at REAL NOT NULL,
  expires_at REAL NOT NULL, used_at REAL);
CREATE TABLE IF NOT EXISTS enrollment_failures(at REAL NOT NULL, client TEXT);
'''


def now():
    return time.time()


def new_id(prefix):
    return prefix + '_' + secrets.token_hex(8)


def dumps(value):
    return None if value is None else json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def loads(value, default=None):
    return default if value is None else json.loads(value)


def path():
    return server_home() / 'finance.db'


def exists():
    target = path()
    return not any(p.is_symlink() for p in (target, *target.parents)) and target.is_file()


class Database:
    """Opens the configured database; the schema is created on first use."""

    def __init__(self, location=None):
        self.location = location

    def file(self):
        if self.location is None:
            private_directory()
            self.location = path()
        return storage.no_symlinks(self.location)

    def _open(self):
        target = self.file()
        created = not target.exists()
        if created:
            os.close(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600))
        con = sqlite3.connect(target, timeout=10, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute('PRAGMA foreign_keys=ON')
        con.execute('PRAGMA busy_timeout=10000')
        if created or not getattr(self, '_ready', False):
            con.execute('PRAGMA journal_mode=WAL')
            con.executescript(SCHEMA)
            con.execute('INSERT OR IGNORE INTO meta(key, value) VALUES (?, ?)', ('schema_version', str(SCHEMA_VERSION)))
            version = con.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
            if int(version) != SCHEMA_VERSION:
                con.close()
                raise ValueError('unsupported_server_database')
            for suffix in ('', '-wal', '-shm'):
                extra = target.with_name(target.name + suffix)
                if extra.exists():
                    os.chmod(extra, 0o600)
            self._ready = True
        return con

    @contextmanager
    def read(self):
        con = self._open()
        try:
            yield con
        finally:
            con.close()

    @contextmanager
    def write(self):
        """One IMMEDIATE transaction: check-and-set updates see a stable state."""
        con = self._open()
        try:
            con.execute('BEGIN IMMEDIATE')
            try:
                yield con
            except BaseException:
                con.execute('ROLLBACK')
                raise
            con.execute('COMMIT')
        finally:
            con.close()

    def event(self, con, job_id, kind, **detail):
        con.execute('INSERT INTO job_events(job_id, at, kind, detail) VALUES (?, ?, ?, ?)',
                    (job_id, now(), kind, dumps(detail)))
