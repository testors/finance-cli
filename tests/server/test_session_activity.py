"""Synthetic idle clocks; no credentials, real sessions or institution traffic."""
from types import SimpleNamespace
from unittest.mock import patch

from support import ServerCase
from finance_cli.server import model, session_activity, worker
from finance_cli.server.adapters.base import Step
from finance_cli.server.db import Database
from finance_cli.services.hana import request_activity


class SessionActivityTests(ServerCase):
    def setUp(self):
        super().setUp()
        self.sessions = []
        with self.db.write() as con, patch.object(model, 'now', return_value=1000):
            for name in ('one', 'two'):
                con.execute('INSERT INTO logins(id,institution,method,display_name,created_at,updated_at) '
                            'VALUES (?,?,?,?,?,?)', (name, 'hana', 'onesign', name, 1000, 1000))
                sid = model.add_session(con, login_id=name, location='unused', revision=1, job_id=None)
                self.sessions.append(dict(con.execute('SELECT * FROM sessions WHERE id=?', (sid,)).fetchone()))
        self.adapter = SimpleNamespace(service='hana', uses_session=True, steps={'run': Step('run')}, first_step='run')

    def test_only_bank_sends_extend_their_own_session_and_observer_is_scoped(self):
        ctx = object.__new__(worker.Context)
        ctx.db, ctx.adapter, ctx.session, ctx.step = self.db, self.adapter, self.sessions[0], 'run'
        ctx.last_bank_request_at, ctx.idle_blocked = None, False
        with patch.object(session_activity, 'now', return_value=1599):
            with request_activity.observe(ctx.before_hana_request):
                request_activity.before_request('ra')
                request_activity.before_request('ca')
                with self.db.read() as con:
                    self.assertEqual(session_activity.metadata(con, ctx.session)['last_request_at'], 1000)
                request_activity.before_request('bank')
            request_activity.before_request('bank')  # CLI/default context does nothing.
        with Database(self.db.file()).read() as con:
            self.assertEqual(session_activity.metadata(con, self.sessions[0], at=1600)['last_request_at'], 1599)
            self.assertFalse(session_activity.metadata(con, self.sessions[0], at=1600)['idle_expired'])
            self.assertTrue(session_activity.metadata(con, self.sessions[1], at=1600)['idle_expired'])
        with patch.object(session_activity, 'now', return_value=2199):
            with request_activity.observe(ctx.before_hana_request):
                with self.assertRaisesRegex(request_activity.RequestBlocked, '^session_idle_expired$'):
                    request_activity.before_request('ra')
            request_activity.before_request('bank')  # A blocked context also resets its observer.

    def test_legacy_schema_uses_creation_time_and_other_institutions_are_unaffected(self):
        with self.db.write() as con:
            con.execute('DROP TABLE session_activity')  # Pre-feature schema version 1.
            con.execute('UPDATE sessions SET checked_at=3000')
        reopened = Database(self.db.file())
        with reopened.read() as con, patch.object(session_activity, 'now', return_value=1600):
            self.assertEqual(session_activity.metadata(con, self.sessions[0])['last_request_at'], 1000)
            self.assertEqual(session_activity.refusal(con, self.adapter, self.sessions[0]), 'session_idle_expired')
            self.adapter.service = 'hometax'
            self.assertIsNone(session_activity.refusal(con, self.adapter, self.sessions[0]))
        with reopened.write() as con:
            session_activity.record(con, self.sessions[0]['id'], 1599)
            con.execute('DELETE FROM sessions WHERE id=?', (self.sessions[0]['id'],))
            self.assertEqual(con.execute('SELECT count(*) FROM session_activity').fetchone()[0], 0)
