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
        with patch.object(session_activity, 'now', return_value=1589):
            with request_activity.observe(ctx.before_hana_request):
                request_activity.before_request('ra')
                request_activity.before_request('ca')
                with self.db.read() as con:
                    self.assertEqual(session_activity.metadata(con, ctx.session, 'hana')['last_request_at'], 1000)
                request_activity.before_request('bank')
            request_activity.before_request('bank')  # CLI/default context does nothing.
        with Database(self.db.file()).read() as con:
            self.assertEqual(session_activity.metadata(con, self.sessions[0], 'hana', at=1590)['last_request_at'], 1589)
            self.assertFalse(session_activity.metadata(con, self.sessions[0], 'hana', at=1590)['idle_expired'])
            self.assertTrue(session_activity.metadata(con, self.sessions[1], 'hana', at=1590)['idle_expired'])
        with patch.object(session_activity, 'now', return_value=2179):
            with request_activity.observe(ctx.before_hana_request):
                with self.assertRaisesRegex(request_activity.RequestBlocked, '^session_idle_expired$'):
                    request_activity.before_request('ra')
            request_activity.before_request('bank')  # A blocked context also resets its observer.

    def test_legacy_schema_uses_creation_time_for_all_idle_limited_institutions(self):
        with self.db.write() as con:
            con.execute('DROP TABLE session_activity')  # Pre-feature schema version 1.
            con.execute('UPDATE sessions SET checked_at=3000')
        reopened = Database(self.db.file())
        with reopened.read() as con, patch.object(session_activity, 'now', return_value=2790):
            self.assertEqual(session_activity.metadata(con, self.sessions[0], 'hana')['last_request_at'], 1000)
            for service in ('hana', 'hana_corporate', 'giro', 'hometax'):
                self.adapter.service = service
                self.assertEqual(session_activity.refusal(con, self.adapter, self.sessions[0]), 'session_idle_expired')
        with reopened.write() as con:
            session_activity.record(con, self.sessions[0]['id'], 1599)
            con.execute('DELETE FROM sessions WHERE id=?', (self.sessions[0]['id'],))
            self.assertEqual(con.execute('SELECT count(*) FROM session_activity').fetchone()[0], 0)

    def test_each_service_counts_the_idle_gap_it_was_seen_to_keep(self):
        with self.db.read() as con:
            for service, limit in (('giro', 290), ('hana', 590), ('hana_corporate', 590), ('hometax', 1790)):
                self.adapter.service = service
                value = session_activity.metadata(con, self.sessions[0], service, at=1000 + limit - 1)
                self.assertEqual((value['idle_seconds'], value['idle_expires_at'], value['idle_expired']),
                                 (limit, 1000 + limit, False))
                self.assertTrue(session_activity.metadata(con, self.sessions[0], service, at=1000 + limit)['idle_expired'])
                with patch.object(session_activity, 'now', return_value=1000 + limit - 1):
                    self.assertIsNone(session_activity.refusal(con, self.adapter, self.sessions[0]))
                with patch.object(session_activity, 'now', return_value=1000 + limit):
                    self.assertEqual(session_activity.refusal(con, self.adapter, self.sessions[0]), 'session_idle_expired')

    def test_corporate_session_counts_the_timeout_its_login_was_told(self):
        import json
        told = {**self.sessions[0], 'verdict': json.dumps({'accepted': True, 'server_session_timeout_minutes': 10})}
        with self.db.read() as con:
            value = session_activity.metadata(con, told, 'hana_corporate', at=1599)
            self.assertEqual((value['idle_seconds'], value['idle_expires_at'], value['idle_expired']), (600, 1600, False))
            self.assertTrue(session_activity.metadata(con, told, 'hana_corporate', at=1600)['idle_expired'])
            self.assertEqual(session_activity.metadata(con, {**told, 'verdict': {'server_session_timeout_minutes': 12}},
                                                       'hana_corporate')['idle_seconds'], 720)
            # Only Hana corporate states a timeout; the field means nothing for another service.
            self.assertEqual(session_activity.metadata(con, told, 'hana')['idle_seconds'], 590)
            for verdict in (None, '', 'not-json', '{}', json.dumps({'server_session_timeout_minutes': '10'}),
                            json.dumps({'server_session_timeout_minutes': 0}), json.dumps({'server_session_timeout_minutes': True}),
                            json.dumps({'server_session_timeout_minutes': 1441}), json.dumps([10])):
                with self.subTest(verdict=verdict):
                    self.assertEqual(session_activity.metadata(con, {**told, 'verdict': verdict}, 'hana_corporate')['idle_seconds'], 590)
            legacy = {k: v for k, v in told.items() if k != 'verdict'}
            self.assertEqual(session_activity.metadata(con, legacy, 'hana_corporate')['idle_seconds'], 590)

    def test_listing_can_leave_out_login_extension_jobs_before_its_limit(self):
        from finance_cli.server import jobs
        with self.db.write() as con:
            for index, name in enumerate(('hana.onesign.accounts', 'hana.session.extend', 'hana.session.extend')):
                con.execute('INSERT INTO jobs(id,name,origin,request_digest,status,step,created_at,updated_at) '
                            'VALUES (?,?,?,?,?,?,?,?)',
                            (f'jb_{index}', name, 'web', 'synthetic', 'finished', 'run', 1000 + index, 1000 + index))
        with self.db.read() as con:
            self.assertEqual([j['name'] for j in jobs.listing(con, limit=1)], ['hana.session.extend'])
            self.assertEqual([j['id'] for j in jobs.listing(con, limit=1, hide_extensions=True)], ['jb_0'])
        self.enroll()
        self.assertEqual(len(self.get('/jobs').json()['jobs']), 3)
        self.assertEqual([j['id'] for j in self.get('/jobs?hide=session_extend&limit=1').json()['jobs']], ['jb_0'])
