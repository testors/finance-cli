"""Server foundation: settings, browser access, model and job store. Synthetic only."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from support import ORIGIN, ServerCase, synthetic_certificate

from finance_cli.core import profiles, storage
from finance_cli.server import access, config as settings, jobs, model, worker
from finance_cli.server.adapters import base
from finance_cli.server.db import dumps, loads


class SettingsTests(unittest.TestCase):
    def test_public_origin_rules(self):
        self.assertEqual(settings.normalize_origin('https://Finance.Example.ts.net:443/'), 'https://finance.example.ts.net')
        self.assertEqual(settings.normalize_origin('http://localhost:8740'), 'http://localhost:8740')
        for value in ('http://192.168.0.10:8740', 'https://host/path', 'https://user@host', 'ftp://host', 'https://'):
            with self.assertRaises(ValueError):
                settings.normalize_origin(value)
        local = settings.Config()
        self.assertEqual((local.mode, local.secure), ('local', False))
        proxy = settings.Config(public_origin='https://finance.example.ts.net')
        self.assertEqual((proxy.mode, proxy.secure), ('proxy', True))
        self.assertEqual(proxy.public_origin, 'https://finance.example.ts.net')


class LockTests(unittest.TestCase):
    def test_hold_is_reused_only_for_its_exact_path(self):
        with self.subTest('same process'), tempfileless() as root:
            path = root / 'resource.lock'
            with storage.hold(path):
                with storage.lock(path):
                    pass  # The worker's business function reuses the held lock.
                with self.assertRaises(ValueError):
                    with storage.hold(path):
                        pass
                code = subprocess.run([sys.executable, '-c', 'import sys; from finance_cli.core import storage\n'
                                       'try:\n with storage.lock(sys.argv[1]): pass\nexcept BlockingIOError: sys.exit(7)',
                                       str(path)]).returncode
                self.assertEqual(code, 7)
            with storage.lock(path):
                with self.assertRaises(BlockingIOError):
                    with storage.lock(path):
                        pass


class tempfileless:
    def __enter__(self):
        import tempfile
        self.temp = tempfile.TemporaryDirectory()
        return Path(self.temp.name).resolve()

    def __exit__(self, *args):
        self.temp.cleanup()


class AccessTests(ServerCase):
    def test_static_app_and_headers(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn("script-src 'self'", response.headers['content-security-policy'])
        self.assertEqual(response.headers['x-frame-options'], 'DENY')
        self.assertEqual(self.client.get('/static/../config.json').status_code, 404)
        self.assertEqual(self.client.get('/static/unknown.js').status_code, 404)

    def test_every_packaged_screen_file_is_served(self):
        # The screen is one set of modules that import each other; one that is not served stops it all.
        from importlib.resources import files
        import re
        names = sorted(p.name for p in files('finance_cli.server').joinpath('static').iterdir() if p.name != 'index.html')
        self.assertIn('busy.js', names)
        for name in names:
            with self.subTest(name=name):
                response = self.client.get('/static/' + name)
                self.assertEqual(response.status_code, 200)
                self.assertIn("script-src 'self'", response.headers['content-security-policy'])
                for imported in re.findall(r"from '\./([a-z]+\.js)'", response.text):
                    self.assertIn(imported, names)

    def test_arbitrary_hosts_allow_public_access_but_require_device_authentication(self):
        for host in ('100.64.0.1:8740', 'synthetic.example:8740'):
            with self.subTest(host=host):
                response = self.client.get('/api/v1/auth/state', headers={'Host': host})
                self.assertEqual(response.status_code, 200)
                self.assertFalse(response.json()['enrolled'])
                protected = self.client.get('/api/v1/capabilities', headers={'Host': host})
                self.assertEqual((protected.status_code, protected.json()['error']), (401, 'access_required'))

    def test_enrollment_code_single_use_rate_limit_and_arbitrary_origin(self):
        self.assertEqual(self.get('/capabilities').status_code, 401)
        state = self.get('/auth/state').json()
        self.assertEqual((state['enrolled'], state['mode']), (False, 'local'))
        with self.db.write() as con:
            code = access.create_code(con, self.config)['code']
        wrong = self.client.post('/api/v1/auth/enroll', json={'code': 'AAAAA-AAAAA'}, headers={'Origin': ORIGIN})
        self.assertEqual((wrong.status_code, wrong.json()), (403, {'error': 'enrollment_code_invalid'}))
        ok = self.client.post('/api/v1/auth/enroll', json={'code': code.lower()},
                              headers={'Origin': 'http://synthetic.example:8740'})
        self.assertEqual(ok.status_code, 200)
        cookie = ok.headers['set-cookie'].lower()
        self.assertIn('httponly', cookie)
        self.assertIn('samesite=strict', cookie)
        self.assertNotIn('secure', cookie)  # Local HTTP development origin only.
        again = self.client.post('/api/v1/auth/enroll', json={'code': code}, headers={'Origin': ORIGIN})
        self.assertEqual(again.status_code, 403)
        with self.db.read() as con:
            stored = [r[0] for r in con.execute('SELECT code_hash FROM enrollment_codes')]
            self.assertNotIn(code.replace('-', ''), json.dumps(stored))
        for _ in range(10):
            self.client.post('/api/v1/auth/enroll', json={'code': 'BBBBB-BBBBB'}, headers={'Origin': ORIGIN})
        with self.db.write() as con:
            fresh = access.create_code(con, self.config)['code']
        limited = self.client.post('/api/v1/auth/enroll', json={'code': fresh}, headers={'Origin': ORIGIN})
        self.assertEqual((limited.status_code, limited.json()['error']), (429, 'enrollment_rate_limited'))

    def test_proxy_origin_sets_secure_cookie_and_ignores_remote_forwarding(self):
        from fastapi.testclient import TestClient
        from finance_cli.server.app import client_address, create_app
        config = settings.Config(public_origin='https://finance.example.ts.net')
        client = self.enterContext(TestClient(create_app(config, db=self.db, dispatcher=False),
                                              base_url='https://finance.example.ts.net'))
        with self.db.write() as con:
            code = access.create_code(con, config)['code']
        response = client.post('/api/v1/auth/enroll', json={'code': code},
                               headers={'Origin': 'https://finance.example.ts.net'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('secure', response.headers['set-cookie'].lower())
        # A code made for another public origin is not accepted.
        with self.db.write() as con:
            local = access.create_code(con, self.config)['code']
        other = client.post('/api/v1/auth/enroll', json={'code': local}, headers={'Origin': 'https://finance.example.ts.net'})
        self.assertEqual(other.status_code, 403)

        class Peer:
            def __init__(self, host):
                self.client = type('C', (), {'host': host})()
                self.headers = {'x-forwarded-for': '203.0.113.9, 198.51.100.7'}
        self.assertEqual(client_address(Peer('127.0.0.1')), '198.51.100.7')
        self.assertEqual(client_address(Peer('192.0.2.1')), '192.0.2.1')

    def test_csrf_arbitrary_origin_idle_expiry_and_revocation(self):
        self.enroll()
        self.assertEqual(self.get('/capabilities').status_code, 200)
        no_token = self.client.post('/api/v1/profiles', json={'name': '내 개인'},
                                    headers={'Origin': 'http://synthetic.example:8740'})
        self.assertEqual((no_token.status_code, no_token.json()['error']), (403, 'csrf_token_invalid'))
        no_origin = self.client.post('/api/v1/profiles', json={'name': '내 개인'}, headers={'X-CSRF-Token': self.csrf})
        self.assertEqual(no_origin.status_code, 200)
        other_origin = self.client.post('/api/v1/profiles', json={'name': '다른 주소'},
                                        headers={'X-CSRF-Token': self.csrf, 'Origin': 'http://synthetic.example:8740'})
        self.assertEqual(other_origin.status_code, 200)
        self.assertEqual(self.post('/profiles', {'name': '내 개인'}).status_code, 200)
        devices = self.get('/auth/devices').json()['devices']
        self.assertTrue(devices[0]['current'])
        with self.db.write() as con:
            con.execute('UPDATE devices SET last_seen_at=?', (time.time() - self.config.idle_minutes * 60 - 5,))
        self.assertEqual(self.get('/profiles').status_code, 401)
        self.enroll()
        self.assertEqual(self.post('/auth/logout').status_code, 200)
        self.assertEqual(self.get('/profiles').status_code, 401)

    def test_errors_never_echo_request_values(self):
        self.enroll()
        secret_like = 'VALUE-THAT-MUST-NOT-ECHO'
        for response in (self.post('/profiles', {'name': secret_like * 5}),
                         self.post('/jobs', {'name': 'giro.bills.parse', 'input': {'upload_id': secret_like,
                                                                                    'tax_type': 'national'}}),
                         self.post('/logins', {'institution': secret_like}),
                         self.client.post('/api/v1/jobs', content=b'{not json' + secret_like.encode(),
                                          headers=self.headers())):
            self.assertIn(response.status_code, (400, 404, 409))
            self.assertNotIn(secret_like, response.text)


class ModelTests(ServerCase):
    def test_logins_revision_and_signing_without_inference(self):
        self.enroll()
        synthetic_certificate('login-cert')
        synthetic_certificate('invoice-cert')
        created = self.post('/logins', {'institution': 'hometax', 'method': 'joint_certificate', 'name': '홈택스',
                                        'credential': 'login-cert'}).json()
        self.assertEqual((created['revision'], created['channel'], created['signing']), (1, None, {}))
        self.assertEqual(created['credential']['type'], 'joint')
        stale = self.patch_(f"/logins/{created['id']}", {'expected_revision': 0, 'name': 'x'})
        self.assertEqual((stale.status_code, stale.json()['error']), (409, 'revision_conflict'))
        renamed = self.patch_(f"/logins/{created['id']}", {'expected_revision': 1, 'name': '홈택스 개인'}).json()
        self.assertEqual(renamed['revision'], 1)  # Display names are not execution settings.
        signed = self.patch_(f"/logins/{created['id']}", {'expected_revision': 1, 'signing': {
            'invoice_sign': {'method': 'joint_certificate', 'credential': 'invoice-cert'}}}).json()
        self.assertEqual(signed['revision'], 2)
        refused = self.patch_(f"/logins/{created['id']}", {'expected_revision': 2, 'signing': {
            'transfer_sign': {'method': 'onesign', 'credential': 'x'}}})
        self.assertEqual(refused.status_code, 400)
        server_managed = self.patch_(f"/logins/{created['id']}", {'expected_revision': 2,
                                                                 'registration': {'app_profile': 'x'}})
        self.assertEqual(server_managed.json()['error'], 'registration_is_server_managed')
        options = self.get(f"/logins/{created['id']}/auth-options").json()
        self.assertFalse(options['automatic_fallback'])
        self.assertEqual({o['purpose'] for o in options['options']}, {'login', 'invoice_sign'})
        credentials = self.get('/credentials').json()['credentials']
        self.assertEqual({c['ref'] for c in credentials}, {'login-cert', 'invoice-cert'})
        self.assertNotIn('blob', json.dumps(credentials))

    def test_certificate_profile_import_is_read_only_and_old_cli_cannot_touch_it(self):
        synthetic_certificate('personal')
        profiles.set_certificate('main', 'hometax', 'personal')
        profiles.set_certificate('main', 'giro', 'personal')
        path = self.home / 'profiles.json'
        before = path.read_bytes()
        from finance_cli.server.cli import main as server_main
        output = io.StringIO()
        with patch('sys.stdout', output):
            self.assertEqual(server_main(['import-profiles']), 0)
        report = json.loads(output.getvalue())
        self.assertEqual([c['service'] for c in report['created']], ['hometax'])
        # Giro now has a PIN login; a legacy certificate profile is still not a PIN connection.
        self.assertEqual(report['skipped'][0]['reason'], 'unsupported_login_method')
        self.assertEqual(path.read_bytes(), before)
        with self.db.read() as con:
            login = model.list_logins(con)[0]
        self.assertIsNone(login['channel'])
        # The old CLI keeps writing its own file; the new model is unaffected.
        profiles.set_certificate('other', 'hometax', 'personal')
        with self.db.read() as con:
            self.assertEqual(len(model.list_logins(con)), 1)
        output = io.StringIO()
        with patch('sys.stdout', output):
            server_main(['import-profiles'])
        self.assertEqual(json.loads(output.getvalue())['skipped'][0]['reason'], 'unsupported_login_method')

    def test_targets_only_from_verification_results_and_profiles_group_them(self):
        self.enroll()
        synthetic_certificate()
        login = self.post('/logins', {'institution': 'hometax', 'method': 'joint_certificate', 'name': 'h',
                                      'credential': 'synthetic'}).json()
        job_id = insert_job(self.db, login_id=login['id'], attempt={'target_candidates': [
            {'ref': 'c1', 'kind': 'business', 'identity_key': 'business:T00001', 'label': '가상 사업장',
             'identity': {'tin': 'T00001', 'name': '가상 사업장'}}]})
        forged = self.post(f"/logins/{login['id']}/targets", {'job_id': job_id, 'candidate': 'c2'})
        self.assertEqual(forged.json()['error'], 'candidate_not_found')
        target = self.post(f"/logins/{login['id']}/targets", {'job_id': job_id, 'candidate': 'c1'}).json()
        self.assertEqual((target['kind'], target['identity']['tin']), ('business', '•0001'))
        again = self.post(f"/logins/{login['id']}/targets", {'job_id': job_id, 'candidate': 'c1'}).json()
        self.assertEqual(again['id'], target['id'])
        profile = self.post('/profiles', {'name': 'A스튜디오', 'kind': 'sole_proprietor',
                                          'target_ids': [target['id']]}).json()
        self.assertEqual(profile['target_ids'], [target['id']])
        readiness = self.get(f"/profiles/{profile['id']}/capabilities").json()
        self.assertEqual(readiness['targets'][0]['readiness'], 'login_required')
        unset = self.post('/profiles', {'name': '미설정'}).json()
        self.assertIsNone(unset['kind'])

    def test_saved_account_results_show_full_numbers_by_ref_without_requery_or_record_rewrite(self):
        self.enroll()
        synthetic_certificate()
        login = self.post('/logins', {'institution': 'hana', 'method': 'joint_certificate', 'name': 'h',
                                      'credential': 'synthetic'}).json()
        numbers = ['12345678901234', '98765432101234']  # Same last four digits: never match on the mask.
        masked = '••••••••••1234'
        candidates = [{'ref': f'account-{index}', 'kind': 'account', 'identity_key': 'account:' + number,
                       'label': '계좌 ' + masked, 'identity': {'account_number': number}, 'token': 'PRIVATE'}
                      for index, number in enumerate(numbers, 1)]
        result = {'accounts': [{'ref': 'account-2', 'account_number': masked, 'label': '별칭'},
                               {'ref': 'account-1', 'account_number': masked, 'label': '계좌 ' + masked}],
                  'rows': [{'acctNo': masked}, {'acctNo': masked}]}
        for name in ('hana.accounts.list', 'hana.onesign.accounts'):
            self.assertIsNotNone(jobs.registry.get(name))
            job_id = insert_job(self.db, name=name, login_id=login['id'], result=result,
                                attempt={'target_candidates': candidates})
            shown = self.get('/jobs/' + job_id).json()
            self.assertEqual([r['account_number'] for r in shown['result']['accounts']], numbers[::-1])
            self.assertEqual([r['acctNo'] for r in shown['result']['rows']], numbers)
            self.assertEqual([r['label'] for r in shown['result']['accounts']], ['별칭', '계좌 ' + numbers[0]])
            self.assertNotIn('PRIVATE', json.dumps(shown))
            target = self.post(f"/logins/{login['id']}/targets", {'job_id': job_id, 'candidate': 'account-1'}).json()
            self.assertEqual(target['identity']['account_number'], numbers[0])
            self.assertEqual(target['display_name'], '계좌 ' + numbers[0])
            with self.db.read() as con:
                self.assertEqual(loads(jobs.get(con, job_id)['result']), result)

    def test_account_fields_are_visible_without_exposing_other_sensitive_fields(self):
        from finance_cli.server.adapters.hometax import scalar_row
        from finance_cli.server.adapters.hana_queries import bank_row
        number = '123-456789-01234'
        self.assertEqual(bank_row({'wdrwAcctNo': number, 'rcvAcctNo': number, 'thrAcctNo': number,
                                   'acctNo': number, 'token': 'PRIVATE', 'cookie': 'PRIVATE'}),
                         dict.fromkeys(('wdrwAcctNo', 'rcvAcctNo', 'thrAcctNo', 'acctNo'), number))
        self.assertEqual(scalar_row({'acctNo': number, 'rrn': '1234567890123', 'crdNo': '1234567890123456',
                                    'telNo': '01012345678', 'nested': {'token': 'PRIVATE'}}),
                         {'acctNo': number, 'rrn': '•••••••••0123', 'crdNo': '••••••••••••3456',
                          'telNo': '•••••••5678'})


def insert_job(db, *, login_id=None, result=None, name='giro.bills.parse', status='finished', attempt=None):
    from finance_cli.server.db import new_id, now
    job_id = new_id('jb')
    with db.write() as con:
        con.execute('INSERT INTO jobs(id, name, origin, login_id, snapshot, input, request_digest, status, step, local,'
                    ' outcome, result, attempt, created_at, updated_at, observed_at) VALUES'
                    " (?,?,?,?,'{}','{}','x',?,'run','{}','success',?,?,?,?,?)",
                    (job_id, name, 'web:test', login_id, status, dumps(result), dumps(attempt or {}), now(), now(), now()))
    return job_id


class Probe(base.Adapter):
    """In-process adapter for worker contract tests."""
    name = 'test.probe'
    title = '테스트'
    area = 'giro'
    service = 'giro'
    requires_login = False
    steps = {'run': base.Step('run', secrets=('pin',))}

    def __init__(self, resource=None, behaviour=None):
        self.resource, self.behaviour = resource, behaviour

    def validate(self, value, login=None):
        return value or {}

    def resources(self, ctx, step):
        return [self.resource] if self.resource else []

    def run(self, ctx, step):
        return self.behaviour(ctx)


class WorkerHelpers(ServerCase):
    def submit_probe(self, adapter, input=None, key=None, origin='web:dv_test'):
        with patch.dict('finance_cli.server.adapters._registry', {'test.probe': adapter}, clear=False), \
                patch('finance_cli.server.capabilities.job_state', return_value={'status': 'available'}):
            return jobs.submit(self.db, name='test.probe', origin=origin, input=input, idempotency_key=key)

    def run_probe(self, adapter, job, secrets=None):
        stdin = io.StringIO(json.dumps(secrets) + '\n' if secrets is not None else '')
        control = io.StringIO()
        with patch.dict('finance_cli.server.adapters._registry', {'test.probe': adapter}, clear=False):
            status = worker.run(self.db, job['id'], 'run', control=control, stdin=stdin)
        events = [json.loads(line) for line in control.getvalue().splitlines()]
        with self.db.read() as con:
            return status, events, jobs.get(con, job['id'])

    def setUp(self):
        super().setUp()
        from finance_cli.server import adapters
        adapters.load()



class WorkerTests(WorkerHelpers):
    def test_idempotency_binds_key_to_content(self):
        adapter = Probe(behaviour=lambda ctx: base.StepResult(outcome='success'))
        first, created = self.submit_probe(adapter, {'a': 1}, key='key-00000001')
        again, created_again = self.submit_probe(adapter, {'a': 1}, key='key-00000001')
        self.assertEqual((first['id'], created, created_again), (again['id'], True, False))
        with self.assertRaisesRegex(model.Conflict, 'idempotency_key_conflict'):
            self.submit_probe(adapter, {'a': 2}, key='key-00000001')
        other, _ = self.submit_probe(adapter, {'a': 1}, key='key-00000001', origin='web:dv_other')
        self.assertNotEqual(other['id'], first['id'])

    def test_busy_resource_keeps_job_queued_and_secrets_unread(self):
        lock = self.root / 'resource.lock'
        seen = []
        adapter = Probe(resource=lock, behaviour=lambda ctx: seen.append(ctx.secrets) or base.StepResult(outcome='success'))
        job, _ = self.submit_probe(adapter)
        with storage.lock(lock):
            status, events, stored = self.run_probe(adapter, job, {'pin': '123456'})
        self.assertEqual((status, events[-1]['event'], stored['status']), ('busy', 'busy', 'queued'))
        self.assertEqual(seen, [])
        status, events, stored = self.run_probe(adapter, job, {'pin': '123456'})
        self.assertEqual([e['event'] for e in events], ['ready'])
        self.assertEqual((status, stored['status'], stored['outcome']), ('finished', 'finished', 'success'))
        self.assertEqual(seen, [{'pin': '123456'}])
        text = json.dumps(dict(stored))
        with self.db.read() as con:
            text += json.dumps([dict(r) for r in con.execute('SELECT * FROM job_events')])
        self.assertAbsent(text, '123456')
        self.assertEqual(self.run_probe(adapter, job, {'pin': '1'})[0], 'skipped')

    def test_missing_step_secret_stops_before_work(self):
        adapter = Probe(behaviour=lambda ctx: self.fail('must not run'))
        job, _ = self.submit_probe(adapter)
        status, _, stored = self.run_probe(adapter, job, {})
        self.assertEqual((stored['outcome'], loads(stored['local'])['stopped']), ('not_started', 'step_input_missing'))

    def test_observed_verdict_survives_later_error(self):
        def behaviour(ctx):
            ctx.reserve()
            ctx.observe(service_verdict={'branch': 'success'}, outcome='success', result={'rows': []})
            raise RuntimeError('storage failed after the service verdict')
        adapter = Probe(behaviour=behaviour)
        job, _ = self.submit_probe(adapter)
        _, _, stored = self.run_probe(adapter, job, {'pin': '1'})
        self.assertEqual((stored['outcome'], loads(stored['service_verdict'])), ('success', {'branch': 'success'}))
        self.assertEqual(loads(stored['local'])['stopped'], 'local_processing_error')
        self.assertNotIn('storage failed', stored['local'])

    def test_error_without_verdict_is_unknown_once_sent_and_not_started_before(self):
        def sent(ctx):
            ctx.reserve()
            raise base.Stop('transport_error')
        for behaviour, expected in ((sent, 'unknown'), (lambda ctx: (_ for _ in ()).throw(ValueError('x')), 'not_started')):
            adapter = Probe(behaviour=behaviour)
            job, _ = self.submit_probe(adapter)
            _, _, stored = self.run_probe(adapter, job, {'pin': '1'})
            self.assertEqual(stored['outcome'], expected)

    def test_recovery_never_resends(self):
        adapter = Probe(behaviour=lambda ctx: base.StepResult(outcome='success'))
        job, _ = self.submit_probe(adapter)
        with self.db.write() as con:
            con.execute("UPDATE jobs SET status='running', attempt=? WHERE id=?",
                        (dumps({'sent': True, 'reserved_step': 'run'}), job['id']))
        self.assertEqual(worker.recover(self.db), [job['id']])
        with self.db.read() as con:
            stored = jobs.get(con, job['id'])
        self.assertEqual((stored['status'], stored['outcome']), ('finished', 'unknown'))
        self.assertTrue(loads(stored['local'])['interrupted'])
        # A reservation from an earlier step does not make this step's crash unknown.
        other, _ = self.submit_probe(adapter)
        with self.db.write() as con:
            con.execute("UPDATE jobs SET status='running', attempt=? WHERE id=?",
                        (dumps({'sent': True, 'reserved_step': 'prepare'}), other['id']))
        worker.recover(self.db)
        with self.db.read() as con:
            self.assertEqual(jobs.get(con, other['id'])['outcome'], 'not_started')

    def test_running_job_with_live_worker_is_left_alone(self):
        adapter = Probe(behaviour=lambda ctx: base.StepResult(outcome='success'))
        job, _ = self.submit_probe(adapter)
        with self.db.write() as con:
            con.execute("UPDATE jobs SET status='running' WHERE id=?", (job['id'],))
        holder = subprocess.Popen([sys.executable, '-c', 'import sys,time; from finance_cli.core import storage\n'
                                   'with storage.lock(sys.argv[1]):\n print("held", flush=True); time.sleep(30)',
                                   str(worker.job_directory(job['id']) / 'worker.lock')], stdout=subprocess.PIPE)
        try:
            holder.stdout.readline()
            self.assertEqual(worker.recover(self.db), [])
        finally:
            holder.kill()
            holder.wait()
            holder.stdout.close()

    def test_secret_handoff_refused_when_worker_cannot_start(self):
        from finance_cli.server import dispatch
        script = self.root / 'fake_worker.py'
        record = self.root / 'received.txt'
        script.write_text('import json,sys\nmode=sys.argv[1]\n'
                          'print(json.dumps({"event": mode}), flush=True)\n'
                          'if mode=="ready":\n open(sys.argv[2],"w").write(sys.stdin.readline())\n')

        def fake(mode):
            def spawn(job_id, step, *, with_secrets):
                return subprocess.Popen([sys.executable, str(script), mode, str(record)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE)
            return spawn
        with patch.object(dispatch, 'spawn', fake('busy')):
            self.assertEqual(dispatch.start_with_secrets('jb_x', 'run', {'pin': '123456'}), 'busy')
        self.assertFalse(record.exists())
        with patch.object(dispatch, 'spawn', fake('ready')):
            self.assertEqual(dispatch.start_with_secrets('jb_x', 'run', {'pin': '123456'}), 'started')
        for _ in range(50):
            if record.exists() and record.read_text():
                break
            time.sleep(0.05)
        self.assertEqual(json.loads(record.read_text()), {'pin': '123456'})

    def test_confirmation_is_bound_to_digest_revision_and_deadline(self):
        synthetic_certificate()
        with self.db.write() as con:
            login = model.create_login(con, institution_name='hometax', method='joint_certificate', name='h',
                                       credential='synthetic')
        job_id = insert_job(self.db, login_id=login['id'], status='awaiting_input')
        with self.db.write() as con:
            con.execute('UPDATE jobs SET login_revision=1, awaiting=?, expires_at=? WHERE id=?',
                        (dumps({'kind': 'confirm', 'digest': 'd1', 'next_step': 'issue', 'step': 'prepare'}),
                         time.time() + 60, job_id))
        with self.assertRaisesRegex(base.InputError, 'confirmation_mismatch'):
            jobs.accept_confirmation(self.db, job_id, 'd2', 'web:x')
        job, changed = jobs.accept_confirmation(self.db, job_id, 'd1', 'web:x')
        self.assertEqual((job['status'], job['step'], changed), ('queued', 'issue', True))
        job, changed = jobs.accept_confirmation(self.db, job_id, 'd1', 'web:x')
        self.assertFalse(changed)  # A repeated confirmation never re-executes.
        jobs.revert_confirmation(self.db, job_id, 'busy')
        with self.db.read() as con:
            self.assertEqual(jobs.get(con, job_id)['status'], 'awaiting_input')
        with self.db.write() as con:
            con.execute('UPDATE jobs SET expires_at=? WHERE id=?', (time.time() - 1, job_id))
        with self.assertRaisesRegex(jobs.NotReady, 'job_expired'):
            jobs.accept_confirmation(self.db, job_id, 'd1', 'web:x')
        other = insert_job(self.db, login_id=login['id'], status='awaiting_input')
        with self.db.write() as con:
            con.execute('UPDATE jobs SET login_revision=1, awaiting=? WHERE id=?',
                        (dumps({'kind': 'confirm', 'digest': 'd1', 'next_step': 'issue'}), other))
            model.update_login(con, login['id'], expected_revision=1, channel=None, credential='synthetic')
            self.assertEqual(jobs.get(con, other)['status'], 'expired')


class ReviewRegressionTests(WorkerHelpers):
    def test_resource_error_finishes_the_job_instead_of_respawning(self):
        def resources(ctx, step):
            raise ValueError('session_not_found')
        adapter = Probe(behaviour=lambda ctx: self.fail('must not run'))
        adapter.resources = resources
        job, _ = self.submit_probe(adapter)
        status, events, stored = self.run_probe(adapter, job, {'pin': '1'})
        self.assertEqual((status, stored['status'], stored['outcome']), ('finished', 'finished', 'not_started'))
        self.assertEqual(loads(stored['local'])['stopped'], 'session_not_found')

    def test_stranded_secret_steps_are_released(self):
        from finance_cli.server.dispatch import Dispatcher
        adapter = Probe(behaviour=lambda ctx: base.StepResult(outcome='success'))
        job, _ = self.submit_probe(adapter)
        with self.db.write() as con:
            con.execute('UPDATE jobs SET updated_at=? WHERE id=?', (time.time() - 120, job['id']))
        with patch.dict('finance_cli.server.adapters._registry', {'test.probe': adapter}, clear=False):
            Dispatcher(self.db).release_stranded()
        with self.db.read() as con:
            stored = jobs.get(con, job['id'])
        self.assertEqual((stored['status'], loads(stored['local'])['cancelled_reason']),
                         ('cancelled', 'secrets_not_delivered'))

    def test_chunked_bodies_are_refused(self):
        self.enroll()
        response = self.client.post('/api/v1/profiles', content=iter([b'{"name": "x"}']),
                                    headers=self.headers(**{'Content-Type': 'application/json'}))
        self.assertEqual((response.status_code, response.json()['error']), (411, 'length_required'))

    def test_enrollment_limit_is_per_client(self):
        with self.db.write() as con:
            for _ in range(10):
                self.assertEqual(access.enroll(con, self.config, 'AAAAA-AAAAA', None, '198.51.100.1')[1],
                                 'enrollment_code_invalid')
            code = access.create_code(con, self.config)['code']
            self.assertEqual(access.enroll(con, self.config, code, None, '198.51.100.1')[1], 'enrollment_rate_limited')
            self.assertIsNotNone(access.enroll(con, self.config, code, None, '198.51.100.2')[0])

    def test_zero_day_window_is_kept(self):
        from finance_cli.server.adapters.giro import BillsParse
        self.assertEqual(BillsParse().validate({'upload_id': 'up_x', 'tax_type': 'local', 'mode': 'due',
                                                'within_days': 0})['within_days'], 0)


class PrivacyCheckTests(ServerCase):
    def test_short_secret_is_not_matched_in_generated_values_and_is_found_where_it_is_stored(self):
        generated = json.dumps({'id': 'jb_c158200040d6049b', 'created_at': 1791628105.604931, 'at': 1791626049.5,
                                'request_digest': 'f619b434b500a9b7e9e8aa32818955ddf73ac1906049eb4dbf2ba4b906cab640',
                                'session': 'web3657d1c23d0bfd86049e1f5', 'version': '6.2.2', 'host': '127.0.0.1'})
        self.assertEqual(generated.count('6049'), 5)
        self.assertAbsent(generated, '6049')
        self.assertAbsent(str((1791628105.604931, 'jb_c158200040d6049b', None)), '6049')
        for stored in ({'local': {'account_password': '6049'}}, {'result': 'pw=6049'}, {'pin': 6049},
                       {'note': '0006049'}, {'version': '6.2.6049'}):
            with self.subTest(stored=stored), self.assertRaises(AssertionError):
                self.assertAbsent(json.dumps(stored), '6049')
        # A needle that reads as an identifier or a decimal itself is searched in the text as it stands.
        for needle in ('c158200040d6049b', '1791628105.604931'):
            with self.subTest(needle=needle), self.assertRaises(AssertionError):
                self.assertAbsent(generated, needle)


class GiroEndToEndTests(ServerCase):
    def test_upload_parse_through_worker_process(self):
        from finance_cli.server.dispatch import Dispatcher
        self.enroll()
        page = {'responseCode': '000', 'paymentList': [
            {'elecNo': 'TEST-0000001', 'companyName': '가상 테스트 기관', 'payMny': '12,340', 'payLimitDate': '20260930'},
            {'elecNo': 'TEST-0000002', 'companyName': '가상 테스트 기관', 'payMny': '1,23', 'payLimitDate': '미정'}],
            'pageNaviMap': {'currentPage': '1', 'totalPage': '1', 'totalCount': '2'}}
        upload = self.client.post('/api/v1/uploads?kind=giro_bills', content=json.dumps(page).encode(),
                                  headers=self.headers(**{'Content-Type': 'application/json'})).json()
        response = self.post('/jobs', {'name': 'giro.bills.parse', 'input': {
            'upload_id': upload['id'], 'tax_type': 'national', 'mode': 'due', 'today': '2026-09-27', 'within_days': 7}})
        self.assertEqual(response.status_code, 202, response.text)
        job = response.json()
        dispatcher = Dispatcher(self.db)
        self.assertEqual(dispatcher.run_once(), [job['id']])
        dispatcher.running[job['id']].wait(timeout=60)
        job = self.get(f"/jobs/{job['id']}").json()
        self.assertEqual((job['status'], job['outcome']), ('finished', 'partial_success'), job)
        self.assertEqual(job['result']['bills'][0]['days_until_due'], 3)
        self.assertEqual(job['result']['bills'][0]['electronic_number'], '•••0001')
        self.assertEqual(job['result']['unparsed_count'], 1)
        self.assertFalse(job['result']['payment_state_inferred'])
        listing = self.get('/jobs').json()['jobs']
        self.assertNotIn('result', listing[0])

    def test_deeply_nested_upload_is_refused_without_parsing(self):
        from finance_cli.server.adapters.giro import MAX_DEPTH, nesting_depth
        self.assertEqual(nesting_depth('{"a": "[[[[", "b": [1, [2]]}'), 3)
        self.assertGreater(nesting_depth('[' * 100000), MAX_DEPTH)


if __name__ == '__main__':
    unittest.main()


class CliHistoryTests(ServerCase):
    def fin(self, argv, stdin=''):
        import contextlib
        from finance_cli.cli.main import main
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch('sys.stdin', io.StringIO(stdin)):
            code = main(argv)
        return code, output.getvalue()

    def test_cli_runs_join_the_history_without_values_and_never_change_results(self):
        from finance_cli.server import db as server_db
        page = json.dumps({'responseCode': '000', 'paymentList': [], 'pageNaviMap': {}})
        path = self.root / 'SECRET-LOOKING-NAME.json'
        path.write_text(page)
        with patch.object(server_db, 'exists', return_value=False):
            code, _ = self.fin(['giro', 'bills', 'list', '--type', 'national', '--input', str(path)])
        with self.db.read() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 0)
        baseline = self.fin(['giro', 'bills', 'list', '--type', 'national', '--input', str(path)])
        with self.db.read() as con:
            rows = [dict(r) for r in con.execute("SELECT * FROM jobs")]
        self.assertEqual(len(rows), 1)
        self.assertEqual(loads(rows[0]['snapshot'])['command'], ['giro', 'bills', 'list'])
        self.assertEqual(loads(rows[0]['local'])['exit_code'], baseline[0])
        # Whether the run carried the send approval is a flag, not a value; this one only read a file.
        self.assertIs(loads(rows[0]['local'])['send_requested'], False)
        self.assertNotIn('SECRET-LOOKING-NAME', json.dumps(rows))
        with patch('finance_cli.server.jobs.record_cli', side_effect=RuntimeError('database broken')):
            self.assertEqual(self.fin(['giro', 'bills', 'list', '--type', 'national', '--input', str(path)]), baseline)
        self.enroll()
        listing = self.get('/jobs').json()['jobs']
        self.assertEqual((listing[0]['origin'], listing[0]['command']), ('cli', ['giro', 'bills', 'list']))
        with patch.dict(os.environ, {'FINANCE_REQUEST_ORIGIN': 'agent'}):
            self.fin(['giro', 'bills', 'list', '--type', 'national', '--input', str(path)])
        self.assertEqual(self.get('/jobs').json()['jobs'][0]['origin'], 'agent')
        from finance_cli.cli.main import record_history
        record_history('hana', ['transfer', 'execute', '--name', 'SECRET-LOOKING-VALUE', '--send'], 0)
        approved = self.get('/jobs').json()['jobs'][0]
        self.assertEqual((approved['command'], approved['local']['send_requested']), (['hana', 'transfer', 'execute'], True))
        self.assertNotIn('SECRET-LOOKING-VALUE', json.dumps(approved))


class JobListingTests(ServerCase):
    def test_every_listing_filter_applies_before_the_limit(self):
        """Newer unrelated jobs and CLI records never push a screen's own rows out of its listing."""
        from finance_cli.server import jobs
        self.enroll()
        old, created = jobs.submit(self.db, name='giro.readiness', origin='web:test')
        self.assertTrue(created)
        for _ in range(3):
            jobs.record_cli(self.db, origin='cli', command=['hana', 'transfer', 'execute'], exit_code=0, service='hana')
        newest = self.get('/jobs?limit=2').json()['jobs']
        self.assertEqual([j['name'] for j in newest], ['cli.hana', 'cli.hana'])
        for query in ('name=giro.readiness&limit=1', 'area=giro&limit=1', 'origin=web&limit=1'):
            self.assertEqual([j['id'] for j in self.get('/jobs?' + query).json()['jobs']], [old['id']], query)
        self.assertEqual(len(self.get('/jobs?origin=cli').json()['jobs']), 3)
        for query in ('origin=agent', 'origin=web%25', 'area=unknown', 'area=banking',
                      'name=giro.readiness&login_id=other', 'name=giro.readiness&target_id=other'):
            self.assertEqual(self.get('/jobs?' + query).json()['jobs'], [], query)
        older = self.get(f"/jobs?limit=5&before={newest[-1]['created_at']!r}").json()['jobs']
        self.assertEqual(older[-1]['id'], old['id'])
        self.assertFalse({j['id'] for j in newest} & {j['id'] for j in older})

    def test_api_answers_name_the_served_copy_of_the_app(self):
        """A tab compares the name with the one it started with; static files themselves carry none."""
        from finance_cli.server.app import assets_version
        name = self.get('/auth/state').headers['X-Finance-Assets']
        self.assertRegex(name, r'^[0-9a-f]{16}$')
        self.assertEqual(name, assets_version())
        self.enroll()
        self.assertEqual(self.get('/logins').headers['X-Finance-Assets'], name)
        self.assertNotIn('X-Finance-Assets', self.client.get('/static/app.js').headers)
