import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule, SyntheticModule} from 'node:vm';
import {JSDOM} from 'jsdom';

const root = new URL('../../src/finance_cli/server/static/', import.meta.url);

async function setup(t) {
  const dom = new JSDOM('<main id="main"></main><div id="enroll"></div><div id="stage"></div><div id="toast"></div><dialog id="detail-dialog"></dialog><button data-action="capture"></button>',
    {url: 'http://127.0.0.1:8740', runScripts: 'outside-only'});
  t.after(() => dom.window.close());
  const context = dom.getInternalVMContext();
  const data = {local: 5000, server: 1000, asked: [], gets: [], sent: [], submissions: 0, error: null, stopped: null};
  context.Date.now = () => data.local * 1000;
  data.row = {id: 'selected', institution: 'hana', method: 'onesign', current_session_id: 's',
    session: {last_request_at: 1000, idle_expires_at: 1600}};
  const values = {ApiError: class extends Error {}, TERMINAL: new Set(),
    api: {state: async () => ({enrolled: false}), get: async path => {
      data.gets.push(path);
      assert.equal(path, '/logins');
      return {logins: [structuredClone(data.row)], server_time: data.server};
    }},
    submit: async (name, fields) => {
      data.submissions++;
      if (data.error) throw {code: data.error, reasons: data.reasons};
      const job = {id: 'job', name, ...fields}; data.sent.push(job); return job;
    },
    follow: async () => {
      data.onFollow?.();
      return {...data.sent.at(-1), status: 'finished', outcome: data.outcome || 'success',
        local: data.stopped ? {stopped: data.stopped} : {}};
    },
  };
  const api = new SyntheticModule(Object.keys(values), function () {
    for (const [key, value] of Object.entries(values)) this.setExport(key, value);
  }, {context});
  const views = new SyntheticModule(['views', 'actions'], function () {
    this.setExport('views', {});
    this.setExport('actions', {capture: ctx => { data.ctx = ctx; },
      login: async (ctx, button) => { data.asked.push(button.dataset); }});
  }, {context});
  const ui = new SourceTextModule(await readFile(new URL('ui.js', root), 'utf8'), {context});
  const app = new SourceTextModule(await readFile(new URL('app.js', root), 'utf8'), {context});
  await app.link(name => ({'./api.js': api, './views.js': views, './ui.js': ui}[name]));
  await app.evaluate();
  Object.assign(app.namespace.state, {logins: [structuredClone(data.row)], sessionClock: {server: 1000, local: 5000}});
  dom.window.document.querySelector('[data-action="capture"]').click();
  return Object.assign(data, app.namespace, {document: dom.window.document});
}

test('600-second boundary uses server time despite browser clock offset', async t => {
  const app = await setup(t);
  app.local = 5599;
  assert.equal(app.bankSessionExpired(app.row), false);
  app.local = 5600;
  assert.equal(app.bankSessionExpired(app.row), true);
  assert.equal(app.bankSessionExpired({...app.row, institution: 'hometax'}), false);
  assert.equal(app.bankSessionExpired(null), false);
});

test('expired request opens the selected login without submitting or replaying', async t => {
  const app = await setup(t);
  app.local = 5600; app.server = 1600;
  let completed = 0;
  assert.equal(await app.ctx.run('hana.onesign.accounts', {login_id: 'selected'}, {onDone: () => completed++}), null);
  assert.deepEqual(app.gets, ['/logins']);
  assert.deepEqual(app.sent, []);
  assert.equal(app.asked.length, 1);
  assert.equal(app.asked[0].login, 'selected');
  assert.equal(app.asked[0].reason, 'session_idle_expired');
  assert.equal(completed, 0);
});

test('activity in another tab prevents a stale browser timeout', async t => {
  const app = await setup(t);
  app.local = 5600; app.server = 1600;
  app.row.session.last_request_at = 1590;
  app.row.session.idle_expires_at = 2190;
  assert.equal(await app.ensureBankSession(app.ctx, 'selected'), true);
  assert.equal(app.asked.length, 0);
  assert.equal(app.state.logins[0].session.idle_expires_at, 2190);
});

test('server expiry refusal and worker expiry both route to login without retry', async t => {
  for (const where of ['submit', 'worker']) {
    const app = await setup(t);
    if (where === 'submit') app.error = 'session_idle_expired';
    else app.stopped = 'session_idle_expired';
    let completed = 0;
    assert.equal(await app.ctx.run('hana.onesign.accounts', {login_id: 'selected'}, {onDone: () => completed++}), null);
    assert.equal(app.asked.length, 1);
    assert.equal(app.sent.length, where === 'submit' ? 0 : 1);
    assert.equal(completed, 0);
  }
});

test('finished bank work refreshes its persisted deadline; local export needs no login', async t => {
  const app = await setup(t);
  app.row.session.idle_expires_at = 1700;
  await app.ctx.run('hana.onesign.accounts', {login_id: 'selected'});
  assert.equal(app.state.logins[0].session.idle_expires_at, 1700);
  app.local = 5700; app.server = 1700;
  await app.ctx.run('hana.onesign.history.export', {login_id: 'selected'});
  assert.equal(app.sent.length, 2);
  assert.equal(app.asked.length, 0);
  assert.equal(app.state.logins[0].session.idle_expires_at, 1700); // Local API reads never extend it.
});

test('unavailable jobs show setup reasons without submitting again', async t => {
  const app = await setup(t);
  app.error = 'capability_unavailable';
  app.reasons = ['hometax_runtime_not_installed', 'node_not_found'];
  assert.equal(await app.ctx.run('hometax.login', {login_id: 'selected'}, {panel: 'stage'}), null);
  const message = app.document.querySelector('#stage').textContent;
  assert.match(message, /홈택스 실행 환경이 설치되지 않았어요/);
  assert.match(message, /fin runtime install hometax/);
  assert.match(message, /서버에 Node가 없어요/);
  assert.equal(message, '접수 안 됨' + app.document.querySelector('#toast').textContent);
  assert.equal(app.sent.length, 0);
  assert.equal(app.submissions, 1);
  app.reasons = [];
  await app.ctx.run('hometax.login', {login_id: 'selected'}, {panel: 'stage'});
  assert.match(app.document.querySelector('#stage').textContent, /이 기능은 지금 사용할 수 없어요/);
});

test('area tabs mark only areas with a live login and drop the mark at the idle limit', async t => {
  const app = await setup(t);
  app.document.querySelector('#stage').innerHTML = '<nav class="area-tabs"></nav>';
  const live = () => Object.fromEntries([...app.document.querySelectorAll('.area-tab')]
    .map(tab => [tab.dataset.mode, tab.classList.contains('live') && Boolean(tab.querySelector('.session-mark'))]));
  app.state.mode = 'giro';
  app.state.logins = [{...app.row, readiness: 'ready'},
    {id: 'tax', institution: 'hometax', readiness: 'login_required', session: {state: 'expired'}},
    {id: 'giro', institution: 'giro', readiness: 'ready', disabled: true}];
  app.local = 5599;
  app.renderTabs();
  assert.deepEqual(live(), {banking: true, corporate: false, giro: false, tax: false});
  assert.equal(app.document.querySelector('.area-tab[aria-current]').dataset.mode, 'giro');
  assert.match(app.document.querySelector('[data-mode="banking"]').getAttribute('aria-label'), /로그인됨/);
  app.local = 5600;
  app.renderTabs();
  assert.equal(live().banking, false);
  assert.equal(app.gets.length, 0);
});

test('an area with every login logged out says so on its work screens and offers the login there', async t => {
  const app = await setup(t);
  const main = app.document.querySelector('#main');
  const rows = [{id: 'bank', institution: 'hana', readiness: 'login_required', display_name: '합성 은행'},
    {id: 'giro', institution: 'giro', readiness: 'login_required', display_name: '합성 지로'},
    {id: 'tax', institution: 'hometax', readiness: 'ready', display_name: '합성 홈택스'}];
  const draw = (view, mode, logins = rows) => {
    Object.assign(app.state, {view, mode, logins: structuredClone(logins)});
    main.innerHTML = '<div class="page-heading"><h1>합성 화면</h1></div><form><input name="typed"></form>';
    main.querySelector('input').value = '합성 입력';
    app.renderLoginNotice();
    return main.querySelector('.login-notice');
  };
  for (const [view, mode, name] of [['giro-live', 'giro', '모바일지로'], ['giro-receipts', 'giro', '모바일지로'],
    ['history', 'banking', '하나개인뱅킹'], ['transfer', 'banking', '하나개인뱅킹']]) {
    const notice = draw(view, mode);
    assert.ok(notice, view);
    assert.match(notice.textContent, new RegExp(name + '에 로그인되어 있지 않아요'));
    assert.equal(notice.previousElementSibling.className, 'page-heading');
    assert.equal(notice.querySelectorAll('[data-action="login"]').length, 1);
  }
  assert.equal(draw('giro-live', 'giro').querySelector('button').dataset.login, 'giro');
  // Several logged-out connections: one named login button each.
  const two = draw('accounts', 'banking', [...rows, {id: 'bank2', institution: 'hana', readiness: 'login_required', display_name: '<b>둘째</b>'}]);
  assert.deepEqual([...two.querySelectorAll('button')].map(b => [b.dataset.login, b.textContent]),
    [['bank', '합성 은행 로그인'], ['bank2', '<b>둘째</b> 로그인']]);
  // A live login, a screen that needs no session, a shared screen, or no connection at all: no notice.
  assert.equal(draw('taxhome', 'tax'), null);
  assert.equal(draw('history', 'banking', [{...rows[0], readiness: 'query_only'}]), null);
  for (const view of ['girostatus', 'bills', 'deadlines']) assert.equal(draw(view, 'giro'), null, view);
  assert.equal(draw('reports', 'tax', [{...rows[2], readiness: 'login_required'}]), null);
  assert.equal(draw('settings', 'giro'), null);
  assert.equal(draw('corporate-accounts', 'corporate'), null);
  assert.equal(draw('giro-live', 'giro', [{...rows[1], disabled: true}]), null);
  // The login button runs the connection's own login; nothing is sent by showing the notice.
  draw('giro-live', 'giro').querySelector('button').click();
  await new Promise(resolve => setTimeout(resolve));
  assert.equal(app.asked.at(-1).login, 'giro');
  assert.equal(app.gets.length, 0);
});

test('a session that lapses while a form is open shows the notice without redrawing the form', async t => {
  const app = await setup(t);
  const main = app.document.querySelector('#main');
  Object.assign(app.state, {view: 'history', mode: 'banking', logins: [{...app.row, readiness: 'ready'}]});
  main.innerHTML = '<div class="page-heading"><h1>합성 화면</h1></div><form><input name="typed"></form>';
  main.querySelector('input').value = '합성 입력';
  app.renderLoginNotice();
  assert.equal(main.querySelector('.login-notice'), null);
  app.local = 5600; app.server = 1600;
  await app.ctx.run('hana.onesign.accounts', {login_id: 'selected'});
  assert.ok(main.querySelector('.login-notice'));
  assert.equal(main.querySelectorAll('.login-notice').length, 1);
  assert.equal(main.querySelector('input').value, '합성 입력');
  assert.equal(app.sent.length, 0);
});

test('records, connections and coverage belong to no area tab', async t => {
  const app = await setup(t);
  app.document.querySelector('#stage').innerHTML = '<nav class="area-tabs"></nav>';
  app.state.mode = 'giro';
  for (const [view, current] of [['settings', null], ['activity', null], ['coverage', null], ['giro-live', 'giro'], ['bills', 'giro']]) {
    app.state.view = view;
    app.renderTabs();
    assert.equal(app.document.querySelector('.area-tab[aria-current]')?.dataset.mode ?? null, current);
  }
});

test('a plain success shows when it was read; every other state keeps its badge', async t => {
  const app = await setup(t);
  const done = {id: 'j', status: 'finished', outcome: 'success', origin: 'web', observed_at: 1790000000, verification: 'live_untested'};
  assert.doesNotMatch(app.jobState(done), /status-pill|실서버 미검증|웹 요청/);
  assert.match(app.jobState(done), /조회/);
  assert.match(app.jobState({...done, outcome: 'rejected'}), /기관 거절/);
  // Giro's "고지내용 없음" answer is named as such, from the listed verdict or the full result.
  const bills = {...done, name: 'giro.bills.list', outcome: 'rejected'};
  for (const none of [{service_verdict: {no_bills_reported: true}}, {result: {no_bills_reported: true}}]) {
    assert.match(app.jobState({...bills, ...none}), /고지 없음/);
    assert.doesNotMatch(app.jobState({...bills, ...none}), /기관 거절/);
  }
  assert.match(app.jobState({...bills, service_verdict: {no_bills_reported: false}}), /기관 거절/);
  assert.match(app.jobState({...done, name: 'giro.payment.prepare', outcome: 'rejected', result: {no_bills_reported: true}}), /기관 거절/);
  assert.match(app.jobState({...done, outcome: 'unknown'}), /결과 미확인/);
  assert.match(app.jobState({...done, outcome: 'partial_success'}), /부분 성공/);
  assert.match(app.jobState({...done, status: 'running', outcome: 'not_started'}), /실행 중/);
  assert.match(app.jobState({...done, origin: 'cli'}), /CLI 요청/);
  assert.match(app.jobState({...done, local: {session_saved: false}}), /세션 저장 확인 안 됨/);
});

test('only an area tab switches area; a button with its own mode value runs its action', async t => {
  const app = await setup(t);
  const button = app.document.querySelector('[data-action="capture"]');
  button.dataset.mode = 'status';
  app.state.mode = 'tax';
  app.ctx = null;
  button.click();
  await new Promise(resolve => setTimeout(resolve));
  assert.ok(app.ctx, 'the action ran');
  assert.equal(app.state.mode, 'tax');
});

test('the area tab counts down to the nearest idle limit and stops at logout', async t => {
  const app = await setup(t);
  app.document.querySelector('#stage').innerHTML = '<nav class="area-tabs"></nav>';
  app.state.logins = [{...app.row, readiness: 'ready'}, {id: 'tax', institution: 'hometax', readiness: 'ready', session: {state: 'usable'}}];
  app.local = 5000;
  app.renderTabs();
  assert.equal(app.document.querySelector('[data-mode="banking"] .tab-countdown').textContent, '10:00');
  assert.equal(app.document.querySelector('[data-mode="tax"] .tab-countdown'), null, 'no countdown without a known limit');
  app.local = 5535;
  app.renderTabs();
  const soon = app.document.querySelector('[data-mode="banking"] .tab-countdown');
  assert.equal(soon.textContent, '1:05');
  assert.ok(soon.classList.contains('soon'));
  app.local = 5600;
  app.renderTabs();
  assert.equal(app.document.querySelector('.tab-countdown'), null, 'a session past its limit is logged out');
  assert.equal(app.gets.length, 0);
});

// A joint-certificate login whose module has an extension job, 80 seconds before its limit.
async function nearLimit(t, change = {}) {
  const app = await setup(t);
  Object.assign(app.row, {method: 'joint_certificate', readiness: 'ready', display_name: '합성 연결'}, change);
  app.state.capabilities = {jobs: ['hana.session.extend', 'hana.onesign.session.extend']};
  app.state.vaults = {};
  app.state.logins = [structuredClone(app.row)];
  app.onFollow = () => { app.row.session.idle_expires_at = app.server + 600; };
  app.local = 5520; app.server = 1520;
  return app;
}

test('automatic extension is off until chosen, waits for the limit and sends the extension job once', async t => {
  const app = await nearLimit(t);
  await app.extendLogin('selected');
  assert.equal(app.sent.length, 0, 'off by default');
  app.local = 5000; app.server = 1000;
  app.setAutoExtend(true);
  assert.equal(app.document.defaultView.localStorage.getItem('finance.autoExtend'), 'true');
  app.local = 5400; app.server = 1400;
  await app.extendLogin('selected');
  assert.equal(app.sent.length, 0, 'not while more than the lead time is left');
  app.local = 5520; app.server = 1520;
  await app.extendLogin('selected');
  assert.deepEqual(app.sent.map(j => [j.name, j.login_id, j.secrets]), [['hana.session.extend', 'selected', undefined]]);
  assert.equal(app.state.logins[0].session.idle_expires_at, 2120, 'the new limit comes from the server record');
  assert.equal(app.extensionState(app.state.logins[0]), 'on');
  await app.extendLogin('selected');
  assert.equal(app.sent.length, 1, 'with a fresh limit nothing more is sent');
});

test('an extension that does not succeed is not retried and stops for that session', async t => {
  const app = await nearLimit(t);
  app.local = 5000; app.server = 1000;
  app.setAutoExtend(true);
  app.local = 5520; app.server = 1520;
  app.outcome = 'rejected'; app.onFollow = null;
  await app.extendLogin('selected');
  assert.equal(app.sent.length, 1);
  assert.equal(app.extensionState(app.state.logins[0]), 'stopped');
  assert.match(app.document.querySelector('#toast').textContent, /자동 로그인 연장이 되지 않았어요 \(기관 거절\)/);
  app.local = 5590; app.server = 1590;
  await app.extendLogin('selected');
  assert.equal(app.sent.length, 1, 'the same session is never tried again');
});

test('a busy session, a missing extension job or a locked store sends nothing and is not a failure', async t => {
  const busy = await nearLimit(t);
  busy.local = 5000; busy.server = 1000; busy.setAutoExtend(true);
  busy.local = 5520; busy.server = 1520; busy.error = 'resource_busy';
  await busy.extendLogin('selected');
  assert.equal(busy.sent.length, 0);
  assert.equal(busy.extensionState(busy.state.logins[0]), 'on', 'another job using the session is not a failed extension');

  const none = await nearLimit(t);
  none.state.capabilities = {jobs: []};
  none.setAutoExtend(true);
  await none.extendLogin('selected');
  assert.equal(none.submissions, 0);
  assert.equal(none.extensionState(none.state.logins[0]), 'unsupported');

  const locked = await nearLimit(t, {method: 'onesign', credential: {ref: 'store'}});
  locked.local = 5000; locked.server = 1000; locked.setAutoExtend(true);
  locked.local = 5520; locked.server = 1520;
  assert.equal(locked.extensionState(locked.state.logins[0]), 'locked');
  await locked.extendLogin('selected');
  assert.equal(locked.submissions, 0, 'no passphrase is kept in the browser to send');
  locked.state.vaults = {store: true};
  await locked.extendLogin('selected');
  assert.equal(JSON.stringify(locked.sent.map(j => [j.name, j.secrets])), JSON.stringify([['hana.onesign.session.extend', {}]]));

  const expired = await nearLimit(t);
  expired.local = 5000; expired.server = 1000; expired.setAutoExtend(true);
  expired.local = 5600; expired.server = 1600;
  await expired.extendLogin('selected');
  assert.equal(expired.submissions, 0, 'a session past its limit is logged out, not revived');
});

test('idle limits also cover corporate and giro sessions, and never block the login that replaces one', async t => {
  for (const [institution, method, login, query] of [['hana_corporate', 'id_password', 'hana.corporate.login-idpw', 'hana.corporate.accounts'],
    ['giro', 'pin', 'giro.login', 'giro.accounts.list']]) {
    const app = await setup(t);
    Object.assign(app.row, {institution, method, readiness: 'ready'});
    app.state.logins = [structuredClone(app.row)];
    app.local = 5599; app.server = 1599;
    assert.equal(app.bankSessionExpired(app.state.logins[0]), false);
    app.local = 5600; app.server = 1600;
    assert.equal(app.bankSessionExpired(app.state.logins[0]), true);
    await app.ctx.run(login, {login_id: 'selected'});
    assert.deepEqual(app.sent.map(j => j.name), [login], 'a new login is sent even though the old session is past its limit');
    assert.equal(app.asked.length, 0);
    assert.equal(await app.ctx.run(query, {login_id: 'selected'}), null);
    assert.equal(app.sent.length, 1, 'a query on the expired session is not sent');
    assert.equal(app.asked.length, 1);
    assert.equal(app.asked[0].reason, 'session_idle_expired');
  }
});

test('corporate and giro sessions are extended with their own job and need no store passphrase', async t => {
  for (const [change, job] of [[{institution: 'hana_corporate', method: 'onesign', credential: {ref: 'store'}}, 'hana.corporate.session.extend'],
    [{institution: 'giro', method: 'pin'}, 'giro.session.extend']]) {
    const app = await nearLimit(t, change);
    app.state.capabilities = {jobs: [job]};
    app.local = 5000; app.server = 1000;
    app.setAutoExtend(true);
    assert.equal(app.extensionState(app.state.logins[0]), 'on');
    app.local = 5520; app.server = 1520;
    await app.extendLogin('selected');
    assert.equal(JSON.stringify(app.sent.map(j => [j.name, j.login_id, j.secrets])), JSON.stringify([[job, 'selected', undefined]]));
  }
});
