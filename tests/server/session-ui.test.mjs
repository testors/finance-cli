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
      if (data.job && path === '/jobs/' + data.job.id) return structuredClone(data.job);
      data.gets.push(path);
      assert.equal(path, '/logins');
      return {logins: [structuredClone(data.row)], server_time: data.server};
    }},
    submit: async (name, fields, options) => {
      data.submissions++;
      data.options = options;
      data.onSubmit?.();
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
    this.setExport('actions', {capture: ctx => { data.ctx = ctx; }, broken: async () => { throw data.thrown; },
      login: async (ctx, button) => { data.asked.push(button.dataset); }});
  }, {context});
  const ui = new SourceTextModule(await readFile(new URL('ui.js', root), 'utf8'), {context});
  const busy = new SourceTextModule(await readFile(new URL('busy.js', root), 'utf8'), {context});
  const app = new SourceTextModule(await readFile(new URL('app.js', root), 'utf8'), {context});
  await app.link(name => ({'./api.js': api, './views.js': views, './ui.js': ui, './busy.js': busy}[name]));
  await app.evaluate();
  Object.assign(app.namespace.state, {logins: [structuredClone(data.row)], sessionClock: {server: 1000, local: 5000}});
  dom.window.document.querySelector('[data-action="capture"]').click();
  return Object.assign(data, app.namespace, {document: dom.window.document, busy: busy.namespace});
}

test('600-second boundary uses server time despite browser clock offset', async t => {
  const app = await setup(t);
  app.local = 5599;
  assert.equal(app.bankSessionExpired(app.row), false);
  app.local = 5600;
  assert.equal(app.bankSessionExpired(app.row), true);
  assert.equal(app.bankSessionExpired({...app.row, institution: 'hometax'}), true);
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
  for (const [institution, name] of [['hana', 'hana.onesign.accounts'], ['hometax', 'hometax.tax.dues']]) {
    for (const where of ['submit', 'worker']) {
      const app = await setup(t);
      app.row.institution = institution;
      app.state.logins = [structuredClone(app.row)];
      if (where === 'submit') app.error = 'session_idle_expired';
      else app.stopped = 'session_idle_expired';
      let completed = 0;
      assert.equal(await app.ctx.run(name, {login_id: 'selected'}, {onDone: () => completed++}), null);
      assert.equal(app.asked.length, 1);
      assert.equal(app.sent.length, where === 'submit' ? 0 : 1);
      assert.equal(completed, 0);
    }
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

const SHELL = '<nav class="area-tabs"></nav><div class="workspace-label"></div><nav class="main-nav"></nav><nav class="common-nav"></nav>'
  + '<nav class="bottom-nav"></nav><button class="profile-switch"></button><span id="server-mode"></span><footer id="footer"></footer>';

test('an action that redraws its own screen stays current for its next step; a screen the user left is not revived', async t => {
  const app = await setup(t);
  app.document.querySelector('#stage').innerHTML = SHELL;
  const ctx = app.ctx;
  let reached = 0;
  const step = () => ctx.run('hana.onesign.accounts', {login_id: 'selected'}, {onDone: () => reached++});
  await app.render(ctx);
  assert.equal(ctx.current(), true);
  await step();
  assert.equal(reached, 1, 'a step chained after the redraw, such as the balance query after a login, reaches the screen');
  await app.render();
  assert.equal(ctx.current(), false, 'a redraw that is not its own, such as a screen change, ends it');
  await app.render(ctx);
  assert.equal(ctx.current(), false);
  await step();
  assert.equal(reached, 1, 'a late answer for the screen that was left is dropped');
});

test('a prepared transfer left for later is offered again only on the login session it was prepared in', async t => {
  const app = await setup(t);
  const dialog = app.document.querySelector('#detail-dialog');
  dialog.innerHTML = '<div id="dialog-content"></div>';
  dialog.showModal = () => { dialog.open = true; };
  app.job = {id: 'job', name: 'hana.transfer.prepare', title: '원화 이체', origin: 'web', status: 'awaiting_input', step: 'prepare',
    outcome: 'not_started', login_id: 'selected', session_id: 's', attempt: {sent: true}};
  const offered = async () => { await app.showJob('job'); return Boolean(dialog.querySelector('[data-action="transfer-open"]')); };
  assert.equal(await offered(), true);
  app.job.session_id = 'older';
  assert.equal(await offered(), false, 'a newer login took the session it was prepared in');
  Object.assign(app.job, {session_id: 's', status: 'finished', step: 'execute'});
  assert.equal(await offered(), false);
  assert.ok(dialog.querySelector('[data-action="reconcile"]'), 'an executed transfer offers its result lookup instead');
  assert.equal(app.gets.length, 0);
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
  app.state.logins = [{...app.row, readiness: 'ready'}, {...app.row, id: 'tax', institution: 'hometax', readiness: 'ready'}];
  app.local = 5000;
  app.renderTabs();
  assert.equal(app.document.querySelector('[data-mode="banking"] .tab-countdown').textContent, '10:00');
  assert.equal(app.document.querySelector('[data-mode="tax"] .tab-countdown').textContent, '10:00');
  app.local = 5535;
  app.renderTabs();
  const soon = app.document.querySelector('[data-mode="banking"] .tab-countdown');
  assert.equal(soon.textContent, '1:05');
  assert.ok(soon.classList.contains('soon'));
  assert.equal(app.document.querySelector('[data-mode="tax"] .tab-countdown').textContent, '1:05');
  app.local = 5600;
  app.renderTabs();
  assert.equal(app.document.querySelector('.tab-countdown'), null, 'a session past its limit is logged out');
  assert.equal(app.document.querySelector('[data-mode="tax"]').classList.contains('live'), false);
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
  assert.equal(app.options.hold, false, 'nobody asked for it at the screen, so it does not hold the screen');
  assert.equal(app.busy.blocking(), false);
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

test('idle limits cover corporate, giro and hometax sessions, and allow a replacement login', async t => {
  for (const [institution, method, login, query] of [['hana_corporate', 'id_password', 'hana.corporate.login-idpw', 'hana.corporate.accounts'],
    ['giro', 'pin', 'giro.login', 'giro.accounts.list'],
    ['hometax', 'joint_certificate', 'hometax.login', 'hometax.tax.dues']]) {
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

test('hometax activity refreshes the countdown and a session refresh is never the automatic extension', async t => {
  const app = await nearLimit(t, {institution: 'hometax'});
  app.state.capabilities.jobs.push('hometax.session.refresh');
  app.setAutoExtend(true);
  assert.equal(app.extensionState(app.state.logins[0]), 'unsupported', 'only the extension job extends');
  await app.extendLogin('selected');
  assert.equal(app.submissions, 0);
  await app.ctx.run('hometax.tax.dues', {login_id: 'selected'});
  assert.equal(app.state.logins[0].session.idle_expires_at, 2120);
  app.local = 6120; app.server = 2120;
  await app.ctx.run('hometax.report.resave', {login_id: 'selected'});
  assert.equal(app.sent.length, 2, 'a saved report can be used without the current login session');
  assert.equal(app.asked.length, 0);
});

test('corporate, giro and hometax sessions are extended with their own job and need no store passphrase', async t => {
  for (const [change, job] of [[{institution: 'hana_corporate', method: 'onesign', credential: {ref: 'store'}}, 'hana.corporate.session.extend'],
    [{institution: 'giro', method: 'pin'}, 'giro.session.extend'],
    [{institution: 'hometax', method: 'joint_certificate'}, 'hometax.session.extend']]) {
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

test('a job holds the screen from the press to its result and opens it before what follows', async t => {
  const app = await setup(t);
  app.state.capabilities = {features: [{jobs: [{name: 'hana.onesign.accounts', title: '하나은행 계좌 목록·잔액'}]}]};
  const text = selector => app.document.querySelector(selector).textContent;
  const seen = [];
  app.onSubmit = () => seen.push(['접수 전', app.busy.blocking(), text('#busy-title'), text('#busy-status')]);
  app.onFollow = () => seen.push(['실행 중', app.busy.blocking(), text('#busy-title')]);
  const final = await app.ctx.run('hana.onesign.accounts', {login_id: 'selected'}, {
    onDone: () => seen.push(['결과 처리', app.busy.blocking()])});
  assert.equal(final.outcome, 'success');
  assert.deepEqual(seen, [['접수 전', true, '하나은행 계좌 목록·잔액', '접수 중'], ['실행 중', true, '하나은행 계좌 목록·잔액'],
    ['결과 처리', false]]);
  assert.equal(app.options, undefined, 'a job asked for at the screen is sent with the default hold');
  await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(app.document.querySelector('#busy').hasAttribute('open'), false);
});

test('a refused submission opens the screen again and says why', async t => {
  const app = await setup(t);
  app.error = 'resource_busy';
  assert.equal(await app.ctx.run('hana.onesign.accounts', {login_id: 'selected'}), null);
  assert.equal(app.busy.blocking(), false);
  assert.match(app.document.querySelector('#toast').textContent, /다른 작업이 실행 중이에요/);
});

test('a job a screen finds running is followed without holding; one the user just confirmed holds', async t => {
  const app = await setup(t);
  const job = {id: 'job', name: 'hana.transfer.prepare', title: '원화 이체', status: 'queued'};
  app.sent.push(job);
  const seen = [];
  app.onFollow = () => seen.push(app.busy.blocking());
  await app.ctx.track(job, {});
  await app.ctx.track(job, {hold: true});
  assert.deepEqual(seen, [false, true]);
  assert.equal(app.busy.blocking(), false);
});

test('the result of a job whose screen was left meanwhile is still said', async t => {
  const app = await setup(t);
  let done = 0;
  app.onFollow = () => { app.state.token += 1; };   // the screen was redrawn or left while the job ran
  app.sent.push({id: 'job', name: 'hana.onesign.accounts', title: '하나은행 계좌 목록·잔액'});
  await app.ctx.run('hana.onesign.accounts', {login_id: 'selected'}, {onDone: () => done++});
  assert.equal(done, 0);
  assert.equal(app.document.querySelector('#toast').textContent, 'hana.onesign.accounts: 성공');
  assert.equal(app.busy.blocking(), false);
});

test('an error an action did not handle itself is said on the screen, and its button works again', async t => {
  const app = await setup(t);
  app.document.querySelector('#main').insertAdjacentHTML('beforeend', '<button data-action="broken">고장</button>');
  const button = app.document.querySelector('[data-action="broken"]');
  for (const [thrown, message] of [[{code: 'job_not_found'}, /job_not_found/], [new TypeError('synthetic'), /화면에서 처리하지 못했어요/]]) {
    app.thrown = thrown;
    button.click();
    assert.equal(button.disabled, true);
    await new Promise(resolve => setTimeout(resolve, 5));
    assert.match(app.document.querySelector('#toast').textContent, message);
    assert.match(app.document.querySelector('#main [role="alert"]').textContent, message);
    assert.equal(button.disabled, false);
  }
});

test('a hometax extension without a verdict stops for the session its command saved under a new id', async t => {
  const app = await nearLimit(t, {institution: 'hometax'});
  app.state.capabilities = {jobs: ['hometax.session.extend']};
  app.local = 5000; app.server = 1000;
  app.setAutoExtend(true);
  app.local = 5520; app.server = 1520;
  app.outcome = 'unknown';
  // The check was sent: its reservation moved the limit and its output became the current session.
  app.onFollow = () => Object.assign(app.row, {current_session_id: 'saved', session: {last_request_at: 1520, idle_expires_at: 3310}});
  await app.extendLogin('selected');
  assert.deepEqual(app.sent.map(j => j.name), ['hometax.session.extend']);
  assert.equal(app.state.logins[0].current_session_id, 'saved');
  assert.equal(app.extensionState(app.state.logins[0]), 'stopped');
  assert.match(app.document.querySelector('#toast').textContent, /자동 로그인 연장이 되지 않았어요 \(결과 미확인\)/);
  app.local = 7230; app.server = 3230;
  await app.extendLogin('selected');
  assert.equal(app.sent.length, 1, 'the saved session is not checked again near its own limit');
});

test('a work screen of an area with a live login offers a new login beside its heading, in one place', async t => {
  const app = await setup(t);
  const main = app.document.querySelector('#main');
  const rows = [{id: 'bank', institution: 'hana', readiness: 'ready', display_name: '합성 은행'},
    {id: 'bank2', institution: 'hana', readiness: 'login_required', display_name: '합성 둘째'},
    {id: 'giro', institution: 'giro', readiness: 'login_required', display_name: '합성 지로'}];
  const draw = (view, mode, logins = rows) => {
    Object.assign(app.state, {view, mode, logins: structuredClone(logins)});
    main.innerHTML = '<div class="page-heading"><h1>합성 화면</h1><div class="heading-actions"><button data-own>화면 버튼</button></div></div>';
    app.renderLoginNotice();
    return [...main.querySelectorAll('.heading-actions .session-actions [data-action="login"]')].map(b => [b.dataset.login, b.textContent]);
  };
  for (const view of ['accounts', 'history', 'inquiry', 'transfer', 'security'])
    assert.deepEqual(draw(view, 'banking'), [['bank', '다시 로그인']], view);
  assert.equal(main.querySelector('.login-notice'), null, 'a live login: no notice asks for one');
  assert.ok(main.querySelector('[data-own]'), 'the actions of the screen itself stay');
  // Several live logins are named, as the notice names several logged-out ones.
  assert.deepEqual(draw('accounts', 'banking', [rows[0], {...rows[1], readiness: 'query_only'}]),
    [['bank', '합성 은행 다시 로그인'], ['bank2', '합성 둘째 다시 로그인']]);
  // A logged-out area asks in its notice instead; a shared screen or one that needs no session offers neither.
  assert.deepEqual(draw('giro-live', 'giro'), []);
  assert.ok(main.querySelector('.login-notice [data-action="login"]'));
  assert.deepEqual(draw('settings', 'banking'), []);
  assert.deepEqual(draw('girostatus', 'giro', [{...rows[2], readiness: 'ready'}]), []);
  // Drawn again, it is replaced rather than added to.
  draw('accounts', 'banking'); app.renderLoginNotice();
  assert.equal(main.querySelectorAll('.session-actions').length, 1);
  main.querySelector('.session-actions button').click();
  await new Promise(resolve => setTimeout(resolve));
  assert.equal(app.asked.at(-1).login, 'bank');
  assert.equal(app.gets.length, 0, 'showing or pressing it asks the server for nothing by itself');
});

test('a tab loaded from an older copy of the app says so and leaves the reload to the person', async t => {
  const app = await setup(t);
  const main = app.document.querySelector('#main');
  Object.assign(app.state, {view: 'settings', mode: 'banking'});
  main.innerHTML = '<div class="page-heading"><h1>합성 화면</h1></div><form><input name="typed"></form>';
  main.querySelector('input').value = '합성 입력';
  app.renderLoginNotice();
  assert.equal(main.querySelector('.login-notice'), null);
  app.outdated();
  const notice = main.querySelector('.login-notice.outdated');
  assert.match(notice.textContent, /새 버전이 배포됐어요/);
  assert.equal(notice.previousElementSibling.className, 'page-heading');
  assert.equal(notice.querySelector('button').dataset.ui, 'reload');
  assert.equal(main.querySelector('input').value, '합성 입력', 'what was being typed is left alone');
  // It stays through later redraws of the notices, once.
  app.renderLoginNotice();
  assert.equal(main.querySelectorAll('.login-notice.outdated').length, 1);
  assert.equal(app.sent.length, 0);
});
