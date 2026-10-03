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
    follow: async () => ({...data.sent.at(-1), status: 'finished', outcome: 'success',
      local: data.stopped ? {stopped: data.stopped} : {}}),
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
