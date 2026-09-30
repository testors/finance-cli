import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule, SyntheticModule} from 'node:vm';
import {JSDOM} from 'jsdom';

const root = new URL('../../src/finance_cli/server/static/', import.meta.url);

async function setup(t, method = 'onesign', readiness = 'query_only', secret = {}) {
  const dom = new JSDOM('<main></main><div id="results"></div><dialog id="detail-dialog"><div id="dialog-content"></div></dialog><div id="toast"></div>',
    {url: 'http://127.0.0.1:8740', runScripts: 'outside-only'});
  t.after(() => dom.window.close());
  dom.window.HTMLDialogElement.prototype.close = function () { this.open = false; };
  const context = dom.getInternalVMContext();
  context.Date.now = () => Date.parse('2026-09-30T16:00:00Z');
  const row = {id: 'login', institution: 'hana', method, readiness, display_name: '합성 연결',
    credential: {ref: 'synthetic'}, current_session_id: 'session', session: {state: 'consumed'}};
  const target = {id: 'target', login_id: row.id, kind: 'account', display_name: '합성 계좌', identity: {account_number: '••••1234'}};
  const state = {logins: [row], targets: [target], cache: new Map(), rows: {}, capabilities: {features: []},
    vaults: {synthetic: true}, credentials: [], profiles: []};
  const calls = [], asked = [], checked = [];
  const ctx = {run: async (name, fields, options) => { calls.push({name, fields, options}); }};
  const values = {
    state, login: id => state.logins.find(r => r.id === id), target: id => state.targets.find(r => r.id === id), profile: () => null,
    scopeLogins: () => state.logins, scopeTargets: () => state.targets,
    onesignStore: owner => owner.credential.ref,
    askSecrets: async (...args) => { asked.push(args); return secret; },
    SECRET_LABELS: {vault_passphrase: ['vault_passphrase', '저장소 암호'], pin: ['pin', 'PIN'],
      certificate_password: ['certificate_password', '인증서 비밀번호']},
    applyRemember: () => {}, changeView: () => {}, jobState: () => '', refreshModel: async () => {},
    bankSessionExpired: () => state.idleExpired || false,
    ensureBankSession: async (ctx, id) => { checked.push(id); return !state.idleExpired; }, expiredBankLogin: async () => {},
    rememberField: () => '', render: () => {}, secretFields: () => [], showJob: () => {},
  };
  const app = new SyntheticModule(Object.keys(values), function () {
    for (const [k, v] of Object.entries(values)) this.setExport(k, v);
  }, {context});
  const api = new SyntheticModule(['api', 'submit'], function () {
    this.setExport('api', {get: async path => {
      if (path.startsWith('/jobs?')) return {jobs: []};
      return {credentials: [], devices: [], id_cards: []};
    }});
    this.setExport('submit', () => { throw new Error('unexpected submission'); });
  }, {context});
  const certificates = new SyntheticModule(['certificateActions'], function () {
    this.setExport('certificateActions', {});
  }, {context});
  const ui = new SourceTextModule(await readFile(new URL('ui.js', root), 'utf8'), {context});
  const views = new SourceTextModule(await readFile(new URL('views.js', root), 'utf8'), {context});
  await views.link(name => ({'./app.js': app, './api.js': api, './ui.js': ui, './certificates.js': certificates}[name]));
  await views.evaluate();
  return {ctx, state, calls, asked, checked, row, document: dom.window.document, ...views.namespace};
}

for (const method of ['onesign', 'joint_certificate']) {
  test(`${method} accounts can be selected in both history screens`, async t => {
    const ui = await setup(t, method);
    for (const view of ['history', 'inquiry']) {
      ui.document.querySelector('main').innerHTML = await ui.views[view](ui.ctx);
      assert.equal(ui.document.querySelector('[name="target_id"]').value, 'target');
      assert.equal(ui.document.querySelector('[name="end_date"]').value, '2026-10-01');
      assert.equal(ui.document.querySelector('[name="start_date"]').value, view === 'history' ? '2026-09-25' : '2026-09-01');
      assert.doesNotMatch(ui.document.body.textContent, /공동인증서 로그인으로 조회한 계좌 대상이 없어요/);
    }
    assert.equal(ui.calls.length, 0);
  });

  test(`${method} history and follow-ups use their login method without logging in`, async t => {
    const ui = await setup(t, method);
    for (const view of ['history', 'inquiry']) {
      ui.document.querySelector('main').innerHTML = await ui.views[view](ui.ctx);
      await ui.actions[`${view}-query`](ui.ctx, ui.document.querySelector('form'));
      ui.state.rows[view] = {job: {id: 'parent', login_id: 'login', target_id: 'target'}, pages: ['parent'], rows: []};
    }
    const button = {dataset: {job: 'parent', index: '0'}};
    for (const action of ['history-more', 'history-detail', 'history-export', 'inquiry-detail']) {
      await ui.actions[action](ui.ctx, button);
    }
    assert.deepEqual(ui.calls.map(c => c.name), ['history.list', 'inquiry.history', 'history.more', 'history.detail',
      'history.export', 'inquiry.detail'].map(n => `hana.${method === 'onesign' ? 'onesign.' : ''}${n}`));
    assert.equal(ui.asked.length, method === 'onesign' ? 6 : 0);
    for (const call of ui.calls) {
      assert.equal(call.fields.login_id, 'login');
      assert.equal(call.fields.target_id, 'target');
      assert.deepEqual(Object.keys(call.options.secrets), []);
    }
    for (const question of ui.asked) {
      assert.equal(question[3].store, 'synthetic');
      assert.deepEqual(Array.from(question[1], f => f[0]), ['vault_passphrase']);
    }
  });
}

test('after transfer, accounts and settings offer queries and optional manual login', async t => {
  const ui = await setup(t);
  for (const view of ['accounts', 'settings']) {
    ui.document.querySelector('main').innerHTML = await ui.views[view](ui.ctx);
    assert.match(ui.document.body.textContent, /조회용 세션 있음/);
    assert.equal(ui.document.querySelector('[data-action="login"]').textContent, '다시 로그인');
    assert.ok(ui.document.querySelector('[data-action="accounts-query"]'));
  }
  ui.document.querySelector('main').innerHTML = await ui.views.transfer(ui.ctx);
  assert.match(ui.document.body.textContent, /다음 이체.*새 로그인/);
  await ui.actions['transfer-prepare'](ui.ctx, ui.document.querySelector('form'));
  assert.equal(ui.calls.length, 0);
  assert.equal(ui.asked.length, 0);
});

test('expired login still asks for login in accounts', async t => {
  const ui = await setup(t, 'onesign', 'login_required');
  ui.document.querySelector('main').innerHTML = await ui.views.accounts(ui.ctx);
  assert.ok(ui.document.querySelector('[data-action="login"]'));
  assert.equal(ui.document.querySelector('[data-action="accounts-query"]'), null);
});

test('cancelling the store password sends no query', async t => {
  const ui = await setup(t, 'onesign', 'query_only', null);
  ui.document.querySelector('main').innerHTML = await ui.views.history(ui.ctx);
  await ui.actions['history-query'](ui.ctx, ui.document.querySelector('form'));
  assert.equal(ui.calls.length, 0);
});

test('idle accounts, history and transfers check expiry before requesting secrets', async t => {
  const ui = await setup(t, 'onesign', 'ready');
  ui.state.idleExpired = true;
  await ui.actions['accounts-query'](ui.ctx, {dataset: {login: 'login'}});
  for (const view of ['history', 'inquiry', 'transfer']) {
    ui.document.querySelector('main').innerHTML = await ui.views[view](ui.ctx);
    await ui.actions[view === 'transfer' ? 'transfer-prepare' : `${view}-query`](ui.ctx, ui.document.querySelector('form'));
  }
  assert.deepEqual(ui.checked, ['login', 'login', 'login', 'login']);
  assert.equal(ui.asked.length, 0);
  assert.equal(ui.calls.length, 0);
  ui.document.querySelector('main').innerHTML = await ui.views.accounts(ui.ctx);
  assert.match(ui.document.body.textContent, /세션 만료 · 다시 로그인/);
});


test('ready sessions keep a visible login action without requesting credentials on render', async t => {
  const ui = await setup(t, 'onesign', 'ready', {pin: '123456'});
  for (const view of ['accounts', 'settings']) {
    ui.document.querySelector('main').innerHTML = await ui.views[view](ui.ctx);
    assert.equal(ui.document.querySelector('[data-action="login"]').textContent, '다시 로그인');
    assert.ok(ui.document.querySelector('[data-action="accounts-query"]'));
  }
  assert.equal(ui.asked.length, 0);
  assert.equal(ui.calls.length, 0);
  await ui.actions.login(ui.ctx, ui.document.querySelector('[data-action="login"]'));
  assert.deepEqual(ui.calls.map(c => c.name), ['hana.onesign.login']);
  assert.equal(ui.calls[0].fields.login_id, 'login');
  assert.deepEqual(ui.calls[0].options.secrets, {pin: '123456'});
  assert.equal(ui.asked[0][3].store, 'synthetic');
  await ui.calls[0].options.onDone({outcome: 'success'});
  assert.equal(ui.calls.length, 1, 'successful re-login must not retry the earlier query');
});

test('a rejected account query leaves manual re-login available without assuming expiry', async t => {
  const ui = await setup(t);
  ui.state.cache.set('hana.onesign.accounts|login||', {id: 'failed', status: 'finished', outcome: 'rejected',
    session_id: 'session', result: {accounts: []}, service_verdict: {accepted: false}, local: {}});
  ui.document.querySelector('main').innerHTML = await ui.views.accounts(ui.ctx);
  assert.match(ui.document.body.textContent, /기관이 실패로 판정/);
  assert.equal(ui.document.querySelector('[data-action="login"]').textContent, '다시 로그인');
  assert.ok(ui.document.querySelector('[data-action="accounts-query"]'));
  assert.equal(ui.row.readiness, 'query_only');
  assert.equal(ui.calls.length, 0);
});

test('banking screens re-login to the selected account, without running a query or transfer', async t => {
  const ui = await setup(t, 'onesign', 'ready', {pin: '123456'});
  ui.state.logins.push({...ui.row, id: 'other-login', credential: {ref: 'other-store'}});
  ui.state.targets.push({...ui.state.targets[0], id: 'other-target', login_id: 'other-login'});
  for (const view of ['history', 'inquiry', 'transfer']) {
    ui.document.querySelector('main').innerHTML = await ui.views[view](ui.ctx);
    ui.document.querySelector('[name="target_id"]').value = 'other-target';
    const button = ui.document.querySelector('[data-action="account-login"]');
    assert.equal(button.type, 'button', 're-login must not submit the banking form');
    await ui.actions['account-login'](ui.ctx, button);
    assert.equal(ui.calls.at(-1).name, 'hana.onesign.login');
    assert.equal(ui.calls.at(-1).fields.login_id, 'other-login');
    assert.equal(ui.asked.at(-1)[3].store, 'other-store');
  }
  assert.equal(ui.calls.length, 3);
});

test('new and disabled logins show appropriate actions', async t => {
  const ui = await setup(t, 'onesign', 'login_required');
  ui.row.current_session_id = null;
  ui.document.querySelector('main').innerHTML = await ui.views.accounts(ui.ctx);
  assert.equal(ui.document.querySelector('[data-action="login"]').textContent, '로그인');
  ui.row.disabled = true;
  for (const view of ['accounts', 'settings']) {
    ui.document.querySelector('main').innerHTML = await ui.views[view](ui.ctx);
    assert.equal(ui.document.querySelector('[data-action="login"]'), null);
  }
});
