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
  const row = {id: 'login', institution: 'hana', method, readiness, display_name: '합성 연결',
    credential: {ref: 'synthetic'}, current_session_id: 'session', session: {state: 'consumed'}};
  const target = {id: 'target', login_id: row.id, kind: 'account', display_name: '합성 계좌', identity: {account_number: '••••1234'}};
  const state = {logins: [row], targets: [target], cache: new Map(), rows: {}, capabilities: {features: []},
    vaults: {synthetic: true}, credentials: [], profiles: []};
  const calls = [], asked = [];
  const ctx = {run: async (name, fields, options) => { calls.push({name, fields, options}); }};
  const values = {
    state, login: () => row, target: () => target, profile: () => null,
    scopeLogins: () => state.logins, scopeTargets: () => state.targets,
    onesignStore: owner => owner.credential.ref,
    askSecrets: async (...args) => { asked.push(args); return secret; },
    SECRET_LABELS: {vault_passphrase: ['vault_passphrase', '저장소 암호']},
    applyRemember: () => {}, changeView: () => {}, jobState: () => '', refreshModel: async () => {},
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
  return {ctx, state, calls, asked, row, document: dom.window.document, ...views.namespace};
}

for (const method of ['onesign', 'joint_certificate']) {
  test(`${method} accounts can be selected in both history screens`, async t => {
    const ui = await setup(t, method);
    for (const view of ['history', 'inquiry']) {
      ui.document.querySelector('main').innerHTML = await ui.views[view](ui.ctx);
      assert.equal(ui.document.querySelector('[name="target_id"]').value, 'target');
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

test('after transfer, accounts and settings offer queries without a login prompt', async t => {
  const ui = await setup(t);
  for (const view of ['accounts', 'settings']) {
    ui.document.querySelector('main').innerHTML = await ui.views[view](ui.ctx);
    assert.match(ui.document.body.textContent, /조회 가능/);
    assert.equal(ui.document.querySelector('[data-action="login"]'), null);
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
