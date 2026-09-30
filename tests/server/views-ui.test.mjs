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
  const target = {id: 'target', login_id: row.id, kind: 'account', display_name: '합성 계좌', identity: {account_number: '12345678901234'}};
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
  test(`${method} security queries use the selected login without an account target`, async t => {
    const ui = await setup(t, method);
    ui.state.targets = [];
    ui.document.querySelector('main').innerHTML = await ui.views.security(ui.ctx);
    assert.doesNotMatch(ui.document.body.textContent, /공동인증서 하나은행 로그인이 없어요/);
    const form = ui.document.querySelector('form');
    assert.equal(form.querySelector('[name="login_id"]').value, 'login');
    assert.equal(form.querySelector('[name="kind"]').options.length, 6);
    assert.equal(ui.calls.length, 0);
    assert.equal(ui.asked.length, 0);
    await ui.actions['security-query'](ui.ctx, form);
    assert.equal(ui.calls[0].name, `hana.${method === 'onesign' ? 'onesign.' : ''}security.query`);
    assert.equal(ui.calls[0].fields.login_id, 'login');
    assert.equal(ui.calls[0].fields.input.kind, 'limits');
    assert.equal(ui.calls[0].fields.target_id, undefined);
    assert.equal(ui.asked.length, method === 'onesign' ? 1 : 0);
    if (method === 'onesign') assert.equal(ui.asked[0][3].store, 'synthetic');
    const button = form.querySelector('[data-action="security-login"]');
    assert.equal(button.type, 'button');
    await ui.actions['security-login'](ui.ctx, button);
    assert.equal(ui.calls[1].name, method === 'onesign' ? 'hana.onesign.login' : 'hana.login');
    assert.equal(ui.calls[1].fields.login_id, 'login');
  });

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

async function showLimits(ui, observation, outcome = 'success') {
  ui.document.querySelector('main').innerHTML = await ui.views.security(ui.ctx);
  await ui.actions['security-query'](ui.ctx, ui.document.querySelector('form'));
  const job = {status: 'finished', outcome, result: {observation}};
  ui.calls.at(-1).options.onDone(job);
  assert.equal(job.outcome, outcome, 'display warnings must not alter the bank verdict');
  return ui.document.querySelector('#results');
}

test('limit results separate bank amounts from medium guidance and remove internal fields', async t => {
  const ui = await setup(t);
  const result = await showLimits(ui, {
    fields: {bot1TrnsLimAmt: '145678901', dd1TrnsLimAmt: 650000001,
      scrtMdclDvCd: '2', mbphOtpYn: 'N', trnsLimRslt: false},
    display: {medium: 'otp', once_ceiling_text: '100,000,000', daily_ceiling_text: '500,000,000', exception_prompt: false},
    rows: [], diagnostics: [],
  });
  const amounts = Array.from(result.querySelector('.limit-grid').querySelectorAll('dd'), el => el.textContent);
  assert.deepEqual(amounts, ['1억 4,567만 8,901 원145,678,901원', '6억 5,000만 1 원650,000,001원']);
  assert.match(result.textContent, /보안매체 · OTP/);
  assert.match(result.querySelector('.limit-reference').textContent, /보안매체별 안내 한도.*1회 이체한도1억 원100,000,000원.*1일 이체한도5억 원500,000,000원/s);
  assert.match(result.textContent, /실제 이체 가능한 금액은 이 조회만으로 확정할 수 없어요/);
  assert.doesNotMatch(result.textContent, /bot1TrnsLimAmt|dd1TrnsLimAmt|scrtMdclDvCd|mbphOtpYn|trnsLimRslt|_ceiling_text|exception_prompt|false|조회 결과가 0건/);
  assert.equal(ui.calls.length, 1, 'a discrepancy must not trigger another request');
});

test('limit display preserves zero and large integers without claiming a missing medium is OTP', async t => {
  const ui = await setup(t);
  const result = await showLimits(ui, {fields: {bot1TrnsLimAmt: 0, dd1TrnsLimAmt: '9007199254740993'},
    display: {medium: 'otp', once_ceiling_text: '100,000,000', daily_ceiling_text: '500,000,000'}}, 'unknown');
  assert.match(result.textContent, /기관의 최종 판정을 확인하지 못했어요/);
  assert.match(result.textContent, /1회 이체한도0원/);
  assert.match(result.textContent, /9,007,199,254,740,993원/);
  assert.match(result.textContent, /보안매체 · 확인 안 됨/);
  assert.equal(result.querySelector('.limit-reference'), null);
  for (const value of [undefined, null, '', false, '12,34', '-1', '1.5', '1e3', 1.5, Number.MAX_SAFE_INTEGER + 1, '<img src=x onerror=alert(1)>']) {
    const node = await showLimits(ui, {fields: {bot1TrnsLimAmt: value, dd1TrnsLimAmt: '0'}});
    assert.equal(node.querySelector('dd').textContent, '확인 안 됨');
    assert.match(node.textContent, /1일 이체한도0원/);
    assert.equal(node.querySelector('img'), null);
    assert.doesNotMatch(node.textContent, /undefined|null|false/);
  }
});

test('limit medium and exception messaging retain the original typed predicates', async t => {
  const ui = await setup(t);
  for (const [fields, label, medium] of [
    [{scrtMdclDvCd: '1', mbphOtpYn: 'Y'}, '보안카드(자물쇠카드)', 'card'],
    [{scrtMdclDvCd: '2', mbphOtpYn: 'Y'}, '모바일 OTP', 'mobile'],
    [{scrtMdclDvCd: '2', mbphOtpYn: 'N'}, 'OTP', 'otp'],
    [{scrtMdclDvCd: 'unexpected', mbphOtpYn: 'N'}, '확인 안 됨', 'otp'],
  ]) {
    const result = await showLimits(ui, {fields: {...fields, bot1TrnsLimAmt: '20,000', dd1TrnsLimAmt: 30000},
      display: {medium, once_ceiling_text: '100,000', daily_ceiling_text: '200,000'}});
    assert.ok(result.textContent.includes('보안매체 · ' + label));
    assert.doesNotMatch(result.textContent, /은행 조회값이 보안매체별 안내 한도보다 커요/);
  }
  for (const flag of ['true', true, false, 'false', undefined]) {
    const result = await showLimits(ui, {fields: {scrtMdclDvCd: '1', trnsLimRslt: flag}});
    assert.equal(result.textContent.includes('예외신청이 완료되었다는 뜻은 아니에요'), flag === 'true');
  }
});

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
  for (const view of ['history', 'inquiry', 'transfer', 'security']) {
    ui.document.querySelector('main').innerHTML = await ui.views[view](ui.ctx);
    await ui.actions[view === 'transfer' ? 'transfer-prepare' : `${view}-query`](ui.ctx, ui.document.querySelector('form'));
  }
  assert.deepEqual(ui.checked, ['login', 'login', 'login', 'login', 'login']);
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
