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
  dom.window.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  const context = dom.getInternalVMContext();
  context.Date.now = () => Date.parse('2026-09-30T16:00:00Z');
  const row = {id: 'login', institution: 'hana', method, readiness, display_name: '합성 연결',
    credential: {ref: 'synthetic'}, current_session_id: 'session', session: {state: 'consumed'}};
  const target = {id: 'target', login_id: row.id, kind: 'account', display_name: '합성 계좌', identity: {account_number: '12345678901234'}};
  const state = {logins: [row], targets: [target], cache: new Map(), rows: {}, capabilities: {features: []},
    vaults: {synthetic: true}, credentials: [], profiles: []};
  const calls = [], asked = [], checked = [], apiCalls = [];
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
      apiCalls.push(path);
      if (state.failJobList && path.startsWith('/jobs?')) throw new Error('synthetic list error');
      if (path.startsWith('/jobs?')) return {jobs: []};
      return {credentials: [], devices: [], id_cards: []};
    }});
    this.setExport('submit', () => { throw new Error('unexpected submission'); });
  }, {context});
  const certificates = new SyntheticModule(['certificateActions'], function () {
    this.setExport('certificateActions', {});
  }, {context});
  const ui = new SourceTextModule(await readFile(new URL('ui.js', root), 'utf8'), {context});
  const corporate = new SourceTextModule(await readFile(new URL('corporate.js', root), 'utf8'), {context});
  const giro = new SourceTextModule(await readFile(new URL('giro.js', root), 'utf8'), {context});
  const views = new SourceTextModule(await readFile(new URL('views.js', root), 'utf8'), {context});
  await views.link(name => ({'./app.js': app, './api.js': api, './ui.js': ui, './corporate.js': corporate, './giro.js': giro, './certificates.js': certificates}[name]));
  await views.evaluate();
  return {ctx, state, calls, asked, checked, apiCalls, row, document: dom.window.document, ...views.namespace};
}

test('a completed tax query stays current when returning to its screen', async t => {
  const ui = await setup(t, 'joint_certificate', 'ready');
  ui.row.institution = 'hometax'; ui.state.targets[0].kind = 'personal';
  const old = {id: 'old', name: 'hometax.tax.dues', login_id: 'login', target_id: 'target',
    status: 'finished', outcome: 'success', result: {items: [{itrfNm: '이전 합성 세목', romAmt: 1}],
      item_count: 1, pagination: {complete: true}}};
  const fresh = {...old, id: 'fresh', result: {...old.result, items: [{itrfNm: '새 합성 세목', romAmt: 2}]}};
  ui.state.cache.set('hometax.tax.dues||target|', old);
  ui.state.cache.set('hometax.tax.dues||another-target|', old);
  const main = ui.document.querySelector('main');
  main.innerHTML = await ui.views.dues(ui.ctx);
  let submissions = 0;
  ui.ctx.run = async (name, fields, options) => {
    submissions++;
    ui.state.cache.set(options.key, fresh);
    await options.onDone(fresh);
    return fresh;
  };
  await ui.actions['tax-query'](ui.ctx, main.querySelector('form'));
  assert.match(main.textContent, /새 합성 세목/);
  main.innerHTML = await ui.views.dues(ui.ctx);
  assert.match(main.textContent, /새 합성 세목/);
  assert.doesNotMatch(main.textContent, /이전 합성 세목/);
  assert.equal(ui.state.cache.get('hometax.tax.dues||another-target|'), old);
  assert.equal(submissions, 1);
  assert.equal(ui.apiCalls.length, 0, 'Navigation reuses the completed job without replaying a query');
});

test('summary and account screens share concurrent job-list reads, with no lasting list cache', async t => {
  const tax = await setup(t, 'joint_certificate', 'ready');
  tax.row.institution = 'hometax'; tax.state.targets[0].kind = 'personal';
  await tax.views.taxhome(tax.ctx);
  assert.deepEqual(tax.apiCalls, ['/jobs?limit=200']);
  await tax.views.taxhome(tax.ctx);
  assert.deepEqual(tax.apiCalls, ['/jobs?limit=200', '/jobs?limit=200']);
  const bank = await setup(t, 'onesign', 'ready');
  bank.state.logins = Array.from({length: 3}, (_, i) => ({...bank.row, id: 'synthetic-' + i}));
  await bank.views.accounts(bank.ctx);
  assert.deepEqual(bank.apiCalls, ['/jobs?limit=200']);
  assert.equal(bank.calls.length, 0);
});

test('a failed shared list read does not prevent the next explicit screen load', async t => {
  const ui = await setup(t, 'joint_certificate', 'ready');
  ui.row.institution = 'hometax'; ui.state.targets[0].kind = 'personal';
  ui.state.failJobList = true;
  await assert.rejects(ui.views.taxhome(ui.ctx), /synthetic list error/);
  assert.equal(ui.apiCalls.length, 1);
  ui.state.failJobList = false;
  await ui.views.taxhome(ui.ctx);
  assert.equal(ui.apiCalls.length, 2);
  assert.equal(ui.calls.length, 0);
});

test('Hometax connection shows missing runtime before asking for a password', async t => {
  const ui = await setup(t, 'joint_certificate', 'login_required');
  ui.row.institution = 'hometax';
  ui.state.targets = [];
  ui.state.capabilities.features = [{id: 'hometax-login', status: 'setup_required',
    reasons: ['hometax_runtime_not_installed']}];
  ui.document.querySelector('main').innerHTML = await ui.views.settings(ui.ctx);
  assert.match(ui.document.querySelector('.connection-card').textContent, /홈택스 실행 환경 미설치/);
  assert.match(ui.document.querySelector('.connection-card').textContent, /fin runtime install hometax/);
  assert.equal(ui.calls.length, 0);
  assert.equal(ui.asked.length, 0);
});

const syntheticDue = {authCommonNm: null, chrgNm: null, applcEndDt: null, adtTxamt: null,
  itrfNm: '합성 세목', pmtDdt: '20261025', romAmt: 123456, nromAmt: 900000, pmtAmt: 700000,
  txhfOgzNm: '합성 세무서', txtnClNm: '합성 과세구분', bankElctPmtPblNo: 'synthetic-payment'};

async function showDues(t, items, {outcome = 'success', complete = true, itemCount} = {}) {
  const ui = await setup(t, 'joint_certificate', 'ready');
  ui.row.institution = 'hometax';
  ui.state.targets[0].kind = 'personal';
  const job = {id: 'dues-job', name: 'hometax.tax.dues', status: 'finished', outcome,
    login_id: 'login', target_id: 'target', result: {items, item_count: itemCount, pagination: {complete}}};
  ui.state.cache.set('hometax.tax.dues||target|', job);
  ui.document.querySelector('main').innerHTML = await ui.views.dues(ui.ctx);
  return ui;
}

test('dues uses labeled tax, deadline and amount fields even when the first fields are empty', async t => {
  const ui = await showDues(t, [syntheticDue]);
  const table = ui.document.querySelector('#results table');
  assert.deepEqual([...table.querySelectorAll('th')].map(n => n.textContent), ['세목', '납부기한', '납부할 세액', '관서명']);
  assert.deepEqual([...table.querySelectorAll('td')].map(n => n.textContent), ['합성 세목', '2026-10-25', '123,456원', '합성 세무서']);
  assert.equal(ui.document.querySelector('#results .list-footer').textContent, '홈택스 조회 결과 1건 · 조회 완료');
  assert.doesNotMatch(ui.document.querySelector('#results').textContent, /authCommonNm|chrgNm|applcEndDt|adtTxamt|900,000|700,000/);
  await ui.actions.row(ui.ctx, table.querySelector('tbody tr'));
  const detail = ui.document.querySelector('#dialog-content').textContent;
  assert.match(detail, /납부할 세액 상세/);
  assert.match(detail, /과세구분합성 과세구분/);
  assert.match(detail, /전자납부번호synthetic-payment/);
  assert.doesNotMatch(detail, /authCommonNm|itrfNm|romAmt|null/);
  assert.equal(ui.calls.length, 0);
  assert.equal(ui.asked.length, 0);
});

test('dues retains zero, exact numeric strings and missing values without blank rows', async t => {
  const ui = await showDues(t, [
    {...syntheticDue, romAmt: 0}, {...syntheticDue, romAmt: '9007199254740993'},
    {itrfNm: '<img src=x>', pmtDdt: null, romAmt: null, nromAmt: 80000},
  ]);
  const rows = [...ui.document.querySelectorAll('#results tbody tr')];
  assert.equal(rows[0].querySelectorAll('td')[2].textContent, '0원');
  assert.equal(rows[1].querySelectorAll('td')[2].textContent, '9,007,199,254,740,993원');
  assert.deepEqual([...rows[2].querySelectorAll('td')].map(n => n.textContent), ['<img src=x>', '확인 안 됨', '확인 안 됨', '확인 안 됨']);
  assert.equal(ui.document.querySelector('#results img'), null);
  assert.match(ui.document.querySelector('#results .list-footer').textContent, /조회 결과 3건/);
});

test('dues distinguishes an empty completed query from missing or incomplete results', async t => {
  const empty = await showDues(t, []);
  assert.equal(empty.document.querySelector('#results table'), null);
  assert.match(empty.document.querySelector('#results').textContent, /조회된 납부할 세액이 없어요/);
  assert.match(empty.document.querySelector('#results .list-footer').textContent, /조회 결과 0건 · 조회 완료/);
  for (const [items, options] of [[null, {}], [[], {outcome: 'unknown', complete: false}],
    [[], {outcome: 'partial_success', complete: false}]]) {
    const ui = await showDues(t, items, options);
    assert.equal(ui.document.querySelector('#results .list-footer'), null);
    assert.doesNotMatch(ui.document.querySelector('#results').textContent, /조회 결과 0건|조회 완료|조회된 납부할 세액이 없어요/);
  }
  const missing = await showDues(t, null);
  missing.document.querySelector('main').innerHTML = await missing.views.taxhome(missing.ctx);
  assert.equal(missing.document.querySelector('[data-view="dues"] .number').textContent, '결과 확인 필요');
});

test('dues explains display limits and preserves partially returned items', async t => {
  const ui = await showDues(t, Array.from({length: 201}, () => syntheticDue), {itemCount: 1200});
  assert.equal(ui.document.querySelectorAll('#results tbody tr').length, 200);
  assert.equal(ui.document.querySelector('#results .list-footer').textContent, '홈택스 조회 결과 1200건 중 200건 표시 · 조회 완료');
  const partial = await showDues(t, [syntheticDue], {outcome: 'partial_success', complete: false});
  assert.match(partial.document.querySelector('#results').textContent, /일부만 성공/);
  assert.match(partial.document.querySelector('#results .list-footer').textContent, /조회 결과 1건 · 조회 범위 확인 필요/);
  assert.equal(partial.document.querySelectorAll('#results tbody tr').length, 1);
});

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

test('bank accounts need no target registration or separate default transfer signer', async t => {
  const ui = await setup(t, 'onesign', 'ready');
  ui.state.cache.set('hana.onesign.accounts|login||', {id: 'saved', status: 'finished', outcome: 'success',
    result: {accounts: [{ref: 'account-1', label: '합성 계좌', account_number: '12345678901234', balance: 100}],
      candidate_targets: {'account-1': 'target'}}});
  for (const view of ['accounts', 'settings']) {
    ui.document.querySelector('main').innerHTML = await ui.views[view](ui.ctx);
    assert.equal(ui.document.querySelector('[data-action="register-candidate"]'), null);
    assert.equal(ui.document.querySelector('[data-action="signing"]'), null);
    assert.doesNotMatch(ui.document.querySelector('main').textContent, /대상 등록|계좌 조회·등록|이체 서명/);
  }
  await ui.actions['login-menu'](ui.ctx, {dataset: {login: 'login'}});
  assert.equal(ui.document.querySelector('[data-run="signing"]'), null);
  assert.equal(ui.calls.length, 0);
  assert.equal(ui.asked.length, 0);
});

test('account query completion refreshes the model without a registration dialog or more bank requests', async t => {
  const ui = await setup(t, 'onesign', 'ready', {vault_passphrase: 'synthetic'});
  ui.state.view = 'settings';
  await ui.actions['accounts-query'](ui.ctx, {dataset: {login: 'login'}});
  assert.equal(ui.calls.length, 1);
  await ui.calls[0].options.onDone({status: 'finished', outcome: 'success', result: {accounts: []}});
  assert.equal(ui.document.querySelector('[data-action="register-candidate"]'), null);
  assert.equal(ui.calls.length, 1);
});

test('coverage explains partial live evidence and distinguishes login paths without bank requests', async t => {
  const ui = await setup(t);
  ui.state.capabilities = {verification_reviewed_at: '2026-10-01', features: [{
    id: 'hana-accounts', area: 'banking', title: '계좌·잔액 조회', placement: 'work', placement_label: '웹 업무',
    status: 'available', reasons: [], verification: 'live_partial',
    verification_note: '하나인증서 성공 확인. 공동인증서 미확인. <합성 범위>', verification_reviewed_at: '2026-10-01',
    jobs: [{name: 'hana.onesign.accounts', title: '하나인증서 계좌', status: 'available', verification: 'live_verified',
      verification_note: '계좌 응답 확인', requires_input: [], requires_confirmation: false},
    {name: 'hana.accounts.list', title: '공동인증서 계좌', status: 'available', verification: 'live_untested',
      verification_note: '최근 성공 근거 없음', requires_input: [], requires_confirmation: false}],
  }]};
  ui.document.querySelector('main').innerHTML = await ui.views.coverage(ui.ctx);
  assert.match(ui.document.body.textContent, /일부 실사용 확인/);
  assert.match(ui.document.body.textContent, /확인 기준: 2026-10-01/);
  assert.match(ui.document.body.textContent, /공동인증서 미확인/);
  assert.equal(ui.document.querySelector('합성'), null);
  await ui.actions['feature-info'](ui.ctx, ui.document.querySelector('[data-feature="hana-accounts"]'));
  const dialog = ui.document.querySelector('#dialog-content').textContent;
  assert.match(dialog, /계좌 응답 확인/);
  assert.match(dialog, /최근 성공 근거 없음/);
  assert.match(dialog, /실서버 미검증/);
  ui.document.querySelector('main').innerHTML = await ui.views.accounts(ui.ctx);
  assert.match(ui.document.querySelector('main').textContent, /실사용 확인/);
  assert.doesNotMatch(ui.document.querySelector('main').textContent, /실서버 미검증/);
  assert.equal(ui.calls.length, 0);
  assert.equal(ui.asked.length, 0);
});


test('Giro readiness uses reviewed capability levels instead of hardcoded untested labels', async t => {
  const ui = await setup(t);
  ui.state.capabilities.features = [
    {id: 'giro-login', title: '간편비밀번호 로그인', verification: 'live_verified', verification_note: '웹 PIN 로그인 성공 확인.'},
    {id: 'giro-receipts', title: '납부내역', verification: 'live_verified', verification_note: '웹 납부내역 목록·상세 조회 성공 확인.'},
    {id: 'giro-pay', title: '지로 납부', verification: 'live_partial', verification_note: 'CLI 국세 납부 성공. 웹 납부 실행은 미확인.'},
  ];
  ui.document.querySelector('main').innerHTML = await ui.views.girostatus(ui.ctx);
  const text = ui.document.querySelector('main').textContent;
  assert.match(text, /웹 PIN 로그인 성공 확인/);
  assert.match(text, /웹 납부내역 목록·상세 조회 성공 확인/);
  assert.match(text, /일부 실사용 확인/);
  assert.doesNotMatch(text, /실서버 미검증|웹에서의 실제 로그인·납부 확인은 아직/);
  assert.equal(ui.calls.length, 0);
});
