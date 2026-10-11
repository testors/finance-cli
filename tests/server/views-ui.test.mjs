import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule, SyntheticModule} from 'node:vm';
import {JSDOM} from 'jsdom';

const root = new URL('../../src/finance_cli/server/static/', import.meta.url);

async function setup(t, method = 'onesign', readiness = 'query_only', secret = {}) {
  const dom = new JSDOM('<main id="main"></main><div id="results"></div><dialog id="detail-dialog"><div id="dialog-content"></div></dialog><div id="toast"></div>',
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
  const calls = [], asked = [], checked = [], apiCalls = [], changed = [], redraws = [], posted = [];
  const ctx = {run: async (name, fields, options) => { calls.push({name, fields, options}); }};
  const values = {
    state, login: id => state.logins.find(r => r.id === id), target: id => state.targets.find(r => r.id === id), profile: () => null,
    scopeLogins: () => state.logins, scopeTargets: () => state.targets,
    onesignStore: owner => owner.credential.ref,
    askSecrets: async (...args) => { asked.push(args); return typeof secret === 'function' ? secret() : secret; },
    SECRET_LABELS: {vault_passphrase: ['vault_passphrase', '저장소 암호'], pin: ['pin', 'PIN'],
      certificate_password: ['certificate_password', '인증서 비밀번호']},
    applyRemember: () => {}, changeView: (...args) => { changed.push(args); }, jobState: () => '', refreshModel: async () => {},
    bankSessionExpired: () => state.idleExpired || false,
    ensureBankSession: async (ctx, id) => { checked.push(id); return !state.idleExpired; }, expiredBankLogin: async () => {},
    rememberField: () => '', render: by => { redraws.push(by); }, secretFields: () => [], showJob: () => {},
    extensionState: () => state.extension || 'none', setAutoExtend: on => { state.autoExtend = on; },
    extensionJob: () => state.extensionJob || null,
  };
  const app = new SyntheticModule(Object.keys(values), function () {
    for (const [k, v] of Object.entries(values)) this.setExport(k, v);
  }, {context});
  const api = new SyntheticModule(['api', 'submit'], function () {
    this.setExport('api', {get: async path => {
      apiCalls.push(path);
      if (state.failJobList && path.startsWith('/jobs?')) throw new Error('synthetic list error');
      if (path.startsWith('/jobs?')) return {jobs: state.listed ? state.listed(path) : []};
      if (state.served?.[path]) return state.served[path];
      return {credentials: [], devices: [], id_cards: []};
    }, post: async path => {
      if (!state.acceptPosts) throw {code: 'job_not_cancellable'};
      posted.push(path);
      return {};
    }, patch: async () => { throw {code: 'revision_conflict'}; }});
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
  return {ctx, state, calls, asked, checked, apiCalls, changed, redraws, posted, row, document: dom.window.document, ...views.namespace};
}

// The activity list reads one page without login extensions, which can run every few minutes.
const ACTIVITY = '/jobs?limit=50&hide=session_extend';

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

test('screens ask for each result by its job name and target, with no lasting list cache', async t => {
  const tax = await setup(t, 'joint_certificate', 'ready');
  tax.row.institution = 'hometax'; tax.state.targets[0].kind = 'personal';
  await tax.views.taxhome(tax.ctx);
  // The server filters before its limit, so unrelated jobs and CLI records cannot push a result
  // out of reach. The invoice direction is matched on the stored input, among the recent ones.
  const asked = ['/jobs?name=hometax.tax.dues&limit=1&target_id=target', '/jobs?name=hometax.tax.refunds&limit=1&target_id=target',
    '/jobs?name=hometax.invoice.list&limit=50&target_id=target'];
  assert.deepEqual(tax.apiCalls, asked);
  await tax.views.taxhome(tax.ctx);
  assert.deepEqual(tax.apiCalls, [...asked, ...asked]);
  const bank = await setup(t, 'onesign', 'ready');
  bank.state.logins = Array.from({length: 3}, (_, i) => ({...bank.row, id: 'synthetic-' + i}));
  await bank.views.accounts(bank.ctx);
  assert.deepEqual(bank.apiCalls, [0, 1, 2].map(i => `/jobs?name=hana.onesign.accounts&limit=1&login_id=synthetic-${i}`));
  assert.equal(bank.calls.length, 0);
});

test('a result that only the server filter can reach is shown, and another direction is not', async t => {
  const ui = await setup(t, 'joint_certificate', 'ready');
  ui.row.institution = 'hometax'; ui.state.targets[0].kind = 'business';
  const job = direction => ({id: direction, name: 'hometax.invoice.list', login_id: 'login', target_id: 'target', status: 'finished',
    outcome: 'success', input: {direction}, result: {items: [{dmnrTnmNm: '합성 ' + direction, wrtDt: '20260915'}], pagination: {complete: true}}});
  ui.state.listed = path => path.startsWith('/jobs?name=hometax.invoice.list&') ? [job('purchases'), job('sales')] : [];
  ui.state.served = {'/jobs/sales': job('sales'), '/jobs/purchases': job('purchases')};
  const main = ui.document.querySelector('main');
  ui.state.params = {};
  main.innerHTML = await ui.views.invoices(ui.ctx);
  assert.deepEqual(ui.apiCalls.filter(path => path.startsWith('/jobs/')), ['/jobs/sales']);
  assert.match(main.textContent, /합성 sales/);
  assert.doesNotMatch(main.textContent, /합성 purchases/);
  assert.match(main.textContent, /2026-09-15/, 'a known date field reads as a date');
});

test('a failed list read does not prevent the next explicit screen load', async t => {
  const ui = await setup(t, 'joint_certificate', 'ready');
  ui.row.institution = 'hometax'; ui.state.targets[0].kind = 'personal';
  ui.state.failJobList = true;
  await assert.rejects(ui.views.taxhome(ui.ctx), /synthetic list error/);
  assert.equal(ui.apiCalls.length, 3);
  ui.state.failJobList = false;
  await ui.views.taxhome(ui.ctx);
  assert.equal(ui.apiCalls.length, 6);
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

async function showDues(t, items, {outcome = 'success', complete = true, itemCount, extra = {}} = {}) {
  const ui = await setup(t, 'joint_certificate', 'ready');
  ui.row.institution = 'hometax';
  ui.state.targets[0].kind = 'personal';
  const job = {id: 'dues-job', name: 'hometax.tax.dues', status: 'finished', outcome,
    login_id: 'login', target_id: 'target', result: {items, item_count: itemCount, pagination: {complete}, ...extra}};
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
  assert.equal(missing.document.querySelector('[data-open="dues"] .number').textContent, '결과 확인 필요');
});

test('dues counts a list the service omitted as zero only for a completed success without a sum', async t => {
  const omitted = await showDues(t, null, {extra: {list_omitted: true, amount_sum: 0}});
  assert.match(omitted.document.querySelector('#results').textContent, /조회된 납부할 세액이 없어요/);
  assert.match(omitted.document.querySelector('#results .list-footer').textContent, /조회 결과 0건 · 조회 완료 · 홈택스가 목록 없이/);
  omitted.document.querySelector('main').innerHTML = await omitted.views.taxhome(omitted.ctx);
  assert.equal(omitted.document.querySelector('[data-open="dues"] .number').textContent, '0건');
  for (const options of [{extra: {list_omitted: true, amount_sum: 1000}}, {extra: {list_omitted: true}, complete: false},
    {extra: {list_omitted: true}, outcome: 'unknown'}, {extra: {list_omitted: false}}]) {
    const ui = await showDues(t, null, options);
    assert.match(ui.document.querySelector('#results').textContent, /조회 항목을 확인하지 못했어요/);
  }
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
    // A new login is offered by the shell beside the heading, not by a button inside the form.
    assert.equal(form.querySelector('[data-action="login"],[data-action="security-login"]'), null);
    assert.equal(ui.calls.length, 1);
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
      ui.state.rows[view] = {job: {id: 'parent', login_id: 'login', target_id: 'target'}, rows: []};
    }
    const button = {dataset: {job: 'parent', index: '0'}};
    assert.equal(ui.actions['history-more'], undefined, 'one history job collects every page');
    for (const action of ['history-detail', 'history-export', 'inquiry-detail']) {
      await ui.actions[action](ui.ctx, button);
    }
    assert.deepEqual(ui.calls.map(c => c.name), ['history.list', 'inquiry.history', 'history.detail',
      'history.export', 'inquiry.detail'].map(n => `hana.${method === 'onesign' ? 'onesign.' : ''}${n}`));
    assert.equal(ui.asked.length, method === 'onesign' ? 5 : 0);
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

// A work screen leaves a live session's new login to the shell's heading; a connection card keeps its own.
const ownLogin = (ui, view, label) => assert.equal(ui.document.querySelector('main [data-action="login"]')?.textContent,
  view === 'settings' ? label : undefined, view);

test('after transfer, accounts and settings offer queries and the connection card a manual login', async t => {
  const ui = await setup(t);
  for (const view of ['accounts', 'settings']) {
    ui.document.querySelector('main').innerHTML = await ui.views[view](ui.ctx);
    assert.match(ui.document.body.textContent, /조회용 세션 있음/);
    ownLogin(ui, view, '다시 로그인');
    assert.ok(ui.document.querySelector('[data-action="accounts-query"]'));
  }
  ui.document.querySelector('main').innerHTML = await ui.views.transfer(ui.ctx);
  assert.match(ui.document.body.textContent, /다음 이체.*새 로그인/);
  const form = ui.document.querySelector('form');
  form.elements.account.value = '00012345678'; form.elements.amount.value = '12,000';
  await ui.actions['transfer-prepare'](ui.ctx, form);
  assert.deepEqual(ui.calls.map(c => c.name), ['hana.onesign.login'], 'only the login is requested, never the transfer');
  assert.equal(ui.asked.length, 1);
  assert.match(ui.asked[0][2], /새 이체에는 새 로그인이 필요해요/);
  await ui.calls[0].options.onDone({outcome: 'success'});
  assert.equal(ui.calls.length, 1, 'logging in must not send the kept transfer');
  ui.document.querySelector('main').innerHTML = await ui.views.transfer(ui.ctx);
  assert.equal(ui.document.querySelector('[name="account"]').value, '00012345678');
  assert.equal(ui.document.querySelector('[name="amount"]').value, '12,000');
});

test('a login opened for a new transfer goes on to the account password, and only typing it prepares the transfer', async t => {
  const answers = [{pin: '123456'}, null, {account_password: '1234'}];
  const ui = await setup(t, 'onesign', 'query_only', () => answers.shift());
  const main = ui.document.querySelector('main');
  const pressed = [];
  // As the app does: a submitted form runs its action, and a successful login redraws the screen.
  ui.document.addEventListener('submit', event => {
    event.preventDefault();
    pressed.push(ui.actions[event.target.dataset.submit](ui.ctx, event.target));
  });
  ui.ctx.run = async (name, fields, options) => {
    ui.calls.push({name, fields, options});
    if (name !== 'hana.onesign.login') return;
    ui.row.readiness = 'ready';
    await options.onDone({outcome: 'success'});
    main.innerHTML = await ui.views.transfer(ui.ctx);
  };
  const names = () => ui.calls.map(c => c.name);
  main.innerHTML = await ui.views.transfer(ui.ctx);
  main.querySelector('[name="account"]').value = '00012345678'; main.querySelector('[name="amount"]').value = '12,000';
  await ui.actions['transfer-prepare'](ui.ctx, main.querySelector('form'));
  await Promise.all(pressed);
  assert.deepEqual(ui.asked.map(a => a[0]), ['합성 연결 로그인', '이체 준비'], 'the account password is asked right after the login');
  assert.match(ui.asked[0][2], /로그인하면 이어서 출금 계좌 비밀번호/);
  assert.match(ui.document.querySelector('#toast').textContent, /^로그인 · 성공/, 'the login result is not read as a transfer result');
  assert.deepEqual(names(), ['hana.onesign.login'], 'a cancelled account password sends no transfer');
  assert.equal(main.querySelector('[name="account"]').value, '00012345678');
  await ui.actions['transfer-prepare'](ui.ctx, main.querySelector('form'));
  assert.deepEqual(names(), ['hana.onesign.login', 'hana.transfer.prepare'], 'with the session ready no login is asked again');
  assert.equal(JSON.stringify(ui.calls[1].fields.input),
    JSON.stringify({recipient_bank_code: '081', recipient_account_number: '00012345678', amount_krw: 12000}));
  assert.equal(pressed.length, 1, 'the form is submitted once after the login, and never again by itself');

  // A screen the user left during the login keeps no values, so nothing is submitted for it.
  ui.row.readiness = 'query_only';
  answers.push({pin: '123456'});
  ui.ctx.run = async name => { ui.calls.push({name}); ui.row.readiness = 'ready'; ui.state.params = {}; };
  await ui.actions['transfer-prepare'](ui.ctx, main.querySelector('form'));
  assert.deepEqual(names().slice(2), ['hana.onesign.login']);
  assert.equal(pressed.length, 1);
  assert.equal(ui.asked.at(-1)[0], '합성 연결 로그인');
});

test('a confirmed transfer ends on a redrawn empty form; one refused before sending or left for later is confirmed again', async t => {
  const ui = await setup(t, 'onesign', 'ready', {account_password: '1234'});
  const main = ui.document.querySelector('main');
  ui.state.acceptPosts = true;
  const prepared = {id: 'job', name: 'hana.transfer.prepare', login_id: 'login', status: 'awaiting_input', awaiting: {digest: 'synthetic',
    requires: [], preview: {recipient_bank_code: '081', recipient_account: '00012345678', amount_krw: 12000, fee_krw: 0, total_krw: 12000}}};
  const done = {...prepared, status: 'finished', outcome: 'success', awaiting: null, attempt: {sent: true}};
  const confirm = async (final, current = true) => {
    main.innerHTML = await ui.views.transfer(ui.ctx);
    Object.assign(ui.ctx, {current: () => current, track: async () => final, run: async (name, fields, options) => options.onDone(prepared)});
    main.querySelector('[name="account"]').value = '00012345678'; main.querySelector('[name="amount"]').value = '12,000';
    await ui.actions['transfer-prepare'](ui.ctx, main.querySelector('form'));
    ui.document.querySelector('#confirm-form').dispatchEvent(new ui.document.defaultView.Event('submit', {cancelable: true}));
    await new Promise(resolve => setTimeout(resolve));
    return ui.document.querySelector('#dialog-title').textContent;
  };
  assert.equal(await confirm(done), '이체 결과');
  assert.equal(ui.redraws.length, 1);
  main.innerHTML = await ui.views.transfer(ui.ctx);
  assert.equal(main.querySelector('[name="account"]').value, '', 'the redrawn form cannot send the same transfer again');
  assert.equal(main.querySelector('[name="amount"]').value, '');
  assert.equal(await confirm({...done, outcome: 'unknown'}), '이체 결과');
  assert.equal(ui.redraws.length, 2, 'whatever the verdict, the attempt is over');
  assert.equal(await confirm(done, false), '이체 결과');
  assert.equal(ui.redraws.length, 2, 'a screen the user moved to meanwhile is left as it is');
  // Refused before anything was sent: the prepared transfer and its form are kept and the confirmation is asked again.
  const title = () => ui.document.querySelector('#dialog-title').textContent;
  assert.equal(await confirm({...prepared, local: {last_confirmation_refused: 'store_authentication_failed'}}), '이 내용으로 보낼까요?');
  assert.match(ui.document.querySelector('#detail-dialog .form-error').textContent, /저장소 암호가 맞지 않아요/);
  assert.equal(ui.redraws.length, 2);
  assert.deepEqual(ui.posted, Array(4).fill('/jobs/job/confirm'), 'each confirmation is posted once');
  // Left for later, it opens again from its job detail; once it has run, that shows its result.
  ui.state.served = {'/jobs/job': prepared};
  await ui.actions['transfer-open'](ui.ctx, {dataset: {job: 'job'}});
  assert.equal(title(), '이 내용으로 보낼까요?');
  ui.state.served = {'/jobs/job': done};
  await ui.actions['transfer-open'](ui.ctx, {dataset: {job: 'job'}});
  assert.equal(title(), '이체 결과');
  assert.equal(ui.posted.length, 4, 'opening it sends nothing');
});

test('an expired login offers no query in accounts; the login is asked once, by the shell notice', async t => {
  const ui = await setup(t, 'onesign', 'login_required');
  const main = ui.document.querySelector('main');
  main.innerHTML = await ui.views.accounts(ui.ctx);
  assert.equal(main.querySelector('[data-action="login"]'), null, 'no second login button under the notice');
  assert.equal(main.querySelector('[data-action="accounts-query"]'), null);
  // Beside a login that is still live there is no notice, so the logged-out one offers its own login.
  ui.state.logins.push({...ui.row, id: 'live', readiness: 'ready', display_name: '합성 둘째'});
  main.innerHTML = await ui.views.accounts(ui.ctx);
  assert.deepEqual([...main.querySelectorAll('[data-action="login"]')].map(b => b.dataset.login), ['login']);
  assert.deepEqual([...main.querySelectorAll('[data-action="accounts-query"]')].map(b => b.dataset.login), ['live']);
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
  assert.match(ui.document.body.textContent, /로그아웃됨 · 10분 넘게 요청 없음/);
  // The limit shown is the one the server sent for that institution's session.
  ui.state.logins[0].session = {...ui.state.logins[0].session, idle_seconds: 290};
  ui.document.querySelector('main').innerHTML = await ui.views.accounts(ui.ctx);
  assert.match(ui.document.body.textContent, /로그아웃됨 · 4분 50초 넘게 요청 없음/);
});


test('ready sessions keep a visible login action without requesting credentials on render', async t => {
  const ui = await setup(t, 'onesign', 'ready', {pin: '123456'});
  for (const view of ['accounts', 'settings']) {
    ui.document.querySelector('main').innerHTML = await ui.views[view](ui.ctx);
    ownLogin(ui, view, '다시 로그인');
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
  assert.deepEqual(ui.calls.map(c => c.name), ['hana.onesign.login', 'hana.onesign.accounts'],
    'a successful bank login reads balances once and replays nothing else');
});

test('a rejected account query leaves the session as it is, without assuming expiry', async t => {
  const ui = await setup(t);
  ui.state.cache.set('hana.onesign.accounts|login||', {id: 'failed', status: 'finished', outcome: 'rejected',
    session_id: 'session', result: {accounts: []}, service_verdict: {accepted: false}, local: {}});
  ui.document.querySelector('main').innerHTML = await ui.views.accounts(ui.ctx);
  assert.match(ui.document.body.textContent, /기관이 실패로 판정/);
  // Still a live session: the query stays, and the shell keeps offering a new login beside the heading.
  assert.match(ui.document.body.textContent, /조회용 세션 있음/);
  assert.equal(ui.document.querySelector('main [data-action="login"]'), null);
  assert.ok(ui.document.querySelector('[data-action="accounts-query"]'));
  assert.equal(ui.row.readiness, 'query_only');
  assert.equal(ui.calls.length, 0);
});

test('banking screens carry no login button of their own, and a login from the transfer screen keeps what was typed', async t => {
  const ui = await setup(t, 'onesign', 'ready', {pin: '123456'});
  ui.state.logins.push({...ui.row, id: 'other-login', credential: {ref: 'other-store'}});
  ui.state.targets.push({...ui.state.targets[0], id: 'other-target', login_id: 'other-login'});
  const main = ui.document.querySelector('main');
  for (const view of ['history', 'inquiry', 'transfer', 'security']) {
    main.innerHTML = await ui.views[view](ui.ctx);
    assert.equal(main.querySelector('[data-action$="login"]'), null, view + ': the shell offers the new login beside the heading');
  }
  // The shell's button names the login; the login runs for that one and sends nothing else.
  main.innerHTML = await ui.views.transfer(ui.ctx);
  main.querySelector('[name="account"]').value = '00012345678'; main.querySelector('[name="amount"]').value = '12,000';
  await ui.actions.login(ui.ctx, {dataset: {login: 'other-login'}});
  assert.deepEqual(ui.calls.map(c => [c.name, c.fields.login_id]), [['hana.onesign.login', 'other-login']]);
  assert.equal(ui.asked.at(-1)[3].store, 'other-store');
  // A login redraws the screen: the transfer form comes back with what was typed.
  main.innerHTML = await ui.views.transfer(ui.ctx);
  assert.equal(main.querySelector('[name="account"]').value, '00012345678');
  assert.equal(main.querySelector('[name="amount"]').value, '12,000');
});

test('new and disabled logins show appropriate actions', async t => {
  const ui = await setup(t, 'onesign', 'login_required');
  ui.row.current_session_id = null;
  ui.document.querySelector('main').innerHTML = await ui.views.accounts(ui.ctx);
  assert.equal(ui.document.querySelector('main [data-action="login"]'), null, 'a first login is asked by the shell notice');
  ui.document.querySelector('main').innerHTML = await ui.views.settings(ui.ctx);
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
  assert.doesNotMatch(ui.document.querySelector('main').textContent, /실사용 확인|실서버 미검증/);
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

test('a page notice before an invoice query is not described as service hours and hints at the target kind', async t => {
  const ui = await setup(t, 'joint_certificate', 'ready');
  ui.row.institution = 'hometax';
  const job = {id: 'notice', name: 'hometax.invoice.list', login_id: 'login', target_id: 'target', status: 'finished',
    outcome: 'unknown', service_verdict: {branch: 'no_action', reason: 'original_action_not_observed', original_dialog_observed: true},
    result: {items: null, pagination: null}};
  ui.state.params = {};
  ui.state.cache.set('hometax.invoice.list||target|sales', job);
  const main = ui.document.querySelector('main');
  for (const [kind, hinted] of [['personal', true], ['business', false]]) {
    ui.state.targets[0].kind = kind;
    main.innerHTML = await ui.views.invoices(ui.ctx);
    assert.match(main.textContent, /홈택스 화면이 안내창을 띄우고 조회를 진행하지 않았어요/);
    assert.doesNotMatch(main.textContent, /이용 불가 시간대/);
    assert.equal(/조회 대상을 사업장으로 바꿔/.test(main.textContent), hinted);
  }
  job.service_verdict = {branch: 'no_action', reason: 'original_action_not_observed'};
  main.innerHTML = await ui.views.invoices(ui.ctx);
  assert.match(main.textContent, /이용 불가 시간대/);
});

function hometax(ui, kind = 'business') {
  ui.row.institution = 'hometax'; ui.state.targets[0].kind = kind; ui.state.params = {};
  return ui.document.querySelector('main');
}

const taxJob = (name, items) => ({id: name, name, login_id: 'login', target_id: 'target', status: 'finished', outcome: 'success',
  result: {items, pagination: {complete: true}}});
const lines = box => [...box.querySelectorAll(':scope > .summary-line')].map(line => [line.querySelector('span').textContent, line.querySelector('strong').textContent]);

test('a paid tax is named as paid, in the order the tax office lists it', async t => {
  const ui = await setup(t, 'joint_certificate', 'ready');
  const main = hometax(ui, 'personal');
  ui.state.cache.set('hometax.tax.payments||target|', taxJob('hometax.tax.payments', [{atchRomAmt: '0', attrYr: '2026',
    bankElctPmtNo: '0126-****', elctPmtNo: '2026****', hmtxYn: 'Y', itrfCdNm: '합성 세목', mataTxprNm: '합성 이름', romAmt: '1234567',
    romDt: '20261001', romFnnOrgnNm: '합성 수납점', txhfOgzCd: '000', txhfOgzNm: '합성세무서'}]));
  main.innerHTML = await ui.views.payments(ui.ctx);
  const results = main.querySelector('#results');
  assert.deepEqual([...results.querySelectorAll('th')].map(n => n.textContent), ['세목', '수납관서', '납부일자', '납부세액']);
  assert.deepEqual([...results.querySelectorAll('tbody td')].map(n => n.textContent), ['합성 세목', '합성세무서', '2026-10-01', '1,234,567']);
  assert.equal(results.querySelector('th:last-child').className, 'num');
  assert.doesNotMatch(results.textContent, /납부할 세액|atchRomAmt/, 'an amount already paid is not shown as an amount still due');
  ui.actions.row(ui.ctx, results.querySelector('tbody tr'));
  const detail = ui.document.querySelector('#dialog-content');
  assert.deepEqual(lines(detail.querySelector('.summary-lines')), [['세목', '합성 세목'], ['수납관서', '합성세무서'], ['납부일자', '2026-10-01'],
    ['납부세액', '1,234,567'], ['귀속연도', '2026'], ['전자납부번호', '0126-****'],
    ['전자납부번호(세목년월+결정구분+세목코드+발행번호)', '2026****'], ['수납점포', '합성 수납점'], ['관서코드', '000']]);
  assert.match(detail.querySelector('details summary').textContent, /그 밖의 항목 3개/);
  assert.deepEqual(lines(detail.querySelector('.folded-fields .summary-lines')), [['atchRomAmt', '0'], ['hmtxYn', 'Y'], ['mataTxprNm', '합성 이름']],
    'a field the tax office names nowhere, or only as unpaid, keeps its own name and value');
  assert.equal(ui.calls.length, 0);
});

test('refund, notice and return rows carry the names, dates and code names of their own screens', async t => {
  const ui = await setup(t, 'joint_certificate', 'ready');
  const main = hometax(ui, 'personal');
  ui.state.cache.set('hometax.tax.refunds||target|', taxJob('hometax.tax.refunds', [{attrYm: '202609', bokTrtRsltCd: '01', itrfNm: '합성 세목',
    rfamtPymnAmt: '50000', rfndDcsDfntDt: '20261002', txhfOgzNm: '합성세무서'}, {bokTrtRsltCd: '77', itrfNm: '합성 세목 2', rfamtPymnAmt: 7, rfndDcsDfntDt: '합성'}]));
  main.innerHTML = await ui.views.refunds(ui.ctx);
  assert.deepEqual([...main.querySelectorAll('#results th')].map(n => n.textContent), ['세목명', '환급일자', '환급금액', '지급구분']);
  assert.deepEqual([...main.querySelectorAll('#results tbody td')].map(n => n.textContent),
    ['합성 세목', '2026-10-02', '50,000', '미수령', '합성 세목 2', '합성', '7', '77'], 'a code or a date of another shape stays as received');
  ui.actions.row(ui.ctx, main.querySelector('#results tbody tr'));
  assert.deepEqual(lines(ui.document.querySelector('#dialog-content .summary-lines')), [['세목명', '합성 세목'], ['환급일자', '2026-10-02'],
    ['환급금액', '50,000'], ['지급구분', '미수령'], ['귀속년월', '2026-09'], ['세무서명', '합성세무서']]);
  ui.state.cache.set('hometax.tax.notices||target|', taxJob('hometax.tax.notices', [{elctNtfPrslDtm: '20261003091500', elctPmtNo: '2026****',
    itrfNm: '합성 세목', pmtDdt: '20261031', pmtTxamt: '30000', pmtYn: '미납', txprNm: '합성 상호'}]));
  main.innerHTML = await ui.views.notices(ui.ctx);
  assert.deepEqual([...main.querySelectorAll('#results th')].map(n => n.textContent), ['세목명', '납부기한', '납부할 세액', '납부여부']);
  ui.actions.row(ui.ctx, main.querySelector('#results tbody tr'));
  assert.deepEqual(lines(ui.document.querySelector('#dialog-content .summary-lines')), [['세목명', '합성 세목'], ['납부기한', '2026-10-31'],
    ['납부할 세액', '30,000'], ['납부여부', '미납'], ['열람일시', '2026-10-03 09:15:00'], ['전자납부번호', '2026****'], ['상호(성명)', '합성 상호']]);
  ui.state.cache.set('hometax.returns.list||target|', taxJob('hometax.returns.list', [{cvaAplnDtm: '20261004101112', rtnClNm: '정기신고',
    rtnCvaId: 'R1', stmnKndNm: '합성 신고서', txnrmYm: '202609', userId: 'synthetic'}]));
  main.innerHTML = await ui.views.returns(ui.ctx);
  assert.deepEqual([...main.querySelectorAll('#results th')].map(n => n.textContent), ['신고서종류', '과세연월', '신고구분', '접수일시']);
  assert.deepEqual([...main.querySelectorAll('#results tbody td')].map(n => n.textContent), ['합성 신고서', '2026-09', '정기신고', '2026-10-04 10:11:12']);
  ui.actions.row(ui.ctx, main.querySelector('#results tbody tr'));
  assert.deepEqual(lines(ui.document.querySelector('#dialog-content .summary-lines')).slice(4), [['신고 ID', 'R1'], ['제출자ID', 'synthetic']]);
});

test('a corporate ledger row opens with the names of the bank\'s own detail screen', async t => {
  const ui = await setup(t, 'id_password', 'ready');
  const main = ui.document.querySelector('main');
  ui.state.rows['corporate-history'] = {rows: [{AMT_TYP_CD: 'S1', BAL_FLCT_DV_CD: '2', MEMO_CTT: '합성 메모', RMRK: '합성 적요',
    TRSC_AF_BAL: '000000000900000.500', TRSC_AMT: '000000000100000.000', TRSC_DT: '20261001', TRSC_TM: '093000'}]};
  main.innerHTML = '<table><tbody><tr data-row="corporate-history:0"></tr></tbody></table>';
  ui.actions.row(ui.ctx, main.querySelector('tr'));
  const detail = ui.document.querySelector('#dialog-content');
  assert.deepEqual(lines(detail.querySelector('.summary-lines')), [['잔액변동구분', '출금'], ['추가메모', '합성 메모'], ['적요', '합성 적요'],
    ['거래 후 잔액', '900,000.5'], ['거래금액', '100,000'], ['거래일자', '2026-10-01'], ['거래시각', '09:30:00']]);
  assert.deepEqual(lines(detail.querySelector('.folded-fields .summary-lines')), [['AMT_TYP_CD', 'S1']]);
  // A field name is data from the institution: one that matches a built-in name is still only a field.
  ui.state.rows['corporate-history'] = {rows: [{BAL_FLCT_DV_CD: 'constructor', RMRK: '합성 적요', constructor: '합성', toString: '합성 2'}]};
  ui.actions.row(ui.ctx, main.querySelector('tr'));
  assert.deepEqual(lines(detail.querySelector('.summary-lines')), [['잔액변동구분', 'constructor'], ['적요', '합성 적요']]);
  assert.deepEqual(lines(detail.querySelector('.folded-fields .summary-lines')), [['constructor', '합성'], ['toString', '합성 2']]);
});

test('each invoice tab shows only its own direction, with known field names in Korean', async t => {
  const ui = await setup(t, 'joint_certificate', 'ready');
  const main = hometax(ui);
  ui.state.cache.set('hometax.invoice.list||target|sales', {id: 'sales', name: 'hometax.invoice.list', login_id: 'login',
    target_id: 'target', status: 'finished', outcome: 'success', input: {direction: 'sales'},
    result: {items: [{dmnrTnmNm: '합성 매출처', wrtDt: '2026-10-01', syntheticUnknown: '원문'}], pagination: {complete: true}}});
  ui.state.params = {direction: 'purchases'};
  main.innerHTML = await ui.views.invoices(ui.ctx);
  assert.doesNotMatch(main.textContent, /합성 매출처/, 'the purchases tab never shows sales rows');
  assert.match(main.textContent, /아직 조회하지 않았어요/);
  await ui.actions['invoice-query'](ui.ctx, main.querySelector('form'));
  assert.equal(ui.calls[0].fields.input.direction, 'purchases');
  assert.equal(ui.calls[0].options.key, 'hometax.invoice.list||target|purchases');
  ui.state.params = {};
  main.innerHTML = await ui.views.invoices(ui.ctx);
  assert.deepEqual([...main.querySelectorAll('#results th')].map(n => n.textContent), ['공급받는 자 상호', '작성일', 'syntheticUnknown']);
  assert.equal(main.querySelector('#results td').dataset.label, '공급받는 자 상호');
  await ui.actions.row(ui.ctx, main.querySelector('#results tbody tr'));
  const detail = ui.document.querySelector('#dialog-content');
  assert.match(detail.querySelector('.summary-lines').textContent, /공급받는 자 상호합성 매출처/);
  assert.match(detail.querySelector('details summary').textContent, /그 밖의 항목 1개/);
  assert.match(detail.querySelector('details').textContent, /syntheticUnknown원문/);
  assert.equal(ui.calls.length, 1);
});

test('an error stays on the screen or in the open dialog after its toast is gone', async t => {
  const ui = await setup(t);
  const main = ui.document.querySelector('main');
  main.innerHTML = '<div class="page-heading"></div><section class="panel"></section>';
  await ui.actions['cancel-job'](ui.ctx, {dataset: {job: 'synthetic'}});
  assert.match(main.querySelector('.page-heading + .page-error').textContent, /이미 시작한 작업은 취소할 수 없어요/);
  await ui.actions['cancel-job'](ui.ctx, {dataset: {job: 'synthetic'}});
  assert.equal(main.querySelectorAll('.page-error').length, 1, 'a repeated error replaces the previous one');
  ui.actions['rename-login'](ui.ctx, {dataset: {login: 'login'}});
  const form = ui.document.querySelector('#dialog-content form');
  await ui.actions['save-login-name'](ui.ctx, form);
  assert.match(ui.document.querySelector('#dialog-content .form-error').textContent, /다른 곳에서 설정이 바뀌었어요/);
  assert.ok(ui.document.querySelector('#detail-dialog').open, 'the dialog and its input stay');
});

test('the balance total adds won accounts only and an account row opens its history', async t => {
  const ui = await setup(t, 'onesign', 'ready');
  ui.state.cache.set('hana.onesign.accounts|login||', {id: 'saved', status: 'finished', outcome: 'success', result: {
    accounts: [{ref: 'account-1', label: '합성 원화', account_number: '12345678901234', currency: 'KRW', balance: 1000},
      {ref: 'account-2', label: '합성 통화 미표시', account_number: '22345678901234', balance: 500},
      {ref: 'account-3', label: '합성 외화', account_number: '32345678901234', currency: 'USD', balance: 70}],
    candidate_targets: {'account-1': 'target'}}});
  const main = ui.document.querySelector('main');
  main.innerHTML = await ui.views.accounts(ui.ctx);
  assert.equal(main.querySelector('.total-balance').textContent, '1,500원');
  assert.match(main.querySelector('.balance-meta').textContent, /2개 계좌 합산.*외화 1개 계좌는 합계에서 제외/);
  const linked = main.querySelectorAll('tr[data-action="account-history"]');
  assert.equal(linked.length, 1, 'only an account linked to this login is a link');
  ui.actions['account-history'](ui.ctx, linked[0]);
  assert.equal(JSON.stringify(ui.changed), JSON.stringify([['history', {target: 'target'}]]));
  assert.equal(ui.calls.length, 0);
});

test('return queries send a named tax item as its code and nothing for the default', async t => {
  const ui = await setup(t, 'joint_certificate', 'ready');
  const main = hometax(ui);
  main.innerHTML = await ui.views.returns(ui.ctx);
  const form = main.querySelector('form');
  await ui.actions['returns-query'](ui.ctx, form);
  assert.equal('tax_code' in ui.calls[0].fields.input, false);
  form.elements.tax_code_choice.value = '41';
  await ui.actions['returns-query'](ui.ctx, form);
  assert.equal(ui.calls[1].fields.input.tax_code, '41');
  assert.equal('tax_code_choice' in ui.calls[1].fields.input, false);
  form.elements.tax_code_choice.value = 'custom';
  ui.actions['tax-code-choice'](ui.ctx, form.elements.tax_code_choice);
  assert.equal(form.elements.tax_code.disabled, false);
  form.elements.tax_code.value = '99';
  await ui.actions['returns-query'](ui.ctx, form);
  assert.equal(ui.calls[2].fields.input.tax_code, '99');
});

test('a summary card without a result asks for its query once; one with a result only opens it', async t => {
  const ui = await setup(t, 'joint_certificate', 'ready');
  const main = hometax(ui, 'personal');
  ui.state.cache.set('hometax.tax.dues||target|', {id: 'dues', name: 'hometax.tax.dues', status: 'finished', outcome: 'success',
    login_id: 'login', target_id: 'target', observed_at: 1790000000,
    result: {items: [{itrfNm: '합성 세목'}], item_count: 1, amount_sum: 1794500, pagination: {complete: true}}});
  main.innerHTML = await ui.views.taxhome(ui.ctx);
  const dues = main.querySelector('[data-open="dues"]'), refunds = main.querySelector('[data-open="refunds"]');
  assert.equal(dues.dataset.run, undefined);
  assert.equal(refunds.dataset.run, '1');
  assert.match(dues.textContent, /홈택스 합계 1,794,500원/);
  ui.actions['tax-open'](ui.ctx, refunds); ui.actions['tax-open'](ui.ctx, dues);
  assert.equal(JSON.stringify(ui.changed), JSON.stringify([['refunds', {autorun: true}], ['dues', {}]]));
  let submitted = 0;
  const later = [];
  ui.state.params = {autorun: true};
  main.innerHTML = await ui.views.refunds({...ui.ctx, later: run => later.push(run)});
  main.querySelector('form').requestSubmit = () => { submitted++; };
  later.forEach(run => run());
  main.innerHTML = await ui.views.refunds({...ui.ctx, later: run => later.push(run)});
  assert.equal(submitted, 1);
  assert.equal(later.length, 1, 'returning to the screen does not ask again');
  assert.equal(ui.calls.length, 0, 'rendering alone never submits a job');
});

test('history returns with the account\'s last result and a period button sets Korea-time dates', async t => {
  const ui = await setup(t, 'onesign', 'ready');
  ui.state.cache.set('hana.onesign.history.list||target|', {id: 'list', name: 'hana.onesign.history.list', status: 'finished',
    outcome: 'success', login_id: 'login', target_id: 'target',
    result: {rows: [{date: '2026-09-30', time: '10:00', type: '입금', name: '합성 입금', amount: 1000, balance: 5000}], pagination_complete: true}});
  ui.state.params = {target: 'target'};
  const main = ui.document.querySelector('main');
  main.innerHTML = await ui.views.history(ui.ctx);
  assert.match(main.textContent, /합성 입금/);
  assert.equal(ui.calls.length, 0, 'showing a saved result asks the bank for nothing');
  assert.equal(ui.asked.length, 0);
  ui.actions.period(ui.ctx, main.querySelector('[data-action="period"][data-days="30"]'));
  assert.equal(main.querySelector('[name="start_date"]').value, '2026-09-01');
  assert.equal(main.querySelector('[name="end_date"]').value, '2026-10-01');
  await ui.actions['history-query'](ui.ctx, main.querySelector('form'));
  assert.equal(ui.calls[0].options.key, 'hana.onesign.history.list||target|');
  assert.equal(ui.calls[0].fields.input.start_date, '2026-09-01');
});

test('history shows every collected row in one list and says when the range is unfinished', async t => {
  const ui = await setup(t, 'onesign', 'ready');
  const main = ui.document.querySelector('main');
  const rows = Array.from({length: 250}, (_, i) => ({date: '2026-09-30', time: '10:00', type: '입금', name: `합성 ${i + 1}`, amount: 1000, balance: 5000}));
  const show = async (outcome, result, local = {}) => {
    ui.state.cache.set('hana.onesign.history.list||target|', {id: 'list', name: 'hana.onesign.history.list', status: 'finished',
      outcome, login_id: 'login', target_id: 'target', result, local});
    ui.state.params = {target: 'target'};
    main.innerHTML = await ui.views.history(ui.ctx);
  };
  await show('success', {rows, pagination_complete: true});
  assert.equal(main.querySelectorAll('tr[data-row^="history:"]').length, 250);
  assert.match(main.querySelector('#results .list-footer').textContent, /250건 · 조회 완료/);
  assert.equal(main.querySelector('[data-action="history-more"]'), null);
  assert.ok(main.querySelector('[data-action="history-export"][data-job="list"]'));
  // A row of a later page is addressed by its place in the merged list, on the same job.
  await ui.actions['history-detail'](ui.ctx, {dataset: {index: '149'}});
  assert.equal(ui.calls[0].name, 'hana.onesign.history.detail');
  assert.equal(ui.calls[0].fields.parent_job_id, 'list');
  assert.equal(ui.calls[0].fields.input.row, 150);

  await show('partial_success', {rows: rows.slice(0, 3), pagination_complete: false}, {stopped: 'continuation_cursor_requires_review'});
  assert.match(main.querySelector('#results .list-footer').textContent, /3건 · 조회 범위 미완료/);
  assert.match(main.textContent, /일부만 성공했어요/);
  assert.match(main.textContent, /다음 페이지 정보를 확인할 수 없어/);
  assert.ok(main.querySelector('[data-action="history-export"]'), 'received pages can still be saved');

  await show('partial_success', {rows: [], pagination_complete: false});
  assert.match(main.textContent, /확인한 거래 내역이 아직 없어요/);
  assert.doesNotMatch(main.textContent, /조회 결과가 0건이에요/);

  await show('partial_success', {rows: null, pagination_complete: false}, {stopped: 'history_processing_error'});
  assert.equal(main.querySelector('[data-action="history-export"]'), null);
  assert.equal(main.querySelector('#results table'), null);

  await show('success', {rows: [], pagination_complete: true});
  assert.match(main.textContent, /조회 결과가 0건이에요/);
  assert.match(main.querySelector('#results .list-footer').textContent, /0건 · 조회 완료/);
});

test('a first Hometax login goes on to the user and business check; a later login does not', async t => {
  const ui = await setup(t, 'joint_certificate', 'login_required', {certificate_password: 'synthetic'});
  ui.row.institution = 'hometax'; ui.state.targets = [];
  await ui.actions.login(ui.ctx, {dataset: {login: 'login'}});
  assert.match(ui.asked[0][2], /사용자·사업장을 이어서 확인/);
  await ui.calls[0].options.onDone({outcome: 'rejected'});
  assert.equal(ui.calls.length, 1, 'a login that did not succeed asks for nothing more');
  await ui.calls[0].options.onDone({outcome: 'success'});
  assert.deepEqual(ui.calls.map(c => c.name), ['hometax.login', 'hometax.targets.discover']);
  ui.state.targets = [{id: 'target', login_id: 'login', kind: 'personal', display_name: '합성 대상'}];
  await ui.actions.login(ui.ctx, {dataset: {login: 'login'}});
  assert.doesNotMatch(ui.asked[1][2], /이어서 확인/);
  await ui.calls[2].options.onDone({outcome: 'success'});
  assert.equal(ui.calls.length, 3, 'a login with registered targets runs no extra check');
});

test('adding a connection always starts from the institution, whichever area was open', async t => {
  const ui = await setup(t);
  for (const mode of ['giro', 'corporate', 'tax']) {
    ui.state.mode = mode;
    await ui.actions['add-login-dialog'](ui.ctx);
    assert.deepEqual([...ui.document.querySelectorAll('[data-action="add-login-pick"]')].map(b => b.dataset.institution),
      ['hometax', 'hana', 'hana_corporate', 'giro']);
    assert.equal(ui.document.querySelector('#dialog-content input'), null, 'no password is asked before an institution is chosen');
  }
  await ui.actions['add-login-pick'](ui.ctx, ui.document.querySelector('[data-institution="hometax"]'));
  assert.equal(ui.document.querySelector('[name="institution"]').value, 'hometax');
  assert.match(ui.document.querySelector('#dialog-content button[type="submit"]').textContent, /추가하고 로그인/);
  assert.equal(ui.asked.length, 0);
  assert.equal(ui.calls.length, 0);
});

test('invoice amounts are suggested from quantity and unit price without overwriting typed values', async t => {
  const ui = await setup(t, 'joint_certificate', 'ready');
  const main = hometax(ui);
  main.innerHTML = ui.views.invoiceform(ui.ctx);
  const form = main.querySelector('form');
  assert.ok(main.querySelector('[data-action="signing"][data-login="login"]'), 'a missing issuing certificate can be set from here');
  assert.equal(form.querySelectorAll('.item-editor:not([hidden])').length, 1);
  ui.actions['invoice-add-item'](ui.ctx, form.querySelector('[data-action="invoice-add-item"]'));
  assert.equal(form.querySelectorAll('.item-editor:not([hidden])').length, 2);
  const field = name => form.querySelector(`[name="items.0.${name}"]`);
  field('quantity').value = '3'; field('unit_price').value = '3335';
  ui.actions['invoice-item-calc'](ui.ctx, field('unit_price'));
  assert.equal(field('supply_amount').value, '10005');
  assert.equal(field('tax_amount').value, '1000', 'a fraction of a won is dropped');
  field('tax_amount').value = '1001'; field('quantity').value = '4';
  ui.actions['invoice-item-calc'](ui.ctx, field('quantity'));
  assert.equal(field('supply_amount').value, '13340');
  assert.equal(field('tax_amount').value, '1001', 'a typed amount stays');
  assert.equal(ui.calls.length, 0);
});

for (const method of ['onesign', 'joint_certificate']) {
  test(`a successful ${method} bank login reads balances once, but not for a transfer or a failed login`, async t => {
    const ui = await setup(t, method, 'ready', {});
    const main = ui.document.querySelector('main');
    const names = () => ui.calls.map(c => c.name);
    const [loginJob, accountsJob] = method === 'onesign' ? ['hana.onesign.login', 'hana.onesign.accounts'] : ['hana.login', 'hana.accounts.list'];
    main.innerHTML = await ui.views.accounts(ui.ctx);
    await ui.actions.login(ui.ctx, {dataset: {login: 'login'}});
    assert.match(ui.asked[0][2], /잔액을 이어서 조회/, 'the dialog says so before any password is typed');
    await ui.calls[0].options.onDone({outcome: 'rejected'});
    await ui.calls[0].options.onDone({outcome: 'success', local: {stopped: 'session_not_saved'}});
    assert.deepEqual(names(), [loginJob], 'a login that did not succeed asks for nothing more');
    await ui.calls[0].options.onDone({outcome: 'success'});
    assert.deepEqual(names(), [loginJob, accountsJob]);
    assert.equal(ui.redraws.at(-1), ui.ctx, 'the login redraws as its own action, so the balance result still reaches the screen');
    assert.equal(ui.calls[1].options.panel, 'job-login');
    if (method === 'onesign') assert.match(ui.asked[1][2], /저장소 암호가 한 번 더/);

    // From a screen that does not list this login's accounts the query runs quietly.
    main.innerHTML = await ui.views.history(ui.ctx);
    await ui.calls[0].options.onDone({outcome: 'success'});
    assert.equal(ui.calls[2].name, accountsJob);
    assert.equal(ui.calls[2].options.panel, undefined, 'the open screen is left as it is');
    await ui.calls[2].options.onDone({status: 'finished', outcome: 'unknown', local: {}});
    assert.match(main.querySelector('.page-error').textContent, /로그인 뒤 잔액 조회 결과: 결과 미확인/);

    const before = ui.calls.length;
    await ui.actions.login(ui.ctx, {dataset: {login: 'login', reason: 'transfer_login_required'}});
    assert.doesNotMatch(ui.asked.at(-1)[2], /잔액을 이어서 조회/);
    await ui.calls.at(-1).options.onDone({outcome: 'success'});
    assert.equal(ui.calls.length, before + 1, 'a login opened to send a transfer reads no balances');
    ui.state.view = 'transfer';
    await ui.actions.login(ui.ctx, {dataset: {login: 'login'}});
    await ui.calls.at(-1).options.onDone({outcome: 'success'});
    assert.equal(ui.calls.length, before + 2);
    ui.state.view = 'accounts'; ui.row.readiness = 'login_required';
    await ui.actions.login(ui.ctx, {dataset: {login: 'login'}});
    await ui.calls.at(-1).options.onDone({outcome: 'success'});
    assert.equal(ui.calls.length, before + 3, 'without a usable session nothing more is requested');
  });
}

test('a session past its idle limit shows as logged out and offers only a login', async t => {
  const ui = await setup(t, 'onesign', 'ready');
  ui.state.idleExpired = true;
  const main = ui.document.querySelector('main');
  for (const view of ['accounts', 'settings']) {
    main.innerHTML = await ui.views[view](ui.ctx);
    assert.match(main.textContent, /로그아웃됨/);
    assert.doesNotMatch(main.textContent, /세션 있음|로그인됨\s*확인/);
    ownLogin(ui, view, '로그인');
    assert.equal(main.querySelector('[data-action="accounts-query"]'), null);
  }
  assert.equal(ui.calls.length, 0);
});

test('an idle hometax connection shows logout and offers login instead of discovery', async t => {
  const ui = await setup(t, 'joint_certificate', 'ready');
  ui.row.institution = 'hometax';
  ui.state.idleExpired = true;
  const main = ui.document.querySelector('main');
  main.innerHTML = await ui.views.settings(ui.ctx);
  assert.match(main.textContent, /로그아웃됨/);
  assert.equal(main.querySelector('[data-action="login"]').textContent, '로그인');
  assert.equal(main.querySelector('[data-action="discover"]'), null);
  assert.match(main.querySelector('.connection-settings').textContent, /로그인 자동 연장꺼짐켜기/, 'the browser switch, as on the other connections');
  assert.equal(ui.calls.length, 0);
});

test('automatic login extension is one switch for the browser and says what it does for each login', async t => {
  const ui = await setup(t, 'onesign', 'ready');
  const main = ui.document.querySelector('main');
  main.innerHTML = await ui.views.accounts(ui.ctx);
  const toggle = main.querySelector('[data-action="auto-extend-toggle"]');
  assert.equal(toggle.getAttribute('role'), 'switch');
  assert.equal(toggle.getAttribute('aria-checked'), 'false');
  main.innerHTML = await ui.views.settings(ui.ctx);
  assert.match(main.querySelector('.connection-settings').textContent, /로그인 자동 연장꺼짐켜기/);
  await ui.actions['auto-extend-toggle'](ui.ctx, toggle);
  assert.equal(ui.state.autoExtend, true);
  for (const [extension, text] of [['on', /자동 연장 켜짐/], ['locked', /저장소 암호를 기억해 두어야 자동 연장돼요/],
    ['unsupported', /연장 요청이 아직 없어 자동 연장하지 않아요/], ['stopped', /자동 연장 중단됨/]]) {
    ui.state.extension = extension;
    for (const view of ['accounts', 'settings']) {
      main.innerHTML = await ui.views[view](ui.ctx);
      assert.match(main.textContent, text);
    }
  }
  for (const [institution, method] of [['hana_corporate', 'id_password'], ['giro', 'pin'], ['hometax', 'joint_certificate']]) {
    Object.assign(ui.row, {institution, method});
    ui.state.extension = 'on';
    main.innerHTML = await ui.views.settings(ui.ctx);
    assert.match(main.querySelector('.connection-settings').textContent, /로그인 자동 연장자동 연장 켜짐끄기/);
  }
  Object.assign(ui.row, {institution: 'hana', method: 'onesign'});
  main.innerHTML = await ui.views.accounts(ui.ctx);
  assert.equal(main.querySelector('[data-action="auto-extend-toggle"]').getAttribute('aria-checked'), 'true');
  await ui.actions['auto-extend-toggle'](ui.ctx, toggle);
  assert.equal(ui.state.autoExtend, false);
  assert.equal(ui.calls.length, 0, 'the switch itself sends nothing to the bank');
  assert.equal(ui.asked.length, 0);
});

test('the activity list leaves out login extensions unless asked', async t => {
  const ui = await setup(t);
  const main = ui.document.querySelector('main');
  ui.state.params = {};
  main.innerHTML = await ui.views.activity(ui.ctx);
  assert.equal(ui.apiCalls.at(-1), ACTIVITY);
  assert.match(main.querySelector('.list-footer').textContent, /로그인 연장 기록은 숨겼어요/);
  assert.equal(main.querySelector('[data-action="activity-more"]'), null, 'a short first page offers no older rows');
  ui.actions['activity-extensions'](ui.ctx, main.querySelector('[data-action="activity-extensions"]'));
  assert.equal(JSON.stringify(ui.changed.at(-1)), JSON.stringify(['activity', {extensions: true}]));
  ui.state.params = {extensions: true};
  main.innerHTML = await ui.views.activity(ui.ctx);
  assert.equal(ui.apiCalls.at(-1), '/jobs?limit=50');
});

test('the activity list filters on the server and adds older pages under the rows shown', async t => {
  const ui = await setup(t);
  const main = ui.document.querySelector('main');
  const row = i => ({id: 'job-' + i, name: 'cli.hana', title: 'CLI 실행', origin: 'cli', status: 'finished', outcome: 'unknown',
    created_at: 1790000000 - i, command: ['hana', 'accounts'], local: {exit_code: 0}});
  ui.state.listed = path => path.includes('before=') ? [row(50), row(51)] : Array.from({length: 50}, (_, i) => row(i));
  ui.state.params = {area: 'giro', origin: 'cli'};
  main.innerHTML = await ui.views.activity(ui.ctx);
  assert.equal(ui.apiCalls.at(-1), ACTIVITY + '&area=giro&origin=cli');
  assert.equal(main.querySelector('#activity-area').value, 'giro');
  assert.equal(main.querySelector('#activity-origin').value, 'cli');
  assert.equal(main.querySelectorAll('.operation-row').length, 50);
  assert.match(main.querySelector('.list-footer').textContent, /전송 승인\(--send\) 여부, 종료코드만/);
  const more = main.querySelector('[data-action="activity-more"]');
  await ui.actions['activity-more'](ui.ctx, more);
  assert.equal(ui.apiCalls.at(-1), `${ACTIVITY}&area=giro&origin=cli&before=${1790000000 - 49}`);
  assert.equal(main.querySelectorAll('.operation-row').length, 52, 'older rows join the ones already shown');
  assert.equal(main.querySelector('[data-action="activity-more"]'), null);
  assert.match(main.querySelector('#activity-more').textContent, /더 이전 기록은 없어요/);
  main.querySelector('#activity-origin').value = 'web';
  ui.actions['activity-filter'](ui.ctx, main.querySelector('#activity-origin'));
  assert.equal(JSON.stringify(ui.changed.at(-1)), JSON.stringify(['activity', {area: 'giro', origin: 'web'}]));
  ui.state.listed = () => [];
  main.innerHTML = await ui.views.activity(ui.ctx);
  assert.match(main.querySelector('.empty-state').textContent, /조건에 맞는 작업 기록이 없어요/);
});

test('a login is extended by hand with its own job, and only where its module has one', async t => {
  const ui = await setup(t, 'onesign', 'ready', {vault_passphrase: 'synthetic'});
  await ui.actions['login-menu'](ui.ctx, {dataset: {login: 'login'}});
  assert.equal(ui.document.querySelector('[data-run="extend"]'), null, 'no extension job, no menu item');
  ui.state.extensionJob = 'hana.onesign.session.extend';
  await ui.actions['login-menu'](ui.ctx, {dataset: {login: 'login'}});
  await ui.actions.extend(ui.ctx, ui.document.querySelector('[data-run="extend"]'));
  assert.deepEqual(ui.calls.map(c => c.name), ['hana.onesign.session.extend']);
  assert.equal(ui.asked[0][3].store, 'synthetic', 'a personal OneSign extension opens its store');
  Object.assign(ui.row, {institution: 'giro', method: 'pin'});
  ui.state.extensionJob = 'giro.session.extend';
  await ui.actions.extend(ui.ctx, {dataset: {login: 'login'}});
  assert.equal(ui.calls[1].name, 'giro.session.extend');
  assert.equal(ui.asked.length, 1, 'no passphrase for a module that needs none');
});

test('ledger rows show dates, times and the direction of each amount, and their detail uses plain names', async t => {
  const ui = await setup(t, 'onesign', 'ready');
  const main = ui.document.querySelector('main');
  const job = {id: 'history', name: 'hana.onesign.history.list', login_id: 'login', target_id: 'target', status: 'finished', outcome: 'success',
    result: {pagination_complete: true, rows: [
      {date: '20261007', time: '181656', type: '대체', name: '합성 출금', amount: 1500, balance: 8500, currency: 'KRW', variation: 'decrease', extra: null, memo: ''},
      {date: '20261006', time: '090000', type: '타행이체', name: '합성 입금', amount: 10000, balance: 10000, currency: 'KRW', variation: 'increase', extra: null, memo: ''},
      {date: '합성 원문', time: null, type: '기타', name: '방향 없음', amount: 7, balance: 10000, currency: 'KRW', variation: 'none', extra: null, memo: ''}]}};
  ui.state.cache.set('hana.onesign.history.list||target|', job);
  ui.state.params = {};
  main.innerHTML = await ui.views.history(ui.ctx);
  const cells = [...main.querySelectorAll('#results tbody tr')].map(tr => [...tr.children].map(td => td.textContent));
  assert.deepEqual(cells, [['2026-10-07', '18:16:56', '대체', '합성 출금', '-1,500', '8,500'],
    ['2026-10-06', '09:00:00', '타행이체', '합성 입금', '+10,000', '10,000'],
    ['합성 원문', '', '기타', '방향 없음', '7', '10,000']], 'a value of another shape and an unmarked amount stay as received');
  assert.equal(main.querySelectorAll('#results td.incoming').length, 1);
  ui.actions.row(ui.ctx, main.querySelector('#results tr[data-row]'));
  const dialog = ui.document.querySelector('#detail-dialog');
  assert.deepEqual([...dialog.querySelectorAll('.summary-line > span')].map(n => n.textContent),
    ['거래일자', '거래시각', '구분', '내용', '입출금', '금액', '잔액', '통화']);
  assert.match(dialog.textContent, /출금/);
  assert.doesNotMatch(dialog.textContent, /variation|amount|decrease|기관 응답의 필드명/);
  assert.equal(ui.calls.length, 0, 'opening a row asks the bank for nothing');
});

test('transfer rows use the field names this project reads and leave the rest to the row detail', async t => {
  const ui = await setup(t, 'onesign', 'ready');
  const main = ui.document.querySelector('main');
  const job = {id: 'inquiry', name: 'hana.onesign.inquiry.history', login_id: 'login', target_id: 'target', status: 'finished', outcome: 'success',
    result: {rows: [{achvChnlNm: '합성 채널', chnlSvcCd: 'S00', lstTrscDt: '20261002', lstTrscTm: '101500', rcvAcctNo: '00012345',
      rcvBnkNm: '합성은행', rmteNm: '합성 수취인', trscAmt: '1234500', trscDt: '20261001', trscStNm: '완료', trscTm: '093000'}]}};
  ui.state.cache.set('hana.onesign.inquiry.history||target|', job);
  ui.state.params = {};
  main.innerHTML = await ui.views.inquiry(ui.ctx);
  assert.deepEqual([...main.querySelectorAll('#results th')].map(n => n.textContent),
    ['거래일자', '거래시각', '받는 분', '입금은행', '입금계좌번호', '이체금액', '처리 상태']);
  assert.deepEqual([...main.querySelectorAll('#results tbody td')].map(n => n.textContent),
    ['2026-10-01', '09:30:00', '합성 수취인', '합성은행', '00012345', '1,234,500', '완료']);
  const opened = () => {
    ui.actions.row(ui.ctx, main.querySelector('#results tr[data-row]'));
    return ui.document.querySelector('#detail-dialog');
  };
  const named = dialog => Object.fromEntries([...dialog.querySelector('.summary-lines').querySelectorAll(':scope > .summary-line')]
    .map(line => [line.querySelector('span').textContent, line.querySelector('strong').textContent]));
  let dialog = opened();
  assert.deepEqual(named(dialog), {거래구분: '합성 채널', 처리일자: '2026-10-02', 처리시각: '10:15:00', 입금계좌번호: '00012345', 입금은행: '합성은행',
    '받는 분': '합성 수취인', 이체금액: '1,234,500', 거래일자: '2026-10-01', '처리 상태': '완료', 거래시각: '09:30:00'});
  assert.match(dialog.querySelector('details.verdict summary').textContent, /그 밖의 항목 1개/, 'a field the bank shows under no name stays as sent');
  assert.match(dialog.querySelector('.folded-fields').textContent, /chnlSvcCdS00/);
  // The bank names the last date by the transfer's state; a state it has no name for keeps the field name.
  const row = job.result.rows[0];
  for (const [state, kind, name] of [['완료', '즉시이체', '이체일자'], ['오류', '합성 채널', '오류일자'], ['취소', '합성 채널', '취소일자']]) {
    Object.assign(row, {trscStNm: state, achvChnlNm: kind});
    main.innerHTML = await ui.views.inquiry(ui.ctx);
    assert.equal(named(opened())[name], '2026-10-02', state);
  }
  for (const state of ['대기', 'constructor']) {
    Object.assign(row, {trscStNm: state});
    main.innerHTML = await ui.views.inquiry(ui.ctx);
    dialog = opened();
    assert.match(dialog.querySelector('.folded-fields').textContent, /lstTrscDt2026-10-02/, state);
  }
  assert.match(dialog.querySelector('.folded-fields').textContent, /lstTrscDt2026-10-02.*lstTrscTm10:15:00/s);
  assert.match(dialog.querySelector('details.verdict summary').textContent, /그 밖의 항목 3개/);
  // Rows of a shape this project does not read keep the generic table and the bank's own names.
  job.result.rows = [{anyNm: '합성', otherDt: '20260101'}];
  main.innerHTML = await ui.views.inquiry(ui.ctx);
  assert.deepEqual([...main.querySelectorAll('#results th')].map(n => n.textContent), ['anyNm', 'otherDt']);
  assert.match(main.querySelector('#results tbody').textContent, /20260101/);
});

test('an empty security screen says what to do, and a CLI record says whether it carried the send approval', async t => {
  const ui = await setup(t, 'onesign', 'ready');
  const main = ui.document.querySelector('main');
  main.innerHTML = await ui.views.security(ui.ctx);
  assert.match(main.querySelector('#results .empty-state').textContent, /조회 항목을 고르고 조회하세요/);
  const row = local => ({id: 'cli', name: 'cli.hana', title: 'CLI 실행', origin: 'cli', status: 'finished', outcome: 'unknown',
    created_at: 1790000000, command: ['hana', 'transfer', 'execute'], local});
  ui.state.params = {};
  for (const [local, shown] of [[{exit_code: 0, send_requested: true}, /전송 승인\(--send\)종료코드 0/],
    [{exit_code: 0, send_requested: false}, /전송 승인 없음종료코드 0/], [{exit_code: 0}, /^CLI 실행 기록종료코드 0$/]]) {
    ui.state.listed = () => [row(local)];
    main.innerHTML = await ui.views.activity(ui.ctx);
    assert.match(main.querySelector('.operation-row .pill-row').textContent, shown);
  }
  assert.equal(ui.calls.length, 0);
});

test('an adapter reason code reads in words and a message from the institution stays as received', async t => {
  const ui = await setup(t, 'joint_certificate', 'ready');
  ui.row.institution = 'hometax'; ui.state.targets[0].kind = 'business';
  const main = ui.document.querySelector('main');
  const job = reason => ({id: 'invoice', name: 'hometax.invoice.list', login_id: 'login', target_id: 'target', status: 'finished',
    outcome: 'unknown', input: {direction: 'sales'}, service_verdict: {reason}, result: null});
  ui.state.params = {};
  ui.state.cache.set('hometax.invoice.list||target|sales', job('original_action_not_observed'));
  main.innerHTML = await ui.views.invoices(ui.ctx);
  assert.match(main.querySelector('#results .scope-note').textContent, /\(홈택스 화면의 조회 요청을 관측하지 못함\)/);
  assert.doesNotMatch(main.textContent, /original_action_not_observed/);
  ui.state.cache.set('hometax.invoice.list||target|sales', job('합성 기관 안내문'));
  main.innerHTML = await ui.views.invoices(ui.ctx);
  assert.match(main.querySelector('#results .scope-note').textContent, /\(합성 기관 안내문\)/);
});
