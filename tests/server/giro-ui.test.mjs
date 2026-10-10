import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule, SyntheticModule} from 'node:vm';
import {JSDOM} from 'jsdom';

const root = new URL('../../src/finance_cli/server/static/', import.meta.url);
async function setup(t) {
  const dom = new JSDOM('<main></main><dialog id="detail-dialog"><div id="dialog-content"></div></dialog><div id="toast"></div>',
    {url: 'http://127.0.0.1:8740', runScripts: 'outside-only'});
  t.after(() => dom.window.close());
  dom.window.HTMLDialogElement.prototype.close = function () { this.open = false; };
  dom.window.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  const context = dom.getInternalVMContext();
  const row = {id: 'giro', institution: 'giro', method: 'pin', readiness: 'ready', display_name: '합성 지로'};
  const state = {logins: [row], params: {}, rows: {}, cache: new Map()};
  const calls = [], requests = [], asked = [], paths = [], responses = new Map(), jobs = [];
  const api = {get: async path => { paths.push(path); return path.startsWith('/jobs?') ? {jobs} : responses.get(path); }, post: async (path, value) => {
    requests.push({path, value: JSON.parse(JSON.stringify(value))});
    return path === '/logins' ? row : responses.get(path);
  }};
  const values = {state, login: id => state.logins.find(r => r.id === id), askSecrets: async (...args) => {
    asked.push(args); return state.cancel ? null : {pin: '654321'};
  }, refreshModel: async () => {}, render: async () => {}, changeView: () => {}, jobState: () => ''};
  const app = new SyntheticModule(Object.keys(values), function () { for (const [k, v] of Object.entries(values)) this.setExport(k, v); }, {context});
  const apiModule = new SyntheticModule(['api'], function () { this.setExport('api', api); }, {context});
  const ui = new SourceTextModule(await readFile(new URL('ui.js', root), 'utf8'), {context});
  const module = new SourceTextModule(await readFile(new URL('giro.js', root), 'utf8'), {context});
  await module.link(name => ({'./app.js': app, './api.js': apiModule, './ui.js': ui}[name]));
  await module.evaluate();
  const ctx = {run: async (name, fields, opts = {}) => {
    calls.push({name, fields, opts});
    const job = responses.get(name) || {id: 'job', outcome: 'success', result: {session_id: 'session'}};
    await opts.onDone?.(job); return job;
  }, track: async (job, opts) => { await opts.onDone?.(job); return job; }};
  const add = job => { jobs.unshift(job); responses.set('/jobs/' + job.id, job); };
  return {...module.namespace, ctx, row, state, calls, asked, requests, paths, responses, jobs, add, document: dom.window.document};
}

test('PIN login uses registered connection with no certificate/account setup or automatic query', async t => {
  const a = await setup(t);
  await a.giroLogin(a.ctx);
  assert.deepEqual(a.calls.map(c => c.name), ['giro.login']);
  assert.equal(a.calls[0].opts.secrets.pin, '654321');
  assert.equal(a.requests.length, 0);
  assert.match(a.asked[0][1][0][1], /6자리/);
  a.state.cancel = true;
  await a.giroLogin(a.ctx);
  assert.equal(a.calls.length, 1);
});

test('new login creates only a PIN connection and never persists PIN in its metadata', async t => {
  const a = await setup(t); a.state.logins = [];
  await a.giroLogin(a.ctx);
  assert.deepEqual(a.requests[0], {path: '/logins', value: {institution: 'giro', method: 'pin', name: '모바일지로'}});
  assert.equal(JSON.stringify(a.requests).includes('654321'), false);
});

test('recipient lookup and validation errors explain the pre-PIN stop without retry', async t => {
  const a = await setup(t);
  for (const issue of ['recipient_public_lookup_failed', 'recipient_validation_failed', 'recipient_validation_incomplete']) {
    a.responses.set('giro.login', {id: 'login', outcome: 'unknown', result: {session_saved: false},
      local: {stage: 'recipient.validate', processing_issues: [issue], session_saved: false}});
    await a.giroLogin(a.ctx);
    assert.match(a.document.querySelector('#dialog-content').textContent, /인증서·폐지목록.*PIN 인증 전에 중단/);
    assert.doesNotMatch(a.document.querySelector('#dialog-content').textContent, /654321/);
  }
  assert.deepEqual(a.calls.map(c => c.name), ['giro.login', 'giro.login', 'giro.login']);
  assert.equal(a.requests.length, 0);
});

test('bill screen uses Korean headers, exact amount, deadline, and opaque selection', async t => {
  const a = await setup(t);
  a.add({id: 'bills', name: 'giro.bills.list', login_id: 'giro', input: {tax_type: 'national'}, outcome: 'success',
    result: {complete: true, bills: [{ref: '0', tax_type: 'national', tax_name: '<script>합성세</script>', issuer: '합성기관',
      amount_raw: '9,007,199,254,740,999', due_date: '2026-10-31', electronic_number: '****1234'}]}});
  a.document.querySelector('main').innerHTML = await a.giroViews['giro-live'](a.ctx);
  const page = a.document.querySelector('main');
  assert.match(page.textContent, /9,007,199,254,740,999원/);
  assert.match(page.textContent, /납부기한/);
  assert.match(page.textContent, /2026-10-31/);
  assert.equal(page.querySelector('script'), null);
  assert.equal(page.querySelector('[data-action="giro-payment-options"]').dataset.ref, '0');
  assert.equal(a.calls.length, 0);
});

test('311 no-bills guidance is distinct from successful empty, null and incomplete lists', async t => {
  const a = await setup(t);
  const job = {id: 'bills', name: 'giro.bills.list', login_id: 'giro', input: {tax_type: 'national'}, outcome: 'rejected',
    result: {complete: false, no_bills_reported: true, bills: null}};
  a.add(job);
  let html = await a.giroViews['giro-live'](a.ctx);
  assert.match(html, /납부할 고지가 없어요/); assert.match(html, /고지내용 없음/);
  assert.doesNotMatch(html, /표시 0건|조회된 고지가 없어요|처리하지 않았어요/);
  job.outcome = 'success'; job.result = {complete: true, bills: []};
  html = await a.giroViews['giro-live'](a.ctx);
  assert.match(html, /조회된 고지가 없어요/);
  job.result = {complete: false, bills: null};
  html = await a.giroViews['giro-live'](a.ctx);
  assert.match(html, /고지 목록을 확인하지 못했어요/);
  assert.doesNotMatch(html, /조회된 고지가 없어요/);
});

test('account choice shows alias and never asks for a password before immutable review', async t => {
  const a = await setup(t);
  a.add({id: 'bills', login_id: 'giro'});
  a.responses.set('giro.payment.options', {id: 'options', outcome: 'success', result: {amount: '2000000',
    bill: {tax_type: 'national', due_date: '2026-10-31'}, accounts: [{index: 1, availability: 'available',
      account_alias: '합성 생활비', bank_name: '합성은행', account_masked: '****5678'},
      {index: 2, availability: 'outside_bank_hours', account_alias: '사용 불가'}]}});
  await a.giroActions['giro-payment-options'](a.ctx, {dataset: {job: 'bills', ref: '0'}});
  const form = a.document.querySelector('form');
  assert.match(form.textContent, /합성 생활비 · 합성은행 · \*\*\*\*5678/);
  assert.equal(form.querySelectorAll('option').length, 1);
  assert.equal(form.querySelector('input[type=password]'), null);
  assert.deepEqual(a.calls.map(c => c.name), ['giro.payment.options']);
});

test('payment confirmation names the same login PIN, sends fixed digest once and clears fields', async t => {
  const a = await setup(t);
  const job = {id: 'pay', name: 'giro.payment.prepare', login_id: 'giro', status: 'awaiting_input',
    awaiting: {digest: 'fixed', requires: ['account_password', 'pin'], preview: {tax_type: 'national',
      amount: '2000000', account_alias: '합성 생활비', account_masked: '****5678'}}};
  a.add(job);
  await a.giroActions['giro-payment-open'](a.ctx, {dataset: {job: 'pay'}});
  const form = a.document.querySelector('form');
  assert.match(a.document.body.textContent, /로그인할 때 사용한/);
  form.elements.account_password.value = '5678'; form.elements.pin.value = '654321';
  a.responses.set('/jobs/pay/confirm', {...job, status: 'finished', outcome: 'success', result: {payment_attempted: true}});
  await a.giroActions['giro-payment-confirm'](a.ctx, form);
  assert.deepEqual(a.requests[0], {path: '/jobs/pay/confirm', value: {confirmation: 'fixed', secrets: {account_password: '5678', pin: '654321'}}});
  assert.equal(form.elements.pin.value, ''); assert.equal(form.elements.account_password.value, '');
  assert.match(a.document.body.textContent, /기관의 납부 성공 응답/);
  assert.equal(a.calls.length, 0);
  assert.equal(JSON.stringify(a.state).includes('654321'), false);
});

test('a logged-out screen offers no query; without a connection it offers the first login', async t => {
  const a = await setup(t);
  a.row.readiness = 'login_required';
  const main = a.document.querySelector('main');
  const views = ['giro-live', 'giro-receipts', 'giro-accounts'];
  for (const view of views) {
    main.innerHTML = await a.giroViews[view](a.ctx);
    // The shell's notice under the heading carries the login of an existing connection.
    assert.equal(main.querySelector('[data-action="giro-login"]'), null);
    assert.equal(main.querySelector('button[type="submit"]'), null);
    assert.equal(main.querySelector('[data-action="giro-accounts-query"]'), null);
    assert.doesNotMatch(main.textContent, /조회를 누르세요|조회하세요/);
  }
  // An earlier result stays in view after the logout.
  a.add({id: 'bills', name: 'giro.bills.list', login_id: 'giro', input: {tax_type: 'national'}, outcome: 'success',
    result: {complete: true, bills: [{ref: '0', tax_name: '합성세', amount_raw: '1,000', electronic_number: '****1234'}]}});
  main.innerHTML = await a.giroViews['giro-live'](a.ctx);
  assert.match(main.textContent, /합성세/);
  a.state.logins = [];
  for (const view of views) {
    main.innerHTML = await a.giroViews[view](a.ctx);
    assert.ok(main.querySelector('.empty-state [data-action="giro-login"]'));
    assert.equal(main.querySelector('button[type="submit"]'), null);
  }
  assert.equal(a.calls.length, 0);
});

test('receipts default to the last month, paging keeps the shown period, and waiting payments are listed', async t => {
  const a = await setup(t);
  const main = a.document.querySelector('main');
  const day = ago => new Date(Date.now() + 9 * 3600000 - ago * 86400000).toISOString().slice(0, 10);
  main.innerHTML = await a.giroViews['giro-receipts'](a.ctx);
  assert.equal(main.querySelector('[name="start_date"]').value, day(30));
  assert.equal(main.querySelector('[name="end_date"]').value, day(0));
  assert.equal(main.querySelector('[name="page"]').type, 'hidden');
  a.add({id: 'receipts', name: 'giro.receipts.list', login_id: 'giro', outcome: 'success',
    input: {start_date: '2026-08-01', end_date: '2026-08-31', page: 2},
    result: {complete: true, page_navi: {currentPage: 2, totalPage: 3}, receipts: [{ref: '0', issuer: '합성기관', paid_date: '20260810', amount_raw: '1,000', payment_type: ''}]}});
  a.add({id: 'pay', name: 'giro.payment.prepare', login_id: 'giro', status: 'awaiting_input', created_at: 1790000000});
  main.innerHTML = await a.giroViews['giro-receipts'](a.ctx);
  // The paid date reads as a date, and the amount stands apart from the muted line.
  assert.equal(main.querySelector('.setting-row .meta').textContent, '2026-08-10');
  assert.equal(main.querySelector('.setting-row .row-amount').textContent, '1,000원');
  const [previous, next] = main.querySelectorAll('[data-action="giro-receipts-page"]');
  assert.equal(previous.dataset.page, '1');
  assert.equal(next.dataset.page, '3');
  assert.equal(main.querySelector('[data-action="giro-payment-open"]').dataset.job, 'pay');
  main.querySelector('[name="start_date"]').value = '2026-01-01';
  await a.giroActions['giro-receipts-page'](a.ctx, next);
  assert.equal(JSON.stringify(a.calls[0].fields.input), JSON.stringify({start_date: '2026-08-01', end_date: '2026-08-31', page: 3}));
});


test('receipt null responses remain visible and distinct from empty lists and rejection', async t => {
  const a = await setup(t);
  const job = {id: 'receipts', name: 'giro.receipts.list', login_id: 'giro', outcome: 'success',
    input: {start_date: '2026-04-12', end_date: '2026-10-09', page: 1}, result: {receipts: null}};
  a.add(job);
  let html = await a.giroViews['giro-receipts'](a.ctx);
  assert.match(html, /기관 응답에 납부내역 목록이 없어요/);
  assert.doesNotMatch(html, /이 페이지에 납부내역이 없어요|giro-receipts-page/);
  assert.equal(job.result.receipts, null);
  job.result.receipts = [];
  html = await a.giroViews['giro-receipts'](a.ctx);
  assert.match(html, /이 페이지에 납부내역이 없어요/);
  job.result.receipts = null; job.outcome = 'rejected';
  html = await a.giroViews['giro-receipts'](a.ctx);
  assert.match(html, /납부내역 목록을 확인하지 못했어요/);
  assert.doesNotMatch(html, /기관 응답에 납부내역 목록이 없어요/);
  job.outcome = 'success'; job.input.page = 2;
  html = await a.giroViews['giro-receipts'](a.ctx);
  assert.match(html, /납부내역 목록을 확인하지 못했어요/);
  assert.equal(a.calls.length, 0);
});

test('each screen asks for its own job name and login, so other jobs cannot hide its result', async t => {
  const a = await setup(t);
  const main = a.document.querySelector('main');
  a.add({id: 'national', name: 'giro.bills.list', login_id: 'giro', outcome: 'success', input: {tax_type: 'national'},
    result: {complete: true, bills: []}});
  a.state.params.tax_type = 'local';
  main.innerHTML = await a.giroViews['giro-live'](a.ctx);
  assert.match(main.textContent, /세금 종류를 고르고 고지 조회를 누르세요/, 'another tax type is not shown as this one');
  main.innerHTML = await a.giroViews['giro-accounts'](a.ctx);
  main.innerHTML = await a.giroViews['giro-receipts'](a.ctx);
  // Filtered on the server before its limit; the tax type is matched among the recent bill queries.
  assert.deepEqual(a.paths, ['/jobs?name=giro.bills.list&login_id=giro&limit=50', '/jobs?name=giro.accounts.list&login_id=giro&limit=1',
    '/jobs?name=giro.receipts.list&login_id=giro&limit=1', '/jobs?name=giro.payment.prepare&login_id=giro&limit=20']);
});

test('a logged-out list offers no payment, and the confirmation carries the warnings a transfer has', async t => {
  const a = await setup(t);
  const main = a.document.querySelector('main');
  a.add({id: 'bills', name: 'giro.bills.list', login_id: 'giro', outcome: 'success', input: {tax_type: 'national'},
    result: {complete: true, bills: [{ref: '0', tax_name: '합성세', issuer: '합성기관', amount_raw: '1,000', due_date: '2026-10-31', electronic_number: '0000'}]}});
  main.innerHTML = await a.giroViews['giro-live'](a.ctx);
  assert.ok(main.querySelector('[data-action="giro-payment-options"]'));
  a.row.readiness = 'login_required';
  main.innerHTML = await a.giroViews['giro-live'](a.ctx);
  assert.equal(main.querySelector('[data-action="giro-payment-options"]'), null, 'the bill stays in view without a button that cannot work');
  assert.match(main.querySelector('.list-footer').textContent, /로그인하면 이 목록에서 납부할 수 있어요/);
  a.add({id: 'pay', name: 'giro.payment.prepare', login_id: 'giro', status: 'awaiting_input', verification: 'live_partial',
    awaiting: {digest: 'digest', requires: ['account_password'], expires_at: Date.now() / 1000 + 125, preview: {tax_type: 'national', amount: '1000'}}});
  await a.giroActions['giro-payment-open'](a.ctx, {dataset: {job: 'pay'}});
  const dialog = a.document.querySelector('#detail-dialog');
  assert.match(dialog.querySelector('.pill-row').textContent, /일부 실사용 확인되돌릴 수 없음/);
  assert.match(dialog.querySelector('.countdown').textContent, /^2분 0\d초$/, 'the time left to confirm is shown at once');
  assert.equal(a.calls.length, 0);
});
