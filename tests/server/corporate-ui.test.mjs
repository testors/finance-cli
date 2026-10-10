import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule, SyntheticModule} from 'node:vm';
import {JSDOM} from 'jsdom';

const root = new URL('../../src/finance_cli/server/static/', import.meta.url);
async function setup(t) {
  const dom = new JSDOM('<main></main><div id="job-panel"></div><div id="corporate-results"></div><dialog id="detail-dialog"><div id="dialog-content"></div></dialog><div id="toast"></div>',
    {url: 'http://127.0.0.1:8740', runScripts: 'outside-only'});
  t.after(() => dom.window.close());
  dom.window.HTMLDialogElement.prototype.close = function () { this.open = false; };
  dom.window.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  const context = dom.getInternalVMContext();
  const state = {logins: [], targets: [], credentials: [], cache: new Map(), rows: {}, params: {}, vaults: {}};
  const calls = [], requests = [], changes = [];
  const responses = new Map();
  const lookup = id => state.logins.find(row => row.id === id);
  const api = {get: async path => {
    requests.push({method: 'get', path});
    if (responses.has(path)) return responses.get(path);
    if (path === '/credentials') return {credentials: state.credentials};
    if (path === '/corporate/options') return {settings: ['shared'], selected: 'shared'};
    if (path.startsWith('/jobs?')) return {jobs: []};
    if (path.endsWith('/corporate-ars')) return {code: '1234'};
    throw new Error('Unexpected path ' + path);
  }, post: async (path, value) => {
    requests.push({method: 'post', path, value});
    if (path === '/logins') return {id: 'corporate', institution: value.institution, method: value.method,
      credential: {ref: value.credential}, display_name: value.name, readiness: 'ready'};
    if (path.endsWith('/confirm')) return responses.get('confirmed');
    throw new Error('Unexpected post ' + path);
  }};
  const ctx = {run: async (name, fields, opts = {}) => {
    calls.push({name, fields, opts});
    const value = responses.get(name) || {id: 'job', name, status: 'finished', outcome: 'success', result: {session_id: 'saved'}};
    if (opts.key) state.cache.set(opts.key, value);
    await opts.onDone?.(value);
    return value;
  }, track: async job => responses.get('tracked') || job};
  const labels = {login_password: ['login_password', '기업 로그인 비밀번호'], certificate_password: ['certificate_password', '인증서 암호'],
    vault_passphrase: ['vault_passphrase', '저장소 암호'], pin: ['pin', 'PIN', '[0-9]{6}'],
    account_password: ['account_password', '계좌 비밀번호', '[0-9]{4}'], otp: ['otp', 'OTP', '[0-9]{6}']};
  const values = {state, login: lookup, target: id => state.targets.find(row => row.id === id), profile: () => null,
    scopeLogins: institution => state.logins.filter(r => !r.disabled && r.institution === institution), scopeTargets: () => state.targets,
    refreshModel: async () => {}, render: async () => {}, changeView: name => changes.push(name), jobState: () => '',
    secretFields: (fields, store) => fields.filter(([name]) => name !== 'vault_passphrase' || !state.vaults[store]), rememberField: () => '', applyRemember: async values => values,
    onesignStore: row => row?.method === 'onesign' ? row.credential.ref : null, SECRET_LABELS: labels};
  const app = new SyntheticModule(Object.keys(values), function () { for (const [k, v] of Object.entries(values)) this.setExport(k, v); }, {context});
  const apiModule = new SyntheticModule(['api'], function () { this.setExport('api', api); }, {context});
  const ui = new SourceTextModule(await readFile(new URL('ui.js', root), 'utf8'), {context});
  const module = new SourceTextModule(await readFile(new URL('corporate.js', root), 'utf8'), {context});
  await module.link(name => ({'./app.js': app, './api.js': apiModule, './ui.js': ui}[name]));
  await module.evaluate();
  return {...module.namespace, ctx, state, requests, calls, responses, changes, document: dom.window.document};
}

test('ID/password logs in and queries accounts in one form without credentials or session setup', async t => {
  const a = await setup(t);
  await a.corporateLogin(a.ctx);
  const form = a.document.querySelector('form');
  assert.deepEqual([...form.querySelectorAll('input')].map(i => i.name), ['credential', 'login_password']);
  assert.equal(form.querySelector('button[type=submit]').disabled, false);
  form.elements.credential.value = 'SyntheticId'; form.elements.login_password.value = 'SyntheticSecret';
  await a.corporateActions['corporate-login'](a.ctx, form);
  assert.deepEqual(a.calls.map(r => r.name), ['hana.corporate.login-idpw', 'hana.corporate.accounts']);
  assert.deepEqual(JSON.parse(JSON.stringify(a.calls[0].opts.secrets)), {login_password: 'SyntheticSecret'});
  assert.equal(JSON.stringify(a.requests.filter(r => r.method === 'post')).includes('SyntheticSecret'), false);
  assert.equal(form.elements.login_password.value, '');
  assert.deepEqual(a.changes, ['corporate-accounts']);
});

test('existing ID login does not recreate connections or ask for a certificate', async t => {
  const a = await setup(t);
  const row = {id: 'saved', institution: 'hana_corporate', method: 'id_password', credential: {ref: 'SYNTHETICID'}};
  a.state.logins.push(row);
  await a.corporateLogin(a.ctx, row);
  const form = a.document.querySelector('form');
  assert.equal(form.querySelector('[name=credential]'), null);
  form.elements.login_password.value = 'SyntheticSecret';
  await a.corporateActions['corporate-login'](a.ctx, form);
  assert.equal(a.requests.filter(r => r.method === 'post').length, 0);
});

test('certificate login selects the common vault without device registration', async t => {
  const a = await setup(t);
  a.state.credentials.push({type: 'joint', ref: 'shared'});
  await a.corporateLogin(a.ctx, null, 'joint_certificate');
  const form = a.document.querySelector('form');
  assert.equal(form.elements.credential.value, 'shared');
  assert.equal(form.querySelector('[name=login_password]'), null);
  form.elements.certificate_password.value = 'SharedPassword';
  await a.corporateActions['corporate-login'](a.ctx, form);
  assert.equal(a.calls[0].name, 'hana.corporate.login');
  assert.equal(a.calls[0].opts.secrets.certificate_password, 'SharedPassword');
  assert.equal(JSON.stringify(a.requests).includes('registration'), false);
});

test('ambiguous settings are selectable but a shared setting needs no extra field', async t => {
  const a = await setup(t);
  await a.corporateLogin(a.ctx);
  assert.equal(a.document.querySelector('[name=settings]'), null);
  a.responses.set('/corporate/options', {settings: ['one', 'two'], selected: null});
  await a.corporateLogin(a.ctx);
  assert.equal(a.document.querySelectorAll('[name=settings] option').length, 2);
});

test('personal accounts and login data never appear in corporate account choices', async t => {
  const a = await setup(t);
  a.state.logins.push({id: 'personal', institution: 'hana', display_name: '개인 전용'});
  a.state.targets.push({id: 'account', login_id: 'personal', kind: 'account', display_name: '개인 계좌'});
  const html = await a.corporateViews['corporate-accounts'](a.ctx);
  assert.doesNotMatch(html, /개인 전용|개인 계좌/);
  const history = await a.corporateViews['corporate-history'](a.ctx);
  assert.doesNotMatch(history, /개인 계좌/);
  assert.equal(a.calls.length, 0);
});

function account(a, kind = 'krw') {
  a.state.logins.push({id: 'corporate', institution: 'hana_corporate', display_name: '합성 기업', readiness: 'ready'});
  a.state.targets.push({id: 'account', login_id: 'corporate', kind: 'account', display_name: '합성 계좌',
    identity: {account_number: '000104', account_type: kind}});
}

test('history preserves exact amounts and shows completed empty versus partial pages', async t => {
  const a = await setup(t); account(a);
  const job = {id: 'history', status: 'finished', outcome: 'success', result: {transactions: [], complete: true}};
  a.state.cache.set('corporate:history:account', job);
  let html = await a.corporateViews['corporate-history'](a.ctx);
  assert.match(html, /조회 결과가 0건/); assert.match(html, /조회 완료/);
  job.result.complete = false;
  html = await a.corporateViews['corporate-history'](a.ctx);
  assert.doesNotMatch(html, /조회 결과가 0건/);
  assert.match(html, /조회가 완료된 것은 아니에요/);
  job.result = {complete: false, transactions: [{TRSC_DT: '20261001', TRSC_AMT: '000123456789012345.000', RMRK: '<script>bad</script>'}]};
  html = await a.corporateViews['corporate-history'](a.ctx);
  assert.match(html, /123,456,789,012,345/);
  assert.equal(a.state.rows['corporate-history'].rows[0].TRSC_AMT, '000123456789012345.000'); assert.match(html, /조회 범위 미완료/);
  assert.doesNotMatch(html, /<script>bad/);
  assert.equal(a.calls.length, 0, 'Opening a saved result never repeats the bank request');
});

test('history submits chosen foreign currency and loan sequence without manual pagination', async t => {
  const a = await setup(t); account(a, 'loan');
  a.document.querySelector('main').innerHTML = await a.corporateViews['corporate-history'](a.ctx);
  const form = a.document.querySelector('main form');
  form.elements.sequence.value = '0002'; form.elements.direction.value = '1';
  await a.corporateActions['corporate-history'](a.ctx, form);
  assert.equal(a.calls[0].fields.input.sequence, '0002');
  assert.equal('direction' in a.calls[0].fields.input, false);
  assert.equal(a.calls[0].name, 'hana.corporate.history');
});

test('transfer prepares recipient and amount without soliciting passwords', async t => {
  const a = await setup(t); account(a);
  a.document.querySelector('main').innerHTML = await a.corporateViews['corporate-transfer'](a.ctx);
  const form = a.document.querySelector('main form');
  assert.equal(form.querySelector('input[type=password]'), null);
  assert.equal(form.elements.bank.tagName, 'SELECT');
  form.elements.recipient.value = '000-201'; form.elements.amount.value = '1,000';
  await a.corporateActions['corporate-transfer'](a.ctx, form);
  assert.equal(a.calls[0].name, 'hana.corporate.transfer.prepare');
  assert.equal(a.calls[0].fields.input.amount, '1000');
  assert.equal(a.calls[0].fields.input.recipient, '000201');
  assert.equal(a.calls[0].opts.secrets, undefined);
});

test('duplicate preview requires acknowledgment and authentication asks only for the selected secret', async t => {
  const a = await setup(t);
  const prepared = {id: 'draft', status: 'awaiting_input', awaiting: {digest: 'draft-hash', next_step: 'execute', requires: [],
    preview: {items: [{DUP_YN: 'Y', RMTE_NM: '합성 수취인', RCV_ACCT_NO: '000201', TRNS_AMT: '1000'}]}}};
  a.responses.set('/jobs/draft', prepared);
  await a.corporateActions['corporate-transfer-open'](a.ctx, {dataset: {job: 'draft'}});
  let form = a.document.querySelector('form');
  assert.equal(form.checkValidity(), false);
  assert.equal(form.querySelector('input[type=password]'), null);
  assert.match(a.document.querySelector('dialog').textContent, /합성 수취인/);
  prepared.awaiting = {...prepared.awaiting, next_step: 'otp', requires: ['otp']};
  await a.corporateActions['corporate-transfer-open'](a.ctx, {dataset: {job: 'draft'}});
  form = a.document.querySelector('form');
  assert.deepEqual([...form.querySelectorAll('input')].map(i => i.name), ['otp']);
});

test('ARS challenge is read only for the waiting job and requires an explicit completion action', async t => {
  const a = await setup(t);
  a.responses.set('/jobs/draft', {id: 'draft', status: 'awaiting_input', awaiting: {next_step: 'ars', requires: [], preview: {}}});
  await a.corporateActions['corporate-transfer-open'](a.ctx, {dataset: {job: 'draft'}});
  assert.match(a.document.querySelector('dialog').textContent, /1234/);
  assert.match(a.document.querySelector('button[type=submit]').textContent, /전화 인증 완료/);
  assert.equal(a.requests.filter(r => r.method === 'post').length, 0);
  assert.equal(a.calls.length, 0);
});

test('new corporate OneSign login reuses an unlocked common vault', async t => {
  const a = await setup(t);
  a.state.credentials.push({type: 'onesign', ref: 'unlocked'}, {type: 'onesign', ref: 'locked'});
  a.state.vaults.unlocked = true;
  await a.corporateLogin(a.ctx, null, 'onesign');
  assert.equal(a.document.querySelector('[name=vault_passphrase]'), null);
  assert.ok(a.document.querySelector('[name=pin]'));
  await a.corporateActions['corporate-login-credential'](a.ctx, {value: 'locked'});
  assert.ok(a.document.querySelector('[name=vault_passphrase]'));
});

test('unsent preparation offers cancellation and sent results offer only result lookup', async t => {
  const a = await setup(t);
  const job = {id: 'draft', name: 'hana.corporate.transfer.prepare', status: 'finished', result: {preparation_available: true, transfer_sent: false}};
  a.responses.set('/jobs/draft', job);
  await a.corporateActions['corporate-transfer-open'](a.ctx, {dataset: {job: 'draft'}});
  assert.ok(a.document.querySelector('[data-action=corporate-transfer-cancel]'));
  assert.equal(a.document.querySelector('[data-action=corporate-transfer-result]'), null);
  job.result.transfer_sent = true;
  await a.corporateActions['corporate-transfer-open'](a.ctx, {dataset: {job: 'draft'}});
  assert.equal(a.document.querySelector('[data-action=corporate-transfer-cancel]'), null);
  assert.ok(a.document.querySelector('[data-action=corporate-transfer-result]'));
});

test('separate incoming and outgoing fields retain zero without hiding the withdrawal', async t => {
  const a = await setup(t); account(a, 'fund');
  a.state.cache.set('corporate:history:account', {result: {complete: true, transactions: [
    {TRSC_DT: '20261001', RCV_AMT_CTT: '0.000', PAYM_AMT_CTT: '123456.789', TRSC_AF_BAL_CTT: '100.123'}]}});
  const html = await a.corporateViews['corporate-history'](a.ctx);
  assert.match(html, /입금액/); assert.match(html, /출금액/);
  assert.match(html, /123,456.789/); assert.match(html, /100.123/);
});

test('screens ask for each result by job name with its login or account, so other jobs cannot hide it', async t => {
  const a = await setup(t); account(a);
  await a.corporateViews['corporate-accounts'](a.ctx);
  await a.corporateViews['corporate-history'](a.ctx);
  await a.corporateViews['corporate-transfer'](a.ctx);
  // Filtered on the server before its limit, not picked out of the newest jobs of every kind.
  assert.deepEqual(a.requests.filter(r => r.path.startsWith('/jobs?')).map(r => r.path), [
    '/jobs?name=hana.corporate.accounts&login_id=corporate&limit=1', '/jobs?name=hana.corporate.history&target_id=account&limit=1',
    '/jobs?name=hana.corporate.transfer.prepare&limit=20']);
});
