/* Whole flows on the real screen modules, with a synthetic same-origin API in place of fetch.
   What is checked is what a person at the screen meets between a press and its result. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule} from 'node:vm';
import {JSDOM} from 'jsdom';

const root = new URL('../../src/finance_cli/server/static/', import.meta.url);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const TITLES = {'hana.onesign.login': '하나은행 하나인증서 로그인', 'hana.onesign.accounts': '하나은행 계좌 목록·잔액',
  'hana.transfer.prepare': '원화 이체', 'hometax.login': '홈택스 로그인'};

async function boot(t, {mode = 'banking', view = 'accounts', loggedIn = false} = {}) {
  const html = (await readFile(new URL('index.html', root), 'utf8')).replace(/<script[^>]*><\/script>/, '');
  const dom = new JSDOM(html, {url: 'http://127.0.0.1:8740/#' + view, runScripts: 'outside-only'});
  t.after(() => dom.window.close());
  const w = dom.window, context = dom.getInternalVMContext(), document = w.document;
  w.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  w.HTMLDialogElement.prototype.close = function () { this.open = false; this.dispatchEvent(new w.Event('close')); };
  w.Element.prototype.scrollTo = function () {};
  context.structuredClone = value => JSON.parse(JSON.stringify(value));
  const timeout = w.setTimeout.bind(w);
  context.setTimeout = (fn, ms, ...rest) => timeout(fn, ms >= 600 && ms <= 3100 ? 5 : ms, ...rest);   // only job polling is hurried
  w.sessionStorage.setItem('finance.mode', JSON.stringify(mode));
  const now = () => Date.now() / 1000, session = () => ({last_request_at: now(), idle_expires_at: now() + 590});
  const server = {jobs: new Map(), requests: [], serial: 0, delay: 60,
    logins: [{id: 'bank', institution: 'hana', method: 'onesign', readiness: loggedIn ? 'ready' : 'login_required', display_name: '합성 하나인증서',
      credential: {ref: 'main'}, current_session_id: loggedIn ? 's0' : null, session: loggedIn ? session() : null, disabled: false, revision: 1, signing: {}},
    {id: 'tax', institution: 'hometax', method: 'joint_certificate', readiness: 'login_required', display_name: '합성 홈택스',
      credential: {ref: 'personal'}, current_session_id: null, session: null, disabled: false, revision: 1, signing: {}}],
    targets: [{id: 'account', login_id: 'bank', kind: 'account', display_name: '합성 계좌', identity: {account_number: '12345678901234'}, disabled: false},
      {id: 'person', login_id: 'tax', kind: 'personal', display_name: '합성 개인', identity: {}, disabled: false}],
    last() { return [...this.jobs.values()].at(-1); },
    set(values) { Object.assign(this.last(), values); },
    finish(values = {}) {
      const job = this.last();
      Object.assign(job, {status: 'finished', outcome: 'success', observed_at: now(), local: {}, awaiting: null, ...values});
      if (job.name.endsWith('.login')) Object.assign(this.logins.find(l => l.id === job.login_id),
        {readiness: 'ready', current_session_id: 's' + (++this.serial), session: session()});
    }};
  const features = ['hana-accounts', 'hana-history', 'hana-transfer', 'hana-inquiry', 'hana-security', 'hometax-tax', 'hometax-invoice-query',
    'hometax-returns'].map(id => ({id, status: 'available', reasons: [], jobs: []}));
  features[0].jobs = Object.entries(TITLES).map(([name, title]) => ({name, title}));
  const route = async (method, path, body) => {
    server.requests.push(method + ' ' + path);
    if (path === '/auth/state') return [200, {enrolled: true, csrf_token: 'synthetic', mode: 'local'}];
    if (path === '/logins') return [200, {logins: server.logins, server_time: now()}];
    if (path === '/targets') return [200, {targets: server.targets}];
    if (path === '/capabilities') return [200, {features, jobs: []}];
    if (path === '/vaults') return [200, {vaults: [{name: 'main', unlocked: true}]}];
    if (path.startsWith('/jobs?')) return [200, {jobs: []}];
    if (path === '/jobs' && method === 'POST') {
      await sleep(server.delay);
      const job = {id: 'job' + (++server.serial), name: body.name, title: TITLES[body.name], status: 'queued', outcome: 'not_started',
        login_id: body.login_id, target_id: body.target_id || null, created_at: now(), local: {}, fixed: {}, attempt: {}, awaiting: null};
      server.jobs.set(job.id, job);
      return [202, job];
    }
    const found = server.jobs.get(path.split('/')[2]);
    if (path.endsWith('/confirm')) { await sleep(server.delay); Object.assign(found, {status: 'queued', awaiting: null}); return [200, found]; }
    if (path.startsWith('/jobs/')) return found ? [200, found] : [404, {error: 'job_not_found'}];
    if (method !== 'GET') { await sleep(server.delay); return [200, {}]; }
    return [200, {profiles: [], credentials: [], devices: [], id_cards: []}];
  };
  context.fetch = async (url, options = {}) => {
    const [status, value] = await route(options.method || 'GET', String(url).slice('/api/v1'.length), options.body && JSON.parse(options.body));
    return {ok: status < 400, status, json: async () => JSON.parse(JSON.stringify(value))};
  };
  const modules = new Map();
  const load = name => {
    if (!modules.has(name)) modules.set(name, readFile(new URL(name, root), 'utf8').then(source => new SourceTextModule(source, {context, identifier: name})));
    return modules.get(name);
  };
  const app = await load('app.js');
  await app.link(specifier => load(specifier.slice(2)));
  await app.evaluate();
  await sleep(40);
  const text = node => (node?.textContent || '').replace(/\s+/g, ' ').trim();
  const held = () => { const box = document.querySelector('#busy'); return box?.open ? [text(box.querySelector('#busy-title')), text(box.querySelector('#busy-status'))] : null; };
  const press = (label, scope = document.querySelector('#main')) => [...scope.querySelectorAll('button')].find(b => text(b).startsWith(label)).click();
  const dialog = () => document.querySelector('#detail-dialog').open ? text(document.querySelector('#dialog-title')) : null;
  const type = values => { for (const [name, value] of Object.entries(values)) document.querySelector(`[name="${name}"]`).value = value; };
  return {document, server, held, press, dialog, type, text, state: app.namespace.state, app: app.namespace,
    toast: () => text(document.querySelector('#toast')), submit: selector => document.querySelector(selector).requestSubmit()};
}

test('a bank login holds the screen from the moment its password is confirmed until its result', async t => {
  const ui = await boot(t);
  assert.equal(ui.held(), null);
  ui.press('로그인');
  await sleep(10);
  assert.equal(ui.dialog(), '합성 하나인증서 로그인');
  assert.equal(ui.held(), null, 'typing a password is not held');
  ui.type({pin: '000000'});
  ui.submit('#secret-form');
  await sleep(20);
  assert.equal(ui.dialog(), null);
  assert.deepEqual(ui.held(), ['하나은행 하나인증서 로그인', '접수 중'], 'held before the server has answered');
  await sleep(80);
  assert.deepEqual(ui.held(), ['하나은행 하나인증서 로그인', '대기 중']);
  ui.server.set({status: 'running'});
  await sleep(30);
  assert.deepEqual(ui.held(), ['하나은행 하나인증서 로그인', '실행 중']);
  ui.server.finish();
  await sleep(120);
  // The login is over and went on to its balance query, which is held under its own name.
  assert.deepEqual([...ui.server.jobs.values()].map(j => j.name), ['hana.onesign.login', 'hana.onesign.accounts']);
  assert.deepEqual(ui.held()?.[0], '하나은행 계좌 목록·잔액');
  ui.server.finish({result: {accounts: []}});
  await sleep(120);
  assert.equal(ui.held(), null);
});

test('a login from a screen that has no job line of its own is held and named all the same', async t => {
  const ui = await boot(t, {mode: 'tax', view: 'taxhome'});
  assert.equal(ui.document.querySelector('#job-panel'), null);
  ui.press('로그인');
  await sleep(10);
  ui.type({certificate_password: 'synthetic'});
  ui.submit('#secret-form');
  await sleep(20);
  assert.deepEqual(ui.held(), ['홈택스 로그인', '접수 중']);
  await sleep(80);
  ui.server.set({status: 'running'});
  await sleep(30);
  assert.deepEqual(ui.held(), ['홈택스 로그인', '실행 중']);
});

test('a transfer is held from the confirmation press to its result', async t => {
  const ui = await boot(t, {view: 'transfer', loggedIn: true});
  ui.type({account: '11122233344455', amount: '1000'});
  ui.submit('form[data-submit="transfer-prepare"]');
  await sleep(10);
  ui.type({account_password: '0000'});
  ui.submit('#secret-form');
  await sleep(20);
  assert.deepEqual(ui.held(), ['원화 이체', '접수 중']);
  await sleep(80);
  ui.server.set({status: 'awaiting_input', awaiting: {requires: [], digest: 'synthetic', next_step: 'execute', expires_at: Date.now() / 1000 + 600, preview: {}}});
  await sleep(60);
  assert.equal(ui.dialog(), '이 내용으로 보낼까요?');
  assert.equal(ui.held(), null, 'reading and confirming is not held');
  ui.submit('#confirm-form');
  await sleep(20);
  assert.deepEqual(ui.held(), ['원화 이체', ''], 'held at once, before the confirmation is answered');
  await sleep(80);
  ui.server.set({status: 'running'});
  await sleep(30);
  assert.equal(ui.dialog(), null);
  assert.deepEqual(ui.held(), ['원화 이체', '실행 중']);
  ui.server.finish({attempt: {sent: true}, step: 'execute'});
  await sleep(150);
  assert.equal(ui.held(), null);
  assert.equal(ui.dialog(), '이체 결과');
  assert.equal(ui.server.requests.filter(r => r.endsWith('/confirm')).length, 1);
});

test('a request that fails inside an action is said on the screen', async t => {
  const ui = await boot(t, {loggedIn: true});
  ui.document.querySelector('#main').insertAdjacentHTML('beforeend', '<button data-action="transfer-open" data-job="missing">이체 이어하기</button>');
  ui.press('이체 이어하기');
  await sleep(40);
  assert.match(ui.toast(), /job_not_found/);
  assert.match(ui.text(ui.document.querySelector('#main [role="alert"]')), /job_not_found/);
  assert.equal(ui.held(), null);
});

test('a table is marked for labelled rows as it arrives on a narrow screen, on the page and in a dialog', async t => {
  const ui = await boot(t);
  const table = '<div class="table-wrap"><table class="table data"><tbody><tr><td data-label="합성">1</td></tr></tbody></table></div>';
  ui.document.querySelector('#main').insertAdjacentHTML('beforeend', table);
  ui.document.querySelector('#dialog-content').innerHTML = table;
  await sleep(5);
  // jsdom lays nothing out, so the stage is as narrow as a screen can be.
  assert.equal(ui.document.querySelectorAll('.table-wrap.stacked').length, 2);
});

test('a login dialog leaves remembering the store passphrase to the user; the issuance wizard offers it chosen', async t => {
  const ui = await boot(t);
  const fields = [['vault_passphrase', '저장소 암호']];
  assert.match(ui.app.rememberField(fields, 'main'), /name="remember_vault">/);
  assert.match(ui.app.rememberField(fields, 'main', {chosen: true}), /name="remember_vault" checked>/);
  assert.equal(ui.app.rememberField([['pin', 'PIN']], 'main'), '');
});
