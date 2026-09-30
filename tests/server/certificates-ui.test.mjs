import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule, SyntheticModule} from 'node:vm';
import {JSDOM} from 'jsdom';

const root = new URL('../../src/finance_cli/server/static/', import.meta.url);
const options = {hana: {settings: [{name: 'synthetic', version: '1.0.27'}], carriers: [
  {code: '4', name: 'SKT', terms_digest: 'skt-review', terms: [{title: 'SKT 필수 약관', urls: ['https://example.invalid/skt']}]},
  {code: '6', name: 'KT', terms_digest: 'kt-review', terms: [{title: 'KT 필수 약관', urls: ['https://example.invalid/kt']}]},
]}};

async function setup(t, result = {}, {lost = false} = {}) {
  const dom = new JSDOM('<dialog id="detail-dialog"><div id="dialog-content"></div></dialog><div id="toast"></div>',
    {url: 'http://127.0.0.1:8740', runScripts: 'outside-only'});
  t.after(() => dom.window.close());
  const {window} = dom;
  window.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  window.HTMLDialogElement.prototype.close = function () { this.open = false; };
  const context = dom.getInternalVMContext();
  const requests = [];
  context.fetch = async (path, init) => {
    const input = init.body && JSON.parse(init.body);
    requests.push({path, method: init.method, input});
    if (init.method === 'POST' && lost) throw new Error('Synthetic connection loss');
    let data;
    if (path === '/api/v1/certificates/options') data = options;
    else if (path === '/api/v1/credentials') data = {credentials: result.ready ? [{type: 'onesign', ref: 'synthetic'}] : []};
    else if (path === '/api/v1/jobs' && init.method === 'POST') data = {id: 'jb_synthetic', status: 'running'};
    else if (path === '/api/v1/jobs/jb_synthetic') data = {id: 'jb_synthetic', status: 'finished', outcome: 'success', result};
    else throw new Error('Unexpected API ' + path);
    return {ok: true, json: async () => data};
  };
  const app = new SyntheticModule(['state', 'refreshModel'], function () {
    this.setExport('state', {credentials: []});
    this.setExport('refreshModel', async () => {});
  }, {context, identifier: new URL('app.js', root).href});
  const modules = new Map([[app.identifier, app]]);
  async function load(url) {
    if (!modules.has(url)) modules.set(url, new SourceTextModule(await readFile(new URL(url), 'utf8'), {context, identifier: url}));
    return modules.get(url);
  }
  const module = await load(new URL('certificates.js', root).href);
  await module.link((specifier, parent) => load(new URL(specifier, parent.identifier).href));
  await module.evaluate();
  const actions = module.namespace.certificateActions;
  const document = window.document;
  const fill = (name, value) => { document.querySelector(`[name="${name}"]`).value = value; };
  const target = dataset => ({dataset});
  return {actions, document, window, requests, fill, target};
}

test('onboarding exposes three certificate types and accurately limits issuance', async t => {
  const ui = await setup(t);
  await ui.actions['certificate-add']();
  assert.match(ui.document.body.textContent, /공동인증서/);
  assert.match(ui.document.body.textContent, /금융인증서/);
  assert.match(ui.document.body.textContent, /하나인증서/);
  assert.match(ui.document.body.textContent, /신규 발급·클라우드 연결은 아직 미지원/);
  assert.equal(ui.document.querySelectorAll('[data-action="certificate-joint"]').length, 1);
  assert.equal(ui.document.querySelectorAll('[data-action="certificate-hana"]').length, 1);
});

test('phone carrier changes replace reviewed terms and clear consent', async t => {
  const ui = await setup(t);
  await ui.actions['certificate-hana-next']({}, ui.target({name: 'synthetic', stage: 'profile', job: 'jb_synthetic'}));
  const form = ui.document.querySelector('form');
  assert.equal(form.dataset.digest, 'skt-review');
  const checkbox = form.querySelector('[name="agree"]');
  checkbox.checked = true;
  const select = form.querySelector('[name="carrier"]');
  select.value = '6';
  await ui.actions['certificate-carrier']({}, select);
  assert.equal(form.dataset.digest, 'kt-review');
  assert.equal(checkbox.checked, false);
  assert.match(ui.document.querySelector('#certificate-terms').textContent, /KT 필수 약관/);
  assert.equal(ui.requests.filter(r => r.method === 'POST').length, 0);
});

test('driver identity inputs are required only in the driver branch', async t => {
  const ui = await setup(t);
  await ui.actions['certificate-hana-next']({}, ui.target({name: 'synthetic', stage: 'prepare-id', job: 'jb_synthetic'}));
  const driver = ui.document.querySelector('#certificate-driver');
  assert.ok(driver.hidden);
  assert.ok([...driver.querySelectorAll('input')].every(i => i.disabled));
  const select = ui.document.querySelector('[name="kind"]');
  select.value = 'driver';
  ui.actions['certificate-id-kind']({}, select);
  assert.ok(!driver.hidden);
  assert.ok([...driver.querySelectorAll('input')].every(i => i.required && !i.disabled));
  select.value = 'resident';
  ui.actions['certificate-id-kind']({}, select);
  assert.ok([...driver.querySelectorAll('input')].every(i => i.disabled));
  assert.equal(ui.document.querySelector('[name="send"]'), null);
});

test('issue sends approval and PIN as private inputs once, then offers completion', async t => {
  const ui = await setup(t, {certificate_issued: true, next_stage: 'complete', issuance_state: 'issued'});
  await ui.actions['certificate-hana-next']({}, ui.target({name: 'synthetic', stage: 'issue', job: 'jb_synthetic'}));
  const form = ui.document.querySelector('form');
  ui.fill('vault_passphrase', 'SYNTHETIC-private-vault');
  ui.fill('new_pin', '604928'); ui.fill('new_pin_confirmation', '604928'); ui.fill('issue_confirmation', '발급');
  form.querySelector('[name="send"]').checked = true;
  await ui.actions['certificate-hana-submit']({}, form);
  await ui.actions['certificate-hana-submit']({}, form);
  const sent = ui.requests.filter(r => r.method === 'POST');
  assert.equal(sent.length, 1);
  assert.equal(sent[0].input.name, 'hana.onesign.issue.issue');
  assert.equal(sent[0].input.input.send, true);
  assert.equal(sent[0].input.secrets.new_pin, '604928');
  assert.equal(sent[0].input.secrets.issue_confirmation, '발급');
  assert.equal(sent[0].input.input.new_pin, undefined);
  assert.equal(ui.document.querySelector('[data-stage="complete"]').textContent, '가입 완료 계속');
  assert.ok(!ui.document.body.innerHTML.includes('SYNTHETIC-private-vault'));
  assert.equal(ui.window.sessionStorage.length, 0);
  assert.equal(ui.window.localStorage.length, 0);
});

test('lost submission response does not allow a second request from the same form', async t => {
  const ui = await setup(t, {}, {lost: true});
  await ui.actions['certificate-hana-inspect']({}, ui.target({name: 'synthetic'}));
  const form = ui.document.querySelector('form');
  ui.fill('vault_passphrase', 'SYNTHETIC-private-vault');
  await ui.actions['certificate-hana-submit']({}, form);
  await ui.actions['certificate-hana-submit']({}, form);
  assert.equal(ui.requests.filter(r => r.method === 'POST').length, 1);
  assert.match(ui.document.querySelector('#certificate-error').textContent, /자동 재전송하지 않아요/);
  assert.equal(form.querySelector('[name="vault_passphrase"]').value, '');
});

test('NPKI and PFX format controls enable only the required file inputs', async t => {
  const ui = await setup(t);
  ui.actions['certificate-joint']();
  assert.equal(ui.document.querySelector('[name="private_key_file"]').disabled, true);
  assert.equal(ui.document.querySelector('[name="pfx_index"]').required, false);
  const select = ui.document.querySelector('[name="format"]');
  select.value = 'npki'; ui.actions['certificate-format']({}, select);
  assert.equal(ui.document.querySelector('[name="private_key_file"]').disabled, false);
  assert.equal(ui.document.querySelector('[name="pfx_index"]').disabled, true);
});


test('unconfigured issuance disables its own submit with a hidden enrollment form present', async t => {
  const ui = await setup(t);
  const original = options.hana.settings;
  options.hana.settings = [];
  try {
    ui.document.body.insertAdjacentHTML('afterbegin', '<form hidden id="enroll-form"><button type="submit">등록</button></form>');
    await ui.actions['certificate-hana']();
    assert.equal(ui.document.querySelector('[data-submit="certificate-hana-init"] button[type="submit"]').disabled, true);
    assert.equal(ui.document.querySelector('#enroll-form button').disabled, false);
  } finally { options.hana.settings = original; }
});
