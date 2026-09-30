import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule, SyntheticModule} from 'node:vm';
import {JSDOM} from 'jsdom';

const root = new URL('../../src/finance_cli/server/static/', import.meta.url);
const ORDER = ['init', 'profile', 'authenticate', 'request-sms', 'verify-sms', 'consent', 'begin-id', 'prepare-id', 'identity', 'list-accounts', 'account', 'issue', 'complete'];
const REMOTE = new Set(['authenticate', 'request-sms', 'verify-sms', 'begin-id', 'identity', 'list-accounts', 'account', 'issue', 'complete']);
const options = {hana: {settings: [{name: 'synthetic', version: '1.0.27'}], carriers: [
  {code: '4', name: 'SKT', terms_digest: 'skt-review', terms: [{title: 'SKT 필수 약관', urls: ['https://example.invalid/skt']}]},
  {code: '6', name: 'KT', terms_digest: 'kt-review', terms: [{title: 'KT 필수 약관', urls: ['https://example.invalid/kt']}]},
]}};

const ACCOUNTS = [{choice: '0', label: '하나은행 123*****9012'}, {choice: '1', label: '하나은행 987*****3210'}];

const CARD = {name: 'resident-card', kind: 'resident', issue_date: '2020.02.29', saved_at: 1700000000};

test('stored identity rejection explains a mismatched name without resending', async t => {
  const ui = await setup(t, {stage:'identity', overrides:{inspect:{result:{next_stage:null,ready:false,
    identity_diagnostic:{input_checks:{name_matches_phone:false,name_is_document_label:true},requests:[
      {stage:'image',service_status:'accepted',image_accepted:true},
      {stage:'identity',service_status:'rejected',error_codes:['TEST456']}]}}}}});
  await ui.resume();
  assert.deepEqual(ui.names(), ['inspect']);
  assert.match(ui.document.body.textContent, /사진 접수 완료/);
  assert.match(ui.document.body.textContent, /은행 거절.*TEST456/);
  assert.match(ui.document.body.textContent, /성명 칸에 신분증 종류가 입력/);
  assert.doesNotMatch(ui.document.body.textContent, /완료 성공/);
  assert.equal(ui.form(), null);
});

test('account selection uses the stored bank list and waits for an explicit choice', async t => {
  const ui = await setup(t, {stage: 'account'}); await ui.resume();
  assert.deepEqual(ui.names(), ['inspect']);
  assert.equal(ui.document.querySelector('[name="account_number"]'), null);
  const select = ui.document.querySelector('[name="account_choice"]');
  assert.equal(select.value, '');
  assert.equal(select.options.length, 3);
  assert.match(select.textContent, /987\*+3210/);
  ui.fill('account_password', '6049'); await ui.submit();
  assert.deepEqual(ui.names(), ['inspect']);
  ui.fill('account_choice', '1'); await ui.submit();
  assert.deepEqual(ui.names(), ['inspect', 'account']);
  assert.deepEqual(ui.jobs()[1].input.secrets, {account_choice: '1', account_password: '6049'});
  assert.equal(ui.form().dataset.stage, 'issue');
});

test('an empty account list disables verification without a free-text fallback', async t => {
  const ui = await setup(t, {stage: 'account', overrides: {inspect: {result: {next_stage: 'account', accounts: []}}}});
  await ui.resume();
  assert.match(ui.document.body.textContent, /선택할 수 있는 발급용 본인계좌를 확인하지 못/);
  assert.equal(ui.form().querySelector('button[type="submit"]').disabled, true);
  assert.equal(ui.document.querySelector('[name="account_number"]'), null);
  assert.equal(ui.document.querySelector('[name="account_password"]'), null);
  assert.deepEqual(ui.names(), ['inspect']);
});

test('stored account mismatch explains the local stop without retrying', async t => {
  const ui = await setup(t, {stage: 'account', overrides: {inspect: {result: {next_stage: null,
    account_diagnostic: {selection_not_found: true, account_count: 6, password_verification_requested: false}}}}});
  await ui.resume();
  assert.match(ui.document.body.textContent, /본인계좌 목록 6개와 일치하지/);
  assert.match(ui.document.body.textContent, /비밀번호 검증 요청은 보내지 않았/);
  assert.deepEqual(ui.names(), ['inspect']);
});

test('closing after identity leaves account listing for an explicit resumed request', async t => {
  const ui = await setup(t, {stage: 'identity', closeAt: 'identity'}); await ui.resume(); await ui.submit();
  assert.deepEqual(ui.names(), ['inspect', 'identity']);
});

test('a lost account-list response never triggers password verification or a requery', async t => {
  const ui = await setup(t, {stage: 'identity', lost: 'list-accounts'}); await ui.resume(); await ui.submit();
  assert.deepEqual(ui.names(), ['inspect', 'identity', 'list-accounts']);
  assert.equal(ui.form(), null);
  assert.match(ui.document.body.textContent, /자동 재전송하지 않아요/);
});

async function setup(t, {stage = 'init', overrides = {}, lost = '', closeAt = '', unlockFailed = false, refreshFailed = false, cards = []} = {}) {
  const dom = new JSDOM('<dialog id="detail-dialog"><div id="dialog-content"></div></dialog><div id="toast"></div>',
    {url: 'http://127.0.0.1:8740', runScripts: 'outside-only'});
  t.after(() => dom.window.close());
  const {window} = dom, document = window.document;
  window.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  window.HTMLDialogElement.prototype.close = function () { this.open = false; };
  const context = dom.getInternalVMContext();
  const requests = [], cached = {}, completed = new Map(), selectedFiles = new WeakMap();
  const model = {credentials: [], vaults: {}};
  let next = stage, created = stage !== 'init';
  const snapshot = () => ({next_stage: next, ready: next === null, certificate_issued: next === 'complete' || next === null,
    ...(next === 'account' ? {accounts: ACCOUNTS} : {}),
    ...(next === 'consent' ? {terms_digest: 'observed-signup-terms', terms: [{title: '가입 필수 약관', urls: ['https://example.invalid/signup']}]} : {})});
  // jsdom has no file picker. Model a selected native File in FormData without browser storage.
  context.FormData = class extends window.FormData {
    constructor(form) { super(form); if (selectedFiles.has(form)) this.set('image', selectedFiles.get(form)); }
  };
  context.fetch = async (path, init) => {
    const input = init.body && JSON.parse(init.body);
    requests.push({path, method: init.method, input});
    let data;
    if (path.startsWith('/api/v1/vaults/') && path.endsWith('/unlock')) {
      if (unlockFailed) return {ok: false, status: 400, json: async () => ({error: 'store_authentication_failed'})};
      cached[decodeURIComponent(path.split('/')[4])] = true;
      data = {unlocked: true};
    } else if (path === '/api/v1/vaults') data = {vaults: Object.entries(cached).map(([name, unlocked]) => ({name, unlocked}))};
    else if (path === '/api/v1/certificates/options') data = options;
    else if (path === '/api/v1/credentials') data = {credentials: created ? [{type: 'onesign', ref: 'synthetic'}] : []};
    else if (path === '/api/v1/id-cards') data = {id_cards: cards, network_used: false};
    else if (path === '/api/v1/jobs' && init.method === 'POST' && input.name === 'idcard.add') {
      const id = 'jb_' + (completed.size + 1);
      completed.set(id, {id, name: input.name, status: 'finished', outcome: 'success', local: {}, attempt: {},
        result: {name: input.input.name, kind: 'resident', saved: true, network_used: false}});
      data = {id, status: 'running'};
    } else if (path === '/api/v1/jobs' && init.method === 'POST') {
      const current = input.name.split('.').at(-1), id = 'jb_' + (completed.size + 1);
      if (current === lost) throw new Error('Synthetic connection loss');
      if (current !== 'inspect') assert.equal(current, next, 'only the next service stage may execute');
      const result = current === 'inspect' ? snapshot() : {next_stage: ORDER[ORDER.indexOf(current) + 1] || null,
        created: current === 'init', ready: current === 'complete', certificate_issued: ['issue', 'complete'].includes(current)};
      if (current === 'list-accounts') result.accounts = ACCOUNTS;
      if (current === 'verify-sms') Object.assign(result, {terms_digest: 'observed-signup-terms', terms: [{title: '가입 필수 약관', urls: ['https://example.invalid/signup']}]});
      const final = {id, name: input.name, status: 'finished', outcome: 'success', result, local: {}, attempt: {}, ...overrides[current]};
      if (current !== 'inspect' && final.outcome === 'success') { next = final.result?.next_stage; created = true; }
      completed.set(id, final);
      data = {id, status: 'running'};
    } else if (path.startsWith('/api/v1/jobs/')) {
      data = completed.get(path.split('/').at(-1));
      assert.ok(data, 'only accepted jobs are polled');
      if (data.name.endsWith('.' + closeAt)) document.querySelector('#dialog-content').innerHTML = '';
    } else throw new Error('Unexpected API ' + path);
    return {ok: true, json: async () => data};
  };
  const app = new SyntheticModule(['state', 'refreshModel', 'applyRemember', 'secretFields', 'rememberField'], function () {
    this.setExport('state', model);
    this.setExport('refreshModel', async () => { if (refreshFailed) throw new Error('Synthetic refresh loss'); model.vaults = {...cached}; });
    this.setExport('secretFields', (fields, store) => fields.filter(([name]) => name !== 'vault_passphrase' || !model.vaults[store]));
    this.setExport('rememberField', fields => fields.length ? '<label><input type="checkbox" name="remember_vault" checked>암호 기억</label>' : '');
    this.setExport('applyRemember', async (values, store) => {
      const remember = values.remember_vault === 'on'; delete values.remember_vault;
      if (remember && values.vault_passphrase) {
        await modules.get(new URL('api.js', root).href).namespace.api.post('/vaults/' + encodeURIComponent(store) + '/unlock', {passphrase: values.vault_passphrase});
        model.vaults[store] = true; delete values.vault_passphrase;
      }
      return values;
    });
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
  const form = () => document.querySelector('[data-submit="certificate-hana-submit"]');
  const fill = (name, value) => { document.querySelector(`[name="${name}"]`).value = value; };
  const check = name => { document.querySelector(`[name="${name}"]`).checked = true; };
  const jobs = () => requests.filter(r => r.path === '/api/v1/jobs' && r.method === 'POST');
  const names = () => jobs().map(r => r.input.name.split('.').at(-1));
  const submit = () => actions['certificate-hana-submit']({}, form());
  const resume = async ({unlocked = true} = {}) => {
    cached.synthetic = unlocked;
    await actions['certificate-hana-inspect']({}, {dataset: {name: 'synthetic'}});
  };
  const phone = () => { fill('name', 'synthetic'); fill('vault_passphrase', 'SYNTHETIC-private-vault'); fill('customer_name', '합성 이름'); fill('birth7', '9001011'); fill('phone', '01000000000'); check('agree'); };
  const identity = () => {
    if (document.querySelector('[name="agree"]')) check('agree');
    fill('id_name', '합성 이름'); fill('issueDate', '2020.02.29'); fill('birthDate', '900101'); fill('resident', '1000000'); check('identity_confirmed');
    const selected = new window.File(['SYNTHETIC-JPEG'], 'synthetic.jpg', {type: 'image/jpeg'});
    selectedFiles.set(form(), selected);
    document.querySelector('[name="image"]').required = false; // Native picker validity is represented by selectedFiles above.
  };
  const pin = () => { fill('new_pin', '604928'); fill('new_pin_confirmation', '604928'); };
  const saved = () => {
    if (document.querySelector('[name="agree"]')) check('agree');
    fill('idcard_passphrase', 'SYNTHETIC-card-passphrase'); check('saved_confirmed');
  };
  const photo = target => {
    selectedFiles.set(target, new window.File(['SYNTHETIC-JPEG'], 'synthetic.jpg', {type: 'image/jpeg'}));
    target.querySelector('[name="image"]').required = false;
  };
  return {actions, document, window, requests, cached, form, fill, check, jobs, names, submit, resume, phone, identity, pin, saved, photo};
}

test('onboarding exposes supported certificate types and preserves joint import controls', async t => {
  const ui = await setup(t);
  await ui.actions['certificate-add']();
  assert.match(ui.document.body.textContent, /공동인증서/);
  assert.match(ui.document.body.textContent, /금융인증서/);
  assert.match(ui.document.body.textContent, /신규 발급·클라우드 연결은 아직 미지원/);
  assert.equal(ui.document.querySelectorAll('[data-action="certificate-hana"]').length, 1);
  ui.actions['certificate-joint']();
  assert.equal(ui.document.querySelector('[name="private_key_file"]').disabled, true);
  assert.equal(ui.document.querySelector('[name="pfx_index"]').required, false);
  const select = ui.document.querySelector('[name="format"]'); select.value = 'npki'; ui.actions['certificate-format']({}, select);
  assert.equal(ui.document.querySelector('[name="private_key_file"]').disabled, false);
  assert.equal(ui.document.querySelector('[name="pfx_index"]').disabled, true);
});

test('issuance completes in four screens with one phone request and no intermediate confirmations', async t => {
  const ui = await setup(t);
  await ui.actions['certificate-hana']();
  assert.equal(ui.document.querySelectorAll('.certificate-steps li').length, 4);
  ui.phone(); const first = ui.form(); await ui.submit();
  assert.deepEqual(ui.names(), ORDER.slice(0, 4));
  assert.equal(ui.form().dataset.stage, 'verify-sms');
  assert.equal(ui.document.querySelector('[name="vault_passphrase"]'), null);
  assert.equal(ui.document.querySelector('[name="send"]'), null);
  ui.fill('sms', '012345'); await ui.submit();
  assert.equal(ui.form().dataset.stage, 'consent');
  assert.match(ui.document.querySelector('[aria-current="step"]').textContent, /2.*신분증/);
  assert.match(ui.document.body.textContent, /가입 필수 약관/);
  ui.identity(); await ui.submit();
  assert.equal(ui.form().dataset.stage, 'account');
  ui.fill('account_choice', '0'); ui.fill('account_password', '6049'); await ui.submit();
  assert.equal(ui.form().dataset.stage, 'issue');
  ui.pin(); await ui.submit();
  assert.deepEqual(ui.names(), ORDER);
  assert.match(ui.document.body.textContent, /발급과 가입이 완료/);
  assert.equal(ui.form(), null);
  await ui.actions['certificate-hana-submit']({}, first);
  assert.deepEqual(ui.names(), ORDER);
  assert.equal(new Set(ui.jobs().map(r => r.input.idempotency_key)).size, ORDER.length);
  for (const row of ui.jobs()) {
    const current = row.input.name.split('.').at(-1);
    assert.equal(row.input.input.send, REMOTE.has(current) ? true : undefined);
    assert.equal(row.input.secrets.vault_passphrase, current === 'init' ? 'SYNTHETIC-private-vault' : undefined);
    assert.equal(row.input.secrets.remember_vault, undefined);
    assert.equal(JSON.stringify(row.input.input).includes('6049'), false);
  }
  const byStage = Object.fromEntries(ui.jobs().map(r => [r.input.name.split('.').at(-1), r.input.secrets]));
  assert.deepEqual(Object.keys(byStage['verify-sms']), ['sms']);
  assert.deepEqual(Object.keys(byStage['prepare-id']), ['identity_capture']);
  assert.deepEqual(Object.keys(byStage.account), ['account_choice', 'account_password']);
  assert.equal(byStage.consent.agreement, 'observed-signup-terms');
  assert.equal(byStage.issue.issue_confirmation, '발급');
  assert.deepEqual(Object.keys(byStage.complete), []);
  assert.equal(ui.window.localStorage.length, 0); assert.equal(ui.window.sessionStorage.length, 0);
});

test('carrier changes replace terms and require fresh consent before any submission', async t => {
  const ui = await setup(t); await ui.actions['certificate-hana'](); ui.phone();
  const select = ui.document.querySelector('[name="carrier"]'); select.value = '6';
  await ui.actions['certificate-carrier']({}, select);
  assert.equal(ui.form().dataset.digest, 'kt-review');
  assert.match(ui.document.querySelector('#certificate-terms').textContent, /KT 필수 약관/);
  assert.equal(ui.document.querySelector('[name="agree"]').checked, false);
  await ui.submit(); assert.deepEqual(ui.names(), []);
});

test('driver fields and reviewed photo are sent only with the local preparation job', async t => {
  const ui = await setup(t, {stage: 'prepare-id'}); await ui.resume();
  const driver = ui.document.querySelector('#certificate-driver');
  assert.ok(driver.hidden); assert.ok([...driver.querySelectorAll('input')].every(i => i.disabled));
  const select = ui.document.querySelector('[name="kind"]'); select.value = 'driver'; ui.actions['certificate-id-kind']({}, select);
  assert.ok(!driver.hidden); assert.ok([...driver.querySelectorAll('input')].every(i => i.required && !i.disabled));
  ui.identity(); for (const [key,value] of Object.entries({regionCode: '11',driver1:'20',driver2:'123456',driver3:'78'})) ui.fill(key,value);
  await ui.submit();
  assert.deepEqual(ui.names(), ['inspect','prepare-id','identity','list-accounts']);
  const capture = JSON.parse(ui.jobs()[1].input.secrets.identity_capture);
  assert.equal(capture.kind, 'driver'); assert.equal(capture.fields.driver2, '123456'); assert.equal(capture.confirmation, '본인 신분증');
  assert.deepEqual(ui.jobs()[2].input.secrets, {});
});

for (const [stage, next, sent] of [['authenticate','verify-sms',['authenticate','request-sms']], ['identity','account',['identity','list-accounts']], ['complete',null,['complete']]]) {
  test(`resume from ${stage} skips completed operations and requires a fresh action for remaining requests`, async t => {
    const ui = await setup(t, {stage}); await ui.resume();
    assert.deepEqual(ui.names(), ['inspect']);
    if (stage === 'identity') assert.equal(ui.document.querySelector('[name="image"]'), null);
    await ui.submit(); assert.deepEqual(ui.names(), ['inspect', ...sent]);
    if (next) assert.equal(ui.form().dataset.stage, next); else assert.match(ui.document.body.textContent, /발급과 가입이 완료/);
  });
}

test('a finished certificate opens the completed state without reissuing', async t => {
  const ui = await setup(t, {stage: null}); await ui.resume();
  assert.deepEqual(ui.names(), ['inspect']); assert.equal(ui.form(), null);
  assert.match(ui.document.body.textContent, /발급과 가입이 완료/);
});

test('unlock once to resume, and a later lock is reflected before continuing', async t => {
  const ui = await setup(t, {stage: 'account'}); await ui.resume({unlocked:false});
  assert.deepEqual(ui.names(), []); ui.fill('vault_passphrase','SYNTHETIC-private-vault'); await ui.submit();
  assert.deepEqual(ui.names(), ['inspect']); assert.equal(ui.document.querySelector('[name="vault_passphrase"]'), null);
  await ui.resume({unlocked:false}); assert.ok(ui.document.querySelector('[name="vault_passphrase"]'));
});

test('opting out remembers the passphrase only through the current screen batch', async t => {
  const ui = await setup(t); await ui.actions['certificate-hana'](); ui.phone();
  ui.document.querySelector('[name="remember_vault"]').checked = false; await ui.submit();
  assert.deepEqual(ui.names(), ORDER.slice(0,4));
  assert.ok(ui.jobs().every(r => r.input.secrets.vault_passphrase === 'SYNTHETIC-private-vault'));
  assert.ok(ui.document.querySelector('[name="vault_passphrase"]'));
  assert.equal(ui.requests.some(r => r.path.endsWith('/unlock')), false);
});

test('failure to cache after creation keeps the successful batch and warns before the next input', async t => {
  const ui = await setup(t, {unlockFailed:true}); await ui.actions['certificate-hana'](); ui.phone(); await ui.submit();
  assert.deepEqual(ui.names(), ORDER.slice(0,4));
  assert.equal(ui.form().dataset.stage, 'verify-sms'); assert.match(ui.document.body.textContent, /암호를 기억하지 못했어요/);
  assert.ok(ui.jobs().every(r => r.input.secrets.vault_passphrase === 'SYNTHETIC-private-vault'));
});

for (const [outcome, local] of [['rejected',{stopped:'synthetic_rejection'}], ['unknown',{}], ['success',{stopped:'local_processing_error'}]]) {
  test(`${outcome} with ${JSON.stringify(local)} stops the batch before SMS`, async t => {
    const ui = await setup(t, {overrides:{authenticate:{outcome,local}}});
    await ui.actions['certificate-hana'](); ui.phone(); await ui.submit();
    assert.deepEqual(ui.names(), ORDER.slice(0,3)); assert.equal(ui.form(), null);
    assert.match(ui.document.body.textContent, /발급 진행을 멈췄어요/);
  });
}

test('an unexpected next stage halts without changing the reported successful outcome', async t => {
  const ui = await setup(t, {overrides:{authenticate:{result:{next_stage:'consent'}}}});
  await ui.actions['certificate-hana'](); ui.phone(); await ui.submit();
  assert.deepEqual(ui.names(), ORDER.slice(0,3));
  assert.match(ui.document.body.textContent, /다음 진행 상태를 확인하지 못해/);
  assert.match(ui.document.body.textContent, /성공/);
});

test('a lost response cannot trigger another submission or the next service request', async t => {
  const ui = await setup(t, {lost:'authenticate'}); await ui.actions['certificate-hana'](); ui.phone();
  const form = ui.form(); await ui.submit(); await ui.actions['certificate-hana-submit']({},form);
  assert.deepEqual(ui.names(), ORDER.slice(0,3));
  assert.match(ui.document.body.textContent, /자동 재전송하지 않아요/);
  assert.equal(form.querySelector('[name="vault_passphrase"]').value, '');
});

test('closing during a request prevents subsequent requests in its batch', async t => {
  const ui = await setup(t, {closeAt:'authenticate'}); await ui.actions['certificate-hana'](); ui.phone(); await ui.submit();
  assert.deepEqual(ui.names(), ORDER.slice(0,3));
});

test('a double click during submission starts each operation just once', async t => {
  const ui = await setup(t); await ui.actions['certificate-hana'](); ui.phone();
  const form = ui.form();
  await Promise.all([ui.actions['certificate-hana-submit']({}, form), ui.actions['certificate-hana-submit']({}, form)]);
  assert.deepEqual(ui.names(), ORDER.slice(0,4));
});

test('closing after local creation still honors remembering the password without requesting SMS', async t => {
  const ui = await setup(t, {closeAt:'init'}); await ui.actions['certificate-hana'](); ui.phone(); await ui.submit();
  assert.deepEqual(ui.names(), ['init']); assert.equal(ui.cached.synthetic, true);
});

test('a PIN mismatch can be corrected before any issuance request', async t => {
  const ui = await setup(t, {stage:'issue'}); await ui.resume(); ui.pin(); ui.fill('new_pin_confirmation','904628');
  await ui.submit(); assert.deepEqual(ui.names(), ['inspect']);
  assert.match(ui.document.querySelector('#certificate-error').textContent, /PIN 확인이 달라요/);
  ui.fill('new_pin_confirmation','604928'); await ui.submit();
  assert.deepEqual(ui.names(), ['inspect','issue','complete']);
});

test('partial issuance preserves the certificate evidence and does not continue completion', async t => {
  const ui = await setup(t, {stage:'issue',overrides:{issue:{outcome:'partial_success',result:{certificate_issued:true},local:{stopped:'registration_failed'}}}});
  await ui.resume(); ui.pin(); await ui.submit();
  assert.deepEqual(ui.names(), ['inspect','issue']);
  assert.match(ui.document.body.textContent, /인증서 발급은 확인됐어요/);
  assert.match(ui.document.body.textContent, /부분 성공/);
});

test('a local photo error stops before identity and offers correction through saved progress', async t => {
  const ui = await setup(t, {stage:'consent', overrides:{'prepare-id':{outcome:'not_started',local:{stopped:'identity_jpeg_invalid'},result:null}}});
  await ui.resume(); ui.identity(); await ui.submit();
  assert.deepEqual(ui.names(), ['inspect','consent','begin-id','prepare-id']);
  assert.match(ui.document.body.textContent, /JPEG 사진을 읽을 수 없어요/);
  const edit = ui.document.querySelector('[data-action="certificate-hana-inspect"]');
  assert.equal(edit.textContent, '신분증 입력 수정'); await ui.actions['certificate-hana-inspect']({},edit);
  assert.equal(ui.form().dataset.stage, 'prepare-id');
  assert.deepEqual(ui.names(), ['inspect','consent','begin-id','prepare-id','inspect']);
});

test('issuance success survives a lost completion response and never repeats issuance', async t => {
  const ui = await setup(t, {stage:'issue', lost:'complete'}); await ui.resume(); ui.pin(); await ui.submit();
  assert.deepEqual(ui.names(), ['inspect','issue','complete']);
  assert.match(ui.document.body.textContent, /인증서 발급은 확인됐어요/);
});

test('a list refresh failure does not hide completed issuance', async t => {
  const ui = await setup(t, {stage:'issue', refreshFailed:true}); await ui.resume(); ui.pin(); await ui.submit();
  assert.deepEqual(ui.names(), ['inspect','issue','complete']);
  assert.match(ui.document.body.textContent, /발급과 가입이 완료/);
});

test('unconfigured new issuance disables only its own submit', async t => {
  const ui = await setup(t), original = options.hana.settings;
  const enrollment = ui.document.createElement('form'); enrollment.id = 'enroll-form'; enrollment.innerHTML = '<button type="submit">등록</button>'; ui.document.body.prepend(enrollment);
  try {
    options.hana.settings = []; await ui.actions['certificate-hana']();
    assert.equal(ui.form().querySelector('button[type="submit"]').disabled,true);
    assert.equal(enrollment.querySelector('button').disabled,false);
  } finally { options.hana.settings = original; }
});

test('new issuance suggests saving an ID card first, or counts the saved ones', async t => {
  const empty = await setup(t); await empty.actions['certificate-hana']();
  assert.equal(empty.document.querySelectorAll('[data-action="idcard-add"]').length, 1);
  const stocked = await setup(t, {cards: [CARD]}); await stocked.actions['certificate-hana']();
  assert.equal(stocked.document.querySelector('[data-action="idcard-add"]'), null);
  assert.match(stocked.document.body.textContent, /보관한 신분증 1개/);
});

test('a saved ID card replaces the photo form and only its name and passphrase are sent', async t => {
  const ui = await setup(t, {stage: 'consent', cards: [CARD]}); await ui.resume();
  const direct = ui.document.querySelector('#certificate-id-direct');
  assert.ok(direct.hidden); assert.ok([...direct.querySelectorAll('input, select')].every(i => i.disabled));
  assert.match(ui.document.querySelector('[name="id_source"]').textContent, /resident-card · 주민등록증 · 발급일 2020\.02\.29/);
  ui.saved(); await ui.submit();
  assert.deepEqual(ui.names(), ['inspect', 'consent', 'begin-id', 'prepare-id', 'identity', 'list-accounts']);
  const prepare = ui.jobs()[3].input;
  assert.equal(prepare.input.id_card, 'resident-card');
  assert.deepEqual(Object.keys(prepare.secrets), ['identity_capture']);
  assert.deepEqual(JSON.parse(prepare.secrets.identity_capture), {passphrase: 'SYNTHETIC-card-passphrase', confirmation: '본인 신분증'});
  assert.ok(ui.jobs().every(r => !JSON.stringify(r.input.input).includes('SYNTHETIC-card-passphrase')));
  assert.equal(ui.jobs()[4].input.input.id_card, undefined);
  assert.equal(ui.form().dataset.stage, 'account');
  assert.equal(ui.window.localStorage.length, 0); assert.equal(ui.window.sessionStorage.length, 0);
});

test('choosing direct entry restores the photo form for a card that is not saved', async t => {
  const ui = await setup(t, {stage: 'prepare-id', cards: [CARD]}); await ui.resume();
  const select = ui.document.querySelector('[name="id_source"]'); select.value = '';
  ui.actions['certificate-id-source']({}, select);
  assert.ok(ui.document.querySelector('#certificate-id-saved').hidden);
  assert.equal(ui.document.querySelector('[name="idcard_passphrase"]').disabled, true);
  assert.equal(ui.document.querySelector('[name="id_name"]').disabled, false);
  assert.ok([...ui.document.querySelectorAll('#certificate-driver input')].every(i => i.disabled));
  ui.identity(); await ui.submit();
  assert.deepEqual(ui.names(), ['inspect', 'prepare-id', 'identity', 'list-accounts']);
  assert.equal(ui.jobs()[1].input.input.id_card, undefined);
  assert.equal(JSON.parse(ui.jobs()[1].input.secrets.identity_capture).fields.resident, '1000000');
});

test('a wrong saved-card passphrase stops before identity and offers correction', async t => {
  const ui = await setup(t, {stage: 'prepare-id', cards: [CARD], overrides: {'prepare-id': {outcome: 'not_started',
    local: {stopped: 'incorrect_passphrase_or_damaged_id_card'}, result: null}}});
  await ui.resume(); ui.saved(); await ui.submit();
  assert.deepEqual(ui.names(), ['inspect', 'prepare-id']);
  assert.match(ui.document.body.textContent, /신분증 보관 암호가 맞지 않거나/);
  assert.equal(ui.document.querySelector('[data-action="certificate-hana-inspect"]').textContent, '신분증 입력 수정');
});

test('saving an ID card is one local job with the photo and numbers only in its secrets', async t => {
  const ui = await setup(t); ui.actions['idcard-add']();
  const form = ui.document.querySelector('[data-submit="idcard-save"]');
  ui.fill('name', 'resident-card'); ui.fill('idcard_passphrase', 'SYNTHETIC-card-passphrase');
  ui.fill('idcard_passphrase_confirmation', 'SYNTHETIC-card-passphrase');
  ui.fill('id_name', '합성 이름'); ui.fill('issueDate', '2020.02.29'); ui.fill('birthDate', '900101'); ui.fill('resident', '1000000');
  ui.check('identity_confirmed'); ui.photo(form);
  await ui.actions['idcard-save']({}, form);
  assert.equal(ui.jobs().length, 1);
  const job = ui.jobs()[0].input;
  assert.deepEqual([job.name, job.input], ['idcard.add', {name: 'resident-card'}]);
  assert.deepEqual(Object.keys(job.secrets).sort(), ['idcard_passphrase', 'identity_capture']);
  const capture = JSON.parse(job.secrets.identity_capture);
  assert.deepEqual([capture.kind, capture.fields.birthDate, capture.confirmation], ['resident', '900101', '본인 신분증']);
  assert.ok(capture.image.length > 0);
  assert.match(ui.document.body.textContent, /신분증을 암호화해 보관했어요/);
  assert.equal(ui.document.querySelectorAll('[data-action="certificate-hana"]').length, 1);
  assert.equal(ui.window.localStorage.length, 0); assert.equal(ui.window.sessionStorage.length, 0);
});

test('a mismatched ID card passphrase confirmation sends nothing', async t => {
  const ui = await setup(t); ui.actions['idcard-add']();
  const form = ui.document.querySelector('[data-submit="idcard-save"]');
  ui.fill('name', 'resident-card'); ui.fill('idcard_passphrase', 'SYNTHETIC-card-passphrase');
  ui.fill('idcard_passphrase_confirmation', 'SYNTHETIC-other');
  ui.fill('id_name', '합성 이름'); ui.fill('issueDate', '2020.02.29'); ui.fill('birthDate', '900101'); ui.fill('resident', '1000000');
  ui.check('identity_confirmed'); ui.photo(form);
  await ui.actions['idcard-save']({}, form);
  assert.equal(ui.jobs().length, 0);
  assert.match(ui.document.querySelector('#certificate-error').textContent, /확인 입력이 달라요/);
  assert.equal(ui.document.querySelector('[name="idcard_passphrase"]').value, '');
});
