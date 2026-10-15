/* Synthetic DOM tests: no real credentials, browser profile or institution calls. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule} from 'node:vm';
import {JSDOM} from 'jsdom';

async function setup(t) {
  const dom = new JSDOM('<dialog id="detail-dialog"><div id="dialog-content"></div></dialog>',
    {url: 'http://127.0.0.1:8740', runScripts: 'outside-only'});
  t.after(() => dom.window.close());
  const w = dom.window;
  w.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  w.HTMLDialogElement.prototype.close = function () { this.open = false; };
  const module = new SourceTextModule(await readFile(new URL('../../src/finance_cli/server/static/ui.js', import.meta.url), 'utf8'),
    {context: dom.getInternalVMContext()});
  await module.link(() => { throw new Error('No imports or network needed'); });
  await module.evaluate();
  return {ui: module.namespace, w, document: w.document};
}
const secret = (name, extra = '') => `<input name="${name}" type="password" required ${extra}>`;
const screen = inputs => `<form id="action">${inputs}<button type="submit">확인</button></form>`;
const account = input => input.form.querySelector('[autocomplete="username"]').value;

test('different secrets have independent native form owners; metadata stays out of API data', async t => {
  const {ui, w, document} = await setup(t);
  ui.showDialog('합성 로그인', screen(secret('vault_passphrase') + secret('pin', 'pattern="[0-9]{6}"') + '<input name="label" value="synthetic">'),
    {passwords: {vault_passphrase: ui.passwordAccount('onesign-vault', 'sample'), pin: ui.passwordAccount('onesign-pin', 'sample')}});
  const form = document.querySelector('#action'), vault = form.querySelector('[name="vault_passphrase"]'), pin = form.querySelector('[name="pin"]');
  assert.notEqual(vault.form, form);
  assert.notEqual(vault.form, pin.form);
  assert.equal(document.querySelector('form form'), null);
  assert.notEqual(account(vault), account(pin));
  assert.equal(vault.autocomplete, 'current-password');
  vault.value = 'synthetic-vault'; pin.value = '123456';
  assert.deepEqual(Object.fromEntries(ui.formData(form)), {label: 'synthetic', vault_passphrase: 'synthetic-vault', pin: '123456'});
  assert.deepEqual([...new w.FormData(form).keys()], ['label']);
  assert.equal(w.localStorage.length, 0);
  assert.equal(w.sessionStorage.length, 0);
  assert.equal(vault.form.textContent.includes('synthetic-vault'), false);
});

test('the same store has the same account across screens and input names, while another store is distinct', async t => {
  const {ui, document} = await setup(t);
  const show = (name, ref, kind = 'onesign-vault') => {
    ui.showDialog('합성', screen(secret(name)), {passwords: {[name]: ui.passwordAccount(kind, ref)}});
    const input = document.querySelector(`[name="${name}"]`);
    return {id: input.form.id, account: account(input)};
  };
  const first = show('vault_passphrase', 'sample');
  assert.deepEqual(show('passphrase', 'sample'), first);
  assert.notDeepEqual(show('vault_passphrase', 'second'), first);
  assert.notDeepEqual(show('certificate_password', 'sample', 'joint-certificate'), first);
  assert.deepEqual(show('certificate_password', '<합성&">', 'joint-certificate'), show('certificate_password', '<합성&">', 'joint-certificate'));
  assert.equal(document.querySelector('script'), null);
});

test('switching a selected certificate changes only its account and clears its old password', async t => {
  const {ui, w, document} = await setup(t);
  ui.showDialog('합성 인증', screen('<select name="credential"><option>A</option><option>B</option></select>' + secret('certificate_password') + secret('vault_passphrase')),
    {passwords: {certificate_password: form => ui.passwordAccount('joint-certificate', form.querySelector('select').value),
      vault_passphrase: ui.passwordAccount('onesign-vault', 'sample')}});
  const form = document.querySelector('#action'), cert = form.querySelector('[name="certificate_password"]'), vault = form.querySelector('[name="vault_passphrase"]');
  cert.value = 'synthetic-cert'; vault.value = 'synthetic-vault';
  const old = cert.form.id;
  form.querySelector('select').value = 'B';
  form.querySelector('select').dispatchEvent(new w.Event('change', {bubbles: true}));
  assert.equal(account(cert), ui.passwordAccount('joint-certificate', 'B'));
  assert.notEqual(cert.form.id, old);
  assert.equal(cert.value, '');
  assert.equal(vault.value, 'synthetic-vault');
});

test('click and Enter validate all secrets and dispatch the business action only once', async t => {
  const {ui, document} = await setup(t);
  ui.showDialog('합성 확인', screen(secret('vault_passphrase') + secret('pin', 'pattern="[0-9]{6}"')),
    {passwords: {vault_passphrase: ui.passwordAccount('onesign-vault', 'sample'), pin: ui.passwordAccount('onesign-pin', 'sample')}});
  const form = document.querySelector('#action'), vault = form.querySelector('[name="vault_passphrase"]'), pin = form.querySelector('[name="pin"]');
  let actions = 0, nativeSubmits = 0;
  form.addEventListener('submit', event => { event.preventDefault(); actions++; });
  document.addEventListener('submit', event => { if (event.target !== form) nativeSubmits++; });
  form.requestSubmit();
  assert.equal(actions, 0, 'empty secrets are still required despite having other form owners');
  vault.value = 'synthetic-vault'; pin.value = 'bad';
  form.requestSubmit(); assert.equal(actions, 0);
  pin.value = '123456';
  form.querySelector('button').click(); assert.equal(actions, 1);
  pin.form.requestSubmit(); assert.equal(actions, 2, 'Enter follows the same business submit');
  assert.equal(nativeSubmits, 0, 'password forms never navigate or reach document action dispatch');
  form.querySelector('button').disabled = true;
  pin.form.requestSubmit(); assert.equal(actions, 2);
});

test('disabled secrets stay out of validation and API data; reset and close erase all secret values', async t => {
  const {ui, document} = await setup(t);
  ui.showDialog('합성', screen(secret('vault_passphrase') + '<fieldset disabled>' + secret('unused') + '</fieldset>'));
  const form = document.querySelector('#action'), vault = form.querySelector('[name="vault_passphrase"]'), unused = form.querySelector('[name="unused"]');
  vault.value = 'synthetic-vault'; unused.value = 'synthetic-unused';
  let actions = 0;
  form.addEventListener('submit', event => { event.preventDefault(); actions++; });
  form.requestSubmit(); assert.equal(actions, 1);
  assert.deepEqual(Object.fromEntries(ui.formData(form)), {vault_passphrase: 'synthetic-vault'});
  form.reset(); assert.equal(vault.value, ''); assert.equal(unused.value, '');
  vault.value = 'synthetic-vault';
  ui.closeDialog();
  assert.equal(vault.value, '');
  assert.equal(document.querySelector('#dialog-content').innerHTML, '');
});

test('new password confirmation shares its account; OTP remains a one-time code', async t => {
  const {ui, document} = await setup(t);
  ui.showDialog('합성 발급', screen(secret('new_pin') + secret('new_pin_confirmation') + secret('otp')),
    {passwords: {new_pin: ui.passwordAccount('onesign-pin', 'sample')}});
  const pin = document.querySelector('[name="new_pin"]'), confirmation = document.querySelector('[name="new_pin_confirmation"]'), otp = document.querySelector('[name="otp"]');
  assert.equal(pin.form, confirmation.form);
  assert.equal(pin.autocomplete, 'new-password');
  assert.equal(confirmation.autocomplete, 'new-password');
  assert.notEqual(otp.form, pin.form);
  assert.equal(otp.autocomplete, 'one-time-code');
  assert.equal(otp.form.querySelector('[name="username"]').disabled, true);
});
