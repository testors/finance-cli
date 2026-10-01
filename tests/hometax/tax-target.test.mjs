import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {BusinessRuntime, runBusiness} from '../../src/hometax_cli/business.mjs';
import {loadDOM} from '../../src/hometax_cli/browserless.mjs';

const PERSONAL = {tin:'P-SYNTHETIC', rprsTin:''};
const BUSINESS = {tin:'B-SYNTHETIC', rprsTin:PERSONAL.tin};

// Synthetic page boundaries: keep the real target guard, tax navigation,
// collection, verdict and file handling. No remote pages or requests.
async function fixture(t, options = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'tax-target-'));
  t.after(() => fs.rm(directory, {recursive:true, force:true}));
  const calls = [];
  let account = options.account || PERSONAL;
  t.mock.method(BusinessRuntime.prototype, 'open', async function () {
    calls.push('session.open');
    const runtime = this;
    this.page = {
      state:{branch:options.expired ? 'failure' : 'success', reason:options.expired ? 'sso_ended' : 'tokenOK'},
      pageReady:true, record:() => ({cookie_jar:{cookies:[]}, warnings:[]}), close() {},
      dom:{window:{
        location:{origin:'https://example.test', href:'https://example.test/main'},
        document:{getElementById:() => null},
        ntsframework:{session:{get:key => account[key]}},
        btnProcess_onClick() {
          calls.push('dues.enter');
          if (!options.denied) runtime.navigation = {url:'https://example.test/?actionId=UTBRMAAC02F001'};
          else runtime.window.document.getElementById = id => id === 'popup_container' ? {} : null;
        },
      }},
    };
  });
  t.mock.method(BusinessRuntime.prototype, 'menu', async function (entry) {
    calls.push(entry.screen);
    return true;
  });
  t.mock.method(BusinessRuntime.prototype, 'navigate', async function () {
    calls.push('dues.request');
    this.services.push({action_id:'ATERMAAA004R01', branch:options.branch || 'success', response_observed:true,
      response:{RESULT:{result:options.branch === 'failure' ? 'F' : 'S'}, pubcRomCmnDVOList:[]}});
    if (options.afterResponseError) throw new Error('synthetic callback error');
  });
  t.mock.method(BusinessRuntime.prototype, 'businessSelect', async function (tin) {
    calls.push(['business.select', tin]);
    const service = {action_id:'ATXPPAAA003A01', branch:options.switchBranch || 'success', response_observed:true};
    this.services.push(service);
    if (options.switchError) throw new Error('synthetic error after accepted switch');
    if (!options.mismatch) account = tin === 'ORIGIN' ? PERSONAL : BUSINESS;
    return {branch:service.branch, reason:'original_service_result', data:{account}};
  });
  const config = {command:'tax', operation:'dues', timeout:1, output:path.join(directory, 'result.json')};
  return {config, calls, read:async () => JSON.parse(await fs.readFile(config.output, 'utf8'))};
}

test('same target is checked in memory: one initialization and one dues request', async t => {
  const f = await fixture(t);
  const summary = await runBusiness({...f.config, target:{kind:'personal', tin:PERSONAL.tin}, timings:true});
  assert.deepEqual(f.calls, ['session.open', 'UTBRMAAC01F001', 'dues.enter', 'dues.request']);
  assert.equal(summary.branch, 'success');
  assert.equal(summary.target_verified, true);
  assert.deepEqual(summary.target_check, [{operation:'account.show', branch:'success', reason:'verified_session'}]);
  assert.deepEqual(summary.timings.map(x => x.stage), ['session.open', 'tax.dues']);
  assert.ok(summary.timings.every(x => Number.isFinite(x.duration_ms) && x.duration_ms >= 0));
  assert.equal(JSON.stringify(summary).includes(PERSONAL.tin), false);
  const record = await f.read();
  assert.deepEqual(record.data.items, []);
  assert.equal(record.confirmed_target.tin, PERSONAL.tin);
  assert.equal((await fs.stat(f.config.output)).mode & 0o777, 0o600);
});

test('CLI with no target keeps the current taxpayer and default summary fields', async t => {
  const f = await fixture(t, {account:BUSINESS});
  const summary = await runBusiness(f.config);
  assert.equal(summary.branch, 'success');
  assert.equal('target_verified' in summary, false);
  assert.equal('timings' in summary, false);
  assert.equal((await f.read()).data.account.tin, BUSINESS.tin);
  assert.equal(f.calls.filter(x => x === 'session.open').length, 1);
});

for (const direction of ['business', 'personal']) {
  test(`select ${direction} and query share one initialized runtime`, async t => {
    const f = await fixture(t, {account:direction === 'business' ? PERSONAL : BUSINESS});
    const tin = direction === 'business' ? BUSINESS.tin : 'ORIGIN';
    const summary = await runBusiness({...f.config, target:{kind:direction, tin}, timings:true});
    assert.deepEqual(f.calls, ['session.open', ['business.select', tin], 'UTBRMAAC01F001', 'dues.enter', 'dues.request']);
    assert.equal(summary.target_verified, true);
    assert.deepEqual(summary.timings.map(x => x.stage), ['session.open', 'business.select', 'tax.dues']);
    assert.equal(summary.target_check[1].branch, 'success');
    assert.equal((await f.read()).data.account.tin, direction === 'business' ? BUSINESS.tin : PERSONAL.tin);
  });
}

for (const options of [{mismatch:true}, {switchBranch:'failure'}, {switchBranch:'no_action'}, {switchError:true},
  {expired:true}, {account:{tin:BUSINESS.tin}}]) {
  test(`unverified target cannot reach tax navigation: ${JSON.stringify(options)}`, async t => {
    const f = await fixture(t, options);
    const target = options.account ? {kind:'personal', tin:'ORIGIN'} : {kind:'business', tin:BUSINESS.tin};
    const summary = await runBusiness({...f.config, target});
    assert.equal(summary.target_verified, false);
    assert.equal(f.calls.includes('UTBRMAAC01F001'), false);
    assert.equal(f.calls.includes('dues.request'), false);
    if (options.switchError) assert.equal(summary.target_check[1].branch, 'success', 'Keep the accepted switch');
    if (options.expired) assert.equal(summary.branch, 'failure');
  });
}

for (const options of [{denied:true}, {branch:'failure'}, {afterResponseError:true}]) {
  test(`original navigation and service verdict survive the combined flow: ${JSON.stringify(options)}`, async t => {
    const f = await fixture(t, options);
    const summary = await runBusiness({...f.config, target:{kind:'personal', tin:PERSONAL.tin}});
    assert.equal(summary.branch, options.denied ? 'no_action' : options.branch || 'success');
    assert.equal(f.calls.filter(x => x === 'dues.request').length, options.denied ? 0 : 1);
  });
}

test('successful query is preserved when recording and cleanup fail', async t => {
  const f = await fixture(t);
  t.mock.method(BusinessRuntime.prototype, 'record', () => {throw new Error('synthetic write error');});
  t.mock.method(BusinessRuntime.prototype, 'close', () => {throw new Error('synthetic close error');});
  const summary = await runBusiness({...f.config, target:{kind:'personal', tin:PERSONAL.tin}, timings:true});
  assert.equal(summary.branch, 'success');
  assert.equal(summary.session_file_saved, false);
  assert.equal(summary.target_verified, true);
  assert.equal(summary.timings.length, 2);
  assert.equal(f.calls.filter(x => x === 'dues.request').length, 1);
});

test('output reservation happens before target selection or any session request', async t => {
  const f = await fixture(t);
  await fs.writeFile(f.config.output, 'existing synthetic file');
  await assert.rejects(runBusiness({...f.config, target:{kind:'business', tin:BUSINESS.tin}}), {code:'EEXIST'});
  assert.deepEqual(f.calls, []);
  assert.equal(await fs.readFile(f.config.output, 'utf8'), 'existing synthetic file');
});

test('request timings observe responses and errors without replaying callbacks or changing verdicts', async () => {
  const runtime = new BusinessRuntime({});
  const dom = new (loadDOM().JSDOM)('', {url:'https://example.test', beforeParse(window) {
    window.$ = {mobile:{loadPage() {}}, ajax(settings) {
      if (settings.syntheticError) settings.error();
      else settings.success({RESULT:{result:'S'}});
      settings.complete();
    }};
    runtime.observer(window);
  }});
  try {
    await new Promise(resolve => dom.window.document.addEventListener('DOMContentLoaded', resolve));
    let callbacks = 0;
    const url = '/jsonAction.do?actionId=ATERMAAA004R01';
    dom.window.$.ajax({url, success() {callbacks++;}});
    assert.throws(() => dom.window.$.ajax({url, success() {callbacks++; throw new Error('synthetic');}}));
    dom.window.$.ajax({url, syntheticError:true, error() {callbacks++;}});
    assert.equal(callbacks, 3);
    assert.equal(runtime.pending, 0);
    assert.deepEqual(runtime.services.map(s => s.branch), ['success', 'success', 'no_action']);
    assert.equal(runtime.services[1].callback_exception, true);
    assert.equal(runtime.services[2].transport_error, true);
    assert.ok(runtime.services.every(s => Number.isFinite(s.response_ms) && s.response_ms >= 0));
  } finally {dom.window.close();}
});
