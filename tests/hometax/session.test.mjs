import assert from 'node:assert/strict';
import {test} from 'node:test';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {extensionReport, runSession, SavedSession} from '../../src/hometax_cli/session.mjs';

test('session output cannot overwrite its input or trigger network before reservation', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'session-preserve-'));
  try {
    const session = path.join(directory,'session.json');
    const contents = JSON.stringify({cookie_jar:{},storage:{marker:'synthetic'}});
    await fs.writeFile(session,contents,{mode:0o600});
    let requests = 0;
    await assert.rejects(runSession({session,output:session,operation:'resume',timeout:1}, {
      getPage() {requests++; throw new Error('Network forbidden');},
    }), {code:'EEXIST'});
    assert.equal(requests,0);
    assert.equal(await fs.readFile(session,'utf8'),contents);
  } finally {await fs.rm(directory,{recursive:true,force:true});}
});

test('accepted binding receives a startup observation stage after slow original script execution', async () => {
  const runtime = new SavedSession(null,1000,{});
  let started = false;
  runtime.dom = {window:{get __hometaxPageStarted() {return started;},
    ntsframework:{session:{get:()=>started ? 'success' : undefined}}}};
  const expiredResourceDeadline = Date.now()-1;
  runtime.report({kind:'verify',result:'tokenOK'});
  runtime.report({kind:'session-bound'});
  const timer = setTimeout(()=>{started=true;},150);
  try {
    await runtime.wait(expiredResourceDeadline);
    assert.equal(runtime.state.branch,'success');
    assert.equal(runtime.pageReady,true,'Wait for the actual original startup signal');
  } finally {clearTimeout(timer);}
  const unknown = new SavedSession(null,1000,{});
  await unknown.wait(expiredResourceDeadline);
  assert.equal(unknown.state.branch,'no_action','Old or missing evidence cannot grant a new success stage');
});

// A synthetic main page: the real file handling, record and summary, with the observation
// stage replaced by the events the original session scripts would report. No requests.
async function extend(t, events) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'session-extend-'));
  t.after(() => fs.rm(directory, {recursive:true, force:true}));
  const session = path.join(directory, 'session.json'), output = path.join(directory, 'extended.json');
  await fs.writeFile(session, JSON.stringify({cookie_jar:{cookies:[]}, storage:{}}), {mode:0o600});
  const pages = [];
  let refreshes = 0;
  t.mock.method(SavedSession.prototype, 'wait', async function () {
    for (const event of events) this.report(event);
  });
  const summary = await runSession({session, output, operation:'extend', timeout:1}, {
    async getPage(url) {
      pages.push(new URL(url).pathname);
      return url.includes('NtsCommonTb')
        ? {url, body:'document.write("<meta name=\\"synthetic\\">")'}
        : {url, body:'<html><head><script src="/js/comm/NtsCommonTb_main.js"></script></head><body></body></html>'};
    },
    beforeParse(window) {
      window.ntsframework = {session:{get:() => undefined}, setSessionIfPresent() {refreshes++;}};
    },
  });
  return {summary, record:JSON.parse(await fs.readFile(output, 'utf8')), pages, refreshes};
}

test('extend is one session check: an accepted check is the extension and no token is re-acquired', async t => {
  const {summary, record, pages, refreshes} = await extend(t, [{kind:'verify', result:'tokenOK'}, {kind:'session-bound'}]);
  assert.deepEqual(pages, ['/jsonAction.do', '/js/comm/NtsCommonTb_main.js'], 'the main page once, never the login screen');
  assert.equal(refreshes, 0);
  const accepted = {method:'session-check', login_extension_accepted:true, extension_effect:'idle_limit_reset_observed',
    session_ended:false, session_current_validity:'valid', server_expires_at:null, automatic_login:false, automatic_retry:false};
  assert.deepEqual(extensionReport('success'), accepted);
  for (const value of [summary, record]) {
    assert.equal(value.operation, 'extend');
    assert.equal(value.branch, 'success');
    assert.equal(value.refresh_started, false);
    for (const [key, expected] of Object.entries(accepted)) assert.equal(value[key], expected, key);
  }
  assert.equal(summary.session_file_saved, true);
  assert.ok(record.cookie_jar, 'the checked session is saved for the next command');
});

test('extend reports an ended login as ended and an unobserved verdict as unverified', async t => {
  const ended = await extend(t, [{kind:'verify', result:'except'}, {kind:'portal-token', present:false}]);
  assert.equal(ended.summary.branch, 'failure');
  assert.equal(ended.summary.reason, 'no_sso_token');
  assert.deepEqual([ended.summary.login_extension_accepted, ended.summary.session_ended, ended.summary.session_current_validity,
    ended.summary.extension_effect], [false, true, 'ended', 'unverified']);
  assert.equal(ended.refreshes, 0);

  const unobserved = await extend(t, [{kind:'verify', result:'except'}, {kind:'session-cleared'}]);
  assert.equal(unobserved.summary.branch, 'no_action');
  assert.deepEqual([unobserved.summary.login_extension_accepted, unobserved.summary.session_ended,
    unobserved.summary.session_current_validity, unobserved.summary.extension_effect], [null, false, 'unverified', 'unverified']);
  assert.equal(unobserved.record.login_extension_accepted, null, 'a cleared login alone is not taken as a refusal');
  assert.equal(unobserved.refreshes, 0);
});

test('resume and refresh results carry no extension claim', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'session-resume-'));
  t.after(() => fs.rm(directory, {recursive:true, force:true}));
  const session = path.join(directory, 'session.json');
  await fs.writeFile(session, JSON.stringify({cookie_jar:{cookies:[]}, storage:{}}), {mode:0o600});
  for (const operation of ['resume', 'refresh']) {
    const output = path.join(directory, operation + '.json');
    const summary = await runSession({session, output, operation, timeout:1},
      {getPage() {throw new Error('Network forbidden');}});
    const record = JSON.parse(await fs.readFile(output, 'utf8'));
    for (const value of [summary, record]) {
      assert.equal(value.branch, 'no_action');
      for (const key of ['method', 'login_extension_accepted', 'extension_effect', 'session_ended']) assert.equal(key in value, false, key);
    }
  }
});
