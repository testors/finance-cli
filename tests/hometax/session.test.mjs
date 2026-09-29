import assert from 'node:assert/strict';
import {test} from 'node:test';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {runSession, SavedSession} from '../../src/hometax_cli/session.mjs';

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
