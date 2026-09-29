import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {CDP, login} from '../../src/hometax_cli/browser.mjs';

test('CDP correlates out-of-order replies and propagates protocol errors', async () => {
  class Socket extends EventTarget {
    sent = [];
    send(s) {this.sent.push(JSON.parse(s));}
    reply(data) {this.dispatchEvent(new MessageEvent('message', {data:JSON.stringify(data)}));}
  }
  const socket = new Socket(), client = new CDP(socket);
  const a = client.send('one'), b = client.send('two');
  socket.reply({id:2, result:{n:2}}); socket.reply({id:1, result:{n:1}});
  assert.deepEqual(await a, {n:1}); assert.deepEqual(await b, {n:2});
  const c = client.send('three'); socket.reply({id:3,error:{code:-1}});
  await assert.rejects(c, /CDP command failed/);
});

test('browser orchestration preserves success if cookie export fails; no real network', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'hometax-browser-'));
  const originalConnect = CDP.connect;
  let loginCalls = 0;
  const fake = {
    listeners:[], close(){},
    async send(method, params) {
      if (method==='Target.createBrowserContext') return {browserContextId:'synthetic-context'};
      if (method==='Target.createTarget') return {targetId:'synthetic-target'};
      if (method==='Target.attachToTarget') return {sessionId:'s'};
      if (method==='Browser.getVersion') return {userAgent:'SyntheticBrowser'};
      if (method==='Storage.getCookies') throw new Error('simulated export failure');
      if (method==='Runtime.evaluate') {
        if (params.expression.startsWith('nts_calledByNative')) {
          loginCalls++;
          for (const event of [{kind:'login-request'}, {kind:'decision',branch:'success',
            response:{result:{resultMsg:{code:'S'}}}}, {kind:'session',sessionStorage:{},localStorage:{}}]) {
            for (const f of this.listeners) f({sessionId:'s',method:'Runtime.bindingCalled',
              params:{name:'__hometaxReport',payload:JSON.stringify(event)}});
          }
        }
        return {result:{value:true}};
      }
      return {};
    },
  };
  CDP.connect = async () => fake;
  try {
    const output = path.join(directory, 'session.json');
    const result = await login({cdp:'ws://offline.invalid', output, timeout:1,
      appVersion:'14.3',callback:{javascript:"javascript:nts_calledByNative({})"}});
    assert.equal(result.branch, 'success'); assert.equal(loginCalls, 1);
    assert.equal(result.session_file_saved, true);
    assert.equal((await fs.stat(output)).mode & 0o777, 0o600);
    const saved = JSON.parse(await fs.readFile(output));
    assert.equal(saved.branch, 'success'); assert.equal(saved.warnings.length, 1);
    assert.equal(result.response, undefined);
    await assert.rejects(login({output}), /EEXIST/);
  } finally {
    CDP.connect = originalConnect;
    await fs.rm(directory, {recursive:true, force:true});
  }
});
