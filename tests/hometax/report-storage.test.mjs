import test from 'node:test';
import assert from 'node:assert/strict';
import {loadDOM} from '../../src/hometax_cli/browserless.mjs';

test('report WebView shares origin-local data and storage events without sharing parent session state', async () => {
  const {JSDOM,shareLocalStorage} = loadDOM();
  const parent = new JSDOM('',{url:'https://mob.tbht.hometax.go.kr/parent'});
  const child = new JSDOM('',{url:'https://mob.tbht.hometax.go.kr/report'});
  const other = new JSDOM('',{url:'https://mob.hometax.go.kr/'});
  let detach;
  try {
    parent.window.localStorage.setItem('reportServiceParam','synthetic');
    parent.window.sessionStorage.setItem('screenId','parent-screen');
    detach = shareLocalStorage(child.window,parent.window);
    assert.equal(child.window.localStorage.getItem('reportServiceParam'),'synthetic');
    assert.equal(child.window.sessionStorage.getItem('screenId'),null);
    child.window.sessionStorage.setItem('screenId','report-screen');
    assert.equal(parent.window.sessionStorage.getItem('screenId'),'parent-screen');
    const event = new Promise(resolve=>parent.window.addEventListener('storage',resolve,{once:true}));
    child.window.localStorage.removeItem('reportServiceParam');
    const observed = await event;
    assert.equal(observed.url,'https://mob.tbht.hometax.go.kr/report');
    assert.equal(observed.storageArea,parent.window.localStorage);
    assert.equal(observed.key,'reportServiceParam');
    assert.equal(observed.oldValue,'synthetic');
    assert.equal(observed.newValue,null);
    assert.equal(parent.window.localStorage.getItem('reportServiceParam'),null);
    assert.throws(()=>shareLocalStorage(other.window,parent.window),/origin/);
    detach(); detach = undefined;
    child.window.close();
    parent.window.localStorage.setItem('nextReport','next');
    assert.equal(parent.window.localStorage.getItem('nextReport'),'next');
  } finally {detach?.();parent.window.close();child.window.close();other.window.close();}
});
