import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule} from 'node:vm';
import {JSDOM} from 'jsdom';

/* The real module on a page with nothing else, and a clock the test moves by hand. */
async function setup(t) {
  const dom = new JSDOM('<main id="main"><button id="other">다른 버튼</button></main>', {url: 'http://127.0.0.1:8740', runScripts: 'outside-only'});
  t.after(() => dom.window.close());
  const context = dom.getInternalVMContext();
  const clock = {now: 1000000, timers: new Map(), serial: 0, opened: 0};
  dom.window.HTMLDialogElement.prototype.showModal = function () { clock.opened++; this.setAttribute('open', ''); };
  dom.window.HTMLDialogElement.prototype.close = function () { this.removeAttribute('open'); this.dispatchEvent(new dom.window.Event('close')); };
  context.Date.now = () => clock.now;
  context.setTimeout = (fn, ms = 0) => { clock.timers.set(++clock.serial, {at: clock.now + ms, fn}); return clock.serial; };
  context.clearTimeout = id => { clock.timers.delete(id); };
  const pass = ms => {
    const end = clock.now + ms;
    for (;;) {
      const due = [...clock.timers].filter(([, timer]) => timer.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
      if (!due) break;
      clock.timers.delete(due[0]);
      clock.now = Math.max(clock.now, due[1].at);
      due[1].fn();
    }
    clock.now = end;
  };
  const module = new SourceTextModule(await readFile(new URL('../../src/finance_cli/server/static/busy.js', import.meta.url), 'utf8'), {context});
  await module.link(() => { throw new Error('unexpected import'); });
  await module.evaluate();
  const document = dom.window.document;
  const text = selector => document.querySelector(selector).textContent;
  return {...module.namespace, document, window: dom.window, pass, clock, text, box: () => document.querySelector('#busy'),
    corner: () => document.querySelector('#busy-corner')};
}

test('a hold closes the screen at once, names the work and opens it again when the work is over', async t => {
  const busy = await setup(t);
  assert.equal(busy.blocking(), false);
  const held = busy.hold('거래 내역 조회');
  assert.ok(busy.box().open, 'held from the moment it is asked');
  assert.equal(busy.box().classList.contains('quiet'), false);
  assert.equal(busy.text('#busy-title'), '거래 내역 조회');
  assert.ok(busy.box().querySelector('.spinner'));
  held.update('실행 중');
  assert.equal(busy.text('#busy-status'), '실행 중');
  held.update('완료', '거래 내역 조회 (서버 이름)');
  assert.equal(busy.text('#busy-title'), '거래 내역 조회 (서버 이름)');
  assert.equal(busy.box().querySelector('#busy-later').hidden, true);
  held.release();
  assert.equal(busy.blocking(), false);
  busy.pass(0);
  assert.equal(busy.box().open, false);
  held.release(); held.update('늦은 갱신');   // a finished hold changes nothing
  assert.equal(busy.box().open, false);
});

test('requests in a row keep one unbroken hold and the first name', async t => {
  const busy = await setup(t);
  const outer = busy.hold('원화 이체');
  const inner = busy.hold('', {quiet: true});      // the request made inside it
  assert.equal(busy.text('#busy-title'), '원화 이체');
  inner.release();
  outer.release();
  const next = busy.hold('원화 이체');             // the follow-up starts in the same turn
  busy.pass(0);
  assert.ok(busy.box().open, 'the screen never opened in between');
  assert.equal(busy.clock.opened, 1);
  next.release();
  busy.pass(0);
  assert.equal(busy.box().open, false);
});

test('a short request blocks from the start but is shown only once it takes longer than a moment', async t => {
  const busy = await setup(t);
  const held = busy.hold('', {quiet: true});
  assert.ok(busy.box().open && busy.blocking(), 'no second press gets through');
  assert.ok(busy.box().classList.contains('quiet'), 'nothing flashes for a request that is over at once');
  busy.pass(249);
  assert.ok(busy.box().classList.contains('quiet'));
  busy.pass(1);
  assert.equal(busy.box().classList.contains('quiet'), false);
  assert.equal(busy.text('#busy-title'), '요청을 처리하고 있어요');
  held.release();
  busy.pass(0);
  assert.equal(busy.box().open, false);
});

test('a long hold can be sent to the background: the screen is free and the corner keeps saying what runs', async t => {
  const busy = await setup(t);
  const held = busy.hold('납부할 세액 조회');
  held.update('실행 중');
  busy.pass(9999);
  assert.equal(busy.box().querySelector('#busy-later').hidden, true, 'not offered before ten seconds');
  busy.pass(1);
  assert.equal(busy.box().querySelector('#busy-later').hidden, false);
  assert.equal(held.background, false);
  busy.box().querySelector('#busy-later button').click();
  busy.pass(0);
  assert.equal(busy.box().open, false);
  assert.equal(busy.blocking(), false);
  assert.equal(held.background, true);
  assert.equal(busy.corner().hidden, false);
  assert.match(busy.corner().textContent, /백그라운드 작업: 납부할 세액 조회 · 실행 중/);
  held.update('완료');
  assert.match(busy.corner().textContent, /납부할 세액 조회 · 완료/);
  // The next thing asked for holds the screen again, with its own ten seconds.
  const next = busy.hold('거래 내역 조회');
  assert.ok(busy.box().open);
  assert.equal(busy.text('#busy-title'), '거래 내역 조회');
  assert.equal(busy.box().querySelector('#busy-later').hidden, true);
  next.release();
  held.release();
  busy.pass(0);
  assert.equal(busy.box().open, false);
  assert.equal(busy.corner().hidden, true);
});

test('escape does not open a held screen, and a failed piece of work still releases it', async t => {
  const busy = await setup(t);
  const held = busy.hold('원화 이체');
  const cancel = new busy.window.Event('cancel', {cancelable: true});
  busy.box().dispatchEvent(cancel);
  assert.equal(cancel.defaultPrevented, true);
  busy.box().close();                               // forced shut by the browser
  assert.ok(busy.box().open, 'it is held again while the work runs');
  held.release();
  busy.pass(0);
  assert.equal(busy.box().open, false);
  await assert.rejects(busy.during('실패하는 요청', async () => { assert.ok(busy.blocking()); throw new Error('synthetic'); }), /synthetic/);
  assert.equal(busy.blocking(), false);
  assert.equal(await busy.during('값을 돌려주는 요청', Promise.resolve(7)), 7);
});
