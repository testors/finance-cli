import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule} from 'node:vm';
import {JSDOM} from 'jsdom';

async function setup(t) {
  const dom = new JSDOM('<input data-amount>', {runScripts: 'outside-only'});
  t.after(() => dom.window.close());
  const w = dom.window, input = w.document.querySelector('input');
  const module = new SourceTextModule(await readFile(new URL('../../src/finance_cli/server/static/ui.js', import.meta.url), 'utf8'),
    {context: dom.getInternalVMContext()});
  await module.link(() => {}); await module.evaluate();
  const ui = module.namespace;
  input.addEventListener('beforeinput', ui.amountBeforeInput);
  input.addEventListener('input', () => ui.formatAmountInput(input));
  const set = (value, start = value.length, end = start) => { input.value = value; input.setSelectionRange(start, end); };
  const edit = (type, text = '') => {
    const event = new w.InputEvent('beforeinput', {bubbles: true, cancelable: true, inputType: type, data: text});
    if (!input.dispatchEvent(event)) return;
    let start = input.selectionStart, end = input.selectionEnd;
    if (start === end && type === 'deleteContentBackward') start = Math.max(0, start - 1);
    if (start === end && type === 'deleteContentForward') end = Math.min(input.value.length, end + 1);
    input.setRangeText(text, start, end, 'end');
    input.dispatchEvent(new w.InputEvent('input', {bubbles: true, inputType: type}));
  };
  return {input, set, edit, ui};
}

test('typing groups every three digits, and backspace removes digits down to empty', async t => {
  const {input, edit} = await setup(t);
  for (const digit of '3000000') edit('insertText', digit);
  assert.equal(input.value, '3,000,000');
  for (const value of ['300,000', '30,000', '3,000', '300', '30', '3', '']) {
    edit('deleteContentBackward'); assert.equal(input.value, value);
    assert.equal(input.selectionStart, value.length);
  }
});

test('backspace and Delete next to a comma remove the neighboring digit in one press', async t => {
  const {input, set, edit} = await setup(t);
  set('12,345', 3); edit('deleteContentBackward');
  assert.equal(input.value, '1,345'); assert.equal(input.selectionStart, 1);
  set('12,345', 2); edit('deleteContentForward');
  assert.equal(input.value, '1,245'); assert.equal(input.selectionStart, 3);
  set('1,000', 2); edit('deleteContentBackward');
  assert.equal(input.value, '000'); assert.equal(input.selectionStart, 0);
});

test('middle insertion, selected replacement and paste keep the logical caret and exact digits', async t => {
  const {input, set, edit} = await setup(t);
  set('12,345', 2); edit('insertText', '9');
  assert.equal(input.value, '129,345'); assert.equal(input.selectionStart, 3);
  set('1,234,567', 2, 5); edit('insertText', '9');
  assert.equal(input.value, '19,567'); assert.equal(input.selectionStart, 2);
  set(''); edit('insertFromPaste', '123456789012345678901');
  assert.equal(input.value, '123,456,789,012,345,678,901');
  assert.equal(input.selectionStart, input.value.length);
  set(''); edit('insertFromPaste', '-1,234,567');
  assert.equal(input.value, '-1,234,567');
  set('1,000', 0, 5); edit('deleteContentBackward'); assert.equal(input.value, '');
});

test('formatting never converts decimals, exponents or other invalid text into a different amount', async t => {
  const {ui} = await setup(t);
  for (const value of ['1.23', '1e6', '3만원', '+1', 'NaN']) assert.equal(ui.groupAmount(value), value);
  assert.equal(ui.groupAmount(''), '');
  assert.equal(ui.groupAmount('-'), '-');
  assert.equal(ui.groupAmount('0'), '0');
  assert.equal(ui.groupAmount('0001000'), '0,001,000');
});
