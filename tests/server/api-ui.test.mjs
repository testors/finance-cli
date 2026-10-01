import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule, createContext} from 'node:vm';

test('API errors keep setup reasons and the stable error code', async () => {
  let result = {error: 'capability_unavailable', reasons: ['hometax_runtime_not_installed', null]};
  const context = createContext({fetch: async () => ({ok: false, status: 409, json: async () => result})});
  const source = await readFile(new URL('../../src/finance_cli/server/static/api.js', import.meta.url), 'utf8');
  const module = new SourceTextModule(source, {context});
  await module.link(() => { throw new Error('unexpected import'); });
  await module.evaluate();
  await assert.rejects(module.namespace.api.get('/jobs/job'), error => {
    assert.equal(error.code, 'capability_unavailable');
    assert.equal(error.status, 409);
    assert.deepEqual(Array.from(error.reasons), ['hometax_runtime_not_installed']);
    return true;
  });
  result = {error: 'resource_busy'};
  await assert.rejects(module.namespace.api.get('/jobs/job'), error => {
    assert.equal(error.code, 'resource_busy');
    assert.equal(error.reasons.length, 0);
    return true;
  });
});
