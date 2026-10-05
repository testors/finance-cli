import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule, createContext} from 'node:vm';
import {webcrypto} from 'node:crypto';

test('HTTP browsers without randomUUID can submit a login exactly once', async () => {
  const requests = [];
  const context = createContext({
    crypto: {getRandomValues: bytes => webcrypto.getRandomValues(bytes)},
    Blob,
    fetch: async (url, options) => {
      requests.push({url, options});
      return {ok: true, json: async () => ({id: 'synthetic-login', status: 'queued'})};
    },
  });
  const source = await readFile(new URL('../../src/finance_cli/server/static/api.js', import.meta.url), 'utf8');
  const module = new SourceTextModule(source, {context});
  await module.link(() => { throw new Error('unexpected import'); });
  await module.evaluate();
  const result = await module.namespace.submit('hana.onesign.login', {login_id: 'synthetic'});
  assert.equal(result.id, 'synthetic-login');
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, '/api/v1/jobs');
  assert.equal(requests[0].options.method, 'POST');
  const body = JSON.parse(requests[0].options.body);
  assert.equal(body.name, 'hana.onesign.login');
  assert.match(body.idempotency_key, /^web-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.notEqual(module.namespace.idempotencyKey(), body.idempotency_key);
});

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

test('tax job polling caps at one second without submitting or retrying the job', async () => {
  const source = await readFile(new URL('../../src/finance_cli/server/static/api.js', import.meta.url), 'utf8');
  for (const name of ['hometax.tax.dues', 'hometax.tax.payments', 'hana.accounts']) {
    const delays = [], requests = [];
    const context = createContext({
      fetch: async (url, options) => {
        requests.push([url, options.method]);
        return {ok:true, json:async () => ({name, status:requests.length < 8 ? 'running' : 'finished'})};
      },
      setTimeout: (resolve, delay) => {delays.push(delay); resolve();},
    });
    const module = new SourceTextModule(source, {context});
    await module.link(() => {throw new Error('unexpected import');});
    await module.evaluate();
    const result = await module.namespace.follow('synthetic');
    assert.equal(result.status, 'finished');
    assert.equal(Math.max(...delays), name.startsWith('hometax.tax.') ? 1000 : 3000);
    assert.ok(requests.every(([url, method]) => url === '/api/v1/jobs/synthetic' && method === 'GET'));
  }
});
