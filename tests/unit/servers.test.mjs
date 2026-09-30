// Несколько серверов в настройках: нормализация списка, выбор сервера по адресу страницы, старые ключи.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadVR, deq } from './_load.mjs';

test('нормализация списка серверов и старых ключей', () => {
  const { VR } = loadVR();
  assert.deepEqual(JSON.parse(JSON.stringify(VR.normalizeServers({ servers: [{ host: ' https://MP.Test/ ', port: 8443, token: ' t ' }, { host: '' }, null] }))), [{ host: 'mp.test', port: '8443', token: 't' }]);
  assert.deepEqual(JSON.parse(JSON.stringify(VR.normalizeServers({ host: 'old.test:443', token: 'x' }))), [{ host: 'old.test', port: '', token: 'x' }]);
  assert.deepEqual(VR.normalizeServers({ servers: [], host: 'old.test', token: 'x' }).length, 1, 'пустой список: берутся старые ключи');
  deq(VR.normalizeServers({}), []);
  deq(VR.normalizeServers(null), []);
});

test('сервер выбирается по адресу страницы без учета регистра', () => {
  const { VR } = loadVR();
  const list = [{ host: 'a.test', port: '', token: '1' }, { host: 'b.test', port: '', token: '2' }];
  assert.equal(VR.pickServer(list, 'B.TEST').token, '2');
  assert.equal(VR.pickServer(list, 'c.test'), null);
  assert.equal(VR.pickServer([], 'a.test'), null);
});

test('loadConfig: для страницы берется свой сервер, чужие не активируют модуль', async () => {
  const { VR, ctx } = loadVR();
  let stored = { servers: [{ host: 'other.test', port: '', token: 'o' }, { host: 'mp.test', port: '3334', token: 'm' }] };
  ctx.chrome.storage.sync.get = (k, cb) => cb(stored);
  await VR.loadConfig();
  assert.equal(VR.config().token, 'm'); assert.equal(VR.config().port, '3334');
  assert.equal(VR.isConfiguredHost(), true);
  assert.deepEqual(JSON.parse(JSON.stringify(VR.servers())), [{ host: 'other.test', port: '' }, { host: 'mp.test', port: '3334' }], 'список без токенов');
  ctx.location.hostname = 'unknown.test';
  await VR.loadConfig();
  assert.equal(VR.isConfiguredHost(), false);
  assert.deepEqual({ ...VR.config() }, {});
  // Старые ключи одной записи
  ctx.location.hostname = 'mp.test'; stored = { host: 'MP.test', port: '', token: 'legacy' };
  await VR.loadConfig();
  assert.equal(VR.config().token, 'legacy'); assert.equal(VR.isConfiguredHost(), true);
});

test('запросы идут на порт выбранного сервера с его токеном', async () => {
  const { VR, ctx } = loadVR();
  ctx.chrome.storage.sync.get = (k, cb) => cb({ servers: [{ host: 'mp.test', port: '8443', token: 'tok' }] });
  await VR.loadConfig();
  let seen = null;
  ctx.fetch = async (url, opts) => { seen = { url, auth: opts.headers.Authorization }; return { ok: true, status: 200, text: async () => '{"productVersion":"28.0"}', headers: { get: () => 'application/json' } }; };
  const d = await VR.raw.get('/api/deployment_configuration/v1/system_info');
  assert.equal(d.productVersion, '28.0');
  assert.equal(seen.url, 'https://mp.test:8443/api/deployment_configuration/v1/system_info');
  assert.equal(seen.auth, 'Bearer tok');
  ctx.location.hostname = 'nowhere.test'; await VR.loadConfig();
  await assert.rejects(VR.raw.get('/x'), /токен/);
});
