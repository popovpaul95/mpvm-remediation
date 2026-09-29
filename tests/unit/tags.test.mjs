import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadVR, deq } from './_load.mjs';
const host = id => ({ '@Host': { id, name: 'h-' + id } });

test('назначение тегов: дедупликация узлов, счетчики успешных и неудачных (D11)', async () => {
  const { VR, calls } = loadVR();
  VR.pdql = async () => ({ records: [host('a'), host('a'), host('b')] });
  VR.put = async (p, b) => { calls.put.push({ p, b }); if (p.endsWith('/b')) throw new Error('HTTP 500'); return {}; };
  const r = await VR.assignAssetTags({ pdql: 'filter(Host) | select(@Host)', addIds: ['t1'] });
  assert.equal(calls.put.length, 2, 'каждый узел ровно один PUT');
  deq({ count: r.count, failed: r.failed, requested: r.requested, truncated: r.truncated }, { count: 1, failed: 1, requested: 2, truncated: false });
  deq(calls.put[0].b, { tagIdsToAdd: ['t1'], tagIdsToRemove: [] });
  // applyAutoTags: hasMatches по выборке, ok только без ошибок
  VR.get = async () => [];
  VR.post = async () => ({ id: 'tag-new' });
  const res = await VR.applyAutoTags({ rules: [{ name: 'auto:x', color: 'grey', pdql: 'filter(Host) | select(@Host)' }] });
  assert.equal(res[0].hasMatches, true); assert.equal(res[0].ok, false); assert.equal(res[0].count, 1); assert.equal(res[0].failed, 1);
  VR.put = async () => { throw new Error('HTTP 403'); };
  const all = await VR.applyAutoTags({ rules: [{ name: 'auto:y', pdql: 'filter(Host) | select(@Host)' }] });
  assert.equal(all[0].count, 0, 'все PUT упали: назначенных нет'); assert.equal(all[0].hasMatches, true); assert.match(all[0].error, /403/);
  VR.pdql = async () => ({ records: [] });
  const empty = await VR.applyAutoTags({ rules: [{ name: 'auto:z', pdql: 'filter(Host) | select(@Host)' }] });
  assert.equal(empty[0].hasMatches, false); assert.equal(empty[0].ok, true);
});
test('обрезка выборки помечается флагом', async () => {
  const { VR } = loadVR();
  VR.pdql = async (q, limit) => ({ records: Array.from({ length: limit }, (_, i) => host('h' + i)) });
  VR.put = async () => ({});
  const r = await VR.assignAssetTags({ pdql: 'filter(Host) | select(@Host) | limit(5)', addIds: ['t'], limit: 3 });
  assert.equal(r.truncated, true); assert.equal(r.count, 3);
});
test('удаление тегов: по префиксу и точно по имени', async () => {
  const { VR, calls } = loadVR();
  VR.get = async () => [{ id: '1', name: 'auto:x' }, { id: '2', name: 'auto:x2' }, { id: '3', name: 'user:y' }];
  VR.pdql = async () => ({ records: [host('a')] });
  VR.put = async () => ({}); VR.del = async p => { calls.del.push(p); return {}; };
  await VR.removeAutoTags({ prefix: 'auto:x' });
  deq(calls.del, ['/api/tags/v1/asset/tags/1', '/api/tags/v1/asset/tags/2'], 'префикс задевает auto:x2');
  calls.del.length = 0;
  await VR.removeAutoTags({ prefix: 'auto:x', exact: true });
  deq(calls.del, ['/api/tags/v1/asset/tags/1'], 'точное имя удаляет только auto:x');
});
