// Поколения интерфейса MaxPatrol VM: 28.0 (маршруты /mpx/...) и 27.x (hash-маршруты #/...).
// Адреса штатных экранов, параметры страницы из hash, версия сервера и доступность тегов активов.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadVR } from './_load.mjs';

const GUID = '1e21d350-c381-4001-0000-00000001273c';
const INST = '1e29a97bd3c000010000000000000002_1e29a97d9000a00100000000000002a1_1e21d4ce32c14001000000000002d211';

function legacy(ctx) { ctx.location.pathname = '/'; ctx.location.hash = '#/assets?viewMode=list&assetId=a-1&tabName=summary'; }
function modern(ctx) { ctx.location.pathname = '/mpx/common/am/assets'; ctx.location.search = '?groupId=g&assetId=a-2'; ctx.location.hash = ''; }

test('поколение интерфейса определяется по адресу страницы', () => {
  const { VR, ctx } = loadVR();
  assert.equal(VR.isLegacyUi(), false, 'без hash-маршрута считаем 28.0');
  legacy(ctx); assert.equal(VR.isLegacyUi(), true);
  modern(ctx); assert.equal(VR.isLegacyUi(), false);
  ctx.location.pathname = '/mpx/vm/vulnerability-card'; ctx.location.hash = '#/x'; assert.equal(VR.isLegacyUi(), false, 'hash внутри /mpx не делает интерфейс старым');
});

test('параметры страницы читаются из строки запроса и из hash', () => {
  const { VR, ctx } = loadVR();
  legacy(ctx);
  assert.equal(VR.pageParams().get('assetId'), 'a-1');
  assert.equal(VR.pageParams().get('tabName'), 'summary');
  modern(ctx);
  assert.equal(VR.pageParams().get('assetId'), 'a-2');
  ctx.location.search = '?assetId=s'; ctx.location.hash = '#/x?assetId=h';
  assert.equal(VR.pageParams().get('assetId'), 's', 'строка запроса важнее hash');
  ctx.location.search = ''; ctx.location.hash = '#/assets/vulnerability-card?vulnerabilityId=' + GUID + '&vulnerabilityInstanceId=' + INST;
  assert.equal(VR.pageParams().get('vulnerabilityInstanceId'), INST);
});

test('адреса штатных экранов: 28.0', () => {
  const { VR, ctx } = loadVR(); modern(ctx);
  assert.equal(VR.passportUrl(GUID), `https://mp.test/mpx/vm/vulnerability-passport-card?vulnerabilityId=${GUID}`);
  assert.equal(VR.assetUrl('a-1'), 'https://mp.test/mpx/common/am/assets?groupId=00000000-0000-0000-0000-000000000002&viewMode=list&assetId=a-1&tabName=summary');
  assert.equal(VR.instanceUrl(INST), `https://mp.test/mpx/vm/vulnerability-card?vulnerabilityId=1e21d4ce-32c1-4001-0000-00000002d211&vulnerabilityInstanceId=${INST}`);
  assert.equal(VR.listUrl('filter(Host.OsName = "Astra")'), 'https://mp.test/mpx/common/am/assets?groupId=00000000-0000-0000-0000-000000000002&pdqlQuery=' + encodeURIComponent('filter(Host.OsName = "Astra")'));
  assert.equal(VR.passportUrl(''), null); assert.equal(VR.assetUrl(null), null); assert.equal(VR.instanceUrl('bad'), null);
});

test('адреса штатных экранов: 27.x (hash-маршруты, queryId и select для списка)', async () => {
  const { VR, ctx } = loadVR(); legacy(ctx);
  assert.equal(VR.passportUrl(GUID), `https://mp.test/#/assets/vulnerability-passport?vulnerabilityId=${GUID}`);
  assert.equal(VR.assetUrl('a-1'), 'https://mp.test/#/assets?viewMode=list&groupId=00000000-0000-0000-0000-000000000002&assetId=a-1&tabName=summary');
  assert.equal(VR.instanceUrl(INST), `https://mp.test/#/assets/vulnerability-card?vulnerabilityId=1e21d4ce-32c1-4001-0000-00000002d211&vulnerabilityInstanceId=${INST}`);
  // Пока идентификатор запроса «Все активы» не получен: без queryId, но с select
  assert.equal(VR.listUrl('filter(Host.OsName = "Astra")'), 'https://mp.test/#/assets?groupId=00000000-0000-0000-0000-000000000002&pdqlQuery=' + encodeURIComponent('filter(Host.OsName = "Astra") | select(@Host)'));
  assert.equal(VR.listUrl('filter(Host.@Vulners) | select(@Host, Host.@Vulners.Status as St)'), 'https://mp.test/#/assets?groupId=00000000-0000-0000-0000-000000000002&pdqlQuery=' + encodeURIComponent('filter(Host.@Vulners) | select(@Host, Host.@Vulners.Status as St)'), 'select уже есть: не дублируется');
  VR.get = async p => { assert.equal(p, '/api/assets_temporal_readmodel/v1/stored_queries/folders/queries'); return { nodes: [{ id: 'q-all', displayName: 'Все активы' }] }; };
  assert.equal(await VR.ensureDefaultQuery(), 'q-all');
  assert.match(VR.listUrl('filter(Host.@Vulners) | select(@Host)'), /#\/assets\?groupId=[0-9-]+&queryId=q-all&pdqlQuery=/);
  VR.get = async () => { throw new Error('не должен вызываться повторно'); };
  assert.equal(await VR.ensureDefaultQuery(), 'q-all', 'идентификатор кэшируется');
});

test('в 28.0 идентификатор запроса не запрашивается', async () => {
  const { VR, ctx, calls } = loadVR(); modern(ctx);
  assert.equal(await VR.ensureDefaultQuery(), null);
  assert.equal(calls.get.length, 0);
});

test('версия сервера: разбор и кэш', async () => {
  const { VR } = loadVR();
  let n = 0; VR.get = async () => { n++; return { productVersion: '27.6.33103' }; };
  const p = await VR.product();
  assert.deepEqual({ ...p }, { version: '27.6.33103', major: 27, minor: 6 });
  await VR.product(); assert.equal(n, 1, 'второй вызов из кэша');
  assert.equal(VR.productCached().major, 27);
  VR.resetProduct(); await VR.product(); assert.equal(n, 2, 'после сброса запрашивается заново');
  VR.get = async () => ({ productVersion: '28.0.42578' }); VR.resetProduct();
  assert.equal((await VR.product()).major, 28);
  VR.get = async () => ({}); VR.resetProduct();
  assert.deepEqual({ ...(await VR.product()) }, { version: '', major: 0, minor: 0 });
});

test('теги активов: доступны с 28.0, до ответа о версии судим по интерфейсу', async () => {
  const { VR, ctx } = loadVR();
  assert.equal(VR.hasAssetTags(), true, '28.0 по адресу');
  legacy(ctx); assert.equal(VR.hasAssetTags(), false, '27.x по адресу');
  await assert.rejects(VR.assetTags(), /28\.0/);
  await assert.rejects(VR.createAssetTag('auto:x', 'grey'), /28\.0/);
  await assert.rejects(VR.deleteAssetTag('id'), /28\.0/);
  await assert.rejects(VR.assignAssetTagsByIds({ ids: ['a'], addIds: ['t'] }), /28\.0/);
  await assert.rejects(VR.tagCoverage(), /28\.0/);
  await assert.rejects(VR.applyAutoTags({ rules: [{ name: 'auto:x', pdql: 'filter(Host) | select(@Host)' }] }), /28\.0/);
  // Версия сервера важнее адреса
  VR.get = async () => ({ productVersion: '28.0.1' }); await VR.product();
  assert.equal(VR.hasAssetTags(), true);
  modern(ctx); VR.resetProduct(); VR.get = async () => ({ productVersion: '27.6.1' }); await VR.product();
  assert.equal(VR.hasAssetTags(), false);
  assert.throws(() => VR.requireAssetTags(), /27\.6\.1/);
});
