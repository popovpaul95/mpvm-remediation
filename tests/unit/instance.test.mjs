import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadVR, deq } from './_load.mjs';
const ID = '1e5566a8e0c000010000000000000012_1e5566a8e0c000010000000000000012_1e1e0794348140010000000000052b21';
const HOW = `Для устранения уязвимости установите накопительное обновление безопасности ОС Windows, выпущенное в июле 2025 или позднее.
Минимальные необходимые обновления и версии ядра:
Windows 2025:
    v24H2 - KB5062553 - 10.0.26100.4652
Windows 2022:
    v23H2 - KB5062572 - 10.0.25398.1732
    v21H2 - KB5062556 - 10.0.20348.3932
Windows 10:
    v21H2, v22H2 - KB5062554 - 10.0.19041.6093
Для максимальной защиты рекомендуем установить самое свежее накопительное обновление:
Windows 2022:
    v23H2 - KB5087541 - 10.0.25398.2330
    v21H2 - KB5122882 - 10.0.20348.5622`;
const details = { assetMetrics: { cvss3: { score: 8.8, vector: 'AV:L', environmentalScore: 7.7 }, overallScore: 7.7, severity: 'high' },
  detectionInfo: { vulnerType: 'softVulner', detectedAt: '2026-07-07T13:33:56Z', detectionDetails: { conditions: { productName: 'Microsoft Windows', productModelClassName: 'OperatingSystem.Windows.WindowsHost', productConditions: [
    { propertyName: 'Архитектура', propertyValue: 'x64', type: 'DiscreteConditionDetails' }, { propertyName: 'Тип установки', propertyValue: 'Server', type: 'DiscreteConditionDetails' },
    { propertyName: 'Название ОС', propertyValue: 'Windows 2022', type: 'DiscreteConditionDetails' }, { propertyName: 'Выпуск', propertyValue: '21H2', type: 'DiscreteConditionDetails' },
    { propertyName: 'Версия ядра', propertyValue: '10.0.20348.3207', leftValue: null, rightValue: '10.0.20348.3932', rightValueStrict: true, type: 'IntervalConditionDetails' } ] } } },
  currentStatus: { status: 'new', statusReason: null, date: '2026-07-07T13:33:56Z' }, tags: [], patchInfo: { displayName: 'Накопительное обновление KB5122882', type: 'updatePatch', date: '2026-09-08T00:00:00Z', link: { url: 'https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5122882' } } };
const row = (host, id, extra = {}) => ({ '@Host': { name: host, id: '1e5566a8-e0c0-0001-0000-000000000012' }, Imp: 'L', OS: 'Windows 2022', Name: { name: 'Несанкционированные операции' }, Id: id, Score: '7,7', Sev: { value: 'high' }, St: { value: 'new' }, Found: '2026-07-07T13:33:56Z', T: 'False', E: 'False', P: 'True', PatchName: 'KB5122882', PatchLink: { url: 'https://catalog/KB5122882' }, CVE: { displayName: 'CVE-2025-49723' }, ...extra });

test('разбор условий обнаружения: продукт, ОС, выпуск, текущая и требуемая версия', () => {
  const { VR } = loadVR();
  const d = VR.parseDetection(details);
  assert.equal(d.product, 'Microsoft Windows'); assert.equal(d.os, 'Windows 2022'); assert.equal(d.release, '21H2'); assert.equal(d.arch, 'x64'); assert.equal(d.installType, 'Server');
  assert.equal(d.versionLabel, 'Версия ядра'); assert.equal(d.current, '10.0.20348.3207'); assert.equal(d.required, '10.0.20348.3932'); assert.equal(d.requiredStrict, true);
  assert.equal(VR.parseDetection({}), null); assert.equal(VR.parseDetection(null), null);
});
test('варианты исправления в ветке текущей версии с номерами KB', () => {
  const { VR } = loadVR();
  const f = VR.fixOptions(HOW, '10.0.20348.3207');
  deq(f.options.map(o => o.version + '/' + o.kb), ['10.0.20348.3932/KB5062556', '10.0.20348.5622/KB5122882']);
  assert.equal(f.min.version, '10.0.20348.3932'); assert.equal(f.recommended.version, '10.0.20348.5622');
  assert.equal(VR.fixOptions(HOW, '10.0.20348.5622').options.length, 0, 'уже на актуальной версии');
  assert.equal(VR.fixOptions(HOW, '10.0.19041.1000').min.version, '10.0.19041.6093', 'ветка Windows 10');
  const ssl = VR.fixOptions('Обновите OpenSSL до 3.0.15, 3.1.7 или 3.2.3', '3.0.2');
  deq(ssl.options.map(o => o.version), ['3.0.15']); assert.equal(ssl.options[0].kb, null);
  assert.equal(VR.fixOptions('', '1.0').min, null);
});
test('экземпляры по CVE: дедупликация, сводка, повторный фильтр по CVE', async () => {
  const { VR, calls } = loadVR();
  VR.pdql = async (pdql, limit) => { calls.pdql.push({ pdql, limit }); return { records: [row('h1', ID), row('h1', ID), row('h2', ID.replace(/12_/g, '13_'), { St: { value: 'fixed' }, T: 'True' })] }; };
  const r = await VR.cveInstances({ cve: 'CVE-2025-49723' });
  assert.equal(r.items.length, 2); assert.equal(r.summary.total, 2); assert.equal(r.summary.open, 1); assert.equal(r.summary.trend, 1); assert.equal(r.summary.maxScore, 7.7); assert.equal(r.summary.patch, 2);
  assert.equal(r.items[0].vulnId, '1e1e0794-3481-4001-0000-000000052b21'); assert.equal(r.items[0].patchUrl, 'https://catalog/KB5122882'); assert.equal(r.items[0].hostId, '1e5566a8-e0c0-0001-0000-000000000012');
  assert.match(calls.pdql[0].pdql, /\| filter\(CVE = "CVE-2025-49723"\)/);
  await VR.cveInstances({ cve: 'CVE-1', assetId: '1e5566a8-e0c0-0001-0000-000000000012' });
  assert.match(calls.pdql[1].pdql, /^filter\(Host\.@Id = 1e5566a8-e0c0-0001-0000-000000000012 and /);
  await assert.rejects(VR.cveInstances({ cve: 'CVE-1', assetId: 'x) | filter(1=1' }), /идентификатор/);
  assert.equal(VR.instanceAssetGuid(ID), '1e5566a8-e0c0-0001-0000-000000000012');
  assert.match(VR.instanceUrl(ID), /vulnerability-card\?vulnerabilityId=1e1e0794-3481-4001-0000-000000052b21&vulnerabilityInstanceId=/);
});
test('контекст экземпляра: выбор по Id из адреса, по активу, иначе без выбранного', async () => {
  const { VR } = loadVR();
  VR.pdql = async () => ({ records: [row('h1', ID)] });
  VR.get = async p => /location/.test(p) ? { timelineToken: 'tok', objectId: 'obj', vulnerabilityLegacyId: 'v' } : /objects\/obj\/vulnerabilities\/v/.test(p) ? details : /statusLog/.test(p) ? [{ status: 'new' }] : /statistics/.test(p) ? { assetsCount: 69 } : /vulnerabilities\/1e1e0794/.test(p) ? { title: 'Несанкционированные операции', howToFix: HOW, identifiers: [{ displayName: 'BDU:2025-08330' }], links: [{ url: 'https://portal.msrc.microsoft.com/x' }] } : (() => { throw new Error('нет ' + p); })();
  const byInst = await VR.instanceContext({ cve: 'CVE-2025-49723', instanceId: ID });
  assert.equal(byInst.pickedBy, 'instance'); assert.equal(byInst.selected.item.id, ID);
  const s = byInst.selected;
  assert.equal(s.fix.min.version, '10.0.20348.3932'); assert.equal(s.fix.recommended.kb, 'KB5122882');
  deq(s.bdu, ['BDU:2025-08330']); deq(s.links, ['https://portal.msrc.microsoft.com/x']);
  assert.equal(s.metrics.overall, 7.7); assert.equal(s.metrics.base, 8.8); assert.equal(s.patch.name, 'Накопительное обновление KB5122882'); assert.equal(s.stats.assetsCount, 69);
  deq(s.errors, []);
  const byAsset = await VR.instanceContext({ cve: 'CVE-2025-49723', assetId: '1e5566a8-e0c0-0001-0000-000000000012' });
  assert.equal(byAsset.pickedBy, 'asset');
  const none = await VR.instanceContext({ cve: 'CVE-2025-49723' });
  assert.equal(none.selected, null); assert.equal(none.pickedBy, null);
  const other = await VR.instanceContext({ cve: 'CVE-2025-49723', instanceId: ID.replace(/12_/g, '99_') });
  assert.equal(other.selected, null, 'чужой экземпляр не подставляется');
  // частичные ошибки API не ломают контекст
  VR.get = async p => { if (/location/.test(p)) throw new Error('HTTP 503'); return { title: 't', howToFix: HOW, identifiers: [], links: [] }; };
  const partial = await VR.instanceDetailContext(byInst.selected.item);
  assert.equal(partial.det, null); assert.equal(partial.metrics, null); assert.equal(partial.patch.name, 'KB5122882', 'патч из PDQL при недоступных деталях'); assert.ok(partial.errors.some(e => /503/.test(e)));
});
test('задача Jira на экземпляр: заголовок с активом, патчем и версиями, приоритет, метки', () => {
  process.env.TZ = 'Europe/Moscow';
  const { VR } = loadVR({ now: '2026-09-29T21:30:00Z' });
  const item = { id: ID, host: 'kuopzhfvwq.rf.plat.form (10.1.2.209)', hostId: '1e5566a8-e0c0-0001-0000-000000000012', imp: 'L', os: 'Windows 2022', name: 'Несанкционированные операции', vulnId: '1e1e0794-3481-4001-0000-000000052b21', score: 7.7, sev: 'high', st: 'new', found: '2026-07-07T13:33:56Z', trend: false, expl: false, patch: true };
  const ctx = { cve: 'CVE-2025-49723', item, det: VR.parseDetection(details), fix: VR.fixOptions(HOW, '10.0.20348.3207'), bdu: ['BDU:2025-08330'], links: ['https://portal.msrc.microsoft.com/x'], metrics: { overall: 7.7, base: 8.8 }, status: { status: 'new' }, patch: { name: 'Накопительное обновление KB5122882', url: 'https://catalog/KB5122882', date: '2026-09-08' }, passport: { title: 'Несанкционированные операции', howToFix: HOW }, errors: [], urls: { card: 'https://mp.test/card', passport: 'https://mp.test/pass', asset: 'https://mp.test/asset' } };
  const sla = { slaCritDays: 1, slaHighDays: 7, slaMedDays: 30 };
  const issue = VR.buildInstanceJiraIssue({ ctx, enrich: { results: { 'CVE-2025-49723': { epss: { epss: 0.01 }, nvd: { cvss31: { score: 8.8 } } } } }, sla, host: 'mp.test' });
  assert.equal(issue.summary, 'Устранить CVE-2025-49723 на kuopzhfvwq.rf.plat.form: установить Накопительное обновление KB5122882 (Версия ядра 10.0.20348.3207 → не ниже 10.0.20348.3932, рекомендуется 10.0.20348.5622)');
  assert.equal(issue.level, 'P2'); assert.equal(issue.dueDate, '2026-10-07'); deq(issue.ids, [ID]); assert.equal(issue.targetVersion, '10.0.20348.5622');
  deq(issue.labels, ['mpvm-remediation', 'mpvm-instance', 'mpvm-microsoft-windows']);
  for (const s of ['Версия ядра: 10.0.20348.3207 (требуется >= 10.0.20348.3932)', 'https://catalog/KB5122882', '10.0.20348.5622 (KB5122882)', 'EPSS: 1.0%', 'БДУ: BDU:2025-08330', 'https://bdu.fstec.ru/vul/2025-08330', 'https://mp.test/card', 'базовая CVSS 3.1 по NVD 8.8']) assert.ok(issue.description.includes(s), s);
  const kev = VR.buildInstanceJiraIssue({ ctx, enrich: { results: { 'CVE-2025-49723': { kev: { dateAdded: '2026-01-01' } } } }, sla });
  assert.equal(kev.level, 'P0'); assert.ok(kev.summary.endsWith('[KEV]')); assert.equal(kev.dueDate, '2026-10-01');
  const bare = VR.buildInstanceJiraIssue({ ctx: { ...ctx, det: null, fix: { options: [], min: null, recommended: null }, patch: null, passport: null, bdu: [], links: [], metrics: null }, sla });
  assert.equal(bare.summary, 'Устранить CVE-2025-49723 на kuopzhfvwq.rf.plat.form: установить обновление');
});
