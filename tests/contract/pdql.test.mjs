// Статические инварианты PDQL 28.0 для всех запросов, которые строит расширение:
// повторный filter после select там, где фильтр по коллекции отбирает узлы, а не строки; литералы в then/else;
// уникальные псевдонимы; экранирование строк; одинаковые корзины возраста в обзоре и выборке.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadVR, unescPdql, deq } from '../unit/_load.mjs';

async function collect() {
  const sla = { slaCritDays: 1, slaHighDays: 7, slaMedDays: 30, slaLowDays: 90 };
  const { VR, calls } = loadVR({ ext: op => op === 'settings-get' ? sla : op === 'enrich' ? { results: {} } : null });
  const named = {};
  const grab = async (name, fn) => { const start = calls.pdql.length; try { await fn(); } catch (_) {} calls.pdql.slice(start).forEach((c, i) => { named[name + (i ? '#' + i : '')] = c.pdql; }); };
  for (const scope of ['softs', 'packages', 'os', 'images']) {
    await grab('queue:' + scope, () => VR.queue({ scope, minScore: 7 }));
    await grab('detail:' + scope, () => VR.queueDetail({ scope, soft: 'A', ver: '1', pkg: 'A' }));
  }
  await grab('metrics', () => VR.metrics({ deep: true }));
  await grab('assetRisk', () => VR.assetRisk({}));
  await grab('exclusions', () => VR.exclusions({}));
  await grab('projects', () => VR.projects({}));
  await grab('projects:prefix', () => VR.projects({ prefix: 'proj:' }));
  await grab('assetVulns', () => VR.assetVulns('1e5569fb-4940-0001-0000-0000000000e9'));
  await grab('webVulns', () => VR.webVulns({}));
  await grab('imageSummary', () => VR.imageSummary());
  await grab('guidByCve', () => VR.guidByCve('CVE-2021-44228'));
  await grab('assetsInfo', () => VR.assetsInfo(['1e5569fb-4940-0001-0000-0000000000e9']));
  await grab('tagCoverage', () => VR.tagCoverage());
  for (const [kind, arg] of [['open'], ['overdue', sla], ['soon', sla], ['sev', 'critical'], ['sevOverdue', { sev: 'high', days: 7 }], ['trend'], ['exploit'], ['new30'], ['status', 'fixed'], ['cve', 'CVE-2020-1472'], ['tag', 'proj:x'], ['age', '0-7'], ['age', '8-30'], ['age', '31-90'], ['age', '90+'], ['asset', '1e5569fb-4940-0001-0000-0000000000e9'], ['noImportance'], ['staleScan']]) named['drill:' + kind + (typeof arg === 'string' ? ':' + arg : '')] = VR.drillPdql(kind, arg);
  VR.autoTagRules().forEach(r => { named['rule:' + r.name] = r.pdql; });
  return { VR, named };
}
const segs = q => q.split(/\s*\|\s*(?=(?:filter|select|calc|group|sort|limit|timepoint)\()/);
const pre = q => { const s = segs(q); const i = s.findIndex(x => x.startsWith('select(')); return { before: s.slice(0, i < 0 ? s.length : i), after: i < 0 ? [] : s.slice(i + 1) }; };

test('фильтр по коллекции до select повторяется после select (семантика 28.0)', async () => {
  const { named } = await collect();
  const bad = [];
  for (const [name, q] of Object.entries(named)) {
    if (!q || !/\| select\(/.test(q)) continue;
    const { before, after } = pre(q);
    // select только сущностей (@Host) намеренно отбирает узлы по условию на коллекцию: повторный фильтр не нужен
    const selectSeg = segs(q).find(s => s.startsWith('select(')) || '';
    if (!/\.@|Tags\.Item|Softs\.|Packages\.|@NodeVulners/.test(selectSeg)) continue;
    const preFilter = before.filter(s => s.startsWith('filter(')).join(' ');
    const postFilters = after.filter(s => s.startsWith('filter(')).join(' ');
    if (/Status in \[/.test(preFilter) && !/\bSt in \[/.test(postFilters)) bad.push(name + ': статус');
    if (/Status = "/.test(preFilter) && !/\bSt (=|in)/.test(postFilters)) bad.push(name + ': статус=');
    if (/Tags\.Item like/.test(preFilter) && !/\bTag like/.test(postFilters)) bad.push(name + ': метка');
    if (/(Softs|Packages)\[/.test(preFilter) && !/\bSoft = /.test(postFilters)) bad.push(name + ': ПО');
    if (/CVEs\.Item = /.test(preFilter) && !/\bCVE = /.test(postFilters)) bad.push(name + ': CVE');
  }
  deq(bad, []);
});
test('в then/else только литералы, псевдонимы select и calc уникальны без учета регистра', async () => {
  const { named } = await collect();
  const bad = [];
  for (const [name, q] of Object.entries(named)) {
    if (!q) continue;
    for (const m of q.matchAll(/\bthen\s+(\S+)|\belse\s+(?!if\b)(\S+)/g)) { const v = (m[1] || m[2]).replace(/\)+$/, ''); if (!/^(-?\d+(\.\d+)?|"[^"]*"|true|false|null)$/.test(v)) bad.push(`${name}: ${v}`); }
    const seen = new Set();
    for (const s of segs(q)) { if (!/^(select|calc)\(/.test(s)) continue; for (const m of s.matchAll(/ as (\w+)/g)) { const a = m[1].toLowerCase(); if (seen.has(a)) bad.push(`${name}: псевдоним ${m[1]}`); seen.add(a); } }
  }
  deq(bad, []);
});
test('строки с кавычками, обратными косыми и кириллицей экранируются без разрыва литерала', async () => {
  const { VR, calls } = loadVR();
  const soft = 'Яндекс "Браузер" 100%\\x', ver = '1.0 "b"';
  await VR.queueDetail({ scope: 'softs', soft, ver });
  const q = calls.pdql.pop().pdql;
  const m = q.match(/filter\(Soft = "((?:[^"\\]|\\.)*)" and Ver = "((?:[^"\\]|\\.)*)"/);
  assert.ok(m, q); assert.equal(unescPdql(m[1]), soft); assert.equal(unescPdql(m[2]), ver);
  const d = VR.drillPdql('cve', 'CVE-1"x');
  assert.equal(unescPdql(d.match(/filter\(CVE = "((?:[^"\\]|\\.)*)"\)/)[1]), 'CVE-1"x');
  assert.throws(() => VR.drillPdql('asset', 'abc) | filter(1=1'), /идентификатор/);
  assert.throws(() => VR.drillPdql('age', '7-8'), /корзина/);
  assert.ok(VR.drillPdql('overdue').includes('now()-1d'), 'значения сроков по умолчанию');
  assert.ok(VR.drillPdql('soon').includes('now()-6d'), '80% от 7 дней');
});
test('корзины возраста в обзоре и в выборке по клику совпадают (D7)', async () => {
  const { named, VR } = await collect();
  const calc = named['metrics#1'] || Object.values(named).find(q => /as Age\)/.test(q));
  assert.ok(calc, 'запрос сроков найден');
  assert.ok(calc.includes('if Found > now()-7d then "0-7" else if Found > now()-30d then "8-30" else if Found > now()-90d then "31-90" else "90+" as Age'));
  const expect = { '0-7': 'Found > now()-7d', '8-30': 'Found <= now()-7d and Found > now()-30d', '31-90': 'Found <= now()-30d and Found > now()-90d', '90+': 'Found <= now()-90d' };
  for (const [k, cond] of Object.entries(expect)) assert.ok(VR.drillPdql('age', k).includes(`and ${cond})`), k);
  deq(VR.ageBuckets(), Object.keys(expect));
});
