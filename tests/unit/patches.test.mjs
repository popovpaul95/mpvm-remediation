import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadVR, deq } from './_load.mjs';
const host = (name, id) => ({ '@Host': { name, id } });
const row = (patch, h, n, extra = {}) => ({ ...host(h, 'id-' + h), OS: 'Windows 2022', Imp: { value: 'H' }, Patch: patch, PDate: '2026-09-08T00:00:00Z', N: String(n), MaxScore: '9,1', Trend: '1', Expl: '2', Crit: '0', ...extra });

test('патчи: агрегация патч x актив, ссылки, строка без ссылки, сортировка по числу уязвимостей', async () => {
  const { VR } = loadVR();
  VR.pdql = async q => /Link/.test(q) && !/@Host/.test(q)
    ? { records: [{ Patch: 'KB5122882', Link: { url: 'https://catalog/KB5122882' }, N: '3' }, { Patch: null, Link: { url: null }, N: '5' }] }
    : { records: [row('KB5122882', 'h1', 2), row('KB5122882', 'h2', 1), row('KB5122876', 'h1', 10, { Trend: '0', Expl: '0', MaxScore: '7' }), row('', 'h3', 5), row('KB5122882', 'h1', 4, { Imp: { value: 'L' } })] };
  const r = await VR.patches({});
  deq(r.patches.map(p => [p.patch, p.n, p.hostsCount, p.url, p.kb]), [['KB5122876', 10, 1, '', 'KB5122876'], ['KB5122882', 7, 2, 'https://catalog/KB5122882', 'KB5122882']]);
  assert.equal(r.patches[1].hosts.find(h => h.id === 'id-h1').n, 6, 'узел учитывается один раз, уязвимости суммируются');
  assert.equal(r.patches[1].trend, 3); assert.equal(r.patches[1].maxScore, 9.1); assert.equal(r.patches[1].date, '2026-09-08T00:00:00Z');
  assert.equal(r.noLink.n, 5); assert.equal(r.noLink.hostsCount, 1);
  deq(r.total, { patches: 2, vulns: 17, hosts: 2, noLinkVulns: 5, noLinkHosts: 1 });
});
test('детали патча: экземпляры по Id, CVE, узлы; задача Jira на патч', async () => {
  process.env.TZ = 'Europe/Moscow';
  const { VR } = loadVR({ now: '2026-09-29T21:30:00Z' });
  const ID = 'a'.repeat(32) + '_' + 'b'.repeat(32) + '_' + '1e1e0794348140010000000000052b21';
  const rec = (h, id, cve, score, extra = {}) => ({ ...host(h, 'id-' + h), OS: 'Windows 2022', Imp: { value: 'H' }, Patch: 'KB1', Name: { name: 'Уязвимость X' }, CVE: { displayName: cve }, Score: String(score), Id: id, St: { value: 'new' }, T: 'False', E: 'True', ...extra });
  VR.pdql = async () => ({ records: [rec('h1', ID, 'CVE-1', 9.3), rec('h1', ID, 'CVE-2', 9.3, { T: 'True' }), rec('h2', ID.replace(/a/g, 'c'), 'CVE-1', 7)] });
  const d = await VR.patchDetail({ patch: 'KB1' });
  assert.equal(d.rows, 2, 'экземпляр с двумя CVE считается один раз'); assert.equal(d.ids.length, 2); assert.equal(d.hosts.length, 2); assert.equal(d.hosts[0].n, 1);
  deq(d.cves.map(c => [c.cve, c.n, c.score, c.trend]), [['CVE-1', 2, 9.3, false], ['CVE-2', 1, 9.3, true]]);
  assert.equal(d.vulns[0].n, 2);
  const issue = VR.buildPatchJiraIssue({ patch: { patch: 'Накопительное обновление KB5122876', url: 'https://catalog/KB5122876', date: '2026-09-08T00:00:00Z', maxScore: 9.3, kb: 'KB5122876' }, detail: d, enrich: { results: { 'CVE-1': { kev: { dateAdded: '2026-01-01' } } } }, sla: { slaCritDays: 1, slaHighDays: 7 }, host: 'mp.test' });
  assert.equal(issue.summary, 'Установить Накопительное обновление KB5122876 на 2 узлах: закрывает 2 уязвимостей (2 CVE) [KEV]');
  assert.equal(issue.level, 'P0'); assert.equal(issue.dueDate, '2026-10-01'); deq(issue.ids, d.ids); deq(issue.labels, ['mpvm-remediation', 'mpvm-patch', 'mpvm-kb5122876']);
  for (const s of ['https://catalog/KB5122876', '1 CVE в каталоге CISA KEV', '|CVE-1|9.3|-|да|-|да|2|', '* h1 (Windows 2022, значимость высокая, 1 уязв., max CVSS 9.3)']) assert.ok(issue.description.includes(s), s);
  assert.ok(issue.csv.includes('id-h1')); assert.ok(issue.csv.includes('Windows 2022')); assert.ok(issue.csv.includes('CVE-2'));
  const plain = VR.buildPatchJiraIssue({ patch: { patch: 'KB1', url: '', date: '', maxScore: 6, kb: 'KB1' }, detail: { ...d, cves: d.cves.map(c => ({ ...c, trend: false })) }, enrich: null, sla: {} });
  assert.equal(plain.level, 'P3'); assert.ok(!/\[/.test(plain.summary));
});
