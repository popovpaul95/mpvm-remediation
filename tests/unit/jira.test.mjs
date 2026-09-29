import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadVR, deq } from './_load.mjs';
process.env.TZ = 'Europe/Moscow';
// 00:30 30 сентября по Москве: «+1 день» должен давать 1 октября, а не 30 сентября (D4)
const { VR } = loadVR({ now: '2026-09-29T21:30:00Z' });
const detail = (over = {}) => ({ soft: 'OpenSSL', ver: '3.0.2', rows: 120, truncated: false, ids: ['a', 'b'],
  cves: [{ cve: 'CVE-2024-1', score: 7.5, n: 60, trend: false, exploit: false }, { cve: 'CVE-2024-2', score: 9.8, n: 60, trend: false, exploit: true }],
  hosts: [{ host: 'h1', id: 'i1', n: 60, maxScore: 9.8 }, { host: 'h2', id: 'i2', n: 60, maxScore: 7.5 }], ...over });
const sla = { slaCritDays: 1, slaHighDays: 7, slaMedDays: 30, slaLowDays: 90 };

test('срок задачи считается по местному времени (D4)', () => {
  const kev = { results: { 'CVE-2024-2': { kev: { dateAdded: '2026-01-01' } } } };
  assert.equal(VR.buildJiraIssue({ detail: detail(), group: { maxScore: 9.8 }, enrich: kev, sla }).dueDate, '2026-10-01');
  assert.equal(VR.plusDays(1), '2026-10-01');
  assert.equal(VR.plusDays(0), '2026-09-30');
  assert.equal(VR.buildAssetJiraIssue({ asset: { host: 'h', items: [{ sev: 'critical', score: 9, trend: true }] }, sla }).dueDate, '2026-10-01');
});
test('матрица приоритетов и сроков', () => {
  const cases = [
    [{ enrich: { results: { 'CVE-2024-2': { kev: {} } } }, group: { maxScore: 5 } }, 'P0', 1, '[KEV]'],
    [{ detail: detail({ cves: [{ cve: 'CVE-1', score: 5, n: 1, trend: true }] }), group: { maxScore: 5 } }, 'P0', 1, '[трендовые]'],
    [{ group: { maxScore: 9 } }, 'P1', 1, ''],
    [{ group: { maxScore: 7 } }, 'P2', 7, ''],
    [{ group: { maxScore: 6.9 } }, 'P3', 30, ''],
    [{ group: {} }, 'P3', 30, ''],
  ];
  for (const [over, level, days, tag] of cases) {
    const issue = VR.buildJiraIssue({ detail: detail(), sla, ...over });
    assert.equal(issue.level, level, JSON.stringify(over));
    assert.equal(issue.priority, level);
    assert.equal(issue.dueDate, VR.plusDays(days));
    if (tag) assert.ok(issue.summary.endsWith(tag), issue.summary); else assert.ok(!/\[/.test(issue.summary));
  }
  // без настроек сроков: значения по умолчанию
  assert.equal(VR.buildJiraIssue({ detail: detail(), group: { maxScore: 7 }, sla: {} }).dueDate, VR.plusDays(7));
  assert.equal(VR.buildJiraIssue({ detail: detail(), group: { maxScore: 9 }, sla: { slaCritDays: 3 } }).dueDate, VR.plusDays(3));
});
test('метки Jira для кириллических названий уникальны и непусты (D5)', () => {
  const a = VR.buildJiraIssue({ detail: detail({ soft: 'Яндекс Браузер' }), sla }).labels[1];
  const b = VR.buildJiraIssue({ detail: detail({ soft: 'Касперский' }), sla }).labels[1];
  assert.notEqual(a, 'mpvm--'); assert.notEqual(b, 'mpvm--'); assert.notEqual(a, b);
  assert.equal(a, 'mpvm-yandeks-brauzer');
  assert.equal(VR.jiraLabel('OpenSSL 3.x'), 'mpvm-openssl-3-x');
  assert.match(VR.jiraLabel('文字'), /^mpvm-h[0-9a-f]+$/);
  assert.ok(VR.jiraLabel('a'.repeat(100)).length <= 45);
});
test('усеченная выборка и отсутствие целевой версии', () => {
  const issue = VR.buildJiraIssue({ detail: detail({ truncated: true, rows: 20000 }), group: { maxScore: 9 }, sla, passports: { 'CVE-2024-2': { howToFix: 'обновите до 3.0.1' } } });
  assert.ok(issue.description.includes('не менее 20000'));
  assert.ok(issue.description.includes('до актуальной версии вендора'), 'версия ниже текущей не предлагается');
  assert.equal(issue.targetVersion, null);
  const ok = VR.buildJiraIssue({ detail: detail(), group: { maxScore: 9 }, sla, passports: { 'CVE-2024-2': { howToFix: 'Обновите до 3.0.15, 3.1.7' } } });
  assert.equal(ok.targetVersion, '3.0.15');
  assert.ok(ok.summary.includes('до 3.0.15'));
});
