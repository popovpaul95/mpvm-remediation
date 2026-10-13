// Даты для показа: ДД-ММ-ГГГГ везде, где их видит человек; технические значения (duedate Jira) остаются ISO.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadVR } from './_load.mjs';

test('fmtDate: чистая дата, полночь UTC, дата со временем, Date, число, мусор', () => {
  const { VR } = loadVR();
  assert.equal(VR.fmtDate('2026-09-30'), '30-09-2026');
  assert.equal(VR.fmtDate('2026-09-08T00:00:00Z'), '08-09-2026', 'полночь UTC (дата патча) не сдвигается зоной');
  assert.equal(VR.fmtDate('2026-09-08T00:00:00.000Z'), '08-09-2026');
  const local = new Date(2026, 5, 3, 18, 23);
  assert.equal(VR.fmtDate(local.toISOString()), '03-06-2026', 'время переводится в локальную дату');
  assert.equal(VR.fmtDate(local), '03-06-2026');
  assert.equal(VR.fmtDate(local.getTime()), '03-06-2026');
  assert.equal(VR.fmtDate(''), ''); assert.equal(VR.fmtDate(null), ''); assert.equal(VR.fmtDate(undefined), '');
  assert.equal(VR.fmtDate('не дата'), 'не дата', 'чужие строки не трогаются');
  assert.equal(VR.fmtDate('2026-13-45'), '45-13-2026', 'некорректная дата без падения');
});

test('fmtDateTime: дата и время в локальной зоне', () => {
  const { VR } = loadVR();
  const local = new Date(2026, 8, 30, 16, 5);
  assert.equal(VR.fmtDateTime(local), '30-09-2026 16:05');
  assert.equal(VR.fmtDateTime(local.toISOString()), '30-09-2026 16:05');
  assert.equal(VR.fmtDateTime(local.getTime()), '30-09-2026 16:05');
  assert.equal(VR.fmtDateTime('мусор'), 'мусор'); assert.equal(VR.fmtDateTime(''), '');
});

test('тексты задач Jira показывают ДД-ММ-ГГГГ, а поле duedate остается ISO', () => {
  const { VR } = loadVR({ now: '2026-09-30T10:00:00' });
  const sla = { slaCritDays: 1, slaHighDays: 7, slaMedDays: 30, slaLowDays: 90 };
  const issue = VR.buildAssetJiraIssue({ asset: { host: 'h', items: [{ sev: 'critical', score: 9, trend: true }] }, sla });
  assert.equal(issue.dueDate, '2026-10-01');
  assert.match(issue.description, /срок до 01-10-2026/);
  assert.doesNotMatch(issue.description, /2026-10-01/);
});

test('отчеты и CSV переводят даты ISO из данных', () => {
  const { VR } = loadVR();
  const t = VR.reports.valueText;
  assert.equal(t('2026-06-03'), '03-06-2026');
  assert.equal(t('2026-09-08T00:00:00Z'), '08-09-2026');
  const local = new Date(2026, 5, 3, 18, 23);
  assert.equal(t(local.toISOString()), '03-06-2026 18:23');
  assert.equal(t('CVE-2026-1234'), 'CVE-2026-1234', 'идентификаторы не похожи на даты');
  assert.equal(t('BDU:2026-01234'), 'BDU:2026-01234');
  assert.match(t({ found: '2026-06-03', n: 2 }), /^Обнаружена: 03-06-2026\nКоличество: 2$/);
});
