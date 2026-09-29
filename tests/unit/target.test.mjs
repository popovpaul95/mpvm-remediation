import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadVR, deq } from './_load.mjs';
const { VR } = loadVR();
const tv = (t, c) => VR.targetVersionFromHowToFix(t, c);

test('целевая версия никогда не ниже текущей (D1)', () => {
  assert.equal(tv('Обновите до 3.0.15', '3.0.20'), null);
  assert.equal(tv('Обновите до 3.0.20', '3.0.20'), null);
});
test('выбор ветки текущей версии', () => {
  assert.equal(tv('Обновите OpenSSL до версии 3.0.15, 3.1.7, 3.2.3 или 3.3.2', '3.0.2'), '3.0.15');
  assert.equal(tv('Windows 2016: v1607 - KB4601318 - 10.0.14393.4225; Windows 2019: 10.0.17763.1757; Windows 10 v2004 10.0.19041.1889', '10.0.14393'), '10.0.14393.4225');
  assert.equal(tv('обновите до 24.09', '24.07'), '24.09');
  assert.equal(tv('обновите до 3.3.2', '3.0.2'), '3.3.2', 'нет ветки: берется старшая');
});
test('даты, IP-адреса и оценки CVSS не считаются версиями (D3)', () => {
  const txt = 'Опубликовано 15.01.2024. Сервер 10.0.0.1. CVSS 9.8. Обновите до 2.4.58';
  assert.equal(tv(txt), '2.4.58');
  assert.equal(tv(txt, '2.4.50'), '2.4.58');
  assert.equal(tv('Опубликовано 15.01.2024, сервер 10.0.0.1, CVSS:3.1 7.5'), null);
  deq(VR.versionCandidates('версии 1.2.3 и 4.5.6.7.8'), ['1.2.3', '4.5.6.7.8']);
});
test('суффиксы версий сохраняются и сравниваются (D2)', () => {
  assert.equal(tv('обновите до 1.1.1k или 1.1.1w', '1.1.1j'), '1.1.1w');
  assert.equal(tv('исправлено в 2.34-0ubuntu3.1', '2.34-0ubuntu3'), '2.34-0ubuntu3.1');
  assert.equal(tv('исправлено в 2.34-0ubuntu3.1', '2.35'), null, 'deb-версия ниже текущей не предлагается');
  assert.ok(VR.cmpVersion('1.1.1k', '1.1.1') > 0);
  assert.ok(VR.cmpVersion('1.1.1k', '1.1.2') < 0);
  assert.ok(VR.cmpVersion('2.34', '2.34-0ubuntu3.1') < 0);
  assert.equal(VR.cmpVersion('10.0.14393', '10.0.14393'), 0);
});
