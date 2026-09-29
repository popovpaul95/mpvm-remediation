import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadVR } from './_load.mjs';
import { parseCsv } from '../csv-helper.mjs';

test('HTML и CSV сохраняют всё обогащение CVE и выбранный экземпляр', () => {
  const { VR } = loadVR();
  const enrich = { cves: ['CVE-2026-12345'], results: { 'CVE-2026-12345': {
    verdict: { level: 'P0', reasons: ['Обоснование из KEV'], slaDays: 1 },
    epss: { epss: 0.987654321, percentile: 0.99991, date: '2026-09-28' },
    kev: { vendor: 'Тестовый вендор', product: 'Сервис', ransomware: 'Known', dueDate: '2026-10-10' },
    nvd: { description: 'Полное описание '.repeat(100) + 'КОНЕЦ_ОПИСАНИЯ', cvss31: { vector: 'CVSS:3.1/AV:N/AC:L', score: 9.8 }, cwes: ['CWE-787'], refs: [{ url: 'https://vendor.example/fix?a=1&b=2', tags: ['Vendor Advisory'] }] },
    bdu: [{ id: 'BDU:2026-98765', level: 'Высокий' }], gh: { count: 2, items: [{ name: 'example/poc', url: 'https://github.com/example/poc', stars: 42, updated: '2026-09-29' }] },
    futureSource: { nested: { newField: 'НОВОЕ_ПОЛЕ_ИСТОЧНИКА' } }
  } }, meta: { kevError: 'ОШИБКА_ИСТОЧНИКА', nvdSkipped: 0 } };
  const ctx = { instances: { truncated: true, items: [{ host: 'all-instances.example', id: 'instance-all' }] }, selected: {
    item: { host: 'selected.example', id: 'instance-selected', found: '2026-09-28T12:00:00Z', sev: 'high', st: 'new' },
    det: { current: '1.2.3', required: '1.2.4', conditions: [{ name: 'Условие обнаружения', value: 'уязвимое ПО' }] },
    fix: { min: { version: '1.2.4' }, recommended: { version: '1.2.9' } },
    patch: { name: 'KB987654', url: 'https://vendor.example/patch' }, passport: { howToFix: 'УСТАНОВИТЕ_ИСПРАВЛЕНИЕ' },
    statusLog: [{ note: 'ИСТОРИЯ_СТАТУСА' }], tags: ['proj:export-test'], errors: ['ЧАСТИЧНАЯ_ОШИБКА']
  } };
  const spec = { title: 'Отчёт', sections: VR.reports.cveSections(enrich, { 'CVE-2026-12345': ctx }, { slaHighDays: 7, jiraToken: 'SECRET_MUST_NOT_EXPORT' }) };
  for (const output of [VR.reports.html(spec), VR.reports.csv(spec)]) {
    for (const expected of ['Обоснование из KEV', '0.987654321', '0.99991', 'Тестовый вендор', 'КОНЕЦ_ОПИСАНИЯ', 'CVSS:3.1/AV:N/AC:L', 'CWE-787', 'Vendor Advisory', 'BDU:2026-98765', 'example/poc', 'НОВОЕ_ПОЛЕ_ИСТОЧНИКА', 'ОШИБКА_ИСТОЧНИКА', 'all-instances.example', 'selected.example', '1.2.3', '1.2.4', '1.2.9', 'KB987654', 'УСТАНОВИТЕ_ИСПРАВЛЕНИЕ', 'ИСТОРИЯ_СТАТУСА', 'proj:export-test', 'ЧАСТИЧНАЯ_ОШИБКА', '2026-10-05T12:00:00.000Z', VR.reports.LIMIT_NOTE]) assert.ok(output.includes(expected), expected);
    assert.ok(!output.includes('SECRET_MUST_NOT_EXPORT'));
    assert.ok(!output.includes('[object Object]'));
  }
});

test('Экспорт не обрезает строки и не теряет новые поля поздних записей', () => {
  const { VR } = loadVR();
  const rows = Array.from({ length: 2501 }, (_, i) => ({ host: `HOST_${i}`, score: 0, patch: false }));
  rows[2500].futureField = 'ПОСЛЕДНЕЕ_ПОЛЕ';
  const spec = { title: 'Все узлы', sections: [{ ...VR.reports.table('Узлы', rows), limit: 30 }] };
  const html = VR.reports.html(spec), records = parseCsv(VR.reports.csv(spec));
  assert.match(html, /HOST_2500/);
  assert.match(html, /ПОСЛЕДНЕЕ_ПОЛЕ/);
  assert.ok(records.some(r => r[1] === '2501' && r[3] === 'HOST_2500'));
  assert.ok(records.some(r => r[1] === '2501' && r[3] === 'ПОСЛЕДНЕЕ_ПОЛЕ'));
  assert.ok(records.some(r => r[3] === '0'));
  assert.ok(records.some(r => r[3] === 'нет'));
  assert.ok(records.every(r => r.length === 4));
});

test('Отчёты экранируют HTML, ссылки и формулы CSV без потери текста', () => {
  const { VR } = loadVR();
  const text = '<img src=x onerror=alert(1)>; "цитата"\nновая строка';
  const spec = { title: '<script>alert(1)</script>', sections: VR.reports.dataSections('Данные', { text, formula: '=HYPERLINK("x")', url: 'javascript:alert(1)', safe: 'https://vendor.example/?a=1&b=2' }) };
  const html = VR.reports.html(spec), records = parseCsv(VR.reports.csv(spec));
  assert.ok(!html.includes('<script>') && !html.includes('<img'));
  assert.ok(!html.includes('href="javascript:'));
  assert.match(html, /href="https:\/\/vendor.example\/\?a=1&amp;b=2"/);
  assert.ok(records.some(r => r[3] === text));
  assert.ok(records.some(r => r[3] === '\'=HYPERLINK("x")'));
});

test('Пустой и частичный контекст отражает отсутствие данных, ошибки и загрузку', () => {
  const { VR } = loadVR();
  const spec = { title: 'Неполные данные', sections: VR.reports.cveSections({ cves: ['CVE-2026-12345'], results: { 'CVE-2026-12345': { nvd: null, epss: { epss: 0 }, gh: { count: 0, items: [] } } } }, { 'CVE-2026-12345': { selected: null, loading: true, selectionError: 'Ошибка экземпляра' } }) };
  for (const output of [VR.reports.html(spec), VR.reports.csv(spec)]) {
    assert.ok(output.includes('Нет данных'));
    assert.ok(output.includes('Нет записей'));
    assert.ok(output.includes('Загрузка выполняется'));
    assert.ok(output.includes('Ошибка экземпляра'));
  }
});

test('CSV экранирует также динамические заголовки и сохраняет многострочные описания', () => {
  const { VR } = loadVR();
  const csv = VR.csv([{ text: 'Первая строка\r\nВторая строка\rТретья' }], [['Поле; "новое"', 'text']]);
  assert.deepEqual(parseCsv(csv), [['Поле; "новое"'], ['Первая строка\nВторая строка\nТретья']]);
});

test('Реестр исключений сохраняет также обычные исключения и точную причину', async () => {
  const { VR } = loadVR();
  VR.pdql = async () => ({ records: [{ '@Host': { value: { name: 'host', id: 'h1' } }, Name: { value: 'Обычное исключение' }, Id: { value: 'i1' }, Score: { value: 3 }, Imp: { value: 'L' }, Reason: { value: 'falsePositive' }, Note: { value: 'Подтверждено владельцем' } }] });
  const data = await VR.exclusions();
  assert.equal(data.items.length, 1);
  assert.equal(data.risky.length, 0);
  assert.equal(data.items[0].note, 'Подтверждено владельцем');
});

test('CSV-вложения Jira сохраняют обогащение, все ID, контекст и ограничения выборки', () => {
  const { VR } = loadVR();
  const detail = { soft: 'ПО', ver: '1.0', rows: 1, truncated: true, ids: ['INSTANCE_ID'], hosts: [{ host: 'HOST_FULL', id: 'HOST_ID', os: 'ОС', imp: 'H', n: 1, maxScore: 9.8 }], cves: [{ cve: 'CVE-2026-12345', n: 1, score: 9.8 }], vulns: [{ name: 'Название из паспорта', n: 1 }] };
  const enrich = { cves: ['CVE-2026-12345'], results: { 'CVE-2026-12345': { epss: { epss: 0.123456 }, kev: { vendor: 'Вендор из KEV' }, verdict: { reasons: ['Основание приоритета'] } } } };
  const patch = { patch: 'KB12345', hosts: detail.hosts, maxScore: 9.8, url: 'https://vendor.example/patch' };
  const patchCsv = VR.buildPatchJiraIssue({ patch, detail, enrich, sla: {}, host: 'mp.test' }).csv;
  const groupCsv = VR.groupCsv(detail, enrich, { passports: { test: { howToFix: 'Полная инструкция' } }, assetsInfo: { HOST_ID: { groups: ['Важные серверы'] } } });
  for (const csv of [patchCsv, groupCsv]) {
    const rows = parseCsv(csv);
    assert.ok(rows.every(r => r.length === 4));
    for (const expected of ['HOST_FULL', 'HOST_ID', 'INSTANCE_ID', '0.123456', 'Вендор из KEV', 'Основание приоритета', VR.reports.LIMIT_NOTE]) assert.ok(csv.includes(expected), expected);
  }
  assert.ok(groupCsv.includes('Полная инструкция'));
  assert.ok(groupCsv.includes('Важные серверы'));
  assert.ok(patchCsv.includes('https://vendor.example/patch'));
  const asset = { assetId: 'HOST_ID', host: 'HOST_FULL', items: [{ id: 'INSTANCE_ID', name: 'Открытая уязвимость', cve: 'CVE-2026-12345', st: 'new', sev: 'high', score: 8 }], truncated: true };
  const assetCsv = VR.buildAssetJiraIssue({ asset, sla: {} }).csv;
  assert.ok(parseCsv(assetCsv).every(r => r.length === 4));
  for (const expected of ['HOST_ID', 'HOST_FULL', 'INSTANCE_ID', 'Открытая уязвимость', VR.reports.LIMIT_NOTE]) assert.ok(assetCsv.includes(expected));
});
