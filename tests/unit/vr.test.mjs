import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadVR, deq } from './_load.mjs';
const { VR } = loadVR();
test('GUID паспорта из составного Id, числа и значения ячеек', () => {
  assert.equal(VR.vulnGuid('1e7a7b30a34000010000000000000002_1e7a7b340600a0010000000000003529_1e1e0792688140010000000000051ee9'), '1e1e0792-6881-4001-0000-000000051ee9');
  assert.equal(VR.vulnGuid('A_B_1E1E0792688140010000000000051EE9'), '1E1E0792-6881-4001-0000-000000051EE9');
  assert.equal(VR.vulnGuid('a_b_zzz'), null); assert.equal(VR.vulnGuid(null), null); assert.equal(VR.vulnGuid('a_b'), null);
  assert.equal(VR.num('4,1'), 4.1); assert.equal(VR.num(''), null); assert.equal(VR.num('abc'), null); assert.equal(VR.num(0), 0);
  assert.equal(VR.rowVal({ Tag: { displayName: 'x', color: 'red' } }, 'Tag'), 'x');
  assert.equal(VR.rowVal({ '@Host': { name: 'h', id: '1' } }, '@Host'), 'h');
});
test('CSV: инъекции формул нейтрализованы, кавычки и переводы строк экранированы (D9)', () => {
  const rows = [{ a: '=HYPERLINK("http://x")', b: '+1', c: '-5', d: '-cmd', e: '@x', f: 'a;b', g: 'line1\r\nline2', h: 'say "hi"' }];
  const out = VR.csv(rows, [['A', 'a'], ['B', 'b'], ['C', 'c'], ['D', 'd'], ['E', 'e'], ['F', 'f'], ['G', 'g'], ['H', 'h']]);
  const line = out.split('\n')[1];
  const cells = line.match(/("([^"]|"")*"|[^;]*)(;|$)/g).map(x => x.replace(/;$/, ''));
  assert.equal(cells[0], `"'=HYPERLINK(""http://x"")"`);
  assert.equal(cells[1], "'+1"); assert.equal(cells[2], '-5', 'отрицательное число не трогаем'); assert.equal(cells[3], "'-cmd"); assert.equal(cells[4], "'@x");
  assert.equal(cells[5], '"a;b"'); assert.equal(cells[6], 'line1 line2'); assert.equal(cells[7], '"say ""hi"""');
  assert.ok(out.startsWith('\uFEFF'));
});
test('разбор БДУ: CVE из идентификаторов, не из описания; CSV с переносом строки в кавычках (D8)', () => {
  const xml = '<vul><identifier>BDU:2024-00001</identifier><name>Уязвимость аналогично CVE-2020-9999</name><identifiers><identifier type="CVE">CVE-2024-1111</identifier></identifiers><severity>Высокий</severity><description>похожа на CVE-2020-8888</description><identify_date>01.02.2024</identify_date></vul><vul><identifier>BDU:2024-00002</identifier><identifiers><identifier type="CVE">cve-2024-1111</identifier></identifiers><severity>Низкий</severity></vul>';
  const mx = VR.parseBdu(xml);
  deq(Object.keys(mx).sort(), ['CVE-2024-1111']);
  deq(mx['CVE-2024-1111'].map(x => x.id + ':' + x.level), ['BDU:2024-00001:Высокий', 'BDU:2024-00002:Низкий']);
  const csv = 'BDU:2024-00003;"Описание\r\nна две строки CVE-2024-3333";Средний уровень;05.03.2024\r\nBDU:2024-00004;CVE-2024-4444, CVE-2024-4444;Критический;2024-03-06\n';
  const mc = VR.parseBdu(csv);
  deq(mc['CVE-2024-3333'], [{ id: 'BDU:2024-00003', level: 'Средн', date: '05.03.2024' }]);
  assert.equal(mc['CVE-2024-4444'].length, 1, 'дубли CVE в строке не размножают записи');
  assert.equal(mc['CVE-2024-4444'][0].date, '2024-03-06');
});
