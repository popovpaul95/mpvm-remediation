import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadVR, deq } from './_load.mjs';
const { VR } = loadVR();
const m = {
  statuses: [{ St: 'new', N: '8' }, { St: 'inProgress', N: '2' }, { St: 'fixed', N: '3' }, { St: 'excluded', N: '2' }],
  slaRows: [
    { Sev: 'critical', Over: '1', Soon: '0', Age: '0-7', N: '4' }, { Sev: 'critical', Over: '0', Soon: '1', Age: '8-30', N: '2' },
    { Sev: 'high', Over: '0', Soon: '0', Age: '90+', N: '3' }, { Sev: 'High', Over: '1', Soon: '1', Age: '31-90', N: '1' },
  ],
  signals: [{ T: true, E: 'True', D: 'False', P: 'true', N: '5' }, { T: 'False', E: false, D: 'True', P: 'False', N: '4,0' }],
  assets: [{ Imp: 'H', Scan: 'Actual', Fresh: 'fresh', N: '3' }, { Imp: 'ND', Scan: 'Obsolete', Fresh: 'stale', N: '1' }, { Imp: '', Scan: 'NeverHappened', Fresh: '30-90', N: '2' }],
  flow: [{ New7: '4', New30: '6', Fixed: '3', Excluded: '2', Total: '15' }],
};
test('показатели обзора: арифметика статусов, сроков, возраста', () => {
  const c = VR.computeMetrics(m);
  assert.equal(c.total, 15); assert.equal(c.open, 10, 'open = total - fixed - excluded');
  assert.equal(c.overdue, 5); assert.equal(c.soon, 2, 'просроченные не считаются истекающими');
  deq(c.bySev.critical, { open: 6, over: 4, soon: 2, ok: 0 });
  deq(c.bySev.high, { open: 4, over: 1, soon: 0, ok: 3 });
  for (const s of Object.keys(c.bySev)) { const b = c.bySev[s]; assert.equal(b.open, b.over + b.soon + b.ok, s); }
  assert.equal(c.critOver, 4); assert.equal(c.critOpen, 6); assert.equal(c.highOver, 1); assert.equal(c.highOpen, 4);
  deq(c.age, { '0-7': 4, '8-30': 2, '31-90': 1, '90+': 3 });
  deq(Object.keys(c.age), VR.ageBuckets());
  assert.equal(c.new7, 4); assert.equal(c.new30, 6); assert.equal(c.fixed, 3); assert.equal(c.excluded, 2);
  assert.equal(c.assets, 6); assert.equal(c.noImp, 3); assert.equal(c.stale, 1); assert.equal(c.obsolete, 3); assert.equal(c.highImp, 3);
});
test('булевы сигналы в любом формате (D12), пустые и битые данные без исключений', () => {
  const c = VR.computeMetrics(m);
  assert.equal(c.trend, 5); assert.equal(c.expl, 5); assert.equal(c.danger, 4); assert.equal(c.patch, 5);
  const e = VR.computeMetrics({});
  assert.equal(e.open, 0); assert.equal(e.overdue, 0); deq(e.bySev, {});
  const bad = VR.computeMetrics({ statuses: { error: 'x' }, slaRows: 'нет', signals: null, assets: 5, flow: undefined });
  assert.equal(bad.total, 0); assert.equal(bad.trend, 0); assert.equal(bad.new30, 0);
});
