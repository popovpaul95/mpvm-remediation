import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadVR, deq } from './_load.mjs';

test('таймаут опроса отличим от завершенной операции (D10)', async () => {
  const { VR } = loadVR();
  VR.post = async () => ({ operationId: 'op-1' });
  let polls = 0; VR.get = async () => { polls++; return { totalCount: 100, succeedCount: 10, failedCount: 0 }; };
  const r = await VR.changeStatus({ ids: ['a', 'b'], command: 'SwitchToInProgressStateCommand' });
  assert.equal(polls, 40);
  assert.equal(r.done, false); assert.equal(r.pending, 90); assert.equal(r.succeed, 10); assert.equal(r.total, 100);
  VR.get = async () => ({ totalCount: 2, succeedCount: 2, failedCount: 0 });
  const ok = await VR.changeStatus({ ids: ['a', 'b'], command: 'SwitchToNewStateCommand' });
  assert.equal(ok.done, true); assert.equal(ok.pending, null);
});
test('тело запроса по командам', async () => {
  const { VR, calls } = loadVR();
  VR.post = async (p, b) => { calls.post.push({ p, b }); return { operationId: 'x' }; };
  VR.get = async () => ({ totalCount: 1, succeedCount: 1, failedCount: 0 });
  const base = { ids: ['i1'], tillDate: '2026-10-10T00:00:00Z', reason: 'falsePositive', note: 'n' };
  const bodies = {};
  for (const command of ['SwitchToInProgressStateCommand', 'SwitchToAwaitingFixStateCommand', 'SwitchToExcludeStateCommand', 'SwitchToNewStateCommand']) { await VR.changeStatus({ ...base, command }); bodies[command] = calls.post.pop().b; }
  deq(bodies.SwitchToInProgressStateCommand, { type: 'SwitchToInProgressStateCommand', vulnerabilitiesInstancesIds: ['i1'] });
  deq(bodies.SwitchToNewStateCommand, { type: 'SwitchToNewStateCommand', vulnerabilitiesInstancesIds: ['i1'] });
  deq(bodies.SwitchToAwaitingFixStateCommand, { type: 'SwitchToAwaitingFixStateCommand', vulnerabilitiesInstancesIds: ['i1'], tillDate: base.tillDate, statusNote: 'n' });
  deq(bodies.SwitchToExcludeStateCommand, { type: 'SwitchToExcludeStateCommand', vulnerabilitiesInstancesIds: ['i1'], statusReason: 'falsePositive', tillDate: base.tillDate, statusNote: 'n' });
  await VR.changeStatus({ ids: ['i1'], command: 'SwitchToExcludeStateCommand' });
  assert.equal(calls.post.pop().b.statusReason, 'acceptedAsLowRisk', 'причина по умолчанию только для исключения');
  const before = calls.post.length;
  await assert.rejects(VR.changeStatus({ ids: [null, ''], command: 'SwitchToNewStateCommand' }), /Нет идентификаторов/);
  assert.equal(calls.post.length, before, 'пустой список не отправляется');
});
test('формы идентификатора операции и ошибка опроса', async () => {
  const { VR } = loadVR();
  VR.get = async () => ({ totalCount: 1, succeedCount: 1, failedCount: 0 });
  for (const [resp, id] of [[{ operationId: 'a' }, 'a'], [{ id: 'b' }, 'b'], ['"c"', 'c'], [null, null]]) {
    VR.post = async () => resp;
    const r = await VR.changeStatus({ ids: ['x'], command: 'SwitchToNewStateCommand' });
    assert.equal(r.operationId, id);
    assert.equal(r.done, id ? true : null);
  }
  VR.post = async () => ({ operationId: 'z' });
  VR.get = async () => { throw new Error('HTTP 500'); };
  await assert.rejects(VR.changeStatus({ ids: ['x'], command: 'SwitchToNewStateCommand' }), /операция z .*HTTP 500/i);
});
