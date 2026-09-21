import test from 'node:test';
import assert from 'node:assert/strict';
import { checkGetLogsParams as check } from '../utils/getLogsGuard.js';

test('checks exact inclusive explicit range, including huge integers', () => {
  assert.deepEqual(check([{ fromBlock: '0x1', toBlock: '0x7d0' }]), { ok: true, range: 2000 });
  assert.equal(check([{ fromBlock: '0x1', toBlock: '0x7d1' }]).ok, false);
  assert.equal(check([{ fromBlock: '0x2', toBlock: '0x1' }]).ok, false);
  assert.equal(check([{ fromBlock: '0x20000000000001', toBlock: '0x20000000000001' }]).range, 1);
});

test('never guesses tag values or accepts noncanonical quantities', () => {
  for (const block of [undefined, null, 'latest', 'pending', 'safe', 'finalized', 'earliest', '1', 1, '0x01', '0x', '0x' + 'f'.repeat(1000)]) {
    assert.equal(check([{ fromBlock: block, toBlock: '0x20' }]).ok, false);
    assert.equal(check([{ fromBlock: '0x1', toBlock: block }]).ok, false);
  }
  for (const params of [undefined, [], [null], [[]], [{}], [{}, {}]]) assert.equal(check(params).ok, false);
});

test('block hash cannot bypass range validation', () => {
  const blockHash = '0x' + 'ab'.repeat(32);
  assert.deepEqual(check([{ blockHash }]), { ok: true, range: 1 });
  for (const filter of [{ blockHash: 'garbage' }, { blockHash: null },
    { blockHash, fromBlock: '0x0', toBlock: '0xffffff' }, { blockHash, toBlock: null }]) {
    assert.equal(check([filter]).ok, false);
  }
});

test('address/topic filters are validated and bounded', () => {
  const filter = { fromBlock: '0x1', toBlock: '0x2' };
  const address = '0x' + 'ab'.repeat(20), topic = '0x' + 'cd'.repeat(32);
  assert.equal(check([{ ...filter, address: [address], topics: [null, [topic]] }]).ok, true);
  for (const extra of [{ address: [] }, { address: 'bad' }, { address: Array(21).fill(address) },
    { topics: Array(5).fill(null) }, { topics: [[...Array(21).fill(topic)]] },
    { topics: ['bad'] }, { unknown: 1 }]) assert.equal(check([{ ...filter, ...extra }]).ok, false);
});
