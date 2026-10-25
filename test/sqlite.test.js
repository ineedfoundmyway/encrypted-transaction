import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SQLiteReplayStore } from '../src/sqlite-replay-store.js';

test('SQLite replay records survive restart, expiry and separate connections', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'etx-'));
  const path = join(directory, 'inbox.db');
  let first;
  let second;
  try {
    first = new SQLiteReplayStore(path);
    const key = 'a'.repeat(64);
    assert.equal(await first.consume(key, 200, 100), true);
    first.close(); first = new SQLiteReplayStore(path);
    second = new SQLiteReplayStore(path);
    assert.equal(await first.consume(key, 400, 300), false);
    const results = await Promise.all([first.consume('b'.repeat(64), 500, 300), second.consume('b'.repeat(64), 500, 300)]);
    assert.equal(results.filter(Boolean).length, 1);
    await assert.rejects(first.consume('invalid', 500, 300), { code: 'INVALID_INPUT' });
    await assert.rejects(first.consume('c'.repeat(64), 300, 300), { code: 'INVALID_INPUT' });
  } finally {
    first?.close(); second?.close(); await rm(directory, { recursive: true, force: true });
  }
});
