import { DatabaseSync } from 'node:sqlite';
import { TransactionError } from './index.js';

export class SQLiteReplayStore {
  #db;
  constructor(path) {
    this.#db = new DatabaseSync(path);
    this.#db.exec(`
      PRAGMA busy_timeout = 5000;
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      CREATE TABLE IF NOT EXISTS accepted_instructions (
        replay_key TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL,
        accepted_at INTEGER NOT NULL
      ) STRICT;
    `);
  }
  async consume(key, expiresAt, now) {
    if (!/^[a-f0-9]{64}$/.test(key) || !Number.isSafeInteger(now) || !Number.isSafeInteger(expiresAt) || expiresAt <= now) throw new TransactionError('INVALID_INPUT');
    return this.#db.prepare('INSERT OR IGNORE INTO accepted_instructions (replay_key, expires_at, accepted_at) VALUES (?, ?, ?)').run(key, expiresAt, now).changes === 1;
  }
  close() { this.#db.close(); }
}
