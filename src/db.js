// =============================================================
// SQLite handle + schema migration. Imported by every route
// handler; the same file initializes the DB on first import.
// =============================================================

import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const DB_PATH = resolve(process.env.DB_PATH ?? './data/licenses.db');
mkdirSync(dirname(DB_PATH), { recursive: true });

export const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');    // concurrent readers + a single writer
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');  // good balance for license-scale workloads

// ---------------------------------------------------------------
// Schema. We use a "version" pragma in the schema_meta table so a
// future migration can branch on the previous shape. Right now we
// only have v1.
// ---------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS licenses (
    -- The user-facing license key. Formatted XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
    -- (25 chars from a 32-char alphabet, ~125 bits of entropy).
    key            TEXT PRIMARY KEY,

    -- 'pool'      = generated, not yet activated
    -- 'activated' = locked to a machine
    -- 'revoked'   = admin-revoked, never re-usable
    status         TEXT NOT NULL CHECK (status IN ('pool','activated','revoked')),

    -- The Elyonis-computed machine fingerprint. NULL while in 'pool'.
    machine_id     TEXT,

    activated_at   INTEGER,         -- unix seconds, NULL while in 'pool'
    created_at     INTEGER NOT NULL,
    last_verify_at INTEGER,         -- updated on every /verify hit

    -- 'perpetual'    = never expires
    -- 'subscription' = expires_at must be set
    -- 'trial'        = same as subscription, but capped at 30 days
    type           TEXT NOT NULL CHECK (type IN ('perpetual','subscription','trial')),
    expires_at     INTEGER,         -- unix seconds, NULL = perpetual

    -- Admin-only metadata: customer name, order id, batch label, etc.
    notes          TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_licenses_machine_id ON licenses(machine_id);
  CREATE INDEX IF NOT EXISTS idx_licenses_status     ON licenses(status);

  -- Audit log: every activation / verify / deactivate / revoke writes
  -- a row here so we can trace abuse patterns and replay state.
  CREATE TABLE IF NOT EXISTS license_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key         TEXT NOT NULL,
    event       TEXT NOT NULL,      -- 'activate'|'verify'|'deactivate'|'revoke'|'reject'
    machine_id  TEXT,
    ip          TEXT,
    detail      TEXT,               -- short reason for rejects, version info, etc.
    created_at  INTEGER NOT NULL,
    FOREIGN KEY (key) REFERENCES licenses(key)
  );

  CREATE INDEX IF NOT EXISTS idx_events_key  ON license_events(key);
  CREATE INDEX IF NOT EXISTS idx_events_time ON license_events(created_at);
`);

// Bump schema_meta.version on every breaking migration so we can fail
// fast if an old binary is pointed at a newer DB.
const setVersion = db.prepare(`
  INSERT INTO schema_meta(key,value) VALUES ('version', ?)
  ON CONFLICT(key) DO UPDATE SET value = excluded.value
`);
setVersion.run('1');

// ---------------------------------------------------------------
// Prepared statements -- hot path.
// ---------------------------------------------------------------
export const stmts = {
  findKey: db.prepare('SELECT * FROM licenses WHERE key = ?'),

  // Activation flips pool -> activated and locks the machine_id.
  activate: db.prepare(`
    UPDATE licenses
    SET status = 'activated',
        machine_id = ?,
        activated_at = ?,
        last_verify_at = ?
    WHERE key = ? AND status = 'pool'
  `),

  // Heartbeat: bump last_verify_at on an already-activated key for
  // this machine. Returns rowsChanged so we can tell apart "match" vs
  // "mismatch / revoked".
  touchVerify: db.prepare(`
    UPDATE licenses
    SET last_verify_at = ?
    WHERE key = ? AND machine_id = ? AND status = 'activated'
  `),

  // Deactivate: clear machine_id, return to pool. Only the licensee
  // (proven by matching machine_id) can release a key.
  deactivate: db.prepare(`
    UPDATE licenses
    SET status = 'pool',
        machine_id = NULL,
        activated_at = NULL,
        last_verify_at = NULL
    WHERE key = ? AND machine_id = ? AND status = 'activated'
  `),

  // Admin / bookkeeping.
  insertKey:  db.prepare(`
    INSERT INTO licenses(key, status, created_at, type, expires_at, notes)
    VALUES (?, 'pool', ?, ?, ?, ?)
  `),
  listKeys:    db.prepare(`SELECT * FROM licenses ORDER BY created_at DESC LIMIT ? OFFSET ?`),
  revokeKey:   db.prepare(`UPDATE licenses SET status = 'revoked' WHERE key = ?`),

  logEvent: db.prepare(`
    INSERT INTO license_events(key, event, machine_id, ip, detail, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `),
};

export function nowSec() { return Math.floor(Date.now() / 1000); }
