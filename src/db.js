// =============================================================
// PostgreSQL handle + schema migration. Imported by every route
// handler; initDb() must be awaited once at startup to ensure the
// schema exists. Queries are exposed as async helpers on `stmts`
// so the call sites read like the old better-sqlite3 ones.
// =============================================================

import pg from 'pg';

const { Pool } = pg;

// Unix-second timestamps are stored as BIGINT. node-postgres returns
// BIGINT (OID 20) as a *string* by default to avoid precision loss; our
// values are well under Number.MAX_SAFE_INTEGER, so parse them back to
// numbers to keep the same shape the SQLite build returned.
pg.types.setTypeParser(20, (v) => (v === null ? null : parseInt(v, 10)));

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error('DATABASE_URL env var missing (e.g. postgres://user:pass@host:5432/db).');
  process.exit(1);
}

// Managed Postgres (Render, etc.) requires SSL; a local instance usually
// doesn't. Enable SSL unless we're talking to localhost.
const isLocal = /@(localhost|127\.0\.0\.1)[:/]/.test(connectionString);
export const pool = new Pool({
  connectionString,
  ssl: isLocal ? false : { rejectUnauthorized: false },
  max: 10,
});

export function nowSec() { return Math.floor(Date.now() / 1000); }

// ---------------------------------------------------------------
// Schema. Run once at boot. Idempotent (IF NOT EXISTS everywhere).
// schema_meta.version lets a future migration branch on the old shape.
// ---------------------------------------------------------------
export async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_meta (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS licenses (
      -- The user-facing license key. Formatted XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
      -- (25 chars from a 30-char alphabet, ~122 bits of entropy).
      key            TEXT PRIMARY KEY,

      -- 'pool'      = generated, not yet activated
      -- 'activated' = locked to a machine
      -- 'revoked'   = admin-revoked, never re-usable
      status         TEXT NOT NULL CHECK (status IN ('pool','activated','revoked')),

      -- The Elyonis-computed machine fingerprint. NULL while in 'pool'.
      machine_id     TEXT,

      activated_at   BIGINT,           -- unix seconds, NULL while in 'pool'
      created_at     BIGINT NOT NULL,
      last_verify_at BIGINT,           -- updated on every /verify hit

      -- 'perpetual'    = never expires
      -- 'subscription' = expires_at must be set
      -- 'trial'        = same as subscription, but capped at 30 days
      type           TEXT NOT NULL CHECK (type IN ('perpetual','subscription','trial')),
      expires_at     BIGINT,           -- unix seconds, NULL = perpetual

      -- Admin-only metadata: customer name, order id, batch label, etc.
      notes          TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_licenses_machine_id ON licenses(machine_id);
    CREATE INDEX IF NOT EXISTS idx_licenses_status     ON licenses(status);

    -- Audit log: every activation / verify / deactivate / revoke writes
    -- a row here so we can trace abuse patterns and replay state.
    CREATE TABLE IF NOT EXISTS license_events (
      id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      key         TEXT NOT NULL REFERENCES licenses(key),
      event       TEXT NOT NULL,      -- 'activate'|'verify'|'deactivate'|'revoke'|'reject'
      machine_id  TEXT,
      ip          TEXT,
      detail      TEXT,               -- short reason for rejects, version info, etc.
      created_at  BIGINT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_events_key  ON license_events(key);
    CREATE INDEX IF NOT EXISTS idx_events_time ON license_events(created_at);
  `);

  await pool.query(
    `INSERT INTO schema_meta(key, value) VALUES ('version', '1')
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`
  );
}

// ---------------------------------------------------------------
// Query helpers -- async mirrors of the old prepared statements.
// `.changes` mirrors better-sqlite3's run() result so server.js's
// `r.changes !== 1` checks stay identical.
// ---------------------------------------------------------------
export const stmts = {
  async findKey(key) {
    const r = await pool.query('SELECT * FROM licenses WHERE key = $1', [key]);
    return r.rows[0];
  },

  // Activation flips pool -> activated and locks the machine_id.
  async activate(machineId, activatedAt, lastVerifyAt, key) {
    const r = await pool.query(
      `UPDATE licenses
         SET status = 'activated', machine_id = $1,
             activated_at = $2, last_verify_at = $3
       WHERE key = $4 AND status = 'pool'`,
      [machineId, activatedAt, lastVerifyAt, key]
    );
    return { changes: r.rowCount };
  },

  // Heartbeat: bump last_verify_at on an already-activated key for
  // this machine.
  async touchVerify(lastVerifyAt, key, machineId) {
    const r = await pool.query(
      `UPDATE licenses
         SET last_verify_at = $1
       WHERE key = $2 AND machine_id = $3 AND status = 'activated'`,
      [lastVerifyAt, key, machineId]
    );
    return { changes: r.rowCount };
  },

  // Deactivate: clear machine_id, return to pool. Only the licensee
  // (proven by matching machine_id) can release a key.
  async deactivate(key, machineId) {
    const r = await pool.query(
      `UPDATE licenses
         SET status = 'pool', machine_id = NULL,
             activated_at = NULL, last_verify_at = NULL
       WHERE key = $1 AND machine_id = $2 AND status = 'activated'`,
      [key, machineId]
    );
    return { changes: r.rowCount };
  },

  // Admin force-reset back to pool (licensee lost their old machine).
  async resetKey(key) {
    const r = await pool.query(
      `UPDATE licenses
         SET status = 'pool', machine_id = NULL,
             activated_at = NULL, last_verify_at = NULL
       WHERE key = $1 AND status != 'revoked'`,
      [key]
    );
    return { changes: r.rowCount };
  },

  // Admin / bookkeeping.
  async insertKey(key, createdAt, type, expiresAt, notes) {
    await pool.query(
      `INSERT INTO licenses(key, status, created_at, type, expires_at, notes)
       VALUES ($1, 'pool', $2, $3, $4, $5)`,
      [key, createdAt, type, expiresAt, notes]
    );
  },

  async listKeys(limit, offset) {
    const r = await pool.query(
      `SELECT * FROM licenses ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
      [limit, offset]
    );
    return r.rows;
  },

  async revokeKey(key) {
    const r = await pool.query(
      `UPDATE licenses SET status = 'revoked' WHERE key = $1`,
      [key]
    );
    return { changes: r.rowCount };
  },

  async logEvent(key, event, machineId, ip, detail, createdAt) {
    await pool.query(
      `INSERT INTO license_events(key, event, machine_id, ip, detail, created_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [key, event, machineId, ip, detail, createdAt]
    );
  },
};
