// =============================================================
// One-off migration: copy all licenses + license_events from the old
// SQLite database into the Postgres pointed at by DATABASE_URL.
//
// Run ONCE when switching the server from SQLite to Postgres.
// better-sqlite3 is only needed for this script (not by the server),
// so install it ad-hoc:
//
//   npm install better-sqlite3 --no-save
//   node --env-file-if-exists=.env scripts/import-from-sqlite.js [path-to-sqlite.db]
//
// Idempotent: re-running skips licenses that already exist (ON CONFLICT
// DO NOTHING). Safe to point DATABASE_URL at production once deployed.
// =============================================================

import { pool, initDb } from '../src/db.js';

const SQLITE_PATH = process.argv[2] ?? './data/licenses.db';

let Database;
try {
    Database = (await import('better-sqlite3')).default;
} catch {
    console.error('better-sqlite3 not installed. Run: npm install better-sqlite3 --no-save');
    process.exit(1);
}

const sdb = new Database(SQLITE_PATH, { readonly: true });
const licenses = sdb.prepare('SELECT * FROM licenses').all();
const events   = sdb.prepare('SELECT * FROM license_events ORDER BY id').all();
sdb.close();

// license_events.key is a FK to licenses.key -- drop any orphan events so
// one bad row can't abort the whole transaction.
const keys = new Set(licenses.map((l) => l.key));
const goodEvents = events.filter((e) => keys.has(e.key));

await initDb();

let licCount = 0;
let evtCount = 0;
const client = await pool.connect();
try {
    await client.query('BEGIN');

    for (const l of licenses) {
        const r = await client.query(
            `INSERT INTO licenses
               (key, status, machine_id, activated_at, created_at,
                last_verify_at, type, expires_at, notes)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             ON CONFLICT (key) DO NOTHING`,
            [l.key, l.status, l.machine_id, l.activated_at, l.created_at,
             l.last_verify_at, l.type, l.expires_at, l.notes]
        );
        licCount += r.rowCount;
    }

    for (const e of goodEvents) {
        const r = await client.query(
            `INSERT INTO license_events(key, event, machine_id, ip, detail, created_at)
             VALUES ($1,$2,$3,$4,$5,$6)`,
            [e.key, e.event, e.machine_id, e.ip, e.detail, e.created_at]
        );
        evtCount += r.rowCount;
    }

    await client.query('COMMIT');
} catch (err) {
    await client.query('ROLLBACK');
    throw err;
} finally {
    client.release();
}

console.log(
    `Migrated ${licCount} new licenses (of ${licenses.length} in SQLite) ` +
    `and ${evtCount} events (of ${events.length}; ${events.length - goodEvents.length} orphans skipped).`
);

await pool.end();
