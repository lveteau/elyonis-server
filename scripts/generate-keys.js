// =============================================================
// Generate N license keys and dump them as CSV on stdout.
// =============================================================
//   node scripts/generate-keys.js [count] [type] [expiresAt] [notes]
//
// Defaults:
//   count     = 10
//   type      = 'perpetual' | 'subscription' | 'trial'
//   expiresAt = null (or unix seconds for subscription/trial)
//   notes     = empty
//
// Example:
//   node --env-file-if-exists=.env scripts/generate-keys.js 100 perpetual
//   node --env-file-if-exists=.env scripts/generate-keys.js 25 subscription 1798761600 "Q3 2026 batch"
// =============================================================

import { pool, stmts, nowSec, initDb } from '../src/db.js';
import { randomKey } from '../src/keys.js';

const count     = parseInt(process.argv[2] ?? '10', 10);
const type      = process.argv[3] ?? 'perpetual';
const expiresAt = process.argv[4] ? parseInt(process.argv[4], 10) : null;
const notes     = process.argv[5] ?? null;

if (!['perpetual', 'subscription', 'trial'].includes(type)) {
    console.error(`Invalid type: ${type}`);
    process.exit(1);
}
if ((type === 'subscription' || type === 'trial') && !expiresAt) {
    console.error(`Missing expiresAt for type ${type}`);
    process.exit(1);
}

await initDb();

const now = nowSec();

// Generate unique keys (collision check against the DB).
const fresh = [];
let tries = 0;
while (fresh.length < count && tries < count * 4) {
    tries++;
    const k = randomKey();
    if (await stmts.findKey(k)) continue;   // collision (extremely unlikely)
    fresh.push(k);
}

// Insert them atomically in one transaction.
const client = await pool.connect();
try {
    await client.query('BEGIN');
    for (const k of fresh) {
        await client.query(
            `INSERT INTO licenses(key, status, created_at, type, expires_at, notes)
             VALUES ($1, 'pool', $2, $3, $4, $5)`,
            [k, now, type, expiresAt, notes]
        );
    }
    await client.query('COMMIT');
} catch (e) {
    await client.query('ROLLBACK');
    throw e;
} finally {
    client.release();
}

// CSV out so it's trivial to import into a spreadsheet for ops.
console.log('key,type,expiresAt,createdAt');
for (const k of fresh) {
    console.log(`${k},${type},${expiresAt ?? ''},${now}`);
}
console.error(`Generated ${fresh.length} keys.`);

await pool.end();
