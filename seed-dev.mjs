// Dev-only: seed a known key into a local dev DB so the running Elyonis
// (built with the default localhost:3000 + placeholder HMAC) can activate it.
process.env.DB_PATH = process.env.DB_PATH || './data/dev-licenses.db';
const { stmts, nowSec, db } = await import('./src/db.js');
const key = '98BCV-3MMWY-E7QNV-VHWGP-GMQXH';
const existing = stmts.findKey.get(key);
if (existing) {
  console.log('already present:', existing.key, existing.status, existing.type);
} else {
  stmts.insertKey.run(key, nowSec(), 'perpetual', null, 'dev seed');
  console.log('inserted perpetual pool key:', key);
}
console.log('DB:', process.env.DB_PATH);
