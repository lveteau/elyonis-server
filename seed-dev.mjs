// Dev-only: seed a known key into a local dev DB so the running Elyonis
// (built with the default localhost:3000 + placeholder HMAC) can activate it.
process.env.DB_PATH = process.env.DB_PATH || './data/dev-licenses.db';
const { stmts, nowSec, db } = await import('./src/db.js');
// Une clé par pack commercialisé : la différence Basique / Premium se teste
// côté client (la dictée vocale est fermée en Basique), il faut donc pouvoir
// activer l'un ou l'autre sans reconstruire la base.
const seeds = [
  { key: '98BCV-3MMWY-E7QNV-VHWGP-GMQXH', pack: 'premium', notes: 'dev seed premium' },
  { key: '4KJ7T-QW2ND-8XRVB-M5HCP-Z3FGY', pack: 'basic',   notes: 'dev seed basique' },
];
for (const s of seeds) {
  const existing = stmts.findKey.get(s.key);
  if (existing) {
    console.log('already present:', existing.key, existing.status, existing.type,
                existing.pack);
    continue;
  }
  stmts.insertKey.run(s.key, nowSec(), 'perpetual', null, s.pack, s.notes);
  console.log(`inserted perpetual pool key (${s.pack}):`, s.key);
}
console.log('DB:', process.env.DB_PATH);
