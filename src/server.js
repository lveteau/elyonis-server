// =============================================================
// Elyonis license server -- Express + better-sqlite3.
//
// Public:
//   POST /api/license/activate    { key, machineId }
//   POST /api/license/verify      { key, machineId, token }
//   POST /api/license/deactivate  { key, machineId, token }
//
// Admin (Bearer ADMIN_TOKEN):
//   GET  /api/admin/keys
//   POST /api/admin/keys/:key/revoke
//   POST /api/admin/keys/:key/reset
// =============================================================

import express from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';

import { db, stmts, nowSec } from './db.js';
import { randomKey } from './keys.js';
import * as hmac from './hmac.js';

const PORT = parseInt(process.env.PORT ?? '3000', 10);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
if (!ADMIN_TOKEN || ADMIN_TOKEN.length < 16) {
    console.error('ADMIN_TOKEN env var missing or too short (16+ chars).');
    process.exit(1);
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '4kb' }));

// Trust the upstream proxy (Cloudflare Tunnel) so req.ip == real client IP.
app.set('trust proxy', 1);

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------
function logEvent(key, event, machineId, ip, detail) {
    try { stmts.logEvent.run(key, event, machineId ?? null, ip ?? null,
                              detail ?? null, nowSec()); }
    catch (e) { console.error('logEvent failed:', e.message); }
}

function isExpired(lic, now) {
    return lic.type !== 'perpetual' && lic.expires_at && lic.expires_at <= now;
}

const ActivateSchema   = z.object({ key: z.string().min(10).max(40),
                                     machineId: z.string().min(8).max(128) });
const VerifySchema     = z.object({ key: z.string().min(10).max(40),
                                     machineId: z.string().min(8).max(128),
                                     token: z.string().min(20).max(2048) });
const DeactivateSchema = VerifySchema;

// ---------------------------------------------------------------
// Public endpoints
// ---------------------------------------------------------------

// Activation: tightest rate limit since this is the abuse surface.
// 5 tries / IP / 15 min keeps brute-forcing license keys infeasible
// while leaving room for the licensee to retype a key once or twice.
const activateLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5,
    standardHeaders: true, legacyHeaders: false,
    message: { error: 'too-many-attempts' } });

app.post('/api/license/activate', activateLimiter, (req, res) => {
    const parsed = ActivateSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'invalid-body' });
    const { key, machineId } = parsed.data;

    const lic = stmts.findKey.get(key);
    if (!lic) {
        logEvent(key, 'reject', machineId, req.ip, 'not-found');
        return res.status(404).json({ error: 'unknown-key' });
    }
    if (lic.status === 'revoked') {
        logEvent(key, 'reject', machineId, req.ip, 'revoked');
        return res.status(403).json({ error: 'revoked' });
    }
    const now = nowSec();
    if (isExpired(lic, now)) {
        logEvent(key, 'reject', machineId, req.ip, 'expired');
        return res.status(403).json({ error: 'expired' });
    }

    // Idempotent re-activation on the SAME machine: just refresh
    // last_verify_at and re-issue a token. Licensees re-installing
    // on the same PC shouldn't need to call /deactivate first.
    if (lic.status === 'activated') {
        if (lic.machine_id !== machineId) {
            logEvent(key, 'reject', machineId, req.ip, 'machine-mismatch');
            return res.status(409).json({ error: 'in-use-elsewhere' });
        }
        stmts.touchVerify.run(now, key, machineId);
        const token = hmac.sign({
            key, machineId, type: lic.type,
            expiresAt: lic.expires_at, issuedAt: now, v: 1,
        });
        logEvent(key, 'activate', machineId, req.ip, 'idempotent');
        return res.json({ ok: true, token, type: lic.type,
                          expiresAt: lic.expires_at });
    }

    // Fresh activation: pool -> activated.
    const r = stmts.activate.run(machineId, now, now, key);
    if (r.changes !== 1) {
        // Race: another concurrent /activate beat us to it.
        logEvent(key, 'reject', machineId, req.ip, 'race-lost');
        return res.status(409).json({ error: 'in-use-elsewhere' });
    }
    const token = hmac.sign({
        key, machineId, type: lic.type,
        expiresAt: lic.expires_at, issuedAt: now, v: 1,
    });
    logEvent(key, 'activate', machineId, req.ip, 'fresh');
    return res.json({ ok: true, token, type: lic.type,
                      expiresAt: lic.expires_at });
});

// Verify: heartbeat. Lighter rate limit -- a healthy client calls
// at most once per startup + once per N days in the background.
const verifyLimiter = rateLimit({ windowMs: 60 * 1000, max: 30,
    standardHeaders: true, legacyHeaders: false,
    message: { error: 'too-many-requests' } });

app.post('/api/license/verify', verifyLimiter, (req, res) => {
    const parsed = VerifySchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'invalid-body' });
    const { key, machineId, token } = parsed.data;

    // Reject obviously-forged tokens before touching the DB.
    const payload = hmac.verify(token);
    if (!payload || payload.key !== key || payload.machineId !== machineId) {
        logEvent(key, 'reject', machineId, req.ip, 'bad-token');
        return res.status(401).json({ error: 'bad-token' });
    }

    const lic = stmts.findKey.get(key);
    if (!lic || lic.status !== 'activated' || lic.machine_id !== machineId) {
        logEvent(key, 'reject', machineId, req.ip, 'not-activated');
        return res.status(403).json({ error: 'not-activated' });
    }
    const now = nowSec();
    if (isExpired(lic, now)) {
        logEvent(key, 'reject', machineId, req.ip, 'expired');
        return res.status(403).json({ error: 'expired' });
    }

    stmts.touchVerify.run(now, key, machineId);
    // Re-issue a fresh token so the client's offline grace period
    // restarts each successful verify.
    const newToken = hmac.sign({
        key, machineId, type: lic.type,
        expiresAt: lic.expires_at, issuedAt: now, v: 1,
    });
    logEvent(key, 'verify', machineId, req.ip, null);
    return res.json({ ok: true, token: newToken, expiresAt: lic.expires_at });
});

app.post('/api/license/deactivate', verifyLimiter, (req, res) => {
    const parsed = DeactivateSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'invalid-body' });
    const { key, machineId, token } = parsed.data;

    const payload = hmac.verify(token);
    if (!payload || payload.key !== key || payload.machineId !== machineId) {
        logEvent(key, 'reject', machineId, req.ip, 'bad-token');
        return res.status(401).json({ error: 'bad-token' });
    }

    const r = stmts.deactivate.run(key, machineId);
    if (r.changes !== 1) {
        logEvent(key, 'reject', machineId, req.ip, 'deactivate-mismatch');
        return res.status(409).json({ error: 'not-activated-here' });
    }
    logEvent(key, 'deactivate', machineId, req.ip, null);
    return res.json({ ok: true });
});

// ---------------------------------------------------------------
// Admin
// ---------------------------------------------------------------
function requireAdmin(req, res, next) {
    const h = req.headers['authorization'] ?? '';
    const m = /^Bearer\s+(.+)$/i.exec(h);
    if (!m || m[1] !== ADMIN_TOKEN) {
        return res.status(401).json({ error: 'unauthorized' });
    }
    next();
}

app.get('/api/admin/keys', requireAdmin, (req, res) => {
    const limit  = Math.min(parseInt(req.query.limit  ?? '100', 10), 1000);
    const offset = parseInt(req.query.offset ?? '0', 10);
    const rows = stmts.listKeys.all(limit, offset);
    res.json({ ok: true, rows });
});

// Create a fresh key in the pool. Called by the Elyonis website after
// a successful Stripe checkout: the website POSTs the order details,
// receives the generated key, and emails it to the customer.
//
// Body:
//   { type: 'perpetual' | 'subscription' | 'trial',
//     durationDays?: number,   // mandatory unless type === 'perpetual'
//     notes?: string }          // e.g. customer email or order ID
const AdminCreateSchema = z.object({
    type: z.enum(['perpetual', 'subscription', 'trial']),
    durationDays: z.number().int().positive().max(36500).optional(),
    notes: z.string().max(256).optional(),
});

app.post('/api/admin/keys', requireAdmin, (req, res) => {
    const parsed = AdminCreateSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'invalid-body' });
    const { type, durationDays, notes } = parsed.data;

    if ((type === 'subscription' || type === 'trial') && !durationDays) {
        return res.status(400).json({
            error: 'missing-duration',
            detail: 'durationDays is required for subscription / trial',
        });
    }

    const now = nowSec();
    const expiresAt = durationDays ? now + durationDays * 86400 : null;

    // Collision-retry. With a 30-char alphabet over 25 positions the
    // birthday probability of a collision at our scale is microscopic,
    // but defending against it is cheap.
    let key = null;
    for (let i = 0; i < 8; i++) {
        const candidate = randomKey();
        if (!stmts.findKey.get(candidate)) { key = candidate; break; }
    }
    if (!key) return res.status(500).json({ error: 'key-generation-failed' });

    stmts.insertKey.run(key, now, type, expiresAt, notes ?? null);
    logEvent(key, 'create', null, req.ip, `admin/${type}`);
    res.status(201).json({ ok: true, key, type, expiresAt });
});

app.post('/api/admin/keys/:key/revoke', requireAdmin, (req, res) => {
    const r = stmts.revokeKey.run(req.params.key);
    if (r.changes !== 1) return res.status(404).json({ error: 'unknown-key' });
    logEvent(req.params.key, 'revoke', null, req.ip, 'admin');
    res.json({ ok: true });
});

// Force-reset (back to pool). Used when a licensee lost their old
// machine and can't /deactivate from there.
app.post('/api/admin/keys/:key/reset', requireAdmin, (req, res) => {
    const r = db.prepare(`
        UPDATE licenses
        SET status='pool', machine_id=NULL,
            activated_at=NULL, last_verify_at=NULL
        WHERE key = ? AND status != 'revoked'
    `).run(req.params.key);
    if (r.changes !== 1) return res.status(404).json({ error: 'unknown-key' });
    logEvent(req.params.key, 'reset', null, req.ip, 'admin');
    res.json({ ok: true });
});

// ---------------------------------------------------------------
// Health
// ---------------------------------------------------------------
app.get('/api/health', (_req, res) => {
    res.json({ ok: true, ts: nowSec() });
});

app.use((_req, res) => res.status(404).json({ error: 'not-found' }));

app.listen(PORT, () => {
    console.log(`elyonis-license server listening on :${PORT}`);
});
