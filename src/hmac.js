// =============================================================
// HMAC-SHA-256 activation token. The server signs a small JSON
// payload at activate time; the Elyonis client stores the token
// in the Windows registry and verifies it locally on every
// startup (so the licensee can launch offline). The /verify
// endpoint refreshes the token periodically.
// =============================================================

import { createHmac, timingSafeEqual } from 'node:crypto';

function secret() {
    const s = process.env.HMAC_SECRET;
    if (!s || s.length < 16) {
        throw new Error('HMAC_SECRET env var missing or too short (need 16+ chars)');
    }
    return s;
}

// Base64URL without padding -- compact, registry-safe.
function b64url(buf) {
    return Buffer.from(buf).toString('base64')
        .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64urlDecode(s) {
    const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
    return Buffer.from(
        s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad),
        'base64'
    );
}

// Token format: `${base64url(payloadJSON)}.${base64url(hmac)}`
// payload = { key, machineId, type, expiresAt, issuedAt, version }
export function sign(payload) {
    const body = b64url(JSON.stringify(payload));
    const mac  = b64url(createHmac('sha256', secret()).update(body).digest());
    return `${body}.${mac}`;
}

export function verify(token) {
    if (typeof token !== 'string' || !token.includes('.')) return null;
    const [body, mac] = token.split('.');
    const expected = b64url(createHmac('sha256', secret()).update(body).digest());
    if (expected.length !== mac.length) return null;
    if (!timingSafeEqual(Buffer.from(expected), Buffer.from(mac))) return null;
    try {
        return JSON.parse(b64urlDecode(body).toString('utf8'));
    } catch {
        return null;
    }
}
