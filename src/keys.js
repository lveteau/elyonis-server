// =============================================================
// Key generation primitives, shared between the CLI script and
// the admin HTTP endpoint so both paths produce identical formats.
// =============================================================

import { randomBytes } from 'node:crypto';

// 30-char alphabet excluding ambiguous chars (no 0/O/1/I/L/U) so a
// licensee can read and type a key off a sticker without mistakes.
const ALPHABET = '23456789ABCDEFGHJKMNPQRSTVWXYZ';

export function randomKey() {
    // 25 chars in 5 groups of 5. log2(30^25) ~= 122 bits of entropy.
    const bytes = randomBytes(25);
    let s = '';
    for (let i = 0; i < 25; i++) {
        s += ALPHABET[bytes[i] % ALPHABET.length];
        if (i === 4 || i === 9 || i === 14 || i === 19) s += '-';
    }
    return s;
}
