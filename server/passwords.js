// Hash de contraseñas con scrypt (incluido en Node, sin dependencias extra).
// Formato guardado: scrypt$N$r$p$salt(base64)$hash(base64)
const crypto = require('crypto');

const PARAMS = { N: 16384, r: 8, p: 1, keylen: 64 };
const PREFIX = 'scrypt$';

const scrypt = (password, salt, { N, r, p, keylen }) =>
    new Promise((resolve, reject) => {
        crypto.scrypt(password, salt, keylen, { N, r, p, maxmem: 64 * 1024 * 1024 }, (err, key) =>
            err ? reject(err) : resolve(key)
        );
    });

const isHashed = (value) => typeof value === 'string' && value.startsWith(PREFIX);

async function hashPassword(password) {
    const salt = crypto.randomBytes(16);
    const key = await scrypt(String(password), salt, PARAMS);
    return `${PREFIX}${PARAMS.N}$${PARAMS.r}$${PARAMS.p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

// Comparación en tiempo constante de dos textos (para valores heredados sin hash).
function safeEqual(a, b) {
    const ha = crypto.createHash('sha256').update(String(a)).digest();
    const hb = crypto.createHash('sha256').update(String(b)).digest();
    return crypto.timingSafeEqual(ha, hb);
}

async function verifyPassword(password, stored) {
    if (typeof password !== 'string' || typeof stored !== 'string') return false;
    // Valor heredado en texto plano: solo se acepta hasta que el servidor lo migra a hash.
    if (!isHashed(stored)) return safeEqual(password, stored);
    try {
        const parts = stored.slice(PREFIX.length).split('$');
        if (parts.length !== 5) return false;
        const [N, r, p, saltB64, keyB64] = parts;
        const salt = Buffer.from(saltB64, 'base64');
        const expected = Buffer.from(keyB64, 'base64');
        const params = { N: Number(N), r: Number(r), p: Number(p), keylen: expected.length };
        // Límites razonables por si el valor guardado fuese manipulado.
        if (!Number.isInteger(params.N) || params.N < 1024 || params.N > 65536) return false;
        if (!Number.isInteger(params.r) || params.r < 1 || params.r > 16) return false;
        if (!Number.isInteger(params.p) || params.p < 1 || params.p > 4) return false;
        if (!expected.length || expected.length > 128) return false;
        const key = await scrypt(password, salt, params);
        return key.length === expected.length && crypto.timingSafeEqual(key, expected);
    } catch {
        return false;
    }
}

module.exports = { hashPassword, verifyPassword, isHashed };
