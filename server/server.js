require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { hashPassword, verifyPassword, isHashed } = require('./passwords');

const app = express();
app.disable('x-powered-by');
// Detrás del proxy de Vercel: necesario para que req.ip sea la IP real del cliente.
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production' || !!process.env.VERCEL;

// ===== Configuración =====
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const DEFAULT_GEMINI_MODEL = 'gemini-3.6-flash';
const FALLBACK_GEMINI_MODEL = 'gemini-flash-latest'; // solo si el modelo fijado devuelve 404
const _envModel = (process.env.GEMINI_MODEL || '').trim();
const RETIRED_MODEL = /^gemini-(1\.5|2\.0|2\.5)/;
const GEMINI_MODEL = (!_envModel || RETIRED_MODEL.test(_envModel)) ? DEFAULT_GEMINI_MODEL : _envModel;
if (_envModel && RETIRED_MODEL.test(_envModel)) {
    console.warn(`[Aviso] GEMINI_MODEL=${_envModel} está retirado; se usa ${DEFAULT_GEMINI_MODEL}. Actualiza o borra la variable.`);
}

// JWT_SECRET es obligatorio en producción (mínimo 32 caracteres). Ya no hay valor por defecto.
const _jwtEnv = process.env.JWT_SECRET;
const JWT_OK = typeof _jwtEnv === 'string' && _jwtEnv.length >= 32;
let SIGNING_SECRET = JWT_OK ? _jwtEnv : null;
if (!JWT_OK) {
    if (IS_PROD) {
        console.error('[FATAL] JWT_SECRET no está definida o tiene menos de 32 caracteres. El login queda deshabilitado.');
    } else {
        SIGNING_SECRET = crypto.randomBytes(48).toString('base64url');
        console.warn('[Aviso] JWT_SECRET no definida: se usa una clave temporal (las sesiones se pierden al reiniciar).');
    }
}
const authReady = () => !!SIGNING_SECRET;

const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || 'Afenrir').trim();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);

if (!GEMINI_API_KEY) {
    console.warn('\x1b[33m[Warning] GEMINI_API_KEY is not set. The AI endpoints will fail.\x1b[0m');
}

// ===== Almacenamiento (Upstash Redis / Vercel KV, o archivos JSON en local) =====
const KV_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const HAS_KV = !!(KV_URL && KV_TOKEN);
let _redis = null;
const redis = () => {
    if (!_redis) {
        const { Redis } = require('@upstash/redis');
        _redis = new Redis({ url: KV_URL, token: KV_TOKEN });
    }
    return _redis;
};

const FILE_FOR = { 'jogga-users': 'users.json', 'jogga-players-v2': 'players.json', 'jogga-players': 'players.json' };
const store = {
    async get(key) {
        if (HAS_KV) return (await redis().get(key)) ?? null;
        const file = path.join(__dirname, FILE_FOR[key]);
        if (!fs.existsSync(file)) return null;
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    },
    async set(key, value) {
        if (HAS_KV) { await redis().set(key, value); return; }
        fs.writeFileSync(path.join(__dirname, FILE_FOR[key]), JSON.stringify(value, null, 2));
    }
};

// ===== Límite de intentos (Redis si existe; si no, memoria) =====
const memHits = new Map();
const hit = async (key, windowSec) => {
    if (HAS_KV) {
        try {
            const r = redis();
            const k = `rl:${key}`;
            await r.set(k, 0, { ex: windowSec, nx: true });
            return await r.incr(k);
        } catch (e) {
            console.error('RateLimit KV error (se usa memoria):', e.message);
        }
    }
    const now = Date.now();
    const rec = memHits.get(key);
    if (!rec || now - rec.start > windowSec * 1000) {
        memHits.set(key, { count: 1, start: now, windowSec });
        return 1;
    }
    rec.count++;
    return rec.count;
};
const resetHits = async (key) => {
    memHits.delete(key);
    if (HAS_KV) { try { await redis().del(`rl:${key}`); } catch { /* sin importancia */ } }
};
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of memHits) if (now - v.start > v.windowSec * 1000) memHits.delete(k);
}, 5 * 60 * 1000).unref();

// ===== Usuarios =====
const ROLES = ['user', 'capitan', 'admin'];
const USERNAME_RE = /^[\p{L}\p{N}][\p{L}\p{N} _.\-]{2,23}$/u;

const loadUsers = async () => {
    const users = await store.get('jogga-users');
    return Array.isArray(users) ? users : [];
};
const saveUsers = (users) => store.set('jogga-users', users);
const findUser = (users, name) => users.find(u => (u.username || '').toLowerCase() === String(name).toLowerCase());

// Se ejecuta una vez por instancia, de forma perezosa (antes se hacía al importar, sin esperar).
let _ready = null;
const ensureReady = () => {
    if (!_ready) _ready = seedUsers().catch(err => { _ready = null; throw err; });
    return _ready;
};

async function seedUsers() {
    const users = await loadUsers();
    let changed = false;

    // 1) Migra contraseñas heredadas en texto plano a hash.
    for (const u of users) {
        if (u && typeof u.password === 'string' && !isHashed(u.password)) {
            u.password = await hashPassword(u.password);
            changed = true;
        }
    }

    // 2) El administrador se controla con ADMIN_PASSWORD (variable de entorno, nunca en el código).
    if (ADMIN_PASSWORD) {
        if (ADMIN_PASSWORD.length < 10) console.warn('[Aviso] ADMIN_PASSWORD es corta; usa al menos 10 caracteres.');
        const admin = findUser(users, ADMIN_USERNAME);
        if (!admin) {
            users.push({ username: ADMIN_USERNAME, password: await hashPassword(ADMIN_PASSWORD), role: 'admin' });
            changed = true;
        } else if (admin.role !== 'admin' || !(await verifyPassword(ADMIN_PASSWORD, admin.password))) {
            admin.password = await hashPassword(ADMIN_PASSWORD);
            admin.role = 'admin';
            changed = true;
        }
    } else if (!users.some(u => u.role === 'admin')) {
        console.warn('[Aviso] No hay administrador. Define ADMIN_PASSWORD (y opcionalmente ADMIN_USERNAME) y vuelve a desplegar.');
    }

    if (changed) await saveUsers(users);
}

let _dummyHash = null;
const dummyHash = () => (_dummyHash || (_dummyHash = hashPassword(crypto.randomBytes(16).toString('hex'))));

// ===== Autenticación =====
const authenticateToken = (req, res, next) => {
    if (!authReady()) return res.status(503).json({ error: 'Servidor sin configurar: falta JWT_SECRET.' });
    const [scheme, token] = (req.headers['authorization'] || '').split(' ');
    if (scheme !== 'Bearer' || !token) return res.status(401).json({ error: 'Acceso denegado' });
    jwt.verify(token, SIGNING_SECRET, { algorithms: ['HS256'] }, (err, payload) => {
        if (err) return res.status(401).json({ error: 'Sesión inválida o expirada' });
        req.user = { username: payload.username, role: payload.role };
        next();
    });
};
const requireRole = (...roles) => (req, res, next) =>
    roles.includes(req.user && req.user.role) ? next() : res.status(403).json({ error: 'No autorizado' });

// ===== Middleware global =====
const corsOptions = {
    origin: (origin, callback) => {
        if (!origin) return callback(null, true); // misma origen, curl, etc.
        if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
        if (!IS_PROD && /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return callback(null, true);
        return callback(null, false); // sin cabeceras CORS: el navegador lo bloquea
    }
};
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        let statusColor = '\x1b[32m';
        if (res.statusCode >= 400) statusColor = '\x1b[33m';
        if (res.statusCode >= 500) statusColor = '\x1b[31m';
        console.log(`\x1b[36m${req.method}\x1b[0m ${req.originalUrl} ${statusColor}${res.statusCode}\x1b[0m \x1b[90m${duration}ms\x1b[0m`);
    });
    next();
});

// Mantén esta política en sync con "routes" de vercel.json (allí se aplica al HTML estático).
const CSP = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdn.tailwindcss.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
    "font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'"
].join('; ');

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (IS_PROD) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    if (!req.path.startsWith('/api')) res.setHeader('Content-Security-Policy', CSP);
    next();
});

app.use(express.static(path.join(__dirname, '..', 'public'), {
    maxAge: '1d',
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
    }
}));

app.use('/api', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
});

// ===== Rutas =====
app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', service: 'Jogga Bonito App Backend', timestamp: new Date().toISOString(), geminiConfigured: !!GEMINI_API_KEY });
});

app.post('/api/login', async (req, res) => {
    if (!authReady()) return res.status(503).json({ error: 'Servidor sin configurar: falta JWT_SECRET.' });
    try {
        const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
        const password = typeof req.body?.password === 'string' ? req.body.password : '';
        if (!username || !password || username.length > 64 || password.length > 256) {
            return res.status(400).json({ error: 'Faltan datos' });
        }

        const ip = req.ip || 'unknown';
        const userKey = `login-user:${ip}:${username.toLowerCase()}`;
        const attemptsIp = await hit(`login-ip:${ip}`, 900);
        const attemptsUser = await hit(userKey, 900);
        if (attemptsIp > 30 || attemptsUser > 10) {
            res.setHeader('Retry-After', '900');
            return res.status(429).json({ error: 'Demasiados intentos. Espera unos minutos e inténtalo de nuevo.' });
        }

        await ensureReady();
        const users = await loadUsers();
        const user = findUser(users, username);
        // Si el usuario no existe se verifica contra un hash falso para no revelar su existencia por tiempo.
        const ok = await verifyPassword(password, user ? user.password : await dummyHash());
        if (!user || !ok) return res.status(401).json({ error: 'Credenciales incorrectas' });

        await resetHits(userKey);
        const token = jwt.sign({ username: user.username, role: user.role }, SIGNING_SECRET, { expiresIn: '24h', algorithm: 'HS256' });
        res.json({ success: true, token, role: user.role, username: user.username });
    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.post('/api/users', authenticateToken, requireRole('admin'), async (req, res) => {
    try {
        await ensureReady();
        const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
        const password = typeof req.body?.password === 'string' ? req.body.password : '';
        const role = (req.body?.role === undefined || req.body?.role === '') ? 'user' : req.body.role;

        if (!USERNAME_RE.test(username)) {
            return res.status(400).json({ error: 'Usuario inválido: 3 a 24 caracteres (letras, números, espacio, _ . -).' });
        }
        if (password.length < 8 || password.length > 128) {
            return res.status(400).json({ error: 'La contraseña debe tener entre 8 y 128 caracteres.' });
        }
        if (!ROLES.includes(role)) return res.status(400).json({ error: 'Rol inválido' });

        const users = await loadUsers();
        if (findUser(users, username)) return res.status(409).json({ error: 'El usuario ya existe' });

        users.push({ username, password: await hashPassword(password), role });
        await saveUsers(users);
        res.json({ success: true });
    } catch (err) {
        console.error('Create User Error:', err);
        res.status(500).json({ error: 'Error interno del servidor al crear usuario' });
    }
});

// ----- Plantilla (con versión para detectar ediciones simultáneas) -----
const MAX_PLAYERS = 200;
const MAX_PHOTO_CHARS = 400_000;
const MAX_PAYLOAD_CHARS = 4_000_000; // Vercel rechaza cuerpos de más de ~4,5 MB

const normalizePlayersDoc = (raw) => {
    if (Array.isArray(raw)) return { players: raw, version: 0 }; // formato antiguo
    if (raw && typeof raw === 'object' && Array.isArray(raw.players)) {
        return { players: raw.players, version: Number.isInteger(raw.version) ? raw.version : 0 };
    }
    return { players: null, version: 0 };
};
const loadPlayersDoc = async () => {
    let raw = await store.get('jogga-players-v2');
    if (raw == null && HAS_KV) raw = await store.get('jogga-players');
    return normalizePlayersDoc(raw);
};

const validatePlayers = (players) => {
    if (!Array.isArray(players)) return { status: 400, error: 'Se esperaba un array de jugadores' };
    if (players.length > MAX_PLAYERS) return { status: 400, error: `Límite de ${MAX_PLAYERS} jugadores excedido` };
    for (const p of players) {
        if (!p || typeof p !== 'object' || Array.isArray(p)) return { status: 400, error: 'Jugador inválido' };
        if (typeof p.name !== 'string' || !p.name.trim() || p.name.length > 80) return { status: 400, error: 'Nombre de jugador inválido' };
        if (!['string', 'number'].includes(typeof p.id)) return { status: 400, error: 'Jugador sin id' };
        if (p.photo) {
            if (typeof p.photo !== 'string' || !p.photo.startsWith('data:image/')) return { status: 400, error: 'Foto inválida' };
            if (p.photo.length > MAX_PHOTO_CHARS) return { status: 413, error: `La foto de ${p.name} es demasiado grande.` };
        }
        if (!Array.isArray(p.positions) || p.positions.length > 15) return { status: 400, error: 'Posiciones inválidas' };
    }
    if (JSON.stringify(players).length > MAX_PAYLOAD_CHARS) {
        return { status: 413, error: 'La plantilla es demasiado grande para guardarla (reduce el tamaño de las fotos).' };
    }
    return null;
};

app.get('/api/players', authenticateToken, async (_req, res) => {
    try {
        const doc = await loadPlayersDoc();
        res.json({ players: doc.players, version: doc.version });
    } catch (err) {
        console.error('Players GET Error:', err);
        res.status(500).json({ error: 'Failed to fetch players' });
    }
});

app.post('/api/players', authenticateToken, requireRole('admin', 'capitan'), async (req, res) => {
    try {
        const body = req.body;
        const legacy = Array.isArray(body); // clientes antiguos enviaban el array directamente
        const players = legacy ? body : body?.players;

        const invalid = validatePlayers(players);
        if (invalid) return res.status(invalid.status).json({ error: invalid.error });

        const current = await loadPlayersDoc();
        if (!legacy) {
            if (!Number.isInteger(body.baseVersion)) return res.status(400).json({ error: 'Falta baseVersion' });
            if (body.baseVersion !== current.version) {
                return res.status(409).json({
                    error: 'La plantilla fue modificada por otra persona.',
                    players: current.players,
                    version: current.version
                });
            }
        }

        const doc = { players, version: current.version + 1, updatedAt: new Date().toISOString(), updatedBy: req.user.username };
        await store.set('jogga-players-v2', doc);
        res.json({ success: true, version: doc.version });
    } catch (err) {
        console.error('Players SET Error:', err);
        res.status(500).json({ error: 'Failed to save players' });
    }
});

// ----- IA (Gemini) -----
const IMG_RE = /^data:(image\/(?:jpeg|png|webp|heic|heif));base64,([A-Za-z0-9+/=\s]+)$/;
const parseImage = (str) => {
    if (typeof str !== 'string' || !str || str.length > 15_000_000) return null;
    if (str.startsWith('data:')) {
        const m = IMG_RE.exec(str);
        return m ? { mimeType: m[1], data: m[2].replace(/\s+/g, '') } : null;
    }
    return /^[A-Za-z0-9+/=\s]+$/.test(str) ? { mimeType: 'image/jpeg', data: str.replace(/\s+/g, '') } : null;
};

// Convierte el historial {role, text} al formato de Gemini: empieza en "user", alterna roles
// y termina antes del mensaje actual.
const normalizeHistory = (history) => {
    if (!Array.isArray(history)) return [];
    const out = [];
    for (const h of history.slice(-12)) {
        if (!h || (h.role !== 'user' && h.role !== 'model') || typeof h.text !== 'string') continue;
        const text = h.text.trim().slice(0, 4000);
        if (!text) continue;
        const last = out[out.length - 1];
        if (last && last.role === h.role) last.parts[0].text += '\n' + text;
        else out.push({ role: h.role, parts: [{ text }] });
    }
    while (out.length && out[0].role !== 'user') out.shift();
    while (out.length && out[out.length - 1].role === 'user') out.pop();
    return out;
};

const callGemini = (model, payload, signal) =>
    fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': GEMINI_API_KEY },
        body: payload,
        signal
    });

app.post('/api/ai', authenticateToken, async (req, res) => {
    if (!GEMINI_API_KEY) return res.status(500).json({ error: 'GEMINI_API_KEY no configurada.' });

    if ((await hit(`ai:${req.user.username.toLowerCase()}`, 60)) > 20) {
        return res.status(429).json({ error: 'Demasiadas solicitudes a la IA. Espera un minuto.' });
    }

    let { system, prompt, image, history, json } = req.body || {};

    if (prompt !== undefined) {
        if (typeof prompt !== 'string') return res.status(400).json({ error: 'Invalid prompt format.' });
        prompt = prompt.trim().substring(0, 10000);
    }
    if (!prompt) return res.status(400).json({ error: 'El campo "prompt" es requerido.' });

    if (system !== undefined) {
        if (typeof system !== 'string') return res.status(400).json({ error: 'Invalid system format.' });
        system = system.trim().substring(0, 20000);
    }

    let img = null;
    if (image !== undefined && image !== null) {
        img = parseImage(image);
        if (!img) return res.status(400).json({ error: 'Formato de imagen inválido (usa JPEG, PNG o WebP).' });
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 60000);
    try {
        const parts = [{ text: prompt }];
        if (img) parts.push({ inlineData: { mimeType: img.mimeType, data: img.data } });

        const generationConfig = { temperature: 0.7 };
        if (json === true) generationConfig.responseMimeType = 'application/json';

        const requestBody = { contents: [...normalizeHistory(history), { role: 'user', parts }], generationConfig };
        if (system) requestBody.systemInstruction = { parts: [{ text: system }] };
        const payload = JSON.stringify(requestBody);

        let response = await callGemini(GEMINI_MODEL, payload, controller.signal);
        if (response.status === 404 && GEMINI_MODEL !== FALLBACK_GEMINI_MODEL) {
            console.warn(`[Gemini] ${GEMINI_MODEL} no encontrado; se reintenta con ${FALLBACK_GEMINI_MODEL}`);
            response = await callGemini(FALLBACK_GEMINI_MODEL, payload, controller.signal);
        }

        let data;
        try { data = await response.json(); } catch { data = null; }

        if (!response.ok) {
            console.error('\x1b[31m[Gemini API Error]\x1b[0m', response.status, JSON.stringify(data));
            return res.status(response.status === 429 ? 429 : 502).json({
                error: 'Error de la API de Gemini',
                details: String(data?.error?.message || 'Error desconocido').slice(0, 200)
            });
        }

        const text = (data?.candidates?.[0]?.content?.parts || []).map(p => p.text || '').join('').trim() || null;
        if (!text) return res.status(502).json({ error: 'Gemini no devolvió una respuesta válida.' });

        res.json({ text });
    } catch (err) {
        if (err.name === 'AbortError') return res.status(504).json({ error: 'Timeout de la API de Gemini' });
        console.error('\x1b[31m[Server Error]\x1b[0m', err.message);
        res.status(500).json({ error: 'Error interno.' });
    } finally {
        clearTimeout(timeoutId);
    }
});

// ===== Fallbacks =====
app.use('/api', (_req, res) => res.status(404).json({ error: 'Ruta no encontrada' }));
app.get('*', (_req, res) => { res.sendFile(path.join(__dirname, '..', 'public', 'index.html')); });

app.use((err, _req, res, _next) => {
    if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'La solicitud es demasiado grande.' });
    if (err && (err.type === 'entity.parse.failed' || err instanceof SyntaxError)) return res.status(400).json({ error: 'JSON inválido.' });
    console.error('[Unhandled]', err && err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
});

if (process.env.VERCEL || require.main !== module) {
    module.exports = app;
} else {
    const server = app.listen(PORT, () => {
        console.log('');
        console.log('  ⚽ Jogga Bonito App Backend');
        console.log('  ────────────────────────────────');
        console.log(`  🌐 http://localhost:${PORT}`);
        console.log(`  🤖 Gemini Model: ${GEMINI_MODEL}`);
        console.log(`  🔑 API Key: ${GEMINI_API_KEY ? '✅ Configurada' : '\x1b[31m❌ NO configurada\x1b[0m'}`);
        console.log(`  🔐 JWT: ${JWT_OK ? '✅ Configurado' : '⚠️  temporal (solo desarrollo)'}`);
        console.log(`  💾 Datos: ${HAS_KV ? 'Redis (Upstash/KV)' : 'archivos JSON locales'}`);
        console.log('  ────────────────────────────────');
        console.log('');
    });

    const shutdown = () => {
        console.log('\n\x1b[33m[Shutting down] Closing server gracefully...\x1b[0m');
        server.close(() => {
            console.log('\x1b[32m[Shutting down] Server closed.\x1b[0m');
            process.exit(0);
        });
        setTimeout(() => {
            console.error('\x1b[31m[Shutting down] Forcing shutdown after 10s.\x1b[0m');
            process.exit(1);
        }, 10000).unref();
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
}
