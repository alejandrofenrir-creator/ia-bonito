require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-2.0-flash';
const IS_DEV = process.env.NODE_ENV !== 'production';

// 10. Startup validation
if (!GEMINI_API_KEY) {
    console.warn('\x1b[33m[Warning] GEMINI_API_KEY is not set. The AI endpoints will fail.\x1b[0m');
}

// 9. Better CORS config
const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || !IS_DEV || origin.startsWith('http://localhost') || origin.startsWith('http://127.0.0.1')) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    }
};
app.use(cors(corsOptions));

app.use(express.json({ limit: '10mb' }));

// 2. Request logging
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        let statusColor = '\x1b[32m'; // green
        if (res.statusCode >= 400) statusColor = '\x1b[33m'; // yellow
        if (res.statusCode >= 500) statusColor = '\x1b[31m'; // red
        
        console.log(`\x1b[36m${req.method}\x1b[0m ${req.originalUrl} ${statusColor}${res.statusCode}\x1b[0m \x1b[90m${duration}ms\x1b[0m`);
    });
    next();
});

// 3. Security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

// 8. Compression & 7. Static file caching
app.use(express.static(path.join(__dirname, '..', 'public'), {
    maxAge: '1d'
}));

// API Cache Control
app.use('/api', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
});

// 1. Rate limiting for /api/ai
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000;
const RATE_LIMIT_MAX = 20;

const rateLimiter = (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const now = Date.now();
    const userStats = rateLimitMap.get(ip) || { count: 0, startTime: now };
    
    if (now - userStats.startTime > RATE_LIMIT_WINDOW) {
        userStats.count = 1;
        userStats.startTime = now;
    } else {
        userStats.count++;
    }
    
    rateLimitMap.set(ip, userStats);
    
    if (userStats.count > RATE_LIMIT_MAX) {
        return res.status(429).json({ error: 'Too many requests, please try again later.' });
    }
    
    next();
};

app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', service: 'IA Bonito Backend', timestamp: new Date().toISOString(), geminiConfigured: !!GEMINI_API_KEY });
});

app.get('/api/players', async (req, res) => {
    try {
        if (!process.env.KV_REST_API_URL) return res.status(500).json({ error: 'KV DB no configurada en Vercel.' });
        const { kv } = require('@vercel/kv');
        const players = await kv.get('jogga-players');
        res.json(players || []);
    } catch (err) {
        console.error('KV GET Error:', err);
        res.status(500).json({ error: 'Failed to fetch players' });
    }
});

app.post('/api/players', async (req, res) => {
    try {
        if (!process.env.KV_REST_API_URL) return res.status(500).json({ error: 'KV DB no configurada en Vercel.' });
        const { kv } = require('@vercel/kv');
        const players = req.body;
        if (!Array.isArray(players)) return res.status(400).json({ error: 'Se esperaba un array' });
        if (players.length > 500) return res.status(400).json({ error: 'Límite de jugadores excedido' });
        
        await kv.set('jogga-players', players);
        res.json({ success: true });
    } catch (err) {
        console.error('KV SET Error:', err);
        res.status(500).json({ error: 'Failed to save players' });
    }
});

// 4. Input sanitization helper
const validateImage = (str) => {
    if (typeof str !== 'string') return false;
    if (str.length > 15_000_000) return false; // ~10MB base64
    if (str.startsWith('data:')) return str.startsWith('data:image/');
    return true; // Raw base64 string
};

// Cleanup stale rate limit entries every 5 minutes
setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of rateLimitMap) {
        if (now - data.startTime > RATE_LIMIT_WINDOW * 2) rateLimitMap.delete(ip);
    }
}, 5 * 60 * 1000).unref();

app.post('/api/ai', rateLimiter, async (req, res) => {
    if (!GEMINI_API_KEY) return res.status(500).json({ error: 'GEMINI_API_KEY no configurada.' });
    
    let { system, prompt, image } = req.body;
    
    // 4. Input sanitization
    if (prompt !== undefined) {
        if (typeof prompt !== 'string') return res.status(400).json({ error: 'Invalid prompt format.' });
        prompt = prompt.trim().substring(0, 10000);
    }
    if (!prompt) return res.status(400).json({ error: 'El campo "prompt" es requerido.' });
    
    if (system !== undefined) {
        if (typeof system !== 'string') return res.status(400).json({ error: 'Invalid system format.' });
        system = system.trim().substring(0, 5000);
    }
    
    if (image !== undefined) {
        if (!validateImage(image)) {
            return res.status(400).json({ error: 'Formato de imagen inválido.' });
        }
    }

    try {
        const parts = [{ text: prompt }];
        if (image) {
            const base64Data = image.includes(',') ? image.split(',')[1] : image;
            parts.push({ inlineData: { mimeType: 'image/jpeg', data: base64Data } });
        }
        
        const requestBody = { contents: [{ parts }], generationConfig: { temperature: 0.7 } };
        if (system) requestBody.systemInstruction = { parts: [{ text: system }] };
        
        const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`;
        
        // 5. Timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 60000);
        
        const response = await fetch(geminiUrl, { 
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' }, 
            body: JSON.stringify(requestBody),
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        const data = await response.json();
        
        if (!response.ok) { 
            console.error('\x1b[31m[Gemini API Error]\x1b[0m', JSON.stringify(data, null, 2)); 
            return res.status(response.status).json({ error: 'Error de la API de Gemini', details: data.error?.message || 'Error desconocido' }); 
        }
        
        const text = data.candidates?.[0]?.content?.parts?.[0]?.text || null;
        if (!text) return res.status(502).json({ error: 'Gemini no devolvió una respuesta válida.' });
        
        res.json({ text });
    } catch (err) { 
        if (err.name === 'AbortError') {
            return res.status(504).json({ error: 'Timeout de la API de Gemini' });
        }
        console.error('\x1b[31m[Server Error]\x1b[0m', err.message); 
        res.status(500).json({ error: 'Error interno.', details: err.message }); 
    }
});

app.get('*', (_req, res) => { res.sendFile(path.join(__dirname, '..', 'public', 'index.html')); });

if (process.env.VERCEL) {
    module.exports = app;
} else {
    const server = app.listen(PORT, () => {
        console.log('');
        console.log('  ⚽ IA Bonito Backend');
        console.log('  ────────────────────────────────');
        console.log(`  🌐 http://localhost:${PORT}`);
        console.log(`  🤖 Gemini Model: ${GEMINI_MODEL}`);
        console.log(`  🔑 API Key: ${GEMINI_API_KEY ? '✅ Configurada' : '\x1b[31m❌ NO configurada\x1b[0m'}`);
        console.log(`  🛡️  Security: Headers + Rate Limit (${RATE_LIMIT_MAX}/min)`);
        console.log(`  📁 Static: public/ (cache 1d)`);
        console.log('  ────────────────────────────────');
        console.log('');
    });

    // 6. Graceful shutdown
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


