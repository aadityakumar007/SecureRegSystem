const cors = require('cors');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');

// Configure CORS for Vercel
const corsOptions = {
    credentials: true,
    origin: [
        'https://secure-reg-system.vercel.app',
        /\.vercel\.app$/,
        'http://localhost:3000'
    ]
};

// CSRF Protection Setup
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
});

// Session configuration
const sessionConfig = {
    secret: process.env.JWT_SECRET || 'temp-secret-for-testing',
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
};

export default async function handler(req, res) {
    // Apply CORS
    const corsHandler = cors(corsOptions);
    await new Promise((resolve, reject) => {
        corsHandler(req, res, (result) => {
            if (result instanceof Error) {
                return reject(result);
            }
            return resolve(result);
        });
    });

    // Only allow GET requests
    if (req.method !== 'GET') {
        return res.status(405).json({
            success: false,
            message: 'Method not allowed'
        });
    }

    try {
        console.log('[CSRF] Token request received');
        console.log('[CSRF] Headers:', req.headers);
        console.log('[CSRF] Cookies:', req.cookies);

        // Simple token generation for now
        const crypto = require('crypto');
        const token = crypto.randomBytes(32).toString('hex');
        
        console.log(`[CSRF] Generated token: ${token.substring(0, 8)}...`);
        
        // Set CSRF token in cookie for client
        res.setHeader('Set-Cookie', [
            `_csrf=${token}; Path=/; HttpOnly; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`,
            `csrf-token=${token}; Path=/; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`
        ]);

        res.status(200).json({ 
            success: true,
            csrfToken: token,
            timestamp: new Date().toISOString(),
            environment: process.env.NODE_ENV || 'development'
        });
    } catch (error) {
        console.error('[CSRF] Unexpected error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to generate CSRF token',
            error: error.message 
        });
    }
} 