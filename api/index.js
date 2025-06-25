const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const session = require('express-session');

// Initialize Express app
const app = express();

// Configure CORS for Vercel
app.use(cors({
    credentials: true,
    origin: [
        'https://secure-reg-system.vercel.app',
        /\.vercel\.app$/,
        'http://localhost:3000'
    ]
}));

// Basic middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Configure session for serverless (simplified)
app.use(session({
    secret: process.env.JWT_SECRET || 'temp-secret-for-testing',
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Basic security headers
app.use(helmet({
    contentSecurityPolicy: false, // Disable for now to avoid conflicts
    crossOriginEmbedderPolicy: false
}));

// CSRF Protection Setup
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
});

// Health check endpoint
app.get('/api/test', (req, res) => {
    res.json({ 
        success: true,
        message: 'Vercel serverless API is working!',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// CSRF token endpoint - CRITICAL for login functionality
app.get('/api/csrf-token', (req, res) => {
    try {
        console.log('[CSRF] Token request received');
        console.log('[CSRF] Session ID:', req.sessionID);
        console.log('[CSRF] Headers:', req.headers);
        
        // Apply CSRF protection to generate token
        csrfProtection(req, res, (err) => {
            if (err) {
                console.error('[CSRF] Error generating token:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Failed to generate CSRF token',
                    error: err.message 
                });
            }
            
            const token = req.csrfToken();
            console.log(`[CSRF] Generated token: ${token.substring(0, 8)}...`);
            
            res.json({ 
                success: true,
                csrfToken: token 
            });
        });
    } catch (error) {
        console.error('[CSRF] Unexpected error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to generate CSRF token',
            error: error.message 
        });
    }
});

// Basic login endpoint for testing
app.post('/api/auth/login', csrfProtection, (req, res) => {
    try {
        console.log('[Login] Request received');
        console.log('[Login] Body:', req.body);
        
        // Simple test response
        res.json({
            success: true,
            message: 'Login endpoint is working',
            received: {
                username: req.body.username,
                hasPassword: !!req.body.password,
                hasRecaptcha: !!req.body.recaptchaToken
            }
        });
    } catch (error) {
        console.error('[Login] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Login test failed',
            error: error.message
        });
    }
});

// Catch-all for unmatched API routes
app.use('/api/*', (req, res) => {
    console.log(`[API] Route not found: ${req.method} ${req.path}`);
    res.status(404).json({
        success: false,
        message: `API endpoint not found: ${req.method} ${req.path}`,
        availableEndpoints: [
            'GET /api/test',
            'GET /api/csrf-token',
            'POST /api/auth/login'
        ]
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('[Serverless] Error:', err);
    res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

// Export for Vercel
module.exports = app; 