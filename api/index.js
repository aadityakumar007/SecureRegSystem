const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const config = require('../src/config/config');
const connectDB = require('../src/db/connection');
const authRoutes = require('../src/routes/auth');
const userRoutes = require('../src/routes/user');
const sessionRoutes = require('../src/routes/session');
const { globalLimiter, ipProtection } = require('../src/middleware/rateLimiting');

// Create Express app
const app = express();

// Connect to MongoDB
connectDB();

// CSRF Protection Setup
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
});

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
                "'self'",
                "'unsafe-inline'",
                "cdn.jsdelivr.net",
                "cdnjs.cloudflare.com",
                "www.google.com",
                "www.gstatic.com",
                "recaptcha.google.com"
            ],
            styleSrc: [
                "'self'",
                "'unsafe-inline'",
                "cdnjs.cloudflare.com"
            ],
            imgSrc: [
                "'self'",
                "data:",
                "cdnjs.cloudflare.com",
                "www.google.com",
                "www.gstatic.com",
                "recaptcha.google.com"
            ],
            connectSrc: [
                "'self'",
                "www.google.com",
                "www.gstatic.com",
                "recaptcha.google.com",
                "api.ipify.org",
                "ipapi.co",
                "ipinfo.io"
            ],
            fontSrc: [
                "'self'",
                "cdnjs.cloudflare.com"
            ],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: [
                "'self'",
                "www.google.com",
                "www.gstatic.com",
                "recaptcha.google.com"
            ]
        }
    },
    hsts: false, // Disable for serverless
    noSniff: true,
    frameguard: { action: 'deny' },
    xssFilter: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// Basic middleware
app.use(cors({
    credentials: true,
    origin: true
}));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration for serverless
app.use(session({
    secret: process.env.JWT_SECRET || 'fallback-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    },
}));

// Apply rate limiting
app.use(globalLimiter);
app.use(ipProtection);

// CSRF token endpoint (NO CSRF protection on this endpoint)
app.get('/csrf-token', (req, res) => {
    try {
        console.log('[CSRF] CSRF token endpoint accessed');
        // Apply CSRF protection only to generate token
        csrfProtection(req, res, (err) => {
            if (err) {
                console.error('[CSRF] Error applying protection for token generation:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Failed to initialize CSRF protection',
                    error: err.message 
                });
            }
            
            const token = req.csrfToken();
            console.log(`[CSRF] Generated token for client: ${token.substring(0, 8)}...`);
            res.json({ 
                success: true,
                csrfToken: token 
            });
        });
    } catch (error) {
        console.error('[CSRF] Error generating token:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to generate CSRF token',
            error: error.message 
        });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        message: 'API is working',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// Test endpoint
app.get('/test', (req, res) => {
    console.log(`[API] Test endpoint accessed: ${req.method} ${req.url}`);
    res.json({ 
        success: true,
        message: 'API is working',
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url
    });
});

// Debug endpoint
app.get('/debug', (req, res) => {
    res.json({
        success: true,
        message: 'Debug endpoint working',
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url,
        headers: req.headers,
        query: req.query,
        environment: {
            NODE_ENV: process.env.NODE_ENV,
            VERCEL: process.env.VERCEL
        }
    });
});

// API routes
app.use('/auth', authRoutes);
app.use('/user', userRoutes);
app.use('/session', sessionRoutes);

// Apply CSRF protection to POST/PUT/DELETE requests
app.use((req, res, next) => {
    // Skip CSRF for GET requests
    if (req.method === 'GET' || req.path === '/csrf-token') {
        return next();
    }
    
    console.log(`[CSRF] ${req.method} ${req.path} - Applying CSRF protection`);
    
    // Apply CSRF protection
    csrfProtection(req, res, (err) => {
        if (err) {
            console.log(`[CSRF] BLOCKED: ${req.method} ${req.path} from ${req.ip} - ${err.message}`);
            return res.status(403).json({
                success: false,
                message: 'CSRF token validation failed',
                error: 'Invalid or missing CSRF token'
            });
        }
        next();
    });
});

// Handle 404 for undefined routes
app.use('*', (req, res) => {
    console.log(`[API] Route not found: ${req.method} ${req.originalUrl}`);
    res.status(404).json({
        success: false,
        message: 'API endpoint not found',
        path: req.originalUrl
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('[API] Error:', err.stack);
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});

// Export as Vercel serverless function
module.exports = app; 