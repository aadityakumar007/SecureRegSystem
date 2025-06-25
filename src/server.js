const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const config = require('./config/config');
const connectDB = require('./db/connection');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
const sessionRoutes = require('./routes/session');
const { globalLimiter, ipProtection } = require('./middleware/rateLimiting');
const passwordExpiryChecker = require('./utils/passwordExpiryChecker');

const app = express();

// Connect to MongoDB
connectDB();

// CSRF Protection Setup using csurf (simpler and more reliable)
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: false, // Temporarily disable for testing
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
    // HSTS Configuration - Only enabled in production or when explicitly enabled
    hsts: config.security.hsts.enabled ? {
        maxAge: config.security.hsts.maxAge,
        includeSubDomains: config.security.hsts.includeSubDomains,
        preload: config.security.hsts.preload
    } : false,
    // Additional security headers
    noSniff: true, // X-Content-Type-Options: nosniff
    frameguard: { action: 'deny' }, // X-Frame-Options: DENY
    xssFilter: true, // X-XSS-Protection: 1; mode=block
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' } // Referrer-Policy
}));

// Basic middleware
app.use(cors({
    credentials: true,
    origin: process.env.NODE_ENV === 'production' 
        ? [
            'https://secure-reg-system.vercel.app',
            /\.vercel\.app$/,
            process.env.FRONTEND_URL
          ].filter(Boolean)
        : true
}));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
  secret: config.jwtSecret,
  resave: false,
  saveUninitialized: true, // Changed to true for CSRF to work properly
  cookie: { 
    secure: false, // Temporarily disable for testing
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  },
}));

// Apply enhanced rate limiting and IP protection first
app.use(globalLimiter);
app.use(ipProtection);

// CSRF token endpoint (NO CSRF protection on this endpoint)
app.get('/api/csrf-token', (req, res) => {
    try {
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
            console.log(`[CSRF] Session ID: ${req.sessionID}`);
            console.log(`[CSRF] Cookies present:`, Object.keys(req.cookies));
            res.json({ csrfToken: token });
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

// Test endpoint for debugging
app.get('/api/test', (req, res) => {
    res.json({ message: 'API is working' });
});

// API routes (BEFORE static files and CSRF protection)
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);
app.use('/api/session', sessionRoutes);

// Apply CSRF protection to all POST/PUT/DELETE requests (AFTER API routes)
app.use((req, res, next) => {
    // Skip CSRF for GET requests and static files
    if (req.method === 'GET' || 
        req.path === '/api/csrf-token' ||
        req.path.startsWith('/css/') ||
        req.path.startsWith('/js/') ||
        req.path.startsWith('/images/') ||
        req.path.endsWith('.html') ||
        req.path.endsWith('.css') ||
        req.path.endsWith('.js') ||
        req.path.endsWith('.png') ||
        req.path.endsWith('.jpg') ||
        req.path.endsWith('.ico') ||
        req.path === '/') {
        return next();
    }
    
    // Log CSRF protection attempts
    const tokenPresent = req.headers['x-csrf-token'] || req.body._csrf;
    console.log(`[CSRF] ${req.method} ${req.path} - Token: ${tokenPresent ? 'Present' : 'Missing'}`);
    console.log(`[CSRF] Session ID: ${req.sessionID}`);
    console.log(`[CSRF] X-CSRF-Token header:`, req.headers['x-csrf-token'] ? req.headers['x-csrf-token'].substring(0, 20) + '...' : 'Missing');
    console.log(`[CSRF] _csrf in body:`, req.body._csrf ? req.body._csrf.substring(0, 20) + '...' : 'Missing');
    if (tokenPresent) {
        console.log(`[CSRF] Token value: ${tokenPresent.substring(0, 20)}...`);
    }
    
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

// Serve static files with correct MIME types (AFTER API routes)
app.use(express.static(path.join(__dirname, '../public'), {
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.js')) {
            res.setHeader('Content-Type', 'application/javascript');
        } else if (filePath.endsWith('.css')) {
            res.setHeader('Content-Type', 'text/css');
        } else if (filePath.endsWith('.html')) {
            res.setHeader('Content-Type', 'text/html');
        }
    }
}));

// Serve index.html for the root route
app.get('/', (req, res) => {
      res.sendFile(path.join(__dirname, '../public/login.html'));
});

// Handle 404 for API routes
app.use('/api/*', (req, res) => {
    console.log(`[Server] API route not found: ${req.method} ${req.originalUrl}`);
    res.status(404).json({
        success: false,
        message: 'API endpoint not found'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('[Server] Error:', err.stack);
  res.status(500).json({
        success: false,
        message: 'Something went wrong!'
  });
});

// Content Security Policy
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', 
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' www.google.com www.gstatic.com cdn.jsdelivr.net; " +
        "script-src-attr 'unsafe-inline'; " +
        "style-src 'self' 'unsafe-inline' fonts.googleapis.com cdn.jsdelivr.net; " +
        "font-src 'self' fonts.gstatic.com; " +
        "img-src 'self' data: blob:; " +
        "connect-src 'self' www.google.com www.gstatic.com recaptcha.google.com api.ipify.org ipapi.co ipinfo.io; " +
        "frame-src 'self' www.google.com; " +
        "object-src 'none'; " +
        "base-uri 'self';"
    );
    next();
});

// Start server
const PORT = config.port || 3000;
app.listen(PORT, () => {
    console.log(`[Server] Server is running on port ${PORT}`);
    console.log(`[Server] Available routes:`);
    console.log(`  - POST /api/auth/login`);
    console.log(`  - POST /api/auth/register`);
    console.log(`  - POST /api/auth/verify-otp`);
    console.log(`  - POST /api/auth/change-password`);
    console.log(`  - GET  /api/user/verify-token`);
    console.log(`  - GET  /api/user/info`);
    console.log(`  - GET  /api/user/logs`);
    
    // Start password expiry checker
    passwordExpiryChecker.start();
    console.log(`[Server] Password expiry monitoring started (30-day expiry policy)`);
});