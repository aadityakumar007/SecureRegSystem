const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const config = require('../src/config/config');
const connectDB = require('../src/db/connection');
const authRoutes = require('../src/routes/auth');
const userRoutes = require('../src/routes/user');
const sessionRoutes = require('../src/routes/session');
const { globalLimiter, ipProtection } = require('../src/middleware/rateLimiting');
const passwordExpiryChecker = require('../src/utils/passwordExpiryChecker');

const app = express();

// Connect to MongoDB
connectDB();

// Start password expiry checker (serverless-friendly)
if (!global.passwordExpiryStarted) {
    passwordExpiryChecker.start();
    global.passwordExpiryStarted = true;
    console.log(`[Serverless] Password expiry monitoring started`);
}

// CSRF Protection Setup using csurf
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
    // HSTS Configuration - Only enabled in production or when explicitly enabled
    hsts: config.security.hsts.enabled ? {
        maxAge: config.security.hsts.maxAge,
        includeSubDomains: config.security.hsts.includeSubDomains,
        preload: config.security.hsts.preload
    } : false,
    // Additional security headers
    noSniff: true,
    frameguard: { action: 'deny' },
    xssFilter: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
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
  saveUninitialized: true,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
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
    res.json({ 
        message: 'API is working',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);
app.use('/api/session', sessionRoutes);

// Apply CSRF protection to all POST/PUT/DELETE requests
app.use((req, res, next) => {
    // Skip CSRF for GET requests and certain paths
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

// Serve static files
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
    console.log(`[Serverless] API route not found: ${req.method} ${req.originalUrl}`);
    res.status(404).json({
        success: false,
        message: 'API endpoint not found'
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('[Serverless] Error:', err.stack);
    res.status(500).json({
        success: false,
        message: 'Something went wrong!'
    });
});

// Export the Express app for Vercel
module.exports = app; 