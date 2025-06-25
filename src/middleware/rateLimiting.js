const rateLimit = require('express-rate-limit');
const User = require('../models/User');

// Global rate limiter
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
        success: false,
        error: 'Too many requests from this IP. Please try again later.',
        retryAfter: 15 * 60 // seconds
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting for authenticated users on some endpoints
        return req.path.startsWith('/api/user/') && req.headers.authorization;
    }
});

// In-memory store for IP-based failed attempts
const ipFailedAttempts = new Map();
const MAX_IP_ATTEMPTS = 3; // Max attempts per IP (consistent with user-based lockout)
const IP_LOCK_DURATION = 15 * 60 * 1000; // 15 minutes

// Clean up expired IP locks every 5 minutes
setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of ipFailedAttempts.entries()) {
        if (data.lockExpires && data.lockExpires < now) {
            ipFailedAttempts.delete(ip);
        }
    }
}, 5 * 60 * 1000);

// IP-based brute force protection middleware
const ipBruteForceProtection = (req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for']?.split(',')[0];
    const now = Date.now();
    
    // Get or create IP attempt data
    let ipData = ipFailedAttempts.get(clientIP) || {
        attempts: 0,
        lastAttempt: now,
        lockExpires: null
    };
    
    // Check if IP is currently locked
    if (ipData.lockExpires && ipData.lockExpires > now) {
        const remainingMinutes = Math.ceil((ipData.lockExpires - now) / (60 * 1000));
        console.log(`[IP Protection] Blocked request from locked IP: ${clientIP}, remaining: ${remainingMinutes} minutes`);
        return res.status(429).json({
            success: false,
            message: `Too many failed attempts from this IP address. Please try again in ${remainingMinutes} minutes.`,
            lockRemaining: remainingMinutes
        });
    }
    
    // Reset attempts if lock has expired
    if (ipData.lockExpires && ipData.lockExpires <= now) {
        ipData = {
            attempts: 0,
            lastAttempt: now,
            lockExpires: null
        };
    }
    
    // Add method to record failed attempt
    req.recordIPAttempt = () => {
        ipData.attempts += 1;
        ipData.lastAttempt = now;
        
        console.log(`[IP Protection] Failed attempt from IP: ${clientIP}, total attempts: ${ipData.attempts}`);
        
        // Lock IP after max attempts
        if (ipData.attempts >= MAX_IP_ATTEMPTS) {
            ipData.lockExpires = now + IP_LOCK_DURATION;
            console.log(`[IP Protection] IP locked: ${clientIP} until ${new Date(ipData.lockExpires)}`);
        }
        
        ipFailedAttempts.set(clientIP, ipData);
    };
    
    // Add method to clear IP attempts on successful login
    req.clearIPAttempts = () => {
        console.log(`[IP Protection] Clearing attempts for IP: ${clientIP}`);
        ipFailedAttempts.delete(clientIP);
    };
    
    // Store current attempt count for logging
    req.ipAttemptCount = ipData.attempts;
    
    // Add method to get IP attempt data
    req.getIPAttemptData = () => ipData;
    
    // Add method to clear IP attempts on successful login
    req.clearIPAttempts = () => {
        ipFailedAttempts.delete(clientIP);
        console.log(`[Rate Limiting] Cleared IP attempts for: ${clientIP}`);
    };
    
    next();
};

// Function to get IP attempt data (for use in other modules)
const getIPAttemptData = (clientIP) => {
    return ipFailedAttempts.get(clientIP) || {
        attempts: 0,
        lastAttempt: Date.now(),
        lockExpires: null
    };
};

// Function to clear IP attempt data (for successful logins)
const clearIPAttemptData = (clientIP) => {
    ipFailedAttempts.delete(clientIP);
    console.log(`[Rate Limiting] Cleared IP attempts for: ${clientIP}`);
};

// Enhanced auth rate limiter with more specific rules
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 requests per windowMs
    message: {
        success: false,
        message: 'Too many authentication attempts from this IP, please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
    // Skip successful requests
    skipSuccessfulRequests: true,
    handler: (req, res) => {
        console.log(`[Rate Limiter] Blocked request from IP: ${req.ip}`);
        res.status(429).json({
            success: false,
            message: 'Too many authentication attempts from this IP, please try again later.',
            retryAfter: Math.round(req.rateLimit.resetTime / 1000)
        });
    }
});

// OTP rate limiter - more restrictive for OTP requests
const otpLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 5, // Limit each IP to 5 OTP requests per windowMs
    message: {
        success: false,
        message: 'Too many OTP requests from this IP, please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        console.log(`[OTP Rate Limiter] Blocked OTP request from IP: ${req.ip}`);
        res.status(429).json({
            success: false,
            message: 'Too many OTP requests from this IP, please try again later.',
            retryAfter: Math.round(req.rateLimit.resetTime / 1000)
        });
    }
});

// Registration rate limiter
const registrationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 20, // Limit each IP to 20 registration attempts per hour (increased for testing)
    message: {
        success: false,
        message: 'Too many registration attempts from this IP, please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        console.log(`[Registration Rate Limiter] Blocked registration from IP: ${req.ip}`);
        res.status(429).json({
            success: false,
            message: 'Too many registration attempts from this IP, please try again later.',
            retryAfter: Math.round(req.rateLimit.resetTime / 1000)
        });
    }
});

// Password reset rate limiter
const passwordResetLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // Limit each IP to 3 password reset attempts per hour
    message: {
        success: false,
        message: 'Too many password reset attempts from this IP, please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        console.log(`[Password Reset Rate Limiter] Blocked request from IP: ${req.ip}`);
        res.status(429).json({
            success: false,
            message: 'Too many password reset attempts from this IP, please try again later.',
            retryAfter: Math.round(req.rateLimit.resetTime / 1000)
        });
    }
});

// General API rate limiter
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
        success: false,
        message: 'Too many requests from this IP, please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        console.log(`[API Rate Limiter] Blocked request from IP: ${req.ip}`);
        res.status(429).json({
            success: false,
            message: 'Too many requests from this IP, please try again later.',
            retryAfter: Math.round(req.rateLimit.resetTime / 1000)
        });
    }
});

// Brute force protection middleware
const bruteForceProtection = async (req, res, next) => {
    try {
        const { username, email } = req.body;
        const identifier = username || email;
        
        if (!identifier) {
            return next();
        }

        // Find user by username or email
        const user = await User.findOne({
            $or: [
                { username: identifier },
                { email: identifier }
            ]
        });

        if (user && user.isLocked) {
            const lockExpires = new Date(user.lockExpires);
            const now = new Date();
            
            if (lockExpires > now) {
                const remainingMinutes = Math.ceil((lockExpires - now) / (1000 * 60));
                return res.status(423).json({
                    success: false,
                    error: `Account is locked due to too many failed attempts. Please try again in ${remainingMinutes} minutes.`,
                    lockExpires: lockExpires.toISOString(),
                    remainingMinutes
                });
            } else {
                // Reset lock if expired
                user.isLocked = false;
                user.failedLoginAttempts = 0;
                user.lockExpires = undefined;
                await user.save();
            }
        }

        next();
    } catch (error) {
        console.error('Brute force protection error:', error);
        next();
    }
};

// Progressive delay for failed attempts
const progressiveDelay = (attempts) => {
    if (attempts <= 1) return 0;
    if (attempts <= 3) return 1000; // 1 second
    if (attempts <= 5) return 3000; // 3 seconds
    if (attempts <= 7) return 10000; // 10 seconds
    return 30000; // 30 seconds for 8+ attempts
};

// Account lockout after failed attempts
const handleFailedLogin = async (user) => {
    if (!user) return;

    user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
    
    // Lock account after 5 failed attempts
    if (user.failedLoginAttempts >= 5) {
        user.isLocked = true;
        user.lockExpires = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
        console.log(`Account locked for user: ${user.email}`);
    }
    
    await user.save();
    return user.failedLoginAttempts;
};

// Reset failed attempts on successful login
const handleSuccessfulLogin = async (user) => {
    if (!user) return;

    user.failedLoginAttempts = 0;
    user.isLocked = false;
    user.lockExpires = undefined;
    user.lastLogin = new Date();
    await user.save();
};

// IP-based rate limiting with Redis (optional, fallback to memory)
class IPTracker {
    constructor() {
        this.attempts = new Map();
        this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000); // Cleanup every 5 minutes
    }

    getAttempts(ip) {
        const data = this.attempts.get(ip);
        if (!data) return { count: 0, firstAttempt: Date.now() };
        
        // Reset if window expired
        if (Date.now() - data.firstAttempt > 15 * 60 * 1000) {
            this.attempts.delete(ip);
            return { count: 0, firstAttempt: Date.now() };
        }
        
        return data;
    }

    recordAttempt(ip) {
        const current = this.getAttempts(ip);
        this.attempts.set(ip, {
            count: current.count + 1,
            firstAttempt: current.firstAttempt
        });
        return current.count + 1;
    }

    cleanup() {
        const now = Date.now();
        for (const [ip, data] of this.attempts.entries()) {
            if (now - data.firstAttempt > 15 * 60 * 1000) {
                this.attempts.delete(ip);
            }
        }
    }
}

const ipTracker = new IPTracker();

// Enhanced IP-based protection
const ipProtection = (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const attempts = ipTracker.getAttempts(ip);
    
    if (attempts.count >= 20) { // 20 attempts per 15 minutes per IP
        return res.status(429).json({
            success: false,
            error: 'Too many requests from this IP address. Please try again later.',
            retryAfter: 15 * 60
        });
    }
    
    // Record this attempt for failed requests
    req.recordIPAttempt = () => ipTracker.recordAttempt(ip);
    next();
};

module.exports = {
    globalLimiter,
    authLimiter,
    otpLimiter,
    registrationLimiter,
    passwordResetLimiter,
    apiLimiter,
    bruteForceProtection,
    progressiveDelay,
    handleFailedLogin,
    handleSuccessfulLogin,
    ipProtection,
    ipBruteForceProtection,
    getIPAttemptData,
    clearIPAttemptData
}; 