require('dotenv').config();

module.exports = {
    // Server Configuration
  port: process.env.PORT || 3000,
    nodeEnv: process.env.NODE_ENV || 'development',
  baseUrl: process.env.BASE_URL || 'http://localhost:3000',

    // MongoDB Configuration
    mongoURI: process.env.MONGODB_URI || 'mongodb+srv://dragonfiretheworld:&ecure007@cluster0.xlqn5ri.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0',

    // JWT Configuration
    jwtSecret: process.env.JWT_SECRET || 'Cjos+xv2+oJ6BcS3oAakRobbqAEoWm0QvlbETFQmtu0=',
    jwtExpiresIn: process.env.SESSION_EXPIRES_IN || '1h',

    // Email Configuration
  email: {
        user: process.env.EMAIL_USER || 'dragonfiretheworld@gmail.com',
        pass: process.env.EMAIL_PASS || 'xyhi jyer eqan sadn'
  },

    // reCAPTCHA Configuration
  recaptcha: {
        secretKey: process.env.RECAPTCHA_SECRET_KEY || '6LegBVwrAAAAAClzQM9QC9vasgrfjURUDDNIAKqe',
        siteKey: process.env.RECAPTCHA_SITE_KEY || '6LegBVwrAAAAAPuAvRyJ8JsBS0uVylcmYyyvC6JD'
    },

    // Session Configuration
    session: {
        secret: process.env.SESSION_SECRET || '1c58c0ded1ab3c99512602c8a755573e762464419a671e294acf10aebab106b28c35ceb5eae6063f2a2a0f72816fa39b6c5900a4a35850220128595ae18c2e00',
        expiresIn: process.env.SESSION_EXPIRES_IN || '1h'
    },

    // Security Configuration
    security: {
        bcryptSaltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10,
        passwordMinLength: parseInt(process.env.PASSWORD_MIN_LENGTH) || 8,
        passwordMaxLength: parseInt(process.env.PASSWORD_MAX_LENGTH) || 128,
        maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 3,
        lockoutDuration: parseInt(process.env.LOCKOUT_DURATION) || 15, // minutes
        encryptionKey: process.env.ENCRYPTION_KEY || '4804398e9ef9f6eaca59b50be3e24d7e73a21164511b636315eeef981e5669bb',
        
        // HSTS Configuration
        hsts: {
            enabled: process.env.NODE_ENV === 'production' || process.env.HSTS_ENABLED === 'true',
            maxAge: parseInt(process.env.HSTS_MAX_AGE) || 31536000, // 1 year in seconds
            includeSubDomains: process.env.HSTS_INCLUDE_SUBDOMAINS !== 'false', // Default true
            preload: process.env.HSTS_PRELOAD !== 'false' // Default true
        }
    }
};

// Ensure JWT secret is available
if (!module.exports.jwtSecret || module.exports.jwtSecret === 'Cjos+xv2+oJ6BcS3oAakRobbqAEoWm0QvlbETFQmtu0=') {
  console.warn('Warning: Using default JWT secret. Please set JWT_SECRET in .env file for production.');
}

// Log HSTS configuration
if (module.exports.security.hsts.enabled) {
    console.log('[Security] HSTS enabled for production environment');
    console.log(`[Security] HSTS max-age: ${module.exports.security.hsts.maxAge} seconds`);
    console.log(`[Security] HSTS includeSubDomains: ${module.exports.security.hsts.includeSubDomains}`);
    console.log(`[Security] HSTS preload: ${module.exports.security.hsts.preload}`);
} else {
    console.log('[Security] HSTS disabled for development environment');
}