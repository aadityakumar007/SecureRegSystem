const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');
const Recaptcha = require('recaptcha2');
const { sendOTP, sendVerificationEmail, sendPasswordResetEmail, verifyOTP } = require('../utils/email');
const config = require('../config/config');
const { validateEmail } = require('../utils/emailValidator');
const { validateRecaptcha } = require('../utils/recaptcha');
const User = require('../models/User');
const { generateVerificationToken, generateToken } = require('../utils/token');
const speakeasy = require('speakeasy');
const auth = require('../middleware/auth');
const otpManager = require('../utils/otpManager');
const notificationManager = require('../utils/notificationManager');
const { 
    authLimiter, 
    otpLimiter, 
    registrationLimiter, 
    passwordResetLimiter,
    ipBruteForceProtection
} = require('../middleware/rateLimiting');

const router = express.Router();
const recaptcha = new Recaptcha({
  siteKey: config.recaptcha.siteKey,
  secretKey: config.recaptcha.secretKey,
});

const usersFile = path.join(__dirname, '../users.json');
const otpStore = new Map();

// Temporary storage for pending registrations
const pendingRegistrations = new Map();

// Debug log to verify User model
console.log('User model loaded:', User ? 'Yes' : 'No');

async function readUsers() {
  try {
    const data = await fs.readFile(usersFile, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    return [];
  }
}

async function writeUsers(users) {
  await fs.writeFile(usersFile, JSON.stringify(users, null, 2));
}

function isStrongPassword(password, username) {
    if (!password) return { valid: false, message: 'Password is required.' };
    if (password.length < 12) return { valid: false, message: 'Password must be at least 12 characters long.' };
    
    let score = 0;
    const checks = {
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        numbers: /\d/.test(password),
        special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
    };
    
    // Check each requirement
    if (!checks.uppercase) return { valid: false, message: 'Password must contain at least 2 uppercase letters.' };
    if (!checks.lowercase) return { valid: false, message: 'Password must contain at least 2 lowercase letters.' };
    if (!checks.numbers) return { valid: false, message: 'Password must contain at least 2 numbers.' };
    if (!checks.special) return { valid: false, message: 'Password must contain at least 2 special characters.' };
    
    // Check for at least 2 of each type
    const uppercaseCount = (password.match(/[A-Z]/g) || []).length;
    const lowercaseCount = (password.match(/[a-z]/g) || []).length;
    const numbersCount = (password.match(/\d/g) || []).length;
    const specialCount = (password.match(/[!@#$%^&*(),.?":{}|<>]/g) || []).length;
    
    if (uppercaseCount < 2) return { valid: false, message: 'Password must contain at least 2 uppercase letters.' };
    if (lowercaseCount < 2) return { valid: false, message: 'Password must contain at least 2 lowercase letters.' };
    if (numbersCount < 2) return { valid: false, message: 'Password must contain at least 2 numbers.' };
    if (specialCount < 2) return { valid: false, message: 'Password must contain at least 2 special characters.' };
    
    // Check if password contains username
    if (username && password.toLowerCase().includes(username.toLowerCase())) {
        return { valid: false, message: 'Password cannot contain your username.' };
    }
    
    return { valid: true, message: 'Password meets all requirements.' };
}

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Rate limiters now imported from middleware/rateLimiting.js

// Debug logging
const debug = {
    log: (message, data) => {
        console.log(`[Auth] ${message}`, data || '');
    },
    error: (message, error) => {
        console.error(`[Auth] ${message}`, error);
    }
};

// Register new user
router.post('/register', registrationLimiter, async (req, res) => {
  try {
    const { username, email, password, recaptchaResponse } = req.body;
        debug.log('Register request received:', { username, email });

    // Validate required fields
    if (!username || !email || !password || !recaptchaResponse) {
            debug.error('Registration failed: Missing required fields');
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        // Validate email format and check for disposable domains
        const emailValidation = validateEmail(email);
        if (!emailValidation.isValid) {
            debug.error('Registration failed: Email validation failed', emailValidation.message);
            return res.status(400).json({
                success: false,
                message: emailValidation.message
            });
        }

        // Validate username format
        if (username.length < 3) {
            debug.error('Registration failed: Username too short');
            return res.status(400).json({
                success: false,
                message: 'Username must be at least 3 characters long'
            });
        }

        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            debug.error('Registration failed: Invalid username format');
            return res.status(400).json({
                success: false,
                message: 'Username can only contain letters, numbers, and underscores'
            });
        }

        // Validate password strength
        const passwordValidation = isStrongPassword(password, username);
        if (!passwordValidation.valid) {
            debug.error('Registration failed: Weak password', passwordValidation.message);
            return res.status(400).json({
                success: false,
                message: passwordValidation.message
            });
    }

    // Verify reCAPTCHA
        const recaptchaValid = await validateRecaptcha(recaptchaResponse);
    if (!recaptchaValid) {
            debug.error('Registration failed: reCAPTCHA verification failed');
            return res.status(400).json({
                success: false,
                message: 'reCAPTCHA verification failed'
            });
        }

        // Check if username already exists
        const existingUserByUsername = await User.findOne({ username });
        if (existingUserByUsername) {
            debug.error('Registration failed: Username already exists');
            return res.status(409).json({
                success: false,
                message: 'Username already exists. Please choose a different username.',
                field: 'username'
            });
        }

        // Check if email already exists
        const existingUserByEmail = await User.findOne({ email });
        if (existingUserByEmail) {
            debug.error('Registration failed: Email already exists');
            return res.status(409).json({
                success: false,
                message: 'Email already registered. Please use a different email or try logging in.',
                field: 'email'
            });
        }

        // Generate OTP for email verification (before creating user)
        const otp = otpManager.generateOTP(email, 'pending');
        
        // Store user data temporarily (don't save to database yet)
        const tempUserData = {
      username,
      email,
            password, // Will be hashed when user is created after OTP verification
            isVerified: false,
            createdAt: new Date(),
            role: 'user',
            mfaToken: otp,
            mfaTokenCreatedAt: new Date()
        };
        
        // Store in temporary map with OTP as key
        if (!global.pendingRegistrations) {
            global.pendingRegistrations = new Map();
        }
        global.pendingRegistrations.set(otp, tempUserData);
        
        debug.log('User data stored temporarily for OTP verification:', { username, email });

        // Send verification email
        const emailSent = await sendOTP(tempUserData.email, otp, tempUserData.username);
        if (!emailSent) {
            debug.error('Registration failed: Could not send verification email');
            // Clean up the temporary data if email failed
            global.pendingRegistrations.delete(otp);
            return res.status(500).json({
                success: false,
                message: 'Failed to send verification email. Please try again.'
            });
        }

        res.status(201).json({
            success: true,
            message: 'Registration successful! Please check your email for verification code.',
            requiresMFA: true,
            email: tempUserData.email,
            mfaToken: otp // Include the token for verification
        });

    } catch (error) {
        debug.error('Registration error:', error);
        
        // Handle MongoDB duplicate key errors
        if (error.code === 11000) {
            const field = Object.keys(error.keyPattern)[0];
            const message = field === 'username' ? 
                'Username already exists. Please choose a different username.' :
                'Email already registered. Please use a different email or try logging in.';
            
            return res.status(409).json({
                success: false,
                message: message,
                field: field
            });
        }

        // Handle validation errors
        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                message: errors[0] || 'Validation failed'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Error registering user. Please try again.'
        });
    }
});

// Verify registration OTP route
router.post('/verify-registration', async (req, res) => {
    try {
        const { mfaToken, otp } = req.body;

        if (!mfaToken || !otp) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        // Check if we have pending registration data
        if (!global.pendingRegistrations) {
            return res.status(400).json({ message: 'Invalid or expired verification code' });
        }

        // Get temporary user data using the OTP token
        const tempUserData = global.pendingRegistrations.get(mfaToken);
        if (!tempUserData) {
            return res.status(400).json({ message: 'Invalid or expired verification code' });
        }

        // Check if OTP is expired (2 minutes)
        if (Date.now() - tempUserData.mfaTokenCreatedAt > 2 * 60 * 1000) {
            global.pendingRegistrations.delete(mfaToken);
            return res.status(400).json({ message: 'Verification code has expired' });
        }

        // Verify OTP
        if (tempUserData.mfaToken !== otp) {
            return res.status(400).json({ message: 'Invalid verification code' });
        }

        // Create and save the user to database now
        const user = new User({
            username: tempUserData.username,
            email: tempUserData.email,
            password: tempUserData.password, // Will be hashed by the User model pre-save hook
            isVerified: true, // Mark as verified since OTP was successful
            createdAt: tempUserData.createdAt,
            role: tempUserData.role
        });

        await user.save();

        // Clean up temporary data
        global.pendingRegistrations.delete(mfaToken);
        
        debug.log('User registration completed and saved to database:', { username: user.username, email: user.email });

        // Registration successful - user should now log in manually
        res.json({
            success: true,
            message: 'Registration successful! Please log in with your credentials.'
    });
  } catch (error) {
        console.error('Registration verification error:', error);
        
        // Handle MongoDB duplicate key errors (in case user was created between checks)
        if (error.code === 11000) {
            const field = Object.keys(error.keyPattern)[0];
            const message = field === 'username' ? 
                'Username already exists. Please choose a different username.' :
                'Email already registered. Please use a different email or try logging in.';
            
            return res.status(409).json({
                success: false,
                message: message,
                field: field
            });
        }
        
        res.status(500).json({ message: 'An error occurred during verification' });
  }
});

// Verify OTP route
router.post('/verify-otp', async (req, res) => {
  try {
        const { email, otp } = req.body;
        debug.log('OTP verification request received:', { email, otp });

        // Validate request body
        if (!email || !otp) {
            debug.error('Missing required fields:', { email: !!email, otp: !!otp });
            return res.status(400).json({
                success: false,
                message: 'Email and OTP are required'
            });
    }

        // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
            debug.error('OTP verification failed: User not found');
            return res.status(400).json({
                success: false,
                message: 'User not found'
            });
    }

    // Verify OTP
        const verificationResult = otpManager.verifyOTP(email, otp);
        if (!verificationResult.success) {
            return res.status(400).json(verificationResult);
    }

        // Update user's last login and activity
        user.lastLogin = new Date();
        user.lastActiveAt = new Date();
      await user.save();

        // Generate JWT token
      const token = jwt.sign(
            { 
                _id: user._id,
                userId: user._id.toString(),
                username: user.username,
                role: user.role
            },
            config.jwtSecret,
        { expiresIn: config.jwtExpiresIn }
      );

        debug.log('Token generated successfully');
        
        // Send back complete user data
        const userData = {
            _id: user._id.toString(),
            username: user.username,
            email: user.email,
            role: user.role || 'user',
            lastLogin: user.lastLogin,
            isVerified: user.isVerified,
            createdAt: user.createdAt
        };

        debug.log('Sending response with user data:', userData);

      res.json({
            success: true,
            message: 'OTP verified successfully',
            token,
            user: userData
        });
  } catch (error) {
        debug.error('OTP verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Error verifying OTP'
        });
  }
});

// Login route with unified attempt tracking
// UNIFIED ATTEMPT SYSTEM: Both invalid username and invalid password attempts 
// count toward the same 3-attempt limit per IP address (15-minute lockout)
router.post('/login', authLimiter, ipBruteForceProtection, async (req, res) => {
    try {
        console.log('Login route hit');
        const { username, password, recaptchaToken } = req.body;

        // Debug log
        console.log('Login attempt:', { username, hasPassword: !!password, hasRecaptcha: !!recaptchaToken });

        if (!username || !password || !recaptchaToken) {
            // Record failed attempt for missing data
            if (req.recordIPAttempt) {
                req.recordIPAttempt();
            }
            return res.status(400).json({ 
                success: false,
                message: 'All fields are required' 
            });
        }

        // Verify reCAPTCHA
        const recaptchaValid = await validateRecaptcha(recaptchaToken);
        if (!recaptchaValid) {
            if (req.recordIPAttempt) {
                req.recordIPAttempt();
            }
            return res.status(400).json({ 
                success: false,
                message: 'reCAPTCHA verification failed' 
            });
        }

        console.log('Attempting to find user:', username);
        // Find user
        const user = await User.findOne({ username });
        console.log('User found:', user ? 'Yes' : 'No');
        
        if (!user) {
            console.log('User not found:', username);
            
            // Get current IP attempt data before recording new attempt
            const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for']?.split(',')[0];
            const ipDataBefore = req.getIPAttemptData ? req.getIPAttemptData() : null;
            const attemptsBefore = ipDataBefore ? ipDataBefore.attempts : req.ipAttemptCount || 0;
            
            // Check if IP is already locked
            const now = Date.now();
            if (ipDataBefore && ipDataBefore.lockExpires && ipDataBefore.lockExpires > now) {
                const remainingMinutes = Math.ceil((ipDataBefore.lockExpires - now) / (60 * 1000));
                console.log(`[Auth] IP already locked: ${clientIP}, remaining: ${remainingMinutes} minutes`);
                return res.status(423).json({
                    success: false,
                    message: `Too many failed attempts. Please try again in ${remainingMinutes} minutes.`,
                    attemptsRemaining: 0,
                    isLocked: true,
                    lockRemaining: remainingMinutes
                });
            }
            
            // Record IP attempt for invalid username
            if (req.recordIPAttempt) {
                req.recordIPAttempt();
            }
            
            // Get updated attempt count
            const ipDataAfter = req.getIPAttemptData ? req.getIPAttemptData() : null;
            const attemptsAfter = ipDataAfter ? ipDataAfter.attempts : (attemptsBefore + 1);
            
            // Consistent with user-based lockout: 3 attempts, then lock for 15 minutes
            const maxAttempts = 3;
            const isLocked = attemptsAfter >= maxAttempts;
            const attemptsRemaining = Math.max(0, maxAttempts - attemptsAfter);
            
            console.log(`[Auth] Invalid username attempt ${attemptsAfter}/${maxAttempts} from IP: ${clientIP} (unified counter)`);
            
            if (isLocked) {
                return res.status(423).json({
                    success: false,
                    message: 'Too many failed attempts. Account locked for 15 minutes.',
                    attemptsRemaining: 0,
                    isLocked: true,
                    lockRemaining: 15
                });
            }
            
            return res.status(401).json({ 
                success: false,
                message: `Invalid username or password. ${attemptsRemaining} attempt${attemptsRemaining === 1 ? '' : 's'} remaining.`,
                attemptsRemaining: attemptsRemaining,
                isLocked: false
            });
        }

        // Check if account is currently locked
        if (user.isAccountLocked()) {
            const remainingMinutes = user.getRemainingLockTime();
            console.log(`Account locked for user: ${username}, remaining: ${remainingMinutes} minutes`);
            return res.status(423).json({
                success: false,
                message: `Account is locked due to multiple failed attempts. Please try again in ${remainingMinutes} minutes.`,
                lockRemaining: remainingMinutes
            });
        }

        // Password expiry check moved to dashboard - allow login with expired passwords
        // Password change required check also moved to dashboard

        // Verify password
        console.log('Attempting password verification...');
        const isPasswordValid = await user.verifyPassword(password.trim());
        console.log('Password verification result:', isPasswordValid);

        if (!isPasswordValid) {
            // Get current IP attempt data before recording new attempt
            const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for']?.split(',')[0];
            const ipDataBefore = req.getIPAttemptData ? req.getIPAttemptData() : null;
            const attemptsBefore = ipDataBefore ? ipDataBefore.attempts : req.ipAttemptCount || 0;
            
            // Check if IP is already locked
            const now = Date.now();
            if (ipDataBefore && ipDataBefore.lockExpires && ipDataBefore.lockExpires > now) {
                const remainingMinutes = Math.ceil((ipDataBefore.lockExpires - now) / (60 * 1000));
                console.log(`[Auth] IP already locked: ${clientIP}, remaining: ${remainingMinutes} minutes`);
                return res.status(423).json({
                    success: false,
                    message: `Too many failed attempts. Please try again in ${remainingMinutes} minutes.`,
                    attemptsRemaining: 0,
                    isLocked: true,
                    lockRemaining: remainingMinutes
                });
            }
            
            // Record unified IP attempt (both username and password failures count together)
            if (req.recordIPAttempt) {
                req.recordIPAttempt();
            }
            
            // Also record user-specific attempt for security alerts (but use IP count for limiting)
            const userAttempts = await user.recordFailedAttempt();
            
            // Get updated IP attempt count (this is what we use for limiting)
            const ipDataAfter = req.getIPAttemptData ? req.getIPAttemptData() : null;
            const attemptsAfter = ipDataAfter ? ipDataAfter.attempts : (attemptsBefore + 1);
            
            // Unified attempt limit: 3 attempts total (username + password combined)
            const maxAttempts = 3;
            const isLocked = attemptsAfter >= maxAttempts;
            const attemptsRemaining = Math.max(0, maxAttempts - attemptsAfter);
            
            console.log(`[Auth] Invalid password attempt ${attemptsAfter}/${maxAttempts} from IP: ${clientIP} (unified counter)`);
            
            // Send security alert if IP gets locked or user account gets locked
            if (isLocked || user.isAccountLocked()) {
                await notificationManager.sendSecurityAlert(user, 'account_locked', 
                    `Account security: ${attemptsAfter} failed login attempts from IP ${clientIP}`);
            }
            
            if (isLocked) {
                return res.status(423).json({
                    success: false,
                    message: 'Too many failed attempts. Account locked for 15 minutes.',
                    attemptsRemaining: 0,
                    isLocked: true,
                    lockRemaining: 15
                });
            }
            
            return res.status(401).json({
                success: false,
                message: `Invalid username or password. ${attemptsRemaining} attempt${attemptsRemaining === 1 ? '' : 's'} remaining.`,
                attemptsRemaining: attemptsRemaining,
                isLocked: false
            });
        }

        // Handle successful login - clear failed attempts
        await user.recordSuccessfulLogin();
        
        // Clear IP attempts on successful login
        if (req.clearIPAttempts) {
            req.clearIPAttempts();
        }
        
        // Add login to history
        const ip = req.ip || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'];
        const geoip = require('geoip-lite');
        const geo = geoip.lookup(ip);
        const location = geo ? `${geo.city}, ${geo.country}` : 'Unknown';
        
        // Device fingerprinting for new device detection
        const deviceFingerprint = `${userAgent}-${ip}`;
        const isNewDevice = !user.loginHistory.some(login => 
            login.userAgent === userAgent && login.ipAddress === ip
        );
        
        await user.addLoginHistory(ip, userAgent, location, deviceFingerprint);

        // Generate JWT token with user ID
        console.log('Generating token for user:', user._id);
        const token = jwt.sign(
            { 
                userId: user._id.toString(), // Ensure ID is a string
                username: user.username,
                role: user.role,
                deviceFingerprint: deviceFingerprint,
                loginTimestamp: Date.now()
            },
            config.jwtSecret,
            { expiresIn: config.jwtExpiresIn }
        );
        console.log('Token generated successfully');

        // Generate OTP for MFA
        const otp = otpManager.generateOTP(user.email, user._id);
        user.mfaToken = otp;
        user.mfaTokenCreatedAt = new Date();
        await user.save();

        // Send OTP via email
        const emailSent = await sendOTP(user.email, otp, user.username);
    if (!emailSent) {
            return res.status(500).json({ message: 'Failed to send verification code' });
        }

        // Send login notification (always for security - permanently enabled)
        await notificationManager.sendLoginAlert(user, req, isNewDevice);

        // If it's a new device, send additional security alert
        if (isNewDevice) {
            await notificationManager.sendSecurityAlert(user, 'login_from_new_device', 
                `New device login: ${userAgent} from ${location} (IP: ${ip})`);
        }

        res.json({
            message: 'Verification code sent to your email',
            requiresMFA: true,
            email: user.email,
            token: token // Send token with the response
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            message: 'Error during login',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Verify login OTP
router.post('/verify-login', otpLimiter, async (req, res) => {
  try {
    const { mfaToken, otp } = req.body;

    const user = await User.findOne({ tempMfaToken: mfaToken });
    if (!user || !user.tempMfaTokenExpires || user.tempMfaTokenExpires < Date.now()) {
      return res.status(400).json({
        message: 'Invalid or expired verification code'
      });
    }

    // Verify OTP
    const isValid = await bcrypt.compare(otp, user.tempMfaToken);
    if (!isValid) {
      return res.status(400).json({
        message: 'Invalid verification code'
      });
    }

    // Clear MFA data and update activity
    user.tempMfaToken = undefined;
    user.tempMfaTokenExpires = undefined;
    user.lastLogin = new Date();
    user.lastActiveAt = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id },
      config.jwtSecret,
      { expiresIn: config.jwtExpiresIn }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isVerified: user.isVerified
      }
    });
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({
      message: 'An error occurred during verification'
    });
  }
});

router.post('/verify-login-otp', async (req, res) => {
  const { username, otp } = req.body;
  if (!otpStore[username] || otpStore[username].expiry < Date.now()) {
    delete otpStore[username];
    return res.status(400).json({ error: 'OTP expired or invalid.' });
  }
  if (otpStore[username].otp === otp) {
    const user = (await readUsers()).find(u => u.username === username);
    const token = jwt.sign({ username: user.username, email: user.email }, config.jwtSecret, { expiresIn: config.jwtExpiresIn });
    req.session.token = token;
    delete otpStore[username];
    res.json({ message: 'Login successful.', token });
  } else {
    res.status(400).json({ error: 'Invalid OTP.' });
  }
});

// Forgot password route
router.post('/forgot-password', async (req, res) => {
  try {
  const { email, recaptchaToken } = req.body;

    // Validate required fields
    if (!email || !recaptchaToken) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Verify reCAPTCHA
    const recaptchaValid = await validateRecaptcha(recaptchaToken);
    if (!recaptchaValid) {
      return res.status(400).json({ message: 'reCAPTCHA verification failed' });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'No account found with this email' });
    }

    // Generate OTP
    const otp = otpManager.generateOTP(email, user._id);
    user.mfaToken = otp;
    user.mfaTokenCreatedAt = Date.now();
    await user.save();

    // Send OTP via email
    const emailSent = await sendOTP(user.email, otp, user.username);
    if (!emailSent) {
      return res.status(500).json({ message: 'Failed to send verification code' });
    }

    res.json({
      message: 'Verification code sent to your email',
      email: user.email
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'An error occurred during password reset' });
  }
});

// Verify reset OTP route
router.post('/verify-reset', async (req, res) => {
    try {
        const { mfaToken, otp } = req.body;

        if (!mfaToken || !otp) {
            return res.status(400).json({ message: 'Missing required fields' });
    }

        // Find user by MFA token
        const user = await User.findOne({ mfaToken });
        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired verification code' });
        }

        // Check if OTP is expired (2 minutes)
        if (Date.now() - user.mfaTokenCreatedAt > 2 * 60 * 1000) {
            return res.status(400).json({ message: 'Verification code has expired' });
        }

        // Verify OTP
        if (user.mfaToken !== otp) {
            return res.status(400).json({ message: 'Invalid verification code' });
        }

        // Generate reset token
        const resetToken = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: config.jwtExpiresIn }
        );

        // Clear MFA token
        user.mfaToken = undefined;
        user.mfaTokenCreatedAt = undefined;
        await user.save();

        res.json({
            message: 'Verification successful',
            resetToken
        });
  } catch (error) {
        console.error('Reset verification error:', error);
        res.status(500).json({ message: 'An error occurred during verification' });
  }
});

// Reset password route
router.post('/reset-password', async (req, res) => {
    try {
    console.log('=== Reset Password Debug Log ===');
    const { newPassword } = req.body;
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];

        if (!token || !newPassword) {
            return res.status(400).json({ message: 'Token and new password are required' });
        }

    // Verify and decode the JWT token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (!decoded.userId) {
        return res.status(401).json({ message: 'Invalid token format' });
      }
    } catch (error) {
      return res.status(401).json({ message: 'Invalid or expired token' });
        }

    // Find user by ID from token
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
        }

        // Validate password strength
    const passwordRegex = /^(?=.*[A-Z].*[A-Z])(?=.*[a-z].*[a-z])(?=.*\d.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?].*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{12,}$/;
    const isValid = passwordRegex.test(newPassword);

    if (!isValid) {
            return res.status(400).json({ 
        message: 'Password must be at least 12 characters long and contain at least 2 uppercase letters, 2 lowercase letters, 2 numbers, and 2 special characters'
            });
        }

        // Check if new password is the same as current password
        console.log('[Reset Password] Checking if new password is same as current password');
        try {
            const isSameAsCurrent = await user.verifyPassword(newPassword);
            if (isSameAsCurrent) {
                console.log('[Reset Password] New password is same as current password');
                return res.status(400).json({ 
                    message: 'New password cannot be the same as your current password',
                    errorType: 'SAME_AS_CURRENT'
                });
            }
        } catch (currentPasswordCheckError) {
            console.error('[Reset Password] Error checking current password:', currentPasswordCheckError);
            // Continue with password history check even if current password check fails
        }

        // Check if new password is in history (last 5 passwords)
        console.log('[Reset Password] Checking password history for last 5 passwords');
        try {
            const isInHistory = await user.isPasswordInHistory(newPassword);
            if (isInHistory) {
                console.log('[Reset Password] Password found in history');
                return res.status(400).json({ 
                    message: 'New password cannot be the same as any of your last 5 passwords. Please choose a different password.',
                    errorType: 'PASSWORD_IN_HISTORY',
                    details: 'For security reasons, you cannot reuse any of your previous 5 passwords'
                });
            }
            console.log('[Reset Password] Password not found in history - validation passed');
        } catch (historyCheckError) {
            console.error('[Reset Password] Error checking password history:', historyCheckError);
            // Log the error but don't block password reset for history check failures
            // This ensures the system remains functional even if history checking fails
            console.log('[Reset Password] Continuing with password reset despite history check error');
        }

    // Update password using the user model's save method to trigger the pre-save hook
    user.password = newPassword.trim();
        await user.save();

        res.json({ message: 'Password has been reset successfully' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ message: 'An error occurred while resetting your password' });
    }
});

// MFA verification route
router.post('/verify-mfa', async (req, res) => {
    try {
        const { mfaToken, otp } = req.body;

        if (!mfaToken || !otp) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        // Verify MFA token and OTP
        const user = await User.findOne({ mfaToken });
        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired verification code' });
        }

        // Check if OTP is expired (2 minutes)
        if (Date.now() - user.mfaTokenCreatedAt > 2 * 60 * 1000) {
            return res.status(400).json({ message: 'Verification code has expired' });
  }

        // Verify OTP
        if (user.mfaToken !== otp) {
            return res.status(400).json({ message: 'Invalid verification code' });
        }

        // Clear MFA token and update activity
        user.mfaToken = undefined;
        user.mfaTokenCreatedAt = undefined;
        user.lastLogin = new Date();
        user.lastActiveAt = new Date();
        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: config.jwtExpiresIn }
        );

        res.json({
            message: 'Verification successful',
            token
        });
    } catch (error) {
        console.error('MFA verification error:', error);
        res.status(500).json({ message: 'An error occurred during verification' });
    }
});

// Resend MFA code route
router.post('/resend-mfa', async (req, res) => {
    try {
        const { mfaToken } = req.body;

        if (!mfaToken) {
            return res.status(400).json({ message: 'Missing MFA token' });
        }

        // Find user by MFA token
        const user = await User.findOne({ mfaToken });
  if (!user) {
            return res.status(400).json({ message: 'Invalid or expired verification code' });
  }

        // Check if enough time has passed since last OTP (2 minutes)
        if (user.mfaTokenCreatedAt && Date.now() - user.mfaTokenCreatedAt < 2 * 60 * 1000) {
            const remainingTime = Math.ceil((2 * 60 * 1000 - (Date.now() - user.mfaTokenCreatedAt)) / 1000);
            return res.status(429).json({ 
                message: `Please wait ${remainingTime} seconds before requesting a new code`
            });
  }

        // Generate new OTP
        const otp = otpManager.generateOTP(user.email, user._id);
        user.mfaToken = otp;
        user.mfaTokenCreatedAt = Date.now();
        await user.save();

        // Send new OTP via email
        const emailSent = await sendOTP(user.email, otp, user.username);
        if (!emailSent) {
            return res.status(500).json({ message: 'Failed to send verification code' });
  }

        res.json({ message: 'New verification code sent successfully' });
    } catch (error) {
        console.error('Resend MFA code error:', error);
        res.status(500).json({ message: 'An error occurred while sending the code' });
    }
});

// Resend OTP code route (for registration and password reset)
router.post('/resend-otp', async (req, res) => {
    try {
        const { email, purpose } = req.body;
        debug.log('Resend OTP request:', { email, purpose });

        if (!email || !purpose) {
            return res.status(400).json({ 
                success: false,
                message: 'Email and purpose are required' 
            });
        }

        if (purpose === 'registration') {
            // Handle registration OTP resend
            if (!global.pendingRegistrations || global.pendingRegistrations.size === 0) {
                return res.status(400).json({ 
                    success: false,
                    message: 'No pending registration found. Please start registration again.' 
                });
            }

            // Find pending registration by email
            let tempUserData = null;
            let oldToken = null;
            for (const [token, userData] of global.pendingRegistrations.entries()) {
                if (userData.email === email) {
                    tempUserData = userData;
                    oldToken = token;
                    break;
                }
            }

            if (!tempUserData) {
                return res.status(400).json({ 
                    success: false,
                    message: 'No pending registration found for this email' 
                });
            }

            // Check rate limiting (2 minutes)
            if (tempUserData.mfaTokenCreatedAt && Date.now() - tempUserData.mfaTokenCreatedAt < 2 * 60 * 1000) {
                const remainingTime = Math.ceil((2 * 60 * 1000 - (Date.now() - tempUserData.mfaTokenCreatedAt)) / 1000);
                return res.status(429).json({ 
                    success: false,
                    message: `Please wait ${remainingTime} seconds before requesting a new code`
                });
            }

            // Generate new OTP
            const newOtp = otpManager.generateOTP(email, 'pending');
            
            // Update the pending registration with new token
            tempUserData.mfaToken = newOtp;
            tempUserData.mfaTokenCreatedAt = new Date();
            
            // Remove old entry and add with new token
            global.pendingRegistrations.delete(oldToken);
            global.pendingRegistrations.set(newOtp, tempUserData);

            // Send new OTP via email
            const emailSent = await sendOTP(tempUserData.email, newOtp, tempUserData.username);
            if (!emailSent) {
                debug.error('Failed to send verification email during resend');
                return res.status(500).json({ 
                    success: false,
                    message: 'Failed to send verification email. Please try again.' 
                });
            }

            debug.log('Registration OTP resent successfully');
            res.json({ 
                success: true,
                message: 'New verification code sent to your email' 
            });

        } else {
            // Handle existing user OTP resend (login/reset)
            const user = await User.findOne({ email });
            if (!user) {
                return res.status(400).json({ 
                    success: false,
                    message: 'User not found' 
                });
            }

            // Check rate limiting (2 minutes)
            if (user.mfaTokenCreatedAt && Date.now() - user.mfaTokenCreatedAt < 2 * 60 * 1000) {
                const remainingTime = Math.ceil((2 * 60 * 1000 - (Date.now() - user.mfaTokenCreatedAt)) / 1000);
                return res.status(429).json({ 
                    success: false,
                    message: `Please wait ${remainingTime} seconds before requesting a new code`
                });
            }

            // Generate new OTP
            const otp = otpManager.generateOTP(user.email, user._id);
            user.mfaToken = otp;
            user.mfaTokenCreatedAt = Date.now();
            await user.save();

            // Send new OTP via email
            const emailSent = await sendOTP(user.email, otp, user.username);
            if (!emailSent) {
                return res.status(500).json({ 
                    success: false,
                    message: 'Failed to send verification code' 
                });
            }

            debug.log('OTP resent successfully for existing user');
            res.json({ 
                success: true,
                message: 'New verification code sent to your email' 
            });
        }
    } catch (error) {
        debug.error('Resend OTP error:', error);
        res.status(500).json({ 
            success: false,
            message: 'An error occurred while sending the code' 
        });
    }
});

// Change password
router.post('/change-password', auth, async (req, res) => {
    try {
        console.log('[Auth] Change password request received');
        console.log('[Auth] Request body:', { ...req.body, currentPassword: '***', newPassword: '***' });
        
        const { currentPassword, newPassword } = req.body;
        
        // Use the user from auth middleware directly
        const user = req.user;
        console.log('[Auth] User from middleware:', { id: user._id, username: user.username });

        if (!user) {
            console.error('[Auth] No user found in request');
            return res.status(404).json({ 
                success: false,
                message: 'User not found' 
            });
        }

        // Validate new password
        if (!newPassword || newPassword.length < 12) {
            console.log('[Auth] Password validation failed: too short');
            return res.status(400).json({ 
                success: false,
                message: 'Password must be at least 12 characters long' 
            });
        }

        // Enhanced password strength validation
        const passwordRegex = /^(?=.*[A-Z].*[A-Z])(?=.*[a-z].*[a-z])(?=.*\d.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?].*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{12,}$/;
        if (!passwordRegex.test(newPassword)) {
            console.log('[Auth] Password validation failed: strength requirements');
            return res.status(400).json({
                success: false,
                message: 'Password must contain at least: 2 uppercase letters, 2 lowercase letters, 2 numbers, and 2 special characters'
            });
        }

        // Check if this is a forced password change
        const isForced = user.isPasswordExpired() || user.requiresPasswordChange();
        console.log('[Auth] Password change forced:', isForced);

        // For forced changes, skip current password verification
        if (!isForced) {
            if (!currentPassword) {
                console.log('[Auth] Current password required but not provided');
                return res.status(400).json({ 
                    success: false,
                    message: 'Current password is required' 
                });
            }
            
            // Verify current password
            console.log('[Auth] Verifying current password');
            const isMatch = await user.verifyPassword(currentPassword);
            if (!isMatch) {
                console.log('[Auth] Current password verification failed');
                return res.status(400).json({ 
                    success: false,
                    message: 'Current password is incorrect' 
                });
            }
            console.log('[Auth] Current password verified successfully');
        }

        // Check if new password is the same as current password
        console.log('[Auth] Checking if new password is same as current password');
        try {
            const isSameAsCurrent = await user.verifyPassword(newPassword);
            if (isSameAsCurrent) {
                console.log('[Auth] New password is same as current password');
                return res.status(400).json({ 
                    success: false,
                    message: 'New password cannot be the same as your current password',
                    errorType: 'SAME_AS_CURRENT'
                });
            }
        } catch (currentPasswordCheckError) {
            console.error('[Auth] Error checking current password:', currentPasswordCheckError);
            // Continue with password history check even if current password check fails
        }

        // Check if new password is in history (last 5 passwords)
        console.log('[Auth] Checking password history for last 5 passwords');
        try {
            const isInHistory = await user.isPasswordInHistory(newPassword);
            if (isInHistory) {
                console.log('[Auth] Password found in history');
                return res.status(400).json({ 
                    success: false,
                    message: 'New password cannot be the same as any of your last 5 passwords. Please choose a different password.',
                    errorType: 'PASSWORD_IN_HISTORY',
                    details: 'For security reasons, you cannot reuse any of your previous 5 passwords'
                });
            }
            console.log('[Auth] Password not found in history - validation passed');
        } catch (historyCheckError) {
            console.error('[Auth] Error checking password history:', historyCheckError);
            // Log the error but don't block password change for history check failures
            // This ensures the system remains functional even if history checking fails
            console.log('[Auth] Continuing with password change despite history check error');
        }

        // Update password (this will trigger the pre-save hook)
        console.log('[Auth] Updating password');
        user.password = newPassword.trim();
        await user.save();

        // Send security notification if available
        try {
            const notificationManager = require('../utils/notificationManager');
            await notificationManager.sendSecurityAlert(user, 'password_changed', 
                'Password was successfully changed');
        } catch (notifError) {
            console.log('[Auth] Notification error (non-critical):', notifError.message);
        }

        console.log(`[Auth] Password changed successfully for user: ${user.username}`);

        res.json({ 
            success: true,
            message: 'Password changed successfully',
            passwordExpiry: user.passwordExpiresAt
        });
    } catch (error) {
        console.error('[Auth] Change password error:', error);
        res.status(500).json({ 
            success: false,
            message: 'Server error during password change',
            error: error.message
        });
    }
});

// Secure logout route with token revocation
router.post('/logout', auth, async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const user = req.user;

        if (token && user) {
            // Revoke the current token
            await user.revokeToken(token);
            
            // Send security notification
            await notificationManager.sendSecurityAlert(user, 'token_revoked', 
                'User logged out and token was revoked');
            
            debug.log('User logged out successfully:', user.email);
        }

        res.json({
            success: true,
            message: 'Logged out successfully'
        });
    } catch (error) {
        debug.error('Logout error:', error);
        res.status(500).json({
            success: false,
            message: 'Error during logout'
        });
    }
});

// Logout from all devices
router.post('/logout-all', auth, async (req, res) => {
    try {
        const user = req.user;
        
        // Clear all revoked tokens (effectively invalidating all sessions)
        user.revokedTokens = [];
        await user.save();
        
        // Send security notification
        await notificationManager.sendSecurityAlert(user, 'token_revoked', 
            'All devices logged out - all tokens revoked');

        res.json({
            success: true,
            message: 'Logged out from all devices successfully'
        });
    } catch (error) {
        debug.error('Logout all error:', error);
        res.status(500).json({
            success: false,
            message: 'Error during logout'
        });
    }
});

// Update notification settings
router.put('/notification-settings', auth, async (req, res) => {
    try {
        const user = req.user;
        const { notificationSettings } = req.body;

        // Update notification settings
        user.notificationSettings = {
            ...user.notificationSettings,
            ...notificationSettings
        };
        
        await user.save();

        res.json({
            success: true,
            message: 'Notification settings updated successfully',
            notificationSettings: user.notificationSettings
        });
    } catch (error) {
        debug.error('Update notification settings error:', error);
        res.status(500).json({
            success: false,
            message: 'Error updating notification settings'
        });
    }
});

// Get notifications
router.get('/notifications', auth, async (req, res) => {
    try {
        const userId = req.user._id.toString();
        const limit = parseInt(req.query.limit) || 20;
        
        const notifications = notificationManager.getBrowserNotifications(userId, limit);
        const unreadCount = notificationManager.getUnreadCount(userId);

        res.json({
            success: true,
            notifications,
            unreadCount
        });
    } catch (error) {
        debug.error('Get notifications error:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching notifications'
        });
    }
});

// Mark notification as read
router.put('/notifications/:id/read', auth, async (req, res) => {
    try {
        const userId = req.user._id.toString();
        const notificationId = req.params.id;
        
        const success = notificationManager.markNotificationAsRead(userId, notificationId);

        res.json({
            success,
            message: success ? 'Notification marked as read' : 'Notification not found'
        });
    } catch (error) {
        debug.error('Mark notification read error:', error);
        res.status(500).json({
            success: false,
            message: 'Error marking notification as read'
        });
    }
});

// Mark all notifications as read
router.put('/notifications/mark-all-read', auth, async (req, res) => {
    try {
        const userId = req.user._id.toString();
        
        const success = notificationManager.markAllNotificationsAsRead(userId);

        res.json({
            success,
            message: 'All notifications marked as read'
        });
    } catch (error) {
        debug.error('Mark all notifications read error:', error);
        res.status(500).json({
            success: false,
            message: 'Error marking notifications as read'
        });
    }
});

// Verify token route
router.post('/verify-token', auth, async (req, res) => {
    try {
        debug.log('Token verification request received');
        
        // Get user from auth middleware
        const user = req.user;
        if (!user) {
            debug.error('No user found in request');
            return res.status(401).json({
                success: false,
                message: 'User not found'
            });
        }

        // Update last active timestamp
        await user.updateLastActive();

        // Get fresh user data from database
        const freshUser = await User.findById(user._id);
        if (!freshUser) {
            debug.error('User not found in database');
            return res.status(401).json({
                success: false,
                message: 'User not found'
            });
        }

        debug.log('Token verified successfully');
        res.json({
            success: true,
            message: 'Token verified successfully',
            user: {
                _id: freshUser._id,
                username: freshUser.username,
                email: freshUser.email,
                role: freshUser.role,
                lastLogin: freshUser.lastLogin,
                notificationSettings: freshUser.notificationSettings
            }
        });
    } catch (error) {
        debug.error('Token verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Error verifying token'
        });
    }
});

// Verify token
router.post('/verify-token', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const { userData } = req.body;

        debug.log('Token verification request received');
        debug.log('Token:', token);
        debug.log('User data from request:', userData);

        if (!token) {
            debug.error('No token provided');
            return res.status(401).json({
                success: false,
                message: 'No token provided'
            });
        }

        if (!userData) {
            debug.error('No user data provided');
            return res.status(400).json({
                success: false,
                message: 'No user data provided'
            });
        }

        // Verify token
        const decoded = jwt.verify(token, config.jwtSecret);
        debug.log('Token decoded:', decoded);

        // Find user
        const user = await User.findById(decoded._id);
        debug.log('User found:', user ? 'Yes' : 'No');
        if (user) {
            debug.log('User details:', {
                _id: user._id,
                email: user.email,
                username: user.username
            });
        }

        if (!user) {
            debug.error('User not found:', decoded._id);
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Verify user data matches
        if (user._id.toString() !== userData._id) {
            debug.error('User data mismatch:', {
                tokenUserId: decoded._id,
                providedUserId: userData._id
            });
            return res.status(401).json({
                success: false,
                message: 'Invalid user data'
            });
        }

        // Check if user is active
        if (!user.isActive) {
            debug.error('User is not active:', user.email);
            return res.status(401).json({
                success: false,
                message: 'Account is deactivated'
            });
        }

        debug.log('Token verified successfully for user:', user.email);
        res.json({
            success: true,
            message: 'Token verified successfully',
            user: {
                _id: user._id,
                username: user.username,
                email: user.email,
                role: user.role,
                isActive: user.isActive
            }
        });
    } catch (error) {
        debug.error('Token verification error:', error);
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                message: 'Invalid token'
            });
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Token expired'
            });
        }
        res.status(500).json({
            success: false,
            message: 'Error verifying token'
        });
    }
});

// Clear expired OTPs periodically
setInterval(() => {
    const now = Date.now();
    for (const [email, data] of otpStore.entries()) {
        if (now - data.timestamp > 2 * 60 * 1000) {
            otpStore.delete(email);
            debug.log('Cleared expired OTP for:', email);
        }
    }
}, 60000); // Check every minute

// Get active sessions
router.get('/active-sessions', auth, async (req, res) => {
    try {
        const user = req.user;
        
        // Get active sessions using the new method
        const activeSessions = user.getActiveSessions();
        
        // Mark current session based on request details
        const currentIP = req.ip || req.connection.remoteAddress;
        const currentUserAgent = req.headers['user-agent'];
        const currentFingerprint = `${currentUserAgent}-${currentIP}`;
        
        activeSessions.forEach(session => {
            if (session.deviceFingerprint === currentFingerprint) {
                session.isCurrent = true;
            }
        });

        res.json({
            success: true,
            sessions: activeSessions.reverse(), // Most recent first
            totalSessions: activeSessions.length,
            totalDevices: activeSessions.length // Each session represents a device
        });
    } catch (error) {
        debug.error('Get active sessions error:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching active sessions'
        });
    }
});

// Revoke specific session
router.delete('/sessions/:sessionId', auth, async (req, res) => {
    try {
        const user = req.user;
        const sessionId = req.params.sessionId;
        
        // Find and deactivate the session
        const sessionToRevoke = user.loginHistory.find(session => 
            session._id?.toString() === sessionId || 
            session.sessionId === sessionId
        );
        
        if (sessionToRevoke) {
            sessionToRevoke.isActive = false;
            sessionToRevoke.logoutAt = new Date();
            
            await user.save();

            // Send security notification
            await notificationManager.sendSecurityAlert(user, 'session_revoked', 
                `Session revoked by user request from ${sessionToRevoke.ipAddress || 'unknown IP'}`);

            res.json({
                success: true,
                message: 'Session revoked successfully'
            });
        } else {
            res.status(404).json({
                success: false,
                message: 'Session not found'
            });
        }
    } catch (error) {
        debug.error('Revoke session error:', error);
        res.status(500).json({
            success: false,
            message: 'Error revoking session'
        });
    }
});

// Revoke all sessions except current
router.post('/revoke-all-sessions', auth, async (req, res) => {
    try {
        const user = req.user;
        const currentIP = req.ip || req.connection.remoteAddress;
        const currentUserAgent = req.headers['user-agent'];
        const currentFingerprint = `${currentUserAgent}-${currentIP}`;
        
        // Deactivate all sessions except current
        let revokedCount = 0;
        user.loginHistory.forEach(session => {
            if (session.isActive && session.deviceFingerprint !== currentFingerprint) {
                session.isActive = false;
                session.logoutAt = new Date();
                revokedCount++;
            }
        });
        
        await user.save();

        // Send security notification
        await notificationManager.sendSecurityAlert(user, 'all_sessions_revoked', 
            `${revokedCount} sessions revoked by user request`);

        res.json({
            success: true,
            message: `${revokedCount} sessions revoked successfully`,
            revokedCount
        });
    } catch (error) {
        debug.error('Revoke all sessions error:', error);
        res.status(500).json({
            success: false,
            message: 'Error revoking sessions'
        });
    }
});

module.exports = router;