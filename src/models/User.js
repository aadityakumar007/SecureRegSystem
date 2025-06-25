const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3,
        maxlength: 30
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true,
        minlength: 8
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    isActive: {
        type: Boolean,
        default: true
    },
    lastLogin: {
        type: Date
    },
    // Enhanced brute force protection
    failedLoginAttempts: {
        type: Number,
        default: 0
    },
    isLocked: {
        type: Boolean,
        default: false
    },
    lockExpires: {
        type: Date
    },
    lastFailedAttempt: {
        type: Date
    },
    // Password management
    passwordCreatedAt: {
        type: Date,
        default: Date.now
    },
    passwordExpiresAt: {
        type: Date,
        default: function() {
            // Default password expiry is 30 days from creation
            return new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        }
    },
    passwordChangeRequired: {
        type: Boolean,
        default: false
    },
    passwordHistory: [{
        passwordHash: String,
        createdAt: {
            type: Date,
            default: Date.now
        }
    }],
    // MFA fields
    mfaToken: String,
    mfaTokenCreatedAt: Date,
    // Token revocation
    revokedTokens: [{
        token: String,
        revokedAt: {
            type: Date,
            default: Date.now
        }
    }],
    // Notification preferences
    notificationSettings: {
        loginAlerts: {
            type: Boolean,
            default: true
        },
        securityAlerts: {
            type: Boolean,
            default: true
        },
        systemUpdates: {
            type: Boolean,
            default: true
        },
        email: {
            type: Boolean,
            default: true
        },
        browser: {
            type: Boolean,
            default: true
        }
    },
    // Security tracking
    lastActiveAt: {
        type: Date,
        default: Date.now
    },
    lastDeviceNotification: {
        type: Date
    },
    loginHistory: [{
        sessionId: {
            type: String,
            default: function() {
                return Date.now().toString() + Math.random().toString(36).substr(2, 9);
            }
        },
        timestamp: {
            type: Date,
            default: Date.now
        },
        ipAddress: String,
        userAgent: String,
        location: String,
        deviceFingerprint: String,
        isActive: {
            type: Boolean,
            default: true
        },
        lastActiveAt: {
            type: Date,
            default: Date.now
        },
        logoutAt: Date
    }]
}, {
    timestamps: true
});

// Pre-save hook to hash password and manage password history
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();

    try {
        // Store current password in history before changing it (only for existing users)
        if (!this.isNew && this.password) {
            // Get the original password hash from the database before it gets changed
            const originalUser = await this.constructor.findById(this._id);
            if (originalUser && originalUser.password) {
                this.passwordHistory.push({
                    passwordHash: originalUser.password, // Store the original hashed password
                    createdAt: new Date()
                });

                // Keep only last 5 passwords in history
                if (this.passwordHistory.length > 5) {
                    this.passwordHistory = this.passwordHistory.slice(-5);
                }
            }
        }
        
        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        
        // Update password timestamps when password is changed
        this.passwordCreatedAt = new Date();
        this.passwordExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
        this.passwordChangeRequired = false;

        next();
    } catch (error) {
        next(error);
    }
});

// Method to verify password
userSchema.methods.verifyPassword = async function(password) {
    if (!password || !this.password) {
        return false;
    }
    
    try {
        return await bcrypt.compare(password, this.password);
    } catch (error) {
        console.error('Error verifying password:', error);
        return false;
    }
};

// Method to check if password is expired
userSchema.methods.isPasswordExpired = function() {
    return this.passwordExpiresAt && this.passwordExpiresAt < new Date();
};

// Method to check if password change is required
userSchema.methods.requiresPasswordChange = function() {
    return this.passwordChangeRequired || this.isPasswordExpired();
};

// Method to check if password was used in history
userSchema.methods.isPasswordInHistory = async function(newPassword) {
    if (!newPassword) {
        console.log('[User Model] isPasswordInHistory: No password provided');
        return false;
    }
    
    console.log(`[User Model] Checking password history for user ${this.username}: ${this.passwordHistory.length} entries`);
    
    for (let i = 0; i < this.passwordHistory.length; i++) {
        const historicalPassword = this.passwordHistory[i];
        
        // Skip if passwordHash is null or undefined
        if (!historicalPassword.passwordHash) {
            console.log(`[User Model] Skipping history entry ${i + 1}: null/undefined passwordHash`);
            continue;
        }
        
        try {
            console.log(`[User Model] Checking against history entry ${i + 1} (created: ${historicalPassword.createdAt})`);
            const isMatch = await bcrypt.compare(newPassword, historicalPassword.passwordHash);
            if (isMatch) {
                console.log(`[User Model] Password matches history entry ${i + 1}`);
                return true;
            }
        } catch (error) {
            console.error(`[User Model] Error comparing password with history entry ${i + 1}:`, error);
            // Skip this entry and continue with the next one
            continue;
        }
    }
    
    console.log('[User Model] Password not found in any history entries');
    return false;
};

// Method to handle failed login attempts
userSchema.methods.recordFailedAttempt = async function() {
    this.failedLoginAttempts += 1;
    this.lastFailedAttempt = new Date();

    // Lock account after 3 failed attempts for 15 minutes
    if (this.failedLoginAttempts >= 3) {
        this.isLocked = true;
        this.lockExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
        console.log(`Account locked for user: ${this.username} until ${this.lockExpires}`);
    }
    
    await this.save();
    return this.failedLoginAttempts;
};

// Method to handle successful login
userSchema.methods.recordSuccessfulLogin = async function() {
    this.failedLoginAttempts = 0;
    this.isLocked = false;
    this.lockExpires = undefined;
    this.lastFailedAttempt = undefined;
    this.lastLogin = new Date();
    this.lastActiveAt = new Date();
    
    await this.save();
};

// Method to check if account is currently locked
userSchema.methods.isAccountLocked = function() {
    if (!this.isLocked) return false;
    
    // Check if lock has expired
    if (this.lockExpires && this.lockExpires <= new Date()) {
        // Auto-unlock expired locks
        this.isLocked = false;
        this.lockExpires = undefined;
        this.failedLoginAttempts = 0;
        this.save();
        return false;
    }
    
    return true;
};

// Method to get remaining lock time in minutes
userSchema.methods.getRemainingLockTime = function() {
    if (!this.isLocked || !this.lockExpires) return 0;
    
    const remaining = this.lockExpires - new Date();
    return Math.max(0, Math.ceil(remaining / (60 * 1000))); // Convert to minutes
};

// Method to force password change
userSchema.methods.forcePasswordChange = async function() {
    this.passwordChangeRequired = true;
    await this.save();
};

// Method to revoke token
userSchema.methods.revokeToken = function(token) {
    this.revokedTokens.push({ token });
    return this.save();
};

// Method to check if token is revoked
userSchema.methods.isTokenRevoked = function(token) {
    return this.revokedTokens.some(revokedToken => revokedToken.token === token);
};

// Method to update last active timestamp
userSchema.methods.updateLastActive = function() {
    this.lastActiveAt = new Date();
    return this.save();
};

// Method to add login history with session tracking
userSchema.methods.addLoginHistory = function(ipAddress, userAgent, location, deviceFingerprint) {
    const sessionId = Date.now().toString() + Math.random().toString(36).substr(2, 9);
    
    // Clean up old sessions for the same device
    const existingSessionIndex = this.loginHistory.findIndex(session => 
        session.deviceFingerprint === deviceFingerprint && session.isActive
    );
    
    if (existingSessionIndex !== -1) {
        // Mark old session as inactive instead of creating duplicate
        this.loginHistory[existingSessionIndex].isActive = false;
        this.loginHistory[existingSessionIndex].logoutAt = new Date();
    }
    
    this.loginHistory.push({
        sessionId,
        ipAddress,
        userAgent,
        location,
        deviceFingerprint,
        isActive: true,
        lastActiveAt: new Date()
    });
    
    // Keep only last 20 login records for better session tracking
    if (this.loginHistory.length > 20) {
        this.loginHistory = this.loginHistory.slice(-20);
    }
    
    return this.save();
};

// Method to update session activity
userSchema.methods.updateSessionActivity = function(deviceFingerprint) {
    // Find active session with matching device fingerprint
    const session = this.loginHistory.find(s => 
        s.deviceFingerprint === deviceFingerprint && s.isActive === true
    );
    
    if (session) {
        session.lastActiveAt = new Date();
        console.log(`Session activity updated for device: ${deviceFingerprint.substring(0, 30)}...`);
        return this.save();
    } else {
        console.log(`No active session found for device: ${deviceFingerprint.substring(0, 30)}...`);
        // Don't create new session here, just return without saving
        return Promise.resolve();
    }
};

// Method to get active sessions (deduplicated by device)
userSchema.methods.getActiveSessions = function() {
    const now = new Date();
    
    // Get only sessions that are marked as active (not logged out)
    const activeSessions = this.loginHistory.filter(session => 
        session.isActive === true && !session.logoutAt
    );
    
    // Group by device fingerprint to deduplicate
    const deviceMap = new Map();
    
    activeSessions.forEach(session => {
        const key = session.deviceFingerprint || `${session.userAgent}-${session.ipAddress}`;
        
        // Keep only the most recent session for each device
        if (!deviceMap.has(key) || session.lastActiveAt > deviceMap.get(key).lastActiveAt) {
            deviceMap.set(key, session);
        }
    });
    
    // Convert back to array and format
    return Array.from(deviceMap.values()).map(session => {
        const timeSinceActive = now - new Date(session.lastActiveAt);
        const isRecentlyActive = timeSinceActive < (30 * 60 * 1000); // 30 minutes
        
        return {
            sessionId: session.sessionId,
            _id: session._id,
            device: session.userAgent ? session.userAgent.substring(0, 60) + '...' : 'Unknown Device',
            location: session.location || 'Unknown Location',
            ipAddress: session.ipAddress,
            lastActive: session.lastActiveAt,
            loginTime: session.timestamp,
            isActive: isRecentlyActive, // True active within 30 minutes
            isCurrentlyLoggedIn: true, // All returned sessions are currently logged in
            deviceFingerprint: session.deviceFingerprint || `${session.userAgent}-${session.ipAddress}`,
            timeSinceActive: Math.floor(timeSinceActive / (1000 * 60)) // minutes
        };
    }).sort((a, b) => new Date(b.lastActive) - new Date(a.lastActive)); // Most recent first
};

// Method to logout session
userSchema.methods.logoutSession = function(sessionId) {
    const session = this.loginHistory.find(s => s.sessionId === sessionId);
    if (session) {
        session.isActive = false;
        session.logoutAt = new Date();
        return this.save();
    }
    return Promise.resolve();
};

module.exports = mongoose.model('User', userSchema); 