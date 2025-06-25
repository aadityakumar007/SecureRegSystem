const jwt = require('jsonwebtoken');
const config = require('../config/config');
const User = require('../models/User');

// Debug logging
const debug = {
    log: (message, data) => {
        console.log(`[Auth Middleware] ${message}`, data || '');
    },
    error: (message, error) => {
        console.error(`[Auth Middleware] ${message}`, error);
    }
};

// Debug log to verify User model
debug.log('User model loaded:', User ? 'Yes' : 'No');

const auth = async (req, res, next) => {
    try {
        // Get token from header
        const authHeader = req.header('Authorization');
        debug.log('Auth header received:', { 
            hasHeader: !!authHeader,
            headerLength: authHeader ? authHeader.length : 0 
        });

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
            debug.error('Invalid or missing Authorization header');
            return res.status(401).json({
                success: false,
                message: 'No token, authorization denied'
            });
    }

        const token = authHeader.replace('Bearer ', '');
        debug.log('Token extracted from header');

        // Verify token
        let decoded;
        try {
            decoded = jwt.verify(token, config.jwtSecret);
            debug.log('Token decoded successfully:', {
                userId: decoded._id,
                exp: decoded.exp
            });
        } catch (error) {
            debug.error('Token verification failed:', error);
            if (error.name === 'TokenExpiredError') {
                return res.status(401).json({
                    success: false,
                    message: 'Token has expired'
                });
            }
            return res.status(401).json({
                success: false,
                message: 'Token is not valid'
            });
    }

        // Find user using _id from token (handle both _id and userId formats)
    try {
            const userId = decoded._id || decoded.userId;
            const user = await User.findById(userId);
            debug.log('User lookup result:', {
                found: !!user,
                userId: userId,
                tokenFormat: decoded._id ? '_id' : 'userId'
            });

            if (!user) {
                debug.error('User not found in database');
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            // Check if user is active
            if (!user.isActive) {
                debug.error('User account is deactivated');
                return res.status(403).json({
                    success: false,
                    message: 'Account has been deactivated'
                });
    }

            // Check if user is verified
            if (!user.isVerified) {
                debug.error('User not verified');
                return res.status(403).json({
                    success: false,
                    message: 'User not verified'
                });
            }

            // Check if account is locked
            if (user.isAccountLocked()) {
                debug.error('Account is locked');
                return res.status(423).json({
                    success: false,
                    message: 'Account is locked due to multiple failed attempts',
                    lockRemaining: user.getRemainingLockTime()
                });
            }

                        // Password expiry check moved to dashboard - allow login with expired passwords
            // Password change required check also moved to dashboard

            // Check if token is revoked
            if (user.isTokenRevoked(token)) {
                debug.error('Token has been revoked');
                return res.status(401).json({
                    success: false,
                    message: 'Token has been revoked. Please login again.'
                });
    }

            // Check for session timeout (3 minutes of inactivity)
            const now = new Date();
            const lastActive = user.lastActiveAt || user.lastLogin || user.createdAt;
            const timeSinceLastActive = now - lastActive;
            const sessionTimeout = 3 * 60 * 1000; // 3 minutes in milliseconds
            
            // Be more lenient for recent logins (within last 30 seconds)
            const recentLoginGracePeriod = 30 * 1000; // 30 seconds
            const timeSinceLogin = user.lastLogin ? (now - user.lastLogin) : Infinity;
            const isRecentLogin = timeSinceLogin < recentLoginGracePeriod;

            debug.log('Session timeout check', {
                timeSinceLastActive,
                sessionTimeout,
                isRecentLogin,
                lastActive: lastActive,
                lastLogin: user.lastLogin,
                timeSinceLogin: timeSinceLogin,
                willExpire: timeSinceLastActive > sessionTimeout && !isRecentLogin
            });

            if (timeSinceLastActive > sessionTimeout && !isRecentLogin) {
                debug.error('Session expired due to inactivity - logging out user');
                // Optionally revoke the token
                await user.revokeToken(token);
                return res.status(401).json({
                    success: false,
                    message: 'Session expired due to inactivity. Please login again.',
                    sessionExpired: true
                });
            }

            // Update last active timestamp
            user.lastActiveAt = now;
            
            // Only update session activity if it's been more than 30 seconds since last update
            // to prevent creating multiple session entries on frequent requests
            const currentIP = req.ip || req.connection.remoteAddress;
            const currentUserAgent = req.headers['user-agent'];
            const deviceFingerprint = `${currentUserAgent}-${currentIP}`;
            
            // Find the current session
            const currentSession = user.loginHistory.find(s => 
                s.deviceFingerprint === deviceFingerprint && s.isActive === true
            );
            
            if (currentSession) {
                const lastUpdate = currentSession.lastActiveAt || currentSession.timestamp;
                const timeSinceLastUpdate = now - lastUpdate;
                
                // Only update if it's been more than 30 seconds since last activity update
                if (timeSinceLastUpdate > 30000) {
                    currentSession.lastActiveAt = now;
                    debug.log('Session activity updated for device:', deviceFingerprint.substring(0, 30));
                }
            }
            
            await user.save();

            // Attach user to request with full user object
            req.user = user;
            debug.log('User attached to request:', {
                userId: req.user._id,
                username: req.user.username,
                role: req.user.role,
                lastActive: req.user.lastActiveAt
            });

        next();
        } catch (dbError) {
            debug.error('Database error during user lookup:', dbError);
            return res.status(500).json({
                success: false,
                message: 'Database error during authentication'
            });
        }
    } catch (error) {
        debug.error('Auth middleware error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during authentication'
        });
    }
};

module.exports = auth;