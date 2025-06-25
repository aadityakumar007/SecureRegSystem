const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const authMiddleware = require('../middleware/auth');
const jwt = require('jsonwebtoken');
const config = require('../config/config');
const geoip = require('geoip-lite');

const router = express.Router();

// Helper function to calculate security score
function calculateSecurityScore(user, activities) {
    let score = 85; // Base score
    
    // Reduce score for failed attempts
    const failedAttempts = user.failedLoginAttempts || 0;
    score -= Math.min(failedAttempts * 5, 25);
    
    // Increase score for recent password changes
    const recentPasswordChanges = activities.filter(a => 
        a.type === 'password_change' && 
        (new Date() - new Date(a.timestamp)) < (90 * 24 * 60 * 60 * 1000) // Last 90 days
    ).length;
    score += Math.min(recentPasswordChanges * 5, 15);
    
    // Account age bonus
    const accountAge = (new Date() - user.createdAt) / (1000 * 60 * 60 * 24);
    if (accountAge > 30) score += 5;
    
    return Math.min(Math.max(score, 0), 100);
}

// Helper function to calculate notification count
function calculateNotificationCount(user, activities) {
    let count = 0;
    
    // Password expiry notifications
    if (user.passwordExpiresAt) {
        const daysUntilExpiry = Math.ceil((user.passwordExpiresAt - new Date()) / (1000 * 60 * 60 * 24));
        if (daysUntilExpiry <= 0) count += 2; // Expired
        else if (daysUntilExpiry <= 7) count += 1; // Expiring soon
    }
    
    // Failed login notifications
    if (user.failedLoginAttempts > 0) count += 1;
    
    // Account lock notifications
    if (user.isLocked) count += 1;
    
    // New device login notifications (if any recent logins from different devices)
    const recentLogins = activities.filter(a => 
        a.type === 'login' && 
        (new Date() - new Date(a.timestamp)) < (24 * 60 * 60 * 1000) // Last 24 hours
    );
    if (recentLogins.length > 1) count += 1;
    
    return count;
}

// Helper functions for device extraction
function extractDeviceName(userAgent) {
    if (!userAgent) return 'Unknown Device';
    
    if (userAgent.includes('Mobile') || userAgent.includes('Android')) return 'Mobile Device';
    if (userAgent.includes('iPad')) return 'iPad';
    if (userAgent.includes('iPhone')) return 'iPhone';
    if (userAgent.includes('Tablet')) return 'Tablet';
    return 'Desktop Computer';
}

function extractBrowser(userAgent) {
    if (!userAgent) return 'Unknown Browser';
    
    if (userAgent.includes('Chrome') && !userAgent.includes('Edg')) return 'Chrome';
    if (userAgent.includes('Firefox')) return 'Firefox';
    if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) return 'Safari';
    if (userAgent.includes('Edg')) return 'Edge';
    if (userAgent.includes('Opera')) return 'Opera';
    return 'Unknown Browser';
}

function extractOS(userAgent) {
    if (!userAgent) return 'Unknown OS';
    
    if (userAgent.includes('Windows NT 10.0')) return 'Windows 10/11';
    if (userAgent.includes('Windows')) return 'Windows';
    if (userAgent.includes('Mac OS X')) return 'macOS';
    if (userAgent.includes('Linux')) return 'Linux';
    if (userAgent.includes('Android')) return 'Android';
    if (userAgent.includes('iPhone') || userAgent.includes('iPad')) return 'iOS';
    return 'Unknown OS';
}

function extractDeviceType(userAgent) {
    if (!userAgent) return 'Unknown';
    
    if (userAgent.includes('Mobile') || userAgent.includes('Android')) return 'Mobile';
    if (userAgent.includes('Tablet') || userAgent.includes('iPad')) return 'Tablet';
    return 'Desktop';
}

// Helper function to get location from IP
function getLocationFromIP(ip) {
    try {
        const geo = geoip.lookup(ip);
        if (geo && geo.city && geo.country) {
            return `${geo.city}, ${geo.region}, ${geo.country}`;
        }
        return 'Unknown Location';
    } catch (error) {
        console.error('Error getting location from IP:', error);
        return 'Unknown Location';
    }
}

// Helper function to get ISP information
function getISPFromIP(ip) {
    try {
        const geo = geoip.lookup(ip);
        if (geo && geo.org) {
            return geo.org;
        }
        return 'Unknown ISP';
    } catch (error) {
        console.error('Error getting ISP from IP:', error);
        return 'Unknown ISP';
    }
}

// Debug logging middleware for user routes
router.use((req, res, next) => {
    console.log('[User Routes]', req.method, req.path, {
        headers: req.headers,
        query: req.query,
        body: req.body
    });
    next();
});

// Verify token and return user info
router.get('/verify-token', authMiddleware, async (req, res) => {
    try {
        console.log('[User Routes] Verify token request received for user:', req.user);
        
        // Find user in database to ensure they still exist
        const user = await User.findById(req.user._id);
        
        if (!user) {
            console.log('[User Routes] User not found in database');
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check if user is verified
        if (!user.isVerified) {
            console.log('[User Routes] User not verified');
            return res.status(403).json({
                success: false,
                message: 'User not verified'
            });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        console.log('[User Routes] User found and verified:', {
            id: user._id,
            username: user.username,
            email: user.email,
            role: user.role
        });
        
        // Return user info
        res.json({
            success: true,
            user: {
                _id: user._id.toString(),
                username: user.username,
                email: user.email,
                isVerified: user.isVerified,
                role: user.role,
                lastLogin: user.lastLogin,
                createdAt: user.createdAt
            }
        });
    } catch (error) {
        console.error('[User Routes] Error in verify-token route:', error);
        res.status(500).json({
            success: false,
            message: 'Error verifying token'
        });
    }
});

// Get current IP and location information with real-world detection
router.get('/current-ip', authMiddleware, async (req, res) => {
    try {
        console.log('[User Routes] Fetching real-world IP info for user:', req.user._id);
        
        const geoip = require('geoip-lite');
        const fetch = require('node-fetch');
        
        // Enhanced real IP detection similar to devices endpoint
        let realIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                     req.headers['x-real-ip'] || 
                     req.headers['cf-connecting-ip'] ||
                     req.headers['x-client-ip'] ||
                     req.connection.remoteAddress || 
                     req.socket.remoteAddress ||
                     (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
                     req.ip;

        // Clean IP address (remove IPv6 prefix if present)
        if (realIP && realIP.startsWith('::ffff:')) {
            realIP = realIP.substring(7);
        }
        
        // REAL-WORLD IP DETECTION: Get actual public IP if currently on localhost
        if (!realIP || realIP === '::1' || realIP === '127.0.0.1' || realIP === 'localhost' || realIP.startsWith('192.168.') || realIP.startsWith('10.') || realIP.startsWith('172.')) {
            console.log('[User Routes] Local/Private IP detected, fetching real public IP...');
            
            // Try multiple external IP services for reliability
            const ipServices = [
                'https://api.ipify.org?format=json',
                'https://ipapi.co/json/',
                'https://ipinfo.io/json',
                'https://api.my-ip.io/ip.json'
            ];
            
            for (const service of ipServices) {
                try {
                    console.log('[User Routes] Trying IP service:', service);
                    const ipResponse = await fetch(service, { 
                        timeout: 5000,
                        headers: {
                            'User-Agent': 'SecureSystem-IPDetection/1.0'
                        }
                    });
                    
                    if (ipResponse.ok) {
                        const ipData = await ipResponse.json();
                        let detectedIP = null;
                        
                        // Handle different response formats
                        if (ipData.ip) detectedIP = ipData.ip;
                        else if (ipData.query) detectedIP = ipData.query;
                        else if (typeof ipData === 'string') detectedIP = ipData;
                        else if (ipData.address) detectedIP = ipData.address;
                        
                        if (detectedIP && detectedIP !== realIP) {
                            realIP = detectedIP.trim();
                            console.log('[User Routes] Real public IP detected:', realIP);
                            break;
                        }
                    }
                } catch (ipError) {
                    console.warn('[User Routes] IP service failed:', service, ipError.message);
                    continue;
                }
            }
        }

        console.log('[User Routes] Final detected IP:', realIP);

        // Enhanced location detection with comprehensive fallback
        let location = 'Unknown Location';
        let locationDetails = null;
        let isp = 'Unknown ISP';
        
        // Always try to get location for any IP (including localhost for testing)
        try {
            console.log('[User Routes] Getting location for IP:', realIP);
            
            // Try geoip-lite first (works for public IPs)
            if (realIP !== '127.0.0.1' && realIP !== '::1' && !realIP.startsWith('192.168.') && !realIP.startsWith('10.')) {
                const geo = geoip.lookup(realIP);
                if (geo && geo.city) {
                    location = `${geo.city}, ${geo.region || geo.country}, ${geo.country}`;
                    locationDetails = geo;
                    isp = geo.org || 'Unknown ISP';
                    console.log('[User Routes] GeoIP location found:', location);
                }
            }
            
            // If geoip-lite didn't work or for localhost, try external services
            if (location === 'Unknown Location' || realIP === '127.0.0.1') {
                const geoServices = [
                    `https://ipapi.co/${realIP}/json/`,
                    `https://ipinfo.io/${realIP}/json`,
                    `https://api.ipgeolocation.io/ipgeo?apiKey=free&ip=${realIP}`,
                    `https://freegeoip.app/json/${realIP}`
                ];
                
                for (const geoService of geoServices) {
                    try {
                        console.log('[User Routes] Trying geo service:', geoService);
                        const geoResponse = await fetch(geoService, { 
                            timeout: 5000,
                            headers: {
                                'User-Agent': 'SecureSystem-GeoLocation/1.0',
                                'Accept': 'application/json'
                            }
                        });
                        
                        if (geoResponse.ok) {
                            const geoData = await geoResponse.json();
                            
                            if (geoData && !geoData.error && !geoData.message) {
                                let city = geoData.city || geoData.locality || 'Unknown City';
                                let region = geoData.region || geoData.region_name || geoData.state || 'Unknown Region';
                                let country = geoData.country_name || geoData.country || 'Unknown Country';
                                
                                if (city !== 'Unknown City' || country !== 'Unknown Country') {
                                    location = `${city}, ${region}, ${country}`;
                                    locationDetails = {
                                        city: city,
                                        region: region,
                                        country: country,
                                        timezone: geoData.timezone || geoData.time_zone,
                                        isp: geoData.org || geoData.isp,
                                        latitude: geoData.latitude || geoData.lat,
                                        longitude: geoData.longitude || geoData.lon
                                    };
                                    isp = geoData.org || geoData.isp || 'Unknown ISP';
                                    console.log('[User Routes] External geo service location found:', location);
                                    break;
                                }
                            }
                        }
                    } catch (geoError) {
                        console.warn('[User Routes] Geo service failed:', geoService, geoError.message);
                        continue;
                    }
                }
            }
            
            // Final fallback for development/local testing
            if (location === 'Unknown Location' && (realIP === '127.0.0.1' || realIP === '::1')) {
                location = 'Local Development Environment';
                locationDetails = {
                    city: 'Local',
                    region: 'Development',
                    country: 'Local Machine',
                    timezone: 'Local',
                    isp: 'Local Network'
                };
                isp = 'Local Network';
                console.log('[User Routes] Using local development location');
            }
            
        } catch (locationError) {
            console.error('[User Routes] Location detection error:', locationError);
            location = 'Location Detection Failed';
        }

        // Prepare enhanced response
        const ipInfo = {
            ip: realIP,
            location: location,
            isp: isp,
            timestamp: new Date().toISOString(),
            userAgent: req.headers['user-agent'] || 'Unknown',
            details: locationDetails,
            method: realIP === '127.0.0.1' ? 'local' : 'external'
        };

        console.log('[User Routes] Enhanced IP info response:', ipInfo);

        res.json({
            success: true,
            ...ipInfo
        });
    } catch (error) {
        console.error('[User Routes] Error in current-ip route:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching current IP information',
            ip: req.ip || 'Unknown',
            location: 'Unable to detect',
            isp: 'Unable to detect'
        });
    }
});

// Get user info
router.get('/info', authMiddleware, async (req, res) => {
    try {
        console.log('[User Routes] Fetching user info for:', req.user._id);
        const user = await User.findById(req.user._id).select('-password');
        
        if (!user) {
            console.log('[User Routes] User not found in database');
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check if user is verified
        if (!user.isVerified) {
            console.log('[User Routes] User not verified');
            return res.status(403).json({
                success: false,
                message: 'User not verified'
            });
        }

        // Update last login and active timestamp
        user.lastLogin = new Date();
        user.lastActiveAt = new Date();
        await user.save();

        // Calculate password expiry information
        const passwordCreatedAt = user.passwordCreatedAt || user.createdAt;
        const passwordExpiresAt = user.passwordExpiresAt || new Date(passwordCreatedAt.getTime() + 30 * 24 * 60 * 60 * 1000);
        const now = new Date();
        const daysUntilExpiry = Math.ceil((passwordExpiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
        const isPasswordExpired = daysUntilExpiry <= 0;
        const isPasswordExpiringSoon = daysUntilExpiry <= 7;

        console.log('[User Routes] User info found:', {
            id: user._id,
            username: user.username,
            email: user.email,
            role: user.role,
            passwordCreatedAt: passwordCreatedAt,
            passwordExpiresAt: passwordExpiresAt,
            daysUntilExpiry: daysUntilExpiry
        });

        res.json({
            success: true,
            user: {
                _id: user._id.toString(),
            username: user.username,
            email: user.email,
            isVerified: user.isVerified,
                role: user.role,
                lastLogin: user.lastLogin,
                lastActiveAt: user.lastActiveAt,
                createdAt: user.createdAt,
                // Password management information
                passwordCreatedAt: passwordCreatedAt,
                passwordExpiresAt: passwordExpiresAt,
                daysUntilExpiry: daysUntilExpiry,
                isPasswordExpired: isPasswordExpired,
                isPasswordExpiringSoon: isPasswordExpiringSoon,
                passwordChangeRequired: user.passwordChangeRequired || false,
                // Account security information
                failedLoginAttempts: user.failedLoginAttempts || 0,
                isLocked: user.isLocked || false,
                lockExpires: user.lockExpires,
                // Activity tracking
                activeSessions: user.getActiveSessions ? user.getActiveSessions() : []
            }
        });
    } catch (error) {
        console.error('[User Routes] Error in user info route:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching user info'
        });
    }
});

// Change password
router.post('/change-password', authMiddleware, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = await User.findById(req.user.userId);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Verify current password
        const isValidPassword = await bcrypt.compare(currentPassword, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Check if new password is same as current password
        const isSamePassword = await bcrypt.compare(newPassword, user.password);
        if (isSamePassword) {
            return res.status(400).json({ error: 'New password must be different from current password' });
        }

        // Check if password was used in last 5 passwords
        const isInHistory = await user.isPasswordInHistory(newPassword);
        if (isInHistory) {
            return res.status(400).json({ error: 'Password was used recently. Please choose a different password.' });
        }

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update password
        user.password = hashedPassword;
        await user.save();

        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// Delete account
router.delete('/delete-account', authMiddleware, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.user._id);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        res.json({
            success: true,
            message: 'Account deleted successfully'
        });
    } catch (error) {
        console.error('Error in delete account route:', error);
        res.status(500).json({
            success: false,
            message: 'Error deleting account'
        });
    }
});

// Get user activity logs with real-time session tracking
router.get('/logs', authMiddleware, async (req, res) => {
    try {
        console.log('[User Routes] Fetching real-time activity logs for user:', req.user._id);
        const user = await User.findById(req.user._id);

        if (!user) {
            console.log('[User Routes] User not found in database');
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const activities = [];
        const now = new Date();
        const currentSessionId = req.headers['x-session-id'] || `session_${now.getTime()}`;

        // 1. Add account creation (only once)
        activities.push({
            id: `account_creation`,
            type: 'account_creation',
            title: 'Account Created',
            description: 'User account was created and verified',
            timestamp: user.createdAt,
            status: 'SUCCESS',
            ipAddress: 'System',
            userAgent: 'System Registration',
            location: 'Registration System',
            details: 'Initial account setup completed'
        });

        // 2. Add current real-time session (only one)
        activities.push({
            id: `current_active_session`,
            type: 'current_session',
            title: 'Current Session',
            description: 'Active dashboard session',
            timestamp: user.lastActiveAt || now,
            status: 'ACTIVE', 
            ipAddress: req.ip || 'Unknown',
            userAgent: req.headers['user-agent'] || 'Unknown',
            location: 'Current Location',
            details: `Real-time session, started: ${(user.lastLogin || user.lastActiveAt || now).toLocaleTimeString()}`
        });

        // 4. Add password changes (consolidated)
        const latestPasswordChange = user.passwordCreatedAt || user.createdAt;
        activities.push({
            id: `password_current`,
            type: 'password_change',
            title: 'Password Set',
            description: 'Current password was set',
            timestamp: latestPasswordChange,
            status: 'SUCCESS',
            ipAddress: 'System',
            userAgent: 'Security System',
            location: 'System',
            details: `Expires: ${user.passwordExpiresAt ? user.passwordExpiresAt.toLocaleDateString() : 'Unknown'}`
        });

        // 5. Add security events (if any)
        if (user.failedLoginAttempts > 0 && user.lastFailedAttempt) {
            activities.push({
                id: `security_alert_failed_attempts`,
                type: 'security_alert',
                title: 'Security Alert',
                description: `${user.failedLoginAttempts} failed login attempt(s)`,
                timestamp: user.lastFailedAttempt,
                status: 'WARNING',
                ipAddress: req.ip || 'Unknown',
                userAgent: req.headers['user-agent'] || 'Unknown',
                location: 'Unknown',
                details: user.isLocked ? 'Account temporarily locked' : 'Security monitoring active'
            });
        }

        // 6. Add account verification (if verified)
        if (user.isVerified) {
            activities.push({
                id: `account_verified`,
                type: 'security_event',
                title: 'Account Verified',
                description: 'Email address verified successfully',
                timestamp: new Date(user.createdAt.getTime() + 60000), // 1 minute after creation
                status: 'SUCCESS',
                ipAddress: 'System',
                userAgent: 'Verification System',
                location: 'Email Verification',
                details: 'Email verification completed'
            });
        }

        // Sort activities by timestamp (most recent first)
        activities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        // Get only the most recent 8-10 meaningful activities
        const recentActivities = activities.slice(0, 10);

        // Generate enhanced statistics
        const stats = {
            totalActivities: activities.length,
            recentActivities: recentActivities.length,
            activeSessions: activities.filter(a => a.status === 'ACTIVE').length,
            securityEvents: activities.filter(a => a.type === 'security_alert').length,
            passwordChanges: activities.filter(a => a.type === 'password_change').length,
            lastActivity: recentActivities.length > 0 ? recentActivities[0].timestamp : user.createdAt,
            accountAge: Math.floor((now - user.createdAt) / (1000 * 60 * 60 * 24))
        };

        console.log('[User Routes] Returning clean activity logs:', {
            userId: user._id,
            totalActivities: stats.totalActivities,
            recentCount: stats.recentActivities,
            activeSessions: stats.activeSessions
        });

        res.json({
            success: true,
            activities: recentActivities,
            stats: stats,
            realTimeData: {
                currentTime: now,
                lastActiveAt: user.lastActiveAt,
                sessionDuration: user.lastActiveAt ? Math.floor((now - user.lastActiveAt) / 1000 / 60) : 0 // minutes
            },
            user: {
                username: user.username,
                email: user.email,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin,
                lastActiveAt: user.lastActiveAt,
                isLocked: user.isLocked || false,
                failedAttempts: user.failedLoginAttempts || 0,
                securityScore: calculateSecurityScore(user, activities),
                notificationCount: calculateNotificationCount(user, activities)
            }
        });
    } catch (error) {
        console.error('[User Routes] Error in activity logs route:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching activity logs'
        });
    }
});

        // Get device sessions (Google-like device management with proper deduplication)
router.get('/devices', authMiddleware, async (req, res) => {
    try {
        console.log('[User Routes] Fetching device sessions for user:', req.user._id);
        const user = await User.findById(req.user._id);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const now = new Date();
        const devices = [];
        
        // Enhanced real-world IP address detection with multiple fallback methods
        const geoip = require('geoip-lite');
        const fetch = require('node-fetch');
        
        let realIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                     req.headers['x-real-ip'] || 
                     req.headers['cf-connecting-ip'] ||
                     req.headers['x-client-ip'] ||
                     req.connection.remoteAddress || 
                     req.socket.remoteAddress ||
                     (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
                     req.ip;

        // Clean IP address (remove IPv6 prefix if present)
        if (realIP && realIP.startsWith('::ffff:')) {
            realIP = realIP.substring(7);
        }
        
        // REAL-WORLD IP DETECTION: Get actual public IP if currently on localhost
        if (!realIP || realIP === '::1' || realIP === '127.0.0.1' || realIP === 'localhost' || realIP.startsWith('192.168.') || realIP.startsWith('10.') || realIP.startsWith('172.')) {
            console.log('[User Routes] Local/Private IP detected, fetching real public IP...');
            
            // Try multiple external IP services for reliability
            const ipServices = [
                'https://api.ipify.org?format=json',
                'https://ipapi.co/json/',
                'https://ipinfo.io/json',
                'https://api.my-ip.io/ip.json'
            ];
            
            for (const service of ipServices) {
                try {
                    console.log('[User Routes] Trying IP service:', service);
                    const ipResponse = await fetch(service, { 
                        timeout: 5000,
                        headers: {
                            'User-Agent': 'SecureSystem-IPDetection/1.0'
                        }
                    });
                    
                    if (ipResponse.ok) {
                        const ipData = await ipResponse.json();
                        let detectedIP = null;
                        
                        // Handle different response formats
                        if (ipData.ip) detectedIP = ipData.ip;
                        else if (ipData.query) detectedIP = ipData.query;
                        else if (typeof ipData === 'string') detectedIP = ipData;
                        else if (ipData.address) detectedIP = ipData.address;
                        
                        if (detectedIP && detectedIP !== realIP) {
                            realIP = detectedIP.trim();
                            console.log('[User Routes] Real public IP detected:', realIP);
                            break;
                        }
                    }
                } catch (ipError) {
                    console.warn('[User Routes] IP service failed:', service, ipError.message);
                    continue;
                }
            }
        }

        console.log('[User Routes] Final detected IP:', realIP);
        
        // Enhanced real-world location detection with comprehensive fallback
        let location = 'Unknown Location';
        let locationDetails = null;
        
        // Always try to get location for any IP (including localhost for testing)
        try {
            console.log('[User Routes] Getting location for IP:', realIP);
            
            // Try geoip-lite first (works for public IPs)
            if (realIP !== '127.0.0.1' && realIP !== '::1' && !realIP.startsWith('192.168.') && !realIP.startsWith('10.')) {
                const geo = geoip.lookup(realIP);
                if (geo && geo.city) {
                    location = `${geo.city}, ${geo.region || geo.country}, ${geo.country}`;
                    locationDetails = geo;
                    console.log('[User Routes] GeoIP location found:', location);
                }
            }
            
            // If geoip-lite didn't work or for localhost, try external services
            if (location === 'Unknown Location' || realIP === '127.0.0.1') {
                const geoServices = [
                    `https://ipapi.co/${realIP}/json/`,
                    `https://ipinfo.io/${realIP}/json`,
                    `https://api.ipgeolocation.io/ipgeo?apiKey=free&ip=${realIP}`,
                    `https://freegeoip.app/json/${realIP}`
                ];
                
                for (const geoService of geoServices) {
                    try {
                        console.log('[User Routes] Trying geo service:', geoService);
                        const geoResponse = await fetch(geoService, { 
                            timeout: 5000,
                            headers: {
                                'User-Agent': 'SecureSystem-GeoLocation/1.0',
                                'Accept': 'application/json'
                            }
                        });
                        
                        if (geoResponse.ok) {
                            const geoData = await geoResponse.json();
                            
                            if (geoData && !geoData.error && !geoData.message) {
                                let city = geoData.city || geoData.locality || 'Unknown City';
                                let region = geoData.region || geoData.region_name || geoData.state || 'Unknown Region';
                                let country = geoData.country_name || geoData.country || 'Unknown Country';
                                
                                if (city !== 'Unknown City' || country !== 'Unknown Country') {
                                    location = `${city}, ${region}, ${country}`;
                                    locationDetails = {
                                        city: city,
                                        region: region,
                                        country: country,
                                        timezone: geoData.timezone || geoData.time_zone,
                                        isp: geoData.org || geoData.isp,
                                        latitude: geoData.latitude || geoData.lat,
                                        longitude: geoData.longitude || geoData.lon
                                    };
                                    console.log('[User Routes] External geo service location found:', location);
                                    break;
                                }
                            }
                        }
                    } catch (geoError) {
                        console.warn('[User Routes] Geo service failed:', geoService, geoError.message);
                        continue;
                    }
                }
            }
            
            // Final fallback for development/local testing
            if (location === 'Unknown Location' && (realIP === '127.0.0.1' || realIP === '::1')) {
                location = 'Local Development Environment';
                locationDetails = {
                    city: 'Local',
                    region: 'Development',
                    country: 'Local Machine',
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    isp: 'Local Network'
                };
                console.log('[User Routes] Using local development location');
            }
            
        } catch (locationError) {
            console.error('[User Routes] Location detection error:', locationError);
            location = 'Location Detection Failed';
        }
        
        console.log('[User Routes] Final location:', location);

        // Create current device (always show only ONE active desktop session)
        const currentDevice = {
            id: 'current_session',
            deviceName: `${extractDeviceName(req.headers['user-agent'])} Computer`,
            browser: extractBrowser(req.headers['user-agent']),
            os: extractOS(req.headers['user-agent']),
            deviceType: 'Desktop',
            ipAddress: realIP,
            location: location,
            firstSeen: user.lastLogin || user.createdAt,
            lastSeen: now,
            isActive: true,
            sessionId: 'current',
            userAgent: req.headers['user-agent'] || 'Current Browser',
            isCurrent: true
        };

        devices.push(currentDevice);

        // Create device map for proper deduplication based on browser+OS combination
        const deviceMap = new Map();

        // Add current device first to ensure it's not duplicated
        const currentFingerprint = `${currentDevice.browser}_${currentDevice.os}_Desktop`.toLowerCase();
        deviceMap.set(currentFingerprint, currentDevice);

        // Process login history for INACTIVE devices only (don't duplicate current session)
        if (user.loginHistory && user.loginHistory.length > 0) {
            user.loginHistory.forEach((login, index) => {
                if (!login.userAgent) return; // Skip invalid entries
                
                const deviceInfo = {
                    id: login.sessionId || `device_${index}`,
                    deviceName: `${extractDeviceName(login.userAgent)} Computer`,
                    browser: extractBrowser(login.userAgent),
                    os: extractOS(login.userAgent),
                    deviceType: extractDeviceType(login.userAgent),
                    ipAddress: login.ipAddress || 'Unknown',
                    location: login.location || getLocationFromIP(login.ipAddress) || 'Unknown Location',
                    firstSeen: login.timestamp || login.lastActiveAt || user.createdAt,
                    lastSeen: login.logoutAt || login.lastActiveAt || login.timestamp || user.createdAt,
                    isActive: false, // All historical sessions are inactive
                    sessionId: login.sessionId,
                    userAgent: login.userAgent,
                    isCurrent: false
                };

                // Create fingerprint for this device
                const deviceFingerprint = `${deviceInfo.browser}_${deviceInfo.os}_${deviceInfo.deviceType}`.toLowerCase();
                
                // Only add if it's different from current device and not already added
                if (deviceFingerprint !== currentFingerprint && !deviceMap.has(deviceFingerprint)) {
                    // Ensure it's truly a different device (different browser or OS)
                    const existing = deviceMap.get(deviceFingerprint);
                    if (!existing) {
                    deviceMap.set(deviceFingerprint, deviceInfo);
                    }
                }
            });
        }

        // Convert map to array and ensure current device is first
        const deviceList = Array.from(deviceMap.values()).sort((a, b) => {
            if (a.isCurrent) return -1;
            if (b.isCurrent) return 1;
            return new Date(b.lastSeen) - new Date(a.lastSeen);
        });

        const summary = {
            totalDevices: deviceList.length,
            activeDevices: deviceList.filter(d => d.isActive).length,
            inactiveDevices: deviceList.filter(d => !d.isActive).length,
            lastActivity: currentDevice.lastSeen
        };

        console.log('[User Routes] Device summary:', {
            totalDevices: summary.totalDevices,
            activeDevices: summary.activeDevices,
            currentDeviceIP: realIP,
            currentDeviceLocation: location
        });

        res.json({
            success: true,
            devices: deviceList,
            summary: summary,
            currentDevice: currentDevice,
            realTimeData: {
                currentIP: realIP,
                currentLocation: location,
                timestamp: now,
                sessionDuration: user.lastActiveAt ? Math.floor((now - user.lastActiveAt) / 1000 / 60) : 0
            }
        });

    } catch (error) {
        console.error('[User Routes] Error fetching devices:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching device information'
        });
    }
});

// Revoke device session
router.post('/devices/:deviceId/revoke', authMiddleware, async (req, res) => {
    try {
        const { deviceId } = req.params;
        const user = await User.findById(req.user._id);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Add revoked session to user's revoked tokens
        if (!user.revokedTokens) {
            user.revokedTokens = [];
        }

        user.revokedTokens.push({
            sessionId: deviceId,
            revokedAt: new Date(),
            reason: 'User revoked device access'
        });

        await user.save();

        res.json({
            success: true,
            message: 'Device access revoked successfully'
        });

    } catch (error) {
        console.error('[User Routes] Error revoking device:', error);
        res.status(500).json({
            success: false,
            message: 'Error revoking device access'
        });
    }
});

// End other sessions (terminate all active sessions except current)
router.post('/sessions/end-others', authMiddleware, async (req, res) => {
    try {
        console.log('[User Routes] Ending other sessions for user:', req.user._id);
        const user = await User.findById(req.user._id);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const currentSessionId = req.headers['x-session-id'] || 'current';
        
        // Add all current active sessions (except current) to revoked tokens
        if (!user.revokedTokens) {
            user.revokedTokens = [];
        }

        // Mark all login history as logged out except current session
        if (user.loginHistory && user.loginHistory.length > 0) {
            user.loginHistory.forEach(login => {
                if (login.sessionId !== currentSessionId && !login.logoutAt) {
                    login.logoutAt = new Date();
                    login.isActive = false;
                    
                    // Add to revoked tokens for JWT invalidation
                    user.revokedTokens.push({
                        sessionId: login.sessionId || 'unknown',
                        revokedAt: new Date(),
                        reason: 'User ended other sessions'
                    });
                }
            });
        }

        // Add a general revocation entry for any tokens not specifically tracked
        user.revokedTokens.push({
            sessionId: 'all_others',
            revokedAt: new Date(),
            reason: 'Bulk session termination - ended other sessions'
        });

        await user.save();

        console.log('[User Routes] Other sessions ended successfully for user:', req.user._id);

        res.json({
            success: true,
            message: 'All other sessions have been terminated successfully',
            revokedSessions: user.loginHistory ? user.loginHistory.filter(l => l.logoutAt && l.sessionId !== currentSessionId).length : 0
        });

    } catch (error) {
        console.error('[User Routes] Error ending other sessions:', error);
        res.status(500).json({
            success: false,
            message: 'Error ending other sessions'
        });
    }
});

// Get pending notifications
router.get('/notifications/pending', authMiddleware, async (req, res) => {
    try {
        console.log('[User Routes] Fetching pending notifications for user:', req.user._id);
        const user = await User.findById(req.user._id);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const notifications = [];
        const now = new Date();

        // Password expiry notifications
        const passwordCreatedAt = user.passwordCreatedAt || user.createdAt;
        const passwordExpiresAt = user.passwordExpiresAt || new Date(passwordCreatedAt.getTime() + 30 * 24 * 60 * 60 * 1000);
        const daysUntilExpiry = Math.ceil((passwordExpiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

        if (daysUntilExpiry <= 0) {
            notifications.push({
                id: 'password_expired',
                type: 'security_alert',
                title: '🔒 Password Expired',
                message: 'Your password has expired and must be changed immediately.',
                timestamp: new Date().toISOString(),
                read: false,
                severity: 'high',
                action: 'change_password'
            });
        } else if (daysUntilExpiry <= 7) {
            notifications.push({
                id: 'password_expiring',
                type: 'password_expiry',
                title: '⚠️ Password Expires Soon',
                message: `Your password will expire in ${daysUntilExpiry} day(s). Change it now to maintain account security.`,
                timestamp: new Date().toISOString(),
                read: false,
                severity: 'medium',
                action: 'change_password'
            });
        }

        // Failed login notifications
        if (user.failedLoginAttempts > 0) {
            notifications.push({
                id: 'failed_logins',
                type: 'security_alert',
                title: '🚨 Failed Login Attempts',
                message: `${user.failedLoginAttempts} failed login attempt(s) detected on your account.`,
                timestamp: user.lastFailedAttempt || new Date().toISOString(),
                read: false,
                severity: user.failedLoginAttempts > 3 ? 'high' : 'medium',
                action: 'review_security'
            });
        }

        // Account lock notifications
        if (user.isLocked) {
            notifications.push({
                id: 'account_locked',
                type: 'security_alert',
                title: '🔒 Account Temporarily Locked',
                message: 'Your account has been temporarily locked due to multiple failed login attempts.',
                timestamp: user.lockExpires ? user.lockExpires.toISOString() : new Date().toISOString(),
                read: false,
                severity: 'high',
                action: 'contact_support'
            });
        }

        // New device login notification (only show once per day)
        const recentLogins = user.loginHistory ? user.loginHistory.filter(login => 
            (now - new Date(login.timestamp || login.lastActiveAt)) < (24 * 60 * 60 * 1000)
        ) : [];

        // Check if we already showed a device notification today
        const deviceNotificationShownToday = user.lastDeviceNotification && 
            (now - new Date(user.lastDeviceNotification)) < (24 * 60 * 60 * 1000);

        if (recentLogins.length > 1 && !deviceNotificationShownToday) {
            const uniqueDevices = [...new Set(recentLogins.map(l => l.userAgent))];
            if (uniqueDevices.length > 1) {
                notifications.push({
                    id: 'new_device_login',
                    type: 'security_event',
                    title: '📱 New Device Login',
                    message: 'A login from a new device was detected in the last 24 hours.',
                    timestamp: recentLogins[0].timestamp || new Date().toISOString(),
                    read: false,
                    severity: 'low',
                    action: 'review_devices'
                });

                // Update user record to prevent repeated notifications
                user.lastDeviceNotification = now;
                await user.save();
            }
        }

        // Sort notifications by severity and timestamp
        notifications.sort((a, b) => {
            const severityOrder = { 'high': 3, 'medium': 2, 'low': 1 };
            const severityDiff = severityOrder[b.severity] - severityOrder[a.severity];
            if (severityDiff !== 0) return severityDiff;
            return new Date(b.timestamp) - new Date(a.timestamp);
        });

        res.json({
            success: true,
            notifications: notifications,
            count: notifications.length,
            unreadCount: notifications.filter(n => !n.read).length
        });

    } catch (error) {
        console.error('[User Routes] Error fetching notifications:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching notifications'
        });
    }
});

// Mark notification as read
router.post('/notifications/:notificationId/read', authMiddleware, async (req, res) => {
    try {
        const { notificationId } = req.params;
        console.log('[User Routes] Marking notification as read:', notificationId);
        
        // In a real implementation, you would update the notification in the database
        // For now, just acknowledge the request
        
        res.json({
            success: true,
            message: 'Notification marked as read'
        });
    } catch (error) {
        console.error('[User Routes] Error marking notification as read:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to mark notification as read'
        });
    }
});

// Removed duplicate - current-ip endpoint is defined earlier in the file

// Test route for debugging
router.get('/test', authMiddleware, async (req, res) => {
    try {
        console.log('[User Routes] Test route accessed by user:', req.user._id);
        res.json({
            success: true,
            message: 'Test route working',
            user: {
                id: req.user._id,
                timestamp: new Date()
            }
        });
    } catch (error) {
        console.error('[User Routes] Error in test route:', error);
        res.status(500).json({
            success: false,
            message: 'Test route error'
        });
    }
});

module.exports = router;