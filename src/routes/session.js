const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');
const crypto = require('crypto');

// In-memory stores (use Redis/Database in production)
const activeSessions = new Map();
const userSessions = new Map();
const suspiciousActivities = new Map();
const deviceFingerprints = new Map();
const securityAlerts = new Map();

// Security thresholds
const SECURITY_THRESHOLDS = {
    MAX_CONCURRENT_SESSIONS: 3,
    SUSPICIOUS_ACTIVITY_WINDOW: 5 * 60 * 1000,
    GEO_LOCATION_MAX_DISTANCE: 500
};

// Auth middleware
const authMiddleware = (req, res, next) => {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!token) {
            return res.status(401).json({ success: false, message: 'No token provided' });
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
};

// Register new session
router.post('/register', authMiddleware, async (req, res) => {
    try {
        const { deviceFingerprint, ipAddress, location, browserInfo } = req.body;
        const userId = req.user.userId;
        const sessionId = crypto.randomBytes(32).toString('hex');
        
        // Get location from IP
        const geoData = geoip.lookup(ipAddress);
        const detectedLocation = geoData ? {
            country: geoData.country,
            city: geoData.city,
            latitude: geoData.ll[0],
            longitude: geoData.ll[1]
        } : location;

        // Parse user agent
        const parser = new UAParser(req.headers['user-agent']);
        const deviceInfo = {
            browser: parser.getBrowser(),
            device: parser.getDevice(),
            os: parser.getOS()
        };

        const sessionData = {
            id: sessionId,
            userId,
            deviceFingerprint,
            ipAddress,
            location: detectedLocation,
            deviceInfo,
            browserInfo,
            createdAt: new Date(),
            lastActivity: new Date(),
            isActive: true
        };

        activeSessions.set(sessionId, sessionData);
        
        if (!userSessions.has(userId)) {
            userSessions.set(userId, new Set());
        }
        userSessions.get(userId).add(sessionId);

        // Security checks
        const alerts = await performSecurityChecks(userId, sessionData);
        await storeDeviceFingerprint(userId, deviceFingerprint);

        res.json({
            success: true,
            session: { id: sessionId, createdAt: sessionData.createdAt },
            securityAlerts: alerts
        });

    } catch (error) {
        console.error('[Session] Registration error:', error);
        res.status(500).json({ success: false, message: 'Session registration failed' });
    }
});

// Session heartbeat
router.post('/heartbeat', authMiddleware, async (req, res) => {
    try {
        const { sessionId } = req.body;
        const session = activeSessions.get(sessionId);
        
        if (session) {
            session.lastActivity = new Date();
            activeSessions.set(sessionId, session);
        }
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Heartbeat failed' });
    }
});

// Get active session count
router.get('/active-count', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.userId;
        const activeSessionCount = userSessions.get(userId)?.size || 0;
        
        res.json({ success: true, activeSessionCount });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Failed to get session count' });
    }
});

// Report suspicious activity
router.post('/report-activity', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.userId;
        const activity = { ...req.body, userId, timestamp: new Date() };
        
        if (!suspiciousActivities.has(userId)) {
            suspiciousActivities.set(userId, []);
        }
        suspiciousActivities.get(userId).push(activity);
        
        await analyzeSuspiciousActivity(userId, activity);
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Failed to report activity' });
    }
});

// Terminate all sessions
router.post('/terminate-all', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.userId;
        const sessionIds = Array.from(userSessions.get(userId) || []);
        
        sessionIds.forEach(sessionId => {
            activeSessions.delete(sessionId);
        });
        
        userSessions.delete(userId);
        
        res.json({ success: true, terminatedSessions: sessionIds.length });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Failed to terminate sessions' });
    }
});

// Get pending notifications
router.get('/notifications/pending', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.userId;
        const alerts = securityAlerts.get(userId) || [];
        const recent = alerts.filter(alert => 
            Date.now() - alert.timestamp < (24 * 60 * 60 * 1000)
        );
        
        res.json(recent);
    } catch (error) {
        res.status(500).json({ success: false, message: 'Failed to get notifications' });
    }
});

// Acknowledge device
router.post('/acknowledge-device', authMiddleware, async (req, res) => {
    try {
        const { sessionId } = req.body;
        const session = activeSessions.get(sessionId);
        
        if (session) {
            session.deviceAcknowledged = true;
            activeSessions.set(sessionId, session);
        }
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Failed to acknowledge device' });
    }
});

// === TEST ENDPOINT ===
router.get('/test', (req, res) => {
    res.json({
        success: true,
        message: 'Advanced Session Management API is operational',
        features: {
            deviceFingerprinting: true,
            suspiciousActivityDetection: true,
            crossDeviceNotifications: true,
            securityLockdown: true,
            realTimeMonitoring: true
        },
        stats: {
            activeSessions: activeSessions.size,
            totalUsers: userSessions.size,
            suspiciousActivitiesReported: Array.from(suspiciousActivities.values()).reduce((total, activities) => total + activities.length, 0),
            securityAlertsGenerated: Array.from(securityAlerts.values()).reduce((total, alerts) => total + alerts.length, 0)
        },
        timestamp: new Date().toISOString()
    });
});

// === UTILITY FUNCTIONS ===
async function performSecurityChecks(userId, sessionData) {
    const alerts = [];
    
    // Check concurrent sessions
    const sessionCount = userSessions.get(userId)?.size || 0;
    if (sessionCount > SECURITY_THRESHOLDS.MAX_CONCURRENT_SESSIONS) {
        alerts.push({
            type: 'EXCESSIVE_CONCURRENT_SESSIONS',
            severity: 'HIGH',
            data: { count: sessionCount }
        });
    }
    
    // Check for new device
    const knownDevices = deviceFingerprints.get(userId) || [];
    const isKnownDevice = knownDevices.some(device => 
        device.hash === sessionData.deviceFingerprint.hash
    );
    
    if (!isKnownDevice) {
        alerts.push({
            type: 'NEW_DEVICE_LOGIN',
            severity: 'MEDIUM',
            data: {
                deviceInfo: sessionData.deviceInfo,
                location: sessionData.location
            }
        });
        
        // Store alert for notifications
        if (!securityAlerts.has(userId)) {
            securityAlerts.set(userId, []);
        }
        securityAlerts.get(userId).push({
            type: 'NEW_DEVICE_LOGIN',
            timestamp: Date.now(),
            data: {
                deviceType: getDeviceType(sessionData.deviceInfo),
                location: getLocationString(sessionData.location),
                sessionId: sessionData.id
            }
        });
    }
    
    return alerts;
}

async function storeDeviceFingerprint(userId, fingerprint) {
    if (!deviceFingerprints.has(userId)) {
        deviceFingerprints.set(userId, []);
    }
    
    const devices = deviceFingerprints.get(userId);
    const existing = devices.find(device => device.hash === fingerprint.hash);
    
    if (!existing) {
        devices.push({
            ...fingerprint,
            firstSeen: new Date(),
            lastSeen: new Date()
        });
    } else {
        existing.lastSeen = new Date();
    }
}

async function analyzeSuspiciousActivity(userId, activity) {
    const activities = suspiciousActivities.get(userId) || [];
    const recent = activities.filter(
        a => Date.now() - a.timestamp < SECURITY_THRESHOLDS.SUSPICIOUS_ACTIVITY_WINDOW
    );
    
    const criticalTypes = [
        'device_fingerprint_change',
        'unusual_location_change',
        'excessive_concurrent_sessions'
    ];
    
    if (criticalTypes.includes(activity.type) || recent.length >= 5) {
        await triggerSecurityLockdown(userId, activity);
    }
}

async function triggerSecurityLockdown(userId, activity) {
    console.log(`[Security] LOCKDOWN for user ${userId}`);
    
    // Store lockdown alert
    if (!securityAlerts.has(userId)) {
        securityAlerts.set(userId, []);
    }
    
    securityAlerts.get(userId).push({
        type: 'SECURITY_LOCKDOWN',
        timestamp: Date.now(),
        data: {
            reason: 'Multiple suspicious activities detected',
            triggerActivity: activity.type
        }
    });
}

function getDeviceType(deviceInfo) {
    if (deviceInfo.device?.type) return deviceInfo.device.type;
    if (deviceInfo.os?.name?.includes('Android')) return 'Android device';
    if (deviceInfo.os?.name?.includes('iOS')) return 'iOS device';
    return 'Computer';
}

function getLocationString(location) {
    if (!location) return 'Unknown location';
    return [location.city, location.country].filter(Boolean).join(', ');
}

// Cleanup expired sessions
setInterval(() => {
    const now = Date.now();
    for (const [sessionId, session] of activeSessions.entries()) {
        if (now - session.lastActivity.getTime() > 30 * 60 * 1000) { // 30 minutes
            activeSessions.delete(sessionId);
            const userId = session.userId;
            if (userSessions.has(userId)) {
                userSessions.get(userId).delete(sessionId);
            }
        }
    }
}, 5 * 60 * 1000); // Every 5 minutes

module.exports = router; 