const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

// In-memory stores (in production, use Redis or database)
const activeSessions = new Map(); // sessionId -> sessionData
const userSessions = new Map(); // userId -> Set of sessionIds
const suspiciousActivities = new Map(); // userId -> Array of activities
const deviceFingerprints = new Map(); // userId -> Array of known devices
const securityAlerts = new Map(); // userId -> Array of alerts
const sessionHeartbeats = new Map(); // sessionId -> lastHeartbeat

// Security thresholds
const SECURITY_THRESHOLDS = {
    MAX_CONCURRENT_SESSIONS: 3,
    MAX_LOCATION_CHANGES: 2,
    MAX_FAILED_ATTEMPTS: 3,
    SUSPICIOUS_ACTIVITY_WINDOW: 5 * 60 * 1000, // 5 minutes
    GEO_LOCATION_MAX_DISTANCE: 500, // km
    DEVICE_CHANGE_THRESHOLD: 24 * 60 * 60 * 1000, // 24 hours
    SESSION_TIMEOUT: 30 * 60 * 1000, // 30 minutes
    HEARTBEAT_TIMEOUT: 5 * 60 * 1000 // 5 minutes
};

// === MIDDLEWARE ===
const authMiddleware = async (req, res, next) => {
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

// === SESSION REGISTRATION ===
router.post('/register', authMiddleware, async (req, res) => {
    try {
        const { deviceFingerprint, ipAddress, location, browserInfo, sessionType } = req.body;
        const userId = req.user.userId;

        // Generate session ID
        const sessionId = crypto.randomBytes(32).toString('hex');
        
        // Get geolocation from IP
        const geoData = geoip.lookup(ipAddress);
        const detectedLocation = geoData ? {
            country: geoData.country,
            region: geoData.region,
            city: geoData.city,
            latitude: geoData.ll[0],
            longitude: geoData.ll[1]
        } : location;

        // Parse user agent
        const parser = new UAParser(req.headers['user-agent']);
        const deviceInfo = {
            browser: parser.getBrowser(),
            device: parser.getDevice(),
            os: parser.getOS(),
            userAgent: req.headers['user-agent']
        };

        // Create session data
        const sessionData = {
            id: sessionId,
            userId,
            deviceFingerprint,
            ipAddress,
            location: detectedLocation,
            deviceInfo,
            browserInfo,
            sessionType,
            createdAt: new Date(),
            lastActivity: new Date(),
            isActive: true
        };

        // Store session
        activeSessions.set(sessionId, sessionData);
        
        // Add to user sessions
        if (!userSessions.has(userId)) {
            userSessions.set(userId, new Set());
        }
        userSessions.get(userId).add(sessionId);

        // Security checks
        const securityAlerts = await performSecurityChecks(userId, sessionData);

        // Store known device fingerprint
        await storeDeviceFingerprint(userId, deviceFingerprint);

        console.log(`[Session] Registered session ${sessionId} for user ${userId}`);

        res.json({
            success: true,
            session: {
                id: sessionId,
                createdAt: sessionData.createdAt
            },
            securityAlerts
        });

    } catch (error) {
        console.error('[Session] Registration error:', error);
        res.status(500).json({ success: false, message: 'Session registration failed' });
    }
});

// === SECURITY CHECKS ===
async function performSecurityChecks(userId, sessionData) {
    const alerts = [];

    // Check concurrent sessions
    const userSessionCount = userSessions.get(userId)?.size || 0;
    if (userSessionCount > SECURITY_THRESHOLDS.MAX_CONCURRENT_SESSIONS) {
        alerts.push({
            type: 'EXCESSIVE_CONCURRENT_SESSIONS',
            severity: 'HIGH',
            data: { count: userSessionCount, threshold: SECURITY_THRESHOLDS.MAX_CONCURRENT_SESSIONS }
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
                location: sessionData.location,
                ipAddress: sessionData.ipAddress
            }
        });

        // Broadcast to all user's devices
        await broadcastToUserDevices(userId, {
            type: 'NEW_DEVICE_LOGIN',
            data: {
                deviceType: getDeviceType(sessionData.deviceInfo),
                location: getLocationString(sessionData.location),
                timestamp: new Date(),
                sessionId: sessionData.id
            }
        });
    }

    // Check for unusual location
    if (knownDevices.length > 0 && sessionData.location) {
        const lastKnownLocation = getLastKnownLocation(userId);
        if (lastKnownLocation) {
            const distance = calculateDistance(lastKnownLocation, sessionData.location);
            if (distance > SECURITY_THRESHOLDS.GEO_LOCATION_MAX_DISTANCE) {
                alerts.push({
                    type: 'UNUSUAL_LOCATION',
                    severity: 'HIGH',
                    data: {
                        distance,
                        oldLocation: lastKnownLocation,
                        newLocation: sessionData.location
                    }
                });
            }
        }
    }

    // Store alerts
    if (alerts.length > 0) {
        if (!securityAlerts.has(userId)) {
            securityAlerts.set(userId, []);
        }
        securityAlerts.get(userId).push(...alerts.map(alert => ({
            ...alert,
            timestamp: new Date(),
            sessionId: sessionData.id
        })));
    }

    return alerts;
}

// === SESSION HEARTBEAT ===
router.post('/heartbeat', authMiddleware, async (req, res) => {
    try {
        const { sessionId, activityCount } = req.body;
        const userId = req.user.userId;

        if (!activeSessions.has(sessionId)) {
            return res.status(404).json({ success: false, message: 'Session not found' });
        }

        // Update heartbeat
        sessionHeartbeats.set(sessionId, {
            timestamp: new Date(),
            activityCount,
            userId
        });

        // Update session last activity
        const sessionData = activeSessions.get(sessionId);
        sessionData.lastActivity = new Date();
        activeSessions.set(sessionId, sessionData);

        res.json({ success: true });

    } catch (error) {
        console.error('[Session] Heartbeat error:', error);
        res.status(500).json({ success: false, message: 'Heartbeat failed' });
    }
});

// === ACTIVE SESSION COUNT ===
router.get('/active-count', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.userId;
        const activeSessionCount = userSessions.get(userId)?.size || 0;

        res.json({
            success: true,
            activeSessionCount,
            sessions: Array.from(userSessions.get(userId) || []).map(sessionId => {
                const session = activeSessions.get(sessionId);
                return session ? {
                    id: session.id,
                    deviceInfo: session.deviceInfo,
                    location: session.location,
                    createdAt: session.createdAt,
                    lastActivity: session.lastActivity
                } : null;
            }).filter(Boolean)
        });

    } catch (error) {
        console.error('[Session] Active count error:', error);
        res.status(500).json({ success: false, message: 'Failed to get active sessions' });
    }
});

// === SUSPICIOUS ACTIVITY REPORTING ===
router.post('/report-activity', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.userId;
        const activity = {
            ...req.body,
            userId,
            timestamp: new Date(),
            ipAddress: req.ip
        };

        // Store suspicious activity
        if (!suspiciousActivities.has(userId)) {
            suspiciousActivities.set(userId, []);
        }
        suspiciousActivities.get(userId).push(activity);

        // Analyze activity patterns
        await analyzeSuspiciousActivity(userId, activity);

        console.log(`[Security] Suspicious activity reported for user ${userId}:`, activity.type);

        res.json({ success: true });

    } catch (error) {
        console.error('[Security] Report activity error:', error);
        res.status(500).json({ success: false, message: 'Failed to report activity' });
    }
});

// === SECURITY ALERT BROADCASTING ===
router.post('/broadcast-alert', authMiddleware, async (req, res) => {
    try {
        const { type, data } = req.body;
        const userId = req.user.userId;

        await broadcastToUserDevices(userId, { type, data });

        res.json({ success: true });

    } catch (error) {
        console.error('[Security] Broadcast alert error:', error);
        res.status(500).json({ success: false, message: 'Failed to broadcast alert' });
    }
});

// === SESSION TERMINATION ===
router.post('/terminate-all', authMiddleware, async (req, res) => {
    try {
        const { reason } = req.body;
        const userId = req.user.userId;

        // Get all user sessions
        const sessionIds = Array.from(userSessions.get(userId) || []);

        // Terminate all sessions
        sessionIds.forEach(sessionId => {
            activeSessions.delete(sessionId);
            sessionHeartbeats.delete(sessionId);
        });

        // Clear user sessions
        userSessions.delete(userId);

        // Broadcast termination to all devices
        await broadcastToUserDevices(userId, {
            type: 'SESSION_TERMINATED',
            data: { reason, timestamp: new Date() }
        });

        console.log(`[Security] Terminated all sessions for user ${userId}, reason: ${reason}`);

        res.json({ success: true, terminatedSessions: sessionIds.length });

    } catch (error) {
        console.error('[Session] Terminate all error:', error);
        res.status(500).json({ success: false, message: 'Failed to terminate sessions' });
    }
});

// === DEVICE ACKNOWLEDGMENT ===
router.post('/acknowledge-device', authMiddleware, async (req, res) => {
    try {
        const { sessionId } = req.body;
        const userId = req.user.userId;

        const sessionData = activeSessions.get(sessionId);
        if (!sessionData || sessionData.userId !== userId) {
            return res.status(404).json({ success: false, message: 'Session not found' });
        }

        // Mark device as acknowledged
        sessionData.deviceAcknowledged = true;
        activeSessions.set(sessionId, sessionData);

        // Store as trusted device
        await storeDeviceFingerprint(userId, sessionData.deviceFingerprint, true);

        res.json({ success: true });

    } catch (error) {
        console.error('[Security] Acknowledge device error:', error);
        res.status(500).json({ success: false, message: 'Failed to acknowledge device' });
    }
});

// === NOTIFICATIONS ===
router.get('/notifications/pending', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.userId;
        
        // Get pending notifications (in production, use database)
        const userAlerts = securityAlerts.get(userId) || [];
        const recentAlerts = userAlerts.filter(alert => 
            Date.now() - alert.timestamp < (24 * 60 * 60 * 1000) // Last 24 hours
        );

        res.json(recentAlerts);

    } catch (error) {
        console.error('[Notifications] Pending error:', error);
        res.status(500).json({ success: false, message: 'Failed to get notifications' });
    }
});

// === UTILITY FUNCTIONS ===
async function storeDeviceFingerprint(userId, fingerprint, trusted = false) {
    if (!deviceFingerprints.has(userId)) {
        deviceFingerprints.set(userId, []);
    }
    
    const devices = deviceFingerprints.get(userId);
    const existingDevice = devices.find(device => device.hash === fingerprint.hash);
    
    if (!existingDevice) {
        devices.push({
            ...fingerprint,
            trusted,
            firstSeen: new Date(),
            lastSeen: new Date()
        });
    } else {
        existingDevice.lastSeen = new Date();
        if (trusted) existingDevice.trusted = true;
    }
    
    deviceFingerprints.set(userId, devices);
}

async function analyzeSuspiciousActivity(userId, activity) {
    const userActivities = suspiciousActivities.get(userId) || [];
    const recentActivities = userActivities.filter(
        a => Date.now() - a.timestamp < SECURITY_THRESHOLDS.SUSPICIOUS_ACTIVITY_WINDOW
    );

    // Check for patterns that require immediate action
    const criticalActivities = [
        'device_fingerprint_change',
        'unusual_location_change',
        'excessive_concurrent_sessions',
        'rapid_suspicious_actions'
    ];

    if (criticalActivities.includes(activity.type) || recentActivities.length >= 5) {
        // Trigger security lockdown
        await triggerSecurityLockdown(userId, activity);
    }
}

async function triggerSecurityLockdown(userId, triggerActivity) {
    console.log(`[Security] LOCKDOWN TRIGGERED for user ${userId}`);
    
    // Broadcast immediate security alert
    await broadcastToUserDevices(userId, {
        type: 'SECURITY_LOCKDOWN',
        data: {
            reason: 'Multiple suspicious activities detected',
            triggerActivity: triggerActivity.type,
            timestamp: new Date()
        }
    });
    
    // Schedule session termination (give user time to see warning)
    setTimeout(async () => {
        const sessionIds = Array.from(userSessions.get(userId) || []);
        sessionIds.forEach(sessionId => {
            activeSessions.delete(sessionId);
            sessionHeartbeats.delete(sessionId);
        });
        userSessions.delete(userId);
        
        console.log(`[Security] All sessions terminated for user ${userId} due to security lockdown`);
    }, 30000); // 30 second delay
}

async function broadcastToUserDevices(userId, message) {
    try {
        // In production, this would use WebSocket connections or push notifications
        // For now, store in alerts for polling
        
        if (!securityAlerts.has(userId)) {
            securityAlerts.set(userId, []);
        }
        
        securityAlerts.get(userId).push({
            ...message,
            timestamp: new Date(),
            broadcast: true
        });
        
        console.log(`[Notifications] Broadcast to user ${userId}:`, message.type);
        
    } catch (error) {
        console.error('[Notifications] Broadcast error:', error);
    }
}

function getDeviceType(deviceInfo) {
    if (deviceInfo.device?.type) return deviceInfo.device.type;
    if (deviceInfo.device?.model) return deviceInfo.device.model;
    if (deviceInfo.os?.name?.toLowerCase().includes('android')) return 'Android device';
    if (deviceInfo.os?.name?.toLowerCase().includes('ios')) return 'iOS device';
    if (deviceInfo.os?.name?.toLowerCase().includes('windows')) return 'Windows computer';
    if (deviceInfo.os?.name?.toLowerCase().includes('mac')) return 'Mac computer';
    return 'Unknown device';
}

function getLocationString(location) {
    if (!location) return 'Unknown location';
    
    const parts = [];
    if (location.city) parts.push(location.city);
    if (location.region) parts.push(location.region);
    if (location.country) parts.push(location.country);
    
    return parts.join(', ') || 'Unknown location';
}

function getLastKnownLocation(userId) {
    const userSessionIds = userSessions.get(userId) || new Set();
    const sessions = Array.from(userSessionIds)
        .map(id => activeSessions.get(id))
        .filter(session => session && session.location)
        .sort((a, b) => b.lastActivity - a.lastActivity);
    
    return sessions.length > 0 ? sessions[0].location : null;
}

function calculateDistance(loc1, loc2) {
    const R = 6371; // Earth's radius in km
    const dLat = (loc2.latitude - loc1.latitude) * Math.PI / 180;
    const dLon = (loc2.longitude - loc1.longitude) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
            Math.cos(loc1.latitude * Math.PI / 180) * Math.cos(loc2.latitude * Math.PI / 180) *
            Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
}

// === CLEANUP ROUTINES ===
// Clean up expired sessions and old data
setInterval(() => {
    const now = Date.now();
    
    // Clean up expired sessions
    for (const [sessionId, sessionData] of activeSessions.entries()) {
        const lastActivity = sessionData.lastActivity.getTime();
        if (now - lastActivity > SECURITY_THRESHOLDS.SESSION_TIMEOUT) {
            console.log(`[Cleanup] Removing expired session ${sessionId}`);
            activeSessions.delete(sessionId);
            sessionHeartbeats.delete(sessionId);
            
            // Remove from user sessions
            const userId = sessionData.userId;
            if (userSessions.has(userId)) {
                userSessions.get(userId).delete(sessionId);
                if (userSessions.get(userId).size === 0) {
                    userSessions.delete(userId);
                }
            }
        }
    }
    
    // Clean up old suspicious activities (keep last 7 days)
    const weekAgo = now - (7 * 24 * 60 * 60 * 1000);
    for (const [userId, activities] of suspiciousActivities.entries()) {
        const recentActivities = activities.filter(activity => 
            activity.timestamp.getTime() > weekAgo
        );
        if (recentActivities.length !== activities.length) {
            suspiciousActivities.set(userId, recentActivities);
        }
    }
    
    // Clean up old security alerts (keep last 30 days)
    const monthAgo = now - (30 * 24 * 60 * 60 * 1000);
    for (const [userId, alerts] of securityAlerts.entries()) {
        const recentAlerts = alerts.filter(alert => 
            alert.timestamp.getTime() > monthAgo
        );
        if (recentAlerts.length !== alerts.length) {
            securityAlerts.set(userId, recentAlerts);
        }
    }
    
}, 5 * 60 * 1000); // Every 5 minutes

module.exports = router; 