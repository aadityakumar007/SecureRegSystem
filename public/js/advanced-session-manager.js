/**
 * Advanced Multi-Device Session Management System
 * Features: Real-time device monitoring, suspicious activity detection, 
 * automatic security lockdown, cross-device notifications
 */

class AdvancedSessionManager {
    constructor() {
        this.currentSession = null;
        this.deviceFingerprint = null;
        this.activityBuffer = [];
        this.suspiciousActivities = [];
        this.securityThresholds = {
            maxConcurrentSessions: 3,
            maxLocationChanges: 2,
            maxFailedAttempts: 3,
            unusualActivityWindow: 300000, // 5 minutes
            geoLocationMaxDistance: 500, // km
            deviceChangeThreshold: 24 * 60 * 60 * 1000 // 24 hours
        };
        
        this.eventHandlers = new Map();
        this.notificationQueue = [];
        this.isSecurityLockdown = false;
        
        this.init();
    }

    async init() {
        console.log('[Advanced Session Manager] Initializing...');
        
        // Generate device fingerprint
        this.deviceFingerprint = await this.generateDeviceFingerprint();
        
        // Start monitoring
        this.startRealTimeMonitoring();
        this.startSuspiciousActivityDetection();
        this.startCrossDeviceNotifications();
        
        // Register session
        await this.registerSession();
        
        console.log('[Advanced Session Manager] Initialized successfully');
    }

    // === DEVICE FINGERPRINTING ===
    async generateDeviceFingerprint() {
        const fingerprint = {
            userAgent: navigator.userAgent,
            screen: `${screen.width}x${screen.height}x${screen.colorDepth}`,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            language: navigator.language,
            platform: navigator.platform,
            cookieEnabled: navigator.cookieEnabled,
            hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
            deviceMemory: navigator.deviceMemory || 'unknown',
            maxTouchPoints: navigator.maxTouchPoints || 0
            // Removed timestamp to ensure fingerprint is stable across sessions
        };

        // Add canvas fingerprint
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('Device fingerprint test 🔒', 2, 2);
            fingerprint.canvas = canvas.toDataURL().slice(-50);
        } catch (e) {
            fingerprint.canvas = 'unavailable';
        }

        // Add WebGL fingerprint
        try {
            const gl = document.createElement('canvas').getContext('webgl');
            fingerprint.webgl = {
                vendor: gl.getParameter(gl.VENDOR),
                renderer: gl.getParameter(gl.RENDERER)
            };
        } catch (e) {
            fingerprint.webgl = 'unavailable';
        }

        // Generate hash
        const fingerprintString = JSON.stringify(fingerprint);
        fingerprint.hash = await this.hashString(fingerprintString);
        
        return fingerprint;
    }

    async hashString(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // === SESSION REGISTRATION ===
    async registerSession() {
        try {
            // Get IP and location information
            const ipAddress = await this.getPublicIP();
            const location = await this.getGeolocation();
            
            const sessionData = {
                deviceFingerprint: this.deviceFingerprint,
                ipAddress: ipAddress,
                location: location,
                timestamp: Date.now(),
                browserInfo: this.getBrowserInfo(),
                sessionType: 'web'
            };

            // Store session info for dashboard use
            this.currentSession = {
                id: 'pending',
                ipAddress: ipAddress,
                location: location,
                timestamp: Date.now(),
                userAgent: navigator.userAgent
            };
            
            localStorage.setItem('currentSessionData', JSON.stringify(this.currentSession));

            const response = await this.makeSecureRequest('/api/session/register', {
                method: 'POST',
                body: JSON.stringify(sessionData)
            });

            if (response.ok) {
                const result = await response.json();
                if (result.session) {
                    this.currentSession.id = result.session.id;
                    localStorage.setItem('currentSessionData', JSON.stringify(this.currentSession));
                }
                
                // Check for suspicious activity flags
                if (result.securityAlerts && result.securityAlerts.length > 0) {
                    await this.handleSecurityAlerts(result.securityAlerts);
                }
                
                console.log('[Session] Registered successfully:', this.currentSession.id);
            }
        } catch (error) {
            console.error('[Session] Registration failed:', error);
        }
    }

    // === REAL-TIME MONITORING ===
    startRealTimeMonitoring() {
        // Monitor user behavior patterns
        this.monitorMousePatterns();
        this.monitorKeyboardPatterns();
        this.monitorNetworkChanges();
        this.monitorDeviceChanges();
        this.monitorLocationChanges();
        
        // Periodic session heartbeat
        setInterval(() => this.sendSessionHeartbeat(), 30000); // Every 30 seconds
        
        // Activity pattern analysis
        setInterval(() => this.analyzeActivityPatterns(this.activityBuffer || []), 60000); // Every minute
    }

    monitorMousePatterns() {
        let mouseData = { movements: 0, clicks: 0, lastActivity: Date.now() };
        
        document.addEventListener('mousemove', (e) => {
            mouseData.movements++;
            mouseData.lastActivity = Date.now();
            
            // Detect bot-like behavior (perfectly straight lines, unrealistic speed)
            const speed = Math.sqrt(Math.pow(e.movementX, 2) + Math.pow(e.movementY, 2));
            if (speed > 1000) { // Unrealistic mouse speed
                this.flagSuspiciousActivity('unrealistic_mouse_speed', { speed });
            }
        });

        document.addEventListener('click', (e) => {
            mouseData.clicks++;
            
            // Detect rapid clicking (potential bot)
            const now = Date.now();
            if (!this.lastClickTime) this.lastClickTime = now;
            const timeBetweenClicks = now - this.lastClickTime;
            
            if (timeBetweenClicks < 100) { // Less than 100ms between clicks (more reasonable threshold)
                console.log('[Click Detection] Fast clicking detected:', timeBetweenClicks + 'ms');
                
                // Only flag if extremely rapid (likely automated)
                if (timeBetweenClicks < 50) {
                    this.flagSuspiciousActivity('rapid_clicking', { interval: timeBetweenClicks });
                }
            }
            
            this.lastClickTime = now;
        });
        
        // Analyze mouse patterns every minute
        setInterval(() => {
            this.activityBuffer.push({
                type: 'mouse_activity',
                data: { ...mouseData },
                timestamp: Date.now()
            });
            mouseData = { movements: 0, clicks: 0, lastActivity: Date.now() };
        }, 60000);
    }

    monitorKeyboardPatterns() {
        let keyData = { keystrokes: 0, typingSpeed: [], lastKeyTime: Date.now() };
        
        document.addEventListener('keydown', (e) => {
            const now = Date.now();
            const timeBetweenKeys = now - keyData.lastKeyTime;
            
            keyData.keystrokes++;
            keyData.typingSpeed.push(timeBetweenKeys);
            
            // Detect inhuman typing patterns
            if (timeBetweenKeys < 20) { // Less than 20ms between keystrokes (more reasonable threshold)
                console.log('[Typing Detection] Fast typing detected:', timeBetweenKeys + 'ms');
                
                // Only flag if extremely fast (likely automated)
                if (timeBetweenKeys < 5) {
                    this.flagSuspiciousActivity('inhuman_typing', { interval: timeBetweenKeys });
                }
            }
            
            // Detect copy-paste of large text blocks
            if (e.ctrlKey && e.key === 'v') {
                setTimeout(() => {
                    const activeElement = document.activeElement;
                    if (activeElement && activeElement.value && activeElement.value.length > 100) {
                        this.flagSuspiciousActivity('large_paste_operation', { 
                            length: activeElement.value.length 
                        });
                    }
                }, 10);
            }
            
            keyData.lastKeyTime = now;
        });
    }

    monitorNetworkChanges() {
        // Monitor connection changes
        window.addEventListener('online', () => {
            this.flagSuspiciousActivity('network_reconnection', { timestamp: Date.now() });
        });

        window.addEventListener('offline', () => {
            this.flagSuspiciousActivity('network_disconnection', { timestamp: Date.now() });
        });

        // Monitor IP changes (if available)
        setInterval(async () => {
            try {
                const currentIP = await this.getPublicIP();
                if (this.lastKnownIP && this.lastKnownIP !== currentIP) {
                    this.flagSuspiciousActivity('ip_address_change', { 
                        oldIP: this.lastKnownIP,
                        newIP: currentIP
                    });
                }
                this.lastKnownIP = currentIP;
            } catch (error) {
                console.warn('[Monitoring] Could not check IP address:', error);
            }
        }, 300000); // Every 5 minutes
    }

    monitorDeviceChanges() {
        setInterval(() => {
            const currentFingerprint = this.generateDeviceFingerprint();
            
            if (this.deviceFingerprint && 
                JSON.stringify(currentFingerprint) !== JSON.stringify(this.deviceFingerprint)) {
                this.flagSuspiciousActivity('device_fingerprint_change', {
                    changes: this.compareFingerprints(this.deviceFingerprint, currentFingerprint)
                });
            }
        }, 600000); // Every 10 minutes
    }

    async monitorLocationChanges() {
        if ('geolocation' in navigator) {
            setInterval(async () => {
                try {
                    const currentLocation = await this.getGeolocation();
                    if (this.lastKnownLocation) {
                        const distance = this.calculateDistance(
                            this.lastKnownLocation,
                            currentLocation
                        );
                        
                        if (distance > this.securityThresholds.geoLocationMaxDistance) {
                            this.flagSuspiciousActivity('unusual_location_change', {
                                distance,
                                oldLocation: this.lastKnownLocation,
                                newLocation: currentLocation
                            });
                        }
                    }
                    this.lastKnownLocation = currentLocation;
                } catch (error) {
                    // Geolocation not available or denied
                }
            }, 900000); // Every 15 minutes
        }
    }

    // === SUSPICIOUS ACTIVITY DETECTION ===
    startSuspiciousActivityDetection() {
        // Analyze patterns for suspicious behavior
        setInterval(() => {
            this.detectAnomalousPatterns();
            this.detectConcurrentSessions();
            this.detectRapidActions();
            this.cleanupOldActivities();
        }, 120000); // Every 2 minutes
    }

    flagSuspiciousActivity(type, data) {
        const activity = {
            type,
            data,
            timestamp: Date.now(),
            sessionId: this.currentSession?.id,
            deviceHash: this.deviceFingerprint?.hash
        };
        
        this.suspiciousActivities.push(activity);
        console.warn('[Security] Suspicious activity detected:', activity);
        
        // Send to backend immediately for critical activities
        const criticalActivities = [
            'unrealistic_mouse_speed',
            'inhuman_typing',
            'device_fingerprint_change',
            'unusual_location_change'
        ];
        
        if (criticalActivities.includes(type)) {
            this.reportSuspiciousActivity(activity);
        }
        
        // Check if security lockdown is needed
        this.evaluateSecurityLockdown();
    }

    detectAnomalousPatterns() {
        // Detect patterns that deviate from normal user behavior
        const recentActivities = this.activityBuffer.filter(
            activity => Date.now() - activity.timestamp < this.securityThresholds.unusualActivityWindow
        );
        
        // Check for repetitive actions (potential bot behavior)
        const actionCounts = {};
        recentActivities.forEach(activity => {
            const key = `${activity.type}_${JSON.stringify(activity.data)}`;
            actionCounts[key] = (actionCounts[key] || 0) + 1;
        });
        
        Object.entries(actionCounts).forEach(([action, count]) => {
            if (count > 10) { // Same action repeated more than 10 times
                this.flagSuspiciousActivity('repetitive_behavior', { action, count });
            }
        });
    }

    async detectConcurrentSessions() {
        try {
            const response = await this.makeSecureRequest('/api/session/active-count');
            if (response.ok) {
                const { activeSessionCount } = await response.json();
                
                if (activeSessionCount > this.securityThresholds.maxConcurrentSessions) {
                    this.flagSuspiciousActivity('excessive_concurrent_sessions', {
                        count: activeSessionCount,
                        threshold: this.securityThresholds.maxConcurrentSessions
                    });
                }
            }
        } catch (error) {
            console.error('[Security] Failed to check concurrent sessions:', error);
        }
    }

    detectRapidActions() {
        const recentSuspiciousActivities = this.suspiciousActivities.filter(
            activity => Date.now() - activity.timestamp < 60000 // Last minute
        );
        
        if (recentSuspiciousActivities.length > 5) {
            this.flagSuspiciousActivity('rapid_suspicious_actions', {
                count: recentSuspiciousActivities.length,
                activities: recentSuspiciousActivities.map(a => a.type)
            });
        }
    }

    // === SECURITY LOCKDOWN ===
    evaluateSecurityLockdown() {
        const criticalActivities = this.suspiciousActivities.filter(
            activity => Date.now() - activity.timestamp < 300000 // Last 5 minutes
        );
        
        const criticalCount = criticalActivities.length;
        const hasCriticalTypes = criticalActivities.some(activity =>
            ['device_fingerprint_change', 'unusual_location_change', 'excessive_concurrent_sessions'].includes(activity.type)
        );
        
        if (criticalCount >= 3 || hasCriticalTypes) {
            this.initiateSecurityLockdown();
        }
    }

    async initiateSecurityLockdown() {
        if (this.isSecurityLockdown) return;
        
        this.isSecurityLockdown = true;
        console.error('[Security] INITIATING SECURITY LOCKDOWN');
        
        // Notify all devices
        await this.broadcastSecurityAlert('SECURITY_LOCKDOWN', {
            reason: 'Multiple suspicious activities detected',
            activities: this.suspiciousActivities.slice(-5),
            timestamp: Date.now()
        });
        
        // Show immediate warning to user
        this.showSecurityLockdownDialog();
        
        // Terminate all sessions after warning
        setTimeout(() => {
            this.terminateAllSessions();
        }, 30000); // 30 second warning
    }

    showSecurityLockdownDialog() {
        const overlay = document.createElement('div');
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(220, 38, 38, 0.95);
            z-index: 2147483647;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: Arial, sans-serif;
            color: white;
        `;
        
        overlay.innerHTML = `
            <div style="background: rgba(0, 0, 0, 0.8); padding: 40px; border-radius: 20px; text-align: center; max-width: 600px; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);">
                <div style="font-size: 72px; margin-bottom: 20px;">🚨</div>
                <h1 style="color: #fff; margin: 0 0 20px 0; font-size: 28px;">SECURITY LOCKDOWN INITIATED</h1>
                <p style="font-size: 18px; margin-bottom: 20px; line-height: 1.6;">
                    Suspicious activity has been detected on your account. For your security, all sessions will be terminated in <span id="lockdown-countdown" style="font-weight: bold; font-size: 24px;">30</span> seconds.
                </p>
                <div style="background: rgba(255, 255, 255, 0.1); padding: 20px; border-radius: 10px; margin: 20px 0;">
                    <h3 style="margin: 0 0 10px 0;">Detected Activities:</h3>
                    <ul style="text-align: left; margin: 0; padding-left: 20px;">
                        ${this.suspiciousActivities.slice(-3).map(activity => 
                            `<li>${activity.type.replace(/_/g, ' ').toUpperCase()}</li>`
                        ).join('')}
                    </ul>
                </div>
                <p style="font-size: 14px; opacity: 0.9;">
                    If this was not you, please contact support immediately. You will be redirected to a secure login page.
                </p>
                <button onclick="window.location.href='/login.html'" style="
                    background: #fff;
                    color: #dc2626;
                    border: none;
                    padding: 15px 30px;
                    border-radius: 10px;
                    font-size: 16px;
                    font-weight: bold;
                    cursor: pointer;
                    margin-top: 20px;
                ">Continue to Secure Login</button>
            </div>
        `;
        
        document.body.appendChild(overlay);
        
        // Countdown
        let countdown = 30;
        const countdownElement = overlay.querySelector('#lockdown-countdown');
        const countdownInterval = setInterval(() => {
            countdown--;
            countdownElement.textContent = countdown;
            if (countdown <= 0) {
                clearInterval(countdownInterval);
                this.terminateAllSessions();
            }
        }, 1000);
    }

    async terminateAllSessions() {
        try {
            await this.makeSecureRequest('/api/session/terminate-all', {
                method: 'POST',
                body: JSON.stringify({
                    reason: 'security_lockdown',
                    timestamp: Date.now()
                })
            });
            
            // Clear local storage and redirect
            localStorage.clear();
            sessionStorage.clear();
            window.location.href = '/login.html?security_lockdown=true';
        } catch (error) {
            console.error('[Security] Failed to terminate sessions:', error);
            // Force redirect anyway
            window.location.href = '/login.html?security_lockdown=true';
        }
    }

    // === CROSS-DEVICE NOTIFICATIONS ===
    startCrossDeviceNotifications() {
        console.log('[Notifications] Starting polling-based notification system...');
        
        // Use polling for notifications (more reliable for this implementation)
        this.checkForNotifications(); // Initial check
        
        // Check for notifications every 30 seconds
        this.notificationInterval = setInterval(() => {
            this.checkForNotifications();
        }, 30000);
    }

    async checkForNotifications() {
        try {
            const response = await this.makeSecureRequest('/api/user/notifications/pending');
            if (response.ok) {
                const result = await response.json();
                if (result.success && result.notifications && result.notifications.length > 0) {
                    console.log('[Notifications] Found', result.notifications.length, 'notifications');
                    result.notifications.forEach(notification => {
                        this.handleCrossDeviceNotification(notification);
                    });
                } else {
                    console.log('[Notifications] No new notifications');
                }
            }
        } catch (error) {
            console.error('[Notifications] Failed to check notifications:', error);
        }
    }

    handleCrossDeviceNotification(notification) {
        console.log('[Notifications] Received:', notification);
        
        switch (notification.type) {
            case 'NEW_DEVICE_LOGIN':
                this.showNewDeviceAlert(notification.data);
                break;
            case 'SUSPICIOUS_ACTIVITY':
                this.showSuspiciousActivityAlert(notification.data);
                break;
            case 'SECURITY_LOCKDOWN':
                this.showSecurityLockdownAlert(notification.data);
                break;
            case 'SESSION_TERMINATED':
                this.handleSessionTerminated(notification.data);
                break;
            case 'PASSWORD_CHANGED':
                this.handlePasswordChanged(notification.data);
                break;
            default:
                this.showGenericNotification(notification);
        }
    }

    // Missing generic notification method
    showGenericNotification(notification) {
        try {
            console.log('[Notifications] Generic notification:', notification);
            
            if (typeof Swal !== 'undefined') {
                Swal.fire({
                    title: notification.title || 'Notification',
                    text: notification.message,
                    icon: 'info',
                    position: 'top-end',
                    timer: 5000,
                    showConfirmButton: false,
                    toast: true
                });
            } else {
                // Fallback if SweetAlert2 is not available
                this.showNotificationToast(
                    notification.title || 'Notification',
                    notification.message,
                    'info'
                );
            }
        } catch (error) {
            console.error('[Notifications] Error showing generic notification:', error);
        }
    }

    showNewDeviceAlert(data) {
        this.showNotificationToast('🔐 New Device Login', 
            `Someone signed into your account from a ${data.deviceType} in ${data.location}. If this wasn't you, secure your account immediately.`,
            'warning', {
                actions: [
                    { text: 'This was me', action: () => this.acknowledgeDevice(data.sessionId) },
                    { text: 'Secure Account', action: () => this.secureAccount() }
                ]
            }
        );
    }

    showSuspiciousActivityAlert(data) {
        this.showNotificationToast('⚠️ Suspicious Activity', 
            `Unusual activity detected: ${data.activity}. Your account security is being monitored.`,
            'error'
        );
    }

    showSecurityLockdownAlert(data) {
        this.showNotificationToast('🚨 Security Lockdown', 
            `Security lockdown initiated: ${data.reason}. All sessions will be terminated for your protection.`,
            'error'
        );
    }

    showNotificationToast(title, message, type = 'info', options = {}) {
        const toast = document.createElement('div');
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            max-width: 400px;
            background: ${type === 'error' ? '#dc2626' : type === 'warning' ? '#f59e0b' : '#2563eb'};
            color: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            z-index: 1000000;
            animation: slideInRight 0.5s ease-out;
            font-family: Arial, sans-serif;
        `;
        
        toast.innerHTML = `
            <div style="display: flex; align-items: flex-start; gap: 15px;">
                <div style="flex: 1;">
                    <h4 style="margin: 0 0 10px 0; font-size: 16px;">${title}</h4>
                    <p style="margin: 0; font-size: 14px; line-height: 1.4;">${message}</p>
                    ${options.actions ? `
                        <div style="margin-top: 15px; display: flex; gap: 10px;">
                            ${options.actions.map(action => `
                                <button onclick="(${action.action.toString()})(); this.closest('.notification-toast').remove();" 
                                        style="background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.3); padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 12px;">
                                    ${action.text}
                                </button>
                            `).join('')}
                        </div>
                    ` : ''}
                </div>
                <button onclick="this.parentElement.parentElement.remove()" 
                        style="background: none; border: none; color: white; font-size: 18px; cursor: pointer; padding: 0; margin: 0;">×</button>
            </div>
        `;
        
        document.body.appendChild(toast);
        
        // Auto-remove after 10 seconds
        setTimeout(() => {
            if (toast.parentElement) {
                toast.remove();
            }
        }, 10000);
    }

    // === UTILITY METHODS ===
    async makeSecureRequest(url, options = {}) {
        const token = localStorage.getItem('token');
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
                'X-Session-ID': this.currentSession?.id
            },
            credentials: 'include'
        };
        
        return fetch(url, { ...defaultOptions, ...options });
    }

    async getPublicIP() {
        try {
            // Try multiple IP services with CSP-compliant endpoints
            const services = [
                'https://api.ipify.org?format=json',
                'https://ipapi.co/json/',
                'https://ipinfo.io/json'
            ];
            
            for (const service of services) {
                try {
                    const response = await fetch(service, { timeout: 5000 });
                    const data = await response.json();
                    return data.ip || data.query || 'unknown';
                } catch (error) {
                    console.warn(`[IP Detection] Service ${service} failed:`, error);
                    continue;
                }
            }
            
            // If all external services fail, use a local approach
            return 'local_network';
        } catch (error) {
            console.warn('[IP Detection] All methods failed, using fallback');
            return 'unknown';
        }
    }

    async getGeolocation() {
        return new Promise((resolve, reject) => {
            if ('geolocation' in navigator) {
                navigator.geolocation.getCurrentPosition(
                    position => resolve({
                        latitude: position.coords.latitude,
                        longitude: position.coords.longitude,
                        accuracy: position.coords.accuracy
                    }),
                    error => reject(error),
                    { timeout: 10000, maximumAge: 300000 }
                );
            } else {
                reject(new Error('Geolocation not available'));
            }
        });
    }

    calculateDistance(loc1, loc2) {
        const R = 6371; // Earth's radius in km
        const dLat = (loc2.latitude - loc1.latitude) * Math.PI / 180;
        const dLon = (loc2.longitude - loc1.longitude) * Math.PI / 180;
        const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
                Math.cos(loc1.latitude * Math.PI / 180) * Math.cos(loc2.latitude * Math.PI / 180) *
                Math.sin(dLon/2) * Math.sin(dLon/2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
        return R * c;
    }

    getBrowserInfo() {
        return {
            name: this.getBrowserName(),
            version: this.getBrowserVersion(),
            userAgent: navigator.userAgent,
            viewport: `${window.innerWidth}x${window.innerHeight}`,
            screen: `${screen.width}x${screen.height}`,
            colorDepth: screen.colorDepth,
            pixelRatio: window.devicePixelRatio || 1
        };
    }

    getBrowserName() {
        const userAgent = navigator.userAgent;
        if (userAgent.includes('Chrome')) return 'Chrome';
        if (userAgent.includes('Firefox')) return 'Firefox';
        if (userAgent.includes('Safari')) return 'Safari';
        if (userAgent.includes('Edge')) return 'Edge';
        return 'Unknown';
    }

    getBrowserVersion() {
        const userAgent = navigator.userAgent;
        const match = userAgent.match(/(Chrome|Firefox|Safari|Edge)\/(\d+)/);
        return match ? match[2] : 'Unknown';
    }

    compareFingerprints(old, current) {
        const changes = [];
        Object.keys(old).forEach(key => {
            if (JSON.stringify(old[key]) !== JSON.stringify(current[key])) {
                changes.push({
                    property: key,
                    oldValue: old[key],
                    newValue: current[key]
                });
            }
        });
        return changes;
    }

    cleanupOldActivities() {
        const cutoff = Date.now() - (24 * 60 * 60 * 1000); // 24 hours
        this.activityBuffer = this.activityBuffer.filter(activity => activity.timestamp > cutoff);
        this.suspiciousActivities = this.suspiciousActivities.filter(activity => activity.timestamp > cutoff);
    }

    async sendSessionHeartbeat() {
        try {
            await this.makeSecureRequest('/api/session/heartbeat', {
                method: 'POST',
                body: JSON.stringify({
                    sessionId: this.currentSession?.id,
                    timestamp: Date.now(),
                    activityCount: this.activityBuffer.length
                })
            });
        } catch (error) {
            console.warn('[Session] Heartbeat failed:', error);
        }
    }

    async reportSuspiciousActivity(activity) {
        try {
            await this.makeSecureRequest('/api/security/report-activity', {
                method: 'POST',
                body: JSON.stringify(activity)
            });
        } catch (error) {
            console.error('[Security] Failed to report activity:', error);
        }
    }

    async broadcastSecurityAlert(type, data) {
        try {
            await this.makeSecureRequest('/api/security/broadcast-alert', {
                method: 'POST',
                body: JSON.stringify({ type, data })
            });
        } catch (error) {
            console.error('[Security] Failed to broadcast alert:', error);
        }
    }

    // Public API methods
    async acknowledgeDevice(sessionId) {
        try {
            await this.makeSecureRequest('/api/session/acknowledge-device', {
                method: 'POST',
                body: JSON.stringify({ sessionId })
            });
        } catch (error) {
            console.error('[Security] Failed to acknowledge device:', error);
        }
    }

    async secureAccount() {
        window.location.href = '/change-password.html?security_alert=true';
    }

    handleSessionTerminated(data) {
        alert(`Your session has been terminated: ${data.reason}`);
        window.location.href = '/login.html';
    }

    handlePasswordChanged(data) {
        this.showNotificationToast('🔐 Password Changed', 
            'Your password was changed from another device. If this wasn\'t you, contact support immediately.',
            'warning'
        );
    }

    // Cleanup
    destroy() {
        // Clear notification polling interval
        if (this.notificationInterval) {
            clearInterval(this.notificationInterval);
            this.notificationInterval = null;
        }
        
        // Clear other intervals
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
        
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
            this.monitoringInterval = null;
        }
        
        // Remove event listeners
        if (this.eventHandlers) {
            this.eventHandlers.clear();
        }
        
        console.log('[Advanced Session Manager] Destroyed');
    }

    // Missing security alert handler method
    handleSecurityAlerts(alert) {
        try {
            console.log('[Security Alert]', alert);
            
            // Ensure alert has proper structure
            if (!alert || typeof alert !== 'object') {
                console.warn('[Security Alert] Invalid alert format:', alert);
                return;
            }
            
            // Extract alert type from various possible properties
            const alertType = alert.type || alert.alertType || alert.kind || 'unknown';
            
            // Process different types of security alerts
            switch (alertType) {
                case 'SUSPICIOUS_ACTIVITY':
                case 'suspicious_activity':
                    this.handleSuspiciousActivity(alert);
                    break;
                case 'UNAUTHORIZED_ACCESS':
                case 'unauthorized_access':
                    this.handleUnauthorizedAccess(alert);
                    break;
                case 'SECURITY_BREACH':
                case 'security_breach':
                    this.handleSecurityBreach(alert);
                    break;
                case 'LOCATION_ANOMALY':
                case 'location_anomaly':
                    this.handleLocationAnomaly(alert);
                    break;
                case 'NEW_DEVICE_LOGIN':
                case 'new_device_login':
                case 'security_event':
                    // Don't show repeated new device alerts for same session
                    if (!this.shownDeviceAlerts) {
                        this.shownDeviceAlerts = new Set();
                    }
                    const alertKey = `${alert.id || alert.title}_${this.currentSession?.id}`;
                    if (!this.shownDeviceAlerts.has(alertKey)) {
                        this.shownDeviceAlerts.add(alertKey);
                        this.showGenericNotification(alert);
                    } else {
                        console.log('[Security Alert] Skipping duplicate device alert:', alertKey);
                    }
                    break;
                case 'unknown':
                default:
                    console.log('[Security Alert] Unknown alert type:', alertType, 'Full alert:', alert);
                    // Only show generic notification if it's not a duplicate and has content
                    if (alert.title && alert.message && alertType !== 'unknown') {
                        this.showGenericNotification(alert);
                    }
            }
        } catch (error) {
            console.error('[Security Alert] Error handling alert:', error);
        }
    }

    // Handle suspicious activity alerts
    handleSuspiciousActivity(alert) {
        console.warn('[Suspicious Activity]', alert.details);
        this.showSecurityAlert({
            type: 'warning',
            title: '⚠️ Suspicious Activity Detected',
            message: alert.details.message || 'Unusual activity has been detected on your account.',
            actions: ['Review Activity', 'Secure Account']
        });
    }

    // Handle unauthorized access alerts
    handleUnauthorizedAccess(alert) {
        console.error('[Unauthorized Access]', alert.details);
        this.showSecurityAlert({
            type: 'error',
            title: '🚨 Unauthorized Access Attempt',
            message: alert.details.message || 'An unauthorized access attempt has been detected.',
            actions: ['Change Password', 'Lock Account']
        });
    }

    // Handle security breach alerts
    handleSecurityBreach(alert) {
        console.error('[Security Breach]', alert.details);
        this.initiateSecurityLockdown();
        this.showSecurityAlert({
            type: 'error',
            title: '🔒 Security Breach Detected',
            message: 'A security breach has been detected. Your account will be secured automatically.',
            actions: ['Acknowledge', 'Contact Support']
        });
    }

    // Handle location anomaly alerts
    handleLocationAnomaly(alert) {
        console.warn('[Location Anomaly]', alert.details);
        this.showSecurityAlert({
            type: 'info',
            title: '🌍 Location Change Detected',
            message: alert.details.message || 'We noticed you\'re accessing your account from a new location.',
            actions: ['This was me', 'Secure Account']
        });
    }

    // Show security alert to user
    showSecurityAlert(alertConfig) {
        if (typeof Swal !== 'undefined') {
            Swal.fire({
                title: alertConfig.title,
                text: alertConfig.message,
                icon: alertConfig.type,
                showCancelButton: true,
                confirmButtonText: alertConfig.actions[0] || 'OK',
                cancelButtonText: alertConfig.actions[1] || 'Cancel'
            });
        } else {
            alert(`${alertConfig.title}\n${alertConfig.message}`);
        }
    }

    // Missing activity pattern analysis method
    analyzeActivityPatterns(activities) {
        try {
            console.log('[Activity Analysis] Analyzing patterns for', activities.length, 'activities');
            
            if (!Array.isArray(activities) || activities.length === 0) {
                return {
                    score: 100,
                    patterns: [],
                    anomalies: [],
                    recommendations: []
                };
            }

            const patterns = {
                timePatterns: this.analyzeTimePatterns(activities),
                locationPatterns: this.analyzeLocationPatterns(activities),
                devicePatterns: this.analyzeDevicePatterns(activities),
                behaviorPatterns: this.analyzeBehaviorPatterns(activities)
            };

            const anomalies = this.detectAnomalies(patterns);
            const score = this.calculateSecurityScore(patterns, anomalies);
            const recommendations = this.generateRecommendations(anomalies);

            console.log('[Activity Analysis] Score:', score, 'Anomalies:', anomalies.length);

            return {
                score,
                patterns,
                anomalies,
                recommendations
            };
        } catch (error) {
            console.error('[Activity Analysis] Error:', error);
            return {
                score: 50,
                patterns: {},
                anomalies: [],
                recommendations: ['Unable to analyze activity patterns']
            };
        }
    }

    // Analyze time-based patterns
    analyzeTimePatterns(activities) {
        const hours = activities.map(a => new Date(a.timestamp).getHours());
        const days = activities.map(a => new Date(a.timestamp).getDay());
        
        return {
            mostActiveHours: this.getMostCommon(hours),
            mostActiveDays: this.getMostCommon(days),
            activitySpread: this.calculateSpread(hours)
        };
    }

    // Analyze location patterns
    analyzeLocationPatterns(activities) {
        const locations = activities.map(a => a.ipAddress || a.location).filter(Boolean);
        const uniqueLocations = [...new Set(locations)];
        
        return {
            uniqueLocations: uniqueLocations.length,
            mostCommonLocation: this.getMostCommon(locations),
            locationChanges: this.countLocationChanges(activities)
        };
    }

    // Analyze device patterns
    analyzeDevicePatterns(activities) {
        const devices = activities.map(a => a.userAgent || a.device).filter(Boolean);
        const uniqueDevices = [...new Set(devices)];
        
        return {
            uniqueDevices: uniqueDevices.length,
            mostCommonDevice: this.getMostCommon(devices),
            deviceSwitches: this.countDeviceSwitches(activities)
        };
    }

    // Analyze behavior patterns
    analyzeBehaviorPatterns(activities) {
        const actionTypes = activities.map(a => a.type || a.action).filter(Boolean);
        const failureRate = activities.filter(a => a.status === 'FAILED').length / activities.length;
        
        return {
            actionDistribution: this.getDistribution(actionTypes),
            failureRate: failureRate,
            sessionDuration: this.calculateAverageSessionDuration(activities)
        };
    }

    // Detect anomalies in patterns
    detectAnomalies(patterns) {
        const anomalies = [];
        
        // Check for unusual location activity
        if (patterns.locationPatterns?.uniqueLocations > 5) {
            anomalies.push({
                type: 'LOCATION_ANOMALY',
                severity: 'MEDIUM',
                description: 'Multiple locations detected in recent activity'
            });
        }

        // Check for high failure rate
        if (patterns.behaviorPatterns?.failureRate > 0.3) {
            anomalies.push({
                type: 'HIGH_FAILURE_RATE',
                severity: 'HIGH',
                description: 'High rate of failed login attempts'
            });
        }

        // Check for unusual device activity
        if (patterns.devicePatterns?.uniqueDevices > 3) {
            anomalies.push({
                type: 'DEVICE_ANOMALY',
                severity: 'LOW',
                description: 'Multiple devices used recently'
            });
        }

        return anomalies;
    }

    // Calculate security score based on patterns
    calculateSecurityScore(patterns, anomalies) {
        let score = 100;
        
        // Deduct points for anomalies
        anomalies.forEach(anomaly => {
            switch (anomaly.severity) {
                case 'HIGH': score -= 30; break;
                case 'MEDIUM': score -= 20; break;
                case 'LOW': score -= 10; break;
            }
        });

        // Factor in behavior patterns
        if (patterns.behaviorPatterns?.failureRate > 0.1) {
            score -= patterns.behaviorPatterns.failureRate * 50;
        }

        return Math.max(0, Math.min(100, score));
    }

    // Generate security recommendations
    generateRecommendations(anomalies) {
        const recommendations = [];
        
        anomalies.forEach(anomaly => {
            switch (anomaly.type) {
                case 'LOCATION_ANOMALY':
                    recommendations.push('Review recent login locations');
                    break;
                case 'HIGH_FAILURE_RATE':
                    recommendations.push('Consider enabling 2FA');
                    recommendations.push('Review password strength');
                    break;
                case 'DEVICE_ANOMALY':
                    recommendations.push('Remove unused devices');
                    break;
            }
        });

        if (recommendations.length === 0) {
            recommendations.push('Your account activity looks normal');
        }

        return [...new Set(recommendations)]; // Remove duplicates
    }

    // Helper methods for pattern analysis
    getMostCommon(array) {
        if (!Array.isArray(array) || array.length === 0) {
            return null;
        }
        
        const counts = {};
        array.forEach(item => counts[item] = (counts[item] || 0) + 1);
        
        const keys = Object.keys(counts);
        if (keys.length === 0) {
            return null;
        }
        
        return keys.reduce((a, b) => counts[a] > counts[b] ? a : b);
    }

    calculateSpread(array) {
        if (!Array.isArray(array) || array.length === 0) {
            return 0;
        }
        const min = Math.min(...array);
        const max = Math.max(...array);
        return max - min;
    }

    countLocationChanges(activities) {
        let changes = 0;
        for (let i = 1; i < activities.length; i++) {
            if (activities[i].ipAddress !== activities[i-1].ipAddress) {
                changes++;
            }
        }
        return changes;
    }

    countDeviceSwitches(activities) {
        let switches = 0;
        for (let i = 1; i < activities.length; i++) {
            if (activities[i].userAgent !== activities[i-1].userAgent) {
                switches++;
            }
        }
        return switches;
    }

    getDistribution(array) {
        const counts = {};
        array.forEach(item => counts[item] = (counts[item] || 0) + 1);
        return counts;
    }

    calculateAverageSessionDuration(activities) {
        const sessions = activities.filter(a => a.type === 'login' || a.type === 'logout');
        if (sessions.length < 2) return 0;
        
        // Simplified calculation - would need more complex logic for real sessions
        return sessions.length > 0 ? 30 * 60 * 1000 : 0; // 30 minutes default
    }
}

// Global instance
let advancedSessionManager;

// Auto-initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Only initialize on protected pages
    const currentPath = window.location.pathname;
    const protectedPaths = ['/dashboard.html', '/change-password.html', '/profile.html'];
    
    if (protectedPaths.some(path => currentPath.includes(path))) {
        advancedSessionManager = new AdvancedSessionManager();
    }
});

// Export for manual initialization
window.AdvancedSessionManager = AdvancedSessionManager; 