const { sendEmail } = require('./email');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');

class NotificationManager {
    constructor() {
        this.notifications = new Map(); // In-memory storage for browser notifications
        this.cleanupInterval = setInterval(() => this.cleanup(), 60 * 60 * 1000); // Cleanup every hour
    }

    // Send login alert notification
    async sendLoginAlert(user, req, isNewDevice = false) {
        try {
            // Always send notifications - permanently enabled for security
            console.log(`Sending enhanced login alert for user: ${user.email} - New device: ${isNewDevice}`);

            // Enhanced IP detection with multiple fallbacks
            const ip = req.ip || 
                      req.connection.remoteAddress || 
                      req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
                      req.headers['x-real-ip'] ||
                      req.headers['cf-connecting-ip'] ||
                      req.socket.remoteAddress ||
                      'Unknown IP';

            console.log(`Detected IP: ${ip}`);

            // Enhanced geolocation with comprehensive data
            const geo = geoip.lookup(ip);
            const ua = UAParser(req.headers['user-agent']);
            
            // Comprehensive location detection with multiple fallbacks
            let location = 'Unknown location';
            let locationDetails = '';
            let coordinates = '';
            let timezone = '';
            
            if (geo) {
                // Primary location from IP geolocation
                location = `${geo.city || 'Unknown City'}, ${geo.region || 'Unknown Region'}, ${geo.country || 'Unknown Country'}`;
                coordinates = geo.ll ? `${geo.ll[0]}, ${geo.ll[1]}` : 'Unknown';
                timezone = geo.timezone || 'Unknown';
                
                locationDetails = `
                    <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">🏙️ City:</td><td style="color: #2c3e50;">${geo.city || 'Unknown'}</td></tr>
                    <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">🗺️ Region/State:</td><td style="color: #2c3e50;">${geo.region || 'Unknown'}</td></tr>
                    <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">🌍 Country:</td><td style="color: #2c3e50;">${geo.country || 'Unknown'}</td></tr>
                    <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">🕐 Timezone:</td><td style="color: #2c3e50;">${geo.timezone || 'Unknown'}</td></tr>
                    <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">📍 Coordinates:</td><td style="color: #2c3e50;">${coordinates}</td></tr>
                    <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">🛜 ISP:</td><td style="color: #2c3e50;">${geo.org || 'Unknown ISP'}</td></tr>
                `;
            } else {
                // Fallback location detection
                try {
                    const browserTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
                    location = browserTimezone.replace(/_/g, ' ');
                    timezone = browserTimezone;
                } catch (e) {
                    location = 'Location detection unavailable';
                    timezone = 'Unknown';
                }
                
                locationDetails = `
                    <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">🕐 Browser Timezone:</td><td style="color: #2c3e50;">${timezone}</td></tr>
                    <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">⚠️ Note:</td><td style="color: #e67e22;">Precise location unavailable - using browser timezone</td></tr>
                `;
            }
            
            // Enhanced device information
            const browser = ua.browser.name || 'Unknown Browser';
            const browserVersion = ua.browser.version || 'Unknown Version';
            const os = ua.os.name || 'Unknown OS';
            const osVersion = ua.os.version || 'Unknown Version';
            const deviceModel = ua.device.model || 'Unknown Device';
            const deviceType = ua.device.type || 'desktop';
            const deviceVendor = ua.device.vendor || 'Unknown Vendor';
            
            const device = `${browser} ${browserVersion} on ${os} ${osVersion}`;
            
            // Enhanced timestamp with timezone
            const timestamp = new Date().toLocaleString('en-US', {
                weekday: 'long',
                year: 'numeric',
                month: 'long',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                timeZoneName: 'short'
            });

            // Security risk assessment
            const securityLevel = this.assessSecurityRisk(isNewDevice, geo, ua);
            const riskColor = securityLevel === 'HIGH' ? '#dc2626' : securityLevel === 'MEDIUM' ? '#f59e0b' : '#10b981';

            // Email notification - always send for security
            try {
                await this.sendEmailNotification(user, 'login_alert', {
                    username: user.username,
                    timestamp,
                    location,
                    locationDetails,
                    device,
                    deviceDetails: {
                        browser: browser,
                        browserVersion: browserVersion,
                        os: os,
                        osVersion: osVersion,
                        deviceModel: deviceModel,
                        deviceType: deviceType,
                        deviceVendor: deviceVendor,
                        userAgent: req.headers['user-agent'] || 'Unknown'
                    },
                    ip,
                    geo: geo || {},
                    coordinates,
                    timezone,
                    isNewDevice: isNewDevice,
                    securityLevel: securityLevel,
                    riskColor: riskColor,
                    sessionInfo: {
                        loginTime: timestamp,
                        sessionId: req.headers['x-session-id'] || 'Unknown',
                        userAgentFingerprint: Buffer.from(req.headers['user-agent'] || '').toString('base64').slice(0, 8)
                    }
                });
                console.log(`Enhanced security email sent successfully to: ${user.email}`);
            } catch (emailError) {
                console.error('Enhanced email notification failed:', emailError);
            }

            // Browser notification - always add for security
            this.addBrowserNotification(user._id.toString(), {
                type: 'login_alert',
                title: isNewDevice ? '🚨 New Device Login Alert' : '🔔 Login Alert',
                message: `${isNewDevice ? 'NEW DEVICE: ' : ''}Login from ${location} at ${timestamp}`,
                timestamp: new Date(),
                priority: isNewDevice ? 'high' : 'medium',
                data: { 
                    location, 
                    device, 
                    ip, 
                    isNewDevice, 
                    geo, 
                    coordinates,
                    timezone,
                    securityLevel 
                }
            });

            console.log(`Enhanced login alert sent to user: ${user.email} - New device: ${isNewDevice} - Security Level: ${securityLevel}`);
        } catch (error) {
            console.error('Error sending enhanced login alert:', error);
        }
    }

    // Assess security risk based on various factors
    assessSecurityRisk(isNewDevice, geo, ua) {
        let riskScore = 0;
        
        // New device increases risk
        if (isNewDevice) riskScore += 30;
        
        // Unknown location increases risk
        if (!geo || !geo.city) riskScore += 20;
        
        // Unusual browsers or old versions
        const browser = ua.browser.name || '';
        const browserVersion = parseFloat(ua.browser.version) || 0;
        
        if (!browser.includes('Chrome') && !browser.includes('Firefox') && !browser.includes('Safari') && !browser.includes('Edge')) {
            riskScore += 15;
        }
        
        // Very old browser versions
        if (browserVersion > 0 && browserVersion < 100) riskScore += 10;
        
        // Mobile devices from unknown locations
        if (ua.device.type === 'mobile' && (!geo || !geo.city)) riskScore += 15;
        
        // Determine risk level
        if (riskScore >= 50) return 'HIGH';
        if (riskScore >= 25) return 'MEDIUM';
        return 'LOW';
    }

    // Send security alert notification
    async sendSecurityAlert(user, alertType, details) {
        try {
            // Always send security alerts - permanently enabled for security
            console.log(`Sending security alert for user: ${user.email} - Type: ${alertType}`);

            const timestamp = new Date().toLocaleString();

            // Email notification - always send for security
            try {
                await this.sendEmailNotification(user, 'security_alert', {
                    username: user.username,
                    alertType,
                    details,
                    timestamp
                });
                console.log(`Security alert email sent successfully to: ${user.email}`);
            } catch (emailError) {
                console.error('Security alert email failed:', emailError);
            }

            // Browser notification - always add for security
            this.addBrowserNotification(user._id.toString(), {
                type: 'security_alert',
                title: 'Security Alert',
                message: this.getSecurityAlertMessage(alertType, details),
                timestamp: new Date(),
                priority: 'high',
                data: { alertType, details }
            });

            console.log(`Security alert sent to user: ${user.email} - Type: ${alertType}`);
        } catch (error) {
            console.error('Error sending security alert:', error);
        }
    }

    // Send system update notification
    async sendSystemUpdate(user, updateType, message) {
        try {
            if (!user.notificationSettings.systemUpdates) {
                return;
            }

            const timestamp = new Date().toLocaleString();

            // Email notification
            if (user.notificationSettings.email) {
                await this.sendEmailNotification(user, 'system_update', {
                    username: user.username,
                    updateType,
                    message,
                    timestamp
                });
            }

            // Browser notification
            if (user.notificationSettings.browser) {
                this.addBrowserNotification(user._id.toString(), {
                    type: 'system_update',
                    title: 'System Update',
                    message,
                    timestamp: new Date(),
                    data: { updateType }
                });
            }

            console.log(`System update notification sent to user: ${user.email}`);
        } catch (error) {
            console.error('Error sending system update:', error);
        }
    }

    // Add browser notification to queue
    addBrowserNotification(userId, notification) {
        if (!this.notifications.has(userId)) {
            this.notifications.set(userId, []);
        }

        const userNotifications = this.notifications.get(userId);
        userNotifications.push({
            id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
            ...notification,
            read: false
        });

        // Keep only last 50 notifications per user
        if (userNotifications.length > 50) {
            userNotifications.splice(0, userNotifications.length - 50);
        }

        this.notifications.set(userId, userNotifications);
    }

    // Get browser notifications for user
    getBrowserNotifications(userId, limit = 20) {
        const userNotifications = this.notifications.get(userId) || [];
        return userNotifications.slice(-limit).reverse();
    }

    // Mark notification as read
    markNotificationAsRead(userId, notificationId) {
        const userNotifications = this.notifications.get(userId);
        if (userNotifications) {
            const notification = userNotifications.find(n => n.id === notificationId);
            if (notification) {
                notification.read = true;
                return true;
            }
        }
        return false;
    }

    // Mark all notifications as read
    markAllNotificationsAsRead(userId) {
        const userNotifications = this.notifications.get(userId);
        if (userNotifications) {
            userNotifications.forEach(notification => {
                notification.read = true;
            });
            return true;
        }
        return false;
    }

    // Get unread notification count
    getUnreadCount(userId) {
        const userNotifications = this.notifications.get(userId) || [];
        return userNotifications.filter(n => !n.read).length;
    }

    // Send email notification
    async sendEmailNotification(user, type, data) {
        try {
            const templates = {
                login_alert: {
                    subject: data.isNewDevice ? '🚨 SECURITY ALERT: New Device Login - Secure System' : '🔔 Login Alert - Secure System',
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 650px; margin: 0 auto; background: #f8f9fa; padding: 20px;">
                            <div style="background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
                                ${data.isNewDevice ? 
                                    `<div style="background: linear-gradient(135deg, #dc2626, #991b1b); color: white; padding: 20px; border-radius: 10px; margin-bottom: 25px; text-align: center;">
                                        <div style="font-size: 24px; margin-bottom: 5px;">🚨 NEW DEVICE LOGIN DETECTED</div>
                                        <div style="font-size: 14px; opacity: 0.9;">Immediate attention required</div>
                                    </div>` :
                                    '<h2 style="color: #2c3e50; margin-top: 0; text-align: center; border-bottom: 3px solid #3498db; padding-bottom: 15px;">🔔 Login Alert</h2>'
                                }
                                
                                <div style="margin-bottom: 20px;">
                                    <p style="font-size: 16px; color: #2c3e50; margin-bottom: 5px;">Hello <strong>${data.username}</strong>,</p>
                                    <p style="font-size: 16px; color: #2c3e50;">We detected a ${data.isNewDevice ? '<span style="color: #dc2626; font-weight: bold;">new device</span>' : ''} login to your account with the following details:</p>
                                </div>

                                <!-- Security Level Indicator -->
                                <div style="background: ${data.riskColor}15; border: 2px solid ${data.riskColor}; border-radius: 10px; padding: 15px; margin: 20px 0; text-align: center;">
                                    <div style="color: ${data.riskColor}; font-weight: bold; font-size: 18px;">
                                        🛡️ Security Level: ${data.securityLevel}
                                    </div>
                                    <div style="color: ${data.riskColor}; font-size: 14px; margin-top: 5px;">
                                        ${data.securityLevel === 'HIGH' ? 'High risk detected - Immediate verification recommended' : 
                                          data.securityLevel === 'MEDIUM' ? 'Medium risk - Please verify this login attempt' : 
                                          'Low risk - Routine login notification'}
                                    </div>
                                </div>
                                
                                <!-- Login Summary -->
                                <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0; border-left: 4px solid #3498db;">
                                    <h3 style="color: #2c3e50; margin-top: 0; font-size: 18px;">📋 Login Summary</h3>
                                    <table style="width: 100%; border-collapse: collapse;">
                                        <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e; width: 30%;">🕐 Time:</td><td style="color: #2c3e50;">${data.timestamp}</td></tr>
                                        <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">🌐 IP Address:</td><td style="color: #2c3e50; font-family: monospace;">${data.ip}</td></tr>
                                        <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">📍 Location:</td><td style="color: #2c3e50;">${data.location}</td></tr>
                                        <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">💻 Device:</td><td style="color: #2c3e50;">${data.device}</td></tr>
                                        <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">🔐 Session ID:</td><td style="color: #2c3e50; font-family: monospace;">${data.sessionInfo?.userAgentFingerprint || 'Unknown'}</td></tr>
                                    </table>
                                </div>

                                ${data.locationDetails ? `
                                <div style="background: #e8f4fd; padding: 20px; border-radius: 10px; margin: 20px 0; border-left: 4px solid #3498db;">
                                    <h3 style="color: #2c3e50; margin-top: 0; font-size: 18px;">🌍 Geographic Information</h3>
                                    <table style="width: 100%; border-collapse: collapse;">
                                        ${data.locationDetails}
                                    </table>
                                    ${data.coordinates && data.coordinates !== 'Unknown' ? `
                                    <div style="margin-top: 15px; padding: 10px; background: white; border-radius: 8px; text-align: center;">
                                        <small style="color: #6c757d;">📍 <strong>Approximate Coordinates:</strong> ${data.coordinates}</small>
                                    </div>
                                    ` : ''}
                                </div>
                                ` : ''}

                                ${data.deviceDetails ? `
                                <div style="background: #f0f9ff; padding: 20px; border-radius: 10px; margin: 20px 0; border-left: 4px solid #0ea5e9;">
                                    <h3 style="color: #2c3e50; margin-top: 0; font-size: 18px;">💻 Device Information</h3>
                                    <table style="width: 100%; border-collapse: collapse;">
                                        <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e; width: 35%;">🌐 Browser:</td><td style="color: #2c3e50;">${data.deviceDetails.browser} ${data.deviceDetails.browserVersion}</td></tr>
                                        <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">💻 Operating System:</td><td style="color: #2c3e50;">${data.deviceDetails.os} ${data.deviceDetails.osVersion}</td></tr>
                                        <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">📱 Device Type:</td><td style="color: #2c3e50;">${data.deviceDetails.deviceType}</td></tr>
                                        ${data.deviceDetails.deviceModel && data.deviceDetails.deviceModel !== 'Unknown Device' ? `
                                        <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">📋 Device Model:</td><td style="color: #2c3e50;">${data.deviceDetails.deviceModel}</td></tr>
                                        ` : ''}
                                        ${data.deviceDetails.deviceVendor && data.deviceDetails.deviceVendor !== 'Unknown Vendor' ? `
                                        <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">🏢 Vendor:</td><td style="color: #2c3e50;">${data.deviceDetails.deviceVendor}</td></tr>
                                        ` : ''}
                                        <tr><td style="font-weight: bold; padding: 8px 0; color: #34495e;">🛡️ Security Level:</td><td style="color: ${data.riskColor}; font-weight: bold;">${data.securityLevel}</td></tr>
                                    </table>
                                    
                                    <div style="margin-top: 15px; padding: 10px; background: #f8f9fa; border-radius: 8px;">
                                        <details style="cursor: pointer;">
                                            <summary style="font-weight: bold; color: #6b7280;">🔍 Technical Details (Click to expand)</summary>
                                            <div style="margin-top: 10px; padding: 10px; background: white; border-radius: 5px; font-family: monospace; font-size: 12px; color: #495057; word-break: break-all;">
                                                <strong>User Agent:</strong><br>${data.deviceDetails.userAgent}
                                            </div>
                                        </details>
                                    </div>
                                </div>
                                ` : ''}

                                <!-- Time & Session Information -->
                                <div style="background: #fff3cd; padding: 20px; border-radius: 10px; margin: 20px 0; border-left: 4px solid #ffc107;">
                                    <h3 style="color: #856404; margin-top: 0; font-size: 18px;">⏰ Session Information</h3>
                                    <table style="width: 100%; border-collapse: collapse;">
                                        <tr><td style="font-weight: bold; padding: 8px 0; color: #856404; width: 35%;">🕐 Login Time:</td><td style="color: #856404;">${data.sessionInfo?.loginTime || data.timestamp}</td></tr>
                                        <tr><td style="font-weight: bold; padding: 8px 0; color: #856404;">🌐 Timezone:</td><td style="color: #856404;">${data.timezone || 'Unknown'}</td></tr>
                                        <tr><td style="font-weight: bold; padding: 8px 0; color: #856404;">🔢 Session Type:</td><td style="color: #856404;">${data.isNewDevice ? 'New Device Login' : 'Known Device Login'}</td></tr>
                                    </table>
                                </div>

                                ${data.isNewDevice ? 
                                    `<div style="background: #fff3cd; border: 2px solid #ffc107; padding: 20px; border-radius: 10px; margin: 20px 0;">
                                        <div style="text-align: center; margin-bottom: 15px;">
                                            <div style="font-size: 48px; color: #f59e0b;">⚠️</div>
                                        </div>
                                        <p style="margin: 0; color: #856404; font-weight: bold; text-align: center; font-size: 16px;">
                                            🔐 NEW DEVICE SECURITY NOTICE
                                        </p>
                                        <p style="margin: 10px 0 0 0; color: #856404; text-align: center;">
                                            This login was from a device we haven't seen before. If this wasn't you, please secure your account immediately.
                                        </p>
                                    </div>` :
                                    '<div style="background: #d1ecf1; padding: 15px; border-radius: 8px; margin: 20px 0; text-align: center;"><p style="margin: 0; color: #0c5460;">✅ This is a routine login notification from a recognized device.</p></div>'
                                }

                                <!-- Action Required Section -->
                                <div style="text-align: center; margin: 30px 0;">
                                    <div style="color: #dc2626; font-weight: bold; font-size: 18px; margin-bottom: 15px;">
                                        ${data.isNewDevice || data.securityLevel === 'HIGH' ? '🚨 IMMEDIATE ACTION REQUIRED' : '🔍 Please Review'}
                                    </div>
                                    <div style="background: #fdfdfe; border: 2px solid #ddd; padding: 20px; border-radius: 10px; text-align: left;">
                                        <p style="margin: 0 0 10px 0; font-weight: bold; color: #2c3e50;">If this wasn't you, please:</p>
                                        <ul style="margin: 10px 0; padding-left: 20px; color: #2c3e50;">
                                            <li style="margin: 8px 0;">🔒 Change your password immediately</li>
                                            <li style="margin: 8px 0;">📱 Enable two-factor authentication if not already active</li>
                                            <li style="margin: 8px 0;">📋 Review your account activity and recent sessions</li>
                                            <li style="margin: 8px 0;">🔐 Check your device sessions and revoke unknown devices</li>
                                            <li style="margin: 8px 0;">📧 Contact our support team if you need assistance</li>
                                        </ul>
                                        <p style="margin: 10px 0 0 0; font-weight: bold; color: #dc2626;">
                                            ⚡ Act quickly to protect your account security!
                                        </p>
                                    </div>
                                </div>

                                <!-- Security Tips -->
                                <div style="background: #e8f5e8; padding: 20px; border-radius: 10px; margin: 20px 0; border-left: 4px solid #28a745;">
                                    <h3 style="color: #155724; margin-top: 0; font-size: 16px;">🛡️ Security Best Practices</h3>
                                    <ul style="margin: 10px 0; padding-left: 20px; color: #155724; font-size: 14px;">
                                        <li style="margin: 5px 0;">Always log out from shared or public computers</li>
                                        <li style="margin: 5px 0;">Use strong, unique passwords for your account</li>
                                        <li style="margin: 5px 0;">Enable two-factor authentication for enhanced security</li>
                                        <li style="margin: 5px 0;">Regularly review your login activity and device sessions</li>
                                        <li style="margin: 5px 0;">Keep your browser and operating system updated</li>
                                    </ul>
                                </div>

                                <!-- Footer -->
                                <div style="margin-top: 30px; padding-top: 20px; border-top: 2px solid #eee; text-align: center;">
                                    <p style="color: #7f8c8d; font-size: 14px; margin: 10px 0;">
                                        <strong>Secure System Team</strong><br>
                                        <em>Protecting your digital security</em>
                                    </p>
                                    <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 15px 0;">
                                        <p style="color: #6c757d; font-size: 12px; margin: 0; line-height: 1.4;">
                                            📧 This is an automated security notification sent to protect your account.<br>
                                            🕐 Email generated on: ${new Date().toLocaleString()}<br>
                                            🔒 For your protection, we send login alerts for all account access attempts.<br>
                                            ❓ Questions? Contact our security team for assistance.
                                        </p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `
                },
                security_alert: {
                    subject: 'Security Alert - Secure System',
                    html: `
                        <h2>Security Alert</h2>
                        <p>Hello ${data.username},</p>
                        <p>We detected a security event on your account:</p>
                        <p><strong>Alert Type:</strong> ${data.alertType}</p>
                        <p><strong>Details:</strong> ${data.details}</p>
                        <p><strong>Time:</strong> ${data.timestamp}</p>
                        <p>Please review your account activity and ensure your account is secure.</p>
                        <p>Best regards,<br>Secure System Team</p>
                    `
                },
                system_update: {
                    subject: 'System Update - Secure System',
                    html: `
                        <h2>System Update</h2>
                        <p>Hello ${data.username},</p>
                        <p><strong>Update Type:</strong> ${data.updateType}</p>
                        <p><strong>Message:</strong> ${data.message}</p>
                        <p><strong>Time:</strong> ${data.timestamp}</p>
                        <p>Best regards,<br>Secure System Team</p>
                    `
                }
            };

            const template = templates[type];
            if (template) {
                await sendEmail(user.email, template.subject, template.html);
            }
        } catch (error) {
            console.error('Error sending email notification:', error);
        }
    }

    // Get security alert message
    getSecurityAlertMessage(alertType, details) {
        const messages = {
            'account_locked': 'Your account has been temporarily locked due to suspicious activity.',
            'password_changed': 'Your password has been changed successfully.',
            'mfa_disabled': 'Multi-factor authentication has been disabled for your account.',
            'login_from_new_device': `New device login detected: ${details}`,
            'suspicious_activity': `Suspicious activity detected: ${details}`,
            'token_revoked': 'Security tokens have been revoked for your account.'
        };

        return messages[alertType] || `Security alert: ${details}`;
    }

    // Clean up old notifications
    cleanup() {
        const cutoffTime = Date.now() - (7 * 24 * 60 * 60 * 1000); // 7 days ago

        for (const [userId, notifications] of this.notifications.entries()) {
            const filteredNotifications = notifications.filter(
                notification => notification.timestamp.getTime() > cutoffTime
            );
            
            if (filteredNotifications.length === 0) {
                this.notifications.delete(userId);
            } else {
                this.notifications.set(userId, filteredNotifications);
            }
        }

        console.log('Notification cleanup completed');
    }

    // Broadcast notification to all users (admin only)
    async broadcastNotification(message, type = 'system_update', adminUser) {
        try {
            // Add to all users' browser notifications
            for (const [userId] of this.notifications.entries()) {
                this.addBrowserNotification(userId, {
                    type: 'broadcast',
                    title: 'System Announcement',
                    message,
                    timestamp: new Date(),
                    priority: 'medium',
                    data: { type, from: 'system' }
                });
            }

            console.log(`Broadcast notification sent by ${adminUser}: ${message}`);
        } catch (error) {
            console.error('Error broadcasting notification:', error);
        }
    }
}

// Create singleton instance
const notificationManager = new NotificationManager();

module.exports = notificationManager; 