const User = require('../models/User');
const notificationManager = require('./notificationManager');

class PasswordExpiryChecker {
    constructor() {
        this.checkInterval = 24 * 60 * 60 * 1000; // Check every 24 hours
        this.warningPeriod = 7 * 24 * 60 * 60 * 1000; // Warn 7 days before expiry
        this.isRunning = false;
    }

    start() {
        if (this.isRunning) {
            console.log('[Password Expiry Checker] Already running');
            return;
        }

        this.isRunning = true;
        console.log('[Password Expiry Checker] Starting password expiry monitoring');

        // Run initial check
        this.checkPasswordExpiry();

        // Set up periodic checking
        this.intervalId = setInterval(() => {
            this.checkPasswordExpiry();
        }, this.checkInterval);
    }

    stop() {
        if (this.intervalId) {
            clearInterval(this.intervalId);
            this.intervalId = null;
        }
        this.isRunning = false;
        console.log('[Password Expiry Checker] Stopped');
    }

    async checkPasswordExpiry() {
        try {
            console.log('[Password Expiry Checker] Running password expiry check...');
            
            const now = new Date();
            const warningDate = new Date(now.getTime() + this.warningPeriod);

            // Find users with expired passwords
            const expiredUsers = await User.find({
                passwordExpiresAt: { $lt: now },
                passwordChangeRequired: { $ne: true }
            });

            // Find users whose passwords expire within warning period
            const warningUsers = await User.find({
                passwordExpiresAt: { 
                    $gte: now, 
                    $lt: warningDate 
                },
                passwordChangeRequired: { $ne: true }
            });

            console.log(`[Password Expiry Checker] Found ${expiredUsers.length} expired passwords, ${warningUsers.length} passwords expiring soon`);

            // Force password change for expired users
            for (const user of expiredUsers) {
                await this.handleExpiredPassword(user);
            }

            // Send warnings for soon-to-expire passwords
            for (const user of warningUsers) {
                await this.handlePasswordWarning(user);
            }

        } catch (error) {
            console.error('[Password Expiry Checker] Error during password expiry check:', error);
        }
    }

    async handleExpiredPassword(user) {
        try {
            console.log(`[Password Expiry Checker] Forcing password change for expired password: ${user.username}`);
            
            // Force password change
            await user.forcePasswordChange();
            
            // Send notification
            await notificationManager.sendSecurityAlert(user, 'password_expired', 
                'Your password has expired. Please change your password immediately.');

            // Revoke all existing tokens to force re-login
            user.revokedTokens = user.revokedTokens || [];
            // Note: In a production environment, you might want to revoke all active sessions
            
            await user.save();

            console.log(`[Password Expiry Checker] Password change forced for user: ${user.username}`);
            
        } catch (error) {
            console.error(`[Password Expiry Checker] Error handling expired password for user ${user.username}:`, error);
        }
    }

    async handlePasswordWarning(user) {
        try {
            const daysUntilExpiry = Math.ceil((user.passwordExpiresAt - new Date()) / (24 * 60 * 60 * 1000));
            
            console.log(`[Password Expiry Checker] Sending password expiry warning to user: ${user.username}, expires in ${daysUntilExpiry} days`);
            
            // Send warning notification
            await notificationManager.sendSecurityAlert(user, 'password_expiry_warning', 
                `Your password will expire in ${daysUntilExpiry} days. Please change your password soon to avoid being locked out.`);

        } catch (error) {
            console.error(`[Password Expiry Checker] Error sending password warning to user ${user.username}:`, error);
        }
    }

    // Manual check method for testing
    async runManualCheck() {
        console.log('[Password Expiry Checker] Running manual password expiry check...');
        await this.checkPasswordExpiry();
    }

    // Get statistics about password expiry
    async getPasswordExpiryStats() {
        try {
            const now = new Date();
            const oneWeek = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
            const oneMonth = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

            const stats = {
                expired: await User.countDocuments({
                    passwordExpiresAt: { $lt: now }
                }),
                expiringThisWeek: await User.countDocuments({
                    passwordExpiresAt: { 
                        $gte: now, 
                        $lt: oneWeek 
                    }
                }),
                expiringThisMonth: await User.countDocuments({
                    passwordExpiresAt: { 
                        $gte: now, 
                        $lt: oneMonth 
                    }
                }),
                requireChangeNow: await User.countDocuments({
                    passwordChangeRequired: true
                }),
                total: await User.countDocuments({})
            };

            return stats;
        } catch (error) {
            console.error('[Password Expiry Checker] Error getting password expiry stats:', error);
            return null;
        }
    }
}

// Export singleton instance
const passwordExpiryChecker = new PasswordExpiryChecker();
module.exports = passwordExpiryChecker; 