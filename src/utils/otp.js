const User = require('../models/User');

// Debug logging
const debug = {
    log: (message, data) => {
        console.log(`[OTP] ${message}`, data || '');
    },
    error: (message, error) => {
        console.error(`[OTP] ${message}`, error);
    }
};

// Store OTPs in memory (in production, use Redis or similar)
const otpStore = new Map();

// Generate and send OTP
async function sendOTP(email) {
    try {
        debug.log('Generating OTP for:', email);

        if (!email) {
            debug.error('No email provided');
            return {
                success: false,
                message: 'Email is required'
            };
        }

        // Generate 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        // Store OTP with timestamp
        otpStore.set(email, {
            code: otp,
            timestamp: Date.now(),
            attempts: 0
        });

        debug.log('OTP generated and stored for:', email);

        // In a real application, send OTP via email/SMS
        // For development, log it to console
        console.log(`[DEV] OTP for ${email}: ${otp}`);

        return {
            success: true,
            message: 'OTP sent successfully'
        };
    } catch (error) {
        debug.error('Error sending OTP:', error);
        return {
            success: false,
            message: 'Error sending OTP'
        };
    }
}

// Verify OTP
async function verifyOTP(email, otp) {
    try {
        debug.log('Verifying OTP for:', email);

        if (!email) {
            debug.error('No email provided for verification');
            return {
                success: false,
                message: 'Email is required'
            };
        }

        if (!otp) {
            debug.error('No OTP provided for verification');
            return {
                success: false,
                message: 'OTP is required'
            };
        }

        // Get stored OTP
        const storedOTP = otpStore.get(email);
        debug.log('Stored OTP data:', storedOTP ? 'Found' : 'Not found');
        
        if (!storedOTP) {
            debug.error('No OTP found for email:', email);
            return {
                success: false,
                message: 'No OTP found. Please request a new one.'
            };
        }

        // Check if OTP is expired (2 minutes)
        if (Date.now() - storedOTP.timestamp > 2 * 60 * 1000) {
            debug.error('OTP expired for email:', email);
            otpStore.delete(email);
            return {
                success: false,
                message: 'OTP has expired. Please request a new one.'
            };
        }

        // Check attempts
        if (storedOTP.attempts >= 3) {
            debug.error('Too many attempts for email:', email);
            otpStore.delete(email);
            return {
                success: false,
                message: 'Too many attempts. Please request a new OTP.'
            };
        }

        // Increment attempts
        storedOTP.attempts += 1;
        otpStore.set(email, storedOTP);
        debug.log('Attempt count:', storedOTP.attempts);

        // Verify OTP
        if (storedOTP.code !== otp) {
            debug.error('Invalid OTP for email:', email);
            return {
                success: false,
                message: 'Invalid verification code'
            };
        }

        // Clear OTP after successful verification
        otpStore.delete(email);
        debug.log('OTP verified successfully for email:', email);

        return {
            success: true,
            message: 'OTP verified successfully'
        };
    } catch (error) {
        debug.error('Error verifying OTP:', error);
        return {
            success: false,
            message: 'Error verifying OTP'
        };
    }
}

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

// Export the functions
module.exports = {
    sendOTP,
    verifyOTP
}; 