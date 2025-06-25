// OTP Manager
const otpStore = new Map();

const debug = {
    log: (message, data) => {
        console.log(`[OTP Manager] ${message}`, data || '');
    },
    error: (message, error) => {
        console.error(`[OTP Manager] ${message}`, error);
    }
};

// Generate and store OTP
const generateOTP = (email, userId) => {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    otpStore.set(email, {
        code: otp,
        timestamp: Date.now(),
        attempts: 0,
        userId
    });

    debug.log('OTP generated and stored:', {
        email,
        otp,
        timestamp: new Date().toISOString()
    });

    return otp;
};

// Verify OTP
const verifyOTP = (email, otp) => {
    debug.log('Verifying OTP:', { email, otp });
    debug.log('Current OTP store:', Array.from(otpStore.entries()));

    const storedOTP = otpStore.get(email);
    
    if (!storedOTP) {
        debug.error('No OTP found for:', email);
        return {
            success: false,
            message: 'No OTP found. Please request a new one.'
        };
    }

    // Check if OTP is expired (2 minutes)
    if (Date.now() - storedOTP.timestamp > 2 * 60 * 1000) {
        otpStore.delete(email);
        debug.error('OTP expired for:', email);
        return {
            success: false,
            message: 'OTP has expired. Please request a new one.'
        };
    }

    // Check attempts
    if (storedOTP.attempts >= 3) {
        otpStore.delete(email);
        debug.error('Too many attempts for:', email);
        return {
            success: false,
            message: 'Too many attempts. Please request a new OTP.'
        };
    }

    // Increment attempts
    storedOTP.attempts += 1;
    otpStore.set(email, storedOTP);

    // Verify OTP
    if (storedOTP.code !== otp) {
        debug.error('Invalid OTP for:', email);
        return {
            success: false,
            message: 'Invalid verification code'
        };
    }

    // Clear OTP after successful verification
    otpStore.delete(email);
    debug.log('OTP verified successfully for:', email);

    return {
        success: true,
        message: 'OTP verified successfully',
        userId: storedOTP.userId
    };
};

// Clear expired OTPs
const clearExpiredOTPs = () => {
    const now = Date.now();
    for (const [email, data] of otpStore.entries()) {
        if (now - data.timestamp > 2 * 60 * 1000) {
            otpStore.delete(email);
            debug.log('Cleared expired OTP for:', email);
        }
    }
};

// Start periodic cleanup
setInterval(clearExpiredOTPs, 60000);

module.exports = {
    generateOTP,
    verifyOTP
}; 