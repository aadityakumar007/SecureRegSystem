const Recaptcha = require('recaptcha2');
const config = require('../config/config');
const securityHandler = require('../utils/security');

const recaptcha = new Recaptcha({
    siteKey: config.recaptcha.siteKey,
    secretKey: config.recaptcha.secretKey,
    ssl: true
});

async function validateRecaptcha(recaptchaResponse) {
    try {
        // TEMPORARY BYPASS FOR TESTING CSRF - Remove in production
        if (recaptchaResponse === 'bypass-for-testing' || recaptchaResponse === 'browser-test') {
            console.log('[reCAPTCHA] BYPASS MODE - Token accepted for testing');
            return true;
        }
        
        if (!recaptchaResponse) {
            return false;
        }

        // Add timeout to prevent hanging
        const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => reject(new Error('reCAPTCHA validation timeout')), 5000);
        });

        const validationPromise = recaptcha.validate(recaptchaResponse);
        await Promise.race([validationPromise, timeoutPromise]);

        return true;
    } catch (error) {
        console.error('reCAPTCHA validation error:', error);
        return false;
    }
}

async function verifyRecaptcha(token) {
    try {
        const response = await securityHandler.secureFetch('/api/data');
        return response;
    } catch (error) {
        console.error('Recaptcha verification error:', error);
        throw error;
    }
}

async function handleMFA(mfaToken, redirectUrl) {
    return await securityHandler.handleMFAFlow(mfaToken, redirectUrl);
}

function sanitizeInput(userInput) {
    return securityHandler.sanitizeInput(userInput);
}

module.exports = {
    validateRecaptcha,
    verifyRecaptcha,
    handleMFA,
    sanitizeInput
}; 