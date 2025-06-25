const crypto = require('crypto');

/**
 * Generate a random verification token
 * @returns {string} A random 32-byte hex string
 */
function generateVerificationToken() {
    return crypto.randomBytes(32).toString('hex');
}

/**
 * Generate a random reset password token
 * @returns {string} A random 32-byte hex string
 */
function generateResetToken() {
    return crypto.randomBytes(32).toString('hex');
}

module.exports = {
    generateVerificationToken,
    generateResetToken
}; 