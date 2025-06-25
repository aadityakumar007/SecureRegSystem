const crypto = require('crypto');
require('dotenv').config();

// Get encryption key from environment variable and ensure it's the correct length
let ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// If no key is set, generate a new one
if (!ENCRYPTION_KEY) {
    console.warn('No ENCRYPTION_KEY found in environment variables. Generating a new key...');
    ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
    console.log('Generated new encryption key. Please add this to your .env file:');
    console.log(`ENCRYPTION_KEY=${ENCRYPTION_KEY}`);
}

// Ensure the key is exactly 32 bytes (256 bits) for AES-256
try {
    // Convert hex string to buffer and check length
    const keyBuffer = Buffer.from(ENCRYPTION_KEY, 'hex');
    if (keyBuffer.length !== 32) {
        console.error('Invalid key length. Generating new key...');
        ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
        console.log('Generated new encryption key. Please add this to your .env file:');
        console.log(`ENCRYPTION_KEY=${ENCRYPTION_KEY}`);
    }
} catch (error) {
    console.error('Error processing encryption key:', error);
    console.error('Generating new key...');
    ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
    console.log('Generated new encryption key. Please add this to your .env file:');
    console.log(`ENCRYPTION_KEY=${ENCRYPTION_KEY}`);
}

// Convert hex string to buffer for actual encryption
const KEY_BUFFER = Buffer.from(ENCRYPTION_KEY, 'hex');
const IV_LENGTH = 16; // For AES, this is always 16

function encrypt(text) {
    try {
        if (!text) return text;
        
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv('aes-256-cbc', KEY_BUFFER, iv);
        let encrypted = cipher.update(text.toString(), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted;
    } catch (error) {
        console.error('Encryption error:', error);
        // Return original text if encryption fails
        return text;
    }
}

function decrypt(text) {
    try {
        if (!text || typeof text !== 'string' || !text.includes(':')) return text;
        
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = textParts.join(':');
        const decipher = crypto.createDecipheriv('aes-256-cbc', KEY_BUFFER, iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        console.error('Decryption error:', error);
        // Return original text if decryption fails
        return text;
    }
}

function encryptUserData(userData) {
    if (!userData || typeof userData !== 'object') return userData;

    const sensitiveFields = ['email', 'username'];
    const encryptedData = { ...userData };

    // Encrypt sensitive fields
    sensitiveFields.forEach(field => {
        if (userData[field]) {
            try {
                encryptedData[field] = encrypt(userData[field]);
            } catch (error) {
                console.error(`Error encrypting ${field}:`, error);
                encryptedData[field] = userData[field]; // Keep original if encryption fails
            }
        }
    });

    // Add encryption metadata
    encryptedData._encrypted = true;
    encryptedData._timestamp = new Date().toISOString();

    return encryptedData;
}

function decryptUserData(encryptedData) {
    if (!encryptedData || typeof encryptedData !== 'object' || !encryptedData._encrypted) {
        return encryptedData;
    }

    const sensitiveFields = ['email', 'username'];
    const decryptedData = { ...encryptedData };

    // Decrypt sensitive fields
    sensitiveFields.forEach(field => {
        if (encryptedData[field] && typeof encryptedData[field] === 'string') {
            try {
                decryptedData[field] = decrypt(encryptedData[field]);
            } catch (error) {
                console.error(`Error decrypting ${field}:`, error);
                decryptedData[field] = '[Encrypted]';
            }
        }
    });

    // Remove encryption metadata
    delete decryptedData._encrypted;
    delete decryptedData._timestamp;

    return decryptedData;
}

module.exports = {
    encrypt,
    decrypt,
    encryptUserData,
    decryptUserData
}; 