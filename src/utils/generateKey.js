const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Generate a secure random key
const generateKey = () => {
    // Generate 32 bytes (256 bits) for AES-256
    const key = crypto.randomBytes(32).toString('hex');
    return key;
};

// Save key to .env file
const saveKeyToEnv = (key) => {
    const envPath = path.join(__dirname, '../../.env');
    const envContent = `ENCRYPTION_KEY=${key}\n`;
    
    try {
        // Check if .env exists
        if (fs.existsSync(envPath)) {
            // Read existing .env
            let content = fs.readFileSync(envPath, 'utf8');
            
            // Check if ENCRYPTION_KEY already exists
            if (content.includes('ENCRYPTION_KEY=')) {
                // Replace existing key
                content = content.replace(/ENCRYPTION_KEY=.*\n/, envContent);
            } else {
                // Append new key
                content += envContent;
            }
            
            fs.writeFileSync(envPath, content);
        } else {
            // Create new .env file
            fs.writeFileSync(envPath, envContent);
        }
        
        console.log('Encryption key has been saved to .env file');
        console.log('IMPORTANT: Keep this key secure and never commit it to version control!');
    } catch (error) {
        console.error('Error saving encryption key:', error);
        console.log('Please manually add the following line to your .env file:');
        console.log(`ENCRYPTION_KEY=${key}`);
    }
};

// Generate and save key
const key = generateKey();
console.log('Generated encryption key:', key);
saveKeyToEnv(key); 