const fetch = require('node-fetch');
const config = require('../config/config');

async function secureFetch(url) {
    try {
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                'X-Security-Token': config.securityToken
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('Secure fetch error:', error);
        throw error;
    }
}

async function handleMFAFlow(mfaToken, redirectUrl) {
    try {
        // Implement MFA flow logic here
        return true;
    } catch (error) {
        console.error('MFA flow error:', error);
        throw error;
    }
}

function sanitizeInput(input) {
    if (typeof input !== 'string') {
        return '';
    }
    // Basic sanitization
    return input
        .replace(/[<>]/g, '') // Remove < and >
        .trim(); // Remove leading/trailing whitespace
}

module.exports = {
    secureFetch,
    handleMFAFlow,
    sanitizeInput
}; 