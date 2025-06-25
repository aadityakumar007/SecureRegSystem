const crypto = require('crypto');

// Simple CSRF token endpoint for Vercel
module.exports = async (req, res) => {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'GET') {
        return res.status(405).json({ 
            success: false, 
            message: 'Method not allowed' 
        });
    }

    try {
        // Generate a simple CSRF token
        const token = crypto.randomBytes(32).toString('hex');
        
        console.log(`[CSRF] Generated token: ${token.substring(0, 8)}...`);
        
        res.status(200).json({ 
            success: true,
            csrfToken: token 
        });
        
    } catch (error) {
        console.error('[CSRF] Error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to generate CSRF token' 
        });
    }
}; 