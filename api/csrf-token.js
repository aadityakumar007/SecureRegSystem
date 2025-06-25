const crypto = require('crypto');

// Simple CSRF token handler for Vercel serverless
module.exports = async (req, res) => {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization');

    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
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
        
        console.log(`[CSRF] Generated token for client: ${token.substring(0, 8)}...`);
        console.log(`[CSRF] Request from: ${req.headers.origin || 'unknown'}`);
        
        // Set token in cookie for stateless verification
        res.setHeader('Set-Cookie', [
            `csrfToken=${token}; HttpOnly; SameSite=Lax; Path=/; ${process.env.NODE_ENV === 'production' ? 'Secure;' : ''}`
        ]);
        
        res.status(200).json({ 
            success: true,
            csrfToken: token 
        });
        
    } catch (error) {
        console.error('[CSRF] Error generating token:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to generate CSRF token',
            error: error.message 
        });
    }
}; 