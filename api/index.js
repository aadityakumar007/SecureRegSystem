// Ultra-simple CSRF token endpoint for Vercel
module.exports = (req, res) => {
    // Set basic CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    // Handle preflight
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    // Only handle CSRF token for now
    if (req.method === 'GET') {
        // Generate simple token without crypto dependency
        const token = Math.random().toString(36).substring(2, 15) + 
                     Math.random().toString(36).substring(2, 15) +
                     Date.now().toString(36);
        
        return res.status(200).json({
            success: true,
            csrfToken: token
        });
    }
    
    return res.status(404).json({
        success: false,
        message: 'Not found'
    });
}; 