// Simple test endpoint for Vercel
module.exports = async (req, res) => {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    console.log(`[API] Test endpoint accessed: ${req.method} ${req.url}`);
    
    res.status(200).json({ 
        success: true,
        message: 'API is working',
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url
    });
}; 