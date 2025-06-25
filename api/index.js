const crypto = require('crypto');

// Simple serverless function handler for Vercel
module.exports = async (req, res) => {
    try {
        // Set CORS headers
        res.setHeader('Access-Control-Allow-Credentials', true);
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Content-Type, Authorization');

        // Handle preflight requests
        if (req.method === 'OPTIONS') {
            return res.status(200).end();
        }

        console.log(`[API] ${req.method} ${req.url} - Processing request`);

        // Parse URL to get the path
        const url = new URL(req.url, `http://${req.headers.host}`);
        const path = url.pathname;

        // Route handling
        if (path === '/api/csrf-token' && req.method === 'GET') {
            // Generate a simple CSRF token
            const token = crypto.randomBytes(32).toString('hex');
            console.log(`[CSRF] Generated token: ${token.substring(0, 8)}...`);
            
            return res.status(200).json({ 
                success: true,
                csrfToken: token 
            });
        }

        if (path === '/api/health' && req.method === 'GET') {
            return res.status(200).json({
                status: 'ok',
                message: 'API is working',
                timestamp: new Date().toISOString(),
                environment: process.env.NODE_ENV || 'production'
            });
        }

        if (path === '/api/test' && req.method === 'GET') {
            console.log(`[API] Test endpoint accessed: ${req.method} ${req.url}`);
            return res.status(200).json({ 
                success: true,
                message: 'API is working',
                timestamp: new Date().toISOString(),
                method: req.method,
                url: req.url
            });
        }

        if (path === '/api/debug' && req.method === 'GET') {
            return res.status(200).json({
                success: true,
                message: 'Debug endpoint working',
                timestamp: new Date().toISOString(),
                method: req.method,
                url: req.url,
                path: path,
                headers: req.headers,
                query: url.searchParams,
                environment: {
                    NODE_ENV: process.env.NODE_ENV,
                    VERCEL: process.env.VERCEL
                }
            });
        }

        // For other API routes, try to load the full Express app
        if (path.startsWith('/api/')) {
            try {
                // Dynamic import of the full Express app for complex routes
                const app = require('../src/server.js');
                return app(req, res);
            } catch (appError) {
                console.error('[API] Error loading full app:', appError);
                return res.status(500).json({
                    success: false,
                    message: 'API temporarily unavailable',
                    error: 'Server configuration error'
                });
            }
        }

        // 404 for unknown routes
        console.log(`[API] Route not found: ${req.method} ${path}`);
        return res.status(404).json({
            success: false,
            message: 'API endpoint not found',
            path: path
        });

    } catch (error) {
        console.error('[API] Unhandled error:', error);
        return res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
}; 