const cors = require('cors');

// Configure CORS for Vercel
const corsOptions = {
    credentials: true,
    origin: [
        'https://secure-reg-system.vercel.app',
        /\.vercel\.app$/,
        'http://localhost:3000'
    ]
};

export default async function handler(req, res) {
    // Apply CORS
    const corsHandler = cors(corsOptions);
    await new Promise((resolve, reject) => {
        corsHandler(req, res, (result) => {
            if (result instanceof Error) {
                return reject(result);
            }
            return resolve(result);
        });
    });

    // Only allow GET requests
    if (req.method !== 'GET') {
        return res.status(405).json({
            success: false,
            message: 'Method not allowed'
        });
    }

    try {
        console.log('[API Test] Request received');
        console.log('[API Test] Headers:', req.headers);

        res.status(200).json({ 
            success: true,
            message: 'Vercel serverless API is working!',
            timestamp: new Date().toISOString(),
            environment: process.env.NODE_ENV || 'development',
            url: req.url,
            method: req.method
        });
    } catch (error) {
        console.error('[API Test] Error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'API test failed',
            error: error.message 
        });
    }
} 