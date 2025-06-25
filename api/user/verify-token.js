const cors = require('cors');
const jwt = require('jsonwebtoken');

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
        // Get token from Authorization header
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: 'Authorization token required'
            });
        }

        const token = authHeader.substring(7); // Remove 'Bearer '
        const jwtSecret = process.env.JWT_SECRET || 'your-secret-key';

        // Verify JWT token
        let decoded;
        try {
            decoded = jwt.verify(token, jwtSecret);
        } catch (error) {
            console.log('[Token Verify] Token verification failed:', error.message);
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired token',
                expired: error.name === 'TokenExpiredError'
            });
        }

        console.log('[Token Verify] Token verified for user:', decoded.username);

        // Token is valid
        res.status(200).json({
            success: true,
            message: 'Token is valid',
            user: {
                userId: decoded.userId,
                username: decoded.username,
                email: decoded.email
            },
            expiresAt: decoded.exp ? new Date(decoded.exp * 1000) : null
        });

    } catch (error) {
        console.error('[Token Verify] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Token verification failed',
            error: error.message
        });
    }
} 