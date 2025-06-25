const cors = require('cors');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');

// Configure CORS for Vercel
const corsOptions = {
    credentials: true,
    origin: [
        'https://secure-reg-system.vercel.app',
        /\.vercel\.app$/,
        'http://localhost:3000'
    ]
};

// Helper function to read users
async function readUsers() {
    try {
        const filePath = path.join(process.cwd(), 'src/users.json');
        const data = await fs.readFile(filePath, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('[User Info] Error reading users:', error);
        return [];
    }
}

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
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired token'
            });
        }

        // Read users from file
        const users = await readUsers();
        const user = users.find(u => u.username === decoded.username);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Calculate login statistics
        const loginHistory = user.loginHistory || [];
        const recentLogins = loginHistory.slice(-10); // Last 10 logins
        const totalLogins = loginHistory.length;
        const lastLogin = user.lastLogin || null;

        // Get unique locations
        const uniqueLocations = [...new Set(loginHistory.map(login => login.location).filter(Boolean))];

        // Calculate security score (simplified)
        let securityScore = 85; // Base score
        if (totalLogins > 50) securityScore += 5; // Active user bonus
        if (uniqueLocations.length < 3) securityScore += 5; // Consistent location bonus
        if (user.lastChanged && new Date(user.lastChanged) > new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)) {
            securityScore += 5; // Recent password change bonus
        }
        securityScore = Math.min(securityScore, 100);

        // Return user information
        res.status(200).json({
            success: true,
            user: {
                username: user.username,
                email: user.email,
                lastLogin: lastLogin,
                lastActiveAt: user.lastActiveAt || lastLogin,
                totalLogins: totalLogins,
                recentLogins: recentLogins,
                uniqueLocations: uniqueLocations,
                securityScore: securityScore,
                accountCreated: user.createdAt || '2024-01-01', // Default if not set
                passwordLastChanged: user.lastChanged || '2024-01-01',
                loginHistory: loginHistory
            }
        });

    } catch (error) {
        console.error('[User Info] Error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get user information',
            error: error.message
        });
    }
} 