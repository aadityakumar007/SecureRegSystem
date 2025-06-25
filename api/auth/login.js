const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');

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
        console.error('[Login] Error reading users:', error);
        return [];
    }
}

// Helper function to write users
async function writeUsers(users) {
    try {
        const filePath = path.join(process.cwd(), 'src/users.json');
        await fs.writeFile(filePath, JSON.stringify(users, null, 2));
        return true;
    } catch (error) {
        console.error('[Login] Error writing users:', error);
        return false;
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

    // Only allow POST requests
    if (req.method !== 'POST') {
        return res.status(405).json({
            success: false,
            message: 'Method not allowed'
        });
    }

    try {
        const { username, password, recaptchaToken } = req.body;

        console.log('[Login] Login attempt for:', username);

        // Basic validation
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        // Read users from file
        const users = await readUsers();
        const user = users.find(u => u.username === username || u.email === username);

        if (!user) {
            console.log('[Login] User not found:', username);
            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            console.log('[Login] Invalid password for:', username);
            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        // Generate JWT token
        const jwtSecret = process.env.JWT_SECRET || 'your-secret-key';
        const token = jwt.sign(
            { 
                userId: user.username,
                username: user.username,
                email: user.email
            },
            jwtSecret,
            { expiresIn: '1h' }
        );

        // Get client info for login history
        const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || '127.0.0.1';
        const userAgent = req.headers['user-agent'] || '';
        const geo = geoip.lookup(clientIP);
        const ua = new UAParser(userAgent);

        // Update user login history
        if (!user.loginHistory) {
            user.loginHistory = [];
        }

        user.loginHistory.push({
            sessionId: Math.random().toString(36).substring(2, 15),
            timestamp: new Date(),
            ipAddress: clientIP,
            userAgent: userAgent,
            location: geo ? `${geo.city}, ${geo.country}` : 'Unknown',
            deviceFingerprint: Buffer.from(userAgent + clientIP).toString('base64'),
            isActive: true,
            lastActiveAt: new Date()
        });

        // Keep only last 50 login records
        if (user.loginHistory.length > 50) {
            user.loginHistory = user.loginHistory.slice(-50);
        }

        // Update last login
        user.lastLogin = new Date();
        user.lastActiveAt = new Date();

        // Save updated user data
        await writeUsers(users);

        console.log('[Login] Successful login for:', username);

        res.status(200).json({
            success: true,
            message: 'Login successful',
            token: token,
            user: {
                username: user.username,
                email: user.email,
                lastLogin: user.lastLogin
            }
        });

    } catch (error) {
        console.error('[Login] Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed',
            error: error.message
        });
    }
} 