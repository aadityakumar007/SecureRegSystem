# 📦 Installation Guide - SecureSystem

## ⚠️ Important: This is a Node.js Project

This project uses **Node.js** and **npm**, not Python and pip.

## 🚀 Quick Installation

### Prerequisites
- **Node.js** >= 16.0.0
- **npm** >= 8.0.0
- **MongoDB** >= 4.4.0

### Step-by-Step Installation

1. **Install Node.js**
   ```bash
   # Download from: https://nodejs.org/
   # Or use package manager:
   
   # Windows (using Chocolatey)
   choco install nodejs
   
   # macOS (using Homebrew)
   brew install node
   
   # Ubuntu/Debian
   sudo apt update
   sudo apt install nodejs npm
   ```

2. **Clone & Navigate**
   ```bash
   git clone <your-repo-url>
   cd SecureSystem
   ```

3. **Install Dependencies**
   ```bash
   npm install
   ```

4. **Configure Environment**
   ```bash
   # Copy example environment file
   cp env.example .env
   
   # Edit .env with your settings
   # - MongoDB connection string
   # - JWT secrets
   # - Email credentials
   # - reCAPTCHA keys
   ```

5. **Start the Application**
   ```bash
   # Development mode (auto-restart)
   npm run dev
   
   # Production mode
   npm start
   ```

6. **Access the Application**
   ```
   http://localhost:3000
   ```

## 🔧 Configuration Required

### Environment Variables (.env file)
```env
# Database
MONGODB_URI=mongodb://localhost:27017/securesystem

# Security
JWT_SECRET=your_32_character_secret_key_here
SESSION_SECRET=your_session_secret_key_here
ENCRYPTION_KEY=your_64_character_hex_encryption_key

# Email (Gmail)
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_gmail_app_password

# reCAPTCHA
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key
RECAPTCHA_SITE_KEY=your_recaptcha_site_key

# Optional
PORT=3000
NODE_ENV=development
```

### External Services Setup

1. **MongoDB**
   - Install locally OR use MongoDB Atlas
   - Create database: `securesystem`

2. **Gmail App Password**
   - Enable 2FA on Gmail
   - Generate App Password
   - Use in EMAIL_PASS

3. **Google reCAPTCHA v2**
   - Visit: https://www.google.com/recaptcha/
   - Create new site (v2, "I'm not a robot")
   - Get Site Key and Secret Key

## 🐍 Python Users

If you want to use Python instead, see `requirements.txt` for equivalent packages. However, you'll need to rewrite the entire application as this is specifically built for Node.js.

## 🆘 Troubleshooting

### Common Issues

1. **"npm: command not found"**
   - Install Node.js from https://nodejs.org/

2. **"Cannot connect to MongoDB"**
   - Ensure MongoDB is running
   - Check MONGODB_URI in .env

3. **"Port 3000 already in use"**
   - Change PORT in .env file
   - Or kill process: `npx kill-port 3000`

4. **Email not sending**
   - Check Gmail App Password
   - Verify EMAIL_USER and EMAIL_PASS

### Getting Help

- Check `README.md` for detailed documentation
- Review `SETUP_GUIDE.md` for advanced configuration
- Ensure all environment variables are set correctly

## ✅ Verification

After installation, you should be able to:
- Access login page at http://localhost:3000
- Register new accounts
- Receive OTP emails
- Login with authentication

## 🔄 Development

```bash
# Install development dependencies
npm install

# Run in development mode (auto-restart)
npm run dev

# Run tests (if available)
npm test

# Check for vulnerabilities
npm audit
```

---

**Note**: This project cannot be installed with `pip install -r requirements.txt` as it's not a Python project. Always use `npm install` for Node.js projects.
