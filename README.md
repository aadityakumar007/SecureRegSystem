# 🔐 SecureSystem - Enterprise Authentication Platform

A comprehensive, enterprise-grade authentication system built with Node.js, Express, MongoDB, and modern JavaScript. Features advanced security controls, multi-factor authentication, automated threat protection, and a responsive user interface designed for maximum security and usability.

## 🚀 Key Features

### 🛡️ **Advanced Security Architecture**
- **Multi-Layer Brute Force Protection**: Account-level (3 attempts) + IP-level (10 attempts) lockout system
- **Automatic Password Expiry**: 30-day password rotation with proactive notifications
- **Real-Time Session Management**: 3-minute inactivity timeout with auto-logout
- **CSRF Protection**: Token-based protection against cross-site request forgery
- **XSS Prevention**: Input sanitization and secure headers with Helmet.js
- **Rate Limiting**: Tiered rate limiting across all API endpoints

### 🔑 **Authentication & Authorization**
- **Multi-Factor Authentication**: Email-based OTP verification
- **JWT Token Security**: Secure token management with revocation capability
- **Password Security**: 12+ character requirement with complexity validation
- **Device Tracking**: IP geolocation and user agent fingerprinting
- **Session Validation**: Real-time token verification and session management

### 🎯 **User Experience**
- **Responsive Design**: Mobile-first, modern UI with dark theme
- **Real-Time Validation**: Password strength meter and form validation
- **Auto-Generate Passwords**: Secure 16-character password generation
- **Password Visibility Toggle**: Enhanced password input experience
- **Progressive Loading**: Smooth animations and loading states

### 📊 **Monitoring & Analytics**
- **Security Event Logging**: Comprehensive audit trail of all security events
- **Login History**: IP, location, device, and timestamp tracking
- **Failed Attempt Monitoring**: Real-time tracking of security threats
- **Password Expiry Tracking**: Automated monitoring with email notifications

## 🏗️ Project Structure

```
SecureSystem/
├── 📁 public/                    # Frontend assets
│   ├── 📁 css/                   # Stylesheets
│   │   ├── styles.css            # Main stylesheet
│   │   └── otp-verification.css  # OTP-specific styles
│   ├── 📁 js/                    # Client-side JavaScript
│   │   ├── components/           # Reusable components
│   │   ├── utils/                # Utility functions
│   │   ├── login.js              # Login functionality
│   │   ├── register.js           # Registration with validation
│   │   ├── dashboard.js          # Dashboard management
│   │   └── password-*.js         # Password-related scripts
│   ├── 📁 images/                # Static images
│   ├── login.html                # Login page
│   ├── register.html             # Registration page
│   ├── dashboard.html            # User dashboard
│   ├── change-password.html      # Password change
│   ├── forgot-password.html      # Password reset
│   ├── otp-verification.html     # OTP verification
│   └── mfa-verify.html           # MFA verification
├── 📁 src/                       # Backend source code
│   ├── 📁 config/                # Configuration
│   │   └── config.js             # Environment configuration
│   ├── 📁 controllers/           # Route controllers
│   ├── 📁 db/                    # Database connection
│   │   └── connection.js         # MongoDB connection
│   ├── 📁 middleware/            # Express middleware
│   │   ├── auth.js               # Authentication middleware
│   │   └── rateLimiting.js       # Rate limiting & brute force protection
│   ├── 📁 models/                # Database models
│   │   └── User.js               # User schema with security features
│   ├── 📁 routes/                # API routes
│   │   ├── auth.js               # Authentication endpoints
│   │   └── user.js               # User management endpoints
│   ├── 📁 utils/                 # Utility functions
│   │   ├── email.js              # Email services (OTP, notifications)
│   │   ├── encryption.js         # Data encryption utilities
│   │   ├── otpManager.js         # OTP generation and validation
│   │   ├── passwordExpiryChecker.js # Automated password monitoring
│   │   ├── notificationManager.js # Security notifications
│   │   ├── recaptcha.js          # Google reCAPTCHA validation
│   │   └── security.js           # Security utilities
│   └── server.js                 # Main server file
├── 📁 tests/                     # Test files
├── package.json                  # Dependencies and scripts
├── requirements.txt              # Detailed system requirements
├── env.example                   # Environment variables template
└── README.md                     # This file
```

## 🔧 Installation & Setup

### Prerequisites

- **Node.js** >= 16.0.0
- **npm** >= 8.0.0
- **MongoDB** >= 4.4.0 (Local or Atlas)
- **Gmail Account** with App Password
- **Google reCAPTCHA v2** keys

### Quick Start

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd SecureSystem
   ```

2. **Install Dependencies**
   ```bash
   npm install
   ```

3. **Environment Configuration**
   ```bash
   cp env.example .env
   ```
   
   Configure your `.env` file:
   ```env
   # Server Configuration
   PORT=3000
   NODE_ENV=development
   BASE_URL=http://localhost:3000
   
   # Database
   MONGODB_URI=mongodb://localhost:27017/securesystem
   
   # Security (REQUIRED)
   JWT_SECRET=your_32_character_secret_key_here
   SESSION_SECRET=your_session_secret_key_here
   ENCRYPTION_KEY=your_64_character_hex_encryption_key
   
   # Email Service (REQUIRED)
   EMAIL_USER=your_email@gmail.com
   EMAIL_PASS=your_gmail_app_password
   
   # Google reCAPTCHA v2 (REQUIRED)
   RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key
   RECAPTCHA_SITE_KEY=your_recaptcha_site_key
   ```

4. **Start the Application**
   ```bash
   # Development mode
   npm run dev
   
   # Production mode
   npm start
   ```

5. **Access the Application**
   - Open your browser to `http://localhost:3000`
   - The system will redirect to the login page

## 🔐 Security Features

### **Brute Force Protection**
| Protection Level | Limit | Duration | Auto-Reset |
|-----------------|-------|----------|------------|
| Account Level | 3 failed attempts | 15 minutes | ✅ |
| IP Level | 10 failed attempts | 15 minutes | ✅ |
| Progressive Delay | Increasing delays | Per attempt | ✅ |

### **Password Security**
- **Length**: Minimum 12 characters
- **Complexity**: 2+ uppercase, 2+ lowercase, 2+ numbers, 2+ special chars
- **History**: Prevents reuse of last 5 passwords
- **Expiry**: Automatic 30-day rotation
- **Strength Meter**: Real-time password strength feedback

### **Session Management**
- **JWT Tokens**: 24-hour expiration with revocation capability
- **Inactivity Timeout**: 3-minute automatic logout
- **Token Validation**: Real-time verification on each request
- **Multi-Device Support**: Logout from all devices functionality

### **Rate Limiting**
```javascript
Global API:        100 requests / 15 minutes
Authentication:    10 requests / 15 minutes
OTP Requests:      5 requests / 10 minutes
Registration:      3 requests / 1 hour
Password Reset:    3 requests / 1 hour
```

## 🌐 API Endpoints

### **Authentication Routes** (`/api/auth`)
| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| `POST` | `/register` | User registration with email verification | 3/hour |
| `POST` | `/verify-registration` | Verify registration OTP | 5/10min |
| `POST` | `/login` | User login with reCAPTCHA | 10/15min |
| `POST` | `/verify-otp` | Verify login OTP | 5/10min |
| `POST` | `/forgot-password` | Request password reset | 3/hour |
| `POST` | `/reset-password` | Reset password with token | 3/hour |
| `POST` | `/change-password` | Change password (authenticated) | 10/15min |
| `POST` | `/logout` | Secure logout with token revocation | 100/15min |
| `POST` | `/logout-all` | Logout from all devices | 100/15min |

### **User Management Routes** (`/api/user`)
| Method | Endpoint | Description | Authentication |
|--------|----------|-------------|----------------|
| `GET` | `/info` | Get user profile information | Required |
| `GET` | `/verify-token` | Verify JWT token validity | Required |
| `GET` | `/logs` | Get user login history | Required |
| `PUT` | `/update-profile` | Update user profile | Required |
| `DELETE` | `/delete-account` | Delete user account | Required |

### **Security Routes**
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/csrf-token` | Get CSRF token |
| `GET` | `/api/test` | API health check |

## 🎨 Frontend Features

### **Pages Available**
- **Login Page** (`/login.html`) - Secure login with reCAPTCHA
- **Registration Page** (`/register.html`) - Account creation with validation
- **Dashboard** (`/dashboard.html`) - User profile and account management
- **Password Change** (`/change-password.html`) - Secure password updates
- **Password Reset** (`/forgot-password.html`) - Email-based password recovery
- **OTP Verification** (`/otp-verification.html`) - Multi-factor authentication
- **MFA Verification** (`/mfa-verify.html`) - Enhanced MFA flow

### **UI Components**
- **Password Strength Meter**: Real-time password validation
- **Auto-Generate Password**: Secure 16-character password creation
- **Password Visibility Toggle**: Enhanced password input experience
- **Real-Time Validation**: Form validation with immediate feedback
- **Loading States**: Smooth animations and progress indicators
- **Responsive Design**: Mobile-first, modern interface

## 🔍 Monitoring & Logging

### **Security Events Tracked**
- Failed login attempts with IP and device information
- Account lockouts and unlocks
- Password changes and resets
- Token revocation events
- New device logins
- Password expiry warnings
- Suspicious activity patterns

### **Password Expiry Monitoring**
The system automatically monitors password expiry with:
- **Daily Checks**: Automated background scanning
- **7-Day Warnings**: Proactive email notifications
- **Forced Changes**: Automatic redirection for expired passwords
- **Statistics**: Real-time expiry tracking and reporting

## 🚀 Production Deployment

### **Environment Setup**
```bash
# Set production environment
export NODE_ENV=production

# Use strong secrets
JWT_SECRET=<64-character-random-string>
SESSION_SECRET=<64-character-random-string>
ENCRYPTION_KEY=<128-character-hex-string>

# Configure secure database
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/securesystem

# Enable HTTPS (recommended)
# Use reverse proxy (nginx) or load balancer
```

### **Security Checklist**
- ✅ Enable HTTPS/SSL certificates
- ✅ Configure proper CORS origins
- ✅ Use MongoDB Atlas or secured instance
- ✅ Set up process manager (PM2)
- ✅ Configure log rotation
- ✅ Set up automated backups
- ✅ Monitor performance and security metrics
- ✅ Regular security audits

## 🧪 Testing

### **Security Test Scenarios**
1. **Brute Force Protection**: Verify 3-attempt account lockout
2. **IP Blocking**: Confirm 10-attempt IP-level blocking
3. **Password Expiry**: Validate 30-day automatic expiry
4. **Session Timeout**: Test 3-minute inactivity logout
5. **CSRF Protection**: Verify token validation
6. **XSS Prevention**: Test input sanitization

### **Manual Testing**
```bash
# Test account lockout
# 1. Make 3 failed login attempts
# 2. Verify account is locked for 15 minutes
# 3. Confirm automatic unlock

# Test IP blocking
# 1. Make 10 failed attempts from same IP
# 2. Verify IP is blocked for 15 minutes
# 3. Test with different IP addresses
```

## 📋 Browser Compatibility

| Browser | Version | Status |
|---------|---------|--------|
| Chrome | 80+ | ✅ Fully Supported |
| Firefox | 75+ | ✅ Fully Supported |
| Safari | 13+ | ✅ Fully Supported |
| Edge | 80+ | ✅ Fully Supported |
| Mobile Browsers | Latest | ✅ Responsive Design |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support & Documentation

- **Setup Guide**: See `SETUP_GUIDE.md` for detailed installation instructions
- **Security Features**: See `ENHANCED_SECURITY_FEATURES.md` for security documentation
- **Requirements**: See `requirements.txt` for complete system requirements
- **API Documentation**: All endpoints documented above with rate limits and authentication requirements

## 🔄 Version History

- **v1.0.0**: Initial release with core authentication features
- **Enhanced Security**: Added brute force protection and password expiry
- **UI Improvements**: Modern responsive design with password generation
- **Advanced Monitoring**: Real-time security event tracking and notifications

---

**⚠️ Security Notice**: This system implements enterprise-grade security features. Always use HTTPS in production, keep dependencies updated, and follow security best practices for deployment.

**🎯 Perfect for**: Enterprise applications, SaaS platforms, secure portals, customer authentication systems, and any application requiring robust security controls.
