# 🔐 SecureSystem - Enterprise Authentication Platform

A comprehensive, enterprise-grade authentication system built with Node.js, Express, MongoDB, and modern JavaScript. Features advanced security controls, multi-factor authentication, automated threat protection, advanced session management, and a responsive dark theme interface designed for maximum security and usability.

## 🚀 Key Features

### 🛡️ **Advanced Security Architecture**
- **Multi-Layer Brute Force Protection**: Account-level (3 attempts) + IP-level (10 attempts) lockout system
- **Automatic Password Expiry**: 30-day password rotation with proactive notifications
- **Real-Time Session Management**: 3-minute inactivity timeout with auto-logout
- **Advanced Multi-Device Session Control**: Cross-device monitoring and security lockdown
- **HSTS Implementation**: Force HTTPS connections with configurable security headers
- **CSRF Protection**: Token-based protection against cross-site request forgery
- **XSS Prevention**: Input sanitization and secure headers with Helmet.js
- **Rate Limiting**: Tiered rate limiting across all API endpoints

### 🔑 **Authentication & Authorization**
- **Multi-Factor Authentication**: Email-based OTP verification with resend capability
- **JWT Token Security**: Secure token management with 1-hour expiration and revocation capability
- **Password Security**: 12+ character requirement with complexity validation and history tracking
- **Device Tracking**: IP geolocation and comprehensive device fingerprinting
- **Session Validation**: Real-time token verification and comprehensive session management

### 🎯 **User Experience**
- **Modern Dark Theme**: Professional dark tech design with glass morphism effects
- **Responsive Design**: Mobile-first, modern UI optimized for all devices
- **Real-Time Validation**: Password strength meter and instant form validation
- **Auto-Generate Passwords**: Secure 16-character password generation with strength meter
- **Password Visibility Toggle**: Enhanced password input experience
- **Progressive Loading**: Smooth animations and loading states with micro-interactions

### 📊 **Advanced Session Management**
- **Multi-Device Control**: Monitor and manage sessions across all devices
- **Suspicious Activity Detection**: Real-time bot detection and anomaly analysis
- **Cross-Device Notifications**: Instant security alerts across all user devices
- **Automatic Security Lockdown**: Immediate threat response with comprehensive cleanup
- **Device Fingerprinting**: Hardware-based device identification and tracking

### 🔍 **Monitoring & Analytics**
- **Security Event Logging**: Comprehensive audit trail of all security events
- **Login History**: IP, location, device, and timestamp tracking with geolocation
- **Failed Attempt Monitoring**: Real-time tracking of security threats and patterns
- **Password Expiry Tracking**: Automated monitoring with email notifications
- **Real-Time Threat Detection**: Behavioral analysis and automated response

## 🏗️ Project Structure

```
SecureSystem/
├── 📁 public/                    # Frontend assets
│   ├── 📁 css/                   # Stylesheets
│   │   ├── styles.css            # Main dark theme stylesheet (977 lines)
│   │   ├── otp-verification.css  # OTP-specific dark theme styles
│   │   ├── dashboard-dark.css    # Dashboard dark theme overrides
│   │   └── style.css             # Additional component styles
│   ├── 📁 js/                    # Client-side JavaScript
│   │   ├── advanced-session-manager.js # Advanced session security system
│   │   ├── session-manager.js    # Basic session timeout management
│   │   ├── login.js              # Login functionality with MFA
│   │   ├── register.js           # Registration with validation
│   │   ├── dashboard.js          # Dashboard management
│   │   ├── password-strength-meter.js # Real-time password analysis
│   │   ├── password-validator.js # Password validation rules
│   │   ├── otp-verification.js   # OTP handling and verification
│   │   ├── change-password.js    # Password change functionality
│   │   ├── forgot-password.js    # Password recovery workflow
│   │   ├── mfa.js                # Multi-factor authentication
│   │   ├── utils.js              # Common utilities and CSRF handling
│   │   └── validation.js         # Form validation logic
│   ├── 📁 images/                # Static images
│   ├── login.html                # Login page with reCAPTCHA
│   ├── register.html             # Registration page
│   ├── dashboard.html            # User dashboard with dark theme
│   ├── change-password.html      # Password change interface
│   ├── forgot-password.html      # Password reset interface
│   ├── otp-verification.html     # OTP verification
│   └── mfa-verify.html           # Enhanced MFA verification
├── 📁 src/                       # Backend source code
│   ├── 📁 config/                # Configuration management
│   │   └── config.js             # Environment configuration with HSTS
│   ├── 📁 db/                    # Database connection
│   │   └── connection.js         # MongoDB connection
│   ├── 📁 middleware/            # Express middleware
│   │   ├── auth.js               # Authentication middleware
│   │   └── rateLimiting.js       # Rate limiting & brute force protection
│   ├── 📁 models/                # Database models
│   │   └── User.js               # User schema with security features
│   ├── 📁 routes/                # API routes
│   │   ├── auth.js               # Authentication endpoints
│   │   ├── user.js               # User management endpoints
│   │   ├── session.js            # Session management endpoints
│   │   └── advanced-session.js   # Advanced session security endpoints
│   ├── 📁 utils/                 # Utility functions
│   │   ├── email.js              # Email services (OTP, notifications)
│   │   ├── emailValidator.js     # Email validation and domain checking
│   │   ├── encryption.js         # Data encryption utilities
│   │   ├── otpManager.js         # OTP generation and validation
│   │   ├── passwordExpiryChecker.js # Automated password monitoring
│   │   ├── notificationManager.js # Security notifications
│   │   ├── recaptcha.js          # Google reCAPTCHA validation
│   │   ├── security.js           # Security utilities
│   │   └── token.js              # Token generation utilities
│   └── server.js                 # Main server file
├── 📁 documentation/             # Project documentation
│   ├── ADVANCED_SESSION_MANAGEMENT.md # Advanced session security documentation
│   ├── COMPREHENSIVE_SECURITY_DOCUMENTATION.md # Complete security reference
│   └── COMPLETE_TECH_STACK_REPORT.md # Detailed technology analysis
├── package.json                  # Node.js dependencies and scripts
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
   SESSION_EXPIRES_IN=1h
   
   # Email Service (REQUIRED)
   EMAIL_USER=your_email@gmail.com
   EMAIL_PASS=your_gmail_app_password
   
   # Google reCAPTCHA v2 (REQUIRED)
   RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key
   RECAPTCHA_SITE_KEY=your_recaptcha_site_key
   
   # HSTS Configuration (Production)
   HSTS_ENABLED=false
   HSTS_MAX_AGE=31536000
   HSTS_INCLUDE_SUBDOMAINS=true
   HSTS_PRELOAD=true
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
- **JWT Tokens**: 1-hour expiration with revocation capability
- **Inactivity Timeout**: 3-minute automatic logout
- **Token Validation**: Real-time verification on each request
- **Multi-Device Support**: Advanced session control across all devices
- **Security Lockdown**: Automatic threat response and session termination

### **Advanced Session Security**
- **Device Fingerprinting**: Hardware-based device identification
- **Suspicious Activity Detection**: Real-time bot and anomaly detection
- **Cross-Device Notifications**: Instant alerts across all user devices
- **Geographic Monitoring**: Location-based security analysis
- **Behavioral Analysis**: User pattern recognition and threat assessment

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
| `POST` | `/verify-token` | JWT token validation | 100/15min |

### **User Management Routes** (`/api/user`)
| Method | Endpoint | Description | Authentication |
|--------|----------|-------------|----------------|
| `GET` | `/info` | Get user profile information | Required |
| `GET` | `/logs` | Get user login history | Required |
| `PUT` | `/update-profile` | Update user profile | Required |
| `DELETE` | `/delete-account` | Delete user account | Required |

### **Session Management Routes** (`/api/session`)
| Method | Endpoint | Description | Authentication |
|--------|----------|-------------|----------------|
| `POST` | `/register` | Register new session | Required |
| `POST` | `/heartbeat` | Session activity heartbeat | Required |
| `GET` | `/active-count` | Get active session count | Required |
| `POST` | `/report-activity` | Report suspicious activity | Required |
| `POST` | `/terminate-all` | Emergency session termination | Required |

### **Security Routes**
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/csrf-token` | Get CSRF token |
| `GET` | `/api/test` | API health check |

## 🎨 Frontend Features

### **Pages Available**
- **Login Page** (`/login.html`) - Secure login with reCAPTCHA and dark theme
- **Registration Page** (`/register.html`) - Account creation with validation
- **Dashboard** (`/dashboard.html`) - User profile and session management with dark theme
- **Password Change** (`/change-password.html`) - Secure password updates
- **Password Reset** (`/forgot-password.html`) - Email-based password recovery
- **OTP Verification** (`/otp-verification.html`) - Multi-factor authentication with dark theme
- **MFA Verification** (`/mfa-verify.html`) - Enhanced MFA flow

### **Dark Theme Implementation**
- **Modern Dark Tech Design**: Professional charcoal black (#212A31) and slate gray (#2e3944) color palette
- **Glass Morphism Effects**: Advanced backdrop-filter effects with Safari compatibility
- **Responsive Animations**: Smooth micro-interactions and loading states
- **Enhanced Notifications**: Dark theme SweetAlert2 and notification dropdowns
- **Accessibility**: High contrast support and reduced motion preferences

### **UI Components**
- **Password Strength Meter**: Real-time password validation with visual feedback
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
- Cross-device security alerts

### **Advanced Session Monitoring**
- **Device Fingerprinting**: Comprehensive hardware and software identification
- **Behavioral Analysis**: Mouse patterns, keyboard timing, and interaction analysis
- **Geographic Tracking**: Location-based anomaly detection
- **Concurrent Session Limits**: Configurable maximum device connections
- **Real-Time Threat Response**: Automatic security lockdown procedures

### **Password Expiry Monitoring**
The system automatically monitors password expiry with:
- **Daily Checks**: Automated background scanning every 24 hours
- **7-Day Warnings**: Proactive email notifications for expiring passwords
- **Forced Changes**: Automatic redirection for expired passwords
- **Statistics**: Real-time expiry tracking and reporting

## 🚀 Production Deployment

### **Environment Setup**
```bash
# Set production environment
export NODE_ENV=production

# Use strong secrets (generate new ones)
JWT_SECRET=<64-character-random-string>
SESSION_SECRET=<64-character-random-string>
ENCRYPTION_KEY=<128-character-hex-string>

# Configure secure database
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/securesystem

# Enable HSTS (recommended)
HSTS_ENABLED=true
HSTS_MAX_AGE=31536000
HSTS_INCLUDE_SUBDOMAINS=true
HSTS_PRELOAD=true
```

### **Security Checklist**
- ✅ Enable HTTPS/SSL certificates
- ✅ Configure proper CORS origins
- ✅ Use MongoDB Atlas or secured instance
- ✅ Set up process manager (PM2)
- ✅ Configure log rotation
- ✅ Set up automated backups
- ✅ Monitor performance and security metrics
- ✅ Regular security audits and dependency updates

## 🧪 Testing

### **Security Test Scenarios**
1. **Brute Force Protection**: Verify 3-attempt account lockout
2. **IP Blocking**: Confirm 10-attempt IP-level blocking
3. **Password Expiry**: Validate 30-day automatic expiry
4. **Session Timeout**: Test 3-minute inactivity logout
5. **Advanced Session Security**: Test cross-device notifications and lockdown
6. **CSRF Protection**: Verify token validation
7. **XSS Prevention**: Test input sanitization

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

# Test session security
# 1. Login from multiple devices
# 2. Test cross-device notifications
# 3. Verify security lockdown functionality
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

- **Installation Guide**: See `INSTALL.md` for detailed setup instructions
- **Security Documentation**: See `COMPREHENSIVE_SECURITY_DOCUMENTATION.md` for complete security features
- **Session Management**: See `ADVANCED_SESSION_MANAGEMENT.md` for advanced session security details
- **Technology Stack**: See `COMPLETE_TECH_STACK_REPORT.md` for detailed technical analysis
- **API Documentation**: All endpoints documented above with rate limits and authentication requirements

## 🔄 Version History

- **v1.0.0**: Initial release with core authentication features
- **Enhanced Security**: Added brute force protection and password expiry
- **UI Improvements**: Modern responsive dark theme with glass morphism effects
- **Advanced Session Management**: Multi-device session control and security monitoring
- **Advanced Monitoring**: Real-time security event tracking and notifications
- **HSTS Implementation**: Force HTTPS connections with configurable security headers

---

**⚠️ Security Notice**: This system implements enterprise-grade security features. Always use HTTPS in production, keep dependencies updated, and follow security best practices for deployment.

**🎯 Perfect for**: Enterprise applications, SaaS platforms, secure portals, customer authentication systems, and any application requiring robust security controls with advanced session management.

**💻 Technology Stack**: Node.js, Express, MongoDB, Mongoose, JWT, bcrypt, Helmet.js, and modern vanilla JavaScript with dark theme CSS.
#   D e p l o y m e n t   t r i g g e r   0 6 / 2 5 / 2 0 2 5   1 3 : 5 5 : 5 2  
 