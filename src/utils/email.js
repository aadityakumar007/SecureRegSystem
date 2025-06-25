const nodemailer = require('nodemailer');
const config = require('../config/config');

// Create reusable transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Common email template styles
const styles = `
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; padding: 20px 0; }
        .content { background: #f9f9f9; padding: 20px; border-radius: 5px; }
        .otp { 
            background: #f4f4f4; 
            padding: 15px; 
            text-align: center; 
            font-size: 24px; 
            letter-spacing: 5px; 
            margin: 20px 0;
            border-radius: 5px;
        }
        .footer { 
            text-align: center; 
            margin-top: 20px; 
            padding-top: 20px; 
            border-top: 1px solid #eee;
            font-size: 12px;
            color: #666;
        }
        .button {
            display: inline-block;
            padding: 10px 20px;
            background: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin: 20px 0;
        }
        .warning {
            background: #fff3cd;
            color: #856404;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
    </style>
`;

// Generate 6-digit OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

/**
 * Send verification email
 * @param {string} email - User's email address
 * @param {string} username - User's username
 * @param {string} token - Verification token
 * @returns {Promise<boolean>} Success status
 */
async function sendVerificationEmail(email, username, token) {
    try {
        const verificationUrl = `${config.baseUrl}/verify-email?token=${token}`;
        
        const mailOptions = {
            from: config.email.user,
            to: email,
            subject: 'Verify Your Email Address',
            html: `
                <!DOCTYPE html>
                <html>
                <head>${styles}</head>
                <body>
                    <div class="container">
                        <div class="header">
                <h1>Welcome to Our Platform!</h1>
                        </div>
                        <div class="content">
                            <p>Hello ${username},</p>
                            <p>Thank you for registering! Please verify your email address by clicking the button below:</p>
                            <div style="text-align: center;">
                                <a href="${verificationUrl}" class="button">Verify Email</a>
                            </div>
                <p>This link will expire in 24 hours.</p>
                            <div class="warning">
                                <strong>Security Tip:</strong> Never share this verification link with anyone.
                            </div>
                        </div>
                        <div class="footer">
                <p>If you did not create an account, please ignore this email.</p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('Error sending verification email:', error);
        return false;
    }
}

/**
 * Send password reset email
 * @param {string} email - User's email address
 * @param {string} username - User's username
 * @param {string} token - Reset token
 * @returns {Promise<boolean>} Success status
 */
async function sendPasswordResetEmail(email, username, token) {
    try {
        const resetUrl = `${config.baseUrl}/reset-password?token=${token}`;
        
        const mailOptions = {
            from: config.email.user,
            to: email,
            subject: 'Reset Your Password',
            html: `
                <!DOCTYPE html>
                <html>
                <head>${styles}</head>
                <body>
                    <div class="container">
                        <div class="header">
                <h1>Password Reset Request</h1>
                        </div>
                        <div class="content">
                            <p>Hello ${username},</p>
                            <p>You requested to reset your password. Click the button below to proceed:</p>
                            <div style="text-align: center;">
                                <a href="${resetUrl}" class="button">Reset Password</a>
                            </div>
                <p>This link will expire in 1 hour.</p>
                            <div class="warning">
                                <strong>Security Tip:</strong> If you did not request this password reset, please secure your account immediately.
                            </div>
                        </div>
                        <div class="footer">
                <p>If you did not request a password reset, please ignore this email.</p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('Error sending password reset email:', error);
        return false;
    }
}

// Send OTP email
async function sendOTP(email, otp, username) {
        const mailOptions = {
        from: process.env.EMAIL_USER,
            to: email,
        subject: 'Your Verification Code - Secure System',
            html: `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Verification Code</title>
            </head>
            <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <!-- Header -->
                    <div style="background-color: #2c3e50; padding: 20px; text-align: center; border-radius: 5px 5px 0 0;">
                        <h1 style="color: #ffffff; margin: 0; font-size: 24px;">Verification Code</h1>
                    </div>

                    <!-- Main Content -->
                    <div style="background-color: #ffffff; padding: 30px; border-radius: 0 0 5px 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <!-- Greeting -->
                        <p style="color: #333333; font-size: 16px; margin-bottom: 20px;">
                            Hello <strong>${username}</strong>,
                        </p>

                        <!-- OTP Section -->
                        <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; text-align: center;">
                            <p style="color: #666666; font-size: 14px; margin-bottom: 10px;">Your verification code is:</p>
                            <div style="background-color: #ffffff; padding: 15px; border: 2px dashed #2c3e50; border-radius: 5px; display: inline-block;">
                                <span style="color: #2c3e50; font-size: 32px; font-weight: bold; letter-spacing: 5px;">${otp}</span>
                            </div>
                        </div>

                        <!-- Expiry Notice -->
                        <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0;">
                            <p style="color: #856404; margin: 0; font-size: 14px;">
                                <strong>⚠️ Important:</strong> This code will expire in 2 minutes.
                            </p>
                        </div>

                        <!-- Security Warning -->
                        <div style="background-color: #f8d7da; padding: 15px; border-radius: 5px; margin: 20px 0;">
                            <p style="color: #721c24; margin: 0; font-size: 14px;">
                                <strong>Security Notice:</strong> If you didn't request this code, please ignore this email and ensure your account is secure.
                            </p>
                        </div>

                        <!-- Footer -->
                        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eeeeee;">
                            <p style="color: #666666; font-size: 12px; margin: 0;">
                                This is an automated message from Secure System. Please do not reply to this email.
                            </p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            `
        };

    try {
        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('Email sending error:', error);
        return false;
    }
}

module.exports = {
    sendVerificationEmail,
    sendPasswordResetEmail,
    sendOTP,
    generateOTP,
    sendEmail
};

/**
 * Generic email sending function for notifications
 * @param {string} to - Recipient email address
 * @param {string} subject - Email subject
 * @param {string} html - HTML content
 * @returns {Promise<boolean>} Success status
 */
async function sendEmail(to, subject, html) {
    try {
        const mailOptions = {
            from: process.env.EMAIL_USER || config.email.user,
            to: to,
            subject: subject,
            html: html
        };

        await transporter.sendMail(mailOptions);
        console.log(`Email sent successfully to: ${to}`);
        return true;
    } catch (error) {
        console.error('Generic email sending error:', error);
        return false;
    }
}