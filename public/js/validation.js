// Password validation rules - Updated to match new strict criteria
const PASSWORD_RULES = {
    minLength: 12,
    minUppercase: 2,
    minLowercase: 2,
    minNumbers: 2,
    minSpecial: 2
};

// Password strength levels
const PASSWORD_STRENGTH = {
    WEAK: 'weak',
    AVERAGE: 'average',
    STRONG: 'strong',
    VERY_STRONG: 'very_strong'
};

// Show popup message
function showPopup(title, message, type = 'error') {
    Swal.fire({
        title: title,
        html: message,
        icon: type,
        confirmButtonColor: '#3498db',
        confirmButtonText: 'OK',
        allowOutsideClick: true,
        allowEscapeKey: true
    });
}

// Enhanced password strength checker with exact criteria matching register.js
function checkPasswordStrength(password) {
    if (!password) return PASSWORD_STRENGTH.WEAK;
    
    // Check minimum length (12 characters)
    if (password.length < 12) {
        return PASSWORD_STRENGTH.WEAK;
    }
    
    // Count character types
    const uppercaseCount = (password.match(/[A-Z]/g) || []).length;
    const lowercaseCount = (password.match(/[a-z]/g) || []).length;
    const numberCount = (password.match(/\d/g) || []).length;
    const specialCount = (password.match(/[!@#$%^&*(),.?":{}|<>]/g) || []).length;
    
    // Check if it meets the basic requirements (2 of each type)
    const meetsBasicRequirements = 
        uppercaseCount >= 2 && 
        lowercaseCount >= 2 && 
        numberCount >= 2 && 
        specialCount >= 2;
    
    if (!meetsBasicRequirements) {
        return password.length >= 8 ? PASSWORD_STRENGTH.AVERAGE : PASSWORD_STRENGTH.WEAK;
    }
    
    // Check for common patterns
    const hasCommonPatterns = 
        /(.)\1{3,}/.test(password) || // 4+ repeated characters
        /1234|2345|3456|4567|5678|6789|0123/.test(password) || // sequential numbers
        /abcde|bcdef|cdefg|defgh|efghi|fghij|ghijk|hijkl|ijklm|jklmn|klmno|lmnop|mnopq|nopqr|opqrs|pqrst|rstuv|stuvw|tuvwx|uvwxy|vwxyz/.test(password.toLowerCase()) || // sequential letters (5+ chars)
        /password|123456|qwerty|admin|login|welcome|secret/.test(password.toLowerCase()); // common words
    
    if (hasCommonPatterns) {
        return PASSWORD_STRENGTH.AVERAGE;
    }
    
    // Determine strength based on length and complexity
    if (password.length > 12) {
        // Very Strong: More than 12 characters + meets all requirements
    return PASSWORD_STRENGTH.VERY_STRONG;
    } else {
        // Strong: Exactly 12 characters + meets all requirements
        return PASSWORD_STRENGTH.STRONG;
    }
}

// Password validation with updated strict requirements
function validatePassword(password, username, email) {
    const strength = checkPasswordStrength(password);
    
    // Only Strong and Very Strong passwords are allowed
    if (strength === PASSWORD_STRENGTH.WEAK) {
        showPopup(
            '🔐 Password Requirements',
            `
            <div style="text-align: left;">
                <p><strong>Password Requirements:</strong></p>
                
                <p>✅ <strong>Minimum Length:</strong></p>
                <ul>
                    <li>At least 12 characters</li>
                </ul>
                
                <p>✅ <strong>Character Requirements:</strong></p>
                <ul>
                    <li>2 uppercase letters (A–Z)</li>
                    <li>2 lowercase letters (a–z)</li>
                    <li>2 numbers (0–9)</li>
                    <li>2 special characters (! @ # $ % ^ & * etc.)</li>
                </ul>
                
                <p>💡 Only "Strong" or "Very Strong" passwords are allowed.</p>
            </div>
            `
        );
        return false;
    }
    
    if (strength === PASSWORD_STRENGTH.AVERAGE) {
        showPopup(
            '🚫 Password Rejected',
            `
            <div style="text-align: left;">
                <p><strong>Password rejected due to security concerns:</strong></p>
                
                <p>🚫 <strong>Restrictions:</strong></p>
                <ul>
                    <li>Do NOT use your name, username, email, or company name</li>
                    <li>Avoid personal info, dictionary words, or patterns like "1234" or "aaaa"</li>
                    <li>Password must not match your username or email</li>
                </ul>
                
                <p><strong>Strength Meter:</strong></p>
                <ul style="list-style: none; padding-left: 0;">
                    <li>🔴 Weak → ❌ Rejected</li>
                    <li>🟡 Average → ❌ Rejected</li>
                    <li>🟢 Strong → ✅ Accepted</li>
                    <li>🟢 Very Strong → ✅ Accepted</li>
                </ul>
                
                <p>💡 Only "Strong" or "Very Strong" passwords are allowed.</p>
            </div>
            `
        );
        return false;
    }
    
    // Check if password contains username or email (if they exist and are not empty)
    if (username && password.toLowerCase().includes(username.toLowerCase())) {
        showPopup(
            '❌ Password Security Issue',
            'Your password must not contain your username.<br>Please choose a more secure password.'
        );
        return false;
    }
    
    if (email && password.toLowerCase().includes(email.split('@')[0].toLowerCase())) {
        showPopup(
            '❌ Password Security Issue',
            'Your password must not contain your email address.<br>Please choose a more secure password.'
        );
        return false;
    }
    
    return true;
}

// Email validation
function validateEmail(email) {
    // Basic format validation
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
        showPopup(
            '❌ Invalid Email Format',
            'Please enter a valid email address.'
        );
        return false;
    }

    // Get domain from email
    const domain = email.split('@')[1].toLowerCase();

    // List of allowed domains
    const allowedDomains = [
        'gmail.com',
        'yahoo.com',
        'outlook.com',
        'hotmail.com',
        'protonmail.com',
        'icloud.com'
    ];

    // List of known disposable domains
    const disposableDomains = [
        'mailinator.com',
        'temp-mail.org',
        '10minutemail.com',
        'guerrillamail.com',
        'yopmail.com',
        'throwawaymail.com',
        'tempmail.com',
        'fakeinbox.com',
        'maildrop.cc',
        'getairmail.com',
        'sharklasers.com',
        'guerrillamail.info',
        'guerrillamail.biz',
        'guerrillamail.de',
        'guerrillamail.net',
        'guerrillamail.org',
        'guerrillamailblock.com',
        'spam4.me',
        'trashmail.com',
        'trashmail.net',
        'trashmail.me',
        'trashmail.io',
        'trashmail.ws',
        'trashmail.xyz',
        'tempmail.ninja'
    ];

    // Check if domain is allowed
    if (!allowedDomains.includes(domain)) {
        showPopup(
            '❌ Unsupported Email Provider',
            'Only emails from Gmail, Yahoo, Outlook, Hotmail, ProtonMail, and iCloud are accepted.<br>Please use a supported email provider.'
        );
        return false;
    }

    // Check if domain is disposable
    if (disposableDomains.includes(domain)) {
        showPopup(
            '❌ Disposable Email Detected',
            'Temporary or disposable email addresses are not allowed.<br>Please use a permanent email address.'
        );
        return false;
    }

    return true;
}

// Form validation
function validateRegistrationForm(username, email, password, confirmPassword) {
    // Check if all fields are filled
    if (!username || !email || !password || !confirmPassword) {
        showPopup(
            '⚠️ Registration Error',
            'All fields are required. Please complete the form before submitting.'
        );
        return false;
    }
    
    // Validate email
    if (!validateEmail(email)) {
        return false;
    }
    
    // Validate password
    if (!validatePassword(password, username, email)) {
        return false;
    }
    
    // Check if passwords match
    if (password !== confirmPassword) {
        showPopup(
            '❌ Password Mismatch',
            'The passwords do not match. Please make sure both passwords are identical.'
        );
        return false;
    }
    
    return true;
}

// Export functions to window.validation
window.validation = {
    validateRegistrationForm,
    validateEmail,
    validatePassword,
    checkPasswordStrength,
    showPopup
}; 