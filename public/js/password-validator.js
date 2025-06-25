// Password validation constants - Updated to match exact requirements
const PASSWORD_REQUIREMENTS = {
    MIN_LENGTH: 12,
    MIN_UPPERCASE: 2,
    MIN_LOWERCASE: 2,
    MIN_NUMBERS: 2,
    MIN_SPECIAL: 2,
    STRONG_LENGTH: 12,
    VERY_STRONG_LENGTH: 16
};

// Common password blacklist
const COMMON_PASSWORDS = [
    'password', '123456', 'qwerty', 'admin', 'welcome',
    'letmein', 'monkey', 'dragon', 'baseball', 'football',
    'superman', 'trustno1', 'iloveyou', 'sunshine', 'master'
];

class PasswordValidator {
    constructor() {
        this.lastThreePasswords = [];
        this.username = '';
        this.email = '';
    }

    setUserContext(username, email, lastThreePasswords = []) {
        this.username = username.toLowerCase();
        this.email = email.toLowerCase();
        this.lastThreePasswords = lastThreePasswords;
    }

    validatePassword(password) {
        const errors = [];
        const result = {
            level: 'weak',
            score: 0,
            valid: false,
            errors: []
        };

        // Check minimum length (12 characters)
        if (password.length < PASSWORD_REQUIREMENTS.MIN_LENGTH) {
            errors.push(`Password must be at least ${PASSWORD_REQUIREMENTS.MIN_LENGTH} characters long`);
        }

        // Count character types
        const uppercaseCount = (password.match(/[A-Z]/g) || []).length;
        const lowercaseCount = (password.match(/[a-z]/g) || []).length;
        const numberCount = (password.match(/[0-9]/g) || []).length;
        const specialCount = (password.match(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/g) || []).length;

        // Check character type requirements (2 of each)
        if (uppercaseCount < PASSWORD_REQUIREMENTS.MIN_UPPERCASE) {
            errors.push(`Include at least ${PASSWORD_REQUIREMENTS.MIN_UPPERCASE} uppercase letters`);
        }
        if (lowercaseCount < PASSWORD_REQUIREMENTS.MIN_LOWERCASE) {
            errors.push(`Include at least ${PASSWORD_REQUIREMENTS.MIN_LOWERCASE} lowercase letters`);
        }
        if (numberCount < PASSWORD_REQUIREMENTS.MIN_NUMBERS) {
            errors.push(`Include at least ${PASSWORD_REQUIREMENTS.MIN_NUMBERS} numbers`);
        }
        if (specialCount < PASSWORD_REQUIREMENTS.MIN_SPECIAL) {
            errors.push(`Include at least ${PASSWORD_REQUIREMENTS.MIN_SPECIAL} special characters`);
        }

        // Check against username and email
        if (this.username && password.toLowerCase().includes(this.username)) {
            errors.push('Password cannot contain your username');
        }
        if (this.email && password.toLowerCase().includes(this.email.split('@')[0])) {
            errors.push('Password cannot contain your email address');
        }

        // Check against common passwords
        if (COMMON_PASSWORDS.includes(password.toLowerCase())) {
            errors.push('Password is too common - choose a more unique password');
        }

        // Check for repeated characters (4 or more in a row)
        if (/(.)\1{3,}/.test(password)) {
            errors.push('Password cannot contain 4 or more repeated characters');
        }

        // Check for sequential characters
        if (/1234|2345|3456|4567|5678|6789|0123|abcd|bcde|cdef|defgh|efgh|fghi|ghij|hijkl|ijklm|jklmn|klmno|lmnop|mnopq|nopqr|opqrs|pqrst|qrstu|rstuv|stuvw|tuvwx|uvwxy|vwxyz/.test(password.toLowerCase())) {
            errors.push('Password cannot contain sequential characters');
        }

        // Calculate password strength based on exact requirements
        let score = 0;
        
        // Check if meets all basic requirements
        const meetsAllRequirements = password.length >= PASSWORD_REQUIREMENTS.MIN_LENGTH && 
            uppercaseCount >= PASSWORD_REQUIREMENTS.MIN_UPPERCASE &&
            lowercaseCount >= PASSWORD_REQUIREMENTS.MIN_LOWERCASE &&
            numberCount >= PASSWORD_REQUIREMENTS.MIN_NUMBERS &&
            specialCount >= PASSWORD_REQUIREMENTS.MIN_SPECIAL;
        
        if (meetsAllRequirements) {
            score = 70; // Base score for meeting all requirements (Strong threshold)
        } else {
            // If doesn't meet basic requirements, it's weak or average at best
            score = 30;
        }
        
        // Length-based scoring for Strong vs Very Strong
        if (password.length >= PASSWORD_REQUIREMENTS.VERY_STRONG_LENGTH && meetsAllRequirements) {
            score = 100; // Very Strong: 16+ chars with all requirements (full green bar)
        } else if (password.length >= PASSWORD_REQUIREMENTS.STRONG_LENGTH && meetsAllRequirements) {
            score = 80; // Strong: 12-15 chars with all requirements
        }
        
        // Penalties for weak patterns
        if (/(.)\1{2,}/.test(password)) score -= 10; // Repeated characters
        if (/1234|abcd|qwer/i.test(password)) score -= 15; // Sequential patterns
        if (COMMON_PASSWORDS.some(common => password.toLowerCase().includes(common))) score -= 20;
        if (this.username && password.toLowerCase().includes(this.username)) score -= 25;
        if (this.email && password.toLowerCase().includes(this.email.split('@')[0])) score -= 25;
        
        // Determine strength level based on exact requirements
        if (password.length >= PASSWORD_REQUIREMENTS.VERY_STRONG_LENGTH && 
            meetsAllRequirements && 
            score >= 90) {
            result.level = 'very strong';
        } else if (password.length >= PASSWORD_REQUIREMENTS.STRONG_LENGTH && 
                   meetsAllRequirements && 
                   score >= 70) {
            result.level = 'strong';
        } else if (password.length >= 8 && 
                   uppercaseCount >= 1 && lowercaseCount >= 1 && 
                   numberCount >= 1 && specialCount >= 1) {
            result.level = 'average';
        } else {
            result.level = 'weak';
        }

        result.score = Math.min(Math.max(score, 0), 100);
        
        // Only accept Strong or Very Strong passwords (reject Weak and Average)
        result.valid = errors.length === 0 && (result.level === 'strong' || result.level === 'very strong');
        result.errors = errors;

        return result;
    }

    generateSecurePassword() {
        const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const lowercase = 'abcdefghijklmnopqrstuvwxyz';
        const numbers = '0123456789';
        const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';

        const getRandomChars = (chars, count) => {
            let result = '';
            for (let i = 0; i < count; i++) {
                result += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            return result;
        };

        const shuffle = (str) => {
            const array = str.split('');
            for (let i = array.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [array[i], array[j]] = [array[j], array[i]];
            }
            return array.join('');
        };

        // Generate a 16-character password for "Very Strong" rating
        const password = 
            getRandomChars(uppercase, 2) +
            getRandomChars(lowercase, 4) +
            getRandomChars(numbers, 2) +
            getRandomChars(special, 2) +
            getRandomChars(uppercase + lowercase + numbers + special, 6); // Extra characters for 16 total

        return shuffle(password);
    }
}

// Create and export a singleton instance
const passwordValidator = new PasswordValidator();
export default passwordValidator; 