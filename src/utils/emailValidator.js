/**
 * Email validation utility for secure system
 * This module provides comprehensive email validation including:
 * - Format validation
 * - Allowed domain validation
 * - Disposable email domain blocking
 */

// Regular expression for basic email format validation
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

// List of allowed email providers
const ALLOWED_DOMAINS = [
    'gmail.com',
    'yahoo.com',
    'outlook.com',
    'hotmail.com',
    'protonmail.com', // Added for additional security-focused users
    'icloud.com'      // Added for Apple users
];

// List of known disposable/temporary email domains
const DISPOSABLE_DOMAINS = [
    // Common temporary email services
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
    
    // Guerrilla mail variants
    'guerrillamail.info',
    'guerrillamail.biz',
    'guerrillamail.de',
    'guerrillamail.net',
    'guerrillamail.org',
    'guerrillamailblock.com',
    
    // Trash mail variants
    'trashmail.com',
    'trashmail.net',
    'trashmail.me',
    'trashmail.io',
    'trashmail.ws',
    'trashmail.xyz',
    
    // Spam4.me and variants
    'spam4.me',
    'spamgourmet.com',
    'spambox.us',
    'spamfree24.org',
    'spamfree24.de',
    'spamfree24.eu',
    'spamhole.com',
    'spaml.de',
    'spamstack.net',
    
    // More temporary mail services
    'tempmail.ninja',
    'tempmailaddress.com',
    'tempmailbox.com',
    'tempmailgen.com',
    'tempmail.email',
    'temp-mail.io',
    'temp-mail.ru',
    'tempmail.us.com',
    'tempmail.de',
    'tempmail.fr',
    'temporaryemail.com',
    'temporaryemail.net',
    'temporarymail.org',
    'temporaryinbox.com',
    
    // Popular disposable services that users often try
    'mohmal.com',
    'mailcatch.com',
    'mailnesia.com',
    'mailexpire.com',
    'maildea.com',
    'maildu.de',
    'mail-temp.com',
    'mail-temporaire.fr',
    'emailondeck.com',
    'emaildrop.io',
    'emailtemporanea.net',
    'dispostable.com',
    'disposableemailaddresses.com',
    'discard.email',
    'disposable.email',
    'disposableinbox.com',
    'disposablemail.com',
    'disposable-email.ml',
    'disposeamail.com',
    
    // 10 minute mail variants
    '10minutemail.org',
    '10minutemail.net',
    '10minutemail.cf',
    '10minutemail.ga',
    '10minutemail.gq',
    '10minutemail.ml',
    '10minutemail.tk',
    '20minutemail.com',
    '20minutemail.it',
    '30minutemail.com',
    
    // Additional commonly used temporary services
    'nada.email',
    'email-temp.com',
    'burnermail.io',
    'burntheemail.com',
    'throwaway.email',
    'deadaddress.com',
    'meltmail.com',
    'mytrashmail.com',
    'nowmymail.com',
    'shortmail.net',
    'sneakemail.com',
    'tempail.com',
    'tempemail.com',
    'tempemail.net',
    'tempemail.org',
    'tempomail.fr',
    'tempymail.com',
    'trash2009.com',
    'trashdevil.com',
    'trashemail.de',
    'trashymail.com',
    'tyldd.com',
    'yopmail.net',
    'yopmail.fr',
    'yopmail.org',
    'zoemail.org',
    
    // Additional domains commonly used for temporary emails
    'hosliy.com',
    'haptara.com',
    'mailproxsy.com',
    'incognitomail.org',
    'incognitomail.com',
    'anonbox.net',
    'anonymousemail.me',
    'filzmail.com',
    'fakemail.fr',
    'fakeemailgenerator.com',
    'fakemailz.com',
    'harakirimail.com',
    'hidemail.de',
    'kasmail.com',
    'klzlk.com',
    'kurzepost.de',
    'libox.fr',
    'loadby.us',
    'lroid.com',
    'mt2009.com',
    'mt2014.com',
    'mytrashmailer.com',
    'no-spam.ws',
    'nobulk.com',
    'noclickemail.com',
    'nogmailspam.info',
    'nomail.xl.cx',
    'nomail2me.com',
    'nospam.ze.tc',
    'notmailinator.com',
    'objectmail.com',
    'obobbo.com',
    'onewaymail.com',
    'pookmail.com',
    'proxymail.eu',
    'rcpt.at',
    'sandboxmail.org',
    'selfdestructingmail.com',
    'sendspamhere.com',
    'shiftmail.com',
    'sibmail.com',
    'smellfear.com',
    'snakemail.com',
    'snkmail.com',
    'sofort-mail.de',
    'sogetthis.com',
    'soodonims.com',
    'spam.la',
    'spamavert.com',
    'spambob.com',
    'spambob.net',
    'spambob.org',
    'spambog.com',
    'spambog.de',
    'spambog.ru',
    'spambox.info',
    'spamcannon.com',
    'spamcannon.net',
    'spamcon.org',
    'spamcorptastic.com',
    'spamcowboy.com',
    'spamcowboy.net',
    'spamcowboy.org',
    'spamday.com',
    'spamex.com',
    'spamfree24.com',
    'spamgoes.com',
    'spamhere.com',
    'spamhereplease.com',
    'spamify.com',
    'spaminator.de',
    'spamkill.info',
    'spaml.com',
    'spammotel.com',
    'spamobox.com',
    'spamoff.de',
    'spamslicer.com',
    'spamspot.com',
    'spamthis.co.uk',
    'spamthisplease.com',
    'spamtrail.com',
    'spamtroll.net',
    'super-auswahl.de',
    'supergreatmail.com',
    'supermailer.jp',
    'superrito.com',
    'tagyourself.com',
    'teewars.org',
    'tempalias.com',
    'tempe-mail.com',
    'tempemail.biz',
    'tempinbox.co.uk',
    'tempinbox.com',
    'tempmail.eu',
    'tempmail2.com',
    'tempmaildemo.com',
    'tempmailer.com',
    'tempmailer.de'
];

/**
 * Validates an email address format
 * @param {string} email - The email address to validate
 * @returns {boolean} - True if the email format is valid
 */
function isValidEmailFormat(email) {
    return EMAIL_REGEX.test(email);
}

/**
 * Checks if the email domain is from an allowed provider
 * @param {string} email - The email address to check
 * @returns {boolean} - True if the domain is allowed
 */
function isAllowedDomain(email) {
    const domain = email.split('@')[1].toLowerCase();
    return ALLOWED_DOMAINS.includes(domain);
}

/**
 * Checks if the email domain is from a disposable/temporary email service
 * @param {string} email - The email address to check
 * @returns {boolean} - True if the domain is disposable
 */
function isDisposableDomain(email) {
    const domain = email.split('@')[1].toLowerCase();
    return DISPOSABLE_DOMAINS.includes(domain);
}

/**
 * Comprehensive email validation
 * @param {string} email - The email address to validate
 * @returns {Object} - Validation result with status and message
 */
function validateEmail(email) {
    // Check if email is empty
    if (!email) {
        return {
            isValid: false,
            message: 'Email address is required.'
        };
    }

    // Check email format
    if (!isValidEmailFormat(email)) {
        return {
            isValid: false,
            message: 'Invalid email format. Please enter a valid email address.'
        };
    }

    // Check if domain is allowed
    if (!isAllowedDomain(email)) {
        return {
            isValid: false,
            message: 'Only emails from Gmail, Yahoo, Outlook, Hotmail, ProtonMail, and iCloud are accepted.'
        };
    }

    // Check if domain is disposable
    if (isDisposableDomain(email)) {
        return {
            isValid: false,
            message: 'Temporary or disposable email addresses are not allowed.'
        };
    }

    // All checks passed
    return {
        isValid: true,
        message: 'Email is valid.'
    };
}

module.exports = {
    validateEmail,
    isValidEmailFormat,
    isAllowedDomain,
    isDisposableDomain
}; 