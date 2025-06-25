import passwordValidator from './password-validator.js';

class PasswordStrengthMeter {
    constructor(options = {}) {
        this.options = {
            passwordInput: null,
            strengthMeter: null,
            strengthText: null,
            requirementsList: null,
            generateButton: null,
            onStrengthChange: null,
            ...options
        };

        // Define strength colors
        this.strengthColors = {
            weak: '#ff4d4d',
            average: '#ffc107',
            strong: '#28a745',
            'very strong': '#006400'
        };

        // Define strength text
        this.strengthText = {
            weak: '🔴 Weak',
            average: '🟡 Average',
            strong: '🟢 Strong',
            'very strong': '🟢 Very Strong'
        };

        this.init();
    }

    init() {
        if (!this.options.passwordInput) {
            console.error('Password input element is required');
            return;
        }

        // Initialize strength meter if provided
        if (this.options.strengthMeter) {
            this.updateStrengthMeter(0);
        }

        // Initialize requirements list if provided
        if (this.options.requirementsList) {
            this.updateRequirementsList('');
        }

        // Add event listeners
        this.options.passwordInput.addEventListener('input', this.handlePasswordInput.bind(this));
        this.options.passwordInput.addEventListener('focus', this.showRequirements.bind(this));
        this.options.passwordInput.addEventListener('blur', this.hideRequirements.bind(this));

        // Add generate button if provided
        if (this.options.generateButton) {
            this.options.generateButton.addEventListener('click', this.handleGeneratePassword.bind(this));
        }
    }

    handlePasswordInput(event) {
        const password = event.target.value;
        const result = passwordValidator.validatePassword(password);

        // Update strength meter
        if (this.options.strengthMeter) {
            this.updateStrengthMeter(result.score);
        }

        // Update strength text
        if (this.options.strengthText) {
            this.updateStrengthText(result.level);
        }

        // Update requirements list
        if (this.options.requirementsList) {
            this.updateRequirementsList(password);
        }

        // Call callback if provided
        if (this.options.onStrengthChange) {
            this.options.onStrengthChange(result);
        }
    }

    updateStrengthMeter(score) {
        const meter = this.options.strengthMeter;
        
        // Remove all existing classes
        meter.className = 'strength-meter';
        
        // Set width based on score
        meter.style.width = `${score}%`;
        
        // Add appropriate class based on score
        if (score >= 90) {
            meter.classList.add('very-strong');
            meter.style.backgroundColor = this.strengthColors['very strong'];
            // Ensure very strong passwords show 100% width
            if (score === 100) {
                meter.style.width = '100%';
            }
        } else if (score >= 70) {
            meter.classList.add('strong');
            meter.style.backgroundColor = this.strengthColors.strong;
        } else if (score >= 50) {
            meter.classList.add('average');
            meter.style.backgroundColor = this.strengthColors.average;
        } else {
            meter.classList.add('weak');
            meter.style.backgroundColor = this.strengthColors.weak;
        }
    }

    updateStrengthText(level) {
        const text = this.options.strengthText;
        
        // Remove all existing classes
        text.className = 'strength-text';
        
        // Set text and add appropriate class
        text.textContent = this.strengthText[level];
        text.style.color = this.strengthColors[level];
    }

    updateRequirementsList(password) {
        const list = this.options.requirementsList;
        const result = passwordValidator.validatePassword(password);

        // Update each requirement with corrected criteria (12+ chars, 2 of each type)
        const requirements = [
            { id: 'reqLength', met: password.length >= 12, text: 'At least 12 characters' },
            { id: 'reqUppercase', met: (password.match(/[A-Z]/g) || []).length >= 2, text: 'At least 2 uppercase letters' },
            { id: 'reqLowercase', met: (password.match(/[a-z]/g) || []).length >= 2, text: 'At least 2 lowercase letters' },
            { id: 'reqNumber', met: (password.match(/[0-9]/g) || []).length >= 2, text: 'At least 2 numbers' },
            { id: 'reqSpecial', met: (password.match(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/g) || []).length >= 2, text: 'At least 2 special characters' }
        ];

        requirements.forEach(req => {
            const element = document.getElementById(req.id);
            if (element) {
                // Remove all existing classes
                element.className = '';
                
                // Add appropriate class
                if (req.met) {
                    element.classList.add('requirement-met');
                }
                
                // Update icon
                const icon = element.querySelector('i');
                if (icon) {
                    icon.className = req.met ? 'fas fa-check' : 'fas fa-times';
                }
                
                // Update tooltip
                element.setAttribute('title', req.text);
            }
        });
    }

    handleGeneratePassword() {
        const password = passwordValidator.generateSecurePassword();
        this.options.passwordInput.value = password;
        
        // Trigger input event to update strength meter
        const event = new Event('input', { bubbles: true });
        this.options.passwordInput.dispatchEvent(event);

        // Focus the input
        this.options.passwordInput.focus();
    }

    showRequirements() {
        if (this.options.requirementsList) {
            this.options.requirementsList.style.display = 'block';
        }
    }

    hideRequirements() {
        if (this.options.requirementsList) {
            // Only hide if password is valid
            const password = this.options.passwordInput.value;
            const result = passwordValidator.validatePassword(password);
            if (!result.valid) {
                this.options.requirementsList.style.display = 'block';
            } else {
                this.options.requirementsList.style.display = 'none';
            }
        }
    }

    setUserContext(username, email, lastThreePasswords = []) {
        passwordValidator.setUserContext(username, email, lastThreePasswords);
    }

    validatePassword(password) {
        return passwordValidator.validatePassword(password);
    }
}

export default PasswordStrengthMeter; 