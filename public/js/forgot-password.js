document.addEventListener('DOMContentLoaded', function() {
    const forgotPasswordForm = document.getElementById('forgot-password-form');
    const emailInput = document.getElementById('email');
    const submitBtn = document.getElementById('submitBtn');
    const recaptchaResponse = document.getElementById('recaptchaResponse');

    console.log('[Forgot Password] Form elements initialized:', {
        form: !!forgotPasswordForm,
        email: !!emailInput,
        submitBtn: !!submitBtn,
        recaptchaResponse: !!recaptchaResponse
    });

    // Handle reCAPTCHA verification (this function is called from the global callback)
    window.onRecaptchaVerified = function(response) {
        console.log('[Forgot Password] reCAPTCHA verified');
        if (recaptchaResponse) {
        recaptchaResponse.value = response;
        }
        if (submitBtn) {
        submitBtn.disabled = false;
        }
        // Clear any reCAPTCHA errors
        const recaptchaError = document.getElementById('recaptcha-error');
        if (recaptchaError) {
            recaptchaError.style.display = 'none';
        }
    };

    // Handle reCAPTCHA expiration
    window.onRecaptchaExpired = function() {
        console.log('[Forgot Password] reCAPTCHA expired');
        if (recaptchaResponse) {
            recaptchaResponse.value = '';
        }
        if (submitBtn) {
            submitBtn.disabled = true;
        }
    };

    // Handle form submission
    if (forgotPasswordForm) {
        forgotPasswordForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            console.log('[Forgot Password] Form submission started');
            
            const email = emailInput.value.trim();
            
            // Validate email
            if (!email) {
                showFieldError('email', 'Email address is required');
                return;
            }
            
            if (!window.validation || !window.validation.validateEmail(email)) {
                showFieldError('email', 'Please enter a valid email address');
                return;
            }

            // Check reCAPTCHA
            if (!recaptchaResponse.value) {
                showRecaptchaError('Please complete the reCAPTCHA verification');
                return;
            }

            try {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';

                // Get CSRF token before making the request
                console.log('[Forgot Password] Getting CSRF token...');
                const csrfResponse = await fetch('/api/csrf-token', {
                    credentials: 'include'
                });
                
                if (!csrfResponse.ok) {
                    throw new Error('Failed to get CSRF token');
                }
                
                const csrfData = await csrfResponse.json();
                const csrfToken = csrfData.csrfToken;
                console.log('[Forgot Password] CSRF token obtained');

                const requestBody = {
                    email: email,
                    recaptchaToken: recaptchaResponse.value,
                    _csrf: csrfToken
                };

                console.log('[Forgot Password] Sending request to /api/auth/forgot-password');
                const response = await fetch('/api/auth/forgot-password', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify(requestBody)
                });

                const data = await response.json();
                console.log('[Forgot Password] Response received:', { status: response.status, success: response.ok });

                if (!response.ok) {
                    throw new Error(data.message || 'Failed to process request');
                }

                // Show success message
                if (window.validation && window.validation.showPopup) {
                window.validation.showPopup(
                    '✅ Verification Code Sent',
                    'Please check your email for the verification code.',
                    'success'
                );
                } else {
                    alert('Verification code sent! Please check your email.');
                }

                // Reset form
                forgotPasswordForm.reset();
                recaptchaResponse.value = '';
                if (window.grecaptcha) {
                    grecaptcha.reset();
                }

                // Redirect to OTP verification page after a short delay
                setTimeout(() => {
                window.location.href = `/otp-verification.html?email=${encodeURIComponent(email)}&purpose=reset`;
                }, 2000);

            } catch (error) {
                console.error('[Forgot Password] Error:', error);
                
                // Show error message
                if (window.validation && window.validation.showPopup) {
                window.validation.showPopup(
                    '❌ Error',
                    error.message || 'An error occurred. Please try again.'
                );
                } else {
                    alert('Error: ' + (error.message || 'An error occurred. Please try again.'));
                }
                
                // Reset submit button
                if (submitBtn) {
                    submitBtn.disabled = !recaptchaResponse.value;
                    submitBtn.innerHTML = '<i class="fas fa-paper-plane"></i> Send Reset Link';
                }
            }
        });
    }

    // Helper function to show field-specific errors
    function showFieldError(fieldId, message) {
        const field = document.getElementById(fieldId);
        const errorDiv = document.getElementById(fieldId + '-error');
        
        if (field) {
            field.classList.add('error');
        }
        
        if (errorDiv) {
            errorDiv.innerHTML = `<i class="fas fa-exclamation-circle"></i>${message}`;
            errorDiv.style.display = 'flex';
        }
        
        console.log(`[Forgot Password] Field error for ${fieldId}: ${message}`);
    }

    // Helper function to show reCAPTCHA errors
    function showRecaptchaError(message) {
        const recaptchaError = document.getElementById('recaptcha-error');
        
        if (recaptchaError) {
            recaptchaError.innerHTML = `<i class="fas fa-exclamation-circle"></i>${message}`;
            recaptchaError.style.display = 'flex';
        }
        
        console.log(`[Forgot Password] reCAPTCHA error: ${message}`);
    }

    // Clear errors when user starts typing
    if (emailInput) {
        emailInput.addEventListener('input', function() {
            this.classList.remove('error');
            const errorDiv = document.getElementById('email-error');
            if (errorDiv) {
                errorDiv.style.display = 'none';
            }
        });
    }

    // Reset form when reset button is clicked (if any)
    if (forgotPasswordForm) {
    forgotPasswordForm.addEventListener('reset', function() {
            console.log('[Forgot Password] Form reset');
            if (recaptchaResponse) {
        recaptchaResponse.value = '';
            }
            if (submitBtn) {
        submitBtn.disabled = true;
            }
            if (window.grecaptcha) {
        grecaptcha.reset();
            }
    });
    }
}); 