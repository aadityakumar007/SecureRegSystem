// Add navigation function
function navigateTo(path) {
    window.location.replace(path);
}

// Add reCAPTCHA error handling
function handleRecaptchaError() {
    const errorDiv = document.getElementById('error');
    errorDiv.textContent = 'reCAPTCHA error. Please try again or contact support if the issue persists.';
    if (typeof grecaptcha !== 'undefined') {
        grecaptcha.reset();
    }
}

// Add reCAPTCHA callback
function onRecaptchaLoad() {
    console.log('reCAPTCHA loaded successfully');
    document.getElementById('recaptchaError').style.display = 'none';
    }

// Add reCAPTCHA expiration callback
function onRecaptchaExpired() {
    console.log('reCAPTCHA expired');
    showLoginError('error', 'reCAPTCHA verification expired. Please verify again.');
}

// Check if user is already logged in
if (isLoggedIn()) {
    navigateTo('/dashboard.html');
}

// Enhanced error message display with rich formatting for login
function showLoginError(elementId, message, additionalData = {}) {
    console.log('[Login Error] Showing error:', { elementId, message, additionalData });
    
    const errorDiv = document.getElementById(elementId);
    
    if (!errorDiv) {
        console.error(`Error element with ID '${elementId}' not found`);
        return;
    }
    
    // Clear any previous content
    errorDiv.innerHTML = '';
    
    // Create the main error message
    let errorContent = `<i class="fas fa-exclamation-circle"></i> ${message}`;
    
    // Add remaining attempts information if available
    if (additionalData.attemptsRemaining !== undefined && additionalData.attemptsRemaining >= 0) {
        errorContent += `<br><span style="color: #e67e22; font-weight: 600;">
            ⚠️ ${additionalData.attemptsRemaining} attempt${additionalData.attemptsRemaining === 1 ? '' : 's'} remaining before account lock
        </span>`;
    }
    
    // Add account lock information if available
    if (additionalData.isLocked || additionalData.lockRemaining) {
        const lockTime = additionalData.lockRemaining || 'some time';
        errorContent += `<br><span style="color: #e74c3c; font-weight: 600;">
            🔒 Account locked. Try again in ${lockTime} minute${lockTime === 1 ? '' : 's'}
        </span>`;
        
        // Show countdown timer if lock time is available
        if (typeof lockTime === 'number' && lockTime > 0) {
            showLockCountdown(lockTime);
        }
    }
    
    errorDiv.innerHTML = errorContent;
    errorDiv.style.display = 'flex';
    errorDiv.style.flexDirection = 'column';
    errorDiv.style.gap = '8px';
    
    console.log('[Login Error] Error div updated:', errorDiv);
    console.log('[Login Error] Error div display style:', errorDiv.style.display);
    console.log('[Login Error] Error div innerHTML:', errorDiv.innerHTML);
    
    // Scroll to error message
    errorDiv.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

// Show countdown timer for account lock
function showLockCountdown(lockMinutes) {
    const errorDiv = document.getElementById('error');
    if (!errorDiv) return;
    
    let remainingSeconds = lockMinutes * 60;
    
    const countdownElement = document.createElement('div');
    countdownElement.id = 'lockCountdown';
    countdownElement.className = 'lock-countdown';
    
    errorDiv.appendChild(countdownElement);
    
    const updateCountdown = () => {
        if (remainingSeconds <= 0) {
            countdownElement.className = 'lock-countdown unlocked';
            countdownElement.innerHTML = '✅ Account unlocked! You can try logging in again.';
            
            // Remove the countdown after 3 seconds and enable the form
            setTimeout(() => {
                if (countdownElement.parentNode) {
                    countdownElement.remove();
                }
                // Re-enable the login button and form inputs
                const loginButton = document.querySelector('button[type="submit"]');
                const usernameInput = document.getElementById('username');
                const passwordInput = document.getElementById('password');
                
                if (loginButton) {
                    loginButton.disabled = false;
                    loginButton.innerHTML = '<span class="btn-text"><i class="fas fa-sign-in-alt"></i> Sign In</span>';
                }
                if (usernameInput) usernameInput.disabled = false;
                if (passwordInput) passwordInput.disabled = false;
            }, 3000);
            return;
        }
        
        const minutes = Math.floor(remainingSeconds / 60);
        const seconds = remainingSeconds % 60;
        countdownElement.innerHTML = `
            ⏱️ Account locked for: <strong>${minutes}:${seconds.toString().padStart(2, '0')}</strong>
        `;
        
        remainingSeconds--;
        setTimeout(updateCountdown, 1000);
    };
    
    updateCountdown();
}

// Clear error message
function clearLoginError(elementId) {
    console.log('[Login Error] Clearing error for:', elementId);
    
    const errorDiv = document.getElementById(elementId);
    if (errorDiv) {
        errorDiv.innerHTML = '';
    errorDiv.style.display = 'none';
    }
    
    // Remove countdown if it exists
    const countdown = document.getElementById('lockCountdown');
    if (countdown) {
        countdown.remove();
    }
}

// Toggle password visibility - Updated for button-based toggle
function togglePasswordVisibility() {
    const passwordInput = document.getElementById('password');
    const toggleIcon = document.querySelector('.show-password i');
    
    if (passwordInput && toggleIcon) {
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleIcon.className = 'fas fa-eye-slash';
        } else {
            passwordInput.type = 'password';
            toggleIcon.className = 'fas fa-eye';
        }
    }
}

// Handle form submission
async function handleLogin(event) {
    event.preventDefault();
    
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const loginButton = document.querySelector('button[type="submit"]');

    // Clear any previous errors
    clearLoginError('error');

    // Basic validation
    if (!username || !password) {
        showLoginError('error', 'Username and password are required');
        return;
    }

    // Check if reCAPTCHA is loaded
    if (typeof grecaptcha === 'undefined') {
        showLoginError('error', 'reCAPTCHA is not loaded. Please refresh the page and try again.');
        return;
    }

    const recaptchaResponse = grecaptcha.getResponse();
    if (!recaptchaResponse) {
        showLoginError('error', 'Please complete the reCAPTCHA verification');
        return;
    }

    // Show pulsing dots loading animation
    loginButton.classList.add('loading');
    loginButton.disabled = true;
    const originalContent = loginButton.innerHTML;
    loginButton.innerHTML = '<span class="btn-text"><i class="fas fa-sign-in-alt"></i> Sign In</span>';

    try {
        console.log('[Login] Sending login request with:', {
            username,
            hasPassword: !!password,
            hasRecaptcha: !!recaptchaResponse
        });

        // Get CSRF token
        console.log('[Login] Getting CSRF token...');
        const csrfResponse = await fetch('/api/csrf-token', {
            credentials: 'include'
        });
        
        if (!csrfResponse.ok) {
            throw new Error('Failed to get CSRF token');
        }
        
        const csrfData = await csrfResponse.json();
        const csrfToken = csrfData.csrfToken;
        console.log('[Login] CSRF token obtained');
        
        // Prepare request body
        const requestBody = {
            username: username,
            password: password,
            recaptchaToken: recaptchaResponse,
            _csrf: csrfToken
        };
        
        console.log('[Login] Making login request...');

        const response = await fetch('/api/auth/login', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify(requestBody)
        });

        console.log('[Login] Response received, status:', response.status);
        const data = await response.json();
        console.log('[Login] Response data:', data);

        if (response.ok) {
            if (data.requiresMFA) {
                // Redirect to OTP verification page
                window.location.href = `/otp-verification.html?email=${encodeURIComponent(data.email)}&purpose=login`;
            } else {
                // Store token and redirect to dashboard
                localStorage.setItem('token', data.token);
                window.location.href = '/dashboard.html';
            }
        } else {
            // Remove pulsing dots loading animation on error
            loginButton.classList.remove('loading');
            loginButton.disabled = false;
            loginButton.innerHTML = originalContent;
            
            // Handle different types of errors with enhanced information
            const errorMessage = data.message || 'Login failed';
            const additionalData = {
                attemptsRemaining: data.attemptsRemaining,
                isLocked: data.isLocked,
                lockRemaining: data.lockRemaining
            };
            
            console.log('[Login] Showing error with data:', { errorMessage, additionalData });
            
            // Show enhanced error message
            showLoginError('error', errorMessage, additionalData);
            
            // If account is locked, disable the form temporarily
            if (data.isLocked || data.lockRemaining) {
                loginButton.disabled = true;
                loginButton.innerHTML = '<span class="btn-text"><i class="fas fa-lock"></i> Account Locked</span>';
                
                // Disable form inputs
                document.getElementById('username').disabled = true;
                document.getElementById('password').disabled = true;
            }
            
            // Reset reCAPTCHA on error
            if (typeof grecaptcha !== 'undefined') {
                grecaptcha.reset();
            }
        }
    } catch (error) {
        // Remove pulsing dots loading animation on error
        loginButton.classList.remove('loading');
        loginButton.disabled = false;
        loginButton.innerHTML = originalContent;
        
        console.error('[Login] Error:', error);
        showLoginError('error', 'An error occurred during login. Please check your connection and try again.');
        
        // Reset reCAPTCHA on error
        if (typeof grecaptcha !== 'undefined') {
            grecaptcha.reset();
        }
    }
}

// Add event listeners
document.addEventListener('DOMContentLoaded', function() {
    // Security: Clear reset password session data to prevent going back
    sessionStorage.removeItem('resetToken');
    sessionStorage.removeItem('resetTokenTimestamp');
    sessionStorage.removeItem('resetTokenUsed');
    sessionStorage.removeItem('pendingRegistration');
    console.log('[Security] Reset session data cleared on login page');
    
    const loginForm = document.getElementById('loginForm');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');

    // Handle login form submission
    loginForm.addEventListener('submit', handleLogin);

    // Clear errors when user starts typing
    if (usernameInput) {
        usernameInput.addEventListener('input', function() {
            clearLoginError('error');
            // Re-enable disabled inputs if they were disabled due to lock
            if (this.disabled) {
                this.disabled = false;
                passwordInput.disabled = false;
                const loginButton = document.querySelector('button[type="submit"]');
                if (loginButton) {
                    loginButton.disabled = false;
                    loginButton.innerHTML = '<span class="btn-text"><i class="fas fa-sign-in-alt"></i> Sign In</span>';
                }
            }
        });
    }
    
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            clearLoginError('error');
        });
    }

    // Add password visibility toggle event listener
    const showPasswordToggle = document.getElementById('showPassword') || 
                               document.querySelector('.show-password') ||
                               document.getElementById('togglePassword');
    
    if (showPasswordToggle) {
        showPasswordToggle.addEventListener('click', function(e) {
        e.preventDefault();
            togglePasswordVisibility();
        });
    }

    // Add error handling for reCAPTCHA
    window.onRecaptchaError = function() {
        showLoginError('recaptchaError', 'Error loading reCAPTCHA. Please refresh the page and try again.');
    };
});

// Legacy functions for OTP (keeping for compatibility)
function showOTPScreen(username) {
  const card = document.querySelector('.card');
  card.innerHTML = `
    <h2>📧 Enter OTP</h2>
    <div class="form-group">
      <label for="otp">OTP sent to your email</label>
      <input type="text" id="otp" required>
    </div>
    <button onclick="verifyOTP('${username}')">Verify</button>
   <button class="secondary-btn" onclick="navigateTo('/login.html')">Back</button>
    <div id="error" class="error"></div>
  `;
}

async function verifyOTP(username) {
  const otp = document.getElementById('otp').value.trim();
clearLoginError('error');

  if (!otp) {
   showLoginError('error', 'OTP is required.');
    return;
  }

  try {
    const response = await fetch('/api/auth/verify-login-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, otp }),
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      showLoginError('error', data.error || 'OTP verification failed');
      return;
    }

    // Store both token and user data
    localStorage.setItem('token', data.token);
    localStorage.setItem('user', JSON.stringify(data.user));
    
    // Log successful verification
    console.log('OTP verification successful:', {
      hasToken: !!data.token,
      hasUserData: !!data.user
    });

    // Redirect to dashboard
   navigateTo('/dashboard.html');
  } catch (error) {
    console.error('OTP verification error:', error);
   showLoginError('error', 'Server error. Please try again.');
  }
}