document.addEventListener('DOMContentLoaded', function() {
    const otpInputs = document.querySelectorAll('.otp-input');
    const verifyOtpBtn = document.getElementById('verifyOtp');
    const resendCodeBtn = document.getElementById('resendCode');
    const resendLink = document.getElementById('resendLink');
    const otpError = document.getElementById('otp-error');
    const messageModal = document.getElementById('messageModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalMessage = document.getElementById('modalMessage');
    const modalClose = document.getElementById('modalClose');
    let otpTimer;
    let timeLeft = 120; // 2 minutes in seconds

    // Check for pending registration data first
    const pendingRegistration = sessionStorage.getItem('pendingRegistration');
    let email, purpose, mfaToken;

    if (pendingRegistration) {
        // Registration flow
        const regData = JSON.parse(pendingRegistration);
        email = regData.email;
        purpose = 'registration';
        mfaToken = regData.mfaToken;
        
        // Update page title and description for registration
        document.querySelector('.auth-header h1').textContent = 'Verify Your Email';
        document.querySelector('.auth-header p').textContent = 'Enter the 6-digit code sent to your email to complete registration';
    } else {
        // Login/reset flow - get from URL parameters
        const urlParams = new URLSearchParams(window.location.search);
        email = urlParams.get('email');
        purpose = urlParams.get('purpose') || 'reset'; // Default to reset password
    }

    if (!email) {
        showModal('⚠️ Error', 'Invalid session. Please try again.');
        setTimeout(() => {
            if (pendingRegistration) {
                window.location.href = '/register.html';
            } else {
                window.location.href = '/forgot-password.html';
            }
        }, 3000);
        return;
    }

    // Show modal function
    function showModal(title, message) {
        modalTitle.textContent = title;
        modalMessage.textContent = message;
        messageModal.style.display = 'flex';
    }

    // Close modal function
    function closeModal() {
        messageModal.style.display = 'none';
    }

    // Initialize OTP input behavior
    otpInputs.forEach((input, index) => {
        // Handle input
        input.addEventListener('input', (e) => {
            if (e.target.value.length === 1) {
                if (index < otpInputs.length - 1) {
                    otpInputs[index + 1].focus();
                }
            }
        });

        // Handle backspace
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && !e.target.value && index > 0) {
                otpInputs[index - 1].focus();
            }
        });

        // Handle paste
        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pastedData = e.clipboardData.getData('text').slice(0, 6);
            if (/^\d+$/.test(pastedData)) {
                pastedData.split('').forEach((digit, i) => {
                    if (otpInputs[i]) {
                        otpInputs[i].value = digit;
                    }
                });
                if (otpInputs[pastedData.length]) {
                    otpInputs[pastedData.length].focus();
                }
            }
        });
    });

    // Timer functionality
    function updateTimer() {
        const minutes = Math.floor(timeLeft / 60);
        const seconds = timeLeft % 60;
        document.getElementById('otpTimer').textContent = 
            `${minutes}:${seconds.toString().padStart(2, '0')}`;
        
        // Update circular progress
        const progress = document.querySelector('.timer-progress');
        const circumference = 2 * Math.PI * 45; // 2πr where r=45
        const offset = circumference - (timeLeft / 120) * circumference;
        progress.style.strokeDasharray = `${circumference} ${circumference}`;
        progress.style.strokeDashoffset = offset;
        
        if (timeLeft <= 0) {
            clearInterval(otpTimer);
            resendCodeBtn.disabled = false;
            resendLink.classList.remove('disabled');
            progress.style.strokeDashoffset = circumference;
        } else {
            timeLeft--;
        }
    }

    function startTimer() {
        timeLeft = 120;
        resendCodeBtn.disabled = true;
        resendLink.classList.add('disabled');
        clearInterval(otpTimer);
        otpTimer = setInterval(updateTimer, 1000);
        updateTimer();
    }

    // Start timer when page loads
    startTimer();

    // Verify OTP
    async function verifyOtp() {
        const otp = Array.from(otpInputs).map(input => input.value).join('');
        
        if (otp.length !== 6) {
            showError('Please enter the complete 6-digit code');
            return;
        }

        try {
            verifyOtpBtn.disabled = true;
            verifyOtpBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Verifying...';

            // Get CSRF token before making the request
            console.log('[OTP] Getting CSRF token...');
            const csrfResponse = await fetch('/api/csrf-token', {
                credentials: 'include'
            });
            
            if (!csrfResponse.ok) {
                throw new Error('Failed to get CSRF token');
            }
            
            const csrfData = await csrfResponse.json();
            const csrfToken = csrfData.csrfToken;
            console.log('[OTP] CSRF token obtained:', csrfToken.substring(0, 20) + '...');

            // Handle different verification flows
            if (purpose === 'registration') {
                console.log('[OTP] Registration verification flow');
                // Registration verification - use specific endpoint
                const regResponse = await fetch('/api/auth/verify-registration', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({
                        mfaToken: mfaToken,
                        otp: otp,
                        _csrf: csrfToken
                    })
                });

                const regData = await regResponse.json();

                if (!regResponse.ok) {
                    throw new Error(regData.message || 'Registration verification failed');
                }

                // Clear pending registration data
                sessionStorage.removeItem('pendingRegistration');
                
                // Show success message and redirect to login page
                showModal('✅ Registration Complete!', 'Your account has been created successfully. Please log in with your credentials.');
                
                setTimeout(() => {
                    window.location.href = '/login.html';
                }, 3000);
            } else {
                console.log('[OTP] Standard verification flow for:', purpose);
                // Standard OTP verification for login/reset
                const requestBody = {
                    email: email,
                    otp: otp,
                    purpose: purpose,
                    _csrf: csrfToken
                };

                const response = await fetch('/api/auth/verify-otp', {
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

                if (!response.ok) {
                    throw new Error(data.message || 'Verification failed');
                }

                if (!data.success) {
                    throw new Error(data.message || 'Verification failed');
                }

                if (purpose === 'reset') {
                    // Store the reset token in sessionStorage with timestamp
                    sessionStorage.setItem('resetToken', data.token);
                    sessionStorage.setItem('resetTokenTimestamp', Date.now().toString());
                    showModal('✅ Verification Successful', 'You can now reset your password.');
                    setTimeout(() => {
                        window.location.href = '/reset-password.html';
                    }, 2000);
                } else if (purpose === 'login') {
                    // Clear any existing data
                    localStorage.clear();

                    // Store token and user data
                    if (!data.token || !data.user) {
                        throw new Error('Invalid response: Missing token or user data');
                    }

                    localStorage.setItem('token', data.token);
                    localStorage.setItem('user', JSON.stringify(data.user));

                    // Verify data was stored correctly
                    const storedToken = localStorage.getItem('token');
                    const storedUser = localStorage.getItem('user');

                    if (!storedToken || !storedUser) {
                        throw new Error('Failed to store authentication data');
                    }

                    // Parse user data to verify structure
                    try {
                        const userData = JSON.parse(storedUser);
                        const requiredFields = ['_id', 'username', 'email', 'role'];
                        const missingFields = requiredFields.filter(field => !userData[field]);
                        
                        if (missingFields.length > 0) {
                            throw new Error(`Invalid user data: Missing fields ${missingFields.join(', ')}`);
                        }
                    } catch (error) {
                        localStorage.clear();
                        throw new Error('Invalid user data format');
                    }

                    showModal('✅ Login Successful', 'Redirecting to dashboard...');
                    
                    // Add a small delay to ensure storage is complete
                    await new Promise(resolve => setTimeout(resolve, 100));
                    
                    // Use replace instead of href for better navigation
                    window.location.replace('/dashboard.html');
                }
            }

        } catch (error) {
            console.error('[OTP] Error:', error);
            showModal('❌ Error', error.message || 'Verification failed. Please try again.');
        } finally {
            verifyOtpBtn.disabled = false;
            verifyOtpBtn.innerHTML = '<i class="fas fa-check"></i> Verify Code';
        }
    }

    // Resend OTP
    async function resendOtp() {
        try {
            resendCodeBtn.disabled = true;
            resendCodeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';

            // Get CSRF token before making the request
            console.log('[OTP Resend] Getting CSRF token...');
            const csrfResponse = await fetch('/api/csrf-token', {
                credentials: 'include'
            });
            
            if (!csrfResponse.ok) {
                throw new Error('Failed to get CSRF token');
            }
            
            const csrfData = await csrfResponse.json();
            const csrfToken = csrfData.csrfToken;
            console.log('[OTP Resend] CSRF token obtained:', csrfToken.substring(0, 20) + '...');

            const requestBody = {
                email: email,
                purpose: purpose,
                _csrf: csrfToken
            };

            const response = await fetch('/api/auth/resend-otp', {
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

            if (!response.ok) {
                throw new Error(data.message || 'Failed to resend code');
            }

            // Show success message
            showModal(
                '✅ Code Resent',
                'A new verification code has been sent to your email.'
            );

            // Reset UI
            startTimer();
            clearError();
            otpInputs.forEach(input => {
                input.value = '';
                input.classList.remove('error');
            });
            otpInputs[0].focus();

        } catch (error) {
            console.error('[OTP Resend] Error:', error);
            showError(error.message);
        } finally {
            resendCodeBtn.disabled = false;
            resendCodeBtn.innerHTML = '<i class="fas fa-redo"></i> Resend Code';
        }
    }

    function showError(message) {
        otpError.textContent = message;
        otpError.style.display = 'block';
    }

    function clearError() {
        otpError.textContent = '';
        otpError.style.display = 'none';
    }

    // Event listeners
    verifyOtpBtn.addEventListener('click', verifyOtp);
    resendCodeBtn.addEventListener('click', resendOtp);
    resendLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (!resendCodeBtn.disabled) {
            resendOtp();
        }
    });
    modalClose.addEventListener('click', closeModal);

    // Close modal when clicking outside
    window.addEventListener('click', (e) => {
        if (e.target === messageModal) {
            closeModal();
        }
    });

    // Focus first input on load
    otpInputs[0].focus();
}); 