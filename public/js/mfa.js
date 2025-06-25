// MFA verification handling
class MFAHandler {
    constructor() {
        this.mfaToken = null;
        this.verificationType = null; // 'register', 'login', or 'forgot-password'
    }

    setMFAContext(token, type) {
        this.mfaToken = token;
        this.verificationType = type;
        localStorage.setItem('mfaToken', token);
        localStorage.setItem('mfaType', type);
    }

    getMFAContext() {
        return {
            token: this.mfaToken || localStorage.getItem('mfaToken'),
            type: this.verificationType || localStorage.getItem('mfaType')
        };
    }

    clearMFAContext() {
        this.mfaToken = null;
        this.verificationType = null;
        localStorage.removeItem('mfaToken');
        localStorage.removeItem('mfaType');
    }

    async verifyMFA(code) {
        const { token, type } = this.getMFAContext();
        if (!token || !type) {
            throw new Error('No MFA context found');
        }

        let endpoint;
        switch (type) {
            case 'register':
                endpoint = '/api/auth/verify-registration';
                break;
            case 'login':
                endpoint = '/api/auth/verify-login';
                break;
            case 'forgot-password':
                endpoint = '/api/auth/verify-forgot-password';
                break;
            default:
                throw new Error('Invalid MFA type');
        }

        try {
            // Get CSRF token before making the request
            console.log('[MFA] Getting CSRF token...');
            const csrfResponse = await fetch('/api/csrf-token', {
                credentials: 'include'
            });
            
            if (!csrfResponse.ok) {
                throw new Error('Failed to get CSRF token');
            }
            
            const csrfData = await csrfResponse.json();
            const csrfToken = csrfData.csrfToken;
            console.log('[MFA] CSRF token obtained:', csrfToken.substring(0, 20) + '...');

            const requestBody = {
                mfaToken: token,
                code,
                _csrf: csrfToken
            };

            const response = await fetch(endpoint, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify(requestBody)
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || 'MFA verification failed');
            }

            // Clear MFA context after successful verification
            this.clearMFAContext();

            return data;
        } catch (error) {
            console.error('[MFA] Error:', error);
            throw error;
        }
    }

    showMFAForm() {
        const container = document.querySelector('.card');
        container.innerHTML = `
            <h2>🔐 Two-Factor Authentication</h2>
            <p>Please enter the verification code sent to your email.</p>
            <div class="form-group">
                <label for="mfaCode">Verification Code</label>
                <input type="text" id="mfaCode" maxlength="6" required>
            </div>
            <button onclick="handleMFAVerification()" class="primary-btn">Verify</button>
            <button onclick="handleMFACancel()" class="secondary-btn">Cancel</button>
            <div id="error" class="error"></div>
        `;
    }
}

// Initialize MFA handler
const mfaHandler = new MFAHandler();

// Handle MFA verification
async function handleMFAVerification() {
    const code = document.getElementById('mfaCode').value;
    const errorDiv = document.getElementById('error');

    try {
        const result = await mfaHandler.verifyMFA(code);
        
        // Handle successful verification based on type
        const { type } = mfaHandler.getMFAContext();
        switch (type) {
            case 'register':
                // Store token and redirect to dashboard
                localStorage.setItem('token', result.token);
                window.location.href = '/dashboard.html';
                break;
            case 'login':
                // Store token and redirect to dashboard
                localStorage.setItem('token', result.token);
                window.location.href = '/dashboard.html';
                break;
            case 'forgot-password':
                // Show success message and redirect to login
                await Swal.fire({
                    title: 'Success!',
                    text: 'Password has been reset successfully',
                    icon: 'success',
                    confirmButtonColor: '#3498db'
                });
                window.location.href = '/login.html';
                break;
        }
    } catch (error) {
        errorDiv.textContent = error.message;
    }
}

// Handle MFA cancellation
function handleMFACancel() {
    mfaHandler.clearMFAContext();
    window.location.href = '/login.html';
}

// Check for MFA context on page load
document.addEventListener('DOMContentLoaded', () => {
    const { token, type } = mfaHandler.getMFAContext();
    if (token && type) {
        mfaHandler.showMFAForm();
    }
}); 