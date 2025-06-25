// Security check function
function checkSecurity() {
    // Check if accessed directly without authorization
    if (!sessionStorage.getItem('change_password_authorized')) {
        console.warn('Unauthorized access attempt to change password page');
        window.location.replace('/login.html');
        return false;
    }

    // Check token
    const token = localStorage.getItem('token');
    if (!token) {
        console.warn('No token found');
        window.location.replace('/login.html');
        return false;
    }

    return true;
}

// Initialize change password page with security
document.addEventListener('DOMContentLoaded', async () => {
    try {
        // Security check
        if (!checkSecurity()) {
            return;
        }

        // Prevent access to page elements from console
        Object.defineProperty(window, 'changePassword', {
            get: function() {
                console.warn('Unauthorized access attempt to change password elements');
                return null;
            }
        });

        // Disable right-click
        document.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            return false;
        });

        // Disable F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U
        document.addEventListener('keydown', (e) => {
            if (
                e.key === 'F12' ||
                (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J')) ||
                (e.ctrlKey && e.key === 'u')
            ) {
                e.preventDefault();
                return false;
            }
        });

        // Form submission is handled in the HTML file inline script
        // to avoid conflicts with the comprehensive error handling there

        // Set up back button
        const backButton = document.getElementById('backButton');
        if (backButton) {
            backButton.addEventListener('click', () => {
                sessionStorage.removeItem('change_password_authorized');
                window.location.replace('/dashboard.html');
            });
        }

        // Verify token before allowing any actions
        await verifyToken();

    } catch (error) {
        console.error('Change password page initialization error:', error);
        handleAuthError(error);
    }
});

// Password change handling is now done in the HTML file inline script
// to provide comprehensive error handling and avoid conflicts

// Verify token with security
async function verifyToken() {
    const token = localStorage.getItem('token');
    if (!token) {
        throw new Error('No authentication token found');
    }

    try {
        const response = await makeSecureRequest('/api/user/verify-token', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin'
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Authentication failed');
        }

        const result = await response.json();
        
        if (!result.success) {
            throw new Error('Invalid token');
        }

        return true;
    } catch (error) {
        console.error('Token verification failed:', error);
        throw error;
    }
}

// Handle authentication errors
function handleAuthError(error) {
    console.error('Auth error:', error);
    // Clear all sensitive data
    localStorage.removeItem('token');
    sessionStorage.removeItem('auth_verified');
    sessionStorage.removeItem('change_password_authorized');
    
    Swal.fire({
        icon: 'error',
        title: 'Authentication Error',
        text: error.message || 'Please log in again',
        confirmButtonColor: '#2c3e50'
    }).then(() => {
        window.location.replace('/login.html');
    });
}

// Prevent navigation away without proper logout
window.addEventListener('beforeunload', (e) => {
    if (sessionStorage.getItem('change_password_authorized')) {
        e.preventDefault();
        e.returnValue = '';
    }
}); 