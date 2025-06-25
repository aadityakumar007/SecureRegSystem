// DOM Elements for new dashboard structure
const loadingSpinner = document.getElementById('loadingSpinner');
const errorMessage = document.getElementById('errorMessage');
const dashboardHeader = document.getElementById('dashboardHeader');
const dashboardContent = document.getElementById('dashboardContent');
const logoutBtn = document.getElementById('logoutBtn');

// Debug logging
const debug = {
    log: (message, data) => {
        console.log(`[Dashboard] ${message}`, data || '');
    },
    error: (message, error) => {
        console.error(`[Dashboard] ${message}`, error);
    }
};

// Check authentication status
async function checkAuth() {
    try {
        debug.log('Checking authentication status');
        
        // Get token from localStorage
        const token = localStorage.getItem('token');
        if (!token) {
            debug.error('Missing token');
            throw new Error('Authentication required');
        }

        // Verify token with server
        const response = await fetch('/api/user/verify-token', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });

        debug.log('Token verification response:', {
            status: response.status,
            ok: response.ok
        });

        if (!response.ok) {
            if (response.status === 404) {
                throw new Error('API endpoint not found');
            }
            if (response.status === 401) {
                throw new Error('Authentication failed - invalid token');
            }
            if (response.status === 403) {
                throw new Error('Account not verified - please verify your email');
            }
            throw new Error(`Server error: ${response.status}`);
        }

        const data = await response.json();

        if (!data.success) {
            debug.error('Token verification failed:', data.message);
            throw new Error(data.message || 'Authentication failed');
        }

        debug.log('Token verified successfully');
        return data.user;
    } catch (error) {
        debug.error('Authentication check failed:', error);
        throw error;
    }
}

// Load user information
async function loadUserInfo() {
    try {
        debug.log('Loading user information');
        
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('No authentication token found');
        }

        const response = await fetch('/api/user/info', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });

        debug.log('User info response:', {
            status: response.status,
            ok: response.ok
        });

        if (!response.ok) {
            if (response.status === 404) {
                throw new Error('API endpoint not found');
            }
            if (response.status === 401) {
                throw new Error('Authentication failed - invalid token');
            }
            if (response.status === 403) {
                throw new Error('Account not verified - please verify your email');
            }
            throw new Error(`Server error: ${response.status}`);
        }

        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.message || 'Failed to load user information');
        }

        debug.log('User info loaded successfully:', {
            username: data.user.username,
            email: data.user.email,
            role: data.user.role
        });

        return data.user;
    } catch (error) {
        debug.error('Failed to load user info:', error);
        throw error;
    }
}

// Update dashboard UI with user data (compatible with new structure)
function updateDashboardUI(user) {
    try {
        debug.log('Updating dashboard UI with user information');
        
        if (!user) {
            throw new Error('No user data provided');
        }

        // Update welcome message
        const userWelcome = document.getElementById('userWelcome');
        if (userWelcome) {
            userWelcome.textContent = `Welcome back, ${user.username}!`;
        }
        
        // Update profile information
        const profileContent = document.getElementById('userProfileContent');
        if (profileContent) {
            profileContent.innerHTML = `
                <div class="info-item">
                    <span class="info-label">Username</span>
                    <span class="info-value">${user.username}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Email</span>
                    <span class="info-value">${user.email}</span>
            </div>
                <div class="info-item">
                    <span class="info-label">Role</span>
                    <span class="info-value">${user.role || 'User'}</span>
        </div>
                <div class="info-item">
                    <span class="info-label">Member Since</span>
                    <span class="info-value">${new Date(user.createdAt).toLocaleDateString()}</span>
        </div>
            `;
        }
        
        // Update account status
        const accountStatus = document.getElementById('accountStatus');
        if (accountStatus) {
            if (user.isVerified) {
                accountStatus.textContent = 'Verified';
                accountStatus.className = 'status-badge status-verified';
            } else {
                accountStatus.textContent = 'Unverified';
                accountStatus.className = 'status-badge status-unverified';
            }
        }
        
        // Update last login
        const lastLoginTime = document.getElementById('lastLoginTime');
        if (lastLoginTime && user.lastLogin) {
            lastLoginTime.textContent = new Date(user.lastLogin).toLocaleString();
        }
        
        // Update account created
        const accountCreated = document.getElementById('accountCreated');
        if (accountCreated && user.createdAt) {
            accountCreated.textContent = new Date(user.createdAt).toLocaleDateString();
        }
        
        debug.log('Dashboard UI updated successfully');
    } catch (error) {
        debug.error('Failed to update dashboard UI:', error);
        throw error;
    }
}

// Handle logout (compatible with new structure)
function handleLogout() {
    try {
        debug.log('Handling logout');
        
        // Clear all stored data
        localStorage.clear();
        sessionStorage.clear();
        
        // Redirect to login page
        window.location.href = '/login.html';
        
        debug.log('Logout completed');
    } catch (error) {
        debug.error('Logout failed:', error);
        alert('Logout failed. Please try again.');
    }
}

// Show loading state (compatible with new structure)
function showLoading() {
    debug.log('Showing loading indicator');
    
    if (loadingSpinner) {
        loadingSpinner.style.display = 'block';
    }
    if (dashboardHeader) {
        dashboardHeader.style.display = 'none';
    }
    if (dashboardContent) {
        dashboardContent.style.display = 'none';
    }
    if (errorMessage) {
        errorMessage.style.display = 'none';
    }
}

// Show error state (compatible with new structure)
function showError(message) {
    debug.error('Error occurred:', message);
    
    if (errorMessage) {
        errorMessage.textContent = message;
        errorMessage.style.display = 'block';
    }
    if (loadingSpinner) {
        loadingSpinner.style.display = 'none';
    }
    if (dashboardHeader) {
        dashboardHeader.style.display = 'none';
    }
    if (dashboardContent) {
        dashboardContent.style.display = 'none';
    }
}

// Show dashboard content (compatible with new structure)
function showDashboard() {
    debug.log('Showing dashboard content');
    
    if (loadingSpinner) {
        loadingSpinner.style.display = 'none';
    }
    if (errorMessage) {
        errorMessage.style.display = 'none';
    }
    if (dashboardHeader) {
        dashboardHeader.style.display = 'flex';
    }
    if (dashboardContent) {
        dashboardContent.style.display = 'grid';
    }
}

// Check password expiry and change requirements - handle mandatory reset
async function checkPasswordExpiry(user) {
    try {
        debug.log('Checking password expiry and change requirements');
        
        // First check if password change is specifically required by backend
        const token = localStorage.getItem('token');
        if (token) {
            try {
                const response = await fetch('/api/user/info', {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    if (data.success && data.user) {
                        const userData = data.user;
                        
                        // Check if password change is required (backend logic)
                        if (userData.passwordChangeRequired || userData.requiresPasswordChange) {
                            debug.log('Password change required by backend');
                            await showPasswordChangeRequired('Password change required by system administrator', 'System Requirement');
                            return;
                        }
                        
                        // Check for password expiry from backend
                        if (userData.isPasswordExpired) {
                            debug.log('Password has expired according to backend');
                            await showPasswordChangeRequired('Your password has expired and must be changed', 'Password Expired');
                            return;
                        }
                    }
                }
            } catch (apiError) {
                debug.log('Error fetching backend password status, using client-side fallback:', apiError);
            }
        }
        
        // Fallback client-side check for password expiry
        if (!user.passwordCreatedAt) {
            debug.log('No password creation date found, skipping client-side expiry check');
            return;
        }

        const passwordCreatedAt = new Date(user.passwordCreatedAt);
        const now = new Date();
        const daysSinceCreated = Math.floor((now - passwordCreatedAt) / (1000 * 60 * 60 * 24));
        const daysUntilExpiry = 30 - daysSinceCreated;

        debug.log('Client-side password expiry check:', {
            passwordCreatedAt: passwordCreatedAt.toISOString(),
            daysSinceCreated,
            daysUntilExpiry,
            isExpired: daysUntilExpiry <= 0
        });

        // If password is expired (≥ 30 days), show mandatory reset dialog
        if (daysUntilExpiry <= 0) {
            debug.log('Password has expired (client-side check), showing mandatory reset dialog');
            
            // Calculate how many days overdue
            const daysOverdue = Math.abs(daysUntilExpiry);
            await showPasswordChangeRequired(
                `Your password expired ${daysOverdue} day${daysOverdue !== 1 ? 's' : ''} ago. For security reasons, you must change your password to continue.`,
                '30-Day Password Policy'
            );
            return;
        } else if (daysUntilExpiry <= 7) {
            // Show warning for passwords expiring soon (optional)
            debug.log(`Password expires in ${daysUntilExpiry} days - showing warning`);
            
            if (typeof Swal !== 'undefined') {
                Swal.fire({
                    title: '⚠️ Password Expiring Soon',
                    html: `
                        <div style="text-align: center;">
                            <div style="font-size: 48px; color: #f59e0b; margin-bottom: 15px;">
                                <i class="fas fa-exclamation-triangle"></i>
                            </div>
                            <p style="color: #374151; margin-bottom: 15px;">
                                Your password will expire in <strong style="color: #dc2626;">${daysUntilExpiry} day${daysUntilExpiry !== 1 ? 's' : ''}</strong>.
                            </p>
                            <p style="color: #6b7280; margin-bottom: 20px;">
                                Consider changing your password soon to avoid being forced to reset it later.
                            </p>
                        </div>
                    `,
                    icon: 'warning',
                    confirmButtonText: 'Change Password',
                    cancelButtonText: 'Remind Me Later',
                    showCancelButton: true,
                    confirmButtonColor: '#f59e0b',
                    cancelButtonColor: '#6b7280'
                }).then((result) => {
                    if (result.isConfirmed) {
                        window.location.href = '/change-password.html';
                    }
                });
            }
        }
        
        debug.log('Password expiry and requirement check completed');
    } catch (error) {
        if (error.message === 'Password change required - redirecting') {
            // This is expected when password change is required
            throw error;
        }
        debug.error('Error checking password requirements:', error);
        // Don't block dashboard if check fails
    }
}

// Show password change required dialog
async function showPasswordChangeRequired(reason, title = 'Password Change Required') {
    debug.log('Showing password change required dialog:', { reason, title });
    
    if (typeof Swal !== 'undefined') {
        await Swal.fire({
            title: `🔐 ${title}`,
            html: `
                <div style="text-align: center;">
                    <div style="font-size: 64px; color: #dc2626; margin-bottom: 20px;">
                        <i class="fas fa-key"></i>
                    </div>
                    <h3 style="color: #374151; margin-bottom: 15px;">Password Change Required</h3>
                    <p style="color: #6b7280; margin-bottom: 20px;">
                        ${reason}
                    </p>
                    <div style="background: #fef2f2; padding: 15px; border-radius: 8px; border-left: 4px solid #ef4444; margin: 20px 0;">
                        <p style="color: #dc2626; margin: 0; font-weight: 600;">
                            🛡️ You must change your password to continue using the system
                        </p>
                    </div>
                    <p style="color: #6b7280; font-size: 14px;">
                        You will be redirected to the password change page.
                    </p>
                </div>
            `,
            icon: 'error',
            confirmButtonText: 'Change Password Now',
            confirmButtonColor: '#dc2626',
            allowOutsideClick: false,
            allowEscapeKey: false,
            showCloseButton: false
        });
    } else {
        // Fallback if SweetAlert2 is not available
        alert(`${title}: ${reason}. You will be redirected to the password change page.`);
    }
    
    // Redirect to change password page
    debug.log('Redirecting to change password page');
    window.location.href = '/change-password.html';
    
    // Prevent further dashboard initialization
    throw new Error('Password change required - redirecting');
}

// Initialize dashboard (compatible with new structure)
async function initDashboard() {
    try {
        debug.log('Initializing dashboard');
        
        // Show loading spinner
        showLoading();

        // Check authentication
        const authUser = await checkAuth();

        // Load additional user information
        let userInfo = authUser;
        try {
            const additionalInfo = await loadUserInfo();
            userInfo = { ...authUser, ...additionalInfo };
        } catch (error) {
            debug.log('Additional user info failed, using auth data only');
        }

        // Check for password expiry before showing dashboard
        await checkPasswordExpiry(userInfo);

        // Update UI with user data
        updateDashboardUI(userInfo);

        // Show dashboard
        showDashboard();

        debug.log('Dashboard initialized successfully');
    } catch (error) {
        debug.error('Dashboard initialization failed:', error);
        
        let errorMsg = 'Failed to initialize dashboard';
        if (error.message === 'Authentication required' || 
            error.message === 'No authentication token found' ||
            error.message === 'Authentication failed - invalid token') {
            errorMsg = 'Please log in to access the dashboard';
            // Redirect to login after showing error
            setTimeout(() => {
                window.location.href = '/login.html';
            }, 2000);
        } else if (error.message === 'Account not verified - please verify your email') {
            errorMsg = 'Your account is not verified. Please check your email and verify your account before accessing the dashboard.';
            // Redirect to login after showing error
            setTimeout(() => {
                window.location.href = '/login.html';
            }, 3000);
        } else if (error.message === 'API endpoint not found') {
            errorMsg = 'Server configuration error. Please contact support.';
        } else {
            errorMsg = error.message;
        }
        
        showError(errorMsg);
    }
}

// Event Listeners (compatible with new structure)
document.addEventListener('DOMContentLoaded', () => {
    debug.log('DOM content loaded');
    
    // Check if essential elements exist
    if (!loadingSpinner || !errorMessage) {
        debug.error('Essential DOM elements not found');
        console.error('Missing elements:', {
            loadingSpinner: !!loadingSpinner,
            errorMessage: !!errorMessage,
            dashboardHeader: !!dashboardHeader,
            dashboardContent: !!dashboardContent,
            logoutBtn: !!logoutBtn
        });
        // Still try to initialize even if some elements are missing
    }

    // Don't initialize here if the HTML page already handles it
    // Only initialize if not already handled by inline script
    if (typeof window.initDashboard === 'undefined') {
        initDashboard();
    }
    
    // Add logout handler if not already added
    if (logoutBtn && typeof window.handleLogoutClick === 'undefined') {
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            const confirmed = confirm('Are you sure you want to logout?');
            if (confirmed) {
                handleLogout();
            }
        });
    }
}); 