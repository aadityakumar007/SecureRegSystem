// Navigation function
function navigateTo(path) {
    window.location.replace(path);
}

// Back button handler
function goBack() {
    const currentPage = window.location.pathname;
    switch (currentPage) {
        case '/dashboard.html':
            navigateTo('/login.html');
            break;
        case '/login.html':
            navigateTo('/');
            break;
        case '/register.html':
            navigateTo('/login.html');
            break;
        case '/forgot.html':
            navigateTo('/login.html');
            break;
        default:
            navigateTo('/login.html');
    }
}

// Check if user is logged in
function isLoggedIn() {
    return localStorage.getItem('token') !== null;
}

// Redirect to login if not authenticated
function requireAuth() {
    if (!isLoggedIn()) {
        navigateTo('/login.html');
    }
}

// Handle logout
function logout() {
    localStorage.removeItem('token');
    navigateTo('/login.html');
}

// Show error message
function showError(elementId, message) {
    const errorDiv = document.getElementById(elementId);
    if (errorDiv) {
        errorDiv.textContent = message;
    }
}

// Clear error message
function clearError(elementId) {
    const errorDiv = document.getElementById(elementId);
    if (errorDiv) {
        errorDiv.textContent = '';
    }
} 

// CSRF Token Management for csurf
let csrfToken = null;

async function getCSRFToken(forceRefresh = false) {
    if (csrfToken && !forceRefresh) {
        return csrfToken;
    }
    
    try {
        console.log('[CSRF] Fetching new CSRF token...');
        const response = await fetch('/api/csrf-token', {
            credentials: 'include', // Essential for cookie handling
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        csrfToken = data.csrfToken;
        console.log('[CSRF] Token obtained:', csrfToken ? csrfToken.substring(0, 20) + '...' : 'null');
        
        // Small delay to ensure session is properly established
        await new Promise(resolve => setTimeout(resolve, 100));
        
        return csrfToken;
    } catch (error) {
        console.error('[CSRF] Error fetching CSRF token:', error);
        return null;
    }
}

async function makeSecureRequest(url, options = {}) {
    try {
        console.log('[CSRF] === STARTING SECURE REQUEST ===');
        console.log('[CSRF] URL:', url);
        console.log('[CSRF] Original options:', JSON.stringify(options, null, 2));
        
        // Ensure credentials are included for cookie handling
        options.credentials = 'include';
        
        // Always get a fresh CSRF token for POST requests to ensure session consistency
        const isCriticalRequest = options.method && options.method.toUpperCase() !== 'GET';
        const token = await getCSRFToken(isCriticalRequest);
        if (!token) {
            throw new Error('Unable to obtain CSRF token');
        }
        
        console.log('[CSRF] Request method:', options.method);
        console.log('[CSRF] Is critical request:', isCriticalRequest);
        console.log('[CSRF] Using token:', token.substring(0, 20) + '...');
        console.log('[CSRF] Full token:', token);
        
        // Add CSRF token to request body for csurf
        if (options.body && options.method !== 'GET') {
            console.log('[CSRF] Processing request body...');
            console.log('[CSRF] Body type:', typeof options.body);
            console.log('[CSRF] Body content before:', options.body);
            
            try {
                if (typeof options.body === 'string') {
                    const parsedBody = JSON.parse(options.body);
                    console.log('[CSRF] Parsed body before adding token:', parsedBody);
                    parsedBody._csrf = token;
                    console.log('[CSRF] Parsed body after adding token:', parsedBody);
                    options.body = JSON.stringify(parsedBody);
                    console.log('[CSRF] Token added to JSON body');
                    console.log('[CSRF] Final body:', options.body);
                    console.log('[CSRF] Final body keys:', Object.keys(JSON.parse(options.body)));
                } else if (typeof options.body === 'object') {
                    console.log('[CSRF] Adding token to object body...');
                    options.body._csrf = token;
                    console.log('[CSRF] Token added to object body');
                    console.log('[CSRF] Final body keys:', Object.keys(options.body));
                }
            } catch (e) {
                console.warn('[CSRF] Could not parse body, adding token to headers instead:', e);
                options.headers = options.headers || {};
                options.headers['X-CSRF-Token'] = token;
                console.log('[CSRF] Token added to headers due to body parse error');
            }
        }
        
        // Also add to headers as backup
        options.headers = options.headers || {};
        options.headers['X-CSRF-Token'] = token;
        console.log('[CSRF] Token also added to headers as backup');
        console.log('[CSRF] Final headers:', JSON.stringify(options.headers, null, 2));
        console.log('[CSRF] Final options before fetch:', JSON.stringify(options, null, 2));
        
        console.log('[CSRF] === MAKING FETCH REQUEST ===');
        const response = await fetch(url, options);
        console.log('[CSRF] Response received, status:', response.status);
        
        // If CSRF token is invalid, refresh it and retry once
        if (response.status === 403) {
            const data = await response.json();
            if (data.message && data.message.includes('CSRF')) {
                console.log('[CSRF] Token invalid, refreshing and retrying...');
                csrfToken = null; // Reset token
                const newToken = await getCSRFToken(true); // Force refresh
                if (newToken) {
                    // Retry with new token
                    if (options.body && options.method !== 'GET') {
                        try {
                            if (typeof options.body === 'string') {
                                const parsedBody = JSON.parse(options.body);
                                parsedBody._csrf = newToken;
                                options.body = JSON.stringify(parsedBody);
                            } else if (typeof options.body === 'object') {
                                options.body._csrf = newToken;
                            }
                        } catch (e) {
                            options.headers = options.headers || {};
                            options.headers['X-CSRF-Token'] = newToken;
                        }
                    }
                    // Update headers with new token
                    options.headers = options.headers || {};
                    options.headers['X-CSRF-Token'] = newToken;
                    console.log('[CSRF] Retrying request with new token...');
                    return fetch(url, options);
                }
            }
        }
        
        return response;
    } catch (error) {
        console.error('[CSRF] Secure request failed:', error);
        throw error;
    }
}

// Initialize CSRF token on page load
document.addEventListener('DOMContentLoaded', () => {
    console.log('[CSRF] Initializing CSRF protection...');
    setTimeout(() => {
        getCSRFToken();
    }, 100); // Small delay to ensure page is fully loaded
}); 