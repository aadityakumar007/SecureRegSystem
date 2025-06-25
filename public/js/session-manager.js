// SessionManager.js - Frontend JavaScript (Vanilla JS)

let inactivityTimer;
let warningTimer;
let countdownTimer;
let warningDialog = null;
const INACTIVITY_TIMEOUT = 180000; // 3 minutes in milliseconds (180 seconds)
const WARNING_DURATION = 30000; // 30 seconds warning (increased for better UX)
const MINIMIZED_TIMEOUT = 120000; // 2 minutes when browser is minimized/hidden
let isWarningShown = false;
let lastActivityTime = Date.now();
let countdownSeconds = 30;
let lastMousePosition = { x: 0, y: 0 };
let activityThreshold = 10; // Minimum mouse movement threshold
const SESSION_TIMEOUT = 3 * 60 * 1000; // 3 minutes (matches backend)
const PROTECTED_PAGES = ["/dashboard", "/reset-password", "/verify-otp"];
const PUBLIC_PAGES = ["/login", "/register", "/forgot-password"];
let minimizedStartTime = null;
let isPageHidden = false;
let minimizedTimer = null;

// Debug logging
function logDebug(message, data = '') {
    console.log(`[Session Manager] ${message}`, data);
}

// Initialize session manager
function initializeSessionManager() {
    logDebug('Initializing session manager...');
    
    // Set initial activity time
    lastActivityTime = Date.now();
    
    // Store initial mouse position
    lastMousePosition = { x: 0, y: 0 };
    
    // Add activity listeners with debouncing
    document.addEventListener('mousemove', handleMouseMove, { passive: true });
    document.addEventListener('keydown', handleKeyActivity, { passive: true });
    document.addEventListener('click', handleClickActivity, { passive: true });
    document.addEventListener('scroll', handleScrollActivity, { passive: true });
    document.addEventListener('touchstart', handleTouchActivity, { passive: true });
    
    // Add visibility change handler
    document.addEventListener('visibilitychange', handleVisibilityChange);
    
    // Add focus/blur handlers for the window
    window.addEventListener('focus', handleWindowFocus);
    window.addEventListener('blur', handleWindowBlur);
    
    // Start the inactivity timer
    startInactivityTimer();
    
    logDebug('Session manager initialized successfully');
    logDebug(`Timeout settings: ${INACTIVITY_TIMEOUT}ms total, ${WARNING_DURATION}ms warning`);
    logDebug('Activity detection: Mouse movement >10px, keyboard, clicks, scroll, touch');
}

// Improved activity handlers
function handleMouseMove(event) {
    // Only count significant mouse movements
    const deltaX = Math.abs(event.clientX - lastMousePosition.x);
    const deltaY = Math.abs(event.clientY - lastMousePosition.y);
    
    if (deltaX > activityThreshold || deltaY > activityThreshold) {
        lastMousePosition = { x: event.clientX, y: event.clientY };
        handleUserActivity('mouse movement');
    }
}

function handleKeyActivity(event) {
    // Ignore modifier keys only
    if (!event.ctrlKey && !event.altKey && !event.metaKey && event.key !== 'Shift') {
        handleUserActivity('keyboard');
    }
}

function handleClickActivity(event) {
    // Only count actual clicks, not programmatic ones
    if (event.isTrusted) {
        handleUserActivity('click');
    }
}

function handleScrollActivity(event) {
    // Throttle scroll events
    if (event.isTrusted) {
        handleUserActivity('scroll');
    }
}

function handleTouchActivity(event) {
    if (event.isTrusted) {
        handleUserActivity('touch');
    }
}

// Enhanced user activity handler with dashboard timer sync
function handleUserActivity(source = 'unknown') {
    const now = Date.now();
    const timeSinceLastActivity = now - lastActivityTime;
    
    // Only count activity if it's been more than 1 second since last activity
    if (timeSinceLastActivity > 1000) {
        lastActivityTime = now;
        logDebug(`Real user activity detected: ${source} (${timeSinceLastActivity}ms since last)`);
        
        // Reset dashboard timer if function exists
        if (typeof resetDashboardTimer === 'function') {
            resetDashboardTimer();
        }
        
        // If warning is shown, hide it and reset
        if (isWarningShown) {
            logDebug('Activity detected during warning - resetting session');
            hideWarning();
            resetTimers();
        } else {
            resetTimers();
        }
    }
}

function handleWindowFocus() {
    logDebug('Window focused');
    // Check if the tab was inactive for too long
    const inactiveTime = Date.now() - lastActivityTime;
    if (inactiveTime >= INACTIVITY_TIMEOUT) {
        logDebug('Tab was inactive for too long, logging out');
        handleLogout();
    } else {
        // Don't restart timer on focus - let it continue naturally
        logDebug('Window focused but timer continues normally');
    }
}

function handleWindowBlur() {
    logDebug('Window blurred - timer continues running');
    // Don't update lastActivityTime on blur - let timer continue
}

function handleVisibilityChange() {
    if (document.hidden) {
        logDebug('Page hidden - implementing aggressive timeout for security');
        isPageHidden = true;
        minimizedStartTime = Date.now();
        
        // Clear existing timers when page is hidden
        clearTimeout(inactivityTimer);
        clearTimeout(warningTimer);
        clearTimeout(countdownTimer);
        clearTimeout(minimizedTimer);
        
        // Store when we paused for normal activity tracking
        window.sessionPausedAt = minimizedStartTime;
        
        // Set aggressive minimized timer - force logout after MINIMIZED_TIMEOUT
        minimizedTimer = setTimeout(() => {
            logDebug('Browser was minimized too long - forcing logout for security');
            
            // Show immediate logout notification
            if (warningDialog && warningDialog.parentNode) {
                document.body.removeChild(warningDialog);
            }
            
            // Create immediate logout dialog
            const logoutDialog = document.createElement('div');
            logoutDialog.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.9);
                z-index: 2147483647;
                display: flex;
                align-items: center;
                justify-content: center;
                font-family: Arial, sans-serif;
            `;
            
            logoutDialog.innerHTML = `
                <div style="background: #dc2626; color: white; padding: 30px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.8); text-align: center; max-width: 500px; margin: 20px;">
                    <div style="font-size: 48px; margin-bottom: 20px;">🔒</div>
                    <h2 style="margin: 0 0 15px 0;">Security Timeout</h2>
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        Your session has been terminated because the browser was minimized for more than 2 minutes.
                    </p>
                    <p style="font-size: 14px; margin-bottom: 25px; opacity: 0.9;">
                        This is a security measure to protect your account from unauthorized access.
                    </p>
                    <button onclick="window.location.href='/login.html'" style="
                        background: white;
                        color: #dc2626;
                        border: none;
                        padding: 12px 25px;
                        border-radius: 5px;
                        font-size: 16px;
                        cursor: pointer;
                        font-weight: bold;
                    ">Continue to Login</button>
                </div>
            `;
            
            document.body.appendChild(logoutDialog);
            
            // Force logout after showing message
            setTimeout(() => {
                handleLogout();
            }, 3000);
            
        }, MINIMIZED_TIMEOUT);
        
        logDebug(`Aggressive minimized timer set for ${MINIMIZED_TIMEOUT}ms (${MINIMIZED_TIMEOUT/60000} minutes)`);
        
    } else {
        logDebug('Page visible - checking minimized duration and resuming timers');
        isPageHidden = false;
        
        // Clear minimized timer since page is visible again
        clearTimeout(minimizedTimer);
        
        if (minimizedStartTime) {
            const hiddenDuration = Date.now() - minimizedStartTime;
            const totalInactiveTime = hiddenDuration + (minimizedStartTime - lastActivityTime);
            
            logDebug(`Was hidden for ${hiddenDuration}ms (${hiddenDuration/60000} minutes), total inactive: ${totalInactiveTime}ms`);
            
            // If hidden for more than MINIMIZED_TIMEOUT, force logout
            if (hiddenDuration >= MINIMIZED_TIMEOUT) {
                logDebug('Page was hidden too long - security logout triggered');
                
                // Show security message before logout
                alert(`🔒 SECURITY LOGOUT\n\nYour session was terminated because the browser was minimized for ${Math.round(hiddenDuration/60000)} minutes.\n\nThis is a security feature to protect your account.`);
                
                handleLogout();
                return;
            }
            
            // If total inactivity (including before minimization) exceeds normal timeout
            if (totalInactiveTime >= INACTIVITY_TIMEOUT) {
                logDebug('Total inactivity time exceeded - normal timeout logout');
                handleLogout();
                return;
            }
            
            // Reset minimized tracking
            minimizedStartTime = null;
        }
        
        // Resume normal timer operation with remaining time
        if (window.sessionPausedAt) {
            delete window.sessionPausedAt;
        }
        
        startInactivityTimer();
        logDebug('Normal session timer resumed after visibility restored');
    }
}

function startInactivityTimer() {
    logDebug('Starting inactivity timer...');
    
    // Clear any existing timers
    clearTimeout(inactivityTimer);
    clearTimeout(warningTimer);
    clearTimeout(countdownTimer);
    
    // Reset warning state
    if (isWarningShown) {
        hideWarning();
    }
    
    const warningTime = INACTIVITY_TIMEOUT - WARNING_DURATION;
    logDebug(`Warning will show in ${warningTime}ms (${warningTime/1000} seconds)`);
    logDebug(`Current time: ${new Date().toLocaleTimeString()}`);
    
    // Set new inactivity timer
    inactivityTimer = setTimeout(() => {
        logDebug('Inactivity timeout reached, showing warning...');
        logDebug(`Warning shown at: ${new Date().toLocaleTimeString()}`);
        showWarning();
    }, warningTime);
}

function createWarningDialog() {
    // Remove any existing warning dialog
    hideWarning();
    
    // Create warning overlay
    warningDialog = document.createElement('div');
    warningDialog.id = 'session-warning-overlay';
    warningDialog.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.8);
        z-index: 2147483647;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: Arial, sans-serif;
        animation: fadeIn 0.3s ease-out;
    `;
    
    // Add CSS animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
    `;
    document.head.appendChild(style);
    
    // Create warning dialog box
    const dialogBox = document.createElement('div');
    dialogBox.style.cssText = `
        background: white;
        padding: 30px;
        border-radius: 15px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        text-align: center;
        max-width: 500px;
        margin: 20px;
        animation: pulse 2s infinite;
    `;
    
    dialogBox.innerHTML = `
        <div style="font-size: 48px; margin-bottom: 20px; animation: pulse 2s infinite;">⚠️</div>
        <h2 style="color: #e74c3c; margin: 0 0 15px 0;">Session Timeout Warning</h2>
        <p style="color: #333; font-size: 18px; margin-bottom: 20px;">
            You will be automatically logged out in <strong id="countdown-seconds" style="color: #e74c3c; font-size: 24px;">30</strong> seconds due to inactivity.
        </p>
        <p style="color: #666; font-size: 14px; margin-bottom: 25px;">
            Move your mouse, click, or press any key to stay logged in.
        </p>
        <button id="stay-logged-in-btn" style="
            background: #27ae60;
            color: white;
            border: none;
            padding: 12px 25px;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            margin-right: 10px;
            transition: background 0.3s;
        " onmouseover="this.style.background='#229954'" onmouseout="this.style.background='#27ae60'">Stay Logged In</button>
        <button id="logout-now-btn" style="
            background: #e74c3c;
            color: white;
            border: none;
            padding: 12px 25px;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.3s;
        " onmouseover="this.style.background='#c0392b'" onmouseout="this.style.background='#e74c3c'">Logout Now</button>
    `;
    
    // Add event listeners
    const stayButton = dialogBox.querySelector('#stay-logged-in-btn');
    const logoutButton = dialogBox.querySelector('#logout-now-btn');
    
    stayButton.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        logDebug('User clicked Stay Logged In button');
        hideWarning();
        lastActivityTime = Date.now();
        resetTimers();
    };
    
    logoutButton.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        logDebug('User clicked Logout Now button');
        hideWarning();
        handleLogout();
    };
    
    warningDialog.appendChild(dialogBox);
    document.body.appendChild(warningDialog);
    
    return dialogBox.querySelector('#countdown-seconds');
}

function showWarning() {
    if (isWarningShown) {
        logDebug('Warning already shown, ignoring duplicate call');
        return;
    }

    isWarningShown = true;
    countdownSeconds = 30;
    logDebug('Showing warning dialog...');
    
    // Create and show the warning dialog
    const countdownElement = createWarningDialog();
    
    // Start countdown
    countdownTimer = setInterval(() => {
        countdownSeconds--;
        if (countdownElement) {
            countdownElement.textContent = countdownSeconds;
            
            // Change color as countdown gets lower
            if (countdownSeconds <= 10) {
                countdownElement.style.color = '#e74c3c';
                countdownElement.style.fontWeight = 'bold';
            }
        }
        
        logDebug(`Countdown: ${countdownSeconds} seconds remaining`);
        
        if (countdownSeconds <= 0) {
            logDebug('Countdown reached zero - auto logout triggered');
            clearInterval(countdownTimer);
            hideWarning();
            handleLogout();
        }
    }, 1000);
    
    // Also set a final timeout as backup
    warningTimer = setTimeout(() => {
        logDebug('Warning timeout reached (backup), logging out...');
        hideWarning();
        handleLogout();
    }, WARNING_DURATION + 1000); // Extra second for safety
}

function hideWarning() {
    if (warningDialog && warningDialog.parentNode) {
        document.body.removeChild(warningDialog);
        warningDialog = null;
    }
    clearTimeout(warningTimer);
    clearInterval(countdownTimer);
    isWarningShown = false;
    logDebug('Warning dialog hidden');
}

function resetTimers() {
    const now = Date.now();
    const timeSinceStart = now - lastActivityTime;
    
    // Only reset if this is a legitimate activity and not too frequent
    if (timeSinceStart > 1000) {
        logDebug(`Resetting timers due to activity (${timeSinceStart}ms since last)`);
        
        if (isWarningShown) {
            hideWarning();
        }
        
        // Update last activity time
        lastActivityTime = now;
        
        // Restart the full timer
        startInactivityTimer();
    }
}

// Clear session and redirect
function clearSession(message) {
    sessionStorage.clear();
    redirectToLogin(message);
}

function redirectToLogin(message) {
    alert(`Session Expired: ${message}`);
        window.location.href = "/login.html";
}

function redirectToPage(path, message) {
    alert(`Session Expired: ${message}`);
        window.location.href = path;
}

function handleLogout() {
    logDebug('Handling logout...');
    try {
        // Clear all timers including new minimized timer
        clearTimeout(inactivityTimer);
        clearTimeout(warningTimer);
        clearInterval(countdownTimer);
        clearTimeout(minimizedTimer);
        hideWarning();
        
        // Reset all tracking variables
        isPageHidden = false;
        minimizedStartTime = null;
        isWarningShown = false;
        
        // Clear session data
        localStorage.removeItem('token');
        sessionStorage.clear();
        
        // Show logout message with reason
        const logoutReason = isPageHidden ? 
            'You have been logged out because the browser was minimized for too long.' :
            'You have been logged out due to inactivity.';
            
        alert(`🔒 LOGGED OUT\n\n${logoutReason}`);
        
        logDebug('Redirecting to login page...');
        window.location.href = '/login.html';
    } catch (error) {
        console.error('Logout error:', error);
        // Force redirect even if there's an error
        window.location.href = '/login.html';
    }
}

// Export functions for use in other files
window.initializeSessionManager = initializeSessionManager;
window.handleLogout = handleLogout;

// Handle page refresh/close
window.addEventListener('beforeunload', () => {
    clearSession('Session timed out due to page close.');
}); 

logDebug('Session manager script loaded'); 