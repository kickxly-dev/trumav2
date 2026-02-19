// Authentication System
class AuthSystem {
    constructor() {
        this.token = localStorage.getItem('trauma_token');
        this.user = JSON.parse(localStorage.getItem('trauma_user') || 'null');
        this.init();
    }

    init() {
        // Clear any existing tokens to force fresh login
        localStorage.removeItem('trauma_token');
        localStorage.removeItem('trauma_user');
    }

    async login(email, password) {
        try {
            // Use current port for API calls
            const currentPort = window.location.port || '10000';
            const apiUrl = `http://localhost:${currentPort}/api/auth/login`;
            
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (response.ok) {
                this.token = data.token;
                this.user = data.user;
                
                localStorage.setItem('trauma_token', this.token);
                localStorage.setItem('trauma_user', JSON.stringify(this.user));
                
                return { success: true, user: data.user };
            } else {
                return { success: false, error: data.error || 'Login failed' };
            }
        } catch (error) {
            return { success: false, error: 'Network error. Please try again.' };
        }
    }

    async signup(name, email, password) {
        try {
            const currentPort = window.location.port || '10000';
            const apiUrl = `http://localhost:${currentPort}/api/auth/signup`;
            
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ name, email, password })
            });

            const data = await response.json();

            if (response.ok) {
                return { success: true, message: 'Account created successfully!' };
            } else {
                return { success: false, error: data.error || 'Signup failed' };
            }
        } catch (error) {
            return { success: false, error: 'Network error. Please try again.' };
        }
    }

    logout() {
        localStorage.removeItem('trauma_token');
        localStorage.removeItem('trauma_user');
        this.token = null;
        this.user = null;
        window.location.href = 'auth.html';
    }

    redirectToAdmin() {
        window.location.href = 'admin.html';
    }

    isAuthenticated() {
        return !!this.token && !!this.user;
    }

    getAuthHeader() {
        return this.token ? `Bearer ${this.token}` : null;
    }
}

// UI Functions
function switchTab(tab) {
    const tabs = document.querySelectorAll('.auth-tab');
    const forms = document.querySelectorAll('.auth-form');
    
    tabs.forEach(t => t.classList.remove('active'));
    forms.forEach(f => f.classList.remove('active'));
    
    if (tab === 'login') {
        tabs[0].classList.add('active');
        document.getElementById('loginForm').classList.add('active');
    } else {
        tabs[1].classList.add('active');
        document.getElementById('signupForm').classList.add('active');
    }
    
    // Clear any messages
    hideAllMessages();
}

function showMessage(form, type, message) {
    const errorEl = document.getElementById(`${form}Error`);
    const successEl = document.getElementById(`${form}Success`);
    
    // Hide both messages first
    errorEl.style.display = 'none';
    successEl.style.display = 'none';
    
    // Show the appropriate message
    if (type === 'error') {
        errorEl.textContent = message;
        errorEl.style.display = 'block';
    } else {
        successEl.textContent = message;
        successEl.style.display = 'block';
    }
}

function hideAllMessages() {
    document.querySelectorAll('.auth-error, .auth-success').forEach(el => {
        el.style.display = 'none';
    });
}

function setLoading(form, loading) {
    const button = document.getElementById(`${form}Button`);
    const buttonText = document.getElementById(`${form}ButtonText`);
    
    if (loading) {
        button.disabled = true;
        buttonText.innerHTML = '<span class="loading-spinner"></span>Processing...';
    } else {
        button.disabled = false;
        buttonText.textContent = form === 'login' ? 'Access Admin Panel' : 'Create Account';
    }
}

async function handleLogin(event) {
    event.preventDefault();
    
    const adminCode = document.getElementById('adminCode').value;
    
    hideAllMessages();
    setLoading('login', true);
    
    // Check admin code
    if (adminCode !== '4567') {
        setLoading('login', false);
        showMessage('login', 'error', 'Invalid admin access code');
        return;
    }
    
    // Direct access with just the code
    showMessage('login', 'success', 'Access granted! Redirecting...');
    setTimeout(() => {
        window.location.href = 'admin.html';
    }, 1500);
}

async function handleSignup(event) {
    event.preventDefault();
    
    const name = document.getElementById('signupName').value;
    const email = document.getElementById('signupEmail').value;
    const password = document.getElementById('signupPassword').value;
    const confirmPassword = document.getElementById('signupConfirmPassword').value;
    
    hideAllMessages();
    
    // Validate passwords match
    if (password !== confirmPassword) {
        showMessage('signup', 'error', 'Passwords do not match');
        return;
    }
    
    // Validate password strength
    if (password.length < 8) {
        showMessage('signup', 'error', 'Password must be at least 8 characters long');
        return;
    }
    
    setLoading('signup', true);
    
    const auth = new AuthSystem();
    const result = await auth.signup(name, email, password);
    
    setLoading('signup', false);
    
    if (result.success) {
        showMessage('signup', 'success', result.message + ' Redirecting to login...');
        setTimeout(() => {
            switchTab('login');
            // Pre-fill email in login form
            document.getElementById('loginEmail').value = email;
        }, 2000);
    } else {
        showMessage('signup', 'error', result.error);
    }
}

function checkPasswordStrength() {
    const password = document.getElementById('signupPassword').value;
    const strengthBar = document.getElementById('passwordStrengthBar');
    
    let strength = 0;
    
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^a-zA-Z0-9]/.test(password)) strength++;
    
    strengthBar.className = 'password-strength-bar';
    
    if (strength <= 2) {
        strengthBar.classList.add('strength-weak');
    } else if (strength <= 4) {
        strengthBar.classList.add('strength-medium');
    } else {
        strengthBar.classList.add('strength-strong');
    }
}

// Test server connection
async function testServer() {
    try {
        const currentPort = window.location.port || '10000';
        const apiUrl = `http://localhost:${currentPort}/api/health`;
        
        const response = await fetch(apiUrl);
        const data = await response.json();
        
        if (response.ok) {
            showMessage('login', 'success', `✅ Server is running! Status: ${data.status}`);
        } else {
            showMessage('login', 'error', '❌ Server not responding');
        }
    } catch (error) {
        showMessage('login', 'error', '❌ Cannot connect to server');
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Check if user is already logged in
    const auth = new AuthSystem();
    if (auth.token && auth.user) {
        auth.redirectToAdmin();
    }
    
    // Add enter key support for switching fields
    document.querySelectorAll('.form-input').forEach(input => {
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const form = input.closest('form');
                const submitBtn = form.querySelector('button[type="submit"]');
                if (submitBtn) {
                    submitBtn.click();
                }
            }
        });
    });
    
    // Add visual feedback for inputs
    document.querySelectorAll('.form-input').forEach(input => {
        input.addEventListener('focus', () => {
            input.parentElement.style.transform = 'scale(1.02)';
        });
        
        input.addEventListener('blur', () => {
            input.parentElement.style.transform = 'scale(1)';
        });
    });
});

// Global auth instance
window.authSystem = new AuthSystem();
