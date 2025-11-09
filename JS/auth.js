const API_BASE_URL = 'http://127.0.0.1:5000/api';
document.addEventListener('DOMContentLoaded', function() {
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';
    
    const pageNavMap = {
        'index.html': 'nav-home',
        '': 'nav-home',
        'about.html': 'nav-about',
        'signup.html': 'nav-signup',
        'login.html': 'nav-login',
        'profile.html': 'nav-profile'
    };
    
    const activeNavId = pageNavMap[currentPage];
    
    if (activeNavId) {
        const activeLink = document.getElementById(activeNavId);
        if (activeLink) {
            activeLink.classList.add('active');
        }
    }

    if (currentPage === 'index.html') {
        checkAuth();
    }
    
    if (currentPage === 'login.html' || currentPage === 'signup.html') {
        const token = localStorage.getItem('token');
        if (token) {
            window.location.href = 'profile.html';
        }
    }
});
function checkAuth() {
    const token = localStorage.getItem('token');
    const user = localStorage.getItem('user');
    
    if (token && user) {
        displayUserInfo(JSON.parse(user));
    }
}

function displayUserInfo(user) {
    console.log('Logged in as:', user.fullname);
}

document.addEventListener('DOMContentLoaded', function() {
    const signupForm = document.getElementById('signup-form');
    if (signupForm) {
        signupForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const fullname = document.getElementById('fullname').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            const terms = document.getElementById('terms').checked;
            
            if (password !== confirmPassword) {
                alert('Passwords do not match!');
                return;
            }
            
            if (!terms) {
                alert('Please agree to the Terms of Service and Privacy Policy');
                return;
            }
            
            try {
                const response = await fetch(`${API_BASE_URL}/signup`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        fullname: fullname,
                        email: email,
                        password: password
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    alert('Account created successfully! Please login.');
                    window.location.href = 'login.html';
                } else {
                    alert(data.message || 'Signup failed. Please try again.');
                }
            } catch (error) {
                console.error('Signup error:', error);
                alert('Network error. Please make sure the backend server is running.');
            }
        });
    }
});

document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const remember = document.getElementById('remember').checked;
            
            try {
                const response = await fetch(`${API_BASE_URL}/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        email: email,
                        password: password
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('user', JSON.stringify(data.user));
                    
                    alert('Login successful!');
                    window.location.href = 'profile.html';
                } else {
                    alert(data.message || 'Login failed. Please try again.');
                }
            } catch (error) {
                console.error('Login error:', error);
                alert('Network error. Please make sure the backend server is running.');
            }
        });
    }
});

function logout() {
    if (confirm('Are you sure you want to logout?')) {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        alert('Logged out successfully!');
        window.location.href = 'login.html';
    }
}
