document.addEventListener('DOMContentLoaded', function() {
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';

    const pageNavMap = {
        'index.html': 'nav-home',
        '': 'nav-home',
        'about.html': 'nav-about',
        'signup.html': 'nav-signup',
        'login.html': 'nav-login'
    };

    const activeNavId = pageNavMap[currentPage];

    if (activeNavId) {
        const activeLink = document.getElementById(activeNavId);
        if (activeLink) {
            activeLink.classList.add('active');
        }
    }
});
