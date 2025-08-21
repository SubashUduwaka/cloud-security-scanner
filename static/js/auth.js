document.addEventListener('DOMContentLoaded', () => {
    const showLogin = document.getElementById('showLogin');
    const showRegister = document.getElementById('showRegister');
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');

    const switchToLogin = () => {
        loginForm.style.display = 'block';
        registerForm.style.display = 'none';
        showLogin.classList.add('active');
        showRegister.classList.remove('active');
    };

    const switchToRegister = () => {
        loginForm.style.display = 'none';
        registerForm.style.display = 'block';
        showLogin.classList.remove('active');
        showRegister.classList.add('active');
    };

    showLogin.addEventListener('click', (e) => {
        e.preventDefault();
        switchToLogin();
        window.location.hash = 'login';
    });

    showRegister.addEventListener('click', (e) => {
        e.preventDefault();
        switchToRegister();
        window.location.hash = 'register';
    });

    // Check URL hash on page load
    if (window.location.hash === '#register') {
        switchToRegister();
    } else {
        switchToLogin();
    }
});