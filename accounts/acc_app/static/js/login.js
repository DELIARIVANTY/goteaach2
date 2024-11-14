// Mendapatkan CSRF token dari cookie
function getCSRFToken() {
    let csrfToken = null;
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i].trim();
        if (cookie.startsWith('csrftoken=')) {
            csrfToken = cookie.substring('csrftoken='.length);
            break;
        }
    }
    return csrfToken;
}

$(document).ready(function() {
    // Toggle untuk hide atau tidak password
    $('#togglePassword').on('click', function() {
        const passwordInput = $('#passwordInput');
        const type = passwordInput.attr('type') === 'password' ? 'text' : 'password';
        passwordInput.attr('type', type);
        $(this).text(type === 'password' ? 'Show' : 'Hide');
    });

    // Memvalidasi form sudah diisikan atau belum (alert notification)
    $('#loginForm').on('submit', function(event) {
        const email = $('input[name="email"]').val();
        const password = $('input[name="password"]').val();

        if (email === '' || password === '') {
            alert('Please fill out all fields');
            event.preventDefault(); // Prevent form submission
        }
    });

    // Animasi sederhana pada tulisan welcome
    const welcomeText = $('#welcome-text');
    setTimeout(function() {
        welcomeText.css({
            'transform': 'scale(1.1)',
            'transition': 'transform 0.5s ease-in-out'
        });
    }, 500);

    setTimeout(function() {
        welcomeText.css('transform', 'scale(1)');
    }, 1500);
});
