document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    // Validate password requirements
    if (!validatePassword(password)) {
        document.getElementById('message').innerText = "Password does not meet requirements!";
        return;
    }

    // Hash the password before sending it to the backend
    const hashedPassword = await hashPassword(password);

    // Send username and hashed password to backend
    const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password: hashedPassword }),
    });

    const result = await response.json();

    if (result.success) {
        document.getElementById('message').innerText = "Login successful!";
        // Redirect or load dashboard
    } else {
        document.getElementById('message').innerText = "Login failed!";
    }
});

function validatePassword(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    return password.length >= minLength && hasUpperCase && hasNumber && hasSpecialChar;
}

async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}
