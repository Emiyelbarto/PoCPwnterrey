from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS, cross_origin
import sqlite3
import os
import jwt
import datetime

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

@app.after_request
def after_request(response):
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: *; frame-src 'self' data: *;"
    return response

def init_db():
    conn = sqlite3.connect('pwnterrey.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            first_name TEXT,
            last_name TEXT,
            email TEXT,
            phone TEXT,
            picture TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Very weak secret key (vulnerable)
SECRET_KEY = "Aa!123456"  # Replace this with a secure one in real apps or .env files please

users = {
    "admin": {"password": "admin", "is_admin": True},
    "user": {"password": "user", "is_admin": False}
}   

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pwnterrey Demo - Login</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .container {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
            transition: all 0.3s ease;
        }

        .container:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.15);
        }

        .logo {
            text-align: center;
            margin-bottom: 2rem;
        }

        .logo h1 {
            color: #333;
            font-size: 2rem;
            font-weight: 300;
        }

        .logo span {
            color: #667eea;
            font-weight: 600;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        label {
            display: block;
            margin-bottom: 0.5rem;
            color: #555;
            font-weight: 500;
        }

        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
        }

        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }

        .btn {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }

        .btn:active {
            transform: translateY(0);
        }

        .alert {
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 1rem;
            font-weight: 500;
        }

        .alert-error {
            background-color: #fee;
            color: #c33;
            border: 1px solid #fcc;
        }

        .alert-success {
            background-color: #efe;
            color: #363;
            border: 1px solid #cfc;
        }

        .demo-info {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1.5rem;
            font-size: 0.9rem;
            color: #6c757d;
        }

        .demo-info h4 {
            color: #495057;
            margin-bottom: 0.5rem;
        }

        .protected-area {
            text-align: center;
        }

        .user-info {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 1rem;
        }

        .logout-btn {
            background: #dc3545;
            margin-top: 1rem;
        }

        .logout-btn:hover {
            background: #c82333;
            box-shadow: 0 5px 15px rgba(220, 53, 69, 0.4);
        }

        .hidden {
            display: none !important;
        }

        .token-display {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            word-break: break-all;
            font-family: monospace;
            font-size: 0.8rem;
        }

        .access-btn {
            background: #28a745;
            margin-top: 0.5rem;
        }

        .access-btn:hover {
            background: #1e7e34;
            box-shadow: 0 5px 15px rgba(40, 167, 69, 0.4);
        }

        .profile-section {
            margin-top: 1.5rem;
            text-align: left;
        }

        .profile-form {
            background: #f8f9fa;
            padding: 1.5rem;
            border-radius: 8px;
            margin-top: 1rem;
        }

        .form-row {
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .form-row .form-group {
            flex: 1;
            margin-bottom: 0;
        }

        .profile-display {
            background: #e9ecef;
            padding: 1rem;
            border-radius: 8px;
            margin-top: 1rem;
        }

        .edit-btn {
            background: #17a2b8;
            margin-top: 0.5rem;
            margin-right: 0.5rem;
        }

        .edit-btn:hover {
            background: #138496;
            box-shadow: 0 5px 15px rgba(23, 162, 184, 0.4);
        }

        .save-btn {
            background: #28a745;
            margin-right: 0.5rem;
        }

        .cancel-btn {
            background: #6c757d;
        }
    </style>
</head>

<body>
    <div class="container">
        <div id="loginArea">
            <div class="logo">
                <h1>Pwnterrey</h1>
                <p style="color: #666; margin-top: 0.5rem;">Pwnterrey Demo Application</p>
                <img src="static/img.png">
            </div>

            <div id="alertContainer"></div>

            <form id="loginForm">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn">Login</button>
            </form>
        </div>

        <div id="protectedArea" class="protected-area hidden">
            <div class="user-info">
                <h2>Welcome to Pwnterrey!</h2>
                <p id="welcomeMessage">You have successfully logged in!</p>
            </div>

            <div class="token-display">
                <strong>Your JWT Token:</strong><br>
                <span id="tokenDisplay"></span>
            </div>

            <div style="margin-top: 1.5rem;">
                <h3>Account Dashboard</h3>
                <p>Your account balance: <strong>$10,000.00</strong></p>
                <p>Last login: <strong id="lastLogin"></strong></p>
            </div>

            <button class="btn access-btn" onclick="accessProtectedRoute()">Access Protected Data</button>
            
            <div class="profile-section">
                <h3>Profile Information</h3>
                <div id="profileDisplay" class="profile-display">
                    <p><strong>Name:</strong> <span id="displayName">Loading...</span></p>
                    <p><strong>Email:</strong> <span id="displayEmail">Loading...</span></p>
                    <p><strong>Phone:</strong> <span id="displayPhone">Loading...</span></p>
                </div>
                
                <button class="btn edit-btn" onclick="toggleEditProfile()">Edit Profile</button>
                
                <div id="profileForm" class="profile-form hidden">
                    <div class="form-row">
                        <div class="form-group">
                            <label for="firstName">First Name</label>
                            <input type="text" id="firstName" name="firstName">
                        </div>
                        <div class="form-group">
                            <label for="lastName">Last Name</label>
                            <input type="text" id="lastName" name="lastName">
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="email">Email</label>
                        <input type="text" id="email" name="email">
                    </div>
                    <div class="form-group">
                        <label for="phone">Phone</label>
                        <input type="text" id="phone" name="phone" placeholder="Enter your phone number (e.g., +1234567890)">
                    </div>
                    <button class="btn save-btn" onclick="saveProfile()">Save Profile</button>
                    <button class="btn cancel-btn" onclick="cancelEdit()">Cancel</button>
                </div>
            </div>
            
            <button class="btn logout-btn" onclick="logout()">Logout</button>
        </div>
    </div>

    <script>
        let authToken = null;

        window.addEventListener('load', function () {
            const savedToken = getCookie('Bearer');
            if (savedToken) {
                authToken = savedToken;
                // Verify token is still valid by calling protected route
                fetch('/protected', {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                }).then(response => {
                    if (response.ok) {
                        showLogin();
                        showAlert('Welcome back! Logged in from saved session.', 'success');
                    } else {
                        deleteCookie('Bearer');
                        authToken = null;
                    }
                }).catch(() => {
                    deleteCookie('Bearer');
                    authToken = null;
                });
            }
        });

        function showAlert(message, type = 'error') {
            const alertContainer = document.getElementById('alertContainer');
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type}`;
            alertDiv.textContent = message;
            alertContainer.innerHTML = '';
            alertContainer.appendChild(alertDiv);

            setTimeout(() => {
                alertDiv.remove();
            }, 5000);
        }

        document.getElementById('loginForm').addEventListener('submit', async function (e) {
            e.preventDefault();

            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password })
                });

                const data = await response.json();

                if (response.ok) {
                    authToken = data.token;
                    setCookie('Bearer', authToken, 5);
                    showLogin();
                    showAlert('Login successful!', 'success');
                } else {
                    showAlert(data.error || 'Login failed');
                }
            } catch (error) {
                showAlert('Network error: ' + error.message);
            }
        });

        function setCookie(name, value, minutes) {
            const date = new Date();
            date.setTime(date.getTime() + (minutes * 60 * 1000));
            const expires = "expires=" + date.toUTCString();
            document.cookie = name + "=" + value + ";" + expires + ";path=/";
        }

        function getCookie(name) {
            const nameEQ = name + "=";
            const ca = document.cookie.split(';');
            for (let i = 0; i < ca.length; i++) {
                let c = ca[i];
                while (c.charAt(0) == ' ') c = c.substring(1, c.length);
                if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length, c.length);
            }
            return null;
        }

        function deleteCookie(name) {
            document.cookie = name + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
        }

        function checkAdminStatus() {
            try {
                const payload = JSON.parse(atob(authToken.split('.')[1]));
                const isAdmin = payload.isadmin;
                
                if (!isAdmin) {
                    document.querySelector('.edit-btn').style.display = 'none';
                    document.getElementById('profileForm').style.display = 'none';
                } else {
                    document.querySelector('.edit-btn').style.display = 'block';
                }
            } catch (error) {
                console.error('Error checking admin status:', error);
            }
        }

        function showLogin() {
            document.getElementById('loginArea').classList.add('hidden');
            document.getElementById('protectedArea').classList.remove('hidden');
            document.getElementById('tokenDisplay').textContent = authToken;
            document.getElementById('lastLogin').textContent = new Date().toLocaleString();
            checkAdminStatus();
            loadProfile();
        }

        function logout() {
            authToken = null;
            deleteCookie('Bearer');
            document.getElementById('loginArea').classList.remove('hidden');
            document.getElementById('protectedArea').classList.add('hidden');
            document.getElementById('loginArea').style.display = 'block';
            document.getElementById('protectedArea').style.display = 'none';
            document.getElementById('username').value = '';
            document.getElementById('password').value = '';
            document.getElementById('alertContainer').innerHTML = '';
            showAlert('Logged out successfully', 'success');
        }

        async function accessProtectedRoute() {
            if (!authToken) {
                showAlert('Please login first');
                return;
            }

            try {
                const response = await fetch('/protected', {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });

                const data = await response.json();

                if (response.ok) {
                    showAlert(data.message, 'success');
                } else {
                    showAlert(data.error || 'Access denied');
                }
            } catch (error) {
                showAlert('Network error: ' + error.message);
            }
        }

        let isEditing = false;

        async function loadProfile() {
            if (!authToken) return;
            try {
                const response = await fetch('/profile', {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (response.ok) {
                    const profile = await response.json();
                    // VULNERABLE: Direct innerHTML injection without sanitization
                    document.getElementById('displayName').innerHTML = `${profile.first_name} ${profile.last_name}`;
                    document.getElementById('displayEmail').innerHTML = profile.email;
                    document.getElementById('displayPhone').innerHTML = profile.phone; // XSS vulnerability here
                    
                    // Populate form fields
                    document.getElementById('firstName').value = profile.first_name;
                    document.getElementById('lastName').value = profile.last_name;
                    document.getElementById('email').value = profile.email;
                    document.getElementById('phone').value = profile.phone;
                }
            } catch (error) {
                console.error('Error loading profile:', error);
            }
        }

        function toggleEditProfile() {
            const form = document.getElementById('profileForm');
            const button = event.target;
            
            if (isEditing) return;
            
            form.classList.remove('hidden');
            button.textContent = 'Editing...';
            button.disabled = true;
            isEditing = true;
        }

        async function saveProfile() {
            const phoneValue = document.getElementById('phone').value;
            const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
            if (phoneValue && !phoneRegex.test(phoneValue)) {
                showAlert('Invalid phone number format. Please enter a valid phone number.');
                return;
            }
            const profileData = {
                first_name: document.getElementById('firstName').value,
                last_name: document.getElementById('lastName').value,
                email: document.getElementById('email').value,
                phone: phoneValue
            };
            
            try {
                const response = await fetch('/profile', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${authToken}`
                    },
                    body: JSON.stringify(profileData)
                });
                
                if (response.ok) {
                    showAlert('Profile updated successfully!', 'success');
                    loadProfile(); // Reload to show updated data
                    cancelEdit();
                } else {
                    const data = await response.json();
                    showAlert(data.error || 'Failed to update profile');
                }
            } catch (error) {
                showAlert('Network error: ' + error.message);
            }
        }

        function cancelEdit() {
            document.getElementById('profileForm').classList.add('hidden');
            const button = document.querySelector('.edit-btn');
            button.textContent = 'Edit Profile';
            button.disabled = false;
            isEditing = false;
        }
    </script>
</body>

</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/profile', methods={'GET'})
@cross_origin()
def get_profile():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'Missing token'}), 403

    try:
        token = auth_header.split()[1]
        data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        username = data['user']
        
        conn = sqlite3.connect('pwnterrey.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM profiles WHERE username = ?', (username,))
        profile = cursor.fetchone()
        conn.close()
        
        if profile:
            return jsonify({
                'first_name': profile[2] or '',
                'last_name': profile[3] or '',
                'email': profile[4] or '',
                'phone': profile[5] or '',
                'picture': profile[6] or ''
            })
        else:
            return jsonify({
                'first_name': '',
                'last_name': '',
                'email': '',
                'phone': '',
                'picture': ''
            })
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 403


@app.route('/profile', methods=['POST'])
@cross_origin()
def update_profile():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'Missing token'}), 403

    try:
        token = auth_header.split()[1]
        data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        username = data['user']
        is_admin = data.get('isadmin', False)
        if not is_admin:
            return jsonify({'error': 'Access denied. Admin privileges required.'}), 403
        profile_data = request.get_json()
        first_name = profile_data.get('first_name', '')
        last_name = profile_data.get('last_name', '')
        email = profile_data.get('email', '')
        phone = profile_data.get('phone', '')  
        picture = profile_data.get('picture', '')
        
        conn = sqlite3.connect('pwnterrey.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO profiles 
            (username, first_name, last_name, email, phone, picture)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, first_name, last_name, email, phone, picture))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Profile updated successfully'})
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 403


@app.route('/login', methods=['POST'])
@cross_origin()
def login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
        
    username = data.get('username')
    password = data.get('password')

    if username in users and users[username]["password"] == password:
        token = jwt.encode({
            'user': username,
            'isadmin': users[username]["is_admin"],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        }, SECRET_KEY, algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/static/<path:filename>')
def serve_static(filename):
    return app.send_static_file(filename)

@app.route('/protected', methods=['GET'])
@cross_origin()
def protected():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'Missing token'}), 403

    try:
        token = auth_header.split()[1]
        data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({'message': f"Welcome back, {data['user']}! You have access to sensitive Pwnterrey data."})
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 403

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)