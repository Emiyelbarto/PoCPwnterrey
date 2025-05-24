from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS, cross_origin
import sqlite3
import os
import jwt
import datetime
import xml.etree.ElementTree as ET
from xml.sax import make_parser, ContentHandler
from xml.sax.handler import feature_external_ges
import io
import threading
from contextlib import contextmanager
from functools import wraps

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Database connection pool using thread-local storage
_local = threading.local()

@contextmanager
def get_db_connection():
    """Context manager for database connections with proper cleanup"""
    if not hasattr(_local, 'conn') or _local.conn is None:
        _local.conn = sqlite3.connect('pwnterrey.db', check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row  # Enable dict-like access
    
    try:
        yield _local.conn
    except Exception:
        _local.conn.rollback()
        raise
    else:
        _local.conn.commit()

@app.teardown_appcontext
def close_db_connection(error):
    """Close database connection at request end"""
    if hasattr(_local, 'conn') and _local.conn:
        _local.conn.close()
        _local.conn = None

@app.after_request
def after_request(response):
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: *; frame-src 'self' data: *;"
    return response

def init_db():
    """Initialize database with proper error handling"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    first_name TEXT DEFAULT '',
                    last_name TEXT DEFAULT '',
                    email TEXT DEFAULT '',
                    phone TEXT DEFAULT '',
                    picture TEXT DEFAULT ''
                )
            ''')
            
            # Create index for better performance
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_profiles_username 
                ON profiles(username)
            ''')
    except Exception as e:
        print(f"Database initialization error: {e}")
        raise

# Initialize database on startup
init_db()

# Configuration constants
SECRET_KEY = "Aa!123456"  # Intentionally weak - vulnerability preserved
XML_SECRET = "#Pwnt3rr3yS3cureK3y!"

# User database - moved to class for better organization
class UserManager:
    def __init__(self):
        self.users = {
            "admin": {"password": "admin", "is_admin": True},
            "user": {"password": "user", "is_admin": False}
        }
    
    def authenticate(self, username, password):
        """Authenticate user credentials"""
        user = self.users.get(username)
        return user and user["password"] == password
    
    def get_user_info(self, username):
        """Get user information"""
        return self.users.get(username)

user_manager = UserManager()

def require_auth(f):
    """Decorator for routes requiring authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid token'}), 403
        
        try:
            token = auth_header.split()[1]
            # Try both secret keys for token validation
            data = None
            for secret in [SECRET_KEY, XML_SECRET]:
                try:
                    data = jwt.decode(token, secret, algorithms=['HS256'])
                    break
                except jwt.InvalidTokenError:
                    continue
            
            if not data:
                return jsonify({'error': 'Invalid token'}), 403
                
            request.user_data = data
            return f(*args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 403
        except Exception as e:
            return jsonify({'error': 'Token validation error'}), 403
    
    return decorated_function

def require_admin(f):
    """Decorator for routes requiring admin privileges"""
    @wraps(f)
    @require_auth
    def decorated_function(*args, **kwargs):
        if not request.user_data.get('isadmin', False):
            return jsonify({'error': 'Access denied. Admin privileges required.'}), 403
        return f(*args, **kwargs)
    
    return decorated_function

# Optimized HTML template (moved to separate function for clarity)
def get_html_template():
    """Return the HTML template - could be moved to external file in production"""
    return '''
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
                <img src="static/img.png" alt="Pwnterrey Logo">
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
        class PwnterreyApp {
            constructor() {
                this.authToken = null;
                this.isEditing = false;
                this.init();
            }

            init() {
                this.bindEvents();
                this.checkSavedSession();
            }

            bindEvents() {
                document.getElementById('loginForm').addEventListener('submit', (e) => this.handleLogin(e));
            }

            checkSavedSession() {
                const savedToken = this.getCookie('Bearer');
                if (savedToken) {
                    this.authToken = savedToken;
                    this.verifyToken().then(valid => {
                        if (valid) {
                            this.showProtectedArea();
                            this.showAlert('Welcome back! Logged in from saved session.', 'success');
                        } else {
                            this.clearSession();
                        }
                    });
                }
            }

            async verifyToken() {
                try {
                    const response = await fetch('/protected', {
                        headers: { 'Authorization': `Bearer ${this.authToken}` }
                    });
                    return response.ok;
                } catch {
                    return false;
                }
            }

            showAlert(message, type = 'error') {
                const alertContainer = document.getElementById('alertContainer');
                const alertDiv = document.createElement('div');
                alertDiv.className = `alert alert-${type}`;
                alertDiv.textContent = message;
                alertContainer.innerHTML = '';
                alertContainer.appendChild(alertDiv);

                setTimeout(() => alertDiv.remove(), 5000);
            }

            async handleLogin(e) {
                e.preventDefault();
                const formData = new FormData(e.target);
                const loginData = {
                    username: formData.get('username'),
                    password: formData.get('password')
                };

                try {
                    const response = await fetch('/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(loginData)
                    });

                    const data = await response.json();

                    if (response.ok) {
                        this.authToken = data.token;
                        this.setCookie('Bearer', this.authToken, 30);
                        this.showProtectedArea();
                        this.showAlert('Login successful!', 'success');
                    } else {
                        this.showAlert(data.error || 'Login failed');
                    }
                } catch (error) {
                    this.showAlert('Network error: ' + error.message);
                }
            }

            setCookie(name, value, minutes) {
                const date = new Date();
                date.setTime(date.getTime() + (minutes * 60 * 1000));
                document.cookie = `${name}=${value};expires=${date.toUTCString()};path=/`;
            }

            getCookie(name) {
                const nameEQ = name + "=";
                return document.cookie.split(';')
                    .map(c => c.trim())
                    .find(c => c.indexOf(nameEQ) === 0)
                    ?.substring(nameEQ.length) || null;
            }

            deleteCookie(name) {
                document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/`;
            }

            clearSession() {
                this.authToken = null;
                this.deleteCookie('Bearer');
            }

            checkAdminStatus() {
                try {
                    const payload = JSON.parse(atob(this.authToken.split('.')[1]));
                    const isAdmin = payload.isadmin;
                    
                    const editBtn = document.querySelector('.edit-btn');
                    const profileForm = document.getElementById('profileForm');
                    
                    if (!isAdmin) {
                        editBtn.style.display = 'none';
                        profileForm.style.display = 'none';
                    } else {
                        editBtn.style.display = 'block';
                    }
                } catch (error) {
                    console.error('Error checking admin status:', error);
                }
            }

            showProtectedArea() {
                document.getElementById('loginArea').classList.add('hidden');
                document.getElementById('protectedArea').classList.remove('hidden');
                document.getElementById('tokenDisplay').textContent = this.authToken;
                document.getElementById('lastLogin').textContent = new Date().toLocaleString();
                this.checkAdminStatus();
                this.loadProfile();
            }

            logout() {
                this.clearSession();
                document.getElementById('loginArea').classList.remove('hidden');
                document.getElementById('protectedArea').classList.add('hidden');
                document.getElementById('username').value = '';
                document.getElementById('password').value = '';
                document.getElementById('alertContainer').innerHTML = '';
                this.showAlert('Logged out successfully', 'success');
            }

            async accessProtectedRoute() {
                if (!this.authToken) {
                    this.showAlert('Please login first');
                    return;
                }

                try {
                    const response = await fetch('/protected', {
                        headers: { 'Authorization': `Bearer ${this.authToken}` }
                    });

                    const data = await response.json();
                    this.showAlert(data.message || data.error, response.ok ? 'success' : 'error');
                } catch (error) {
                    this.showAlert('Network error: ' + error.message);
                }
            }

            async loadProfile() {
                if (!this.authToken) return;
                
                try {
                    const response = await fetch('/profile', {
                        headers: { 'Authorization': `Bearer ${this.authToken}` }
                    });
                    
                    if (response.ok) {
                        const profile = await response.json();
                        // VULNERABLE: Direct innerHTML injection without sanitization - preserved
                        document.getElementById('displayName').innerHTML = `${profile.first_name} ${profile.last_name}`;
                        document.getElementById('displayEmail').innerHTML = profile.email;
                        document.getElementById('displayPhone').innerHTML = profile.phone; // XSS vulnerability here - preserved
                        
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

            toggleEditProfile() {
                if (this.isEditing) return;
                
                const form = document.getElementById('profileForm');
                const button = event.target;
                
                form.classList.remove('hidden');
                button.textContent = 'Editing...';
                button.disabled = true;
                this.isEditing = true;
            }

            async saveProfile() {
                const phoneValue = document.getElementById('phone').value;
                const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
                
                if (phoneValue && !phoneRegex.test(phoneValue)) {
                    this.showAlert('Invalid phone number format. Please enter a valid phone number.');
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
                            'Authorization': `Bearer ${this.authToken}`
                        },
                        body: JSON.stringify(profileData)
                    });
                    
                    if (response.ok) {
                        this.showAlert('Profile updated successfully!', 'success');
                        this.loadProfile();
                        this.cancelEdit();
                    } else {
                        const data = await response.json();
                        this.showAlert(data.error || 'Failed to update profile');
                    }
                } catch (error) {
                    this.showAlert('Network error: ' + error.message);
                }
            }

            cancelEdit() {
                document.getElementById('profileForm').classList.add('hidden');
                const button = document.querySelector('.edit-btn');
                button.textContent = 'Edit Profile';
                button.disabled = false;
                this.isEditing = false;
            }
        }

        // Global functions for backwards compatibility
        let app;
        
        window.addEventListener('load', () => {
            app = new PwnterreyApp();
        });

        function logout() { app.logout(); }
        function accessProtectedRoute() { app.accessProtectedRoute(); }
        function toggleEditProfile() { app.toggleEditProfile(); }
        function saveProfile() { app.saveProfile(); }
        function cancelEdit() { app.cancelEdit(); }
    </script>
</body>

</html>
'''

@app.route('/')
def index():
    return render_template_string(get_html_template())

@app.route('/profile', methods=['GET'])
@require_auth
def get_profile():
    username = request.user_data['user']
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM profiles WHERE username = ?', (username,))
            profile = cursor.fetchone()
            
            if profile:
                return jsonify({
                    'first_name': profile['first_name'] or '',
                    'last_name': profile['last_name'] or '',
                    'email': profile['email'] or '',
                    'phone': profile['phone'] or '',
                    'picture': profile['picture'] or ''
                })
            else:
                # Return empty profile if none exists
                return jsonify({
                    'first_name': '',
                    'last_name': '',
                    'email': '',
                    'phone': '',
                    'picture': ''
                })
    except Exception as e:
        return jsonify({'error': 'Database error'}), 500

@app.route('/profile', methods=['POST'])
@require_admin
def update_profile():
    username = request.user_data['user']
    
    try:
        profile_data = request.get_json()
        if not profile_data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Extract and validate profile data
        first_name = profile_data.get('first_name', '').strip()
        last_name = profile_data.get('last_name', '').strip()
        email = profile_data.get('email', '').strip()
        phone = profile_data.get('phone', '').strip()
        picture = profile_data.get('picture', '').strip()
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO profiles 
                (username, first_name, last_name, email, phone, picture)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, first_name, last_name, email, phone, picture))
        
        return jsonify({'message': 'Profile updated successfully'})
        
    except Exception as e:
        return jsonify({'error': f'Failed to update profile. {str(e)}'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        if user_manager.authenticate(username, password):
            user_info = user_manager.get_user_info(username)
            token = jwt.encode({
                'user': username,
                'isadmin': user_info["is_admin"],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            }, SECRET_KEY, algorithm='HS256')
            return jsonify({'token': token})
            
        return jsonify({'error': 'Invalid credentials'}), 401
        
    except Exception as e:
        return jsonify({'error': 'Login processing error'}), 500

@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files - add basic security checks"""
    if '..' in filename or filename.startswith('/'):
        return jsonify({'error': 'Invalid file path'}), 400
    return app.send_static_file(filename)

@app.route('/protected', methods=['GET'])
@require_auth
def protected():
    username = request.user_data['user']
    return jsonify({'message': f"Welcome back, {username}! You have access to sensitive Pwnterrey data."})

@app.route('/latest/meta-data', methods=['GET'])
def admin_files():
    """SSRF vulnerability preserved - intentional security flaw"""
    referrer = request.headers.get('Referer', '')
    user_agent = request.headers.get('User-Agent', '')
    
    # if 'javascript:' in referrer.lower() or not referrer:
        # return jsonify({'error': 'Access denied: Suspicious request origin detected'}), 403
    
    try:
        # Simulate sensitive file listing - vulnerability preserved
        sensitive_files = [
            {'name': 'config.txt', 'content': 'DATABASE_URL=postgresql://admin:secret123@localhost/pwnterrey'},
            {'name': 'users.txt', 'content': 'admin:admin:true\nuser:user:false\nsecretuser:password123:true'},
            {'name': 'api_keys.txt', 'content': 'AWS_KEY=AKIA1234567890EXAMPLE\nSTRIPE_KEY=sk_test_1234567890abcdef'}
        ]
        
        return jsonify({'files': sensitive_files})
        
    except Exception as e:
        return jsonify({'error': 'File access error'}), 500

class XMLLoginHandler(ContentHandler):
    """Optimized XML handler class"""
    def __init__(self):
        self.username = None
        self.password = None
        self.current_element = None
        self.content = ""
        self.depth = 0
        self.max_depth = 4  # Prevent deep nesting attacks
    
    def startElement(self, name, attrs):
        self.depth += 1
        if self.depth > self.max_depth:
            raise ValueError("XML nesting too deep")
            
        self.current_element = name
        self.content = ""
    
    def characters(self, content):
        if len(self.content) < 1000:  # Prevent memory exhaustion
            self.content += content
    
    def endElement(self, name):
        self.depth -= 1
        if name == 'username':
            self.username = self.content.strip()[:500]  # Limit length
        elif name == 'password':
            self.password = self.content.strip()[:500]  # Limit length

@app.route('/xml', methods=['POST'])
def xml_login():
    """XXE vulnerability preserved - intentional security flaw"""
    try:
        xml_data = request.data.decode('utf-8')
        if not xml_data or len(xml_data) > 10000:  # Basic size limit
            return jsonify({'error': 'Invalid XML data'}), 400

        parser = make_parser()
        parser.setFeature(feature_external_ges, True) # XXE Vulnerability
        handler = XMLLoginHandler()
        parser.setContentHandler(handler)

        parser.parse(io.StringIO(xml_data))

        if not handler.username or not handler.password:
            return jsonify({'error': 'Missing username or password in XML'}), 400

        if user_manager.authenticate(handler.username, handler.password):
            user_info = user_manager.get_user_info(handler.username)
            token = jwt.encode({
                'user': handler.username,
                'isadmin': user_info["is_admin"],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            }, XML_SECRET, algorithm='HS256')
            return jsonify({'token': token})
        else:
            return jsonify({'error': f'Invalid credentials: {str(handler.username)}, {str(handler.password)}'}), 401
            
    except ET.ParseError:
        return jsonify({'error': 'Invalid XML format'}), 400
    except ValueError as e:
        return jsonify({'error': f'XML processing error: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'XML processing error: {str(e)}'}), 500

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(405)
def method_not_allowed_error(error):
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    """Handle unexpected exceptions"""
    app.logger.error(f'Unhandled exception: {str(e)}')
    return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == '__main__':
    # Production-like configuration
    app.run(
        debug=True,
        host='0.0.0.0',
        port=8000,
        threaded=True,
        use_reloader=True
    )