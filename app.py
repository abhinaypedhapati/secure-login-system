from flask import Flask, render_template, request, jsonify, session
import secrets
import os
import sqlite3
import bcrypt
import re
from datetime import datetime
from contextlib import contextmanager
import pyotp

app = Flask(__name__)
app.secret_key = os.urandom(32)

DATABASE = 'secure_login.db'

# ==================== DATABASE FUNCTIONS ====================

@contextmanager
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                twofa_secret TEXT,
                twofa_enabled INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                ip_address TEXT,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success INTEGER DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_id TEXT UNIQUE,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP
            )
        ''')
        conn.commit()
        print("✅ Database initialized!")

def get_user_by_username(username):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cursor.fetchone()

def get_user_by_email(email):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cursor.fetchone()

def get_user_by_id(user_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cursor.fetchone()

def create_user(username, email, password_hash):
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash)
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None

def update_last_login(user_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
        conn.commit()

def enable_2fa(user_id, secret):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET twofa_secret = ?, twofa_enabled = 1 WHERE id = ?", (secret, user_id))
        conn.commit()

def disable_2fa(user_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET twofa_secret = NULL, twofa_enabled = 0 WHERE id = ?", (user_id,))
        conn.commit()

def is_2fa_enabled(user_id):
    user = get_user_by_id(user_id)
    return user and user['twofa_enabled'] == 1

def record_login_attempt(username, ip_address, success):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)",
            (username, ip_address, 1 if success else 0)
        )
        conn.commit()

def get_failed_attempts(username, ip_address, minutes=15):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT COUNT(*) FROM login_attempts 
            WHERE (username = ? OR ip_address = ?) AND success = 0 
            AND attempt_time > datetime('now', '-' || ? || ' minutes')
        ''', (username, ip_address, minutes))
        return cursor.fetchone()[0]

def save_session(user_id, session_id, ip_address, user_agent):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO user_sessions (user_id, session_id, ip_address, user_agent, last_activity) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
            (user_id, session_id, ip_address, user_agent)
        )
        conn.commit()

def update_session_activity(session_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE user_sessions SET last_activity = CURRENT_TIMESTAMP WHERE session_id = ?", (session_id,))
        conn.commit()

def delete_session(session_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_sessions WHERE session_id = ?", (session_id,))
        conn.commit()

def get_user_sessions(user_id, current_session_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT session_id, ip_address, user_agent, created_at, last_activity 
            FROM user_sessions WHERE user_id = ? AND session_id != ? ORDER BY last_activity DESC
        ''', (user_id, current_session_id))
        return cursor.fetchall()

# ==================== AUTH FUNCTIONS ====================

def hash_password(password):
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password, password_hash):
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def validate_username(username):
    if not username or len(username) < 3 or len(username) > 20:
        return False, "Username must be 3-20 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscore"
    return True, ""

def validate_email(email):
    if not email:
        return False, "Email is required"
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return False, "Invalid email format"
    return True, ""

def validate_password(password):
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain an uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain a lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain a number"
    if not re.search(r'[@$!%*?&]', password):
        return False, "Password must contain a special character (@$!%*?&)"
    return True, ""

# ==================== API ROUTES ====================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')
        
        valid, msg = validate_username(username)
        if not valid:
            return jsonify({'success': False, 'message': msg})
        
        valid, msg = validate_email(email)
        if not valid:
            return jsonify({'success': False, 'message': msg})
        
        valid, msg = validate_password(password)
        if not valid:
            return jsonify({'success': False, 'message': msg})
        
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'})
        
        if get_user_by_username(username):
            return jsonify({'success': False, 'message': 'Username already taken'})
        
        if get_user_by_email(email):
            return jsonify({'success': False, 'message': 'Email already registered'})
        
        password_hash = hash_password(password)
        user_id = create_user(username, email, password_hash)
        
        if user_id:
            return jsonify({'success': True, 'message': 'Registration successful! Please login.'})
        else:
            return jsonify({'success': False, 'message': 'Registration failed'})
            
    except Exception as e:
        print(f"Error in register: {e}")
        return jsonify({'success': False, 'message': 'Server error'})

@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        ip_address = request.remote_addr
        
        # Rate limiting check
        failed_attempts = get_failed_attempts(username, ip_address, 15)
        if failed_attempts >= 5:
            record_login_attempt(username, ip_address, False)
            return jsonify({'success': False, 'message': 'Too many failed attempts. Try again later.'})
        
        user = get_user_by_username(username)
        if not user or not verify_password(password, user['password_hash']):
            record_login_attempt(username, ip_address, False)
            return jsonify({'success': False, 'message': 'Invalid username or password'})
        
        record_login_attempt(username, ip_address, True)
        
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['twofa_verified'] = False
        session_id = secrets.token_urlsafe(32)
        session['session_id'] = session_id
        save_session(user['id'], session_id, ip_address, request.headers.get('User-Agent', ''))
        
        if user['twofa_enabled']:
            return jsonify({'success': True, 'message': '2FA required', 'require_2fa': True})
        else:
            session['twofa_verified'] = True
            update_last_login(user['id'])
            return jsonify({'success': True, 'message': 'Login successful', 'require_2fa': False})
            
    except Exception as e:
        print(f"Error in login: {e}")
        return jsonify({'success': False, 'message': 'Server error'})

@app.route('/api/verify-2fa', methods=['POST'])
def api_verify_2fa():
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Session expired'})
        
        data = request.get_json()
        code = data.get('code', '')
        user = get_user_by_id(session['user_id'])
        
        if user['twofa_secret']:
            totp = pyotp.TOTP(user['twofa_secret'])
            if totp.verify(code):
                session['twofa_verified'] = True
                update_last_login(user['id'])
                return jsonify({'success': True, 'message': '2FA verified'})
        
        return jsonify({'success': False, 'message': 'Invalid code'})
            
    except Exception as e:
        print(f"Error in verify-2fa: {e}")
        return jsonify({'success': False, 'message': 'Server error'})

@app.route('/api/dashboard', methods=['GET'])
def api_dashboard():
    try:
        if 'user_id' not in session or not session.get('twofa_verified', False):
            return jsonify({'logged_in': False})
        
        user = get_user_by_id(session['user_id'])
        return jsonify({
            'logged_in': True,
            'username': user['username'],
            'email': user['email'],
            'created_at': user['created_at'],
            'last_login': user['last_login'],
            'twofa_enabled': user['twofa_enabled'] == 1
        })
    except Exception as e:
        return jsonify({'logged_in': False})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    if 'session_id' in session:
        delete_session(session['session_id'])
    session.clear()
    return jsonify({'success': True})

@app.route('/api/check-username', methods=['POST'])
def api_check_username():
    try:
        data = request.get_json()
        username = data.get('username', '')
        user = get_user_by_username(username)
        return jsonify({'available': user is None})
    except Exception as e:
        return jsonify({'available': True})

@app.route('/api/check-email', methods=['POST'])
def api_check_email():
    try:
        data = request.get_json()
        email = data.get('email', '')
        user = get_user_by_email(email)
        return jsonify({'available': user is None})
    except Exception as e:
        return jsonify({'available': True})

@app.route('/api/sessions', methods=['GET'])
def api_sessions():
    try:
        if 'user_id' not in session or not session.get('twofa_verified', False):
            return jsonify([])
        sessions = get_user_sessions(session['user_id'], session['session_id'])
        return jsonify([dict(s) for s in sessions])
    except Exception as e:
        return jsonify([])

@app.route('/api/revoke-session', methods=['POST'])
def api_revoke_session():
    try:
        data = request.get_json()
        delete_session(data.get('session_id'))
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False})

@app.route('/api/setup-2fa', methods=['GET'])
def api_setup_2fa():
    try:
        if 'user_id' not in session or not session.get('twofa_verified', False):
            return jsonify({'error': 'Unauthorized'}), 401
        
        user = get_user_by_id(session['user_id'])
        
        # Generate a real secret key
        secret = pyotp.random_base32()
        
        # Generate provisioning URI
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(name=user['username'], issuer_name="SecureLogin")
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode()
        
        session['temp_2fa_secret'] = secret
        
        return jsonify({
            'secret': secret,
            'qr_code': qr_base64
        })
    except Exception as e:
        print(f"Error in setup-2fa: {e}")
        return jsonify({'secret': 'ABCDEFGHIJKLMNOP', 'qr_code': ''})

@app.route('/api/setup-2fa', methods=['POST'])
def api_setup_2fa_enable():
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Not logged in'})
        
        data = request.get_json()
        secret = data.get('secret')
        code = data.get('code')
        
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            enable_2fa(session['user_id'], secret)
            return jsonify({'success': True, 'message': '2FA enabled'})
        else:
            return jsonify({'success': False, 'message': 'Invalid code'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/disable-2fa', methods=['POST'])
def api_disable_2fa():
    if 'user_id' in session:
        disable_2fa(session['user_id'])
    return jsonify({'success': True})

# Initialize database
init_db()

if __name__ == '__main__':
    print("="*50)
    print("🔐 Secure Login System - Running")
    print("="*50)
    print("Open http://localhost:5000 in your browser")
    print("Press Ctrl+C to stop")
    print("="*50)
    app.run(debug=True, host='0.0.0.0', port=5000)