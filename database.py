"""
Database operations with SQL injection protection
Using parameterized queries for security
"""

import sqlite3
import hashlib
from contextlib import contextmanager

DATABASE = 'secure_login.db'

@contextmanager
def get_db():
    """Get database connection with context manager"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    """Initialize database tables"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Users table - stores user credentials and 2FA secrets
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
        
        # Login attempts table - for rate limiting and security
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                ip_address TEXT,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success INTEGER DEFAULT 0
            )
        ''')
        
        # Sessions table - track active sessions
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_id TEXT UNIQUE,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        print("✅ Database initialized successfully!")

def create_user(username, email, password_hash):
    """Create a new user with parameterized query (SQL injection safe)"""
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

def get_user_by_username(username):
    """Get user by username - parameterized query"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cursor.fetchone()

def get_user_by_email(email):
    """Get user by email - parameterized query"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cursor.fetchone()

def get_user_by_id(user_id):
    """Get user by ID - parameterized query"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cursor.fetchone()

def update_last_login(user_id):
    """Update user's last login time"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (user_id,)
        )
        conn.commit()

def enable_2fa(user_id, secret):
    """Enable 2FA for user"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET twofa_secret = ?, twofa_enabled = 1 WHERE id = ?",
            (secret, user_id)
        )
        conn.commit()

def disable_2fa(user_id):
    """Disable 2FA for user"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET twofa_secret = NULL, twofa_enabled = 0 WHERE id = ?",
            (user_id,)
        )
        conn.commit()

def record_login_attempt(username, ip_address, success):
    """Record login attempt for security monitoring"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)",
            (username, ip_address, 1 if success else 0)
        )
        conn.commit()

def get_failed_attempts(username, ip_address, minutes=15):
    """Get number of failed login attempts in last X minutes"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT COUNT(*) FROM login_attempts 
            WHERE (username = ? OR ip_address = ?) 
            AND success = 0 
            AND attempt_time > datetime('now', '-' || ? || ' minutes')
        ''', (username, ip_address, minutes))
        return cursor.fetchone()[0]

def save_session(user_id, session_id, ip_address, user_agent):
    """Save user session"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO user_sessions (user_id, session_id, ip_address, user_agent, last_activity) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
            (user_id, session_id, ip_address, user_agent)
        )
        conn.commit()

def update_session_activity(session_id):
    """Update session last activity time"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE user_sessions SET last_activity = CURRENT_TIMESTAMP WHERE session_id = ?",
            (session_id,)
        )
        conn.commit()

def delete_session(session_id):
    """Delete a session (logout)"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_sessions WHERE session_id = ?", (session_id,))
        conn.commit()

def delete_all_user_sessions(user_id, current_session_id=None):
    """Delete all user sessions except current one"""
    with get_db() as conn:
        cursor = conn.cursor()
        if current_session_id:
            cursor.execute(
                "DELETE FROM user_sessions WHERE user_id = ? AND session_id != ?",
                (user_id, current_session_id)
            )
        else:
            cursor.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
        conn.commit()

if __name__ == "__main__":
    init_db()