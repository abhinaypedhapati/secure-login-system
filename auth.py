"""
Authentication logic with bcrypt hashing and input validation
"""

import re
import bcrypt
from database import get_user_by_username, get_user_by_email, create_user, record_login_attempt, get_failed_attempts

# Input validation patterns
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
PASSWORD_PATTERN = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')

def validate_username(username):
    """Validate username format"""
    if not username:
        return False, "Username is required"
    if not USERNAME_PATTERN.match(username):
        return False, "Username must be 3-20 characters (letters, numbers, underscore only)"
    return True, ""

def validate_email(email):
    """Validate email format"""
    if not email:
        return False, "Email is required"
    if not EMAIL_PATTERN.match(email):
        return False, "Invalid email format"
    return True, ""

def validate_password(password):
    """Validate password strength"""
    if not password:
        return False, "Password is required"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[@$!%*?&]', password):
        return False, "Password must contain at least one special character (@$!%*?&)"
    return True, ""

def validate_password_match(password, confirm_password):
    """Check if passwords match"""
    if password != confirm_password:
        return False, "Passwords do not match"
    return True, ""

def hash_password(password):
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password, password_hash):
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def register_user(username, email, password, confirm_password):
    """Register a new user with validation"""
    # Validate inputs
    valid, msg = validate_username(username)
    if not valid:
        return False, msg
    
    valid, msg = validate_email(email)
    if not valid:
        return False, msg
    
    valid, msg = validate_password(password)
    if not valid:
        return False, msg
    
    valid, msg = validate_password_match(password, confirm_password)
    if not valid:
        return False, msg
    
    # Check if username already exists
    if get_user_by_username(username):
        return False, "Username already taken"
    
    # Check if email already exists
    if get_user_by_email(email):
        return False, "Email already registered"
    
    # Hash password and create user
    password_hash = hash_password(password)
    user_id = create_user(username, email, password_hash)
    
    if user_id:
        return True, "Registration successful! Please login."
    else:
        return False, "Registration failed. Please try again."

def login_user(username, password, ip_address):
    """Authenticate user with rate limiting"""
    # Check failed attempts
    failed_attempts = get_failed_attempts(username, ip_address, 15)
    if failed_attempts >= 5:
        record_login_attempt(username, ip_address, False)
        return False, "Too many failed attempts. Please try again later."
    
    # Get user
    user = get_user_by_username(username)
    if not user:
        record_login_attempt(username, ip_address, False)
        return False, "Invalid username or password"
    
    # Verify password
    if not verify_password(password, user['password_hash']):
        record_login_attempt(username, ip_address, False)
        return False, "Invalid username or password"
    
    # Successful login
    record_login_attempt(username, ip_address, True)
    return True, user

def sanitize_input(text):
    """Sanitize user input to prevent XSS"""
    if not text:
        return ""
    # Replace HTML special characters
    replacements = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;'
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    return text