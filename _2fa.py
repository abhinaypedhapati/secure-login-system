"""
Two-Factor Authentication - Simplified (No QR code dependency)
"""

import pyotp

def generate_2fa_secret():
    """Generate a new 2FA secret key"""
    return pyotp.random_base32()

def get_totp(secret):
    """Get TOTP object for the secret"""
    return pyotp.TOTP(secret)

def verify_2fa(secret, code):
    """Verify 2FA code"""
    if not secret or not code:
        return False
    return get_totp(secret).verify(code)

def setup_2fa_for_user(username):
    """Setup 2FA for a user"""
    secret = generate_2fa_secret()
    totp = get_totp(secret)
    return {
        'secret': secret,
        'qr_code': None,
        'uri': totp.provisioning_uri(name=username, issuer_name="SecureLogin")
    }

# These are placeholder functions - actual DB operations are in database.py
def enable_2fa_for_user(user_id, secret):
    from database import enable_2fa
    enable_2fa(user_id, secret)

def is_2fa_enabled(user_id):
    from database import get_user_by_id
    user = get_user_by_id(user_id)
    return user and user['twofa_enabled'] == 1

def disable_2fa_for_user(user_id):
    from database import disable_2fa
    disable_2fa(user_id)