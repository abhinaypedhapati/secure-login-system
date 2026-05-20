# 🔐 Secure Login System

A production-ready authentication system with enterprise-grade security features including bcrypt password hashing, rate limiting, SQL injection protection, session management, and optional Two-Factor Authentication (2FA).

---

## 📌 Quick Overview

| Feature                   | Status | Description                         |
| ------------------------- | ------ | ----------------------------------- |
| User Registration         | ✅      | Create new accounts with validation |
| Secure Login              | ✅      | bcrypt password verification        |
| Password Hashing          | ✅      | bcrypt with 12 rounds + salt        |
| SQL Injection Protection  | ✅      | Parameterized queries throughout    |
| Rate Limiting             | ✅      | 5 attempts = 15 minute lockout      |
| Session Management        | ✅      | Track all active sessions           |
| Session Revocation        | ✅      | Remotely kill suspicious sessions   |
| Two-Factor Authentication | ✅      | TOTP with Google Authenticator      |
| Input Validation          | ✅      | Prevent XSS and injection attacks   |
| Logout                    | ✅      | Secure session termination          |



