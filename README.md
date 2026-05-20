# 🔐 Secure Login System

A production-ready authentication system with enterprise-grade security features including bcrypt password hashing, rate limiting, SQL injection protection, session management, and optional Two-Factor Authentication (2FA).

---

## 🌐 Live Demo

**[Click Here to View Live Demo](https://secure-login-system.onrender.com)**


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


## 🛠️ Tech Stack & Skills Involved

### Backend Technologies
| Technology | Purpose | Skill Level |
|------------|---------|-------------|
| **Python 3.11** | Core programming language | Advanced |
| **Flask** | Web framework for routing & sessions | Intermediate |
| **SQLite3** | Lightweight database for user storage | Intermediate |
| **bcrypt** | Password hashing with salt (12 rounds) | Advanced |
| **pyotp** | TOTP implementation for 2FA | Intermediate |
| **qrcode** | QR code generation for 2FA setup | Beginner |

### Security Skills Demonstrated
| Security Concept | Implementation |
|-----------------|----------------|
| **Password Hashing** | bcrypt with unique salt per password |
| **Brute Force Protection** | Rate limiting (5 attempts = 15 min lockout) |
| **SQL Injection Prevention** | Parameterized queries |
| **XSS Prevention** | Input sanitization & HTML escaping |
| **Session Security** | Secure session IDs + tracking |
| **Two-Factor Authentication** | TOTP (RFC 6238) |
| **Secure Logout** | Session invalidation |

### Frontend Skills
| Technology | Purpose |
|------------|---------|
| **HTML5** | Structure of web pages |
| **CSS3** | Styling & responsive design |
| **JavaScript** | Client-side validation & API calls |
| **Fetch API** | Asynchronous backend communication |

### DevOps & Deployment Skills
| Skill | Description |
|-------|-------------|
| **Git** | Version control |
| **GitHub** | Code hosting & collaboration |
| **Render.com** | Cloud deployment (free tier) |
| **Environment Variables** | Secure configuration management |

---


