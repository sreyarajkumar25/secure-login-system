 Secure Login System

Flask web application with secure authentication practices.

```bash
cd 4-secure-login-system
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

**Features:**
- User registration and login
- bcrypt password hashing (never plaintext)
- Parameterized SQL queries (SQL injection protection)
- Session management with secure cookies and logout
- Login attempt logging
- Optional TOTP two-factor authentication (QR code setup)