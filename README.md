# 🔐 Secure Login System

## Project Overview

**Secure Login System** is a Flask-based web application designed to demonstrate modern authentication mechanisms and web application security best practices. The project implements secure user authentication, password hashing, session management, brute-force protection, and optional Two-Factor Authentication (2FA).

Developed as part of the **Cybersecurity Internship** at the **Thiranex Student Program**, this project provides hands-on experience in building secure authentication systems.

---

## Key Features

### User Registration & Authentication

- Secure user registration and login
- Password hashing using **bcrypt**
- Support for stronger hashing algorithms such as **Argon2** (optional)
- Secure password verification

### Input Validation

- Regex-based input validation
- Email and password validation
- Protection against malformed input
- SQL Injection prevention using parameterized queries

### Session Management

- Secure user session handling
- Login timestamp tracking
- Automatic session cleanup on logout
- Protected routes requiring authentication

### Brute-Force Protection

- Rate limiting for failed login attempts
- Temporary account lockout after repeated failures
- Reduces the risk of password guessing attacks

### Two-Factor Authentication (2FA)

- Optional TOTP-based authentication
- Compatible with:
  - Google Authenticator
  - Authy
  - Microsoft Authenticator
- QR code generation for quick setup
- OTP verification during login

---

## Tech Stack

### Backend

- Python 3.9+
- Flask

### Database

- SQLite

### Security Libraries

- bcrypt
- pyotp

### Utilities

- qrcode
- Pillow

---

## Requirements

- Python 3.9 or later

Install the required dependencies:

```bash
pip install -r requirements.txt
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/RishiChaurasia2005/secure-login-system.git
```

Navigate to the project directory:

```bash
cd secure-login-system
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Running the Application

Start the Flask server:

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

---

## Usage

### Register

- Create a new account using:
  - Username
  - Email
  - Strong password

### Login

- Enter your registered credentials.
- Access the protected dashboard after successful authentication.

### Enable Two-Factor Authentication

1. Navigate to the dashboard.
2. Enable 2FA.
3. Scan the generated QR code using:
   - Google Authenticator
   - Authy
   - Microsoft Authenticator
4. Enter the generated six-digit OTP to verify.

### Logout

- End the current session securely.
- All session data is cleared upon logout.

---

## Security Features

- Password hashing using bcrypt
- SQL Injection protection
- Input sanitization and validation
- Session management
- Brute-force attack mitigation
- Time-based One-Time Password (TOTP) authentication
- Secure authentication workflow

---

## Disclaimer

This project is intended **for educational and learning purposes only**.

Although it follows several industry-standard security practices, additional security testing, monitoring, and hardening should be performed before deploying it in a production environment.

---

## Internship Domain

**Cybersecurity — Thiranex Student Program**

Learn more:

**https://thiranex.in/student**

---

## License

This project does not currently include a license.
