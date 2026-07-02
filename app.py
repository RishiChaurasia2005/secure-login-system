from flask import Flask, request, session, redirect, url_for, render_template_string, flash
import bcrypt
import sqlite3
import os
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
import re

app = Flask(__name__)
app.secret_key = os.urandom(24)
DB = 'users.db'

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success INTEGER DEFAULT 0
            )''')
        db.commit()

def is_rate_limited(username):
    with get_db() as db:
        cutoff = datetime.now() - timedelta(minutes=15)
        row = db.execute(
            'SELECT COUNT(*) as cnt FROM login_attempts WHERE username=? AND success=0 AND attempt_time > ?',
            (username, cutoff)
        ).fetchone()
        return row['cnt'] >= 5

def record_attempt(username, success):
    with get_db() as db:
        db.execute('INSERT INTO login_attempts (username, success) VALUES (?,?)', (username, int(success)))
        db.commit()

def validate_input(text, max_len=64):
    return bool(text) and len(text) <= max_len and re.match(r'^[\w.@+\-]+$', text)

BASE = '''
<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Secure Login</title>
<style>
body{font-family:Arial,sans-serif;max-width:420px;margin:60px auto;padding:20px;background:#f4f6f9;}
.card{background:#fff;padding:30px;border-radius:10px;box-shadow:0 2px 12px rgba(0,0,0,.1);}
h2{text-align:center;color:#2c3e50;margin-bottom:24px;}
input{width:100%;padding:10px;margin:8px 0 16px;box-sizing:border-box;border:1px solid #ddd;border-radius:6px;font-size:14px;}
button{width:100%;padding:12px;background:#01696f;color:#fff;border:none;border-radius:6px;font-size:15px;cursor:pointer;}
button:hover{background:#0c4e54;}
.flash{background:#fdecea;color:#c0392b;padding:10px;border-radius:6px;margin-bottom:14px;font-size:13px;}
.success{background:#eafaf1;color:#27ae60;}
a{color:#01696f;}
</style></head><body><div class="card">
{% with msgs=get_flashed_messages(with_categories=true) %}{% for cat,msg in msgs %}
<div class="flash {{ 'success' if cat=='success' else '' }}">{{msg}}</div>
{% endfor %}{% endwith %}
{{ content }}
</div></body></html>
'''

REGISTER_FORM = BASE.replace('{{ content }}', '''
<h2>📝 Register</h2>
<form method="POST">
  <label>Username</label><input name="username" required maxlength="32">
  <label>Email</label><input name="email" type="email" required maxlength="64">
  <label>Password</label><input name="password" type="password" required minlength="8">
  <button type="submit">Create Account</button>
</form>
<p style="text-align:center;margin-top:16px;">Already have an account? <a href="/login">Login</a></p>
''')

LOGIN_FORM = BASE.replace('{{ content }}', '''
<h2>🔐 Login</h2>
<form method="POST">
  <label>Username</label><input name="username" required>
  <label>Password</label><input name="password" type="password" required>
  <button type="submit">Login</button>
</form>
<p style="text-align:center;margin-top:16px;">No account? <a href="/register">Register</a></p>
''')

TOTP_FORM = BASE.replace('{{ content }}', '''
<h2>🔑 Two-Factor Auth</h2>
<p>Enter the 6-digit code from your authenticator app.</p>
<form method="POST">
  <label>OTP Code</label><input name="otp" maxlength="6" pattern="[0-9]{6}" required autofocus>
  <button type="submit">Verify</button>
</form>
''')

DASHBOARD = BASE.replace('{{ content }}', '''
<h2>✅ Dashboard</h2>
<p>Welcome, <strong>{{ username }}</strong>! You are securely logged in.</p>
<p>Session started at: {{ login_time }}</p>
<hr style="margin:20px 0;">
<p>🔒 2FA Status: <strong>{{ totp_status }}</strong></p>
{% if not totp_enabled %}
<form action="/enable-2fa" method="POST"><button style="background:#437a22;">Enable 2FA</button></form>
{% endif %}
<form action="/logout" method="POST" style="margin-top:12px;">
<button style="background:#a12c7b;">Logout</button></form>
''')

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        email    = request.form.get('email','').strip()
        password = request.form.get('password','')
        if not validate_input(username) or not validate_input(email, 64) or len(password) < 8:
            flash('Invalid input. Username/email max 64 chars, password min 8 chars.')
            return render_template_string(REGISTER_FORM)
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
        try:
            with get_db() as db:
                db.execute('INSERT INTO users (username,email,password_hash) VALUES (?,?,?)',
                           (username, email, pw_hash))
                db.commit()
            flash('Account created! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.')
    return render_template_string(REGISTER_FORM)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        if not validate_input(username):
            flash('Invalid input.')
            return render_template_string(LOGIN_FORM)
        if is_rate_limited(username):
            flash('Too many failed attempts. Try again in 15 minutes.')
            return render_template_string(LOGIN_FORM)
        with get_db() as db:
            user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            record_attempt(username, True)
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if user['totp_secret']:
                session['totp_pending'] = True
                return redirect(url_for('verify_2fa'))
            return redirect(url_for('dashboard'))
        else:
            record_attempt(username, False)
            flash('Invalid username or password.')
    return render_template_string(LOGIN_FORM)

@app.route('/verify-2fa', methods=['GET','POST'])
def verify_2fa():
    if 'user_id' not in session or not session.get('totp_pending'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        otp = request.form.get('otp','').strip()
        with get_db() as db:
            user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
        totp = pyotp.TOTP(user['totp_secret'])
        if totp.verify(otp, valid_window=1):
            session.pop('totp_pending', None)
            return redirect(url_for('dashboard'))
        flash('Invalid OTP code. Try again.')
    return render_template_string(TOTP_FORM)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or session.get('totp_pending'):
        return redirect(url_for('login'))
    with get_db() as db:
        user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    totp_enabled = bool(user['totp_secret'])
    return render_template_string(
        DASHBOARD,
        username=session['username'],
        login_time=session.get('login_time','N/A'),
        totp_status='Enabled ✅' if totp_enabled else 'Disabled ❌',
        totp_enabled=totp
