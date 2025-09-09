<<<<<<< HEAD
import sys
import os
import logging
from logging.handlers import RotatingFileHandler
import secrets
import subprocess
from pathlib import Path
import threading
import importlib
import webbrowser

# --- User-Writable Data Directory ---
APP_NAME = "AegisScanner"
if sys.platform == "win32":
    USER_DATA_DIR = os.path.join(os.environ['LOCALAPPDATA'], APP_NAME)
else:
    USER_DATA_DIR = os.path.join(os.path.expanduser('~'), f'.{APP_NAME.lower()}')
os.makedirs(USER_DATA_DIR, exist_ok=True)

# --- Global File Paths ---
log_file = os.path.join(USER_DATA_DIR, 'aegis_scanner_debug.log')
ENV_FILE_PATH = os.path.join(USER_DATA_DIR, '.env')

# --- Hardcoded Debug Flag ---
# This makes debug mode permanently on for this file.
is_debug = False
log_level = logging.DEBUG

# --- SIMPLIFIED LOGGING SETUP ---
def configure_logging():
    """Configures logging for the entire application script."""
    log_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    
    # Handlers: one for the file, one for the main terminal
    file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=5)
    file_handler.setFormatter(log_formatter)
    
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(log_formatter)

    # Configure the Root Logger
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(file_handler)
    # Also log to the main app terminal for convenience
    if not getattr(sys, 'frozen', False):
         root_logger.addHandler(stream_handler)
    root_logger.setLevel(log_level)

    # Set Levels for Library Loggers
    logging.getLogger('waitress').setLevel(logging.INFO)
    logging.getLogger('werkzeug').setLevel(logging.WARNING) # Changed from DEBUG to WARNING
    logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

# --- CONFIGURE LOGGING IMMEDIATELY ---
configure_logging()


from flask import Flask, jsonify, request, redirect, url_for, render_template, flash, session, Response, make_response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_
=======
from flask import Flask, jsonify, request, redirect, url_for, render_template, flash, session, Response
from flask_cors import CORS
from s3_scanner import run_all_scans
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
<<<<<<< HEAD
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import datetime
from datetime import timedelta, timezone
from functools import wraps
import click
from flask_wtf.csrf import CSRFProtect, generate_csrf, CSRFError
from flask_talisman import Talisman
import boto3
from cryptography.fernet import Fernet
=======
import os
import datetime
import boto3
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
import pyotp
import qrcode
from io import BytesIO
import base64
import re
from weasyprint import HTML
<<<<<<< HEAD
from waitress import serve
from itsdangerous import URLSafeTimedSerializer
import parallel_scanner
import json
import hashlib
from zxcvbn import zxcvbn
from botocore.exceptions import ClientError
from google.oauth2 import service_account
from google.cloud import storage
from dotenv import load_dotenv

# --- Global Variables ---
db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
login_manager = LoginManager()
mail = Mail()
csrf = CSRFProtect()
limiter = Limiter(get_remote_address, storage_uri="memory://")
s = None
fernet = None


# --- Main App Creation using Factory Pattern ---
def create_app():
    if getattr(sys, 'frozen', False):
        template_folder = os.path.join(sys._MEIPASS, 'templates')
        static_folder = os.path.join(sys._MEIPASS, 'static')
    else:
        template_folder = 'templates'
        static_folder = 'static'

    app = Flask(__name__, instance_relative_config=True, template_folder=template_folder, static_folder=static_folder)
    
    # Load environment variables for the app's configuration
    if os.path.exists(ENV_FILE_PATH):
        load_dotenv(dotenv_path=ENV_FILE_PATH)

    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or secrets.token_hex(24)
    app.config['ENCRYPTION_KEY'] = os.getenv('ENCRYPTION_KEY')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    DB_PATH = os.path.join(USER_DATA_DIR, 'app.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
    app.config['SQLALCHEMY_ECHO'] = False # We use the logger for this now

    global s, fernet
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    if app.config['ENCRYPTION_KEY']:
        fernet = Fernet(app.config['ENCRYPTION_KEY'].encode())
    
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth'
    login_manager.login_message_category = "info"
    mail.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    csp = {
        'default-src': '\'self\'',
        'script-src': ['\'self\'', 'https://cdn.jsdelivr.net', 'https://unpkg.com', 'https://cdnjs.cloudflare.com', '\'unsafe-inline\''],
        'style-src': ['\'self\'', 'https://cdnjs.cloudflare.com', 'https://fonts.googleapis.com', 'https://unpkg.com', 'https://cdn.jsdelivr.net', '\'unsafe-inline\''],
        'font-src': ['\'self\'', 'https://cdnjs.cloudflare.com', 'https://fonts.gstatic.com'],
        'img-src': ['\'self\'', 'data:']
    }
    Talisman(app, content_security_policy=csp, force_https=False)

    return app

app = create_app()

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    logging.warning(f"--- [SECURITY] CSRF token validation failed. Reason: {e.description} ---")
    flash('Your form session has expired. Please log in and try again.', 'error')
    return redirect(url_for('auth'))

@app.template_filter('a_id_decrypt')
def a_id_decrypt_filter(s):
    try:
        return decrypt_data(s)
    except Exception:
        return "N/A"

# --- Helper Functions ---
def encrypt_data(data, context="generic data"):
    if fernet: 
        logging.info(f"--- [SECURITY] Encrypting {context}. ---")
        return fernet.encrypt(data.encode()).decode()
    raise ValueError("Encryption key not configured.")

def decrypt_data(encrypted_data, context="generic data"):
    if fernet: 
        logging.info(f"--- [SECURITY] Decrypting {context}. ---")
        return fernet.decrypt(encrypted_data.encode()).decode()
    raise ValueError("Encryption key not configured.")
=======
from apscheduler.schedulers.background import BackgroundScheduler
from waitress import serve

# --- App Initialization ---
app = Flask(__name__, instance_relative_config=True, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = 'a-very-secret-and-secure-key-that-you-should-change'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- FIX: Define the database path in the user's AppData folder ---
# This is the standard, writable location for application data.
APP_DATA_DIR = os.path.join(os.getenv('APPDATA'), 'CloudSecurityScanner')
os.makedirs(APP_DATA_DIR, exist_ok=True) # Ensure this directory exists
DB_PATH = os.path.join(APP_DATA_DIR, 'app.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
# --- End of FIX ---

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')

# --- Extensions Initialization ---
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth'
login_manager.login_message_category = "info"
mail = Mail(app)
CORS(app)
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1

# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
<<<<<<< HEAD
    email = db.Column(db.String(120), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    failed_login_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    otp_secret = db.Column(db.String(32))
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    inactivity_timeout = db.Column(db.Integer, default=15, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    backup_email = db.Column(db.String(120), unique=True, nullable=True)
    backup_email_verified = db.Column(db.Boolean, default=False)
    notifications_enabled = db.Column(db.Boolean, nullable=False, default=True)
    report_schedule = db.Column(db.String(20), default='disabled', nullable=False)
    report_day = db.Column(db.String(10), nullable=True)
    report_credential_id = db.Column(db.Integer, nullable=True)
    scans = db.relationship('ScanResult', backref='author', lazy='dynamic', cascade="all, delete-orphan")
    credentials = db.relationship('CloudCredential', backref='owner', lazy='dynamic', cascade="all, delete-orphan")
    password_history = db.relationship('PasswordHistory', backref='user', lazy='dynamic', cascade="all, delete-orphan")
    def set_password(self, password): self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    def check_password(self, password): return bcrypt.check_password_hash(self.password_hash, password)

class CloudCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    profile_name = db.Column(db.String(64), nullable=False)
    provider = db.Column(db.String(20), nullable=False, index=True)
    encrypted_key_1 = db.Column(db.String(512), nullable=True)
    encrypted_key_2 = db.Column(db.Text, nullable=True)

=======
    password_hash = db.Column(db.String(128))
    otp_secret = db.Column(db.String(32))
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    scans = db.relationship('ScanResult', backref='author', lazy='dynamic')
    def set_password(self, password): self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    def check_password(self, password): return bcrypt.check_password_hash(self.password_hash, password)

>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.String(64), index=True)
    resource = db.Column(db.String(128))
    status = db.Column(db.String(64))
    issue = db.Column(db.String(256))
<<<<<<< HEAD
    remediation = db.Column(db.String(512), nullable=True)
    doc_url = db.Column(db.String(256), nullable=True)
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    ip_address = db.Column(db.String(45))
    action = db.Column(db.String(128))
    details = db.Column(db.String(256), nullable=True)
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    user = db.relationship('User')

class SuppressedFinding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    finding_hash = db.Column(db.String(64), nullable=False, index=True)
    reason = db.Column(db.String(256), nullable=True)
    suppress_until = db.Column(db.DateTime, nullable=True)
    service = db.Column(db.String(64))
    resource = db.Column(db.String(128))
    issue = db.Column(db.String(256))
    user = db.relationship('User')

class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    password_hash = db.Column(db.String(128))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc))
    __table_args__ = (db.UniqueConstraint('user_id', 'password_hash', name='uq_user_password_history'),)

# --- App Context Functions and Decorators ---
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token_value=generate_csrf())

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("You do not have permission to access this page.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def check_verified(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.email_verified:
            flash("You must verify your email address to access this page.", "warning")
            return redirect(url_for('unverified'))
        return f(*args, **kwargs)
    return decorated_function

def check_2fa(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.is_2fa_enabled:
            if session.get('2fa_passed') is not True:
                flash("Please complete the 2FA verification to continue.", "warning")
                return redirect(url_for('verify_2fa_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def before_request():
    if not request.endpoint:
        return
    if 'static' == request.endpoint:
        return
    if current_user.is_authenticated:
        session.permanent = True
        timeout_minutes = current_user.inactivity_timeout if hasattr(current_user, 'inactivity_timeout') else 15
        app.permanent_session_lifetime = timedelta(minutes=timeout_minutes)
        if 'last_activity' in session:
            last_activity_dt = datetime.datetime.fromisoformat(session['last_activity'])
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            if now_utc - last_activity_dt > app.permanent_session_lifetime:
                logout_user()
                flash('Your session has expired due to inactivity. Please log in again.', 'info')
        session['last_activity'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
=======
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def is_password_strong(password):
<<<<<<< HEAD
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    results = zxcvbn(password)
    if results['score'] < 3:
        return False, f"Password is too weak. {results['feedback']['warning'] or 'Please use a stronger password.'} {results['feedback']['suggestions']}"
    return True, ""

def log_audit(action, details="", user=None):
    with app.app_context():
        try:
            log_entry = AuditLog(action=action, details=details, ip_address=request.remote_addr, user_id=user.id if user else None)
            db.session.add(log_entry)
            db.session.commit()
        except Exception as e:
            logging.error(f"Audit log failed: {e}")
            db.session.rollback()

def send_verification_email(user):
    with app.app_context():
        logging.info(f"--- [EMAIL] Generating verification email for {user.email}. ---")
        token = s.dumps(user.email, salt='email-confirm-salt')
        msg = Message('Confirm Your Email for Aegis Scanner', recipients=[user.email])
        confirm_url = url_for('verify_email', token=token, _external=True)
        msg.html = render_template('confirm_email.html', confirm_url=confirm_url)
        try: 
            mail.send(msg)
            logging.info(f"--- [EMAIL] Verification email successfully sent to {user.email}. ---")
        except Exception as e: 
            logging.error(f"--- [EMAIL] FAILED to send verification email: {e} ---")

def send_new_primary_email_verification(user, new_email):
    with app.app_context():
        token = s.dumps({'user_id': user.id, 'new_email': new_email}, salt='new-primary-email-salt')
        msg = Message('Confirm Your New Primary Email', recipients=[new_email])
        confirm_url = url_for('verify_new_primary_email', token=token, _external=True)
        msg.html = render_template('confirm_email.html', confirm_url=confirm_url)
        mail.send(msg)

def send_backup_email_verification(user, backup_email):
    with app.app_context():
        token = s.dumps({'user_id': user.id, 'backup_email': backup_email}, salt='backup-email-salt')
        msg = Message('Confirm Your Backup Email', recipients=[backup_email])
        confirm_url = url_for('verify_backup_email', token=token, _external=True)
        msg.html = render_template('confirm_email.html', confirm_url=confirm_url)
        mail.send(msg)

def _create_pdf_report(results):
    html_string = render_template('report.html', results=results, scan_date=datetime.datetime.now())
    return HTML(string=html_string).write_pdf()

def _generate_cache_key(user_id, profile_id, regions):
    regions_str = "|".join(sorted(regions)) if regions else "global"
    return f"{user_id}_{profile_id}_{regions_str}"

def _generate_finding_hash(finding):
    finding_string = f"{finding.get('service', '')}:{finding.get('resource', '')}:{finding.get('issue', '')}"
    return hashlib.sha256(finding_string.encode()).hexdigest()

# --- Main Application Routes ---
@app.route('/')
def initializing():
    logging.debug("Serving the initial loading page: initializing.html")
    return render_template('initializing.html')

@app.route('/splash')
def splash():
    return render_template('splash.html')

@app.route('/welcome')
def welcome():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
=======
    if len(password) < 8: return False, "Password must be at least 8 characters long."
    if not re.search(r"[a-z]", password): return False, "Password must contain a lowercase letter."
    if not re.search(r"[A-Z]", password): return False, "Password must contain an uppercase letter."
    if not re.search(r"\d", password): return False, "Password must contain a digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): return False, "Password must contain a special character."
    return True, ""

# --- Email & Scheduled Job Functions ---
def send_alert_email(new_findings):
    recipient = os.environ.get('MAIL_USERNAME')
    if not recipient:
        print("ERROR: MAIL_USERNAME not set. Cannot send alert email.")
        return
    msg = Message("CRITICAL SECURITY ALERT: New Issues Detected", recipients=[recipient])
    msg.html = render_template('alert_email.html', new_findings=new_findings)
    try:
        mail.send(msg)
        print(f"Alert email sent to {recipient}.")
    except Exception as e:
        print(f"ERROR: Failed to send email: {e}")

def scheduled_scan_job():
    print(f"--- Running scheduled scan at {datetime.datetime.now()} ---")
    with app.app_context():
        scan_time = datetime.datetime.now(datetime.timezone.utc)
        last_scan = db.session.query(ScanResult).filter_by(user_id=None).order_by(ScanResult.timestamp.desc()).first()
        previous_critical_resources = set()
        if last_scan:
            previous_scan_time = last_scan.timestamp
            previous_critical_results = db.session.query(ScanResult).filter(ScanResult.user_id == None, ScanResult.timestamp == previous_scan_time, ScanResult.status == 'CRITICAL').all()
            previous_critical_resources = {f"{r.service}:{r.resource}" for r in previous_critical_results}
        current_scan_results = run_all_scans()
        current_critical_resources = set()
        for result in current_scan_results:
            if "error" not in result:
                if result.get('status') == 'CRITICAL':
                    current_critical_resources.add(f"{result.get('service')}:{result.get('resource')}")
                db_result = ScanResult(service=result.get('service'), resource=result.get('resource'), status=result.get('status'), issue=result.get('issue'), timestamp=scan_time, author=None)
                db.session.add(db_result)
        db.session.commit()
        newly_found_critical = current_critical_resources - previous_critical_resources
        if newly_found_critical:
            print(f"ALERT: Found {len(newly_found_critical)} new critical issues.")
            new_findings_objects = [res for res in current_scan_results if f"{res.get('service')}:{res.get('resource')}" in newly_found_critical]
            send_alert_email(new_findings_objects)
        else:
            print("No new critical issues found.")
    print("--- Scheduled scan finished. ---")

# --- Routes & Other Logic ---
scan_cache = {'results': [], 'timestamp': datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=60)}
CACHE_EXPIRY_SECONDS = 60

@app.route('/')
def welcome():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
    return render_template('welcome.html')

@app.route('/auth')
def auth():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return render_template('auth.html')

@app.route('/login', methods=['POST'])
<<<<<<< HEAD
@limiter.limit("10 per minute")
def login_post():
    login_identifier = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter(or_(User.username == login_identifier, User.email == login_identifier)).first()
    if user and user.is_locked:
        logging.warning(f"--- [AUTH] Locked account login attempt for user '{login_identifier}'. ---")
        flash('This account is locked. Please contact an administrator.', 'error')
        return redirect(url_for('auth', _anchor='login'))
    if user and user.check_password(password):
        user.failed_login_attempts = 0
        db.session.commit()
        log_audit("Login Success", user=user)
        login_user(user)
        logging.info(f"--- [AUTH] Successful login for user '{user.username}'. ---")
        if not user.email_verified: return redirect(url_for('unverified'))
        if user.is_2fa_enabled:
            session['username_for_2fa'] = user.username
            session['2fa_passed'] = False
            return redirect(url_for('verify_2fa_login'))
        else:
            flash('For enhanced security, you must set up Two-Factor Authentication.', 'info')
            return redirect(url_for('setup_2fa'))
    else:
        log_audit("Login Failure", details=f"Attempt for user: '{login_identifier}'")
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= 3:
                user.is_locked = True
                logging.critical(f"--- [AUTH] Account for user '{user.username}' has been locked due to too many failed login attempts. ---")
                log_audit("Account Locked", details=f"Account locked for user: '{user.username}'", user=user)
            else:
                logging.warning(f"--- [AUTH] Failed login attempt for user '{user.username}'. Attempt #{user.failed_login_attempts}. ---")
            db.session.commit()
        else:
            logging.warning(f"--- [AUTH] Failed login attempt for non-existent user '{login_identifier}'. ---")
=======
def login_post():
    user = User.query.filter_by(username=request.form.get('username')).first()
    if user and user.check_password(request.form.get('password')):
        if user.is_2fa_enabled:
            session['username_for_2fa'] = user.username
            return redirect(url_for('verify_2fa_login'))
        else:
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
    else:
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
        flash('Invalid username or password.', 'error')
        return redirect(url_for('auth', _anchor='login'))

@app.route('/register', methods=['POST'])
<<<<<<< HEAD
@limiter.limit("10 per hour")
def register_post():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    eula_accepted = request.form.get('eula')
    admin_key = request.form.get('admin_key')
    
=======
def register_post():
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    eula_accepted = request.form.get('eula')
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
    if not eula_accepted:
        flash('You must accept the EULA to register.', 'error')
        return redirect(url_for('auth', _anchor='register'))
    if password != confirm_password:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('auth', _anchor='register'))
    is_strong, message = is_password_strong(password)
    if not is_strong:
        flash(message, 'error')
        return redirect(url_for('auth', _anchor='register'))
    if User.query.filter_by(username=username).first():
        flash('Username already exists. Please choose another.', 'error')
        return redirect(url_for('auth', _anchor='register'))
<<<<<<< HEAD
    if User.query.filter_by(email=email).first():
        flash('Email address is already registered.', 'error')
        return redirect(url_for('auth', _anchor='register'))
        
    user = User(username=username, email=email)
    logging.info(f"--- [AUTH] Hashing password for new user '{username}'. ---")
    user.set_password(password)
    user_password_history = PasswordHistory(user=user, password_hash=user.password_hash)
    db.session.add(user_password_history)

    if admin_key and admin_key == os.getenv('ADMIN_REGISTRATION_KEY'):
        if User.query.filter_by(is_admin=True).count() < 2:
            user.is_admin = True
            logging.info(f"--- [AUTH] Valid admin key provided. Promoting user '{username}' to admin. ---")
        else:
            logging.warning("--- [AUTH] Valid admin key provided, but max admin count reached. User will be standard. ---")

    db.session.add(user)
    db.session.commit()
    send_verification_email(user)
    login_user(user)
    flash('Registration successful! A verification link has been sent to your email.', 'info')
    return redirect(url_for('unverified'))

@app.route('/verify-email/<token>')
@login_required
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm-salt', max_age=3600)
    except Exception:
        flash('The confirmation link is invalid or has expired.', 'error')
        return redirect(url_for('unverified'))
    if email != current_user.email:
        flash('Invalid verification link.', 'error')
        return redirect(url_for('unverified'))
    if not current_user.email_verified:
        current_user.email_verified = True
        db.session.commit()
        logging.info(f"--- [AUTH] Email successfully verified for user '{current_user.username}'. ---")
        log_audit("Email Verified", user=current_user)
        flash('Your email has been verified! Please set up 2FA to continue.', 'success')
        return redirect(url_for('setup_2fa'))
    else:
        if not current_user.is_2fa_enabled:
            flash('Account already verified. Please set up 2FA to continue.', 'info')
            return redirect(url_for('setup_2fa'))
        else:
            flash('Account already verified.', 'info')
            return redirect(url_for('dashboard'))

@app.route('/unverified')
@login_required
def unverified():
    if current_user.email_verified: return redirect(url_for('dashboard'))
    return render_template('unverified.html')

@app.route('/resend-verification')
@login_required
def resend_verification():
    if current_user.email_verified: return redirect(url_for('dashboard'))
    send_verification_email(current_user)
    flash('A new verification email has been sent.', 'info')
    return redirect(url_for('unverified'))
=======
    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    login_user(user)
    return redirect(url_for('setup_2fa_prompt'))
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1

@app.route('/eula')
def eula():
    return render_template('eula.html')

@app.route('/logout')
@login_required
def logout():
<<<<<<< HEAD
    session.pop('2fa_passed', None)
=======
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('welcome'))

<<<<<<< HEAD
@app.route('/help')
def help_page():
    return render_template('help.html')

@app.route('/request-reset', methods=['GET', 'POST'])
@limiter.limit("5 per 15 minutes")
def request_password_reset():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        login_identifier = request.form.get('login_identifier')
        user = User.query.filter(or_(User.username == login_identifier, User.email == login_identifier)).first()
        if user:
            token = s.dumps(user.email, salt='password-reset-salt')
            reset_url = url_for('reset_with_token', token=token, _external=True)
            msg = Message('Password Reset Request', recipients=[user.email])
            msg.html = render_template('reset_email.html', url=reset_url)
            try:
                mail.send(msg)
                flash('A password reset link has been sent to your email.', 'info')
            except Exception as e:
                logging.error(f"Failed to send password reset email: {e}")
                flash('Could not send reset email. Please contact an administrator.', 'error')
        else:
            flash('No account found with that username or email address.', 'warning')
        return redirect(url_for('auth'))
    return render_template('request_reset.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('request_password_reset'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Invalid user.', 'error')
        return redirect(url_for('auth'))

    if request.method == 'POST':
        password = request.form.get('password')
        is_strong, message = is_password_strong(password)
        if not is_strong:
            flash(message, 'error')
            return render_template('reset_password.html')
        
        user.set_password(password)
        db.session.add(PasswordHistory(user=user, password_hash=user.password_hash))
        db.session.commit()
        log_audit("User reset password", user=user)
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('auth'))
    
    return render_template('reset_password.html')

@app.route('/setup-2fa')
@login_required
@check_verified
=======
@app.route('/setup-2fa-prompt')
@login_required
def setup_2fa_prompt():
    return render_template('setup_2fa_prompt.html')

@app.route('/setup-2fa')
@login_required
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
def setup_2fa():
    if current_user.is_2fa_enabled:
        flash('2FA is already enabled.', 'info')
        return redirect(url_for('dashboard'))
    current_user.otp_secret = pyotp.random_base32()
    db.session.commit()
<<<<<<< HEAD
    uri = pyotp.totp.TOTP(current_user.otp_secret).provisioning_uri(name=current_user.username, issuer_name="Aegis Cloud Scanner")
    logging.info(f"--- [SECURITY] Generated new 2FA QR Code for user '{current_user.username}'. ---")
=======
    uri = pyotp.totp.TOTP(current_user.otp_secret).provisioning_uri(name=current_user.username, issuer_name="Cloud-Security-Scanner")
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf)
    qr_code = base64.b64encode(buf.getvalue()).decode('utf-8')
    return render_template('2fa_setup.html', qr_code=qr_code)

@app.route('/enable-2fa', methods=['POST'])
@login_required
<<<<<<< HEAD
@check_verified
=======
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
def enable_2fa():
    otp_code = request.form.get('otp_code')
    totp = pyotp.TOTP(current_user.otp_secret)
    if totp.verify(otp_code, valid_window=1):
        current_user.is_2fa_enabled = True
        db.session.commit()
<<<<<<< HEAD
        logging.info(f"--- [SECURITY] 2FA successfully enabled for user '{current_user.username}'. ---")
        flash('2FA has been successfully enabled! Welcome to the dashboard.', 'success')
        session['2fa_passed'] = True
        return redirect(url_for('dashboard'))
    else:
        logging.warning(f"--- [SECURITY] Invalid 2FA code provided for user '{current_user.username}'. ---")
=======
        flash('2FA has been successfully enabled!', 'success')
        return redirect(url_for('dashboard'))
    else:
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
        flash('Invalid verification code. Please try again.', 'error')
        return redirect(url_for('setup_2fa'))

@app.route('/verify-2fa-login', methods=['GET', 'POST'])
def verify_2fa_login():
    username = session.get('username_for_2fa')
    if not username: return redirect(url_for('auth'))
    user = User.query.filter_by(username=username).first()
    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(otp_code, valid_window=1):
<<<<<<< HEAD
            logging.info(f"--- [SECURITY] 2FA verification successful for user '{user.username}'. ---")
            login_user(user)
            session.pop('username_for_2fa', None)
            session['2fa_passed'] = True
=======
            login_user(user)
            session.pop('username_for_2fa', None)
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid 2FA code.', 'error')
<<<<<<< HEAD

    resp = make_response(render_template('2fa_verify.html'))
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.route('/onboarding')
@login_required
@check_verified
@check_2fa
def onboarding():
    if not current_user.is_2fa_enabled:
        flash('You must set up Two-Factor Authentication to access the dashboard.', 'info')
        return redirect(url_for('setup_2fa'))
    
    if current_user.credentials.first():
        return redirect(url_for('dashboard'))

    return render_template('onboarding.html')

@app.route('/dashboard')
@login_required
@check_verified
@check_2fa
def dashboard():
    if not current_user.is_2fa_enabled:
        flash('You must set up Two-Factor Authentication to access the dashboard.', 'info')
        return redirect(url_for('setup_2fa'))
    
    if not current_user.credentials.first():
        return redirect(url_for('onboarding'))
        
    credentials = current_user.credentials.all()
    
    try:
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        regions = [r['RegionName'] for r in ec2_client.describe_regions(AllRegions=False).get('Regions', [])]
    except Exception as e:
        logging.error(f"Could not retrieve regions: {e}")
        regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']
        
    return render_template('dashboard.html', credentials=credentials, regions=regions)

@app.route('/api/v1/scan', methods=['GET'])
@login_required
@check_verified
@check_2fa
@limiter.limit("5 per hour", key_func=lambda: current_user.id)
def scan():
    # --- THIS IS THE NEW TOP-LEVEL ERROR TRAP ---
    try:
        profile_id = request.args.get('profile_id')
        regions_to_scan = request.args.getlist('regions')
        progress_mode = request.args.get('progress_mode') == 'true'

        logging.info(f"--- [SCAN] Scan initiated by user '{current_user.username}' for profile ID {profile_id}. ---")

        if not regions_to_scan or 'all' in regions_to_scan: regions_to_scan = None

        if not profile_id:
            return jsonify({"error": "Credential profile ID is required."}), 400

        credential = CloudCredential.query.filter_by(id=profile_id, user_id=current_user.id).first()
        if not credential:
            return jsonify({"error": "Credential profile not found or access denied."}), 404

        scan_user_id = current_user.id

        decrypted_creds = {
            "provider": credential.provider,
            "profile_name": credential.profile_name
        }
        if credential.provider == 'aws':
            key_id = decrypt_data(credential.encrypted_key_1, context=f"AWS Access Key for scan profile '{credential.profile_name}'")
            decrypted_creds["aws_access_key_id"] = key_id
            decrypted_creds["aws_secret_access_key"] = decrypt_data(credential.encrypted_key_2, context=f"AWS Secret Key for scan profile '{credential.profile_name}'")
            logging.debug(f"Using AWS credentials for profile '{credential.profile_name}'. Access Key ID: {key_id}")
        elif credential.provider == 'gcp':
            gcp_json = decrypt_data(credential.encrypted_key_2, context=f"GCP JSON key for scan profile '{credential.profile_name}'")
            decrypted_creds["gcp_service_account_json"] = gcp_json
            try:
                gcp_data = json.loads(gcp_json)
                logging.debug(f"Using GCP credentials for profile '{credential.profile_name}'. Project ID: {gcp_data.get('project_id')}, Service Account: {gcp_data.get('client_email')}")
            except json.JSONDecodeError:
                logging.warning("Could not parse GCP JSON for debug logging.")
        else:
            return jsonify({"error": f"Unsupported provider: {credential.provider}"}), 400
        
        logging.info(f"--- [SCAN] Starting parallel scanner for provider: {credential.provider}. ---")
        
        if progress_mode:
            def generate(user_id):
                final_results = []
                logging.debug("Progress mode: Starting to generate SSE events.")
                with app.app_context():
                    suppressed_hashes = {sf.finding_hash for sf in SuppressedFinding.query.filter_by(user_id=user_id).all()}

                for update in parallel_scanner.run_parallel_scans_progress(credentials=decrypted_creds, regions=regions_to_scan):
                    if isinstance(update, dict) and update.get('status') == 'progress':
                        yield f"data: {json.dumps(update)}\n\n"
                    elif isinstance(update, list):
                        unsuppressed_updates = [r for r in update if _generate_finding_hash(r) not in suppressed_hashes]
                        final_results.extend(unsuppressed_updates)
                
                with app.app_context():
                    scan_time = datetime.datetime.now(datetime.timezone.utc)
                    scan_author = db.session.get(User, user_id)
                    logging.info(f"--- [DATABASE] Storing {len(final_results)} scan results to the database. ---")
                    for result in final_results:
                        if "error" not in result:
                            db_result = ScanResult(
                                service=result.get('service'), 
                                resource=result.get('resource'), 
                                status=result.get('status'), 
                                issue=result.get('issue'), 
                                remediation=result.get('remediation'), 
                                doc_url=result.get('doc_url'), 
                                timestamp=scan_time, 
                                author=scan_author)
                            db.session.add(db_result)
                    db.session.commit()
                    logging.debug("Database save complete.")

                yield f"data: {json.dumps({'status': 'complete', 'results': final_results})}\n\n"
            
            return Response(generate(user_id=scan_user_id), mimetype='text/event-stream')
        else:
            all_results = parallel_scanner.run_parallel_scans_blocking(credentials=decrypted_creds, regions=regions_to_scan)
            
            suppressed_hashes = {sf.finding_hash for sf in SuppressedFinding.query.filter_by(user_id=scan_user_id).all()}
            final_results = [r for r in all_results if _generate_finding_hash(r) not in suppressed_hashes]

            scan_time = datetime.datetime.now(datetime.timezone.utc)
            scan_author = db.session.get(User, scan_user_id)
            logging.info(f"--- [DATABASE] Storing {len(final_results)} scan results to the database. ---")
            for result in final_results:
                if "error" not in result:
                    db_result = ScanResult(
                        service=result.get('service'), 
                        resource=result.get('resource'), 
                        status=result.get('status'), 
                        issue=result.get('issue'), 
                        remediation=result.get('remediation'), 
                        doc_url=result.get('doc_url'), 
                        timestamp=scan_time, 
                        author=scan_author)
                    db.session.add(db_result)
            db.session.commit()
            logging.debug("Database save complete.")
            
            return jsonify({"results": final_results})

    except Exception as e:
        # This will catch any unhandled exception during the scan process
        logging.critical(f"--- [FATAL SCAN ERROR] An unexpected error occurred in the main scan route. ---", exc_info=True)
        return jsonify({"error": f"A fatal server error occurred: {str(e)}"}), 500


@app.route('/api/v1/history', methods=['GET'])
@login_required
@check_verified
@check_2fa
def history():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    pagination = ScanResult.query.filter_by(author=current_user).order_by(ScanResult.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    results = pagination.items
    history_list = [{"id": r.id, "service": r.service, "resource": r.resource, "status": r.status, "issue": r.issue, "timestamp": r.timestamp.isoformat()} for r in results]
    return jsonify({"historical_scans": history_list, "page": pagination.page, "total_pages": pagination.pages, "has_next": pagination.has_next, "has_prev": pagination.has_prev})
    
@app.route('/api/v1/suppress_finding', methods=['POST'])
@login_required
@check_2fa
def suppress_finding():
    data = request.get_json()
    finding = data.get('finding')
    if not finding: return jsonify({"error": "Finding data is required."}), 400
    finding_hash = _generate_finding_hash(finding)
    existing = SuppressedFinding.query.filter_by(user_id=current_user.id, finding_hash=finding_hash).first()
    if existing: return jsonify({"message": "Finding is already suppressed."}), 200
    new_suppression = SuppressedFinding(user_id=current_user.id, finding_hash=finding_hash, reason="Suppressed by user from dashboard.", service=finding.get('service'), resource=finding.get('resource'), issue=finding.get('issue'))
    db.session.add(new_suppression)
    db.session.commit()
    log_audit("Finding Suppressed", details=f"Hash: {finding_hash[:12]}...", user=current_user)
    return jsonify({"message": "Finding suppressed successfully."}), 201

@app.route('/api/v1/unsuppress_finding/<int:suppression_id>', methods=['POST'])
@login_required
@check_2fa
def unsuppress_finding(suppression_id):
    suppression = SuppressedFinding.query.filter_by(id=suppression_id, user_id=current_user.id).first()
    if not suppression: return jsonify({"error": "Suppression not found or access denied."}), 404
    db.session.delete(suppression)
    db.session.commit()
    log_audit("Finding Un-suppressed", details=f"ID: {suppression_id}", user=current_user)
    return jsonify({"message": "Finding has been un-suppressed successfully."}), 200

@app.route('/api/v1/history/trends')
@login_required
@check_verified
@check_2fa
def history_trends():
    thirty_days_ago = datetime.datetime.now(datetime.timezone.utc) - timedelta(days=30)
    trend_data = db.session.query(func.date(ScanResult.timestamp).label('scan_date'), func.count(ScanResult.id).label('critical_count')).filter(ScanResult.status == 'CRITICAL', ScanResult.timestamp >= thirty_days_ago, ScanResult.user_id == current_user.id).group_by('scan_date').order_by('scan_date').all()
=======
    return render_template('2fa_verify.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/api/v1/scan', methods=['GET'])
@login_required
def scan():
    scan_time = datetime.datetime.now(datetime.timezone.utc)
    scan_results = run_all_scans()
    scan_cache['results'] = scan_results
    scan_cache['timestamp'] = scan_time
    for result in scan_results:
        if "error" not in result:
            db_result = ScanResult(service=result.get('service'), resource=result.get('resource'), status=result.get('status'), issue=result.get('issue'), author=current_user)
            db.session.add(db_result)
    db.session.commit()
    return jsonify({"scan_results": scan_results, "timestamp": scan_time.isoformat()})

@app.route('/api/v1/history', methods=['GET'])
@login_required
def history():
    all_results = ScanResult.query.filter( (ScanResult.user_id == current_user.id) | (ScanResult.user_id == None) ).order_by(ScanResult.timestamp.desc()).all()
    history_list = [{"id": r.id, "service": r.service, "resource": r.resource, "status": r.status, "issue": r.issue, "timestamp": r.timestamp.isoformat()} for r in all_results]
    return jsonify({"historical_scans": history_list})

@app.route('/api/v1/history/trends')
@login_required
def history_trends():
    thirty_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
    trend_data = db.session.query(
        func.date(ScanResult.timestamp).label('scan_date'),
        func.count(ScanResult.id).label('critical_count')
    ).filter(
        ScanResult.status == 'CRITICAL',
        ScanResult.timestamp >= thirty_days_ago,
        (ScanResult.user_id == current_user.id) | (ScanResult.user_id == None)
    ).group_by('scan_date').order_by('scan_date').all()
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
    labels = [datetime.datetime.strptime(row.scan_date, '%Y-%m-%d').strftime('%b %d') for row in trend_data]
    data = [row.critical_count for row in trend_data]
    return jsonify({"labels": labels, "data": data})

@app.route('/api/v1/delete_history', methods=['POST'])
@login_required
<<<<<<< HEAD
@check_2fa
=======
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
def delete_history():
    try:
        num_deleted = ScanResult.query.filter_by(author=current_user).delete()
        db.session.commit()
        return jsonify({"message": f"Successfully deleted {num_deleted} of your historical scan results."}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to delete history."}), 500

@app.route('/report/pdf')
@login_required
<<<<<<< HEAD
@check_verified
@check_2fa
def generate_pdf_report():
    scan_results = ScanResult.query.filter_by(author=current_user).order_by(ScanResult.timestamp.desc()).limit(50).all()
    if not scan_results:
        flash('Please run a scan first to generate a report.', 'info')
        return redirect(url_for('dashboard'))
    pdf_bytes = _create_pdf_report(scan_results)
    return Response(pdf_bytes, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=aegis_cloud_security_report.pdf'})

@app.route('/settings', methods=['GET', 'POST'])
@login_required
@check_verified
@check_2fa
def settings():
    if request.method == 'POST':
        form_name = request.form.get('form_name')
        
        if form_name == 'add_cloud_credential':
            provider = request.form.get('provider')
            profile_name = request.form.get('profile_name')
            
            if provider == 'aws':
                access_key_id = request.form.get('aws_access_key_id')
                secret_access_key = request.form.get('aws_secret_access_key')
                if not all([access_key_id, secret_access_key]):
                    flash('AWS Access Key and Secret Key are required.', 'error')
                    return redirect(url_for('settings'))

                try:
                    logging.info(f"--- [CREDENTIALS] Validating new AWS credentials for profile '{profile_name}'. ---")
                    sts_client = boto3.client('sts', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
                    sts_client.get_caller_identity()
                    logging.info(f"--- [CREDENTIALS] AWS credential validation successful. ---")
                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code")
                    logging.error(f"--- [CREDENTIALS] AWS credential validation failed. Error: {error_code}. ---")
                    if error_code == 'InvalidClientTokenId' or error_code == 'SignatureDoesNotMatch':
                        flash('AWS credentials are not valid. Please check the Access Key and Secret Key.', 'error')
                    else:
                        flash(f'An AWS error occurred: {error_code}. Please check credentials and permissions.', 'error')
                    return redirect(url_for('settings'))
                
                new_cred = CloudCredential(owner=current_user, profile_name=profile_name, provider=provider)
                new_cred.encrypted_key_1 = encrypt_data(access_key_id, context=f"AWS Access Key for profile '{profile_name}'")
                new_cred.encrypted_key_2 = encrypt_data(secret_access_key, context=f"AWS Secret Key for profile '{profile_name}'")
                db.session.add(new_cred)

            elif provider == 'gcp':
                gcp_json_key = request.form.get('gcp_service_account_json')
                if not gcp_json_key:
                    flash('GCP Service Account JSON key is required.', 'error')
                    return redirect(url_for('settings'))
                
                try:
                    logging.info(f"--- [CREDENTIALS] Validating new GCP credentials for profile '{profile_name}'. ---")
                    key_data = json.loads(gcp_json_key)
                    creds = service_account.Credentials.from_service_account_info(key_data)
                    storage_client = storage.Client(credentials=creds, project=key_data.get('project_id'))
                    list(storage_client.list_buckets(max_results=1)) # Corrected validation method
                    logging.info(f"--- [CREDENTIALS] GCP credential validation successful. ---")
                except Exception as e:
                    logging.error(f"--- [CREDENTIALS] GCP credential validation failed. Error: {e}. ---")
                    flash(f'GCP credentials are not valid or lack permissions. Error: {str(e)}', 'error')
                    return redirect(url_for('settings'))
                
                new_cred = CloudCredential(owner=current_user, profile_name=profile_name, provider=provider)
                service_account_email = key_data.get('client_email')
                new_cred.encrypted_key_1 = service_account_email
                new_cred.encrypted_key_2 = encrypt_data(gcp_json_key, context=f"GCP JSON key for profile '{profile_name}'")
                db.session.add(new_cred)

            db.session.commit()
            flash(f'Successfully added new {provider.upper()} credential profile.', 'success')

        elif form_name == 'timeout':
            try:
                timeout = int(request.form.get('inactivity_timeout'))
                if 5 <= timeout <= 120:
                    current_user.inactivity_timeout = timeout
                    db.session.commit()
                    flash(f'Inactivity timeout updated to {timeout} minutes.', 'success')
                else: flash('Timeout must be between 5 and 120 minutes.', 'error')
            except (ValueError, TypeError): flash('Invalid input for timeout.', 'error')
        
        elif form_name == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            if not current_user.check_password(current_password):
                flash('Your current password was incorrect.', 'error')
            else:
                is_strong, message = is_password_strong(new_password)
                if not is_strong:
                    flash(message, 'error')
                else:
                    if any(bcrypt.check_password_hash(ph.password_hash, new_password) for ph in current_user.password_history.all()):
                        flash('You cannot reuse a recent password. Please choose a new one.', 'error')
                    else:
                        current_user.set_password(new_password)
                        db.session.add(PasswordHistory(user=current_user, password_hash=current_user.password_hash))
                        db.session.commit()
                        log_audit("User changed password", user=current_user)
                        flash('Your password has been successfully updated.', 'success')
        
        elif form_name == 'disable_2fa':
            password = request.form.get('password_2fa')
            if current_user.check_password(password):
                current_user.is_2fa_enabled = False
                db.session.commit()
                flash('Two-Factor Authentication has been disabled.', 'success')
            else:
                flash('Incorrect password.', 'error')

        elif form_name == 'change_primary_email':
            new_email = request.form.get('new_email')
            password = request.form.get('password')
            if current_user.check_password(password):
                send_new_primary_email_verification(current_user, new_email)
                flash(f'A verification link has been sent to {new_email}.', 'info')
            else:
                flash('Incorrect password.', 'error')

        elif form_name == 'add_backup_email':
            backup_email = request.form.get('backup_email')
            password = request.form.get('password')
            if current_user.check_password(password):
                send_backup_email_verification(current_user, backup_email)
                flash(f'A verification link has been sent to {backup_email}.', 'info')
            else:
                flash('Incorrect password.', 'error')

        return redirect(url_for('settings'))
    
    credentials = current_user.credentials.all()
    suppressed_findings = SuppressedFinding.query.filter_by(user_id=current_user.id).order_by(SuppressedFinding.id.desc()).all()
    return render_template('settings.html', credentials=credentials, suppressed_findings=suppressed_findings)

@app.route('/verify-new-primary-email/<token>')
@login_required
def verify_new_primary_email(token):
    try:
        data = s.loads(token, salt='new-primary-email-salt', max_age=3600)
        user = db.session.get(User, data['user_id'])
        if user and user.id == current_user.id:
            user.email = data['new_email']
            db.session.commit()
            flash('Your primary email has been updated.', 'success')
        else:
            flash('Invalid verification link.', 'error')
    except Exception:
        flash('The verification link is invalid or has expired.', 'error')
    return redirect(url_for('settings'))

@app.route('/verify-backup-email/<token>')
@login_required
def verify_backup_email(token):
    try:
        data = s.loads(token, salt='backup-email-salt', max_age=3600)
        user = db.session.get(User, data['user_id'])
        if user and user.id == current_user.id:
            user.backup_email = data['backup_email']
            user.backup_email_verified = True
            db.session.commit()
            flash('Your backup email has been verified and set.', 'success')
        else:
            flash('Invalid verification link.', 'error')
    except Exception:
        flash('The verification link is invalid or has expired.', 'error')
    return redirect(url_for('settings'))

@app.route('/delete_credential/<int:credential_id>', methods=['POST'])
@login_required
def delete_credential(credential_id):
    credential = CloudCredential.query.filter_by(id=credential_id, user_id=current_user.id).first_or_404()
    db.session.delete(credential)
    db.session.commit()
    flash('Credential profile has been deleted.', 'success')
    return redirect(url_for('settings'))

@app.route('/admin')
@login_required
@admin_required
@check_2fa
def admin_dashboard():
    all_users = User.query.order_by(User.username).all()
    all_scans = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template('admin.html', users=all_users, scans=all_scans, audit_logs=audit_logs)

@app.route('/admin/unlock_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
@check_2fa
def unlock_user(user_id):
    user_to_unlock = db.session.get(User, user_id)
    if user_to_unlock:
        user_to_unlock.is_locked = False
        user_to_unlock.failed_login_attempts = 0
        db.session.commit()
        logging.info(f"--- [AUTH] Admin '{current_user.username}' unlocked user '{user_to_unlock.username}'. ---")
        log_audit("User Unlocked", details=f"Unlocked user: '{user_to_unlock.username}'", user=current_user)
        flash(f"User '{user_to_unlock.username}' has been unlocked.", 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
@check_2fa
def delete_user(user_id):
    if user_id == current_user.id:
        flash("You cannot delete your own account.", 'error')
        return redirect(url_for('admin_dashboard'))
    
    user_to_delete = db.session.get(User, user_id)
    if user_to_delete:
        db.session.delete(user_to_delete)
        db.session.commit()
        log_audit("User Deleted", details=f"Deleted user: '{user_to_delete.username}'", user=current_user)
        flash(f"User '{user_to_delete.username}' and all their data has been permanently deleted.", 'success')
    else:
        flash('User not found.', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/promote_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
@check_2fa
def promote_user(user_id):
    admin_count = User.query.filter_by(is_admin=True).count()
    user_to_promote = db.session.get(User, user_id)
    if user_to_promote and user_to_promote.is_admin:
        flash(f"User '{user_to_promote.username}' is already an administrator.", 'info')
        return redirect(url_for('admin_dashboard'))
    if admin_count >= 2:
        flash('Cannot promote user. The maximum of 2 administrators has been reached.', 'error')
        return redirect(url_for('admin_dashboard'))
    if user_to_promote:
        user_to_promote.is_admin = True
        db.session.commit()
        log_audit("User Promoted", details=f"Promoted user: '{user_to_promote.username}' to Admin", user=current_user)
        flash(f"User '{user_to_promote.username}' has been promoted to administrator.", 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('admin_dashboard'))

@app.cli.command("make-admin")
@click.argument("username")
def make_admin(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        print(f"User '{username}' not found.")
        return
    if user.is_admin:
        print(f"User '{user.username}' is already an administrator.")
        return
    admin_count = User.query.filter_by(is_admin=True).count()
    if admin_count >= 2:
        print("Error: Maximum number of administrators (2) already exists.")
        return
    user.is_admin = True
    db.session.commit()
    print(f"User '{username}' has been granted admin privileges.")

# --- SETUP AND MAIN EXECUTION LOGIC ---
@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if os.path.exists(ENV_FILE_PATH) and os.getenv('MAIL_USERNAME'):
        return redirect(url_for('welcome'))
        
    if request.method == 'POST':
        with open(ENV_FILE_PATH, 'w') as f:
            f.write(f"SECRET_KEY='{request.form['secret_key']}'\n")
            f.write(f"ENCRYPTION_KEY='{request.form['encryption_key']}'\n")
            f.write(f"MAIL_SERVER='smtp.gmail.com'\n")
            f.write(f"MAIL_PORT=587\n")
            f.write(f"MAIL_USE_TLS=True\n")
            f.write(f"MAIL_USERNAME='{request.form['mail_username']}'\n")
            f.write(f"MAIL_PASSWORD='{request.form['mail_password']}'\n")
            f.write(f"ADMIN_REGISTRATION_KEY='{request.form['admin_key']}'\n")
            f.write(f"DOMAIN_NAME='localhost:5000'\n")

        CloudCredential.query.delete()
        db.session.commit()
        flash("Setup complete! For security, any previously saved credentials have been cleared. Please add them again.", "info")
        
        is_frozen = getattr(sys, 'frozen', False)
        return render_template('setup_complete.html', is_frozen=is_frozen)
        
    suggested_secret = os.getenv('SECRET_KEY', secrets.token_hex(24))
    suggested_encryption_key = os.getenv('ENCRYPTION_KEY', Fernet.generate_key().decode())
    logging.info("--- [SECURITY] New Fernet encryption key generated for setup screen. ---")
    return render_template('setup.html', suggested_secret=suggested_secret, suggested_encryption_key=suggested_encryption_key)

@app.route('/check_setup')
def check_setup():
    if not os.getenv('MAIL_USERNAME'):
        return redirect(url_for('setup'))
    else:
        return redirect(url_for('welcome'))

@app.route('/test_email', methods=['POST'])
@csrf.exempt
def test_email():
    data = request.get_json()
    temp_mail = Mail()
    temp_app = Flask("temp_app")
    temp_app.config.update(MAIL_SERVER='smtp.gmail.com', MAIL_PORT=587, MAIL_USE_TLS=True, MAIL_USERNAME=data.get('email'), MAIL_PASSWORD=data.get('password'))
    temp_mail.init_app(temp_app)
    msg = Message("Aegis Scanner Test Email", sender=data.get('email'), recipients=[data.get('email')])
    msg.body = "This is a test email from the Aegis Scanner setup."
    try:
        with temp_app.app_context():
            temp_mail.send(msg)
        return jsonify({"message": "Test email sent successfully!"}), 200
    except Exception as e:
        logging.error(f"Failed to send test email: {e}")
        return jsonify({"error": str(e)}), 500

def shutdown_server():
    os._exit(0)

@app.route('/restart_app')
def restart_app():
    if getattr(sys, 'frozen', False):
        subprocess.Popen([sys.executable])
        threading.Timer(1.0, shutdown_server).start()
        return "<h1>Relaunching... You can close this window.</h1>"
    return "Restart is only available for the executable version."

@app.route('/shutdown', methods=['POST'])
def shutdown():
    """Shuts down the Waitress server."""
    os._exit(0)
    return 'Server shutting down...'

def run_main_app():
    
    first_run_flag = os.path.join(USER_DATA_DIR, '.first_run')
    if not os.path.exists(first_run_flag):
        threading.Timer(1.5, lambda: webbrowser.open("http://127.0.0.1:5000/")).start()
        with open(first_run_flag, 'w') as f:
            f.write('done')

    with app.app_context():
        db.create_all()

    serve(app, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    if not os.path.exists(ENV_FILE_PATH):
        print("INFO: First run detected. Creating temporary .env file.")
        temp_secret = secrets.token_hex(24)
        temp_encrypt = Fernet.generate_key().decode()
        with open(ENV_FILE_PATH, 'w') as f:
            f.write(f"SECRET_KEY='{temp_secret}'\n")
            f.write(f"ENCRYPTION_KEY='{temp_encrypt}'\n")
    
    run_main_app()
=======
def generate_pdf_report():
    scan_results = scan_cache.get('results', [])
    if not scan_results:
        flash('Please run a scan first to generate a report.', 'info')
        return redirect(url_for('dashboard'))
    html_string = render_template('report.html', results=scan_results, scan_date=datetime.datetime.now())
    pdf_bytes = HTML(string=html_string).write_pdf()
    return Response(pdf_bytes, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=cloud_security_report.pdf'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(func=scheduled_scan_job, trigger='interval', hours=24, id='scheduled_scan_job')
    scheduler.start()
    
    print("Scheduler started. Server running on http://127.0.0.1:5000")
    serve(app, host='0.0.0.0', port=5000)
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
