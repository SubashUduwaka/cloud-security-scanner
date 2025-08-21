from flask import Flask, jsonify, request, redirect, url_for, render_template, flash, session, Response
from flask_cors import CORS
from s3_scanner import run_all_scans
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import os
import datetime
import boto3
import pyotp
import qrcode
from io import BytesIO
import base64
import re
from weasyprint import HTML
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

# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    otp_secret = db.Column(db.String(32))
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    scans = db.relationship('ScanResult', backref='author', lazy='dynamic')
    def set_password(self, password): self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    def check_password(self, password): return bcrypt.check_password_hash(self.password_hash, password)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.String(64), index=True)
    resource = db.Column(db.String(128))
    status = db.Column(db.String(64))
    issue = db.Column(db.String(256))
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def is_password_strong(password):
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
    return render_template('welcome.html')

@app.route('/auth')
def auth():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return render_template('auth.html')

@app.route('/login', methods=['POST'])
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
        flash('Invalid username or password.', 'error')
        return redirect(url_for('auth', _anchor='login'))

@app.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    eula_accepted = request.form.get('eula')
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
    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    login_user(user)
    return redirect(url_for('setup_2fa_prompt'))

@app.route('/eula')
def eula():
    return render_template('eula.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('welcome'))

@app.route('/setup-2fa-prompt')
@login_required
def setup_2fa_prompt():
    return render_template('setup_2fa_prompt.html')

@app.route('/setup-2fa')
@login_required
def setup_2fa():
    if current_user.is_2fa_enabled:
        flash('2FA is already enabled.', 'info')
        return redirect(url_for('dashboard'))
    current_user.otp_secret = pyotp.random_base32()
    db.session.commit()
    uri = pyotp.totp.TOTP(current_user.otp_secret).provisioning_uri(name=current_user.username, issuer_name="Cloud-Security-Scanner")
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf)
    qr_code = base64.b64encode(buf.getvalue()).decode('utf-8')
    return render_template('2fa_setup.html', qr_code=qr_code)

@app.route('/enable-2fa', methods=['POST'])
@login_required
def enable_2fa():
    otp_code = request.form.get('otp_code')
    totp = pyotp.TOTP(current_user.otp_secret)
    if totp.verify(otp_code, valid_window=1):
        current_user.is_2fa_enabled = True
        db.session.commit()
        flash('2FA has been successfully enabled!', 'success')
        return redirect(url_for('dashboard'))
    else:
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
            login_user(user)
            session.pop('username_for_2fa', None)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid 2FA code.', 'error')
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
    labels = [datetime.datetime.strptime(row.scan_date, '%Y-%m-%d').strftime('%b %d') for row in trend_data]
    data = [row.critical_count for row in trend_data]
    return jsonify({"labels": labels, "data": data})

@app.route('/api/v1/delete_history', methods=['POST'])
@login_required
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