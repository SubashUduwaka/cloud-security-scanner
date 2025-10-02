"""
License Validation Middleware for Aegis Cloud Scanner
Provides license checking for cloud deployment
"""

from functools import wraps
from flask import session, request, redirect, url_for, flash, current_app, render_template
import os
import sys
from datetime import datetime, timezone, timedelta
from license_manager import LicenseValidator, LicenseManager
import logging

logger = logging.getLogger(__name__)

class LicenseMiddleware:
    """
    Middleware to handle license validation for cloud deployment
    """

    def __init__(self, app=None):
        self.app = app
        self.license_validator = LicenseValidator()
        self.license_manager = LicenseManager()

        # Routes that don't require license validation
        self.exempt_routes = {
            'license_validation',
            'validate_license',
            'request_license',
            'static',
            'favicon.ico',
            'health_check',
            'initializing',
            'splash',
            'setup',
            'check_setup',
            'test_email',
            'version_selection',
            'select_version',
            'auth',
            'login_post',
            'register_post',
            'dashboard',
            'welcome'
        }

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the middleware with Flask app"""
        self.app = app

        # Check if this is local deployment (skip license checks)
        self.is_local_deployment = self._detect_local_deployment()

        if not self.is_local_deployment:
            app.before_request(self._check_license)

    def _detect_local_deployment(self):
        """
        Detect if this is a local deployment (EXE version)
        Local deployments are free and don't require licenses
        """
        # Check for various indicators of local deployment
        local_indicators = [
            os.getenv('AEGIS_LOCAL_DEPLOYMENT') == 'true',
            os.getenv('AEGIS_EXE_VERSION') == 'true',
            'localhost' in os.getenv('SERVER_NAME', ''),
            os.path.exists(os.path.join(os.getcwd(), 'AegisScanner.exe')),
            # Check if running from PyInstaller bundle
            getattr(sys, 'frozen', False),
            # Check for development indicators
            os.getenv('FLASK_ENV') == 'development'
        ]

        is_local = any(local_indicators)

        if is_local:
            logger.info("Local deployment detected - license validation disabled")
        else:
            logger.info("Cloud deployment detected - license validation enabled")

        return is_local

    def _check_license(self):
        """Check user license before each request - simplified check"""
        try:
            # Skip license check for exempt routes
            if request.endpoint in self.exempt_routes:
                return

            # Skip for static files and assets
            if request.path.startswith('/static/') or request.path.startswith('/assets/'):
                return

            # Skip for AJAX requests to certain endpoints
            if request.is_json and request.endpoint in ['health_check', 'api_status']:
                return

            # Skip if we're already on the license validation page
            if request.endpoint == 'license_validation' or request.path == '/license':
                return

            # Check if we're in guest mode
            if session.get('guest_mode'):
                return

            # Check if user is authenticated
            from flask_login import current_user
            if current_user.is_authenticated:
                # Simply allow authenticated users - license is already validated in database
                # Pro users have their license_key stored in DB from registration or upgrade
                # Basic users have no license_key
                # No need for constant re-validation on every request
                return

            # Unauthenticated users - allow them to continue to registration/login
            return

        except Exception as e:
            logger.error(f"License validation error: {str(e)}")
            # On error, allow access but log the issue
            return

    def _refresh_user_license_status(self, user):
        """Refresh user license status - called on each request"""
        try:
            if user.user_type == 'PRO' and user.license_key:
                # Check if license needs re-validation (every hour)
                current_time = datetime.now(timezone.utc)

                # Handle timezone-naive vs timezone-aware comparison
                needs_validation = not user.license_validated_at
                if user.license_validated_at:
                    if user.license_validated_at.tzinfo is None:
                        # Treat naive datetime as UTC
                        last_validation = user.license_validated_at.replace(tzinfo=timezone.utc)
                    else:
                        last_validation = user.license_validated_at

                    needs_validation = last_validation < current_time - timedelta(hours=1)

                if needs_validation:
                    # Re-validate license
                    validation_result = self.license_manager.validate_license_key(user.license_key)

                    if validation_result['is_valid']:
                        # Store as naive datetime (consistent with database schema)
                        user.license_validated_at = datetime.now()
                        from app import db
                        db.session.commit()
                    else:
                        # License is no longer valid
                        user.downgrade_to_basic()
                        from app import db
                        db.session.commit()
                        logger.warning(f"User {user.username} license validation failed: {validation_result.get('error', 'Unknown error')}")

        except Exception as e:
            logger.error(f"Error refreshing license status for user {user.username}: {e}")


def require_license(f):
    """
    Decorator to require valid license for specific routes
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip license check for local deployment
        if hasattr(current_app, 'license_middleware') and current_app.license_middleware.is_local_deployment:
            return f(*args, **kwargs)

        license_key = session.get('license_key')
        if not license_key:
            flash('License required to access this feature', 'warning')
            return redirect(url_for('license_validation'))

        validator = LicenseValidator()
        if not validator.validate_access(license_key):
            session.pop('license_key', None)
            flash('Invalid or expired license', 'error')
            return redirect(url_for('license_validation'))

        return f(*args, **kwargs)
    return decorated_function


def require_feature(feature_name):
    """
    Decorator to require specific feature in license
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Skip feature check for local deployment
            if hasattr(current_app, 'license_middleware') and current_app.license_middleware.is_local_deployment:
                return f(*args, **kwargs)

            validator = LicenseValidator()
            if not validator.has_feature(feature_name):
                flash(f'Your license does not include the {feature_name.replace("_", " ").title()} feature. Please upgrade your license.', 'warning')
                return redirect(url_for('welcome'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


# License validation routes
def init_license_routes(app):
    """Initialize license-related routes"""

    @app.route('/license')
    def license_validation():
        """License validation page"""
        return render_template('license_validation.html')

    @app.route('/license', methods=['POST'])
    def validate_license():
        """Process license validation"""
        try:
            logger.info("=== LICENSE VALIDATION STARTED ===")
            license_key = request.form.get('license_key', '').strip().upper()
            logger.info(f"Received license key: {license_key[:10]}...")

            if not license_key:
                flash('Please enter a license key', 'error')
                return redirect(url_for('license_validation'))

            # Validate license format first
            if not license_key.startswith('AEGIS-') or len(license_key) < 28 or len(license_key) > 29:
                flash('Invalid license key format. Please check your license key.', 'error')
                return redirect(url_for('license_validation'))

            # Validate license
            logger.info("Initializing license manager...")
            license_manager = LicenseManager()
            logger.info("Validating license...")
            validation_result = license_manager.validate_license_key(license_key)
            logger.info(f"Validation result: {validation_result}")

            if validation_result['is_valid']:
                # If user is logged in, upgrade them to Pro immediately (save to database)
                from flask_login import current_user
                if current_user.is_authenticated:
                    # Validate and set license on user account in database
                    logger.info(f"Attempting to validate license for user {current_user.username}")

                    # Get fresh user object from database to avoid session conflicts
                    from app import db, User
                    user = db.session.query(User).filter_by(id=current_user.id).first()

                    if user and user.validate_license_key(license_key):
                        # Commit the changes made by validate_license_key
                        db.session.commit()

                        # Verify the license was saved
                        logger.info(f"After commit - User: {user.username}, Type: {user.user_type}, License: {user.license_key}")

                        flash(f'License activated! You are now a Pro user with unlimited access.', 'success')

                        # Log successful license validation
                        logger.info(f"License validated for user {user.username}: {validation_result.get('user_email', 'unknown')} - Type: {validation_result.get('license_type', 'unknown')}")

                        # Redirect to dashboard to refresh with Pro features
                        return redirect(url_for('dashboard'))
                    else:
                        logger.error(f"License validation FAILED for user {current_user.username} with key {license_key}")
                        flash('License validation failed. Please contact support.', 'error')
                        return redirect(url_for('license_validation'))
                else:
                    # Not logged in - tell them to log in first
                    flash('Please log in or register first, then enter your license key from Settings.', 'info')
                    return redirect(url_for('auth'))
            else:
                error_msg = validation_result.get('error', 'Invalid license key')
                flash(f'License validation failed: {error_msg}', 'error')
                return redirect(url_for('license_validation'))

        except Exception as e:
            import traceback
            logger.error(f"License validation error: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            flash('An error occurred during license validation. Please try again.', 'error')
            return redirect(url_for('license_validation'))

    @app.route('/license-info')
    @require_license
    def license_info():
        """Display current license information"""
        license_info = session.get('license_info', {})
        return render_template('license_info.html', license_info=license_info)

    @app.route('/api/license-status')
    def api_license_status():
        """API endpoint to check current license status"""
        try:
            license_key = session.get('license_key')
            if not license_key:
                return {'is_valid': False, 'error': 'No license key in session'}, 401

            license_manager = LicenseManager()
            validation_result = license_manager.validate_license_key(license_key)

            if validation_result['is_valid']:
                # Simplified license status - no expiration tracking
                return validation_result, 200
            else:
                # License is invalid - clear session
                session.pop('license_key', None)
                session.pop('license_info', None)
                return validation_result, 401

        except Exception as e:
            logger.error(f"License status API error: {str(e)}")
            return {'is_valid': False, 'error': 'License status check failed'}, 500


# Admin license management routes
def init_admin_license_routes(app):
    """Initialize admin license management routes"""

    @app.route('/admin/licenses')
    def admin_licenses():
        """Admin license management dashboard"""
        # This would show all issued licenses, their status, etc.
        # For now, just redirect to admin panel
        return redirect(url_for('admin'))

    @app.route('/admin/generate-license', methods=['POST'])
    def admin_generate_license():
        """Generate new license key (admin only)"""
        try:
            # Get form data
            email = request.form.get('email')
            company = request.form.get('company', '')
            license_type = request.form.get('license_type', 'TRIAL')
            duration = request.form.get('duration', 'SEVEN_DAYS')
            features = request.form.getlist('features')

            if not email:
                flash('Email is required for license generation', 'error')
                return redirect(url_for('admin'))

            # Generate license
            from license_manager import LicenseType, LicenseDuration

            license_manager = LicenseManager()
            license_data = license_manager.generate_license_key(
                LicenseType[license_type],
                LicenseDuration[duration],
                email,
                company,
                features
            )

            # Log license generation
            logger.info(f"License generated by admin: {email} - {license_type} - {duration}")

            flash(f'License generated successfully: {license_data["license_key"]}', 'success')

            return redirect(url_for('admin'))

        except Exception as e:
            logger.error(f"Admin license generation error: {str(e)}")
            flash('Error generating license', 'error')
            return redirect(url_for('admin'))