import logging
import traceback
import sys
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
from functools import wraps
from flask import jsonify, render_template, request, current_app, session
from werkzeug.exceptions import HTTPException
import structlog

class ErrorLevel:
    """Error severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ErrorCategory:
    """Error categories for better classification."""
    SECURITY = "SECURITY"
    VALIDATION = "VALIDATION"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    DATABASE = "DATABASE"
    EXTERNAL_API = "EXTERNAL_API"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    USER_INPUT = "USER_INPUT"
    BUSINESS_LOGIC = "BUSINESS_LOGIC"
    SYSTEM = "SYSTEM"

class AegisError(Exception):
    """
    Base exception class for Aegis Scanner with enhanced error tracking.
    """
    
    def __init__(
        self, 
        message: str,
        error_code: str = "UNKNOWN_ERROR",
        category: str = ErrorCategory.SYSTEM,
        severity: str = ErrorLevel.MEDIUM,
        user_message: Optional[str] = None,
        technical_details: Optional[Dict[str, Any]] = None,
        suggested_action: Optional[str] = None,
        recoverable: bool = True
    ):
        """
        Initialize AegisError with comprehensive error information.
        
        Args:
            message: Technical error message for logging
            error_code: Unique error code for identification
            category: Error category from ErrorCategory
            severity: Error severity from ErrorLevel
            user_message: User-friendly message to display
            technical_details: Additional technical information
            suggested_action: Suggested recovery action
            recoverable: Whether the error is recoverable
        """
        super().__init__(message)
        
        self.error_code = error_code
        self.category = category
        self.severity = severity
        self.user_message = user_message or self._generate_user_message()
        self.technical_details = technical_details or {}
        self.suggested_action = suggested_action
        self.recoverable = recoverable
        self.timestamp = datetime.utcnow()
        self.request_id = self._get_request_id()
        
        
        self.stack_trace = traceback.format_exc()
    
    def _generate_user_message(self) -> str:
        """Generate a user-friendly error message based on category."""
        user_messages = {
            ErrorCategory.SECURITY: "A security issue was detected. Please contact support if this persists.",
            ErrorCategory.VALIDATION: "The information provided is not valid. Please check and try again.",
            ErrorCategory.AUTHENTICATION: "Authentication failed. Please check your credentials.",
            ErrorCategory.AUTHORIZATION: "You don't have permission to perform this action.",
            ErrorCategory.DATABASE: "A database error occurred. Please try again later.",
            ErrorCategory.EXTERNAL_API: "An external service is temporarily unavailable. Please try again.",
            ErrorCategory.INFRASTRUCTURE: "A system error occurred. Our team has been notified.",
            ErrorCategory.USER_INPUT: "Invalid input provided. Please check your data and try again.",
            ErrorCategory.BUSINESS_LOGIC: "Unable to complete the requested operation.",
            ErrorCategory.SYSTEM: "An unexpected error occurred. Please try again."
        }
        return user_messages.get(self.category, user_messages[ErrorCategory.SYSTEM])
    
    def _get_request_id(self) -> Optional[str]:
        """Get current request ID if available."""
        try:
            return getattr(request, 'id', None) if request else None
        except RuntimeError:
            return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for logging/serialization."""
        return {
            'error_code': self.error_code,
            'message': str(self),
            'user_message': self.user_message,
            'category': self.category,
            'severity': self.severity,
            'technical_details': self.technical_details,
            'suggested_action': self.suggested_action,
            'recoverable': self.recoverable,
            'timestamp': self.timestamp.isoformat(),
            'request_id': self.request_id,
            'stack_trace': self.stack_trace
        }


class SecurityError(AegisError):
    """Security-related errors."""
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message, 
            category=ErrorCategory.SECURITY,
            severity=ErrorLevel.CRITICAL,
            recoverable=False,
            **kwargs
        )

class ValidationError(AegisError):
    """Input validation errors."""
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.VALIDATION,
            severity=ErrorLevel.LOW,
            **kwargs
        )

class AuthenticationError(AegisError):
    """Authentication-related errors."""
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorLevel.HIGH,
            **kwargs
        )

class AuthorizationError(AegisError):
    """Authorization-related errors."""
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorLevel.HIGH,
            **kwargs
        )

class DatabaseError(AegisError):
    """Database-related errors."""
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.DATABASE,
            severity=ErrorLevel.HIGH,
            **kwargs
        )

class ExternalAPIError(AegisError):
    """External API-related errors."""
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.EXTERNAL_API,
            severity=ErrorLevel.MEDIUM,
            **kwargs
        )

class CryptoError(AegisError):
    """Cryptography-related errors."""
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.SECURITY,
            severity=ErrorLevel.CRITICAL,
            error_code="CRYPTO_ERROR",
            **kwargs
        )

class ErrorHandler:
    """Centralized error handling and logging system."""
    
    def __init__(self, app=None):
        """Initialize error handler."""
        self.app = app
        self.logger = logging.getLogger(__name__)
        
        # Initialize structured logging
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize error handlers for Flask app."""
        self.app = app
        
        
        app.errorhandler(AegisError)(self.handle_aegis_error)
        app.errorhandler(ValidationError)(self.handle_validation_error)
        app.errorhandler(SecurityError)(self.handle_security_error)
        app.errorhandler(DatabaseError)(self.handle_database_error)
        app.errorhandler(404)(self.handle_not_found)
        app.errorhandler(403)(self.handle_forbidden)
        app.errorhandler(500)(self.handle_internal_error)
        app.errorhandler(Exception)(self.handle_generic_exception)
        
        
        app.before_request(self._add_request_id)
    
    def _add_request_id(self):
        """Add unique request ID to each request."""
        import uuid
        request.id = str(uuid.uuid4())[:8]
    
    def log_error(self, error: AegisError, extra_context: Optional[Dict] = None):
        """Log error with structured logging."""
        context = {
            'error_code': error.error_code,
            'category': error.category,
            'severity': error.severity,
            'request_id': error.request_id,
            'user_id': session.get('_user_id') if 'session' in globals() else None,
            'url': request.url if request else None,
            'method': request.method if request else None,
            'user_agent': request.headers.get('User-Agent') if request else None,
            'remote_addr': request.remote_addr if request else None,
            **(extra_context or {})
        }
        
        
        if error.severity == ErrorLevel.CRITICAL:
            self.logger.critical(str(error), extra=context)
        elif error.severity == ErrorLevel.HIGH:
            self.logger.error(str(error), extra=context)
        elif error.severity == ErrorLevel.MEDIUM:
            self.logger.warning(str(error), extra=context)
        else:
            self.logger.info(str(error), extra=context)
    
    def handle_aegis_error(self, error: AegisError):
        """Handle custom AegisError exceptions."""
        self.log_error(error)
        
        if request.path.startswith('/api/'):
            return jsonify({
                'error': error.user_message,
                'error_code': error.error_code,
                'request_id': error.request_id,
                'recoverable': error.recoverable,
                'suggested_action': error.suggested_action
            }), self._get_http_status_for_category(error.category)
        
        return render_template('error.html', 
                             error=error,
                             error_message=error.user_message), \
               self._get_http_status_for_category(error.category)
    
    def handle_validation_error(self, error: ValidationError):
        """Handle validation errors specifically."""
        self.log_error(error)
        
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'Validation failed',
                'message': error.user_message,
                'details': error.technical_details,
                'error_code': error.error_code
            }), 400
        
        from flask import flash, redirect, url_for
        flash(error.user_message, 'error')
        return redirect(request.referrer or url_for('dashboard'))
    
    def handle_security_error(self, error: SecurityError):
        """Handle security errors with enhanced logging."""
        
        security_context = {
            'security_event': True,
            'threat_level': 'HIGH',
            'requires_investigation': True
        }
        self.log_error(error, security_context)
        
        
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'Security violation detected',
                'request_id': error.request_id
            }), 403
        
        return render_template('error.html', 
                             error_message="Access denied for security reasons."), 403
    
    def handle_database_error(self, error: DatabaseError):
        """Handle database errors with rollback."""
        self.log_error(error)
        
        
        try:
            from flask_sqlalchemy import db
            db.session.rollback()
        except Exception as rollback_error:
            self.logger.error(f"Failed to rollback transaction: {rollback_error}")
        
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'Database operation failed',
                'request_id': error.request_id,
                'recoverable': True
            }), 500
        
        from flask import flash, redirect, url_for
        flash('A database error occurred. Please try again.', 'error')
        return redirect(request.referrer or url_for('dashboard'))
    
    def handle_not_found(self, error):
        """Handle 404 errors."""
        self.logger.warning(f"404 error: {request.url}")
        
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Resource not found'}), 404
        
        return render_template('error.html', 
                             error_message="Page not found."), 404
    
    def handle_forbidden(self, error):
        """Handle 403 errors."""
        self.logger.warning(f"403 error: {request.url}")
        
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Access forbidden'}), 403
        
        return render_template('error.html', 
                             error_message="You don't have permission to access this resource."), 403
    
    def handle_internal_error(self, error):
        """Handle 500 errors."""
        self.logger.error(f"Internal server error: {error}", exc_info=True)
        
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'Internal server error',
                'request_id': getattr(request, 'id', 'unknown')
            }), 500
        
        return render_template('error.html', 
                             error_message="An unexpected error occurred. Please try again later."), 500
    
    def handle_generic_exception(self, error):
        """Handle any unhandled exceptions."""
        
        aegis_error = AegisError(
            message=str(error),
            error_code="UNHANDLED_EXCEPTION",
            category=ErrorCategory.SYSTEM,
            severity=ErrorLevel.HIGH,
            technical_details={'original_exception': type(error).__name__}
        )
        
        return self.handle_aegis_error(aegis_error)
    
    def _get_http_status_for_category(self, category: str) -> int:
        """Map error category to appropriate HTTP status code."""
        status_map = {
            ErrorCategory.SECURITY: 403,
            ErrorCategory.VALIDATION: 400,
            ErrorCategory.AUTHENTICATION: 401,
            ErrorCategory.AUTHORIZATION: 403,
            ErrorCategory.DATABASE: 500,
            ErrorCategory.EXTERNAL_API: 502,
            ErrorCategory.INFRASTRUCTURE: 500,
            ErrorCategory.USER_INPUT: 400,
            ErrorCategory.BUSINESS_LOGIC: 422,
            ErrorCategory.SYSTEM: 500
        }
        return status_map.get(category, 500)

def safe_execute(func):
    """
    Decorator to safely execute functions with comprehensive error handling.
    
    Usage:
        @safe_execute
        def risky_function():
            # Code that might fail
            pass
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except AegisError:
            
            raise
        except Exception as e:
            
            raise AegisError(
                message=f"Error in {func.__name__}: {str(e)}",
                error_code=f"FUNCTION_ERROR_{func.__name__.upper()}",
                category=ErrorCategory.BUSINESS_LOGIC,
                severity=ErrorLevel.MEDIUM,
                technical_details={
                    'function_name': func.__name__,
                    'args': str(args)[:200],  # Limit for security
                    'kwargs': str({k: v for k, v in kwargs.items() if 'password' not in k.lower()})[:200]
                }
            )
    return wrapper

def cloud_api_handler(provider: str):
    """
    Decorator for cloud API calls with provider-specific error handling.
    
    Args:
        provider: Cloud provider name (aws, gcp, azure)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                
                error_details = {
                    'provider': provider,
                    'function': func.__name__,
                    'original_error': str(e)
                }
                
                if provider == 'aws':
                    from botocore.exceptions import ClientError, NoCredentialsError
                    if isinstance(e, ClientError):
                        error_code = e.response.get('Error', {}).get('Code', 'UNKNOWN_AWS_ERROR')
                        raise ExternalAPIError(
                            message=f"AWS API error: {error_code}",
                            error_code=f"AWS_{error_code}",
                            technical_details=error_details,
                            suggested_action="Check AWS credentials and permissions"
                        )
                    elif isinstance(e, NoCredentialsError):
                        raise AuthenticationError(
                            message="AWS credentials not found or invalid",
                            error_code="AWS_NO_CREDENTIALS",
                            technical_details=error_details
                        )
                
                elif provider == 'gcp':
                    from google.api_core.exceptions import GoogleAPIError
                    if isinstance(e, GoogleAPIError):
                        raise ExternalAPIError(
                            message=f"GCP API error: {str(e)}",
                            error_code="GCP_API_ERROR",
                            technical_details=error_details,
                            suggested_action="Check GCP credentials and permissions"
                        )
                
                
                raise ExternalAPIError(
                    message=f"{provider.upper()} operation failed: {str(e)}",
                    error_code=f"{provider.upper()}_ERROR",
                    technical_details=error_details
                )
        return wrapper
    return decorator


class ErrorContext:
    """Context manager for handling errors in specific contexts."""
    
    def __init__(self, context_name: str, category: str = ErrorCategory.SYSTEM, 
                 severity: str = ErrorLevel.MEDIUM, recoverable: bool = True):
        self.context_name = context_name
        self.category = category
        self.severity = severity
        self.recoverable = recoverable
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type and not issubclass(exc_type, AegisError):
            
            raise AegisError(
                message=f"Error in {self.context_name}: {str(exc_val)}",
                error_code=f"CONTEXT_ERROR_{self.context_name.upper()}",
                category=self.category,
                severity=self.severity,
                recoverable=self.recoverable,
                technical_details={
                    'context': self.context_name,
                    'exception_type': exc_type.__name__
                }
            ) from exc_val
        return False


def create_error_template():
    """Create error.html template for consistent error display."""
    return '''
{% extends "layout.html" %}
{% block title %}Error - Aegis{% endblock %}

{% block content %}
<div class="card" style="max-width: 600px; margin: auto; text-align: center;" data-aos="fade-up">
    <div style="font-size: 4rem; color: var(--danger-color); margin-bottom: 1rem;">
        <i class="fas fa-exclamation-triangle"></i>
    </div>
    
    <h2>Something Went Wrong</h2>
    
    {% if error %}
        <div class="error-details" style="text-align: left; margin-top: 2rem;">
            <p><strong>Error:</strong> {{ error.user_message }}</p>
            
            {% if error.suggested_action %}
                <p><strong>Suggested Action:</strong> {{ error.suggested_action }}</p>
            {% endif %}
            
            {% if error.recoverable %}
                <p style="color: var(--success-color);">
                    <i class="fas fa-info-circle"></i>
                    This error is recoverable. Please try your action again.
                </p>
            {% endif %}
            
            {% if error.request_id %}
                <p><small><strong>Request ID:</strong> {{ error.request_id }}</small></p>
            {% endif %}
        </div>
    {% else %}
        <p>{{ error_message or "An unexpected error occurred." }}</p>
    {% endif %}
    
    <div style="margin-top: 2rem;">
        <a href="{{ url_for('dashboard') }}" class="button">
            <i class="fas fa-home"></i> Return to Dashboard
        </a>
        <a href="javascript:history.back()" class="button-secondary" style="margin-left: 1rem;">
            <i class="fas fa-arrow-left"></i> Go Back
        </a>
    </div>
</div>
{% endblock %}
    '''


def register_error_handlers(app):
    """Register all error handlers with Flask app."""
    error_handler = ErrorHandler(app)
    
    
    import os
    template_path = os.path.join(app.template_folder, 'error.html')
    if not os.path.exists(template_path):
        with open(template_path, 'w') as f:
            f.write(create_error_template())
    
    return error_handler


def example_secure_function():
    """Example of using error handling in a secure function."""
    with ErrorContext("secure_operation", ErrorCategory.SECURITY, ErrorLevel.CRITICAL):
        
        if not verify_security_condition():
            raise SecurityError(
                message="Security condition not met",
                error_code="SECURITY_CHECK_FAILED",
                suggested_action="Please verify your permissions and try again"
            )

@safe_execute
def example_database_operation():
    """Example of database operation with error handling."""
    try:
        
        pass
    except Exception as e:
        raise DatabaseError(
            message=f"Database operation failed: {str(e)}",
            error_code="DB_OPERATION_FAILED",
            suggested_action="Check database connectivity and try again"
        )

@cloud_api_handler('aws')
def example_aws_operation():
    """Example of AWS operation with error handling."""
    import boto3
    
    client = boto3.client('s3')
    return client.list_buckets()

def verify_security_condition():
    """Mock security verification."""
    return True  