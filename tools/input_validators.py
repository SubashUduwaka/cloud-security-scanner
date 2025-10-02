# input_validators.py - Comprehensive input validation system (Updated)
import re
import json
import logging
import validators
from typing import Any, Dict, List, Optional, Union, Tuple
from cerberus import Validator
import bleach
from urllib.parse import urlparse
import ipaddress

class SecurityValidator:
    """
    Comprehensive input validation and sanitization system for Aegis Scanner.
    Prevents XSS, injection attacks, and ensures data integrity.
    """
    
    # Define allowed HTML tags and attributes for content that might contain HTML
    ALLOWED_HTML_TAGS = {
        'b', 'i', 'em', 'strong', 'code', 'pre', 'br', 'p', 'span'
    }
    
    ALLOWED_HTML_ATTRS = {
        '*': ['class'],
        'a': ['href', 'title'],
        'span': ['class']
    }
    
    # Common regex patterns
    PATTERNS = {
        'username': re.compile(r'^[a-zA-Z0-9_-]{3,64}$'),
        'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
        'aws_access_key': re.compile(r'^AKIA[0-9A-Z]{16}$'),
        'aws_secret_key': re.compile(r'^[A-Za-z0-9/+=]{40}$'),
        'profile_name': re.compile(r'^[a-zA-Z0-9\s\-_\.()]{1,100}$'),
        'resource_name': re.compile(r'^[a-zA-Z0-9\-_\.:/]{1,255}$'),
        'region_name': re.compile(r'^[a-z0-9\-]{2,20}$'),
        'safe_filename': re.compile(r'^[a-zA-Z0-9\-_\.]{1,255}$'),
        'hex_color': re.compile(r'^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$'),
        'uuid': re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE),
        'cron_expression': re.compile(r'^[0-9*,\-/]+ [0-9*,\-/]+ [0-9*,\-/]+ [0-9*,\-/]+ [0-9*,\-/]+$')
    }
    
    def __init__(self):
        """Initialize the validator with common schemas."""
        self.schemas = self._define_schemas()
        self.validator = Validator()
        self.validator.allow_unknown = True
    
    def _define_schemas(self) -> Dict[str, Dict]:
        """Define Cerberus validation schemas for different input types."""
        return {
            'user_registration': {
                'username': {
                    'type': 'string',
                    'minlength': 3,
                    'maxlength': 64,
                    'regex': self.PATTERNS['username'].pattern,
                    'required': True
                },
                'email': {
                    'type': 'string',
                    'maxlength': 120,
                    'regex': self.PATTERNS['email'].pattern,
                    'required': True
                },
                'password': {
                    'type': 'string',
                    'minlength': 8,
                    'maxlength': 128,
                    'required': True
                },
                'admin_key': {
                    'type': 'string',
                    'maxlength': 256,
                    'required': False,
                    'nullable': True
                }
            },
            
            'aws_credentials': {
                'profile_name': {
                    'type': 'string',
                    'minlength': 1,
                    'maxlength': 100,
                    'regex': self.PATTERNS['profile_name'].pattern,
                    'required': True
                },
                'aws_access_key_id': {
                    'type': 'string',
                    'regex': self.PATTERNS['aws_access_key'].pattern,
                    'required': True
                },
                'aws_secret_access_key': {
                    'type': 'string',
                    'regex': self.PATTERNS['aws_secret_key'].pattern,
                    'required': True
                }
            },
            
            'gcp_credentials': {
                'profile_name': {
                    'type': 'string',
                    'minlength': 1,
                    'maxlength': 100,
                    'regex': self.PATTERNS['profile_name'].pattern,
                    'required': True
                },
                'gcp_service_account_json': {
                    'type': 'string',
                    'minlength': 100,
                    'maxlength': 10000,  # Reasonable limit for JSON key
                    'required': True
                }
            },
            
            'scan_request': {
                'profile_id': {
                    'type': 'integer',
                    'min': 1,
                    'required': True
                },
                'regions': {
                    'type': 'list',
                    'schema': {
                        'type': 'string',
                        'regex': self.PATTERNS['region_name'].pattern
                    },
                    'required': False
                },
                'progress_mode': {
                    'type': 'boolean',
                    'required': False
                }
            },
            
            'user_settings': {
                'inactivity_timeout': {
                    'type': 'integer',
                    'min': 5,
                    'max': 120,
                    'required': False
                },
                'notifications_enabled': {
                    'type': 'boolean',
                    'required': False
                },
                'report_schedule': {
                    'type': 'string',
                    'allowed': ['disabled', 'weekly', 'monthly'],
                    'required': False
                }
            },
            
            # NEW: Scheduled scan validation
            'schedule_scan': {
                'credential_id': {
                    'type': 'integer',
                    'min': 1,
                    'required': True
                },
                'schedule_type': {
                    'type': 'string',
                    'allowed': ['daily', 'weekly', 'monthly'],
                    'required': True
                },
                'regions': {
                    'type': 'list',
                    'schema': {
                        'type': 'string',
                        'regex': self.PATTERNS['region_name'].pattern
                    },
                    'required': False
                },
                'scan_time': {
                    'type': 'string',
                    'regex': r'^([0-1][0-9]|2[0-3]):[0-5][0-9]$',  # HH:MM format
                    'required': False
                }
            },
            
            # NEW: Report scheduling validation
            'schedule_report': {
                'schedule_type': {
                    'type': 'string',
                    'allowed': ['disabled', 'weekly', 'monthly'],
                    'required': True
                },
                'report_day': {
                    'type': 'string',
                    'allowed': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'],
                    'required': False
                },
                'report_time': {
                    'type': 'string',
                    'regex': r'^([0-1][0-9]|2[0-3]):[0-5][0-9]$',  # HH:MM format
                    'required': False
                }
            },
            
            # NEW: Notification preferences validation
            'notification_settings': {
                'notifications_enabled': {
                    'type': 'boolean',
                    'required': True
                },
                'email_on_scan_complete': {
                    'type': 'boolean',
                    'required': False
                },
                'email_on_critical_findings': {
                    'type': 'boolean',
                    'required': False
                },
                'report_schedule': {
                    'type': 'string',
                    'allowed': ['disabled', 'weekly', 'monthly'],
                    'required': False
                }
            },
            
            # NEW: Job management validation
            'job_management': {
                'job_id': {
                    'type': 'string',
                    'minlength': 5,
                    'maxlength': 100,
                    'regex': r'^[a-zA-Z0-9_\-]+$',
                    'required': True
                },
                'action': {
                    'type': 'string',
                    'allowed': ['pause', 'resume', 'delete', 'modify'],
                    'required': True
                }
            },
            
            # NEW: Finding suppression validation
            'suppress_finding': {
                'finding_hash': {
                    'type': 'string',
                    'minlength': 64,
                    'maxlength': 64,
                    'regex': r'^[a-f0-9]{64}$',
                    'required': True
                },
                'reason': {
                    'type': 'string',
                    'maxlength': 500,
                    'required': False
                },
                'suppress_until': {
                    'type': 'string',  # ISO date string
                    'regex': r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z?$',
                    'required': False
                }
            },
            
            # NEW: Advanced scan configuration
            'advanced_scan_config': {
                'scan_depth': {
                    'type': 'string',
                    'allowed': ['basic', 'standard', 'comprehensive'],
                    'required': False
                },
                'include_compliance_checks': {
                    'type': 'boolean',
                    'required': False
                },
                'compliance_frameworks': {
                    'type': 'list',
                    'schema': {
                        'type': 'string',
                        'allowed': ['pci-dss', 'hipaa', 'gdpr', 'sox', 'nist']
                    },
                    'required': False
                },
                'custom_rules': {
                    'type': 'list',
                    'schema': {
                        'type': 'string',
                        'maxlength': 200
                    },
                    'required': False,
                    'maxlength': 10  # Max 10 custom rules
                }
            }
        }
    
    def sanitize_string(self, value: str, allow_html: bool = False) -> str:
        """
        Sanitize string input to prevent XSS and other injection attacks.
        
        Args:
            value: String to sanitize
            allow_html: Whether to allow safe HTML tags
            
        Returns:
            Sanitized string
        """
        if not isinstance(value, str):
            value = str(value)
        
        # Remove null bytes and control characters
        value = value.replace('\x00', '').replace('\r\n', '\n')
        
        # Limit length to prevent DoS
        if len(value) > 10000:
            value = value[:10000]
            logging.warning("Input truncated due to excessive length")
        
        if allow_html:
            # Sanitize HTML but keep allowed tags
            value = bleach.clean(
                value,
                tags=self.ALLOWED_HTML_TAGS,
                attributes=self.ALLOWED_HTML_ATTRS,
                strip=True
            )
        else:
            # Escape all HTML
            value = bleach.clean(value, tags=[], attributes={}, strip=True)
        
        return value.strip()
    
    def validate_email(self, email: str) -> Tuple[bool, str]:
        """
        Validate email address with comprehensive checks.
        
        Args:
            email: Email address to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            email = self.sanitize_string(email).lower()
            
            # Basic format check
            if not self.PATTERNS['email'].match(email):
                return False, "Invalid email format"
            
            # Use validators library for additional checks
            if not validators.email(email):
                return False, "Email address is not valid"
            
            # Check for common typos in domains
            domain = email.split('@')[1]
            suspicious_domains = ['gmial.com', 'yahooo.com', 'hotmial.com']
            if domain in suspicious_domains:
                return False, f"Suspicious domain detected: {domain}"
            
            return True, ""
            
        except Exception as e:
            logging.warning(f"Email validation error: {e}")
            return False, "Email validation failed"
    
    def validate_aws_credentials(self, access_key: str, secret_key: str) -> Tuple[bool, str]:
        """
        Validate AWS credential format.
        
        Args:
            access_key: AWS access key ID
            secret_key: AWS secret access key
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            access_key = self.sanitize_string(access_key)
            secret_key = self.sanitize_string(secret_key)
            
            if not self.PATTERNS['aws_access_key'].match(access_key):
                return False, "Invalid AWS Access Key ID format"
            
            if not self.PATTERNS['aws_secret_key'].match(secret_key):
                return False, "Invalid AWS Secret Access Key format"
            
            return True, ""
            
        except Exception as e:
            logging.warning(f"AWS credentials validation error: {e}")
            return False, "AWS credentials validation failed"
    
    def validate_gcp_service_account_json(self, json_data: str) -> Tuple[bool, str]:
        """
        Validate GCP service account JSON format and required fields.
        
        Args:
            json_data: JSON string of service account key
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            json_data = self.sanitize_string(json_data)
            
            # Parse JSON
            try:
                data = json.loads(json_data)
            except json.JSONDecodeError:
                return False, "Invalid JSON format"
            
            # Check required fields
            required_fields = ['type', 'project_id', 'private_key_id', 'private_key', 'client_email']
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                return False, f"Missing required fields: {', '.join(missing_fields)}"
            
            # Validate field types and formats
            if data.get('type') != 'service_account':
                return False, "JSON must be a service_account type"
            
            if not validators.email(data.get('client_email', '')):
                return False, "Invalid client_email format"
            
            if not data.get('private_key', '').startswith('-----BEGIN PRIVATE KEY-----'):
                return False, "Invalid private key format"
            
            return True, ""
            
        except Exception as e:
            logging.warning(f"GCP JSON validation error: {e}")
            return False, "GCP service account JSON validation failed"
    
    def validate_schedule_time(self, time_str: str) -> Tuple[bool, str]:
        """
        Validate time string in HH:MM format.
        
        Args:
            time_str: Time string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            time_str = self.sanitize_string(time_str)
            
            if not re.match(r'^([0-1][0-9]|2[0-3]):[0-5][0-9]$', time_str):
                return False, "Time must be in HH:MM format (24-hour)"
            
            hours, minutes = map(int, time_str.split(':'))
            
            if not (0 <= hours <= 23):
                return False, "Hours must be between 00 and 23"
            
            if not (0 <= minutes <= 59):
                return False, "Minutes must be between 00 and 59"
            
            return True, ""
            
        except Exception as e:
            logging.warning(f"Time validation error: {e}")
            return False, "Time validation failed"
    
    def validate_cron_expression(self, cron_expr: str) -> Tuple[bool, str]:
        """
        Validate cron expression format.
        
        Args:
            cron_expr: Cron expression to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            cron_expr = self.sanitize_string(cron_expr)
            
            if not self.PATTERNS['cron_expression'].match(cron_expr):
                return False, "Invalid cron expression format"
            
            parts = cron_expr.split()
            if len(parts) != 5:
                return False, "Cron expression must have 5 parts"
            
            return True, ""
            
        except Exception as e:
            logging.warning(f"Cron validation error: {e}")
            return False, "Cron expression validation failed"
    
    def validate_with_schema(self, data: Dict[str, Any], schema_name: str) -> Tuple[bool, Dict[str, List[str]]]:
        """
        Validate data against a predefined schema.
        """
        if schema_name not in self.schemas:
            raise ValueError(f"Unknown schema: {schema_name}")
    
        schema = self.schemas[schema_name]
        # Use the class instance of the validator which has allow_unknown = True
        validator = self.validator 
    
        # Sanitize string values first
        sanitized_data = self._sanitize_dict(data)
    
        is_valid = validator.validate(sanitized_data, schema) # Pass schema to this instance
        errors = validator.errors if not is_valid else {}
    
        return is_valid, errors
    
    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively sanitize dictionary values."""
        sanitized = {}
        
        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = self.sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self.sanitize_string(item) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized
    
    def validate_url(self, url: str, allowed_schemes: List[str] = None) -> Tuple[bool, str]:
        """
        Validate URL format and scheme.
        
        Args:
            url: URL to validate
            allowed_schemes: List of allowed schemes (default: http, https)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if allowed_schemes is None:
            allowed_schemes = ['http', 'https']
        
        try:
            url = self.sanitize_string(url)
            
            if not validators.url(url):
                return False, "Invalid URL format"
            
            parsed = urlparse(url)
            
            if parsed.scheme not in allowed_schemes:
                return False, f"URL scheme '{parsed.scheme}' not allowed"
            
            # Check for suspicious patterns
            suspicious_patterns = ['javascript:', 'data:', 'vbscript:', 'file:']
            url_lower = url.lower()
            
            if any(pattern in url_lower for pattern in suspicious_patterns):
                return False, "Suspicious URL pattern detected"
            
            return True, ""
            
        except Exception as e:
            logging.warning(f"URL validation error: {e}")
            return False, "URL validation failed"
    
    def validate_ip_address(self, ip_str: str) -> Tuple[bool, str]:
        """
        Validate IP address format (IPv4 or IPv6).
        
        Args:
            ip_str: IP address string
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            ip_str = self.sanitize_string(ip_str)
            ipaddress.ip_address(ip_str)
            return True, ""
        except ValueError:
            return False, "Invalid IP address format"
    
    def validate_file_upload(self, filename: str, content: bytes, 
                           max_size: int = 10*1024*1024,  # 10MB default
                           allowed_extensions: List[str] = None) -> Tuple[bool, str]:
        """
        Validate file upload for security.
        
        Args:
            filename: Original filename
            content: File content as bytes
            max_size: Maximum file size in bytes
            allowed_extensions: List of allowed file extensions
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            filename = self.sanitize_string(filename)
            
            # Check filename
            if not self.PATTERNS['safe_filename'].match(filename):
                return False, "Filename contains invalid characters"
            
            # Check file size
            if len(content) > max_size:
                return False, f"File size exceeds limit ({max_size} bytes)"
            
            # Check extension
            if allowed_extensions:
                ext = filename.lower().split('.')[-1] if '.' in filename else ''
                if ext not in allowed_extensions:
                    return False, f"File extension '{ext}' not allowed"
            
            # Check for malicious content patterns
            content_str = content.decode('utf-8', errors='ignore').lower()
            malicious_patterns = ['<script', 'javascript:', 'vbscript:', '<?php']
            
            if any(pattern in content_str for pattern in malicious_patterns):
                return False, "Potentially malicious content detected"
            
            return True, ""
            
        except Exception as e:
            logging.warning(f"File validation error: {e}")
            return False, "File validation failed"


# Flask integration decorators and helpers
from functools import wraps
from flask import request, jsonify, abort

def validate_json_input(schema_name: str):
    """
    Decorator to validate JSON input against a schema.
    
    Args:
        schema_name: Name of the validation schema to use
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 400
            
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'No JSON data provided'}), 400
                
                validator = SecurityValidator()
                is_valid, errors = validator.validate_with_schema(data, schema_name)
                
                if not is_valid:
                    logging.warning(f"Validation failed for {schema_name}: {errors}")
                    return jsonify({'error': 'Validation failed', 'details': errors}), 400
                
                # Add validated data to request context
                request.validated_data = data
                return f(*args, **kwargs)
                
            except Exception as e:
                logging.error(f"JSON validation error: {e}")
                return jsonify({'error': 'Invalid request data'}), 400
        
        return decorated_function
    return decorator

def validate_form_input(schema_name: str):
    """
    Decorator to validate form input against a schema.
    
    Args:
        schema_name: Name of the validation schema to use
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                data = request.form.to_dict()
                
                validator = SecurityValidator()
                is_valid, errors = validator.validate_with_schema(data, schema_name)
                
                if not is_valid:
                    logging.warning(f"Form validation failed for {schema_name}: {errors}")
                    # For form validation, you might want to flash errors and redirect
                    from flask import flash, redirect, url_for
                    for field, field_errors in errors.items():
                        for error in field_errors:
                            flash(f"{field}: {error}", 'error')
                    return redirect(url_for('auth', _anchor='register'))
                
                # Add validated data to request context
                request.validated_data = data
                return f(*args, **kwargs)
                
            except Exception as e:
                logging.error(f"Form validation error: {e}")
                abort(400)
        
        return decorated_function
    return decorator

# Global validator instance for use in routes
security_validator = SecurityValidator()