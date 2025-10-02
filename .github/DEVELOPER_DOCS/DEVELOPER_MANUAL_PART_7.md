# Aegis Cloud Scanner - Developer Manual
## Part 7: Security Implementation and Best Practices

**Document Version:** 1.0
**Last Updated:** September 2024
**Target Audience:** Security Engineers, Software Developers
**Classification:** Internal Development Documentation

---

## Table of Contents
1. [Security Architecture Overview](#security-architecture-overview)
2. [Authentication Mechanisms](#authentication-mechanisms)
3. [Authorization and Access Control](#authorization-and-access-control)
4. [Data Protection and Encryption](#data-protection-and-encryption)
5. [Input Validation and Sanitization](#input-validation-and-sanitization)
6. [Session Management](#session-management)
7. [API Security](#api-security)
8. [Security Monitoring and Logging](#security-monitoring-and-logging)
9. [Vulnerability Management](#vulnerability-management)
10. [Security Testing and Validation](#security-testing-and-validation)

---

## Security Architecture Overview

### Security-First Design Principles

The Aegis Cloud Scanner implements defense-in-depth security architecture with multiple layers of protection:

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Security Layer                   │
├─────────────────────────────────────────────────────────────┤
│  TLS 1.3 │ HTTPS Only │ CSP Headers │ HSTS │ Rate Limiting  │
├─────────────────────────────────────────────────────────────┤
│                 Application Security Layer                  │
├─────────────────────────────────────────────────────────────┤
│ Authentication │ Authorization │ CSRF Protection │ XSS Prevention │
├─────────────────────────────────────────────────────────────┤
│                   Data Security Layer                       │
├─────────────────────────────────────────────────────────────┤
│  Encryption at Rest │ Encryption in Transit │ Key Management │
├─────────────────────────────────────────────────────────────┤
│                Infrastructure Security Layer                │
├─────────────────────────────────────────────────────────────┤
│ Container Security │ OS Hardening │ Network Segmentation │
└─────────────────────────────────────────────────────────────┘
```

### Security Configuration

```python
class SecurityConfig:
    """Centralized security configuration"""

    # Cryptographic settings
    ENCRYPTION_ALGORITHM = 'AES-256-GCM'
    KEY_DERIVATION_ALGORITHM = 'PBKDF2'
    KEY_DERIVATION_ITERATIONS = 100000
    MIN_PASSWORD_LENGTH = 12
    PASSWORD_COMPLEXITY_REQUIRED = True

    # Session security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    SESSION_TIMEOUT_MINUTES = 30
    MAX_CONCURRENT_SESSIONS = 5

    # API security
    API_RATE_LIMIT_PER_MINUTE = 60
    API_RATE_LIMIT_PER_HOUR = 1000
    API_KEY_LENGTH = 32
    JWT_EXPIRY_HOURS = 1
    JWT_REFRESH_EXPIRY_DAYS = 30

    # Input validation
    MAX_INPUT_LENGTH = 10000
    ALLOWED_FILE_EXTENSIONS = ['.json', '.yaml', '.csv']
    MAX_FILE_SIZE_MB = 10

    # Security headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    }

    @classmethod
    def validate_configuration(cls):
        """Validate security configuration"""
        issues = []

        if cls.SESSION_TIMEOUT_MINUTES > 60:
            issues.append("Session timeout exceeds recommended maximum")

        if cls.MIN_PASSWORD_LENGTH < 8:
            issues.append("Minimum password length below security standard")

        if not cls.SESSION_COOKIE_SECURE:
            issues.append("Session cookies not marked as secure")

        return issues
```

---

## Authentication Mechanisms

### Multi-Factor Authentication System

```python
import pyotp
import qrcode
from io import BytesIO
import base64
from werkzeug.security import generate_password_hash, check_password_hash

class MultiFactorAuthentication:
    """Comprehensive multi-factor authentication system"""

    def __init__(self):
        self.totp_issuer = "Aegis Cloud Scanner"

    def generate_totp_secret(self) -> str:
        """Generate TOTP secret for user"""
        return pyotp.random_base32()

    def generate_qr_code(self, user_email: str, secret: str) -> str:
        """Generate QR code for TOTP setup"""
        totp_auth = pyotp.totp.TOTP(secret)
        provisioning_uri = totp_auth.provisioning_uri(
            name=user_email,
            issuer_name=self.totp_issuer
        )

        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()

        return img_str

    def verify_totp_token(self, secret: str, token: str, valid_window: int = 1) -> bool:
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=valid_window)

    def generate_backup_codes(self, count: int = 8) -> List[str]:
        """Generate backup codes for 2FA recovery"""
        codes = []
        for _ in range(count):
            code = secrets.token_hex(4).upper()
            codes.append(f"{code[:4]}-{code[4:]}")
        return codes

    def hash_backup_codes(self, codes: List[str]) -> List[str]:
        """Hash backup codes for secure storage"""
        return [generate_password_hash(code) for code in codes]

    def verify_backup_code(self, hashed_codes: List[str], provided_code: str) -> bool:
        """Verify backup code and mark as used"""
        for i, hashed_code in enumerate(hashed_codes):
            if check_password_hash(hashed_code, provided_code):
                # Mark code as used by removing it
                hashed_codes.pop(i)
                return True
        return False

class PasswordSecurity:
    """Advanced password security implementation"""

    def __init__(self):
        self.min_length = SecurityConfig.MIN_PASSWORD_LENGTH
        self.complexity_required = SecurityConfig.PASSWORD_COMPLEXITY_REQUIRED

    def validate_password_strength(self, password: str) -> Dict[str, Any]:
        """Comprehensive password strength validation"""
        issues = []
        score = 0

        # Length check
        if len(password) < self.min_length:
            issues.append(f"Password must be at least {self.min_length} characters")
        else:
            score += min(len(password) - 8, 10)

        # Character complexity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

        complexity_score = sum([has_upper, has_lower, has_digit, has_special])

        if self.complexity_required and complexity_score < 3:
            issues.append("Password must contain uppercase, lowercase, numbers, and special characters")

        score += complexity_score * 5

        # Common password check
        if self._is_common_password(password):
            issues.append("Password is too common")
            score -= 20

        # Sequential characters check
        if self._has_sequential_chars(password):
            issues.append("Password contains sequential characters")
            score -= 10

        # Repeated characters check
        if self._has_repeated_chars(password):
            issues.append("Password contains too many repeated characters")
            score -= 5

        strength_level = self._calculate_strength_level(score)

        return {
            'is_valid': len(issues) == 0,
            'issues': issues,
            'score': max(0, score),
            'strength': strength_level
        }

    def _is_common_password(self, password: str) -> bool:
        """Check against common password list"""
        common_passwords = [
            'password', '123456', 'password123', 'admin', 'letmein',
            'welcome', 'monkey', '1234567890', 'qwerty', 'abc123'
        ]
        return password.lower() in common_passwords

    def _has_sequential_chars(self, password: str) -> bool:
        """Check for sequential characters"""
        sequences = ['123', 'abc', 'qwe', '789']
        password_lower = password.lower()
        return any(seq in password_lower for seq in sequences)

    def _has_repeated_chars(self, password: str) -> bool:
        """Check for excessive repeated characters"""
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                return True
        return False

    def _calculate_strength_level(self, score: int) -> str:
        """Calculate password strength level"""
        if score >= 50:
            return 'very_strong'
        elif score >= 40:
            return 'strong'
        elif score >= 30:
            return 'medium'
        elif score >= 20:
            return 'weak'
        else:
            return 'very_weak'

    def hash_password(self, password: str) -> str:
        """Securely hash password"""
        return generate_password_hash(
            password,
            method='pbkdf2:sha256:100000'  # 100,000 iterations
        )

    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return check_password_hash(password_hash, password)

class LoginAttemptTracker:
    """Track and prevent brute force attacks"""

    def __init__(self):
        self.attempts = {}  # In production, use Redis or database
        self.max_attempts = 5
        self.lockout_duration = 900  # 15 minutes

    def record_attempt(self, identifier: str, success: bool) -> Dict[str, Any]:
        """Record login attempt"""
        current_time = time.time()

        if identifier not in self.attempts:
            self.attempts[identifier] = {
                'failed_attempts': 0,
                'last_attempt': current_time,
                'locked_until': None
            }

        attempt_info = self.attempts[identifier]

        if success:
            # Reset on successful login
            attempt_info['failed_attempts'] = 0
            attempt_info['locked_until'] = None
        else:
            # Increment failed attempts
            attempt_info['failed_attempts'] += 1
            attempt_info['last_attempt'] = current_time

            # Lock account if threshold exceeded
            if attempt_info['failed_attempts'] >= self.max_attempts:
                attempt_info['locked_until'] = current_time + self.lockout_duration

        return {
            'is_locked': self.is_locked(identifier),
            'failed_attempts': attempt_info['failed_attempts'],
            'lockout_remaining': self.get_lockout_remaining(identifier)
        }

    def is_locked(self, identifier: str) -> bool:
        """Check if account is locked"""
        if identifier not in self.attempts:
            return False

        attempt_info = self.attempts[identifier]
        if attempt_info['locked_until'] is None:
            return False

        if time.time() >= attempt_info['locked_until']:
            # Lock expired, reset
            attempt_info['locked_until'] = None
            attempt_info['failed_attempts'] = 0
            return False

        return True

    def get_lockout_remaining(self, identifier: str) -> int:
        """Get remaining lockout time in seconds"""
        if not self.is_locked(identifier):
            return 0

        attempt_info = self.attempts[identifier]
        return max(0, int(attempt_info['locked_until'] - time.time()))
```

---

## Authorization and Access Control

### Role-Based Access Control (RBAC)

```python
from enum import Enum
from typing import List, Dict, Set
from functools import wraps

class Permission(Enum):
    """System permissions"""
    # Scan permissions
    SCAN_VIEW = "scan:view"
    SCAN_CREATE = "scan:create"
    SCAN_DELETE = "scan:delete"
    SCAN_EXPORT = "scan:export"

    # Report permissions
    REPORT_VIEW = "report:view"
    REPORT_CREATE = "report:create"
    REPORT_DELETE = "report:delete"
    REPORT_EXPORT = "report:export"

    # User permissions
    USER_VIEW = "user:view"
    USER_CREATE = "user:create"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"

    # Admin permissions
    ADMIN_VIEW = "admin:view"
    ADMIN_USERS = "admin:users"
    ADMIN_SYSTEM = "admin:system"
    ADMIN_LICENSES = "admin:licenses"

    # Credential permissions
    CREDENTIAL_VIEW = "credential:view"
    CREDENTIAL_CREATE = "credential:create"
    CREDENTIAL_UPDATE = "credential:update"
    CREDENTIAL_DELETE = "credential:delete"

class Role(Enum):
    """System roles"""
    ADMIN = "admin"
    PRO_USER = "pro_user"
    BASIC_USER = "basic_user"
    READ_ONLY = "read_only"

class RolePermissionManager:
    """Manage role-permission mappings"""

    # Role-permission matrix
    ROLE_PERMISSIONS = {
        Role.ADMIN: {
            Permission.SCAN_VIEW, Permission.SCAN_CREATE, Permission.SCAN_DELETE, Permission.SCAN_EXPORT,
            Permission.REPORT_VIEW, Permission.REPORT_CREATE, Permission.REPORT_DELETE, Permission.REPORT_EXPORT,
            Permission.USER_VIEW, Permission.USER_CREATE, Permission.USER_UPDATE, Permission.USER_DELETE,
            Permission.ADMIN_VIEW, Permission.ADMIN_USERS, Permission.ADMIN_SYSTEM, Permission.ADMIN_LICENSES,
            Permission.CREDENTIAL_VIEW, Permission.CREDENTIAL_CREATE, Permission.CREDENTIAL_UPDATE, Permission.CREDENTIAL_DELETE
        },
        Role.PRO_USER: {
            Permission.SCAN_VIEW, Permission.SCAN_CREATE, Permission.SCAN_DELETE, Permission.SCAN_EXPORT,
            Permission.REPORT_VIEW, Permission.REPORT_CREATE, Permission.REPORT_EXPORT,
            Permission.USER_VIEW, Permission.USER_UPDATE,
            Permission.CREDENTIAL_VIEW, Permission.CREDENTIAL_CREATE, Permission.CREDENTIAL_UPDATE, Permission.CREDENTIAL_DELETE
        },
        Role.BASIC_USER: {
            Permission.SCAN_VIEW, Permission.SCAN_CREATE,
            Permission.REPORT_VIEW,
            Permission.USER_VIEW, Permission.USER_UPDATE,
            Permission.CREDENTIAL_VIEW, Permission.CREDENTIAL_CREATE, Permission.CREDENTIAL_UPDATE
        },
        Role.READ_ONLY: {
            Permission.SCAN_VIEW,
            Permission.REPORT_VIEW,
            Permission.USER_VIEW
        }
    }

    @classmethod
    def get_permissions(cls, role: Role) -> Set[Permission]:
        """Get permissions for role"""
        return cls.ROLE_PERMISSIONS.get(role, set())

    @classmethod
    def has_permission(cls, role: Role, permission: Permission) -> bool:
        """Check if role has specific permission"""
        return permission in cls.get_permissions(role)

    @classmethod
    def get_user_permissions(cls, user_roles: List[Role]) -> Set[Permission]:
        """Get combined permissions from multiple roles"""
        all_permissions = set()
        for role in user_roles:
            all_permissions.update(cls.get_permissions(role))
        return all_permissions

class AccessControlManager:
    """Manage access control and authorization"""

    def __init__(self):
        self.permission_manager = RolePermissionManager()

    def require_permission(self, permission: Permission):
        """Decorator to require specific permission"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if not self.check_permission(permission):
                    raise PermissionDeniedError(f"Permission required: {permission.value}")
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def require_any_permission(self, permissions: List[Permission]):
        """Decorator to require any of the specified permissions"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if not any(self.check_permission(p) for p in permissions):
                    raise PermissionDeniedError(f"One of these permissions required: {[p.value for p in permissions]}")
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def require_role(self, required_role: Role):
        """Decorator to require specific role"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if not self.check_role(required_role):
                    raise PermissionDeniedError(f"Role required: {required_role.value}")
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def check_permission(self, permission: Permission) -> bool:
        """Check if current user has permission"""
        from flask_login import current_user

        if not current_user.is_authenticated:
            return False

        user_roles = self.get_user_roles(current_user)
        user_permissions = self.permission_manager.get_user_permissions(user_roles)

        return permission in user_permissions

    def check_role(self, role: Role) -> bool:
        """Check if current user has role"""
        from flask_login import current_user

        if not current_user.is_authenticated:
            return False

        user_roles = self.get_user_roles(current_user)
        return role in user_roles

    def get_user_roles(self, user) -> List[Role]:
        """Get user roles based on license and user type"""
        roles = []

        # Map license type to roles
        if hasattr(user, 'license_type'):
            if user.license_type == 'enterprise':
                roles.append(Role.ADMIN)
            elif user.license_type == 'pro':
                roles.append(Role.PRO_USER)
            else:
                roles.append(Role.BASIC_USER)

        # Add admin role if user is admin
        if hasattr(user, 'is_admin') and user.is_admin:
            roles.append(Role.ADMIN)

        return roles

    def check_resource_access(self, user, resource_type: str, resource_id: str, action: str) -> bool:
        """Check if user can access specific resource"""
        # Implement resource-based access control
        if resource_type == 'scan_result':
            # Users can only access their own scan results
            from models import ScanResult
            scan = ScanResult.get_by_id(resource_id)
            return scan and scan.user_id == user.id

        elif resource_type == 'cloud_credential':
            # Users can only access their own credentials
            from models import CloudCredential
            credential = CloudCredential.get_by_id(resource_id)
            return credential and credential.user_id == user.id

        # Default deny
        return False

# Usage examples
access_control = AccessControlManager()

@access_control.require_permission(Permission.SCAN_CREATE)
def create_scan():
    """Create new scan - requires scan:create permission"""
    pass

@access_control.require_role(Role.ADMIN)
def admin_function():
    """Admin only function"""
    pass

@access_control.require_any_permission([Permission.SCAN_VIEW, Permission.ADMIN_VIEW])
def view_scan_results():
    """View scan results - requires scan:view OR admin:view"""
    pass

class PermissionDeniedError(Exception):
    """Exception raised when permission is denied"""
    pass
```

---

## Data Protection and Encryption

### Encryption Implementation

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
from typing import bytes, str, Optional

class EncryptionManager:
    """Centralized encryption management"""

    def __init__(self, master_key: Optional[bytes] = None):
        self.master_key = master_key or self._get_master_key()
        self.fernet = Fernet(self.master_key)

    def _get_master_key(self) -> bytes:
        """Get or generate master encryption key"""
        key_path = os.environ.get('MASTER_KEY_PATH')
        if key_path and os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                return f.read()

        # Generate new key (in production, store securely)
        key = Fernet.generate_key()
        logger.warning("Generated new master encryption key")
        return key

    def encrypt_sensitive_data(self, data: str, additional_key: Optional[str] = None) -> str:
        """Encrypt sensitive data with optional additional key"""
        if additional_key:
            # Derive key from additional key + master key
            derived_key = self._derive_key(additional_key.encode(), self.master_key[:16])
            fernet = Fernet(derived_key)
        else:
            fernet = self.fernet

        encrypted_data = fernet.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()

    def decrypt_sensitive_data(self, encrypted_data: str, additional_key: Optional[str] = None) -> str:
        """Decrypt sensitive data"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())

            if additional_key:
                derived_key = self._derive_key(additional_key.encode(), self.master_key[:16])
                fernet = Fernet(derived_key)
            else:
                fernet = self.fernet

            decrypted_data = fernet.decrypt(encrypted_bytes)
            return decrypted_data.decode()

        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise DecryptionError("Failed to decrypt data")

    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """Derive encryption key from password and salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=SecurityConfig.KEY_DERIVATION_ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def encrypt_file(self, file_path: str, output_path: str) -> bool:
        """Encrypt file"""
        try:
            with open(file_path, 'rb') as infile:
                data = infile.read()

            encrypted_data = self.fernet.encrypt(data)

            with open(output_path, 'wb') as outfile:
                outfile.write(encrypted_data)

            return True

        except Exception as e:
            logger.error(f"File encryption failed: {e}")
            return False

    def decrypt_file(self, encrypted_file_path: str, output_path: str) -> bool:
        """Decrypt file"""
        try:
            with open(encrypted_file_path, 'rb') as infile:
                encrypted_data = infile.read()

            decrypted_data = self.fernet.decrypt(encrypted_data)

            with open(output_path, 'wb') as outfile:
                outfile.write(decrypted_data)

            return True

        except Exception as e:
            logger.error(f"File decryption failed: {e}")
            return False

class SecureDataStorage:
    """Secure storage for sensitive application data"""

    def __init__(self, encryption_manager: EncryptionManager):
        self.encryption = encryption_manager

    def store_cloud_credentials(self, user_id: int, provider: str,
                               credentials: Dict[str, Any]) -> str:
        """Securely store cloud credentials"""
        try:
            # Use user ID as additional key component
            additional_key = f"user_{user_id}_{provider}"

            # Encrypt credentials
            credentials_json = json.dumps(credentials)
            encrypted_credentials = self.encryption.encrypt_sensitive_data(
                credentials_json, additional_key
            )

            # Store in database
            from models import CloudCredential
            credential_record = CloudCredential(
                user_id=user_id,
                provider=provider,
                encrypted_credentials=encrypted_credentials,
                salt=os.urandom(16).hex()
            )
            credential_record.save()

            return credential_record.id

        except Exception as e:
            logger.error(f"Failed to store credentials: {e}")
            raise

    def retrieve_cloud_credentials(self, credential_id: str, user_id: int) -> Dict[str, Any]:
        """Securely retrieve cloud credentials"""
        try:
            from models import CloudCredential
            credential_record = CloudCredential.get_by_id(credential_id)

            if not credential_record or credential_record.user_id != user_id:
                raise PermissionDeniedError("Access denied to credentials")

            # Decrypt credentials
            additional_key = f"user_{user_id}_{credential_record.provider}"
            credentials_json = self.encryption.decrypt_sensitive_data(
                credential_record.encrypted_credentials, additional_key
            )

            return json.loads(credentials_json)

        except Exception as e:
            logger.error(f"Failed to retrieve credentials: {e}")
            raise

    def store_api_key(self, user_id: int, api_key: str) -> str:
        """Store encrypted API key"""
        additional_key = f"api_key_{user_id}"
        return self.encryption.encrypt_sensitive_data(api_key, additional_key)

    def retrieve_api_key(self, user_id: int, encrypted_api_key: str) -> str:
        """Retrieve and decrypt API key"""
        additional_key = f"api_key_{user_id}"
        return self.encryption.decrypt_sensitive_data(encrypted_api_key, additional_key)

class DataMasking:
    """Data masking for sensitive information in logs and displays"""

    @staticmethod
    def mask_email(email: str) -> str:
        """Mask email address"""
        if '@' not in email:
            return email

        local, domain = email.split('@', 1)
        if len(local) <= 2:
            masked_local = '*' * len(local)
        else:
            masked_local = local[0] + '*' * (len(local) - 2) + local[-1]

        return f"{masked_local}@{domain}"

    @staticmethod
    def mask_api_key(api_key: str) -> str:
        """Mask API key"""
        if len(api_key) <= 8:
            return '*' * len(api_key)
        return api_key[:4] + '*' * (len(api_key) - 8) + api_key[-4:]

    @staticmethod
    def mask_cloud_credential(credential_value: str) -> str:
        """Mask cloud credential"""
        if len(credential_value) <= 6:
            return '*' * len(credential_value)
        return credential_value[:3] + '*' * (len(credential_value) - 6) + credential_value[-3:]

    @staticmethod
    def mask_sensitive_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively mask sensitive data in dictionary"""
        sensitive_keys = {
            'password', 'secret', 'key', 'token', 'credential',
            'access_key', 'secret_key', 'private_key', 'api_key'
        }

        masked_data = {}
        for key, value in data.items():
            if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
                if isinstance(value, str):
                    masked_data[key] = DataMasking.mask_api_key(value)
                else:
                    masked_data[key] = '[MASKED]'
            elif isinstance(value, dict):
                masked_data[key] = DataMasking.mask_sensitive_data(value)
            else:
                masked_data[key] = value

        return masked_data

class DecryptionError(Exception):
    """Exception raised when decryption fails"""
    pass
```

---

## Input Validation and Sanitization

### Comprehensive Input Validation

```python
import re
import bleach
from cerberus import Validator
from typing import Any, Dict, List, Optional, Union
import html

class InputValidator:
    """Comprehensive input validation and sanitization"""

    def __init__(self):
        self.max_input_length = SecurityConfig.MAX_INPUT_LENGTH
        self.allowed_html_tags = ['b', 'i', 'u', 'em', 'strong', 'p', 'br']
        self.allowed_html_attributes = {}

    def validate_and_sanitize(self, data: Dict[str, Any], schema: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize input data using schema"""
        validator = Validator(schema)

        # Pre-sanitization
        sanitized_data = self._sanitize_input_data(data)

        # Validation
        if not validator.validate(sanitized_data):
            raise ValidationError(validator.errors)

        return validator.document

    def _sanitize_input_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize input data"""
        sanitized = {}

        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = self.sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_input_data(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self.sanitize_string(item) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                sanitized[key] = value

        return sanitized

    def sanitize_string(self, input_string: str) -> str:
        """Sanitize string input"""
        if not isinstance(input_string, str):
            return input_string

        # Length check
        if len(input_string) > self.max_input_length:
            raise ValidationError(f"Input too long (max {self.max_input_length} characters)")

        # HTML escape
        sanitized = html.escape(input_string)

        # Remove null bytes and control characters
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized)

        return sanitized

    def sanitize_html(self, html_input: str) -> str:
        """Sanitize HTML content"""
        return bleach.clean(
            html_input,
            tags=self.allowed_html_tags,
            attributes=self.allowed_html_attributes,
            strip=True
        )

    def validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def validate_url(self, url: str) -> bool:
        """Validate URL format"""
        pattern = r'^https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:\w*))?)?$'
        return re.match(pattern, url) is not None

    def validate_filename(self, filename: str) -> bool:
        """Validate filename"""
        # Check for directory traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return False

        # Check file extension
        allowed_extensions = SecurityConfig.ALLOWED_FILE_EXTENSIONS
        if allowed_extensions:
            ext = os.path.splitext(filename)[1].lower()
            return ext in allowed_extensions

        return True

    def validate_json_structure(self, json_data: Any, required_keys: List[str]) -> bool:
        """Validate JSON structure"""
        if not isinstance(json_data, dict):
            return False

        return all(key in json_data for key in required_keys)

class SchemaDefinitions:
    """Common validation schemas"""

    USER_REGISTRATION = {
        'username': {
            'type': 'string',
            'minlength': 3,
            'maxlength': 50,
            'regex': r'^[a-zA-Z0-9_.-]+$'
        },
        'email': {
            'type': 'string',
            'maxlength': 255,
            'regex': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        },
        'password': {
            'type': 'string',
            'minlength': 12,
            'maxlength': 128
        },
        'first_name': {
            'type': 'string',
            'maxlength': 50,
            'required': False
        },
        'last_name': {
            'type': 'string',
            'maxlength': 50,
            'required': False
        }
    }

    SCAN_CREATION = {
        'name': {
            'type': 'string',
            'minlength': 1,
            'maxlength': 100
        },
        'provider': {
            'type': 'string',
            'allowed': ['aws', 'gcp', 'azure']
        },
        'scan_type': {
            'type': 'string',
            'allowed': ['full', 'compute', 'storage', 'network', 'iam']
        },
        'credential_id': {
            'type': 'integer',
            'min': 1
        },
        'config': {
            'type': 'dict',
            'schema': {
                'regions': {
                    'type': 'list',
                    'schema': {'type': 'string'},
                    'required': False
                },
                'services': {
                    'type': 'list',
                    'schema': {'type': 'string'},
                    'required': False
                }
            }
        }
    }

    CLOUD_CREDENTIAL = {
        'name': {
            'type': 'string',
            'minlength': 1,
            'maxlength': 100
        },
        'provider': {
            'type': 'string',
            'allowed': ['aws', 'gcp', 'azure']
        },
        'description': {
            'type': 'string',
            'maxlength': 500,
            'required': False
        },
        'credentials': {
            'type': 'dict',
            'required': True
        }
    }

class CSRFProtection:
    """CSRF protection implementation"""

    def __init__(self):
        self.token_timeout = 3600  # 1 hour

    def generate_csrf_token(self, session_id: str) -> str:
        """Generate CSRF token"""
        timestamp = str(int(time.time()))
        token_data = f"{session_id}:{timestamp}"

        # Sign token
        secret_key = current_app.config['SECRET_KEY']
        signature = hmac.new(
            secret_key.encode(),
            token_data.encode(),
            hashlib.sha256
        ).hexdigest()

        token = f"{timestamp}:{signature}"
        return base64.urlsafe_b64encode(token.encode()).decode()

    def verify_csrf_token(self, token: str, session_id: str) -> bool:
        """Verify CSRF token"""
        try:
            decoded_token = base64.urlsafe_b64decode(token.encode()).decode()
            timestamp, signature = decoded_token.split(':', 1)

            # Check token age
            if int(time.time()) - int(timestamp) > self.token_timeout:
                return False

            # Verify signature
            token_data = f"{session_id}:{timestamp}"
            secret_key = current_app.config['SECRET_KEY']
            expected_signature = hmac.new(
                secret_key.encode(),
                token_data.encode(),
                hashlib.sha256
            ).hexdigest()

            return hmac.compare_digest(signature, expected_signature)

        except Exception:
            return False

class ValidationError(Exception):
    """Exception raised when validation fails"""

    def __init__(self, errors: Union[str, Dict[str, Any]]):
        self.errors = errors
        super().__init__(str(errors))
```

---

## Session Management

### Secure Session Implementation

```python
import redis
import json
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

class SecureSessionManager:
    """Secure session management with Redis backend"""

    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis_client = redis_client or self._get_redis_client()
        self.session_timeout = SecurityConfig.SESSION_TIMEOUT_MINUTES * 60
        self.max_concurrent_sessions = SecurityConfig.MAX_CONCURRENT_SESSIONS

    def _get_redis_client(self) -> redis.Redis:
        """Get Redis client"""
        redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
        return redis.from_url(redis_url)

    def create_session(self, user_id: int, user_agent: str, ip_address: str) -> str:
        """Create new session"""
        session_id = str(uuid.uuid4())
        session_data = {
            'user_id': user_id,
            'created_at': datetime.utcnow().isoformat(),
            'last_activity': datetime.utcnow().isoformat(),
            'user_agent': user_agent,
            'ip_address': ip_address,
            'is_active': True
        }

        # Check concurrent session limit
        self._enforce_session_limit(user_id)

        # Store session
        session_key = f"session:{session_id}"
        self.redis_client.setex(
            session_key,
            self.session_timeout,
            json.dumps(session_data)
        )

        # Add to user sessions list
        user_sessions_key = f"user_sessions:{user_id}"
        self.redis_client.sadd(user_sessions_key, session_id)
        self.redis_client.expire(user_sessions_key, self.session_timeout)

        logger.info(f"Session created for user {user_id}: {session_id}")
        return session_id

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data"""
        session_key = f"session:{session_id}"
        session_data = self.redis_client.get(session_key)

        if not session_data:
            return None

        session = json.loads(session_data.decode())

        # Check if session is expired
        last_activity = datetime.fromisoformat(session['last_activity'])
        if datetime.utcnow() - last_activity > timedelta(seconds=self.session_timeout):
            self.destroy_session(session_id)
            return None

        return session

    def update_session_activity(self, session_id: str) -> bool:
        """Update session last activity"""
        session = self.get_session(session_id)
        if not session:
            return False

        session['last_activity'] = datetime.utcnow().isoformat()

        session_key = f"session:{session_id}"
        self.redis_client.setex(
            session_key,
            self.session_timeout,
            json.dumps(session)
        )

        return True

    def destroy_session(self, session_id: str) -> bool:
        """Destroy session"""
        session = self.get_session(session_id)
        if not session:
            return False

        user_id = session['user_id']

        # Remove from Redis
        session_key = f"session:{session_id}"
        self.redis_client.delete(session_key)

        # Remove from user sessions list
        user_sessions_key = f"user_sessions:{user_id}"
        self.redis_client.srem(user_sessions_key, session_id)

        logger.info(f"Session destroyed: {session_id}")
        return True

    def destroy_all_user_sessions(self, user_id: int) -> int:
        """Destroy all sessions for user"""
        user_sessions_key = f"user_sessions:{user_id}"
        session_ids = self.redis_client.smembers(user_sessions_key)

        destroyed_count = 0
        for session_id in session_ids:
            if self.destroy_session(session_id.decode()):
                destroyed_count += 1

        return destroyed_count

    def _enforce_session_limit(self, user_id: int):
        """Enforce maximum concurrent sessions"""
        user_sessions_key = f"user_sessions:{user_id}"
        session_ids = list(self.redis_client.smembers(user_sessions_key))

        if len(session_ids) >= self.max_concurrent_sessions:
            # Remove oldest sessions
            sessions_with_activity = []
            for session_id in session_ids:
                session = self.get_session(session_id.decode())
                if session:
                    sessions_with_activity.append((
                        session_id.decode(),
                        datetime.fromisoformat(session['last_activity'])
                    ))

            # Sort by last activity and remove oldest
            sessions_with_activity.sort(key=lambda x: x[1])
            sessions_to_remove = len(sessions_with_activity) - self.max_concurrent_sessions + 1

            for i in range(sessions_to_remove):
                session_id, _ = sessions_with_activity[i]
                self.destroy_session(session_id)

    def get_active_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all active sessions for user"""
        user_sessions_key = f"user_sessions:{user_id}"
        session_ids = self.redis_client.smembers(user_sessions_key)

        active_sessions = []
        for session_id in session_ids:
            session = self.get_session(session_id.decode())
            if session:
                active_sessions.append({
                    'session_id': session_id.decode(),
                    'created_at': session['created_at'],
                    'last_activity': session['last_activity'],
                    'user_agent': session['user_agent'],
                    'ip_address': session['ip_address']
                })

        return active_sessions

    def validate_session_security(self, session_id: str, user_agent: str, ip_address: str) -> bool:
        """Validate session security parameters"""
        session = self.get_session(session_id)
        if not session:
            return False

        # Check user agent (basic fingerprinting)
        if session['user_agent'] != user_agent:
            logger.warning(f"User agent mismatch for session {session_id}")
            # Could be session hijacking, but might also be legitimate
            # In strict mode, this would invalidate the session

        # Check IP address
        if session['ip_address'] != ip_address:
            logger.warning(f"IP address change for session {session_id}")
            # Handle IP changes based on security policy
            # For now, we'll allow it but log it

        return True

class SessionMiddleware:
    """Middleware for session management"""

    def __init__(self, session_manager: SecureSessionManager):
        self.session_manager = session_manager

    def before_request(self):
        """Process request before route handler"""
        from flask import request, g

        # Get session ID from cookie or header
        session_id = request.cookies.get('session_id') or request.headers.get('X-Session-ID')

        if session_id:
            session = self.session_manager.get_session(session_id)
            if session:
                # Validate session security
                if self.session_manager.validate_session_security(
                    session_id,
                    request.headers.get('User-Agent', ''),
                    request.remote_addr
                ):
                    # Update activity
                    self.session_manager.update_session_activity(session_id)

                    # Store in request context
                    g.current_session = session
                    g.session_id = session_id
                else:
                    # Invalid session
                    self.session_manager.destroy_session(session_id)

    def after_request(self, response):
        """Process response after route handler"""
        from flask import g

        # Set secure session cookie
        if hasattr(g, 'session_id'):
            response.set_cookie(
                'session_id',
                g.session_id,
                max_age=SecurityConfig.SESSION_TIMEOUT_MINUTES * 60,
                secure=SecurityConfig.SESSION_COOKIE_SECURE,
                httponly=SecurityConfig.SESSION_COOKIE_HTTPONLY,
                samesite=SecurityConfig.SESSION_COOKIE_SAMESITE
            )

        return response
```

---

## API Security

### API Authentication and Rate Limiting

```python
import jwt
from functools import wraps
from collections import defaultdict
import time
from typing import Dict, Any, Optional

class JWTManager:
    """JWT token management"""

    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.algorithm = 'HS256'
        self.access_token_expiry = SecurityConfig.JWT_EXPIRY_HOURS * 3600
        self.refresh_token_expiry = SecurityConfig.JWT_REFRESH_EXPIRY_DAYS * 86400

    def generate_tokens(self, user_id: int, permissions: List[str]) -> Dict[str, str]:
        """Generate access and refresh tokens"""
        current_time = int(time.time())

        # Access token payload
        access_payload = {
            'user_id': user_id,
            'permissions': permissions,
            'type': 'access',
            'iat': current_time,
            'exp': current_time + self.access_token_expiry
        }

        # Refresh token payload
        refresh_payload = {
            'user_id': user_id,
            'type': 'refresh',
            'iat': current_time,
            'exp': current_time + self.refresh_token_expiry
        }

        access_token = jwt.encode(access_payload, self.secret_key, algorithm=self.algorithm)
        refresh_token = jwt.encode(refresh_payload, self.secret_key, algorithm=self.algorithm)

        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': self.access_token_expiry
        }

    def verify_token(self, token: str, token_type: str = 'access') -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

            if payload.get('type') != token_type:
                return None

            return payload

        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None

    def refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, str]]:
        """Refresh access token using refresh token"""
        payload = self.verify_token(refresh_token, 'refresh')
        if not payload:
            return None

        user_id = payload['user_id']

        # Get user permissions
        from models import User
        user = User.get_by_id(user_id)
        if not user:
            return None

        permissions = self._get_user_permissions(user)
        return self.generate_tokens(user_id, permissions)

    def _get_user_permissions(self, user) -> List[str]:
        """Get user permissions for token"""
        access_control = AccessControlManager()
        user_roles = access_control.get_user_roles(user)
        permissions = RolePermissionManager.get_user_permissions(user_roles)
        return [p.value for p in permissions]

class APIRateLimiter:
    """API rate limiting implementation"""

    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis_client = redis_client or redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/1'))
        self.default_limits = {
            'requests_per_minute': SecurityConfig.API_RATE_LIMIT_PER_MINUTE,
            'requests_per_hour': SecurityConfig.API_RATE_LIMIT_PER_HOUR
        }

    def check_rate_limit(self, identifier: str, limits: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
        """Check if request is within rate limits"""
        limits = limits or self.default_limits
        current_time = int(time.time())

        # Check per-minute limit
        minute_key = f"rate_limit:{identifier}:minute:{current_time // 60}"
        minute_count = self.redis_client.incr(minute_key)
        if minute_count == 1:
            self.redis_client.expire(minute_key, 60)

        # Check per-hour limit
        hour_key = f"rate_limit:{identifier}:hour:{current_time // 3600}"
        hour_count = self.redis_client.incr(hour_key)
        if hour_count == 1:
            self.redis_client.expire(hour_key, 3600)

        # Determine if rate limit exceeded
        minute_exceeded = minute_count > limits['requests_per_minute']
        hour_exceeded = hour_count > limits['requests_per_hour']

        return {
            'allowed': not (minute_exceeded or hour_exceeded),
            'minute_count': minute_count,
            'hour_count': hour_count,
            'minute_limit': limits['requests_per_minute'],
            'hour_limit': limits['requests_per_hour'],
            'reset_minute': (current_time // 60 + 1) * 60,
            'reset_hour': (current_time // 3600 + 1) * 3600
        }

    def get_rate_limit_identifier(self, request) -> str:
        """Get identifier for rate limiting"""
        # Try API key first
        api_key = request.headers.get('X-API-Key')
        if api_key:
            return f"api_key:{api_key}"

        # Try JWT token
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]
            jwt_manager = JWTManager(current_app.config['SECRET_KEY'])
            payload = jwt_manager.verify_token(token)
            if payload:
                return f"user:{payload['user_id']}"

        # Fall back to IP address
        return f"ip:{request.remote_addr}"

class APISecurityMiddleware:
    """Comprehensive API security middleware"""

    def __init__(self):
        self.jwt_manager = JWTManager(current_app.config['SECRET_KEY'])
        self.rate_limiter = APIRateLimiter()

    def authenticate_api_request(self, f):
        """Decorator for API authentication"""
        @wraps(f)
        def decorated(*args, **kwargs):
            from flask import request, jsonify

            # Check for API key
            api_key = request.headers.get('X-API-Key')
            if api_key:
                user = self._validate_api_key(api_key)
                if user:
                    g.current_user = user
                    return f(*args, **kwargs)

            # Check for JWT token
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header[7:]
                payload = self.jwt_manager.verify_token(token)
                if payload:
                    user = User.get_by_id(payload['user_id'])
                    if user:
                        g.current_user = user
                        g.token_permissions = payload.get('permissions', [])
                        return f(*args, **kwargs)

            return jsonify({'error': 'Authentication required'}), 401

        return decorated

    def rate_limit_api(self, limits: Optional[Dict[str, int]] = None):
        """Decorator for API rate limiting"""
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                from flask import request, jsonify

                identifier = self.rate_limiter.get_rate_limit_identifier(request)
                rate_limit_result = self.rate_limiter.check_rate_limit(identifier, limits)

                if not rate_limit_result['allowed']:
                    response = jsonify({
                        'error': 'Rate limit exceeded',
                        'details': {
                            'limit': rate_limit_result['minute_limit'],
                            'reset': rate_limit_result['reset_minute']
                        }
                    })
                    response.status_code = 429
                    response.headers['X-RateLimit-Limit'] = str(rate_limit_result['minute_limit'])
                    response.headers['X-RateLimit-Remaining'] = str(
                        max(0, rate_limit_result['minute_limit'] - rate_limit_result['minute_count'])
                    )
                    response.headers['X-RateLimit-Reset'] = str(rate_limit_result['reset_minute'])
                    return response

                # Add rate limit headers to successful response
                response = f(*args, **kwargs)
                if hasattr(response, 'headers'):
                    response.headers['X-RateLimit-Limit'] = str(rate_limit_result['minute_limit'])
                    response.headers['X-RateLimit-Remaining'] = str(
                        max(0, rate_limit_result['minute_limit'] - rate_limit_result['minute_count'])
                    )
                    response.headers['X-RateLimit-Reset'] = str(rate_limit_result['reset_minute'])

                return response

            return decorated
        return decorator

    def _validate_api_key(self, api_key: str) -> Optional[User]:
        """Validate API key"""
        # In production, store API keys securely hashed
        # This is a simplified implementation
        try:
            # Decode API key to get user ID
            # In practice, you'd look up the hashed API key in database
            pass
        except:
            return None

# Usage examples
api_security = APISecurityMiddleware()

@app.route('/api/v1/scans')
@api_security.authenticate_api_request
@api_security.rate_limit_api({'requests_per_minute': 30, 'requests_per_hour': 500})
def api_list_scans():
    """API endpoint with authentication and rate limiting"""
    pass
```

---

## Security Monitoring and Logging

### Security Event Monitoring

```python
from enum import Enum
import json
from typing import Dict, Any, Optional

class SecurityEventType(Enum):
    """Types of security events"""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    PERMISSION_DENIED = "permission_denied"
    API_KEY_USAGE = "api_key_usage"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    DATA_ACCESS = "data_access"
    CONFIGURATION_CHANGE = "configuration_change"
    SECURITY_SCAN_ANOMALY = "security_scan_anomaly"

class SecurityLogger:
    """Centralized security event logging"""

    def __init__(self):
        self.logger = logging.getLogger('security')
        self.setup_security_logger()

    def setup_security_logger(self):
        """Setup dedicated security logger"""
        handler = RotatingFileHandler(
            os.path.join(USER_DATA_DIR, 'security.log'),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=10
        )

        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)

        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def log_security_event(self, event_type: SecurityEventType, user_id: Optional[int] = None,
                          details: Optional[Dict[str, Any]] = None, request_context: Optional[Dict[str, str]] = None):
        """Log security event"""
        from flask import request, g

        event_data = {
            'event_type': event_type.value,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'user_id': user_id,
            'session_id': getattr(g, 'session_id', None),
            'details': details or {},
        }

        # Add request context if available
        if request_context:
            event_data['request'] = request_context
        elif request:
            event_data['request'] = {
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', ''),
                'method': request.method,
                'url': request.url,
                'endpoint': request.endpoint
            }

        # Mask sensitive data
        masked_data = DataMasking.mask_sensitive_data(event_data)

        self.logger.info(json.dumps(masked_data))

        # Send to SIEM if configured
        self._send_to_siem(event_data)

        # Check for security alerts
        self._check_security_alerts(event_type, user_id, details)

    def _send_to_siem(self, event_data: Dict[str, Any]):
        """Send security event to SIEM system"""
        siem_endpoint = os.environ.get('SIEM_ENDPOINT')
        if not siem_endpoint:
            return

        try:
            import requests
            response = requests.post(
                siem_endpoint,
                json=event_data,
                timeout=5,
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to send event to SIEM: {e}")

    def _check_security_alerts(self, event_type: SecurityEventType, user_id: Optional[int], details: Optional[Dict[str, Any]]):
        """Check if event should trigger security alerts"""
        alert_manager = SecurityAlertManager()

        if event_type == SecurityEventType.LOGIN_FAILURE:
            alert_manager.check_brute_force_alert(user_id or details.get('username'))
        elif event_type == SecurityEventType.PERMISSION_DENIED:
            alert_manager.check_privilege_escalation_alert(user_id)
        elif event_type == SecurityEventType.RATE_LIMIT_EXCEEDED:
            alert_manager.check_dos_alert(details.get('ip_address'))

class SecurityAlertManager:
    """Manage security alerts and automated responses"""

    def __init__(self):
        self.redis_client = redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/2'))

    def check_brute_force_alert(self, identifier: str):
        """Check for brute force attack patterns"""
        if not identifier:
            return

        # Count failed attempts in last 10 minutes
        window_key = f"failed_logins:{identifier}:{int(time.time() // 600)}"
        failed_count = self.redis_client.incr(window_key)
        self.redis_client.expire(window_key, 600)

        if failed_count >= 10:  # 10 failures in 10 minutes
            self._trigger_alert('brute_force', {
                'identifier': identifier,
                'failed_attempts': failed_count,
                'time_window': '10 minutes'
            })

    def check_privilege_escalation_alert(self, user_id: Optional[int]):
        """Check for privilege escalation attempts"""
        if not user_id:
            return

        # Count permission denied events in last hour
        window_key = f"permission_denied:{user_id}:{int(time.time() // 3600)}"
        denied_count = self.redis_client.incr(window_key)
        self.redis_client.expire(window_key, 3600)

        if denied_count >= 5:  # 5 denials in 1 hour
            self._trigger_alert('privilege_escalation', {
                'user_id': user_id,
                'denied_attempts': denied_count,
                'time_window': '1 hour'
            })

    def check_dos_alert(self, ip_address: Optional[str]):
        """Check for denial of service patterns"""
        if not ip_address:
            return

        # Count rate limit exceeded events
        window_key = f"rate_limit_exceeded:{ip_address}:{int(time.time() // 300)}"
        exceeded_count = self.redis_client.incr(window_key)
        self.redis_client.expire(window_key, 300)

        if exceeded_count >= 3:  # 3 rate limit exceeded in 5 minutes
            self._trigger_alert('potential_dos', {
                'ip_address': ip_address,
                'rate_limit_exceeded': exceeded_count,
                'time_window': '5 minutes'
            })

    def _trigger_alert(self, alert_type: str, details: Dict[str, Any]):
        """Trigger security alert"""
        alert_data = {
            'alert_type': alert_type,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'details': details,
            'severity': self._get_alert_severity(alert_type)
        }

        # Log alert
        logger.critical(f"Security Alert: {json.dumps(alert_data)}")

        # Send notifications
        self._send_alert_notifications(alert_data)

        # Take automated action if configured
        self._take_automated_action(alert_type, details)

    def _get_alert_severity(self, alert_type: str) -> str:
        """Get alert severity level"""
        severity_map = {
            'brute_force': 'high',
            'privilege_escalation': 'high',
            'potential_dos': 'medium'
        }
        return severity_map.get(alert_type, 'low')

    def _send_alert_notifications(self, alert_data: Dict[str, Any]):
        """Send alert notifications"""
        # Email notification
        try:
            admin_emails = self._get_admin_emails()
            for email in admin_emails:
                self._send_alert_email(email, alert_data)
        except Exception as e:
            logger.error(f"Failed to send alert email: {e}")

        # Webhook notification
        try:
            webhook_url = os.environ.get('SECURITY_WEBHOOK_URL')
            if webhook_url:
                import requests
                requests.post(webhook_url, json=alert_data, timeout=10)
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")

    def _take_automated_action(self, alert_type: str, details: Dict[str, Any]):
        """Take automated security actions"""
        if alert_type == 'brute_force':
            # Temporarily block IP
            ip_address = details.get('ip_address')
            if ip_address:
                self._block_ip_address(ip_address, duration=3600)  # 1 hour

        elif alert_type == 'privilege_escalation':
            # Lock user account
            user_id = details.get('user_id')
            if user_id:
                self._lock_user_account(user_id)

    def _block_ip_address(self, ip_address: str, duration: int):
        """Block IP address"""
        block_key = f"blocked_ip:{ip_address}"
        self.redis_client.setex(block_key, duration, "1")
        logger.warning(f"Blocked IP address {ip_address} for {duration} seconds")

    def _lock_user_account(self, user_id: int):
        """Lock user account"""
        try:
            from models import User
            user = User.get_by_id(user_id)
            if user:
                user.is_active = False
                user.save()
                logger.warning(f"Locked user account {user_id}")
        except Exception as e:
            logger.error(f"Failed to lock user account {user_id}: {e}")

    def _get_admin_emails(self) -> List[str]:
        """Get admin email addresses"""
        try:
            from models import User
            admin_users = User.query.filter_by(is_admin=True).all()
            return [user.email for user in admin_users if user.email]
        except:
            return []

    def _send_alert_email(self, email: str, alert_data: Dict[str, Any]):
        """Send security alert email"""
        # Implementation would use Flask-Mail or similar
        pass

# Security monitoring decorators
security_logger = SecurityLogger()

def log_security_event(event_type: SecurityEventType, include_details: bool = True):
    """Decorator to log security events"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            from flask import g

            try:
                result = f(*args, **kwargs)

                if include_details:
                    details = {'function': f.__name__, 'success': True}
                else:
                    details = None

                security_logger.log_security_event(
                    event_type,
                    user_id=getattr(g, 'current_user', {}).get('id'),
                    details=details
                )

                return result

            except Exception as e:
                security_logger.log_security_event(
                    event_type,
                    user_id=getattr(g, 'current_user', {}).get('id'),
                    details={'function': f.__name__, 'success': False, 'error': str(e)}
                )
                raise

        return decorated
    return decorator

# Usage example
@log_security_event(SecurityEventType.DATA_ACCESS)
def access_sensitive_data():
    """Function that accesses sensitive data"""
    pass
```

---

## Vulnerability Management

### Security Scanning and Assessment

```python
import subprocess
import json
from typing import List, Dict, Any

class VulnerabilityScanner:
    """Scan application for security vulnerabilities"""

    def __init__(self):
        self.scan_results = {}

    def run_comprehensive_scan(self) -> Dict[str, Any]:
        """Run comprehensive security scan"""
        results = {
            'dependency_scan': self.scan_dependencies(),
            'static_analysis': self.run_static_analysis(),
            'secrets_scan': self.scan_for_secrets(),
            'configuration_audit': self.audit_configuration(),
            'permissions_audit': self.audit_permissions()
        }

        # Generate security report
        security_report = self.generate_security_report(results)
        return security_report

    def scan_dependencies(self) -> Dict[str, Any]:
        """Scan dependencies for known vulnerabilities"""
        results = {'status': 'completed', 'vulnerabilities': [], 'summary': {}}

        try:
            # Use safety to scan Python dependencies
            result = subprocess.run(
                ['safety', 'check', '--json'],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                # No vulnerabilities found
                results['summary'] = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            else:
                # Parse safety output
                try:
                    vulnerability_data = json.loads(result.stdout)
                    results['vulnerabilities'] = self._process_safety_results(vulnerability_data)
                    results['summary'] = self._summarize_vulnerabilities(results['vulnerabilities'])
                except json.JSONDecodeError:
                    results['status'] = 'error'
                    results['error'] = 'Failed to parse safety output'

        except subprocess.TimeoutExpired:
            results['status'] = 'timeout'
        except FileNotFoundError:
            results['status'] = 'tool_not_found'
            results['error'] = 'safety tool not installed'
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)

        return results

    def run_static_analysis(self) -> Dict[str, Any]:
        """Run static code analysis"""
        results = {'status': 'completed', 'issues': [], 'summary': {}}

        try:
            # Use bandit for Python security analysis
            result = subprocess.run(
                ['bandit', '-r', '.', '-f', 'json', '-ll'],
                capture_output=True,
                text=True,
                timeout=600
            )

            try:
                bandit_data = json.loads(result.stdout)
                results['issues'] = self._process_bandit_results(bandit_data)
                results['summary'] = self._summarize_static_analysis(results['issues'])
            except json.JSONDecodeError:
                results['status'] = 'error'
                results['error'] = 'Failed to parse bandit output'

        except subprocess.TimeoutExpired:
            results['status'] = 'timeout'
        except FileNotFoundError:
            results['status'] = 'tool_not_found'
            results['error'] = 'bandit tool not installed'
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)

        return results

    def scan_for_secrets(self) -> Dict[str, Any]:
        """Scan for hardcoded secrets"""
        results = {'status': 'completed', 'secrets': [], 'summary': {}}

        # Common secret patterns
        secret_patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', 'password'),
            (r'api_key\s*=\s*["\'][^"\']+["\']', 'api_key'),
            (r'secret_key\s*=\s*["\'][^"\']+["\']', 'secret_key'),
            (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
            (r'sk_live_[0-9a-zA-Z]{24}', 'stripe_secret_key'),
            (r'xox[baprs]-[0-9a-zA-Z\-]{10,48}', 'slack_token'),
        ]

        try:
            import os
            import re

            for root, dirs, files in os.walk('.'):
                # Skip virtual environment and git directories
                dirs[:] = [d for d in dirs if d not in ['venv', '.git', '__pycache__', 'node_modules']]

                for file in files:
                    if file.endswith(('.py', '.js', '.json', '.yml', '.yaml', '.env')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()

                            for pattern, secret_type in secret_patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    line_number = content[:match.start()].count('\n') + 1
                                    results['secrets'].append({
                                        'file': file_path,
                                        'line': line_number,
                                        'type': secret_type,
                                        'pattern': pattern,
                                        'match': match.group()[:50] + '...' if len(match.group()) > 50 else match.group()
                                    })

                        except Exception as e:
                            logger.error(f"Error scanning file {file_path}: {e}")

            results['summary'] = {
                'total_secrets': len(results['secrets']),
                'files_affected': len(set(s['file'] for s in results['secrets'])),
                'types_found': len(set(s['type'] for s in results['secrets']))
            }

        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)

        return results

    def audit_configuration(self) -> Dict[str, Any]:
        """Audit security configuration"""
        audit_results = {'status': 'completed', 'findings': [], 'summary': {}}

        try:
            findings = []

            # Check Flask security configuration
            flask_config_issues = self._audit_flask_config()
            findings.extend(flask_config_issues)

            # Check database security
            db_config_issues = self._audit_database_config()
            findings.extend(db_config_issues)

            # Check file permissions
            file_permission_issues = self._audit_file_permissions()
            findings.extend(file_permission_issues)

            audit_results['findings'] = findings
            audit_results['summary'] = self._summarize_audit_findings(findings)

        except Exception as e:
            audit_results['status'] = 'error'
            audit_results['error'] = str(e)

        return audit_results

    def _audit_flask_config(self) -> List[Dict[str, Any]]:
        """Audit Flask security configuration"""
        findings = []

        try:
            from app import app
            config = app.config

            # Check SECRET_KEY
            if not config.get('SECRET_KEY') or config['SECRET_KEY'] == 'dev-secret-key':
                findings.append({
                    'type': 'configuration',
                    'severity': 'high',
                    'title': 'Weak or Default Secret Key',
                    'description': 'Application is using weak or default secret key',
                    'recommendation': 'Use a strong, randomly generated secret key'
                })

            # Check debug mode
            if config.get('DEBUG', False):
                findings.append({
                    'type': 'configuration',
                    'severity': 'high',
                    'title': 'Debug Mode Enabled',
                    'description': 'Debug mode is enabled in production',
                    'recommendation': 'Disable debug mode in production'
                })

            # Check session configuration
            if not config.get('SESSION_COOKIE_SECURE', False):
                findings.append({
                    'type': 'configuration',
                    'severity': 'medium',
                    'title': 'Insecure Session Cookies',
                    'description': 'Session cookies are not marked as secure',
                    'recommendation': 'Enable SESSION_COOKIE_SECURE'
                })

        except Exception as e:
            logger.error(f"Flask config audit failed: {e}")

        return findings

    def _audit_database_config(self) -> List[Dict[str, Any]]:
        """Audit database security configuration"""
        findings = []

        try:
            from app import app
            db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')

            # Check for credentials in URI
            if 'password' in db_uri.lower() and 'sqlite' not in db_uri.lower():
                findings.append({
                    'type': 'configuration',
                    'severity': 'medium',
                    'title': 'Database Credentials in URI',
                    'description': 'Database credentials are visible in connection URI',
                    'recommendation': 'Use environment variables for database credentials'
                })

            # Check SQLite file permissions (if using SQLite)
            if 'sqlite' in db_uri.lower():
                import os
                import stat
                db_file = db_uri.replace('sqlite:///', '')
                if os.path.exists(db_file):
                    file_stat = os.stat(db_file)
                    file_mode = stat.filemode(file_stat.st_mode)
                    if file_mode[7:] != '--':  # Check if others have any permissions
                        findings.append({
                            'type': 'file_permissions',
                            'severity': 'medium',
                            'title': 'Database File Permissions Too Permissive',
                            'description': f'Database file has permissions: {file_mode}',
                            'recommendation': 'Restrict database file permissions to owner only'
                        })

        except Exception as e:
            logger.error(f"Database config audit failed: {e}")

        return findings

    def _audit_file_permissions(self) -> List[Dict[str, Any]]:
        """Audit file permissions"""
        findings = []

        try:
            import os
            import stat

            sensitive_files = [
                '.env',
                'config.py',
                'wsgi.py',
                'requirements.txt'
            ]

            for filename in sensitive_files:
                if os.path.exists(filename):
                    file_stat = os.stat(filename)
                    file_mode = stat.filemode(file_stat.st_mode)

                    # Check if file is world-readable
                    if file_mode[7] == 'r':
                        findings.append({
                            'type': 'file_permissions',
                            'severity': 'medium',
                            'title': f'Sensitive File World-Readable: {filename}',
                            'description': f'File {filename} is readable by all users',
                            'recommendation': 'Restrict file permissions to owner only'
                        })

        except Exception as e:
            logger.error(f"File permissions audit failed: {e}")

        return findings

    def audit_permissions(self) -> Dict[str, Any]:
        """Audit application permissions and access controls"""
        audit_results = {'status': 'completed', 'findings': [], 'summary': {}}

        try:
            findings = []

            # Check for proper authorization decorators
            findings.extend(self._check_authorization_decorators())

            # Check for privilege escalation vulnerabilities
            findings.extend(self._check_privilege_escalation())

            # Check for insecure direct object references
            findings.extend(self._check_direct_object_references())

            audit_results['findings'] = findings
            audit_results['summary'] = self._summarize_audit_findings(findings)

        except Exception as e:
            audit_results['status'] = 'error'
            audit_results['error'] = str(e)

        return audit_results

    def generate_security_report(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        total_issues = 0
        critical_issues = 0
        high_issues = 0
        medium_issues = 0
        low_issues = 0

        # Aggregate results
        for scan_type, results in scan_results.items():
            if results.get('status') == 'completed':
                summary = results.get('summary', {})
                if 'total' in summary:
                    total_issues += summary['total']
                    critical_issues += summary.get('critical', 0)
                    high_issues += summary.get('high', 0)
                    medium_issues += summary.get('medium', 0)
                    low_issues += summary.get('low', 0)

        # Calculate risk score
        risk_score = self._calculate_risk_score(critical_issues, high_issues, medium_issues, low_issues)

        report = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'summary': {
                'total_issues': total_issues,
                'critical': critical_issues,
                'high': high_issues,
                'medium': medium_issues,
                'low': low_issues,
                'risk_score': risk_score
            },
            'scan_results': scan_results,
            'recommendations': self._generate_recommendations(scan_results)
        }

        return report

    def _calculate_risk_score(self, critical: int, high: int, medium: int, low: int) -> float:
        """Calculate overall risk score (0-100)"""
        score = (critical * 10) + (high * 5) + (medium * 2) + (low * 1)
        return min(100.0, score)

    def _generate_recommendations(self, scan_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        # Check dependency scan
        dep_results = scan_results.get('dependency_scan', {})
        if dep_results.get('summary', {}).get('total', 0) > 0:
            recommendations.append("Update vulnerable dependencies to latest secure versions")

        # Check static analysis
        static_results = scan_results.get('static_analysis', {})
        if static_results.get('summary', {}).get('total', 0) > 0:
            recommendations.append("Address static analysis security findings")

        # Check secrets scan
        secrets_results = scan_results.get('secrets_scan', {})
        if secrets_results.get('summary', {}).get('total_secrets', 0) > 0:
            recommendations.append("Remove hardcoded secrets and use environment variables or secret management")

        # Check configuration audit
        config_results = scan_results.get('configuration_audit', {})
        config_findings = config_results.get('findings', [])
        high_config_issues = [f for f in config_findings if f.get('severity') == 'high']
        if high_config_issues:
            recommendations.append("Fix high-severity configuration security issues")

        if not recommendations:
            recommendations.append("No critical security issues found - maintain current security practices")

        return recommendations

    def _process_safety_results(self, safety_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process safety scan results"""
        vulnerabilities = []
        for vuln in safety_data:
            vulnerabilities.append({
                'package': vuln.get('package'),
                'version': vuln.get('installed_version'),
                'vulnerability_id': vuln.get('vulnerability_id'),
                'severity': self._map_safety_severity(vuln.get('severity')),
                'description': vuln.get('advisory'),
                'fix_version': vuln.get('specs', [])
            })
        return vulnerabilities

    def _process_bandit_results(self, bandit_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process bandit scan results"""
        issues = []
        for result in bandit_data.get('results', []):
            issues.append({
                'file': result.get('filename'),
                'line': result.get('line_number'),
                'test_id': result.get('test_id'),
                'test_name': result.get('test_name'),
                'severity': result.get('issue_severity').lower(),
                'confidence': result.get('issue_confidence').lower(),
                'description': result.get('issue_text'),
                'code': result.get('code')
            })
        return issues

    def _map_safety_severity(self, severity: str) -> str:
        """Map safety severity to standard levels"""
        severity_map = {
            '9.0-10.0': 'critical',
            '7.0-8.9': 'high',
            '4.0-6.9': 'medium',
            '0.1-3.9': 'low'
        }
        return severity_map.get(severity, 'medium')

    def _summarize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Summarize vulnerability counts by severity"""
        summary = {'total': len(vulnerabilities), 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium')
            summary[severity] = summary.get(severity, 0) + 1
        return summary

    def _summarize_static_analysis(self, issues: List[Dict[str, Any]]) -> Dict[str, int]:
        """Summarize static analysis issues"""
        summary = {'total': len(issues), 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for issue in issues:
            severity = issue.get('severity', 'medium')
            summary[severity] = summary.get(severity, 0) + 1
        return summary

    def _summarize_audit_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Summarize audit findings"""
        summary = {'total': len(findings), 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in findings:
            severity = finding.get('severity', 'medium')
            summary[severity] = summary.get(severity, 0) + 1
        return summary

    def _check_authorization_decorators(self) -> List[Dict[str, Any]]:
        """Check for missing authorization decorators"""
        # This would analyze the codebase for routes missing auth decorators
        return []

    def _check_privilege_escalation(self) -> List[Dict[str, Any]]:
        """Check for privilege escalation vulnerabilities"""
        # This would analyze permission checks and role assignments
        return []

    def _check_direct_object_references(self) -> List[Dict[str, Any]]:
        """Check for insecure direct object references"""
        # This would analyze route parameters and object access patterns
        return []
```

---

## Security Testing and Validation

### Automated Security Testing

```python
import unittest
import requests
from unittest.mock import patch, MagicMock

class SecurityTestSuite(unittest.TestCase):
    """Comprehensive security test suite"""

    def setUp(self):
        """Set up test environment"""
        from app import app
        self.app = app.test_client()
        self.app.testing = True

    def test_sql_injection_protection(self):
        """Test SQL injection protection"""
        # Test various SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "1'; DELETE FROM users; --"
        ]

        for payload in sql_payloads:
            with self.subTest(payload=payload):
                response = self.app.get(f'/api/v1/scans?scan_id={payload}')
                # Should return 400 (validation error) or 403 (blocked)
                self.assertIn(response.status_code, [400, 403])

    def test_xss_protection(self):
        """Test XSS protection"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>"
        ]

        for payload in xss_payloads:
            with self.subTest(payload=payload):
                response = self.app.post('/api/v1/scans',
                    json={'name': payload, 'provider': 'aws'},
                    headers={'Content-Type': 'application/json'}
                )
                # Should sanitize input and not execute script
                self.assertNotIn('<script>', response.get_data(as_text=True))

    def test_csrf_protection(self):
        """Test CSRF protection"""
        # Test POST request without CSRF token
        response = self.app.post('/login', data={
            'username': 'test',
            'password': 'test'
        })
        self.assertEqual(response.status_code, 403)

    def test_authentication_bypass(self):
        """Test authentication bypass attempts"""
        # Test accessing protected endpoint without auth
        response = self.app.get('/api/v1/scans')
        self.assertEqual(response.status_code, 401)

        # Test with invalid token
        response = self.app.get('/api/v1/scans',
            headers={'Authorization': 'Bearer invalid_token'})
        self.assertEqual(response.status_code, 401)

    def test_authorization_bypass(self):
        """Test authorization bypass attempts"""
        # Mock authenticated user without permission
        with patch('flask_login.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 1
            mock_user.license_type = 'basic'

            # Try to access admin endpoint
            response = self.app.get('/admin/users')
            self.assertEqual(response.status_code, 403)

    def test_rate_limiting(self):
        """Test rate limiting"""
        # Make multiple requests quickly
        responses = []
        for _ in range(100):
            response = self.app.get('/api/v1/health')
            responses.append(response.status_code)

        # Should eventually get rate limited
        self.assertIn(429, responses)

    def test_input_validation(self):
        """Test input validation"""
        # Test oversized input
        large_input = 'A' * 100000
        response = self.app.post('/api/v1/scans',
            json={'name': large_input, 'provider': 'aws'},
            headers={'Content-Type': 'application/json'}
        )
        self.assertEqual(response.status_code, 400)

        # Test invalid data types
        response = self.app.post('/api/v1/scans',
            json={'name': 123, 'provider': 'aws'},
            headers={'Content-Type': 'application/json'}
        )
        self.assertEqual(response.status_code, 400)

    def test_session_security(self):
        """Test session security"""
        # Test session fixation
        response1 = self.app.get('/')
        session_id1 = self._extract_session_id(response1)

        # Login
        response2 = self.app.post('/login', data={
            'username': 'test@example.com',
            'password': 'testpassword123'
        })

        session_id2 = self._extract_session_id(response2)

        # Session ID should change after login
        self.assertNotEqual(session_id1, session_id2)

    def test_file_upload_security(self):
        """Test file upload security"""
        # Test malicious file upload
        malicious_files = [
            ('test.php', b'<?php system($_GET["cmd"]); ?>'),
            ('test.jsp', b'<%@ page import="java.util.*,java.io.*"%>'),
            ('test.exe', b'MZ\x90\x00'),  # PE header
        ]

        for filename, content in malicious_files:
            with self.subTest(filename=filename):
                response = self.app.post('/api/v1/upload',
                    data={'file': (io.BytesIO(content), filename)})
                # Should reject malicious files
                self.assertIn(response.status_code, [400, 403])

    def test_information_disclosure(self):
        """Test for information disclosure"""
        # Test debug information in responses
        response = self.app.get('/nonexistent-endpoint')
        response_text = response.get_data(as_text=True)

        # Should not disclose stack traces or sensitive info
        self.assertNotIn('Traceback', response_text)
        self.assertNotIn('File "/', response_text)
        self.assertNotIn('SECRET_KEY', response_text)

    def test_insecure_direct_object_references(self):
        """Test for insecure direct object references"""
        # Mock two different users
        with patch('flask_login.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 1

            # Try to access another user's data
            response = self.app.get('/api/v1/scans/999')  # Assuming this belongs to user 2
            self.assertIn(response.status_code, [403, 404])

    def test_security_headers(self):
        """Test security headers"""
        response = self.app.get('/')
        headers = response.headers

        # Check for security headers
        expected_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]

        for header in expected_headers:
            with self.subTest(header=header):
                self.assertIn(header, headers)

    def test_password_security(self):
        """Test password security"""
        weak_passwords = [
            'password',
            '123456',
            'qwerty',
            'admin',
            'test'
        ]

        for password in weak_passwords:
            with self.subTest(password=password):
                response = self.app.post('/register', data={
                    'username': 'test',
                    'email': 'test@example.com',
                    'password': password
                })
                # Should reject weak passwords
                self.assertEqual(response.status_code, 400)

    def test_encryption_security(self):
        """Test encryption implementation"""
        from security import EncryptionManager

        encryption_manager = EncryptionManager()
        test_data = "sensitive information"

        # Test encryption
        encrypted = encryption_manager.encrypt_sensitive_data(test_data)
        self.assertNotEqual(test_data, encrypted)

        # Test decryption
        decrypted = encryption_manager.decrypt_sensitive_data(encrypted)
        self.assertEqual(test_data, decrypted)

        # Test with wrong key
        with self.assertRaises(Exception):
            wrong_manager = EncryptionManager(b'wrong_key_123456789012345678901234')
            wrong_manager.decrypt_sensitive_data(encrypted)

    def _extract_session_id(self, response):
        """Extract session ID from response"""
        for cookie in response.headers.getlist('Set-Cookie'):
            if 'session_id=' in cookie:
                return cookie.split('session_id=')[1].split(';')[0]
        return None

class PenetrationTestSuite(unittest.TestCase):
    """Penetration testing scenarios"""

    def setUp(self):
        self.base_url = 'http://localhost:5000'

    def test_directory_traversal(self):
        """Test directory traversal attacks"""
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ]

        for payload in traversal_payloads:
            with self.subTest(payload=payload):
                response = requests.get(f'{self.base_url}/download?file={payload}')
                # Should not return system files
                self.assertNotIn('root:', response.text)
                self.assertNotIn('localhost', response.text)

    def test_command_injection(self):
        """Test command injection attacks"""
        command_payloads = [
            '; cat /etc/passwd',
            '| whoami',
            '`id`',
            '$(uname -a)',
            '& dir'
        ]

        for payload in command_payloads:
            with self.subTest(payload=payload):
                response = requests.post(f'{self.base_url}/api/v1/scan',
                    json={'command': f'scan {payload}'})
                # Should not execute system commands
                self.assertNotIn('uid=', response.text)
                self.assertNotIn('Windows', response.text)

    def test_header_injection(self):
        """Test HTTP header injection"""
        malicious_headers = {
            'X-Forwarded-For': 'evil.com\r\nX-Injected-Header: malicious',
            'User-Agent': 'Mozilla\r\nX-XSS-Test: <script>alert(1)</script>',
            'Referer': 'http://example.com\r\nSet-Cookie: evil=true'
        }

        for header, value in malicious_headers.items():
            with self.subTest(header=header):
                response = requests.get(f'{self.base_url}/', headers={header: value})
                # Should sanitize headers
                self.assertNotIn('X-Injected-Header', str(response.headers))
                self.assertNotIn('<script>', str(response.headers))

if __name__ == '__main__':
    # Run security tests
    unittest.main()
```

---

**End of Part 7**

**Next:** Part 8 will cover Testing Framework and Guidelines, including unit testing, integration testing, security testing, and quality assurance practices.