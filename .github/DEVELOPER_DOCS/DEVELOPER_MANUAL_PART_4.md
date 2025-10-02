# Aegis Cloud Scanner - Developer Manual
## Part 4: Database Schema and Models

**Document Version:** 1.0
**Last Updated:** September 2024
**Target Audience:** Software Developers, Database Administrators
**Classification:** Internal Development Documentation

---

## Table of Contents
1. [Database Architecture Overview](#database-architecture-overview)
2. [SQLAlchemy ORM Configuration](#sqlalchemy-orm-configuration)
3. [Core Data Models](#core-data-models)
4. [Database Relationships](#database-relationships)
5. [Migration Management](#migration-management)
6. [Data Access Patterns](#data-access-patterns)
7. [Performance Optimization](#performance-optimization)
8. [Data Security and Encryption](#data-security-and-encryption)
9. [Backup and Recovery](#backup-and-recovery)
10. [Schema Evolution](#schema-evolution)

---

## Database Architecture Overview

### Database Technology Stack

**Development Environment:**
- **Database Engine:** SQLite 3.x
- **Location:** `{USER_DATA_DIR}/aegis_scanner.db`
- **Configuration:** WAL mode for better concurrency

**Production Environment:**
- **Database Engine:** PostgreSQL 15+
- **Connection Pooling:** SQLAlchemy connection pool
- **High Availability:** Master-slave replication (recommended)

### Database Configuration

```python
# config.py - Database configuration
class Config:
    # Development database (SQLite)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        f'sqlite:///{USER_DATA_DIR}/aegis_scanner.db'

    # SQLAlchemy configuration
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,        # Validate connections before use
        'pool_recycle': 300,          # Recycle connections every 5 minutes
        'pool_timeout': 20,           # Connection timeout
        'max_overflow': 10,           # Maximum overflow connections
        'echo': False                 # Set to True for SQL query logging
    }

class ProductionConfig(Config):
    # Production database (PostgreSQL)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://aegis:password@localhost/aegis_scanner_prod'

    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,              # Base connection pool size
        'max_overflow': 20,           # Additional connections beyond pool_size
        'pool_pre_ping': True,
        'pool_recycle': 3600,         # Recycle connections every hour
        'pool_timeout': 30
    }
```

### Database Initialization

```python
# app.py - Database initialization
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize database
    db.init_app(app)
    migrate.init_app(app, db)

    # Create tables in application context
    with app.app_context():
        db.create_all()

    return app
```

---

## SQLAlchemy ORM Configuration

### Base Model Class

```python
from datetime import datetime, timezone
from sqlalchemy.ext.declarative import declared_attr

class BaseModel(db.Model):
    """Base model class with common fields and methods"""

    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                          onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    @declared_attr
    def __tablename__(cls):
        """Generate table name from class name"""
        return cls.__name__.lower()

    def to_dict(self):
        """Convert model instance to dictionary"""
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, datetime):
                value = value.isoformat()
            result[column.name] = value
        return result

    def save(self):
        """Save instance to database"""
        db.session.add(self)
        db.session.commit()
        return self

    def delete(self):
        """Delete instance from database"""
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def get_by_id(cls, id):
        """Get instance by ID"""
        return cls.query.get(id)

    @classmethod
    def get_or_404(cls, id):
        """Get instance by ID or raise 404"""
        return cls.query.get_or_404(id)
```

---

## Core Data Models

### 1. User Model

```python
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, BaseModel):
    """User model with authentication and authorization"""

    __tablename__ = 'users'

    # Basic user information
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    # User profile
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    organization = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))

    # Account status
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    last_login = db.Column(db.DateTime)
    login_count = db.Column(db.Integer, default=0)

    # License management
    license_type = db.Column(db.String(20), default='basic', nullable=False)
    license_key = db.Column(db.String(255), unique=True)
    license_expires_at = db.Column(db.DateTime)
    license_validated_at = db.Column(db.DateTime)
    license_hardware_id = db.Column(db.String(100))

    # Two-factor authentication
    totp_secret = db.Column(db.String(32))
    is_2fa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    backup_codes = db.Column(db.JSON)  # Encrypted backup codes

    # User preferences
    preferences = db.Column(db.JSON, default=dict)  # User settings and preferences
    timezone = db.Column(db.String(50), default='UTC')

    # Relationships
    scan_results = db.relationship('ScanResult', backref='user', lazy='dynamic',
                                  cascade='all, delete-orphan')
    cloud_credentials = db.relationship('CloudCredential', backref='user', lazy='dynamic',
                                       cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic',
                                cascade='all, delete-orphan')

    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)

    def has_valid_license(self):
        """Check if user has valid license"""
        if not self.license_expires_at:
            return False
        return datetime.now(timezone.utc) < self.license_expires_at.replace(tzinfo=timezone.utc)

    def has_feature_access(self, feature_name):
        """Check if user has access to specific feature"""
        from licenses.license_manager import FEATURE_MATRIX
        features = FEATURE_MATRIX.get(self.license_type, {})
        return features.get(feature_name, False)

    def get_scan_limit(self):
        """Get daily scan limit for user"""
        from licenses.license_manager import FEATURE_MATRIX
        features = FEATURE_MATRIX.get(self.license_type, {})
        return features.get('max_scans_per_day', 0)

    def __repr__(self):
        return f'<User {self.username}>'
```

### 2. Scan Result Model

```python
class ScanResult(BaseModel):
    """Scan result storage and management"""

    __tablename__ = 'scan_results'

    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # Scan metadata
    scan_name = db.Column(db.String(100), nullable=False)
    provider = db.Column(db.String(20), nullable=False, index=True)  # aws, gcp, azure
    scan_type = db.Column(db.String(50), nullable=False)  # full, compute, storage, network, iam
    region = db.Column(db.String(50))  # Cloud region scanned

    # Scan timing
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = db.Column(db.DateTime)
    duration_seconds = db.Column(db.Integer)  # Calculated field

    # Scan status
    status = db.Column(db.String(20), default='pending', nullable=False, index=True)
    # Status values: pending, running, completed, failed, cancelled

    progress_percentage = db.Column(db.Integer, default=0)
    current_step = db.Column(db.String(100))
    error_message = db.Column(db.Text)

    # Scan configuration
    scan_config = db.Column(db.JSON)  # Configuration used for the scan
    credentials_used = db.Column(db.String(100))  # Reference to credential set

    # Results summary
    total_resources = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    info_count = db.Column(db.Integer, default=0)

    # Risk scoring
    risk_score = db.Column(db.Float)  # Calculated risk score 0-100
    compliance_score = db.Column(db.Float)  # Compliance score 0-100

    # Detailed results
    findings = db.Column(db.JSON)  # Array of security findings
    summary = db.Column(db.JSON)  # Scan summary and statistics
    raw_data = db.Column(db.Text)  # Raw scan data (compressed)

    # Export tracking
    export_formats = db.Column(db.JSON, default=list)  # List of exported formats
    last_exported = db.Column(db.DateTime)

    # Relationships
    findings_detail = db.relationship('Finding', backref='scan_result', lazy='dynamic',
                                    cascade='all, delete-orphan')

    @property
    def total_findings(self):
        """Total number of findings"""
        return (self.critical_count + self.high_count + self.medium_count +
                self.low_count + self.info_count)

    @property
    def is_completed(self):
        """Check if scan is completed"""
        return self.status in ['completed', 'failed', 'cancelled']

    def calculate_duration(self):
        """Calculate and update scan duration"""
        if self.started_at and self.completed_at:
            delta = self.completed_at - self.started_at
            self.duration_seconds = int(delta.total_seconds())

    def get_findings_by_severity(self, severity):
        """Get findings filtered by severity"""
        return self.findings_detail.filter_by(severity=severity).all()

    def __repr__(self):
        return f'<ScanResult {self.scan_name} - {self.provider}>'
```

### 3. Finding Model

```python
class Finding(BaseModel):
    """Individual security finding from scans"""

    __tablename__ = 'findings'

    # Foreign keys
    scan_result_id = db.Column(db.Integer, db.ForeignKey('scan_results.id'),
                              nullable=False, index=True)

    # Finding identification
    finding_id = db.Column(db.String(100), nullable=False, index=True)  # Unique within scan
    rule_id = db.Column(db.String(100), nullable=False, index=True)     # Security rule identifier

    # Finding details
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False, index=True)  # critical, high, medium, low, info

    # Resource information
    resource_type = db.Column(db.String(50), nullable=False)  # EC2, S3, IAM, etc.
    resource_id = db.Column(db.String(200), nullable=False)   # Resource identifier
    resource_name = db.Column(db.String(200))                 # Human-readable name
    resource_region = db.Column(db.String(50))                # Cloud region
    resource_tags = db.Column(db.JSON)                        # Resource tags

    # Finding status
    status = db.Column(db.String(20), default='open', nullable=False, index=True)
    # Status values: open, acknowledged, resolved, false_positive, suppressed

    # Risk assessment
    risk_score = db.Column(db.Float)                          # Individual risk score 0-10
    cvss_score = db.Column(db.Float)                          # CVSS score if applicable
    exposure_level = db.Column(db.String(20))                 # public, internal, private

    # Compliance mapping
    compliance_frameworks = db.Column(db.JSON)                # List of compliance standards
    compliance_controls = db.Column(db.JSON)                  # Specific control mappings

    # Remediation information
    remediation_guidance = db.Column(db.Text)                 # How to fix the issue
    remediation_effort = db.Column(db.String(20))             # low, medium, high
    remediation_priority = db.Column(db.Integer)              # 1-5 priority score

    # Additional metadata
    evidence = db.Column(db.JSON)                             # Supporting evidence
    references = db.Column(db.JSON)                           # External references
    first_seen = db.Column(db.DateTime, nullable=False)       # When first detected
    last_seen = db.Column(db.DateTime, nullable=False)        # Most recent detection

    @property
    def age_days(self):
        """Calculate age of finding in days"""
        return (datetime.now(timezone.utc) - self.first_seen.replace(tzinfo=timezone.utc)).days

    def mark_resolved(self, resolution_note=None):
        """Mark finding as resolved"""
        self.status = 'resolved'
        if resolution_note:
            if not self.evidence:
                self.evidence = {}
            self.evidence['resolution_note'] = resolution_note
            self.evidence['resolved_at'] = datetime.now(timezone.utc).isoformat()

    def __repr__(self):
        return f'<Finding {self.finding_id} - {self.severity}>'
```

### 4. Cloud Credential Model

```python
from cryptography.fernet import Fernet
import os

class CloudCredential(BaseModel):
    """Encrypted storage of cloud provider credentials"""

    __tablename__ = 'cloud_credentials'

    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # Credential metadata
    name = db.Column(db.String(100), nullable=False)          # User-defined name
    provider = db.Column(db.String(20), nullable=False, index=True)  # aws, gcp, azure
    description = db.Column(db.Text)                          # Optional description

    # Encrypted credential data
    encrypted_credentials = db.Column(db.Text, nullable=False)  # Encrypted JSON
    salt = db.Column(db.String(32), nullable=False)           # Encryption salt
    encryption_key_id = db.Column(db.String(100))             # Key management reference

    # Credential status
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    last_used = db.Column(db.DateTime)
    last_verified = db.Column(db.DateTime)
    verification_error = db.Column(db.Text)

    # Usage tracking
    usage_count = db.Column(db.Integer, default=0)
    last_scan_id = db.Column(db.Integer, db.ForeignKey('scan_results.id'))

    def encrypt_credentials(self, credentials_dict, encryption_key):
        """Encrypt and store credentials"""
        import json
        fernet = Fernet(encryption_key)
        credentials_json = json.dumps(credentials_dict)
        self.encrypted_credentials = fernet.encrypt(credentials_json.encode()).decode()

    def decrypt_credentials(self, encryption_key):
        """Decrypt and return credentials"""
        import json
        fernet = Fernet(encryption_key)
        decrypted_data = fernet.decrypt(self.encrypted_credentials.encode())
        return json.loads(decrypted_data.decode())

    def verify_credentials(self):
        """Verify credentials with cloud provider"""
        # Implementation depends on provider
        # This would call the appropriate cloud SDK to test credentials
        pass

    def mark_used(self, scan_id=None):
        """Mark credentials as used"""
        self.last_used = datetime.now(timezone.utc)
        self.usage_count += 1
        if scan_id:
            self.last_scan_id = scan_id

    def __repr__(self):
        return f'<CloudCredential {self.name} - {self.provider}>'
```

### 5. Audit Log Model

```python
class AuditLog(BaseModel):
    """Audit trail for user actions and system events"""

    __tablename__ = 'audit_logs'

    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)  # Nullable for system events

    # Event information
    event_type = db.Column(db.String(50), nullable=False, index=True)
    event_category = db.Column(db.String(30), nullable=False, index=True)  # auth, scan, admin, system
    event_description = db.Column(db.Text, nullable=False)

    # Request context
    ip_address = db.Column(db.String(45))                     # IPv4 or IPv6
    user_agent = db.Column(db.Text)                           # Browser/client info
    session_id = db.Column(db.String(100))                    # Session identifier
    request_id = db.Column(db.String(100))                    # Request correlation ID

    # Event details
    resource_type = db.Column(db.String(50))                  # Type of resource affected
    resource_id = db.Column(db.String(200))                   # ID of resource affected
    event_data = db.Column(db.JSON)                           # Additional event data

    # Event outcome
    status = db.Column(db.String(20), nullable=False, index=True)  # success, failure, error
    error_message = db.Column(db.Text)                        # Error details if applicable

    # Security classification
    risk_level = db.Column(db.String(20), default='low')      # low, medium, high, critical
    requires_investigation = db.Column(db.Boolean, default=False)

    @classmethod
    def log_event(cls, event_type, event_category, description, user_id=None,
                  status='success', **kwargs):
        """Create audit log entry"""
        log_entry = cls(
            user_id=user_id,
            event_type=event_type,
            event_category=event_category,
            event_description=description,
            status=status,
            **kwargs
        )
        log_entry.save()
        return log_entry

    @classmethod
    def log_security_event(cls, event_type, description, user_id=None, risk_level='medium'):
        """Log security-related events"""
        return cls.log_event(
            event_type=event_type,
            event_category='security',
            event_description=description,
            user_id=user_id,
            risk_level=risk_level,
            requires_investigation=(risk_level in ['high', 'critical'])
        )

    def __repr__(self):
        return f'<AuditLog {self.event_type} - {self.status}>'
```

### 6. System Configuration Model

```python
class SystemConfiguration(BaseModel):
    """System-wide configuration settings"""

    __tablename__ = 'system_configurations'

    # Configuration identification
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    category = db.Column(db.String(50), nullable=False, index=True)

    # Configuration value
    value = db.Column(db.Text)                                # JSON or string value
    data_type = db.Column(db.String(20), nullable=False)      # string, integer, boolean, json

    # Configuration metadata
    description = db.Column(db.Text)
    default_value = db.Column(db.Text)
    is_sensitive = db.Column(db.Boolean, default=False)       # Encrypt sensitive values
    is_readonly = db.Column(db.Boolean, default=False)        # Prevent modification

    # Validation
    validation_regex = db.Column(db.String(200))              # Validation pattern
    allowed_values = db.Column(db.JSON)                       # List of allowed values
    min_value = db.Column(db.Float)                           # Minimum numeric value
    max_value = db.Column(db.Float)                           # Maximum numeric value

    @classmethod
    def get_value(cls, key, default=None):
        """Get configuration value by key"""
        config = cls.query.filter_by(key=key).first()
        if not config:
            return default

        if config.data_type == 'boolean':
            return config.value.lower() == 'true'
        elif config.data_type == 'integer':
            return int(config.value)
        elif config.data_type == 'json':
            import json
            return json.loads(config.value)
        else:
            return config.value

    @classmethod
    def set_value(cls, key, value, category='general'):
        """Set configuration value"""
        config = cls.query.filter_by(key=key).first()
        if not config:
            config = cls(key=key, category=category)

        config.value = str(value)
        config.save()
        return config

    def __repr__(self):
        return f'<SystemConfiguration {self.key}>'
```

---

## Database Relationships

### Entity Relationship Diagram

```
Users (1) ←→ (*) ScanResults
Users (1) ←→ (*) CloudCredentials
Users (1) ←→ (*) AuditLogs

ScanResults (1) ←→ (*) Findings
ScanResults (1) ←→ (*) CloudCredentials (last_scan_id)

SystemConfigurations (standalone)
```

### Relationship Definitions

```python
# User relationships
class User(BaseModel):
    scan_results = db.relationship('ScanResult', backref='user', lazy='dynamic',
                                  cascade='all, delete-orphan')
    cloud_credentials = db.relationship('CloudCredential', backref='user', lazy='dynamic',
                                       cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic',
                                cascade='all, delete-orphan')

# ScanResult relationships
class ScanResult(BaseModel):
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    findings_detail = db.relationship('Finding', backref='scan_result', lazy='dynamic',
                                    cascade='all, delete-orphan')

# Finding relationships
class Finding(BaseModel):
    scan_result_id = db.Column(db.Integer, db.ForeignKey('scan_results.id'), nullable=False)

# CloudCredential relationships
class CloudCredential(BaseModel):
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    last_scan_id = db.Column(db.Integer, db.ForeignKey('scan_results.id'))
    last_scan = db.relationship('ScanResult', foreign_keys=[last_scan_id])
```

### Foreign Key Constraints

```sql
-- Foreign key constraints (automatically generated by SQLAlchemy)
ALTER TABLE scan_results ADD CONSTRAINT fk_scan_results_user_id
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE findings ADD CONSTRAINT fk_findings_scan_result_id
    FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE;

ALTER TABLE cloud_credentials ADD CONSTRAINT fk_cloud_credentials_user_id
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE audit_logs ADD CONSTRAINT fk_audit_logs_user_id
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;
```

---

## Migration Management

### Flask-Migrate Setup

```python
# app.py - Migration initialization
from flask_migrate import Migrate

migrate = Migrate()

def create_app():
    app = Flask(__name__)

    # Initialize migration
    migrate.init_app(app, db)

    return app
```

### Migration Commands

```bash
# Initialize migration repository (one-time setup)
flask db init

# Create new migration after model changes
flask db migrate -m "Add findings table with detailed security data"

# Review generated migration
cat migrations/versions/001_add_findings_table.py

# Apply migration to database
flask db upgrade

# Rollback migration if needed
flask db downgrade

# Show migration history
flask db history

# Show current migration version
flask db current
```

### Sample Migration File

```python
"""Add findings table with detailed security data

Revision ID: 001_add_findings_table
Revises:
Create Date: 2024-09-29 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '001_add_findings_table'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Create findings table
    op.create_table('findings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('scan_result_id', sa.Integer(), nullable=False),
        sa.Column('finding_id', sa.String(length=100), nullable=False),
        sa.Column('rule_id', sa.String(length=100), nullable=False),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('resource_type', sa.String(length=50), nullable=False),
        sa.Column('resource_id', sa.String(length=200), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('risk_score', sa.Float()),
        sa.Column('remediation_guidance', sa.Text()),
        sa.Column('evidence', sa.JSON()),
        sa.ForeignKeyConstraint(['scan_result_id'], ['scan_results.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes
    op.create_index(op.f('ix_findings_scan_result_id'), 'findings', ['scan_result_id'], unique=False)
    op.create_index(op.f('ix_findings_severity'), 'findings', ['severity'], unique=False)
    op.create_index(op.f('ix_findings_status'), 'findings', ['status'], unique=False)

def downgrade():
    # Drop indexes
    op.drop_index(op.f('ix_findings_status'), table_name='findings')
    op.drop_index(op.f('ix_findings_severity'), table_name='findings')
    op.drop_index(op.f('ix_findings_scan_result_id'), table_name='findings')

    # Drop table
    op.drop_table('findings')
```

### Data Migration Utilities

```python
class DataMigration:
    """Utilities for data migration and transformation"""

    @staticmethod
    def migrate_user_schema():
        """Migrate user schema for license management updates"""
        try:
            # Add new columns if they don't exist
            if not hasattr(User, 'license_hardware_id'):
                db.engine.execute('ALTER TABLE users ADD COLUMN license_hardware_id VARCHAR(100)')

            # Update existing data
            users_without_license_type = User.query.filter_by(license_type=None).all()
            for user in users_without_license_type:
                user.license_type = 'basic'
                db.session.add(user)

            db.session.commit()
            logger.info("User schema migration completed successfully")

        except Exception as e:
            db.session.rollback()
            logger.error(f"User schema migration failed: {e}")
            raise

    @staticmethod
    def cleanup_orphaned_data():
        """Clean up orphaned records and inconsistent data"""
        # Remove findings without parent scan results
        orphaned_findings = db.session.query(Finding).filter(
            ~Finding.scan_result_id.in_(
                db.session.query(ScanResult.id)
            )
        ).delete(synchronize_session=False)

        logger.info(f"Cleaned up {orphaned_findings} orphaned findings")
        db.session.commit()
```

---

## Data Access Patterns

### Repository Pattern Implementation

```python
class BaseRepository:
    """Base repository with common database operations"""

    def __init__(self, model_class):
        self.model = model_class

    def get_by_id(self, id):
        """Get record by ID"""
        return self.model.query.get(id)

    def get_all(self, **filters):
        """Get all records with optional filters"""
        query = self.model.query
        for key, value in filters.items():
            if hasattr(self.model, key):
                query = query.filter(getattr(self.model, key) == value)
        return query.all()

    def create(self, **kwargs):
        """Create new record"""
        instance = self.model(**kwargs)
        db.session.add(instance)
        db.session.commit()
        return instance

    def update(self, id, **kwargs):
        """Update existing record"""
        instance = self.get_by_id(id)
        if instance:
            for key, value in kwargs.items():
                if hasattr(instance, key):
                    setattr(instance, key, value)
            db.session.commit()
        return instance

    def delete(self, id):
        """Delete record by ID"""
        instance = self.get_by_id(id)
        if instance:
            db.session.delete(instance)
            db.session.commit()
            return True
        return False

class ScanResultRepository(BaseRepository):
    """Repository for scan result operations"""

    def __init__(self):
        super().__init__(ScanResult)

    def get_by_user(self, user_id, limit=None):
        """Get scan results for user"""
        query = self.model.query.filter_by(user_id=user_id).order_by(
            self.model.created_at.desc()
        )
        if limit:
            query = query.limit(limit)
        return query.all()

    def get_recent_scans(self, days=30):
        """Get recent scans within specified days"""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        return self.model.query.filter(
            self.model.created_at >= cutoff_date
        ).order_by(self.model.created_at.desc()).all()

    def get_by_provider(self, provider, user_id=None):
        """Get scans by cloud provider"""
        query = self.model.query.filter_by(provider=provider)
        if user_id:
            query = query.filter_by(user_id=user_id)
        return query.all()

    def get_scan_statistics(self, user_id=None):
        """Get scan statistics"""
        query = self.model.query
        if user_id:
            query = query.filter_by(user_id=user_id)

        return {
            'total_scans': query.count(),
            'completed_scans': query.filter_by(status='completed').count(),
            'failed_scans': query.filter_by(status='failed').count(),
            'avg_duration': query.with_entities(
                func.avg(self.model.duration_seconds)
            ).scalar() or 0
        }
```

### Query Optimization Patterns

```python
class OptimizedQueries:
    """Optimized database queries for common operations"""

    @staticmethod
    def get_user_dashboard_data(user_id):
        """Get all dashboard data in minimal queries"""
        # Single query for user with related data
        user = User.query.options(
            db.selectinload(User.scan_results).selectinload(ScanResult.findings_detail)
        ).get(user_id)

        # Aggregate statistics query
        scan_stats = db.session.query(
            ScanResult.provider,
            func.count(ScanResult.id).label('count'),
            func.sum(ScanResult.critical_count).label('critical'),
            func.sum(ScanResult.high_count).label('high'),
            func.sum(ScanResult.medium_count).label('medium'),
            func.sum(ScanResult.low_count).label('low')
        ).filter_by(user_id=user_id, status='completed').group_by(
            ScanResult.provider
        ).all()

        return user, scan_stats

    @staticmethod
    def get_finding_trends(user_id, days=30):
        """Get finding trends over time"""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        trends = db.session.query(
            func.date(ScanResult.completed_at).label('scan_date'),
            func.sum(ScanResult.critical_count).label('critical'),
            func.sum(ScanResult.high_count).label('high'),
            func.sum(ScanResult.medium_count).label('medium'),
            func.sum(ScanResult.low_count).label('low')
        ).filter(
            ScanResult.user_id == user_id,
            ScanResult.completed_at >= cutoff_date,
            ScanResult.status == 'completed'
        ).group_by(
            func.date(ScanResult.completed_at)
        ).order_by('scan_date').all()

        return trends

    @staticmethod
    def get_top_findings_by_resource_type(user_id, limit=10):
        """Get most common findings by resource type"""
        findings = db.session.query(
            Finding.resource_type,
            Finding.rule_id,
            Finding.title,
            func.count(Finding.id).label('occurrence_count')
        ).join(ScanResult).filter(
            ScanResult.user_id == user_id,
            Finding.status == 'open'
        ).group_by(
            Finding.resource_type,
            Finding.rule_id,
            Finding.title
        ).order_by(
            func.count(Finding.id).desc()
        ).limit(limit).all()

        return findings
```

---

## Performance Optimization

### Database Indexing Strategy

```sql
-- Primary indexes (automatically created)
CREATE INDEX ix_users_username ON users(username);
CREATE INDEX ix_users_email ON users(email);
CREATE INDEX ix_users_license_type ON users(license_type);

-- Scan result indexes
CREATE INDEX ix_scan_results_user_id ON scan_results(user_id);
CREATE INDEX ix_scan_results_provider ON scan_results(provider);
CREATE INDEX ix_scan_results_status ON scan_results(status);
CREATE INDEX ix_scan_results_created_at ON scan_results(created_at);

-- Finding indexes
CREATE INDEX ix_findings_scan_result_id ON findings(scan_result_id);
CREATE INDEX ix_findings_severity ON findings(severity);
CREATE INDEX ix_findings_status ON findings(status);
CREATE INDEX ix_findings_rule_id ON findings(rule_id);

-- Composite indexes for common queries
CREATE INDEX ix_scan_results_user_status ON scan_results(user_id, status);
CREATE INDEX ix_findings_scan_severity ON findings(scan_result_id, severity);

-- Audit log indexes
CREATE INDEX ix_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX ix_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX ix_audit_logs_created_at ON audit_logs(created_at);
```

### Connection Pool Configuration

```python
# Production database configuration
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_size': 20,                    # Base pool size
    'max_overflow': 30,                 # Additional connections
    'pool_pre_ping': True,              # Validate connections
    'pool_recycle': 3600,               # Recycle every hour
    'pool_timeout': 30,                 # Connection timeout
    'echo': False,                      # Disable SQL echo in production
    'connect_args': {
        'sslmode': 'require',           # Require SSL for PostgreSQL
        'connect_timeout': 10,          # Connection timeout
        'application_name': 'aegis_scanner'
    }
}
```

### Query Performance Monitoring

```python
class QueryPerformanceMonitor:
    """Monitor and log slow database queries"""

    def __init__(self, threshold_seconds=1.0):
        self.threshold = threshold_seconds

    def monitor_query(self, query_func):
        """Decorator to monitor query performance"""
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = query_func(*args, **kwargs)
                duration = time.time() - start_time

                if duration > self.threshold:
                    logger.warning(f"Slow query detected: {query_func.__name__} "
                                 f"took {duration:.2f}s")

                return result
            except Exception as e:
                duration = time.time() - start_time
                logger.error(f"Query failed: {query_func.__name__} "
                           f"after {duration:.2f}s: {e}")
                raise
        return wrapper
```

---

## Data Security and Encryption

### Sensitive Data Encryption

```python
from cryptography.fernet import Fernet
import os
import base64

class DataEncryption:
    """Handle encryption of sensitive database fields"""

    def __init__(self):
        self.encryption_key = self._get_encryption_key()
        self.fernet = Fernet(self.encryption_key)

    def _get_encryption_key(self):
        """Get or generate encryption key"""
        key = os.environ.get('DATA_ENCRYPTION_KEY')
        if not key:
            # Generate and save key (in production, use proper key management)
            key = Fernet.generate_key()
            logger.warning("Generated new encryption key - store securely!")

        if isinstance(key, str):
            key = key.encode()

        return key

    def encrypt_field(self, value):
        """Encrypt sensitive field value"""
        if not value:
            return None

        if isinstance(value, str):
            value = value.encode()

        return self.fernet.encrypt(value).decode()

    def decrypt_field(self, encrypted_value):
        """Decrypt sensitive field value"""
        if not encrypted_value:
            return None

        if isinstance(encrypted_value, str):
            encrypted_value = encrypted_value.encode()

        return self.fernet.decrypt(encrypted_value).decode()

# Usage in models
class SecureCloudCredential(CloudCredential):
    """Cloud credential with field-level encryption"""

    def set_credentials(self, credentials_dict):
        """Set encrypted credentials"""
        encryption = DataEncryption()
        import json
        credentials_json = json.dumps(credentials_dict)
        self.encrypted_credentials = encryption.encrypt_field(credentials_json)

    def get_credentials(self):
        """Get decrypted credentials"""
        encryption = DataEncryption()
        credentials_json = encryption.decrypt_field(self.encrypted_credentials)
        import json
        return json.loads(credentials_json)
```

### Database Security Configuration

```python
# Production security settings
SQLALCHEMY_ENGINE_OPTIONS = {
    # ... other options ...
    'connect_args': {
        'sslmode': 'require',                    # Require SSL
        'sslcert': '/path/to/client-cert.pem',   # Client certificate
        'sslkey': '/path/to/client-key.pem',     # Client key
        'sslrootcert': '/path/to/ca-cert.pem',   # CA certificate
        'application_name': 'aegis_scanner',     # Application identification
        'connect_timeout': 10,                   # Connection timeout
    }
}

# Connection string with SSL
DATABASE_URL = "postgresql://username:password@hostname:5432/database?sslmode=require"
```

---

## Backup and Recovery

### Automated Backup Strategy

```python
class DatabaseBackup:
    """Database backup and recovery utilities"""

    def __init__(self):
        self.backup_dir = os.path.join(USER_DATA_DIR, 'backups')
        os.makedirs(self.backup_dir, exist_ok=True)

    def create_backup(self, backup_type='full'):
        """Create database backup"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"aegis_scanner_{backup_type}_{timestamp}"

        if backup_type == 'full':
            return self._create_full_backup(backup_filename)
        elif backup_type == 'data_only':
            return self._create_data_backup(backup_filename)
        elif backup_type == 'schema_only':
            return self._create_schema_backup(backup_filename)

    def _create_full_backup(self, filename):
        """Create full database backup (schema + data)"""
        if 'sqlite' in current_app.config['SQLALCHEMY_DATABASE_URI']:
            return self._backup_sqlite(filename)
        else:
            return self._backup_postgresql(filename)

    def _backup_sqlite(self, filename):
        """Backup SQLite database"""
        import shutil
        source_db = current_app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        backup_path = os.path.join(self.backup_dir, f"{filename}.db")
        shutil.copy2(source_db, backup_path)
        return backup_path

    def _backup_postgresql(self, filename):
        """Backup PostgreSQL database using pg_dump"""
        import subprocess
        backup_path = os.path.join(self.backup_dir, f"{filename}.sql")

        # Extract database connection details
        db_url = current_app.config['SQLALCHEMY_DATABASE_URI']
        # Parse connection string and run pg_dump

        cmd = [
            'pg_dump',
            '--no-password',
            '--format=custom',
            '--compress=9',
            '--file=' + backup_path,
            db_url
        ]

        subprocess.run(cmd, check=True)
        return backup_path

    def schedule_backups(self):
        """Schedule automated backups"""
        from apscheduler.schedulers.background import BackgroundScheduler

        scheduler = BackgroundScheduler()

        # Daily full backup at 2 AM
        scheduler.add_job(
            func=self.create_backup,
            args=['full'],
            trigger='cron',
            hour=2,
            minute=0,
            id='daily_backup'
        )

        # Weekly data-only backup on Sundays
        scheduler.add_job(
            func=self.create_backup,
            args=['data_only'],
            trigger='cron',
            day_of_week='sun',
            hour=3,
            minute=0,
            id='weekly_backup'
        )

        scheduler.start()
```

### Recovery Procedures

```python
class DatabaseRecovery:
    """Database recovery and restoration utilities"""

    def restore_from_backup(self, backup_path, recovery_type='full'):
        """Restore database from backup"""
        if not os.path.exists(backup_path):
            raise FileNotFoundError(f"Backup file not found: {backup_path}")

        if recovery_type == 'full':
            return self._restore_full_backup(backup_path)
        elif recovery_type == 'data_only':
            return self._restore_data_only(backup_path)

    def _restore_full_backup(self, backup_path):
        """Restore full database backup"""
        # Stop application
        # Drop existing database
        # Restore from backup
        # Restart application
        pass

    def verify_backup_integrity(self, backup_path):
        """Verify backup file integrity"""
        try:
            # Attempt to read backup file
            # Verify structure and data consistency
            return True
        except Exception as e:
            logger.error(f"Backup integrity check failed: {e}")
            return False
```

---

## Schema Evolution

### Version Management

```python
class SchemaVersion:
    """Track and manage database schema versions"""

    @staticmethod
    def get_current_version():
        """Get current schema version"""
        try:
            config = SystemConfiguration.get_value('schema_version', '1.0.0')
            return config
        except:
            return '1.0.0'

    @staticmethod
    def set_version(version):
        """Set schema version"""
        SystemConfiguration.set_value('schema_version', version, 'system')

    @staticmethod
    def is_migration_required():
        """Check if migration is required"""
        current_version = SchemaVersion.get_current_version()
        target_version = '2.0.0'  # Update as needed
        return current_version != target_version
```

### Migration Best Practices

```python
# Migration guidelines and best practices

"""
1. Always backup before migration
2. Test migrations on copy of production data
3. Use transactions for atomic migrations
4. Include rollback procedures
5. Validate data integrity after migration
6. Update schema version after successful migration
7. Monitor application performance post-migration
8. Document all schema changes
"""

class MigrationManager:
    """Manage database schema migrations"""

    def execute_migration(self, migration_script):
        """Execute migration with proper error handling"""
        # Create backup
        backup_manager = DatabaseBackup()
        backup_path = backup_manager.create_backup('pre_migration')

        try:
            # Begin transaction
            with db.session.begin():
                # Execute migration
                migration_script()

                # Validate data integrity
                self.validate_post_migration()

                # Update schema version
                SchemaVersion.set_version('2.0.0')

            logger.info("Migration completed successfully")
            return True

        except Exception as e:
            logger.error(f"Migration failed: {e}")
            # Optionally restore from backup
            return False

    def validate_post_migration(self):
        """Validate database state after migration"""
        # Check foreign key constraints
        # Verify data consistency
        # Test critical queries
        pass
```

---

**End of Part 4**

**Next:** Part 5 will cover API Documentation and Endpoints, including RESTful API design, authentication, request/response formats, and integration examples.