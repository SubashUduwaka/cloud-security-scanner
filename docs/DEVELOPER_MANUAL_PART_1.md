# Aegis Cloud Scanner - Developer Manual
## Part 1: System Architecture and Overview

**Document Version:** 1.0
**Last Updated:** September 2024
**Target Audience:** Software Developers, DevOps Engineers, System Architects
**Classification:** Internal Development Documentation

---

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [System Architecture Overview](#system-architecture-overview)
3. [Technology Stack](#technology-stack)
4. [Core Components](#core-components)
5. [Application Architecture Patterns](#application-architecture-patterns)
6. [Data Flow Architecture](#data-flow-architecture)
7. [Security Architecture](#security-architecture)
8. [Scalability Design](#scalability-design)
9. [Integration Architecture](#integration-architecture)
10. [Development Principles](#development-principles)

---

## Executive Summary

Aegis Cloud Scanner is an enterprise-grade, multi-cloud security assessment platform built using Flask and Python. The application provides comprehensive security scanning capabilities across AWS, Google Cloud Platform (GCP), and Microsoft Azure environments. This developer manual serves as the authoritative technical reference for developers working on the Aegis Cloud Scanner codebase.

### Key Technical Characteristics
- **Architecture Type:** Modular Monolith with Microservice-Ready Components
- **Framework:** Flask 3.0.0 with SQLAlchemy ORM
- **Language:** Python 3.13+ with strict type hints
- **Database:** SQLite (development) / PostgreSQL (production)
- **Deployment:** Docker containers with Gunicorn WSGI server
- **Cloud Integration:** Native SDK integration for AWS, GCP, and Azure
- **License Management:** Custom cryptographic license validation system

---

## System Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Presentation Layer                       │
├─────────────────────────────────────────────────────────────────┤
│  Web UI (Templates/Static)  │  RESTful API  │  Admin Interface   │
├─────────────────────────────────────────────────────────────────┤
│                        Application Layer                        │
├─────────────────────────────────────────────────────────────────┤
│ Authentication │ Authorization │ Rate Limiting │ Input Validation │
├─────────────────────────────────────────────────────────────────┤
│                         Business Logic                          │
├─────────────────────────────────────────────────────────────────┤
│  Cloud Scanners  │  License Manager  │  Report Generator  │     │
│   - AWS Scanner  │  - Validation     │  - PDF Reports     │     │
│   - GCP Scanner  │  - Enforcement    │  - Excel Export    │     │
│   - Azure Scanner│  - Monitoring     │  - JSON Export     │     │
├─────────────────────────────────────────────────────────────────┤
│                         Data Layer                              │
├─────────────────────────────────────────────────────────────────┤
│  SQLAlchemy ORM  │  File Storage  │  Session Management  │      │
│  - User Models   │  - Reports     │  - Redis Cache      │      │
│  - Scan Results  │  - Logs        │  - Background Jobs   │      │
│  - License Data  │  - Exports     │  - Task Scheduler    │      │
├─────────────────────────────────────────────────────────────────┤
│                      Infrastructure Layer                       │
├─────────────────────────────────────────────────────────────────┤
│   Database      │   File System   │   External APIs    │        │
│ SQLite/PostgreSQL │  Local Storage │  Cloud Provider APIs │     │
└─────────────────────────────────────────────────────────────────┘
```

### Component Interaction Model

The application follows a clear separation of concerns with well-defined interfaces between components:

1. **Request Flow:** HTTP Request → Flask Routes → Business Logic → Data Layer → Response
2. **Authentication Flow:** Request → License Middleware → User Authentication → Authorization → Route Handler
3. **Scanning Flow:** User Request → Scanner Selection → Cloud API Integration → Result Processing → Report Generation
4. **Background Processing:** Scheduled Jobs → Task Executor → Database Operations → Notification System

---

## Technology Stack

### Core Framework Stack
```python
# Primary Framework
Flask==3.0.0                    # Web application framework
Flask-SQLAlchemy==3.1.1         # ORM integration
Flask-Migrate==4.0.5            # Database migrations
Flask-Login==0.6.3              # User session management
Flask-Bcrypt==1.0.1             # Password hashing
Flask-WTF==1.2.1                # Form handling and CSRF protection
```

### Cloud Provider SDKs
```python
# AWS Integration
boto3==1.34.0                   # AWS SDK for Python

# Google Cloud Platform
google-cloud-storage==2.10.0    # GCP Storage API
google-api-python-client==2.108.0 # GCP API Client
google-cloud-resource-manager==1.10.4 # GCP Resource Management
google-cloud-compute==1.14.1    # GCP Compute Engine API
google-cloud-kms==2.19.2        # GCP Key Management Service

# Microsoft Azure
azure-identity==1.15.0          # Azure Authentication
azure-mgmt-resource==23.0.1     # Azure Resource Management
azure-mgmt-storage==21.0.0      # Azure Storage Management
azure-mgmt-compute==30.0.0      # Azure Compute Management
azure-mgmt-network==25.0.0      # Azure Network Management
azure-mgmt-security==6.0.0      # Azure Security Center
```

### Security and Cryptography
```python
cryptography                    # Core cryptographic operations
PyJWT==2.8.0                   # JSON Web Token implementation
bcrypt==4.1.2                  # Password hashing algorithm
pyotp==2.9.0                   # Time-based OTP for 2FA
qrcode==7.4.2                  # QR code generation for 2FA setup
```

### Production Infrastructure
```python
gunicorn==21.2.0               # WSGI HTTP Server
supervisor==4.2.5              # Process control system
psycopg2-binary==2.9.10        # PostgreSQL adapter
redis==5.0.1                   # Caching and session storage
celery==5.3.4                  # Distributed task queue
APScheduler==3.10.4            # Advanced task scheduling
```

---

## Core Components

### 1. Application Entry Point (`app.py`)
**File:** `app.py` (386KB, 10,000+ lines)
**Responsibility:** Main application factory, route definitions, middleware configuration

```python
# Key responsibilities:
- Flask application initialization
- Database configuration and migration
- Route registration and URL mapping
- Middleware stack configuration
- Background task scheduling
- License validation integration
- Structured logging setup
```

### 2. License Management System
**Directory:** `licenses/`
**Key Files:**
- `license_middleware.py` - Request interception and validation
- `license_manager.py` - Core license business logic
- `license_validator.py` - Cryptographic validation

```python
# License architecture features:
- RSA-2048 cryptographic signatures
- Time-based license expiration
- Feature-based access control (Pro/Basic tiers)
- Hardware fingerprinting for binding
- Offline validation capabilities
- License renewal and upgrade paths
```

### 3. Cloud Scanner Modules
**Directory:** `scanners/`
**Structure:**
```
scanners/
├── aws/
│   ├── aws_scanner.py          # AWS-specific scanning logic
│   └── __init__.py
├── azure/
│   ├── azure_scanner.py        # Azure-specific scanning logic
│   └── __init__.py
└── gcp/
    ├── gcp_scanner.py          # GCP-specific scanning logic
    └── __init__.py
```

### 4. Utility and Tool Modules
**Directory:** `utils/`
**Directory:** `tools/`
**Key Components:**
- Database utilities and helpers
- Authentication and authorization helpers
- Report generation engines
- Logging and monitoring tools
- Configuration management

---

## Application Architecture Patterns

### 1. Model-View-Controller (MVC) Pattern
```python
# Model Layer (SQLAlchemy Models)
class User(db.Model):
    """User entity with authentication and license management"""

class ScanResult(db.Model):
    """Scan result storage with cloud provider abstraction"""

# View Layer (Jinja2 Templates)
templates/
├── base.html                   # Base template with common layout
├── dashboard.html              # Main dashboard interface
├── scan_results.html           # Scan result display
└── admin/                      # Administrative interfaces

# Controller Layer (Flask Routes)
@app.route('/scan/<provider>')
def initiate_scan(provider):
    """Route controller for cloud scanning operations"""
```

### 2. Repository Pattern
```python
class ScanResultRepository:
    """Data access abstraction for scan results"""

    def get_by_user(self, user_id: int) -> List[ScanResult]:
        """Retrieve scan results for specific user"""

    def save_scan_result(self, result: dict) -> ScanResult:
        """Persist scan result to database"""
```

### 3. Factory Pattern
```python
class CloudScannerFactory:
    """Factory for creating provider-specific scanners"""

    @staticmethod
    def create_scanner(provider: str) -> BaseCloudScanner:
        if provider == 'aws':
            return AWSScanner()
        elif provider == 'gcp':
            return GCPScanner()
        elif provider == 'azure':
            return AzureScanner()
```

### 4. Middleware Pattern
```python
# License validation middleware
@app.before_request
def validate_license():
    """Intercept all requests for license validation"""

# Authentication middleware
@app.before_request
def require_authentication():
    """Enforce authentication on protected routes"""
```

---

## Data Flow Architecture

### 1. User Authentication Flow
```
User Login Request
    ↓
License Validation Middleware
    ↓
User Credential Verification
    ↓
Session Creation
    ↓
Feature Access Authorization
    ↓
Dashboard Redirect
```

### 2. Cloud Scanning Flow
```
Scan Request Initiation
    ↓
Provider Selection & Validation
    ↓
Credential Verification
    ↓
Scanner Factory Instantiation
    ↓
Cloud API Authentication
    ↓
Resource Discovery & Enumeration
    ↓
Security Policy Assessment
    ↓
Vulnerability Detection
    ↓
Result Aggregation & Scoring
    ↓
Database Persistence
    ↓
Report Generation
    ↓
User Notification
```

### 3. License Validation Flow
```
HTTP Request
    ↓
License Middleware Interception
    ↓
License File Validation
    ↓
Cryptographic Signature Verification
    ↓
Expiration Date Check
    ↓
Feature Access Verification
    ↓
Hardware Binding Validation
    ↓
Request Processing Authorization
```

---

## Security Architecture

### 1. Authentication Mechanisms
- **Primary:** Flask-Login session management
- **Secondary:** JWT token-based API authentication
- **Multi-Factor:** TOTP-based 2FA with QR code enrollment
- **Password Security:** Bcrypt hashing with configurable rounds

### 2. Authorization Model
```python
# Role-based access control
ADMIN_ROLE = 'admin'
PRO_USER_ROLE = 'pro_user'
BASIC_USER_ROLE = 'basic_user'

# Feature-based permissions
FEATURES = {
    'multi_cloud_scan': ['pro_user', 'admin'],
    'advanced_reporting': ['pro_user', 'admin'],
    'api_access': ['pro_user', 'admin'],
    'user_management': ['admin']
}
```

### 3. Input Validation and Sanitization
- **Framework:** Cerberus schema validation
- **HTML Sanitization:** Bleach library for XSS prevention
- **SQL Injection Protection:** SQLAlchemy ORM with parameterized queries
- **CSRF Protection:** Flask-WTF integration

### 4. Cryptographic Implementation
```python
# License signature validation
RSA_KEY_SIZE = 2048
SIGNATURE_ALGORITHM = 'SHA256withRSA'
LICENSE_ENCRYPTION = 'AES-256-GCM'

# Session security
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
```

---

## Scalability Design

### 1. Database Scalability
- **Connection Pooling:** SQLAlchemy connection pool management
- **Query Optimization:** Indexed queries with selective loading
- **Migration Strategy:** Flask-Migrate for schema versioning
- **Production Database:** PostgreSQL with read replicas

### 2. Application Scalability
- **WSGI Server:** Gunicorn with worker process scaling
- **Load Balancing:** Nginx reverse proxy configuration
- **Session Storage:** Redis-based session management
- **Background Tasks:** Celery distributed task queue

### 3. Caching Strategy
```python
# Multi-level caching
- Application Cache: Flask-Caching with Redis backend
- Query Cache: SQLAlchemy query result caching
- Static Content: Nginx static file serving
- CDN Integration: CloudFlare for global content delivery
```

### 4. Monitoring and Observability
```python
# Structured logging
- Request/Response logging with correlation IDs
- Performance metrics collection
- Error tracking and alerting
- Health check endpoints for load balancers
```

---

## Integration Architecture

### 1. Cloud Provider Integration
Each cloud provider integration follows a standardized interface:

```python
class BaseCloudScanner(ABC):
    """Abstract base class for cloud scanners"""

    @abstractmethod
    def authenticate(self, credentials: dict) -> bool:
        """Authenticate with cloud provider"""

    @abstractmethod
    def scan_resources(self) -> List[dict]:
        """Scan cloud resources for security issues"""

    @abstractmethod
    def generate_report(self, results: List[dict]) -> dict:
        """Generate standardized security report"""
```

### 2. External API Integration
- **AI Integration:** Google Generative AI for intelligent threat analysis
- **Notification Services:** Email/SMS notification systems
- **Third-party Tools:** Integration hooks for SIEM and monitoring tools

### 3. Data Export Integration
- **PDF Reports:** ReportLab for professional report generation
- **Excel Export:** OpenPyXL for spreadsheet generation
- **JSON/CSV:** Native Python serialization for data interchange

---

## Development Principles

### 1. Code Quality Standards
- **Type Hints:** Mandatory type annotations for all functions
- **Documentation:** Comprehensive docstrings following Google style
- **Testing:** Minimum 80% code coverage requirement
- **Linting:** Black, isort, and flake8 for code formatting

### 2. Security-First Development
- **Secure by Default:** All configurations default to secure settings
- **Input Validation:** Validate and sanitize all user inputs
- **Least Privilege:** Minimal permission grants for all operations
- **Regular Updates:** Automated dependency vulnerability scanning

### 3. Performance Optimization
- **Database Optimization:** Efficient query patterns and indexing
- **Memory Management:** Proper resource cleanup and garbage collection
- **Asynchronous Processing:** Background tasks for long-running operations
- **Caching Strategy:** Intelligent caching at multiple application layers

### 4. Maintainability
- **Modular Design:** Clear separation of concerns and responsibilities
- **Configuration Management:** Environment-based configuration
- **Logging and Monitoring:** Comprehensive observability implementation
- **Documentation:** Self-documenting code with comprehensive external docs

---

**End of Part 1**

**Next:** Part 2 will cover Development Environment Setup including local development configuration, dependency management, database setup, and debugging tools.