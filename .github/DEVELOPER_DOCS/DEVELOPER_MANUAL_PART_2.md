# Aegis Cloud Scanner - Developer Manual
## Part 2: Development Environment Setup

**Document Version:** 1.0
**Last Updated:** September 2024
**Target Audience:** Software Developers, DevOps Engineers
**Classification:** Internal Development Documentation

---

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [System Requirements](#system-requirements)
3. [Development Environment Setup](#development-environment-setup)
4. [Database Configuration](#database-configuration)
5. [Cloud Provider Setup](#cloud-provider-setup)
6. [IDE and Development Tools](#ide-and-development-tools)
7. [Environment Variables](#environment-variables)
8. [Running the Application](#running-the-application)
9. [Development Workflow](#development-workflow)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software
Before setting up the Aegis Cloud Scanner development environment, ensure you have the following software installed:

1. **Python 3.13+**
   - Download from [python.org](https://www.python.org/downloads/)
   - Verify installation: `python --version`
   - Ensure pip is included: `pip --version`

2. **Git**
   - Download from [git-scm.com](https://git-scm.com/)
   - Verify installation: `git --version`

3. **Docker (Optional but Recommended)**
   - Download from [docker.com](https://www.docker.com/)
   - Used for containerized development and testing
   - Verify installation: `docker --version`

4. **Node.js and npm (For frontend dependencies)**
   - Download from [nodejs.org](https://nodejs.org/)
   - Required for CSS/JS preprocessing
   - Verify installation: `node --version && npm --version`

### Development Tools
```bash
# Essential development packages
pip install --upgrade pip setuptools wheel

# Code quality tools
pip install black isort flake8 mypy pytest pytest-cov

# Security scanning tools
pip install bandit safety
```

---

## System Requirements

### Minimum Hardware Requirements
- **CPU:** Dual-core processor (2.0 GHz or higher)
- **RAM:** 8 GB (16 GB recommended for full cloud scanning)
- **Storage:** 10 GB available disk space
- **Network:** Stable internet connection for cloud API access

### Supported Operating Systems
- **Windows 10/11** (Primary development platform)
- **macOS 10.15+** (Catalina or later)
- **Linux** (Ubuntu 20.04+, CentOS 8+, or equivalent)

### Browser Requirements (for testing)
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

---

## Development Environment Setup

### 1. Clone the Repository
```bash
# Clone the main repository
git clone <repository-url> aegis-cloud-scanner
cd aegis-cloud-scanner

# Verify the project structure
ls -la
```

### 2. Virtual Environment Setup
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

# Verify activation
which python
```

### 3. Install Dependencies
```bash
# Install production dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt  # If available

# Verify installation
pip list | grep Flask
```

### 4. Pre-commit Hooks Setup
```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Test hooks
pre-commit run --all-files
```

### Project Structure Verification
After setup, your project structure should look like this:
```
aegis-cloud-scanner/
├── app.py                      # Main application entry point
├── config.py                   # Configuration management
├── wsgi.py                     # WSGI server entry point
├── requirements.txt            # Production dependencies
├── migrate_user_schema.py      # Database migration utility
├── .salt                       # Security salt file
├── venv/                       # Virtual environment (local)
├── docs/                       # Documentation
├── instance/                   # Instance-specific files
├── licenses/                   # License management system
│   ├── __init__.py
│   ├── license_middleware.py
│   ├── license_manager.py
│   └── [other license files]
├── scanners/                   # Cloud provider scanners
│   ├── aws/
│   ├── azure/
│   └── gcp/
├── static/                     # Static web assets
│   ├── css/
│   ├── js/
│   └── images/
├── templates/                  # Jinja2 templates
│   ├── base.html
│   ├── dashboard.html
│   └── [other templates]
├── tools/                      # Utility tools
├── utils/                      # Utility modules
└── tests/                      # Test suite
```

---

## Database Configuration

### Development Database (SQLite)
For local development, Aegis uses SQLite by default:

```python
# config.py - Development configuration
SQLALCHEMY_DATABASE_URI = f'sqlite:///{USER_DATA_DIR}/aegis_scanner.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}
```

### Database Initialization
```bash
# Initialize the database
python -c "from app import app, db; app.app_context().push(); db.create_all()"

# Run migrations (if migration files exist)
flask db upgrade

# Verify database creation
ls -la instance/  # Check for database file
```

### Production Database (PostgreSQL)
For production environments, configure PostgreSQL:

```python
# Environment variables for production
DATABASE_URL = "postgresql://username:password@localhost/aegis_scanner"
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
```

### Database Schema Migration
```bash
# Initialize migration repository
flask db init

# Create new migration
flask db migrate -m "Description of changes"

# Apply migration
flask db upgrade

# Downgrade migration (if needed)
flask db downgrade
```

---

## Cloud Provider Setup

### AWS Configuration
1. **Install AWS CLI**
   ```bash
   pip install awscli
   aws configure
   ```

2. **Set up AWS Credentials**
   ```bash
   # Configure default profile
   aws configure set aws_access_key_id YOUR_ACCESS_KEY
   aws configure set aws_secret_access_key YOUR_SECRET_KEY
   aws configure set default.region us-east-1

   # Verify configuration
   aws sts get-caller-identity
   ```

3. **IAM Permissions Required**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "ec2:Describe*",
           "s3:GetBucketLocation",
           "s3:GetBucketPolicy",
           "iam:GetRole",
           "iam:ListRoles",
           "rds:DescribeDBInstances",
           "cloudtrail:DescribeTrails"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

### Google Cloud Platform Configuration
1. **Install Google Cloud SDK**
   ```bash
   # Download and install gcloud CLI
   # Follow instructions at https://cloud.google.com/sdk/docs/install

   # Initialize gcloud
   gcloud init

   # Authenticate
   gcloud auth application-default login
   ```

2. **Service Account Setup**
   ```bash
   # Create service account
   gcloud iam service-accounts create aegis-scanner \
     --display-name="Aegis Scanner Service Account"

   # Download service account key
   gcloud iam service-accounts keys create credentials.json \
     --iam-account=aegis-scanner@PROJECT_ID.iam.gserviceaccount.com

   # Set environment variable
   export GOOGLE_APPLICATION_CREDENTIALS="path/to/credentials.json"
   ```

3. **Required GCP APIs**
   ```bash
   # Enable required APIs
   gcloud services enable compute.googleapis.com
   gcloud services enable storage.googleapis.com
   gcloud services enable cloudresourcemanager.googleapis.com
   gcloud services enable iam.googleapis.com
   ```

### Azure Configuration
1. **Install Azure CLI**
   ```bash
   # Install Azure CLI
   pip install azure-cli

   # Login to Azure
   az login

   # Set default subscription
   az account set --subscription "Your Subscription ID"
   ```

2. **Service Principal Setup**
   ```bash
   # Create service principal
   az ad sp create-for-rbac --name "aegis-scanner" \
     --role="Reader" \
     --scopes="/subscriptions/YOUR_SUBSCRIPTION_ID"

   # Note the output: appId, password, tenant
   ```

3. **Environment Variables**
   ```bash
   export AZURE_CLIENT_ID="your-app-id"
   export AZURE_CLIENT_SECRET="your-password"
   export AZURE_TENANT_ID="your-tenant-id"
   export AZURE_SUBSCRIPTION_ID="your-subscription-id"
   ```

---

## IDE and Development Tools

### Visual Studio Code Setup
1. **Install VS Code**
   - Download from [code.visualstudio.com](https://code.visualstudio.com/)

2. **Recommended Extensions**
   ```json
   {
     "recommendations": [
       "ms-python.python",
       "ms-python.flake8",
       "ms-python.black-formatter",
       "ms-python.isort",
       "ms-vscode.vscode-json",
       "redhat.vscode-yaml",
       "ms-vscode.vscode-typescript-next",
       "bradlc.vscode-tailwindcss",
       "esbenp.prettier-vscode"
     ]
   }
   ```

3. **VS Code Settings**
   ```json
   // .vscode/settings.json
   {
     "python.defaultInterpreterPath": "./venv/bin/python",
     "python.linting.enabled": true,
     "python.linting.flake8Enabled": true,
     "python.formatting.provider": "black",
     "python.sortImports.args": ["--profile", "black"],
     "editor.formatOnSave": true,
     "editor.codeActionsOnSave": {
       "source.organizeImports": true
     }
   }
   ```

### PyCharm Setup
1. **Install PyCharm Professional**
   - Required for Flask development features

2. **Project Configuration**
   - Set Python interpreter to `./venv/bin/python`
   - Enable Flask support in project settings
   - Configure code style to use Black formatting

### Debug Configuration
```json
// .vscode/launch.json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Flask Development",
      "type": "python",
      "request": "launch",
      "program": "${workspaceFolder}/app.py",
      "env": {
        "FLASK_ENV": "development",
        "FLASK_DEBUG": "1"
      },
      "console": "integratedTerminal",
      "justMyCode": false
    }
  ]
}
```

---

## Environment Variables

### Development Environment Variables
Create a `.env` file in the project root:

```bash
# Application Configuration
FLASK_APP=app.py
FLASK_ENV=development
FLASK_DEBUG=1
SECRET_KEY=your-secret-key-here

# Database Configuration
DATABASE_URL=sqlite:///instance/aegis_scanner.db

# Cloud Provider Credentials
# AWS
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_DEFAULT_REGION=us-east-1

# Google Cloud Platform
GOOGLE_APPLICATION_CREDENTIALS=path/to/gcp-credentials.json
GOOGLE_CLOUD_PROJECT=your-gcp-project-id

# Microsoft Azure
AZURE_CLIENT_ID=your-azure-client-id
AZURE_CLIENT_SECRET=your-azure-client-secret
AZURE_TENANT_ID=your-azure-tenant-id
AZURE_SUBSCRIPTION_ID=your-azure-subscription-id

# License Configuration
LICENSE_PUBLIC_KEY=path/to/license-public-key.pem
LICENSE_PRIVATE_KEY=path/to/license-private-key.pem

# Email Configuration (for notifications)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-email-password

# Security Configuration
SESSION_PERMANENT=False
SESSION_TYPE=filesystem
PERMANENT_SESSION_LIFETIME=3600

# Logging Configuration
LOG_LEVEL=DEBUG
LOG_FILE=logs/aegis_scanner.log

# AI Integration
GOOGLE_AI_API_KEY=your-google-ai-api-key

# Rate Limiting
RATELIMIT_STORAGE_URL=redis://localhost:6379/0
```

### Environment Variable Loading
```python
# config.py snippet
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        f'sqlite:///{USER_DATA_DIR}/aegis_scanner.db'

    # Cloud provider configurations
    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')

    # Security configurations
    SESSION_PERMANENT = False
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
```

---

## Running the Application

### Development Server
```bash
# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Set environment variables (if not using .env file)
export FLASK_APP=app.py
export FLASK_ENV=development
export FLASK_DEBUG=1

# Run the application
python app.py

# Alternative using Flask CLI
flask run --host=0.0.0.0 --port=5000
```

### Production Server (Gunicorn)
```bash
# Install gunicorn
pip install gunicorn

# Run with gunicorn
gunicorn --bind 0.0.0.0:8000 --workers 4 wsgi:application

# With configuration file
gunicorn --config gunicorn.conf.py wsgi:application
```

### Docker Development Environment
```dockerfile
# Dockerfile.dev
FROM python:3.13-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 5000

# Development command
CMD ["python", "app.py"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  web:
    build:
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "5000:5000"
    volumes:
      - .:/app
      - /app/venv
    environment:
      - FLASK_ENV=development
      - FLASK_DEBUG=1
    depends_on:
      - redis
      - postgres

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: aegis_scanner
      POSTGRES_USER: aegis
      POSTGRES_PASSWORD: scanner123
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

### Application Health Check
```bash
# Check application status
curl http://localhost:5000/health

# Check API endpoints
curl http://localhost:5000/api/health

# Check database connectivity
curl http://localhost:5000/api/db-health
```

---

## Development Workflow

### Git Workflow
```bash
# Create feature branch
git checkout -b feature/new-scanner-feature

# Make changes and commit
git add .
git commit -m "feat: add new cloud scanner feature"

# Push to remote
git push origin feature/new-scanner-feature

# Create pull request
# Use GitHub/GitLab web interface
```

### Code Quality Checks
```bash
# Run all quality checks
./scripts/quality-check.sh

# Individual checks
black --check .          # Code formatting
isort --check-only .     # Import sorting
flake8 .                 # Style guide enforcement
mypy .                   # Type checking
bandit -r .              # Security issues
safety check             # Dependency vulnerabilities
```

### Testing Workflow
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_license_manager.py

# Run tests with markers
pytest -m "not slow"
```

### Database Migration Workflow
```bash
# Create migration after model changes
flask db migrate -m "Add new user fields"

# Review migration file
cat migrations/versions/xxx_add_new_user_fields.py

# Apply migration
flask db upgrade

# Test migration rollback
flask db downgrade
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Python Version Compatibility
```bash
# Issue: Python version conflicts
# Solution: Use pyenv for version management
pyenv install 3.13.0
pyenv local 3.13.0
python --version  # Should show 3.13.0
```

#### 2. Virtual Environment Issues
```bash
# Issue: Virtual environment not activating
# Solution: Recreate virtual environment
rm -rf venv
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 3. Database Connection Issues
```python
# Issue: Database locked errors
# Solution: Check for hanging connections
import sqlite3
conn = sqlite3.connect('instance/aegis_scanner.db')
conn.execute('PRAGMA journal_mode=WAL;')
conn.close()
```

#### 4. Cloud Provider Authentication
```bash
# AWS Issues
aws sts get-caller-identity  # Verify credentials
aws configure list           # Check configuration

# GCP Issues
gcloud auth list            # Check authenticated accounts
gcloud config list          # Check configuration

# Azure Issues
az account show             # Check current account
az account list             # List available accounts
```

#### 5. Port Conflicts
```bash
# Issue: Port 5000 already in use
# Solution: Find and kill process
lsof -ti:5000               # Find process ID
kill -9 $(lsof -ti:5000)    # Kill process

# Alternative: Use different port
flask run --port=5001
```

#### 6. Memory Issues
```python
# Issue: Memory consumption during large scans
# Solution: Implement pagination and chunking
def scan_resources_paginated(self, page_size=100):
    for page in self.paginate_resources(page_size):
        yield self.scan_page(page)
```

### Debugging Tools

#### Flask Debug Toolbar
```python
# Install and configure
pip install flask-debugtoolbar

# Add to config
DEBUG_TB_ENABLED = True
DEBUG_TB_INTERCEPT_REDIRECTS = False
```

#### Logging Configuration
```python
# Enhanced logging for debugging
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('debug.log'),
        logging.StreamHandler()
    ]
)
```

#### Performance Profiling
```python
# Install profiling tools
pip install flask-profiler py-spy

# Enable profiler
from flask_profiler import Profiler
profiler = Profiler()
profiler.init_app(app)
```

### Development Server Optimization
```bash
# Use faster WSGI server for development
pip install werkzeug[watchdog]

# Enable auto-reload for template changes
export TEMPLATES_AUTO_RELOAD=True

# Use development proxy for static files
export SEND_FILE_MAX_AGE_DEFAULT=0
```

---

**End of Part 2**

**Next:** Part 3 will cover Application Components and Structure, including detailed module architecture, component interaction patterns, and codebase organization principles.