<div align="center">

# 🛡️ Aegis Cloud Security Scanner

<img src="https://i.imgur.com/947ARvo.gif" alt="Aegis Logo" width="300"/>

### Enterprise-Grade Multi-Cloud Security Posture Management (CSPM)

[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/flask-3.0.0-green.svg)](https://flask.palletsprojects.com/)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](Dockerfile)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![GitHub Release](https://img.shields.io/github/v/release/SubashUduwaka/cloud-security-scanner)](https://github.com/SubashUduwaka/cloud-security-scanner/releases)

**Scan AWS, GCP & Azure | 100+ Security Checks | AI-Powered Assistance | Compliance Tracking**

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Contributing](#-contributing)

<img src="https://i.imgur.com/As7fEvN.png" alt="Aegis Dashboard" width="800"/>

</div>

---

## 🌟 Why Aegis?

Aegis Cloud Security Scanner is a **free, open-source** Cloud Security Posture Management (CSPM) tool that helps you:

- ✅ **Identify security misconfigurations** across AWS, GCP, and Azure
- ✅ **Track compliance** with SOC 2, ISO 27001, GDPR, and HIPAA
- ✅ **Get AI-powered remediation guidance** with integrated Gemini chatbot
- ✅ **Generate professional reports** for stakeholders
- ✅ **Monitor security posture** over time with trend analysis
- ⚡ **Lightning-fast dashboard** - Loads in under 1 second (90% faster than v0.9.0)

> **Built by a security enthusiast for the security community** 🔐

---

## 🆕 What's New in v0.9.2

**Latest Release: October 23, 2025** - Critical bug fixes and security enhancements!

### 🔧 Critical Fixes
- ✅ **License Key Viewing Fixed** - Resolved password verification bug (bcrypt library mismatch)
- ✅ **Database Restore Working** - Fixed CSRF token handling for backup restore functionality
- ✅ **UI Improvements** - Removed annoying real-time monitoring notifications on every page load
- ✅ **Login Form Alignment** - Fixed authentication page layout issues

### 🔐 Security Enhancements
- Enhanced password verification with comprehensive audit logging
- Improved error handling without exposing sensitive information
- Added validation for password hash integrity
- Real-time 2FA adoption statistics in security configuration

### 📊 Admin Panel Improvements
- Accurate 2FA statistics showing actual user adoption rates
- Better license key management with secure password-protected viewing
- Enhanced JavaScript modal handling with proper error recovery
- Improved debugging with structured logging

**See full details in [CHANGELOG.md](CHANGELOG.md)**

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 Security Scanning
- **Multi-Cloud Support**: AWS, GCP, Azure
- **100+ Security Checks**: IAM, Storage, Databases, Networks, Encryption
- **Real-Time Scanning**: Live progress monitoring
- **Severity Classification**: Critical, High, Medium, Low
- **Remediation Guidance**: Step-by-step fix instructions

</td>
<td width="50%">

### 🤖 AI-Powered Assistance
- **Gemini AI Chatbot**: 24/7 security guidance
- **Context-Aware**: Understands your findings
- **Best Practices**: Industry-standard recommendations
- **Interactive Help**: Ask questions, get answers

</td>
</tr>
<tr>
<td width="50%">

### 📊 Compliance & Reporting
- **4 Major Frameworks**: SOC 2, ISO 27001, GDPR, HIPAA
- **PDF Report Generation**: Professional, branded reports
- **Timezone Support**: Reports in your local timezone (including Sri Lanka UTC+5:30)
- **Historical Tracking**: Trend analysis over time
- **Export Options**: PDF and CSV formats
- **Compliance Dashboard**: Real-time posture tracking

</td>
<td width="50%">

### 🔐 Enterprise Security
- **Two-Factor Authentication**: Mandatory 2FA
- **Role-Based Access**: Admin & User roles
- **Real-Time Alerts**: Enterprise alert aggregation API
- **Credential Encryption**: Fernet encryption at rest
- **Audit Logging**: Complete activity trail
- **Session Management**: Secure timeout handling

</td>
</tr>
</table>

---

## 📥 Installation

### Option 1: Windows Installer (Recommended for Windows Users)

**Latest: v0.9.2** - Windows installer with bug fixes and enhanced security!

1. **Download the Installer**
   - Go to [Releases](https://github.com/SubashUduwaka/cloud-security-scanner/releases/latest)
   - Download `AegisCloudScanner_Professional_Setup_v0.8.exe`

2. **Run the Installer**
   - Right-click the installer → "Run as administrator"
   - Follow the installation wizard
   - The installer will automatically:
     - Install GTK3 runtime (for PDF generation)
     - Install Python dependencies via pip
     - Create desktop shortcut
     - Set up start menu shortcuts

3. **Launch the Application**
   - Double-click the desktop shortcut "Aegis Cloud Scanner"
   - Or use Start Menu → "Aegis Cloud Scanner"
   - Application opens at `http://localhost:5000`

**What gets installed:**
- Application files in `C:\Program Files (x86)\Aegis Cloud Security Scanner\`
- User data in `%LOCALAPPDATA%\AegisScanner\`
- Desktop and Start Menu shortcuts
- GTK3 runtime for PDF generation

---

### Option 2: Python Installation (All Platforms)

#### Prerequisites

##### 1. Install Python 3.13+

**Windows:**
1. Download from [python.org](https://www.python.org/downloads/)
2. Run installer and **CHECK** "Add Python to PATH"
3. Verify installation:
   ```cmd
   python --version
   pip --version
   ```

**If Python is not in PATH:**
1. Find Python installation (usually `C:\Users\<username>\AppData\Local\Programs\Python\Python313\`)
2. Add to PATH:
   - Right-click "This PC" → Properties
   - Advanced system settings → Environment Variables
   - Under "System variables", select "Path" → Edit
   - Click "New" and add:
     - `C:\Users\<username>\AppData\Local\Programs\Python\Python313\`
     - `C:\Users\<username>\AppData\Local\Programs\Python\Python313\Scripts\`
   - Click OK on all dialogs
   - Restart Command Prompt

**macOS/Linux:**
```bash
# macOS with Homebrew
brew install python@3.13

# Ubuntu/Debian
sudo apt update
sudo apt install python3.13 python3-pip python3-venv

# Verify
python3 --version
pip3 --version
```

##### 2. Install Git (Optional but recommended)
- **Windows**: Download from [git-scm.com](https://git-scm.com/download/win)
- **macOS**: `brew install git`
- **Linux**: `sudo apt install git`

#### Installation Steps

1. **Clone or Download the Repository**
   ```bash
   # With Git
   git clone https://github.com/SubashUduwaka/cloud-security-scanner.git
   cd cloud-security-scanner

   # Or download ZIP from GitHub and extract
   ```

2. **Create Virtual Environment**
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   # Upgrade pip first
   pip install --upgrade pip

   # Install requirements
   pip install -r requirements.txt
   ```

4. **Run the Application**

   **Production Mode (Recommended):**
   ```bash
   # Windows
   START_AEGIS.bat

   # macOS/Linux
   ./start_aegis.sh
   # or
   python3 run_production.py
   ```

   **Development Mode (for developers):**
   ```bash
   # Windows
   START_AEGIS_DEV.bat

   # macOS/Linux
   ./start_aegis.sh dev
   # or
   python3 app.py
   ```

   **Differences:**
   - **Production**: Uses Waitress WSGI server (multi-threaded, production-ready)
   - **Development**: Uses Flask dev server (auto-reload, debug mode)

5. **Access the Application**
   - Open browser: `http://localhost:5000`
   - Complete initial setup wizard
   - Enable 2FA for security

---

### Option 3: Docker Deployment

**Available Now**: Run Aegis in a containerized environment!

```bash
# Clone the repository
git clone https://github.com/SubashUduwaka/cloud-security-scanner.git
cd cloud-security-scanner

# Using Docker Compose (Recommended)
docker-compose up -d

# Or build and run manually
docker build -t aegis-scanner .
docker run -p 5000:5000 -v aegis-data:/app/instance aegis-scanner
```

**Access**: Navigate to `http://localhost:5000`

**Download Pre-built Image**: Available in [Releases](https://github.com/SubashUduwaka/cloud-security-scanner/releases) as `.tar` file

---

## 🧹 Cleaning Up Old Versions

If you have previous versions installed, follow these steps:

### Windows Installer Versions
1. Go to **Settings** → **Apps** → **Apps & features**
2. Search for "Aegis Cloud Scanner"
3. Click **Uninstall**

### Manual Python Installations
1. **Delete Application Directory**
   - Remove the folder where you cloned/extracted Aegis

2. **Delete User Data** (Optional - removes your settings and database)
   - Press `Win + R`, type: `%LOCALAPPDATA%`
   - Delete `AegisScanner` folder

3. **Delete Legacy Data Locations** (if upgrading from v0.7 or earlier)
   ```cmd
   # Old locations that may exist:
   %USERPROFILE%\.aegisscanner\
   %APPDATA%\aegis-scanner\
   ```

4. **Deactivate Virtual Environment**
   ```bash
   deactivate  # if virtual environment is active
   ```

---

## 🚀 Quick Start

### First-Time Setup

1. **Launch Application**
   - Via installer: Click desktop shortcut
   - Via Python: Run `START_AEGIS.bat` or `python app.py`

2. **Create Account**
   - Navigate to `http://localhost:5000`
   - Click "Register"
   - Fill in email, username, password
   - Verify email (check spam folder)

3. **Enable 2FA** (Recommended)
   - Settings → Security → Enable 2FA
   - Scan QR code with authenticator app (Google Authenticator, Authy, etc.)

4. **Add Cloud Credentials**
   - Settings → Cloud Credentials
   - Add AWS, GCP, or Azure credentials
   - Credentials are encrypted at rest

5. **Run Your First Scan**
   - Dashboard → "Start Scan"
   - Select cloud provider
   - View real-time progress
   - Review findings and remediation steps

---

## 📚 Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [User Manual](docs/USER_MANUAL.md)
- [API Documentation](docs/API.md)
- [Developer Guide](.github/DEVELOPER_DOCS/)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [FAQ](docs/FAQ.md)

---

## 🎯 Roadmap

- [x] AWS Support
- [x] GCP Support
- [x] Azure Support
- [x] Windows Installer
- [x] GTK3 Integration
- [x] License System
- [x] AI Chatbot
- [x] Docker Image Release
- [x] Scheduled Scanning
- [x] Webhook Integrations
- [x] Multi-User Organizations
- [x] Custom Policy Engine
- [x] API Access

---

### For Security Teams
- 🔍 **Continuous Monitoring**: Automated security assessments
- 📊 **Compliance Reporting**: Generate audit-ready reports
- 🚨 **Incident Response**: Quickly identify misconfigurations
- 📈 **Risk Management**: Track security posture over time

### For DevOps Engineers
- ⚡ **Pre-Deployment Checks**: Scan before going to production
- 🔄 **CI/CD Integration**: Automate security in pipelines
- 🛠️ **Infrastructure Validation**: Verify IaC configurations
- 📝 **Documentation**: Generate security documentation

### For Compliance Officers
- ✅ **Framework Mapping**: Map findings to compliance requirements
- 📄 **Audit Reports**: Professional PDF reports for auditors
- 📊 **Dashboard Views**: Real-time compliance status
- 🔒 **Evidence Collection**: Document security controls

---

## 🎬 Screenshots & Demo

<div align="center">

### 🏠 Main Dashboard - Security Overview
<img src="https://i.imgur.com/2YQgBiX.png" alt="Main Dashboard" width="800"/>
<sub>Real-time security posture monitoring with interactive charts and metrics</sub>

---

### 📊 Compliance Center - Framework Tracking
<img src="https://i.imgur.com/b0ufWGe.png" alt="Compliance Center" width="800"/>
<sub>Track compliance across SOC 2, ISO 27001, GDPR, and HIPAA frameworks</sub>

---

### 🔍 Security Scan Results
<img src="https://i.imgur.com/DXJduKK.png" alt="Scan Results" width="800"/>
<sub>Detailed findings with severity classification and remediation guidance</sub>

---

### 🤖 AI-Powered Chatbot Assistant
<img src="https://i.imgur.com/VlGBr2g.png" alt="AI Chatbot" width="250"/>
<sub>Get instant security guidance with Gemini AI integration</sub>

---

### 🔑 License Management
<img src="https://i.imgur.com/akCMA8W.png" alt="License Management" width="800"/>
<sub>Easy license activation and upgrade to Pro features</sub>

---

### 📄 Professional PDF Reports
<img src="https://i.imgur.com/RJMEfrp.png" alt="PDF Reports" width="800"/>
<sub>Generate audit-ready reports with executive summaries and detailed findings</sub>

</div>

---

## 🛠️ Tech Stack

<div align="center">

| Category | Technologies |
|----------|-------------|
| **Backend** | Flask 3.0, SQLAlchemy, Waitress (Windows), Gunicorn (Docker) |
| **Cloud SDKs** | Boto3 (AWS), Google Cloud SDK, Azure SDK |
| **AI** | Google Generative AI (Gemini) |
| **Security** | Flask-Login, Flask-Bcrypt, PyOTP, Fernet |
| **Frontend** | HTML5, CSS3, JavaScript, Chart.js |
| **Database** | SQLite (default), PostgreSQL (production) |
| **DevOps** | Docker, Docker Compose |

</div>

---

## 📦 What's Included

```
cloud-security-scanner/
├── 📄 app.py                    # Main Flask application (dev mode)
├── 📄 run_production.py         # Production server launcher (Waitress)
├── 📄 config.py                 # Configuration settings
├── 📄 wsgi.py                   # WSGI entry point
├── 📄 license_manager.py        # License validation system
├── 🚀 START_AEGIS.bat           # Windows launcher (Production)
├── 🚀 START_AEGIS_DEV.bat       # Windows launcher (Development)
├── 🚀 start_aegis.sh            # Linux/macOS launcher (Production/Dev)
├── 📁 scanners/                 # Cloud scanners (AWS, GCP, Azure)
├── 📁 licenses/                 # License management
├── 📁 templates/                # HTML templates (35+ pages)
├── 📁 static/                   # CSS, JavaScript, images
├── 📁 tools/                    # Utilities (crypto, validators, logging)
├── 📁 docs/                     # User documentation
├── 📁 .github/                  # GitHub workflows & developer docs
├── 🐳 Dockerfile                # Docker configuration
├── 🐳 docker-compose.yml        # Docker Compose setup (uses Gunicorn)
├── 📋 requirements.txt          # Python dependencies
├── 📖 README.md                 # This file
├── 📖 CHANGELOG.md              # Version history
├── 📖 CONTRIBUTING.md           # Contribution guidelines
├── 📖 CODE_OF_CONDUCT.md        # Community standards
├── 📖 SECURITY.md               # Security policy
└── 📁 project_files/            # Development files (not needed for running)
    ├── archives/                # Release builds (.exe, .tar)
    ├── documents/               # Documentation (markdown, docx, pdf)
    ├── installers/              # Installer scripts (.iss)
    ├── scripts/                 # Development scripts
    └── backups/                 # Code backups
```

---

## 🔑 License Management

Aegis uses a **two-tier licensing system**:

### 🆓 Basic (Free)
- ✅ 5 scans per month
- ✅ Single cloud provider
- ✅ Basic reporting
- ✅ Community support

### 💎 Pro (License Key Required)
- ✅ Unlimited scans
- ✅ All cloud providers
- ✅ AI chatbot
- ✅ Advanced reporting
- ✅ Priority support

**🎁 Request a FREE license key**: Email [aegis.aws.scanner@gmail.com](mailto:aegis.aws.scanner@gmail.com)

> License keys are provided **free of charge** for educational and personal use. Just send us an email! 📧

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. 🍴 Fork the repository
2. 🌿 Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. 💾 Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. 🚀 Push to the branch (`git push origin feature/AmazingFeature`)
5. 🎯 Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 🐛 Issues & Support

### Found a bug? Have a feature request?
- 🐛 [Report an issue](https://github.com/SubashUduwaka/cloud-security-scanner/issues/new)
- 💡 [Request a feature](https://github.com/SubashUduwaka/cloud-security-scanner/issues/new)

### Need help?
- 📖 Check the [User Manual](docs/USER_MANUAL.md)
- 💬 Open a [Discussion](https://github.com/SubashUduwaka/cloud-security-scanner/discussions)
- 📧 Email: [aegis.aws.scanner@gmail.com](mailto:aegis.aws.scanner@gmail.com)

---

## 👨‍💻 Authors

<div align="center">

**Aegis Cloud Team**

[![Email](https://img.shields.io/badge/Email-aegis.aws.scanner%40gmail.com-red?style=for-the-badge&logo=gmail)](mailto:aegis.aws.scanner@gmail.com)
[![GitHub](https://img.shields.io/badge/GitHub-SubashUduwaka-black?style=for-the-badge&logo=github)](https://github.com/SubashUduwaka)
[![Phone](https://img.shields.io/badge/Phone-%2B94%2077%20962%206608-green?style=for-the-badge&logo=whatsapp)](tel:+94779626608)

*Built with ❤️ for the security community*

</div>

---

## 📄 License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Built with [Flask](https://flask.palletsprojects.com/)
- Powered by [Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html), [Google Cloud SDK](https://cloud.google.com/sdk), [Azure SDK](https://azure.microsoft.com/en-us/downloads/)
- AI assistance by [Google Gemini](https://ai.google.dev/)
- Icons by [Font Awesome](https://fontawesome.com/)

---

## 📞 Support

- 📧 Email: aegis.aws.scanner@gmail.com
- 🐛 Issues: [GitHub Issues](https://github.com/SubashUduwaka/cloud-security-scanner/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/SubashUduwaka/cloud-security-scanner/discussions)

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=SubashUduwaka/cloud-security-scanner&type=Date)](https://star-history.com/#SubashUduwaka/cloud-security-scanner&Date)

---

<div align="center">

**Made with ❤️ by the Aegis Community**

[⬆ Back to Top](#-aegis-cloud-security-scanner)

</div>
