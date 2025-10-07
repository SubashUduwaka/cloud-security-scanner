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

<img src="https://i.imgur.com/A5CGI6x.png" alt="Aegis Dashboard" width="800"/>

</div>

---

## 🌟 Why Aegis?

Aegis Cloud Security Scanner is a **free, open-source** Cloud Security Posture Management (CSPM) tool that helps you:

- ✅ **Identify security misconfigurations** across AWS, GCP, and Azure
- ✅ **Track compliance** with SOC 2, ISO 27001, GDPR, and HIPAA
- ✅ **Get AI-powered remediation guidance** with integrated Gemini chatbot
- ✅ **Generate professional reports** for stakeholders
- ✅ **Monitor security posture** over time with trend analysis

> **Built by a security enthusiast for the security community** 🔐

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
- **Historical Tracking**: Trend analysis over time
- **Export Options**: Multiple format support
- **Compliance Dashboard**: Real-time posture tracking

</td>
<td width="50%">

### 🔐 Enterprise Security
- **Two-Factor Authentication**: Mandatory 2FA
- **Role-Based Access**: Admin & User roles
- **Credential Encryption**: Fernet encryption at rest
- **Audit Logging**: Complete activity trail
- **Session Management**: Secure timeout handling

</td>
</tr>
</table>

---

## 📥 Installation

### Option 1: Windows Installer (Recommended for Windows Users)

**NEW in v0.9.0**: First official Windows installer with automatic setup!

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
   ```bash
   # Windows
   START_AEGIS.bat

   # macOS/Linux
   python app.py
   ```

5. **Access the Application**
   - Open browser: `http://localhost:5000`
   - Complete initial setup wizard
   - Enable 2FA for security

---

### Option 3: Docker (Coming Soon)

```bash
# Docker image will be available soon
docker pull aegisscanner/aegis-cloud-scanner:latest
docker run -p 5000:5000 aegisscanner/aegis-cloud-scanner:latest
```

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

## 🔧 Configuration

### Cloud Provider Credentials

#### AWS
```
Access Key ID: AKIAIOSFODNN7EXAMPLE
Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Required IAM Permissions**: ReadOnlyAccess or SecurityAudit policy

#### GCP
- Upload Service Account JSON key file
- **Required Roles**: Viewer or Security Reviewer

#### Azure
```
Client ID: 12345678-1234-1234-1234-123456789012
Client Secret: your-secret-here
Tenant ID: 87654321-4321-4321-4321-210987654321
Subscription ID: abcdefgh-ijkl-mnop-qrst-uvwxyz123456
```

**Required Role**: Reader or Security Reader

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
- [ ] Docker Image Release
- [ ] Scheduled Scanning
- [ ] Webhook Integrations
- [ ] Multi-User Organizations
- [ ] Custom Policy Engine
- [ ] API Access
- [ ] CLI Tool

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Quick Contribution Steps:
1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

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
