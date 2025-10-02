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

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Demo](#-demo) • [Contributing](#-contributing)

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

## 🚀 Quick Start

### 🐳 Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/SubashUduwaka/cloud-security-scanner.git
cd cloud-security-scanner

# Build and run with Docker
docker build -t aegis-scanner .
docker run -d -p 5000:5000 --name aegis aegis-scanner

# Or use Docker Compose
docker-compose up -d
```

### 💻 Local Installation

```bash
# Clone the repository
git clone https://github.com/SubashUduwaka/cloud-security-scanner.git
cd cloud-security-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

### ⚙️ Initial Setup

1. **Access the application**: Navigate to `http://localhost:5000`
2. **Complete setup wizard**:
   - Configure SMTP for email notifications
   - Create admin registration key
   - (Optional) Add Gemini API key for AI chatbot
3. **Register your account**: Use the admin key for the first user
4. **Set up 2FA**: Scan QR code with your authenticator app
5. **Add cloud credentials**: Go to Settings → Cloud Credentials
6. **Run your first scan**: Select provider and click "Run Scan"

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [📖 User Manual](docs/USER_MANUAL.md) | Complete guide for end users |
| [🔧 Deployment Guide](docs/DEPLOYMENT_GUIDE.md) | Production deployment instructions |
| [👨‍💻 Developer Docs](.github/DEVELOPER_DOCS/) | Technical documentation for contributors |
| [📋 Changelog](CHANGELOG.md) | Version history and release notes |

---

## 🎯 Use Cases

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
<img src="https://i.imgur.com/VlGBr2g.png" alt="Main Dashboard" width="800"/>
<sub>Real-time security posture monitoring with interactive charts and metrics</sub>

---

### 📊 Compliance Center - Framework Tracking
<img src="https://i.imgur.com/b0ufWGe.png" alt="Compliance Center" width="800"/>
<sub>Track compliance across SOC 2, ISO 27001, GDPR, and HIPAA frameworks</sub>

---

### 🔍 Security Scan Results
<img src="https://i.imgur.com/As7fEvN.png" alt="Scan Results" width="800"/>
<sub>Detailed findings with severity classification and remediation guidance</sub>

---

### 🤖 AI-Powered Chatbot Assistant
<img src="https://i.imgur.com/2YQgBiX.png" alt="AI Chatbot" width="800"/>
<sub>Get instant security guidance with Gemini AI integration</sub>

---

### ⚙️ Settings & Configuration
<img src="https://i.imgur.com/RJMEfrp.png" alt="Settings Panel" width="800"/>
<sub>Manage cloud credentials, notifications, and account settings</sub>

---

### 🔑 License Management
<img src="https://i.imgur.com/DXJduKK.png" alt="License Management" width="800"/>
<sub>Easy license activation and upgrade to Pro features</sub>

---

### 📄 Professional PDF Reports
<img src="https://i.imgur.com/akCMA8W.png" alt="PDF Reports" width="800"/>
<sub>Generate audit-ready reports with executive summaries and detailed findings</sub>

</div>

---

## 🛠️ Tech Stack

<div align="center">

| Category | Technologies |
|----------|-------------|
| **Backend** | Flask 3.0, SQLAlchemy, Gunicorn |
| **Cloud SDKs** | Boto3 (AWS), Google Cloud SDK, Azure SDK |
| **AI** | Google Generative AI (Gemini) |
| **Security** | Flask-Login, Flask-Bcrypt, PyOTP, Fernet |
| **Frontend** | HTML5, CSS3, JavaScript, Chart.js |
| **Database** | SQLite (PostgreSQL ready) |
| **DevOps** | Docker, Docker Compose |

</div>

---

## 📦 What's Included

```
cloud-security-scanner/
├── 📄 app.py                    # Main application
├── 📁 scanners/                 # Cloud scanners (AWS, GCP, Azure)
├── 📁 licenses/                 # License management
├── 📁 templates/                # HTML templates
├── 📁 static/                   # CSS, JavaScript
├── 📁 tools/                    # Utilities (crypto, validators, logging)
├── 📁 docs/                     # User documentation
├── 📁 .github/DEVELOPER_DOCS/   # Developer documentation
├── 🐳 Dockerfile                # Docker configuration
├── 🐳 docker-compose.yml        # Docker Compose setup
├── 📋 requirements.txt          # Python dependencies
└── 📖 README.md                 # This file
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

We welcome contributions from the community! 🎉

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

## 👨‍💻 Author

<div align="center">

**Subash Dananjaya Uduwaka**

[![Email](https://img.shields.io/badge/Email-aegis.aws.scanner%40gmail.com-red?style=for-the-badge&logo=gmail)](mailto:aegis.aws.scanner@gmail.com)
[![GitHub](https://img.shields.io/badge/GitHub-SubashUduwaka-black?style=for-the-badge&logo=github)](https://github.com/SubashUduwaka)
[![Phone](https://img.shields.io/badge/Phone-%2B94%2077%20962%206608-green?style=for-the-badge&logo=whatsapp)](tel:+94779626608)

*Built with ❤️ for the security community*

</div>

---

## 📄 License

This project is licensed under the **GPL-3.0 License** - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- 🎨 UI/UX inspired by modern security platforms
- 🤖 AI powered by Google's Gemini
- ☁️ Cloud SDKs: AWS Boto3, Google Cloud, Azure SDK
- 📊 Charts powered by Chart.js
- 🐳 Containerization with Docker
- 💙 Built with Flask and Python

---

## ⭐ Star History

<div align="center">

[![Star History Chart](https://api.star-history.com/svg?repos=SubashUduwaka/cloud-security-scanner&type=Date)](https://star-history.com/#SubashUduwaka/cloud-security-scanner&Date)

**If you find Aegis helpful, please consider giving it a ⭐ star!**

</div>

---

<div align="center">

**Made with ❤️ and ☕ by Subash Dananjaya Uduwaka**

[⬆ Back to Top](#-aegis-cloud-security-scanner)

</div>
