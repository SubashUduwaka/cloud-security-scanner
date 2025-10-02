# 🚀 Aegis Cloud Security Scanner v0.8 - Production Ready Release

We're excited to announce v0.8 of Aegis Cloud Security Scanner - a comprehensive Cloud Security Posture Management (CSPM) tool for AWS, GCP, and Azure!

## ✨ Key Features

### 🔍 Multi-Cloud Security Scanning
- **AWS Support**: Complete scanning for IAM, S3, RDS, EC2, VPC, CloudTrail, and more
- **GCP Support**: Comprehensive checks for IAM, GCS, Cloud SQL, GCE, and networking
- **Azure Support**: Full scanning for Identity, Storage, Databases, Network, and Key Vault
- **100+ Security Checks**: Covering misconfigurations across all major cloud services

### 🤖 AI-Powered Assistance
- **Gemini AI Chatbot**: Integrated AI assistant for security guidance and remediation help
- **Context-Aware Recommendations**: Get specific advice for your security findings
- **Real-Time Support**: Ask questions and get instant security expertise

### 📊 Compliance & Reporting
- **Compliance Frameworks**: Built-in support for SOC 2, ISO 27001, GDPR, and HIPAA
- **Real-Time Compliance Dashboard**: Track your compliance posture across frameworks
- **PDF Report Generation**: Professional, branded reports with executive summaries
- **Historical Tracking**: Monitor security trends over time with interactive charts

### 🎨 Modern User Experience
- **Dark/Light Mode**: Beautiful theme toggle that persists across sessions
- **Responsive Design**: Works seamlessly on desktop and mobile devices
- **Real-Time Progress**: Monitor scan progress with live console view
- **Interactive Dashboards**: Visualizations with Chart.js for security metrics

### 🔐 Enterprise Security Features
- **Two-Factor Authentication (2FA)**: Mandatory TOTP-based 2FA for all accounts
- **Professional License Management**: Two-tier licensing (Basic/Pro) with easy activation
- **Secure Credential Storage**: All cloud credentials encrypted at rest using Fernet
- **Role-Based Access Control**: Admin and user roles with appropriate permissions
- **Audit Logging**: Comprehensive trail of all user actions and system events

### 🛠️ Developer-Friendly
- **Docker Support**: One-command deployment with Docker and Docker Compose
- **Production Ready**: Gunicorn server with health checks and monitoring
- **PostgreSQL Support**: Ready for production databases
- **Redis Caching**: Optional caching for improved performance
- **RESTful API**: Well-structured Flask application with clean architecture

## 📦 What's Included

- Complete source code for all cloud scanners (AWS, GCP, Azure)
- 39 HTML templates for all features
- Professional CSS with dark mode support
- Comprehensive documentation (User Manual, Developer Guides)
- Docker configuration for easy deployment
- License management system with GUI generator
- Email notification system
- Account management with email verification

## 🚀 Quick Start

### Using Docker (Recommended)
```bash
docker build -t aegis-scanner .
docker run -d -p 5000:5000 aegis-scanner
```

### Local Installation
```bash
git clone https://github.com/SubashUduwaka/cloud-security-scanner.git
cd cloud-security-scanner
python -m venv venv
source venv/bin/activate  # or .\venv\Scripts\activate on Windows
pip install -r requirements.txt
python app.py
```

Visit `http://localhost:5000` and complete the setup wizard!

## 📚 Documentation

- [User Manual](docs/USER_MANUAL.md) - Complete guide for end users
- [Developer Manual](docs/DEVELOPER_MANUAL_PART_1.md) - Technical documentation
- [Deployment Guide](docs/DEPLOYMENT_GUIDE.md) - Production deployment instructions
- [License System](docs/LICENSE_SYSTEM_SUMMARY.md) - License management docs

## 🔧 Requirements

- Python 3.13+ (or 3.8+)
- Cloud credentials (AWS, GCP, or Azure)
- SMTP server for email notifications (Gmail, Outlook, etc.)
- Optional: Gemini API key for AI chatbot

## 🙏 Acknowledgments

Built with ❤️ using:
- Flask 3.0.0 - Web framework
- Boto3 - AWS SDK
- Google Cloud SDK - GCP integration
- Azure SDK - Azure integration
- Chart.js - Interactive visualizations
- Docker - Containerization

## 📄 License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## 📧 Support

- **Email**: aegis.aws.scanner@gmail.com
- **Issues**: [GitHub Issues](https://github.com/SubashUduwaka/cloud-security-scanner/issues)

---

**Full Changelog**: https://github.com/SubashUduwaka/cloud-security-scanner/blob/master/CHANGELOG.md
