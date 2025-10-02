# Aegis Cloud Security Scanner

![Aegis Logo Animation](https://i.imgur.com/947ARvo.gif)

Aegis is a comprehensive web-based Cloud Security Posture Management (CSPM) tool designed to scan **AWS**, **GCP**, and **Azure** environments for security misconfigurations and compliance violations. It provides an intuitive dashboard to run scans, visualize security posture, manage credentials securely, and review historical scan data.

![Aegis Dashboard Screenshot](https://i.imgur.com/A5CGI6x.png)

---

## ✨ Features

### Security Scanning
-   **Multi-Cloud Scanning**: Comprehensive scanning for **Amazon Web Services (AWS)**, **Google Cloud Platform (GCP)**, and **Microsoft Azure** from a single unified interface.
-   **Comprehensive Checks**: 100+ security checks covering IAM, storage, databases, networking, encryption, logging, and more.
-   **Compliance Frameworks**: Built-in support for SOC 2, ISO 27001, GDPR, and HIPAA compliance checks.
-   **Detailed Findings**: Clear descriptions, severity ratings, remediation advice, and direct documentation links for each issue.
-   **Finding Suppression**: Acknowledge and hide specific findings that are not relevant to your environment.

### User Experience
-   **Modern Web Dashboard**: Intuitive UI with real-time visualizations using Chart.js for security posture, critical findings, and trends.
-   **Live Progress View**: Real-time console view to monitor running scans with detailed progress updates.
-   **Dark/Light Mode**: Theme toggle that persists across sessions for comfortable viewing.
-   **AI-Powered Chatbot**: Integrated Gemini AI assistant for security guidance and remediation help.
-   **Notification System**: Customizable email and in-app notifications for scan completion and critical findings.

### Enterprise Features
-   **Professional License Management**: Two-tier licensing (Basic/Pro) with easy activation and deactivation.
-   **Multi-User Support**: Complete authentication system with registration, email verification, and password reset.
-   **Two-Factor Authentication (2FA)**: Mandatory TOTP-based 2FA for enhanced account security.
-   **Admin Panel**: Dedicated interface for user management, audit logs, and system monitoring.
-   **Role-Based Access Control**: Admin and standard user roles with appropriate permissions.

### Reporting & Compliance
-   **PDF Report Generation**: Professional, branded PDF reports with executive summaries and detailed findings.
-   **Compliance Dashboard**: Track compliance posture across multiple frameworks in real-time.
-   **Historical Tracking**: View scan history and trends over time with interactive charts.
-   **Export Capabilities**: Export scan results and findings in multiple formats.

### Security & Privacy
-   **Secure Credential Management**: All cloud credentials encrypted at rest using Fernet symmetric encryption.
-   **Session Security**: Flask-Login session management with automatic timeout and CSRF protection.
-   **Security Headers**: Talisman integration for HTTP security headers (CSP, HSTS, etc.).
-   **Rate Limiting**: Protection against brute force attacks and abuse.
-   **Audit Logging**: Comprehensive audit trail of all user actions and system events.

---

## 🛠️ Tech Stack

### Backend
-   **Framework**: Flask 3.0.0 with Gunicorn/Waitress for production
-   **Database**: SQLAlchemy with SQLite (PostgreSQL ready for production)
-   **Cloud SDKs**: Boto3 (AWS), Google Cloud Client Libraries (GCP), Azure SDK (Azure)
-   **AI Integration**: Google Generative AI (Gemini) for chatbot functionality

### Security
-   **Authentication**: Flask-Login (session management), Flask-Bcrypt (password hashing)
-   **Two-Factor Auth**: PyOTP (TOTP-based 2FA with QR code generation)
-   **Encryption**: Fernet (symmetric credential encryption), cryptography library
-   **Protection**: Flask-Talisman (security headers), Flask-WTF (CSRF protection), Flask-Limiter (rate limiting)

### Frontend
-   **UI/UX**: Responsive HTML5, CSS3 with modern dark/light theme
-   **Visualizations**: Chart.js for interactive graphs and charts
-   **Animations**: AOS (Animate On Scroll) for smooth transitions
-   **Icons**: Font Awesome for consistent iconography

### DevOps & Deployment
-   **Containerization**: Docker with multi-stage builds
-   **Production Server**: Gunicorn with multiple workers and threads
-   **Monitoring**: APScheduler for background tasks, psutil for system monitoring
-   **Caching**: Flask-Caching with Redis support

---

## 🚀 Getting Started

### Prerequisites

-   **Python 3.13+** (recommended) or Python 3.8+
-   **Git** for version control
-   **Docker** (optional, for containerized deployment)
-   A modern web browser (Chrome, Firefox, Edge, Safari)

### Installation & Setup

#### Option 1: Local Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/aegis-scanner.git
    cd aegis-scanner
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    # For Windows
    python -m venv venv
    .\venv\Scripts\activate

    # For macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install the required dependencies:**
    ```bash
    pip install --upgrade pip
    pip install -r requirements.txt
    ```

4.  **Run the application:**
    ```bash
    python app.py
    ```

5.  **Access the application:**
    Open your browser and navigate to `http://127.0.0.1:5000`

#### Option 2: Docker Deployment

1.  **Build the Docker image:**
    ```bash
    docker build -t aegis-scanner .
    ```

2.  **Run the container:**
    ```bash
    docker run -d -p 5000:5000 --name aegis aegis-scanner
    ```

3.  **Access the application:**
    Open your browser and navigate to `http://localhost:5000`

### Initial Configuration

The first time you run Aegis, you'll be guided through an initial setup wizard:

1.  **Email Configuration**:
    -   SMTP server settings for email notifications
    -   For Gmail: Use App Password (16-character code from Google Account Security)
    -   Supports other SMTP providers (Outlook, SendGrid, etc.)

2.  **Admin Registration Key**:
    -   Create a secure secret key
    -   First user registering with this key becomes administrator
    -   Store this key securely for future admin account creation

3.  **Gemini API Key** (Optional):
    -   Enable AI-powered chatbot assistance
    -   Get free API key from [Google AI Studio](https://makersuite.google.com/app/apikey)

The setup process creates a secure `.env` file in `~/.aegisscanner/` with your configuration.

### Usage

1.  **User Registration & Authentication**:
    -   Register a new account (use Admin Registration Key for first admin user)
    -   Verify your email address via the confirmation link
    -   Set up Two-Factor Authentication (2FA) using your authenticator app

2.  **Add Cloud Credentials**:
    -   Navigate to **Settings → Cloud Credentials**
    -   Add AWS, GCP, or Azure credentials
    -   All credentials are encrypted at rest using Fernet encryption

3.  **License Activation** (Optional):
    -   All users start with **Basic** (5 scans/month)
    -   Navigate to **Settings → License Management** to upgrade to **Pro**
    -   Enter license key or request one from support

4.  **Run Security Scans**:
    -   Go to **Dashboard**
    -   Select cloud provider, credential profile, and regions
    -   Click **Run Scan** to start comprehensive security analysis
    -   Monitor progress in real-time or view results when complete

5.  **Review & Remediate**:
    -   View findings organized by severity and service
    -   Check compliance status across frameworks
    -   Generate PDF reports for stakeholders
    -   Use AI chatbot for remediation guidance

---

## 📚 Documentation

-   **[User Manual](docs/USER_MANUAL.md)**: Complete guide for end users
-   **[Developer Manual](docs/DEVELOPER_MANUAL_PART_1.md)**: Technical documentation for developers
-   **[Deployment Guide](docs/DEPLOYMENT_GUIDE.md)**: Production deployment instructions
-   **[License System](docs/LICENSE_SYSTEM_SUMMARY.md)**: License management documentation

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 🔒 Security

For security concerns or vulnerability reports, please see [SECURITY.md](SECURITY.md).

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 📧 Support

-   **Email**: aegis.aws.scanner@gmail.com
-   **Issues**: [GitHub Issues](https://github.com/your-username/aegis-scanner/issues)
-   **Documentation**: [Wiki](https://github.com/your-username/aegis-scanner/wiki)

---

## 🙏 Acknowledgments

-   Built with ❤️ using Flask, Boto3, and Google Cloud SDK
-   UI inspired by modern security platforms
-   Thanks to the open-source community for amazing tools and libraries
