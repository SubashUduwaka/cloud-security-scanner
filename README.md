# Aegis Cloud Scanner

					![Aegis Logo Animation](https://i.imgur.com/947ARvo.gif)

Aegis is a web-based cloud security posture management (CSPM) tool designed to scan **AWS** and **GCP** environments for common security misconfigurations. It provides a user-friendly dashboard to run scans, visualize security posture, manage credentials securely, and review historical scan data.

![Aegis Dashboard Screenshot](https://i.imgur.com/A5CGI6x.png)

---

## ✨ Features

-   **Multi-Cloud Scanning**: Scans both **Amazon Web Services (AWS)** and **Google Cloud Platform (GCP)** environments from a single interface.
-   **Web-Based Dashboard**: An intuitive UI to run scans and visualize results with charts for security posture, critical findings by service, and historical trends.
-   **Secure Credential Management**: Encrypts all cloud credentials at rest using Fernet symmetric encryption.
-   **Comprehensive Checks**: Includes dozens of checks for services like AWS IAM, S3, RDS, EC2, and GCP IAM, GCS, Cloud SQL, and GCE Firewall rules.
-   **Detailed Findings**: Provides clear descriptions, remediation advice, and direct documentation links for each identified issue.
-   **Multi-User Support**: Features a full authentication system with registration, email verification, password reset, and mandatory **Two-Factor Authentication (2FA)**.
-   **Admin Panel**: A dedicated view for administrators to manage users (unlock, delete, promote to admin) and view global audit logs.
-   **Finding Suppression**: Allows users to acknowledge and hide specific findings that are not relevant to their environment.
-   **PDF Reporting**: Generates and downloads a professional PDF summary of the latest scan results on demand.
-   **Live Progress View**: An optional real-time console view to monitor the progress of a running scan.
-   **Theming**: Includes a dark/light mode toggle that persists across sessions.

---

## 🛠️ Tech Stack

-   **Backend**: Flask, SQLAlchemy, Waitress
-   **Frontend**: HTML, CSS, JavaScript (with Chart.js for graphs and AOS for animations)
-   **Cloud SDKs**: Boto3 (for AWS), Google Cloud Client Libraries (for GCP)
-   **Security**: Flask-Bcrypt (password hashing), Flask-Login (session management), PyOTP (2FA), Fernet (credential encryption), Talisman (security headers), CSRFProtect.
-   **Database**: SQLite

---

## 🚀 Getting Started

### Prerequisites

-   Python 3.8+
-   Git
-   A supported web browser (e.g., Chrome, Firefox)

### Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/aegis-scanner.git](https://github.com/your-username/aegis-scanner.git)
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
    pip install -r requirements.txt
    ```

### Configuration

The first time you run the application, it will guide you through a setup process in the browser.

1.  **Run the application:**
    ```bash
    python app.py
    ```

2.  **Open your browser** and navigate to `http://12.0.0.1:5000`. You will be automatically redirected to the setup page.

3.  **Complete the setup form:**
    -   **Email Settings**: Provide SMTP details. For Gmail, you'll need to generate a 16-character "App Password."
    -   **Admin Registration Key**: Create a secret key. The first user who registers with this key will be granted administrator privileges.

    This process securely creates a `.env` file in your user data directory with your application's configuration.

### Usage

1.  After setup, you will be directed to the main application.
2.  **Register a user account.** Use the Admin Registration Key you created during setup to make this first user an admin.
3.  Log in, verify your email, and set up **Two-Factor Authentication (2FA)**.
4.  Navigate to **Settings** to add your AWS or GCP cloud credentials.
5.  Go to the **Dashboard**, select the credential profile and regions you want to scan, and click **Run Scan**.

---

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
