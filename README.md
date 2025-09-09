<<<<<<< HEAD
# Aegis Cloud Scanner (v0.7)

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

2.  **Open your browser** and navigate to `http://127.0.0.1:5000`. You will be automatically redirected to the setup page.

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

This project is licensed under the MIT License. See the `LICENSE` file for details. ````

---
### 🚀 How to Upload to GitHub

Here are the step-by-step instructions to get your project onto a new GitHub repository.

#### Step 1: Create a New Repository on GitHub

1.  Go to [GitHub](https://github.com) and log in.
2.  Click the **+** icon in the top-right corner and select **New repository**.
3.  Give your repository a name (e.g., `aegis-cloud-scanner`).
4.  **IMPORTANT**: Do **not** initialize the repository with a `README` or `.gitignore`.
5.  Click **Create repository**.

#### Step 2: Initialize Git in Your Project Folder

Open a terminal or command prompt in your project's root directory.

1.  **Initialize Git:**
    ```bash
    git init
    ```

2.  **Set the main branch name:**
    ```bash
    git branch -M main
    ```

#### Step 3: Add and Commit Your Files

1.  **Add all files to staging:** The `.gitignore` file will automatically exclude the ignored files.
    ```bash
    git add .
    ```

2.  **Commit the files:**
    ```bash
    git commit -m "Initial commit: Add Aegis Cloud Scanner application"
    ```

#### Step 4: Connect and Push to GitHub

1.  **Link your local repository to GitHub:** Copy the URL from your new GitHub repository page and run the command:
    ```bash
    git remote add origin https://github.com/your-username/your-repo-name.git
    ```

2.  **Push your code to GitHub:**
    ```bash
    git push -u origin main
    ```
=======
# Aegis Cloud Security Scanner

Aegis is a self-hosted, web-based tool designed to continuously scan your AWS environment for security misconfigurations. It provides a user-friendly dashboard, historical trend analysis, and automated reporting to help you maintain a strong security posture.

## Features

- **Comprehensive Scanning**: Checks for dozens of common misconfigurations across services like S3, IAM, EC2, RDS, CloudTrail, and more.

- **Multi-User & Secure**: Full user authentication with mandatory 2FA and encrypted storage for AWS credentials.

- **Interactive Dashboard**: Visualize your security posture with charts for historical trends and breakdowns by service.

- **Automated Reporting**: Schedule weekly or monthly scans and receive email alerts for new critical findings.

- **High-Performance Engine**: Scans run in parallel to deliver results quickly, with live progress updates streamed to the UI.

## Setup & Installation

### Prerequisites

- Python 3.8+

- An AWS account with credentials (`SecurityAudit` and `ReadOnlyAccess` policies recommended).

- A Gmail account (or other SMTP server) for sending email notifications.

### 1. Clone the Repository

Clone this repository to your local machine.

### 2. Install Dependencies

Install all required Python libraries:

```
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Create a file named `.env` in the root of the project folder and add your email configuration:

```
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-gmail-app-password
```

**Note:** For Gmail, you must use an "App Password," not your regular account password.

### 4. Initialize the Database

Run the following commands to set up your local SQLite database:

```
# Creates the migrations folder (only run this once per project)
flask db init

# Generates the initial migration script
flask db migrate -m "Initial migration."

# Applies the migration to create the database tables
flask db upgrade
```

### 5. Create an Admin User

You must create at least one admin user to manage the application. Run this command and replace `your_username` with the username you registered with in the app.

```
flask make-admin your_username
```

### 6. Run the Application

Start the server with this command:

```
python app.py
```

The application will be available at `http://127.0.0.1:5000`.
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
