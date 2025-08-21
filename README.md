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
