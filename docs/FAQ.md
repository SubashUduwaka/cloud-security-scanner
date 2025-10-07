# Frequently Asked Questions (FAQ)

## Table of Contents

- [General Questions](#general-questions)
- [Installation & Setup](#installation--setup)
- [Account & Authentication](#account--authentication)
- [Cloud Credentials](#cloud-credentials)
- [Scanning & Results](#scanning--results)
- [Licensing](#licensing)
- [Reports & Compliance](#reports--compliance)
- [Troubleshooting](#troubleshooting)
- [Security & Privacy](#security--privacy)
- [Advanced Features](#advanced-features)

---

## General Questions

### What is Aegis Cloud Security Scanner?

Aegis is a free, open-source Cloud Security Posture Management (CSPM) tool that helps organizations identify security misconfigurations across AWS, GCP, and Azure environments. It performs 100+ security checks and provides remediation guidance.

### Is Aegis really free?

Yes! Aegis is completely free and open-source under the GPL-3.0 license. We offer two tiers:
- **Basic (Free)**: 5 scans per month, single cloud provider
- **Pro (Free License Key)**: Unlimited scans, all cloud providers, AI chatbot

Request a FREE Pro license by emailing aegis.aws.scanner@gmail.com

### Which cloud providers are supported?

Aegis supports:
- ✅ Amazon Web Services (AWS)
- ✅ Google Cloud Platform (GCP)
- ✅ Microsoft Azure

### What operating systems are supported?

- **Windows**: Windows 10/11 (installer or Python)
- **macOS**: macOS 10.15+ (Python installation)
- **Linux**: Ubuntu 20.04+, Debian, CentOS, RHEL (Python installation)
- **Docker**: All platforms with Docker support

### Do I need programming knowledge to use Aegis?

No! Aegis has a user-friendly web interface. However, basic cloud computing knowledge is helpful for understanding findings and implementing remediations.

---

## Installation & Setup

### How do I install Aegis on Windows?

**Option 1: Windows Installer (Recommended)**
1. Download `AegisCloudScanner_Professional_Setup_v0.8.exe` from [Releases](https://github.com/SubashUduwaka/cloud-security-scanner/releases)
2. Right-click → "Run as administrator"
3. Follow the wizard
4. Launch from desktop shortcut

**Option 2: Python Installation**
See [README - Installation](https://github.com/SubashUduwaka/cloud-security-scanner#installation) for detailed instructions.

### Do I need to install Python separately?

- **Windows Installer**: No, but Python must be installed on your system
- **Manual Installation**: Yes, Python 3.13+ is required

### What is GTK3 and do I need it?

GTK3 is required for PDF report generation. The Windows installer automatically installs it. For manual installations, PDF generation won't work without GTK3.

### Why does the installer require administrator privileges?

Administrator rights are needed to:
- Install GTK3 runtime system-wide
- Create application files in Program Files
- Set up desktop and Start Menu shortcuts
- Install Python dependencies globally

### Where are my files stored after installation?

- **Application Files**: `C:\Program Files (x86)\Aegis Cloud Security Scanner\`
- **User Data**: `%LOCALAPPDATA%\AegisScanner\` (database, credentials, logs)
- **Logs**: `%LOCALAPPDATA%\AegisScanner\aegis_scanner_debug.log`

### How do I update to a new version?

1. Uninstall old version: Settings → Apps → Aegis Cloud Scanner → Uninstall
2. Download new installer from GitHub Releases
3. Install new version (your data is preserved in `%LOCALAPPDATA%\AegisScanner\`)

### Can I run Aegis without installing it?

Yes! Use the Python installation method:
```bash
git clone https://github.com/SubashUduwaka/cloud-security-scanner.git
cd cloud-security-scanner
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
python app.py
```

---

## Account & Authentication

### How do I create an account?

1. Navigate to `http://localhost:5000`
2. Click "Register"
3. Enter email, username, and password
4. Verify your email (check spam folder)
5. Log in with your credentials

### I didn't receive the verification email. What should I do?

- Check your spam/junk folder
- Verify email configuration in application settings
- For local installations, check SMTP settings in environment variables
- Contact support: aegis.aws.scanner@gmail.com

### What is 2FA and should I enable it?

Two-Factor Authentication (2FA) adds an extra security layer by requiring a code from your authenticator app (Google Authenticator, Authy) along with your password. **We strongly recommend enabling 2FA** for enhanced security.

### How do I enable 2FA?

1. Go to Settings → Security
2. Click "Enable 2FA"
3. Scan QR code with your authenticator app
4. Enter the 6-digit code to confirm
5. Save backup codes in a secure location

### I lost my 2FA device. How can I access my account?

Use the backup codes provided when you enabled 2FA. If you've lost those too:
1. Delete the database file: `%LOCALAPPDATA%\AegisScanner\instance\aegis.db`
2. Register a new account
3. Re-add your cloud credentials

**Note**: This will delete all scan history and settings.

### Can I change my password?

Yes! Go to Settings → Security → Change Password

### What password requirements do I need to meet?

Passwords must:
- Be at least 12 characters long
- Include uppercase and lowercase letters
- Include numbers
- Include special characters
- Not contain common patterns

---

## Cloud Credentials

### How do I add cloud credentials?

1. Go to Settings → Cloud Credentials
2. Click "Add Credentials"
3. Select cloud provider (AWS/GCP/Azure)
4. Enter credentials
5. Click "Save"

Credentials are encrypted and stored securely in your local database.

### What AWS permissions does Aegis need?

**Recommended**: Attach the AWS managed policy `SecurityAudit` or `ReadOnlyAccess` to your IAM user.

**Minimum Permissions**: Read-only access to:
- IAM (users, roles, policies)
- S3 (buckets, ACLs, policies)
- EC2 (instances, security groups)
- RDS (instances, snapshots)
- CloudTrail (trails, logs)
- KMS (keys, policies)

### How do I create AWS credentials for Aegis?

1. Log in to AWS Console
2. Go to IAM → Users → Create User
3. Attach `SecurityAudit` policy
4. Create Access Keys (Security Credentials tab)
5. Copy Access Key ID and Secret Access Key
6. Add them to Aegis

**Security Tip**: Create a dedicated IAM user specifically for Aegis with read-only permissions.

### What GCP credentials do I need?

You need a Service Account JSON key file with the **Viewer** or **Security Reviewer** role.

**Creating GCP Credentials**:
1. Go to GCP Console → IAM & Admin → Service Accounts
2. Create Service Account
3. Grant "Viewer" role
4. Create JSON key
5. Upload JSON file to Aegis

### What Azure credentials are required?

You need:
- **Client ID** (Application ID)
- **Client Secret**
- **Tenant ID**
- **Subscription ID**

**Required Role**: Reader or Security Reader

### Can I store credentials without internet connection?

Yes! Starting with v0.9.0, Aegis supports offline credential storage. Credentials are saved locally even if AWS validation fails due to network issues.

### Are my credentials safe?

Yes! All credentials are:
- Encrypted at rest using Fernet encryption
- Stored in a local SQLite database
- Never transmitted to external servers (except to your cloud provider for scanning)
- Isolated in user-specific AppData directory

### Can I use the same credentials on multiple machines?

Yes, but you'll need to add them separately on each machine. Credentials are stored locally and not synced between installations.

### How do I delete stored credentials?

1. Go to Settings → Cloud Credentials
2. Find the credential profile
3. Click "Delete" or "Remove"
4. Confirm deletion

---

## Scanning & Results

### How do I run my first scan?

1. Add cloud credentials (Settings → Cloud Credentials)
2. Go to Dashboard
3. Click "Start Scan"
4. Select cloud provider
5. Wait for scan completion
6. Review findings

### How long does a scan take?

Scan duration depends on:
- Number of resources in your cloud account
- Cloud provider (AWS typically 5-15 minutes)
- Network speed
- Number of regions

**Average times**:
- Small environment (< 50 resources): 2-5 minutes
- Medium environment (50-500 resources): 5-15 minutes
- Large environment (> 500 resources): 15-30 minutes

### Can I scan multiple cloud accounts simultaneously?

No, scans run sequentially. Add multiple credential profiles and run separate scans for each.

### What does each severity level mean?

- **Critical**: Immediate security risk, fix ASAP (e.g., publicly accessible databases)
- **High**: Significant security concern, fix soon (e.g., weak encryption)
- **Medium**: Security best practice violation, should fix (e.g., missing MFA)
- **Low**: Minor improvement recommended (e.g., unused resources)

### Can I export scan results?

Yes! Options include:
- **PDF Report**: Dashboard → Generate Report
- **JSON**: Via API (Pro license)
- **CSV**: Export from scan history

### How do I suppress false positives?

1. Go to scan results
2. Find the specific finding
3. Click "Suppress" or "Ignore"
4. Add a reason (optional)
5. Suppressed findings won't appear in future reports

### Can I schedule automatic scans?

Yes! This feature is available in the Pro version. Go to Settings → Scheduled Scans to configure automated security assessments.

### Do scans affect my cloud resources?

No! Aegis performs **read-only** operations. It cannot modify, delete, or create any resources in your cloud environment.

---

## Licensing

### What's the difference between Basic and Pro?

| Feature | Basic (Free) | Pro (Free) |
|---------|-------------|------------|
| Scans per month | 5 | Unlimited |
| Cloud providers | 1 | All (AWS, GCP, Azure) |
| AI chatbot | ❌ | ✅ |
| PDF reports | Basic | Advanced |
| Scheduled scans | ❌ | ✅ |
| API access | ❌ | ✅ |
| Support | Community | Priority |

### How do I get a Pro license?

Email aegis.aws.scanner@gmail.com with:
- Your name
- Company name (if applicable)
- Intended use (personal/educational/business)

You'll receive a FREE Pro license key within 24-48 hours.

### How do I activate my license?

1. Go to Settings → License Management
2. Click "Activate License"
3. Enter your license key
4. Enter your email and name
5. Click "Activate"

### Can I use Pro license on multiple machines?

Each license key is tied to one user account. For multiple users, request additional licenses.

### My license activation failed. What should I do?

Common issues:
- **Invalid key**: Double-check for typos
- **Already activated**: Each key can only be activated once
- **Network error**: Activation works offline now (v0.9.0+)

Contact support if problems persist.

### Can I generate my own license keys?

For testing/development only. The License Generator GUI is included for developers. Production licenses should be requested from the team.

---

## Reports & Compliance

### How do I generate a PDF report?

1. Complete a scan
2. Go to Dashboard or Scan History
3. Click "Generate Report"
4. Select compliance frameworks (optional)
5. Wait for generation
6. Download PDF

### Why is my PDF report generation failing?

Common causes:
- **GTK3 not installed**: Required for PDF generation
  - Windows installer includes GTK3 automatically
  - Manual installations need GTK3 installed separately
- **Missing dependencies**: Run `pip install weasyprint`
- **Permission errors**: Check logs at `%LOCALAPPDATA%\AegisScanner\aegis_scanner_debug.log`

### What compliance frameworks are supported?

- **SOC 2**: System and Organization Controls 2
- **ISO 27001**: Information Security Management
- **GDPR**: General Data Protection Regulation
- **HIPAA**: Health Insurance Portability and Accountability Act

### How accurate is compliance tracking?

Compliance Center provides automated mapping of findings to framework requirements. However, **full compliance requires manual processes** beyond technical controls. Use Aegis as a tool to assist, not replace, formal compliance programs.

### Can I customize reports?

PDF reports include:
- Executive summary
- Compliance framework mapping
- Detailed findings by severity
- Resource inventory
- Remediation guidance

Advanced customization requires code modifications (open-source!).

---

## Troubleshooting

### The application won't start. What should I do?

1. **Check if Python is installed**: `python --version`
2. **Check if port 5000 is free**: Another application might be using it
   ```bash
   # Windows
   netstat -ano | findstr :5000

   # Kill the process if needed
   taskkill /PID <process_id> /F
   ```
3. **Check logs**: `%LOCALAPPDATA%\AegisScanner\aegis_scanner_debug.log`
4. **Reinstall dependencies**:
   ```bash
   pip install -r requirements.txt --force-reinstall
   ```

### I'm getting "Failed to store AWS credentials" error

This was fixed in v0.9.0. If using an older version:
- **Update to v0.9.0** for offline credential storage
- **Check internet connection**: Older versions required AWS connection
- **Verify credentials**: Test with AWS CLI: `aws sts get-caller-identity`

### Database errors on startup

```
OperationalError: unable to open database file
```

**Solution**:
- Ensure `%LOCALAPPDATA%\AegisScanner\` directory exists and is writable
- Delete and recreate database: Delete `%LOCALAPPDATA%\AegisScanner\instance\aegis.db`
- Check disk space

### "Session expired" errors

Fixed in v0.9.0. For older versions:
- Clear browser cookies
- Restart the application
- Update to latest version

### PDF generation fails with GTK3 error

**Windows Installer Users**: GTK3 should be installed automatically

**Manual Installation**:
1. Download GTK3 runtime: [gtk3-runtime-3.24.31-win64](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases)
2. Install GTK3
3. Restart application

### Scan fails or times out

- **Check credentials**: Verify they're valid in cloud console
- **Check permissions**: Ensure read-only access to services
- **Network issues**: Verify internet connection
- **Large environment**: Increase timeout in settings
- **Check logs**: Look for specific error messages

### Application is slow

- **Close other browser tabs**: Web interface can be resource-intensive
- **Increase system resources**: Allocate more RAM if using Docker
- **Large database**: Clear old scan history in Settings
- **Background scans**: Disable scheduled scans during active use

### I can't access the application from another device

By default, Aegis binds to `localhost` (127.0.0.1). To access from network:
1. Edit `app.py` or set environment variable
2. Change `app.run(host='0.0.0.0')`
3. **Security Warning**: Only do this on trusted networks

### Docker container won't start

```bash
# Check logs
docker logs <container_id>

# Common fixes:
# 1. Port already in use
docker run -p 8080:5000 aegis-scanner

# 2. Permission issues
docker run --user $(id -u):$(id -g) aegis-scanner

# 3. Volume mounting issues
docker run -v aegis-data:/app/instance aegis-scanner
```

---

## Security & Privacy

### Is my data sent to external servers?

**No!** Aegis runs entirely locally. Your data is only sent to:
- Your own cloud provider (AWS/GCP/Azure) for scanning
- Google Gemini API if using AI chatbot (Pro feature, opt-in)

### Where is my data stored?

All data is stored locally:
- **Database**: `%LOCALAPPDATA%\AegisScanner\instance\aegis.db`
- **Credentials**: Encrypted in local database
- **Logs**: `%LOCALAPPDATA%\AegisScanner\aegis_scanner_debug.log`

### How are credentials encrypted?

Credentials are encrypted using Fernet (symmetric encryption based on AES-128 CBC with HMAC) with a unique encryption key generated for each installation.

### Can I use Aegis in a production environment?

Yes! Aegis uses read-only cloud APIs and doesn't modify any resources. However:
- Use dedicated IAM users with minimal permissions
- Enable 2FA on Aegis accounts
- Regularly update to latest version
- Monitor logs for suspicious activity

### Is Aegis compliant with security standards?

Aegis itself:
- Uses encrypted credential storage
- Implements secure authentication (2FA supported)
- Provides audit logging
- Follows OWASP security best practices

**Note**: As an open-source tool, Aegis has not undergone formal security certification (SOC 2, ISO 27001, etc.).

### What network ports does Aegis use?

- **Port 5000**: Web interface (localhost by default)
- **HTTPS/443**: Cloud provider API calls
- **SMTP**: Email verification (if configured)

### Can I run Aegis on an air-gapped network?

Partially. You can:
- Install and run Aegis offline
- Store credentials offline (v0.9.0+)

You cannot:
- Perform cloud scans (requires internet to reach cloud APIs)
- Use AI chatbot
- Send email notifications

---

## Advanced Features

### How do I use the API?

API access requires Pro license:
```bash
# Example: Get scan results
curl -X GET http://localhost:5000/api/v1/scans \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

See [API Documentation](API.md) for full reference.

### Can I integrate Aegis into CI/CD pipelines?

Yes! Use the API to trigger scans and retrieve results:
```yaml
# Example GitHub Actions workflow
- name: Run Security Scan
  run: |
    curl -X POST http://aegis-server/api/v1/scan \
      -H "Authorization: Bearer ${{ secrets.AEGIS_TOKEN }}" \
      -d '{"provider": "aws"}'
```

### How do I configure scheduled scans?

Pro license required:
1. Go to Settings → Scheduled Scans
2. Click "Add Schedule"
3. Select cloud provider
4. Set frequency (daily, weekly, monthly)
5. Configure notifications
6. Save

### Can I add custom security checks?

Yes! Aegis is open-source. To add custom checks:
1. Fork the repository
2. Add scanner function in `scanners/<provider>/<provider>_scanner.py`
3. Follow existing pattern (return list of findings)
4. Submit Pull Request or use locally

### How do I configure webhooks?

Pro license feature:
1. Go to Settings → Integrations → Webhooks
2. Add webhook URL
3. Select events (scan complete, critical finding, etc.)
4. Configure payload format
5. Test webhook

### Can I use Aegis with multiple AWS accounts/organizations?

Yes! Add credentials for each account separately. For AWS Organizations:
1. Create cross-account IAM role
2. Use STS AssumeRole
3. Add role ARN to Aegis

### How do I contribute to Aegis development?

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines. We welcome:
- Bug reports and fixes
- New cloud security checks
- Documentation improvements
- Feature requests
- UI/UX enhancements

### Where can I find the source code?

GitHub: https://github.com/SubashUduwaka/cloud-security-scanner

---

## Still Have Questions?

### 📧 Email Support
aegis.aws.scanner@gmail.com

### 🐛 Report Issues
[GitHub Issues](https://github.com/SubashUduwaka/cloud-security-scanner/issues)

### 💬 Community Discussion
[GitHub Discussions](https://github.com/SubashUduwaka/cloud-security-scanner/discussions)

### 📖 Documentation
- [README](../README.md)
- [User Manual](USER_MANUAL.md)
- [Installation Guide](INSTALLATION.md)
- [API Documentation](API.md)
- [Developer Docs](../.github/DEVELOPER_DOCS/)

---

<div align="center">

**Aegis Cloud Security Scanner**

*Making cloud security accessible to everyone* 🛡️

[⬆ Back to Top](#frequently-asked-questions-faq)

</div>
