# Troubleshooting Guide

This guide covers common issues and their solutions when using Aegis Cloud Security Scanner.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Application Won't Start](#application-wont-start)
- [Authentication & Login Issues](#authentication--login-issues)
- [Cloud Credential Issues](#cloud-credential-issues)
- [Scanning Issues](#scanning-issues)
- [PDF Report Generation Issues](#pdf-report-generation-issues)
- [Database Issues](#database-issues)
- [Performance Issues](#performance-issues)
- [Network & Connectivity Issues](#network--connectivity-issues)
- [Docker Issues](#docker-issues)
- [Advanced Troubleshooting](#advanced-troubleshooting)

---

## Installation Issues

### Windows Installer Fails to Run

**Symptom**: Double-clicking installer does nothing or shows error

**Solutions**:
1. **Run as Administrator**
   ```
   Right-click installer → "Run as administrator"
   ```

2. **Check Windows Defender/Antivirus**
   - Temporarily disable antivirus
   - Add installer to exceptions
   - Download fresh copy (may be corrupted)

3. **Verify File Integrity**
   - Check file size: ~50MB
   - Re-download if different
   - Download from official GitHub Releases only

4. **Check Windows Version**
   - Requires Windows 10/11
   - Update Windows to latest version

**Error**: "This app can't run on your PC"
- Download 64-bit installer
- Update Windows

---

### Python Installation Issues

**Error**: `python: command not found`

**Solutions**:

**Windows**:
1. Install Python from python.org
2. **Check "Add Python to PATH"** during installation
3. If already installed, add manually:
   - Search "Environment Variables"
   - Edit "Path" under System variables
   - Add: `C:\Users\<username>\AppData\Local\Programs\Python\Python313\`
   - Add: `C:\Users\<username>\AppData\Local\Programs\Python\Python313\Scripts\`
4. Restart Command Prompt
5. Verify: `python --version`

**macOS/Linux**:
```bash
# macOS
brew install python@3.13

# Ubuntu/Debian
sudo apt update
sudo apt install python3.13 python3-pip python3-venv

# Verify
python3 --version
```

---

### pip Install Fails

**Error**: `pip: command not found`

**Solution**:
```bash
# Windows
python -m ensurepip --upgrade
python -m pip install --upgrade pip

# macOS/Linux
python3 -m ensurepip --upgrade
python3 -m pip install --upgrade pip
```

**Error**: `Could not find a version that satisfies the requirement`

**Solution**:
```bash
# Update pip first
pip install --upgrade pip

# Install with verbose output to see the issue
pip install -r requirements.txt -v

# If specific package fails, install individually
pip install flask==3.0.0
```

**Error**: `Permission denied` when installing

**Solution**:
```bash
# Use virtual environment (recommended)
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # macOS/Linux

# Then install
pip install -r requirements.txt

# OR use --user flag (not recommended)
pip install --user -r requirements.txt
```

---

### Virtual Environment Issues

**Error**: `venv\Scripts\activate : cannot be loaded`

**Solution** (Windows PowerShell):
```powershell
# Enable script execution (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then activate
venv\Scripts\activate
```

**Alternative**: Use Command Prompt instead of PowerShell
```cmd
venv\Scripts\activate.bat
```

---

### GTK3 Installation Issues

**Symptom**: PDF generation fails with GTK error

**Solutions**:

**Windows Installer Users**:
- GTK3 should install automatically
- If not, download manually: [GTK3 Runtime](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases)
- Install `gtk3-runtime-3.24.31-win64.exe`
- Restart Aegis

**Manual Installation**:
1. Download GTK3 runtime
2. Run installer as Administrator
3. Verify installation: Check `C:\Program Files\GTK3-Runtime Win64\`
4. Restart application

**Alternative**: Use Docker (includes GTK3)

---

## Application Won't Start

### Port 5000 Already in Use

**Error**: `Address already in use` or `OSError: [Errno 48]`

**Solution**:

**Windows**:
```cmd
# Find process using port 5000
netstat -ano | findstr :5000

# Kill the process (replace PID with actual process ID)
taskkill /PID <PID> /F

# OR run Aegis on different port
set FLASK_RUN_PORT=8080
python app.py
```

**macOS/Linux**:
```bash
# Find process
lsof -i :5000

# Kill process
kill -9 <PID>

# OR use different port
export FLASK_RUN_PORT=8080
python app.py
```

---

### Application Crashes on Startup

**Check Logs**:
```
Location: %LOCALAPPDATA%\AegisScanner\aegis_scanner_debug.log
```

**Common Causes**:

1. **Database Corruption**
```bash
# Backup and delete database
copy "%LOCALAPPDATA%\AegisScanner\instance\aegis.db" "%LOCALAPPDATA%\AegisScanner\instance\aegis.db.backup"
del "%LOCALAPPDATA%\AegisScanner\instance\aegis.db"

# Restart application (creates new database)
```

2. **Missing Dependencies**
```bash
pip install -r requirements.txt --force-reinstall
```

3. **Corrupted Virtual Environment**
```bash
# Delete and recreate
rmdir /s venv
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

---

### Flask Application Errors

**Error**: `ImportError: cannot import name 'create_app'`

**Solution**:
- Ensure you're in correct directory: `cloud-security-scanner/`
- Verify `app.py` exists
- Check Python version: `python --version` (needs 3.13+)

**Error**: `ModuleNotFoundError: No module named 'flask'`

**Solution**:
```bash
# Activate virtual environment first
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Authentication & Login Issues

### Cannot Register New Account

**Error**: Email verification not working

**Solutions**:
1. **Check Spam Folder**
2. **Verify SMTP Configuration**
   - Check email settings in application
   - Test email server connection
3. **Use Different Email Provider**
   - Some providers block automated emails
   - Try Gmail, Outlook, or ProtonMail

**Temporary Workaround**: Disable email verification
```python
# In app.py, find and comment out email verification check
# This is NOT recommended for production
```

---

### 2FA Issues

**Error**: "Invalid 2FA code"

**Solutions**:
1. **Check Time Sync**
   - Authenticator app time must match system time
   - Enable automatic time sync on phone
   - Windows: Settings → Time & Language → Set time automatically

2. **Use Backup Codes**
   - Use codes provided during 2FA setup
   - Each code works once

3. **Reset 2FA** (Last Resort)
   - Delete database: `%LOCALAPPDATA%\AegisScanner\instance\aegis.db`
   - Register new account
   - Re-add credentials

---

### "Session Expired" Errors

**Fixed in v0.9.0+**

**For older versions**:
1. Update to latest version
2. Clear browser cookies/cache
3. Restart application
4. Log in again

---

### Password Reset Not Working

**Solutions**:
1. Check spam folder for reset email
2. Verify email is correct
3. Use "Forgot Password" link on login page
4. If all fails: Delete database and create new account (loses data)

---

## Cloud Credential Issues

### "Failed to Store AWS Credentials"

**Error**: Network error or validation failure

**Solutions** (v0.9.0+):
- Credentials are stored even without internet
- Check credentials are correct
- Verify in AWS Console: IAM → Users → Security Credentials

**Test Credentials**:
```bash
# Using AWS CLI
aws configure
aws sts get-caller-identity
```

**Common Issues**:
- **Access Key ID format**: Should be `AKIA...` (20 characters)
- **Secret Key format**: 40 characters, alphanumeric + symbols
- **Spaces**: Remove any leading/trailing spaces
- **Copy/paste errors**: Type manually if pasting fails

---

### AWS Connection Errors

**Error**: `Could not connect to the endpoint URL: "https://sts.amazonaws.com/"`

**Solutions**:
1. **Check Internet Connection**
2. **Verify AWS Region**
   - Default: us-east-1
   - Some regions may be disabled
3. **Check Firewall/Proxy**
   - Allow HTTPS (port 443) outbound
   - Whitelist *.amazonaws.com
4. **Update Aegis**
   - v0.9.0+ fixed endpoint issues

---

### AWS Permission Denied

**Error**: `AccessDenied` or `UnauthorizedOperation`

**Solutions**:
1. **Attach SecurityAudit Policy**
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:List*",
                "iam:Get*",
                "s3:List*",
                "s3:Get*",
                "ec2:Describe*",
                "rds:Describe*"
            ],
            "Resource": "*"
        }
    ]
}
```

2. **Verify IAM User Permissions**
   - AWS Console → IAM → Users → Permissions
   - Should have read-only access

3. **Check MFA Requirements**
   - Some policies require MFA
   - Add MFA to IAM user if required

---

### GCP Authentication Fails

**Error**: Invalid service account or permissions

**Solutions**:
1. **Verify JSON Key Format**
   - Must be valid JSON
   - Contains `private_key`, `client_email`, `project_id`

2. **Check Service Account Permissions**
   - Requires "Viewer" or "Security Reviewer" role
   - GCP Console → IAM & Admin → IAM → Check roles

3. **Enable Required APIs**
```
- Cloud Resource Manager API
- Compute Engine API
- Cloud Storage API
- IAM Service Account Credentials API
```

**Test**:
```bash
gcloud auth activate-service-account --key-file=service-account.json
gcloud projects list
```

---

### Azure Authentication Issues

**Error**: Invalid credentials or insufficient permissions

**Solutions**:
1. **Verify All Four Values**
   - Client ID (Application ID)
   - Client Secret (valid, not expired)
   - Tenant ID
   - Subscription ID

2. **Check Service Principal Permissions**
   - Portal → Subscriptions → Access Control (IAM)
   - Should have "Reader" role

3. **Client Secret Expired**
   - Azure AD → App Registrations → Your App → Certificates & secrets
   - Create new client secret
   - Update in Aegis

**Test**:
```bash
az login --service-principal -u <client_id> -p <client_secret> --tenant <tenant_id>
az account show
```

---

## Scanning Issues

### Scan Fails Immediately

**Check**:
1. **Credentials Added?**
   - Settings → Cloud Credentials
   - At least one credential required

2. **Credentials Valid?**
   - Test in cloud console
   - Check expiration dates

3. **Internet Connection**
   - Scan requires API access to cloud provider

4. **Check Logs**
```
%LOCALAPPDATA%\AegisScanner\aegis_scanner_debug.log
```

---

### Scan Hangs or Times Out

**Solutions**:
1. **Large Environment**: Increase timeout
   - Edit `app.py`: Find `timeout` settings
   - Increase from default (usually 300s)

2. **Network Issues**
   - Check internet stability
   - Disable VPN/proxy temporarily

3. **Resource Limits**
   - Close other applications
   - Increase system resources

4. **Restart Scan**
   - Cancel current scan
   - Wait 30 seconds
   - Start new scan

---

### Incomplete Scan Results

**Symptom**: Scan completes but missing resources

**Solutions**:
1. **Regional Resources Not Scanned**
   - Default: Scans primary region only
   - Multi-region scanning: Pro feature

2. **Permission Issues**
   - Some resources require additional IAM permissions
   - Check logs for "Access Denied" errors

3. **Pagination Issues**
   - Large accounts (>1000 resources) may have truncated results
   - Update to latest version (pagination fixes)

---

### Scan Shows No Findings

**Possible Reasons**:
1. **Your environment is secure!** ✅
2. **Wrong account/region selected**
3. **Credentials lack permissions**
   - Check IAM policies
   - Verify read access to services

**Verify**:
- Check resource count in scan summary
- Verify cloud console shows resources
- Test with known misconfiguration (e.g., public S3 bucket)

---

## PDF Report Generation Issues

### "PDF Generation Failed"

**Error**: GTK3 related errors

**Solution**:
```bash
# Windows - Install GTK3
Download: gtk3-runtime-3.24.31-win64.exe
Run as Administrator

# Verify installation
dir "C:\Program Files\GTK3-Runtime Win64\"
```

**Alternative**: Use Windows Installer (includes GTK3)

---

### WeasyPrint Errors

**Error**: `OSError: cannot load library 'gobject-2.0-0'`

**Solutions**:

**Windows**:
1. Install GTK3 runtime (above)
2. Add to PATH:
```cmd
set PATH=%PATH%;C:\Program Files\GTK3-Runtime Win64\bin
```

**macOS**:
```bash
brew install cairo pango gdk-pixbuf libffi
```

**Linux**:
```bash
# Ubuntu/Debian
sudo apt install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info

# CentOS/RHEL
sudo yum install pango cairo gdk-pixbuf2
```

---

### PDF Missing Images or Styling

**Solutions**:
1. Check CSS file exists: `static/css/report.css`
2. Verify logo files: `static/images/logo.png`
3. Clear browser cache
4. Regenerate report

---

### Large PDFs Fail to Generate

**Error**: Memory error or timeout

**Solutions**:
1. **Reduce Report Size**
   - Suppress low-severity findings
   - Select fewer compliance frameworks
   - Export JSON instead

2. **Increase Memory**
   - Close other applications
   - Increase Python heap size:
   ```bash
   set PYTHONMEMORYMAX=4096
   ```

---

## Database Issues

### Database Locked Error

**Error**: `database is locked`

**Solutions**:
1. **Close All Aegis Instances**
   - Only one instance can access database
   - Check Task Manager for python.exe processes

2. **Remove Lock File**
```cmd
del "%LOCALAPPDATA%\AegisScanner\instance\aegis.db-journal"
```

3. **Restart Application**

---

### Database Corruption

**Error**: `database disk image is malformed`

**Solutions**:
1. **Backup Current Database**
```cmd
copy "%LOCALAPPDATA%\AegisScanner\instance\aegis.db" "%LOCALAPPDATA%\AegisScanner\instance\aegis.db.backup"
```

2. **Try SQLite Repair**
```bash
sqlite3 aegis.db
.dump > dump.sql
.exit

# Create new database
sqlite3 aegis_new.db < dump.sql
```

3. **Delete and Recreate** (Last Resort)
```cmd
del "%LOCALAPPDATA%\AegisScanner\instance\aegis.db"
# Restart application - creates fresh database
# Re-add credentials and settings
```

---

### Migration Errors

**Error**: Database schema migration failed

**Solutions**:
1. **Backup Database**
2. **Run Migration Manually**
```bash
python migrate_user_schema.py
```

3. **Check Flask-Migrate**
```bash
pip install --upgrade Flask-Migrate

# Initialize migrations (if not exists)
flask db init

# Create migration
flask db migrate -m "description"

# Apply migration
flask db upgrade
```

---

## Performance Issues

### Application Running Slow

**Solutions**:
1. **Clear Old Scan Data**
   - Settings → Data Management → Clear History
   - Keep last 30 days only

2. **Optimize Database**
```bash
sqlite3 "%LOCALAPPDATA%\AegisScanner\instance\aegis.db"
VACUUM;
REINDEX;
.exit
```

3. **Check System Resources**
   - Task Manager → Check RAM/CPU usage
   - Close unnecessary applications
   - Increase system RAM if consistently >80%

4. **Disable Debug Mode**
```python
# In app.py
app.run(debug=False)
```

---

### Browser Consuming Too Much Memory

**Solutions**:
1. **Close Unused Tabs**
2. **Clear Browser Cache**
   - Chrome: Ctrl+Shift+Del
   - Firefox: Ctrl+Shift+Del
3. **Use Different Browser**
   - Chrome is most tested
   - Firefox is lighter on memory
4. **Disable Browser Extensions**
   - Ad blockers may interfere

---

### Slow Scans

**Causes**:
1. **Large Environment**: Many resources take time
2. **Network Latency**: Cloud API response times
3. **Rate Limiting**: Cloud provider throttling

**Solutions**:
- Schedule scans during off-peak hours
- Reduce scan scope (specific services only)
- Use local caching (Pro feature)

---

## Network & Connectivity Issues

### Cannot Access from Another Computer

**Symptom**: Aegis runs on localhost:5000 but not accessible from network

**Solution**:
```python
# Edit app.py
app.run(host='0.0.0.0', port=5000)

# Access from network
http://192.168.1.100:5000  # Replace with server IP
```

**Security Warning**:
- Only do this on trusted networks
- Enable firewall rules
- Use HTTPS in production
- Implement proper authentication

---

### Firewall Blocking Connection

**Windows Firewall**:
```cmd
# Allow Python through firewall (as Administrator)
netsh advfirewall firewall add rule name="Aegis Scanner" dir=in action=allow program="C:\Python313\python.exe" enable=yes
```

**Linux (UFW)**:
```bash
sudo ufw allow 5000/tcp
sudo ufw reload
```

---

### Proxy Configuration

**If behind corporate proxy**:

```bash
# Set proxy environment variables
set HTTP_PROXY=http://proxy.company.com:8080
set HTTPS_PROXY=http://proxy.company.com:8080

# For AWS CLI
aws configure set proxy.http http://proxy.company.com:8080
aws configure set proxy.https http://proxy.company.com:8080
```

---

## Docker Issues

### Docker Container Won't Start

**Error**: Database permission errors

**Solution**:
```bash
# Use correct volume mount
docker run -v aegis-data:/app/instance aegis-scanner

# OR use host directory with proper permissions
docker run -v $(pwd)/data:/app/instance -u $(id -u):$(id -g) aegis-scanner
```

---

### Docker Session Expired Errors

**Solution**:
```bash
# Set environment variables
docker run \
  -e SECRET_KEY=your-secret-key-here \
  -e SESSION_COOKIE_SECURE=False \
  -e WTF_CSRF_ENABLED=True \
  aegis-scanner
```

---

### Docker Build Fails

**Error**: Dependency installation fails

**Solutions**:
1. **Clear Docker Cache**
```bash
docker build --no-cache -t aegis-scanner .
```

2. **Check Dockerfile Location**
```bash
# Build from Docker directory
cd DO_NOT_UPLOAD_TO_GITHUB/Docker
docker build -t aegis-scanner .
```

3. **Check Internet Connection**
   - Docker needs to download packages
   - Check proxy settings if behind firewall

---

## Advanced Troubleshooting

### Enable Debug Logging

**Temporary Debug Mode**:
```python
# In app.py
import logging
logging.basicConfig(level=logging.DEBUG)
```

**Check Detailed Logs**:
```
Location: %LOCALAPPDATA%\AegisScanner\aegis_scanner_debug.log
```

**Increase Log Verbosity**:
```python
# In app.py or config.py
LOG_LEVEL = 'DEBUG'  # From 'INFO'
```

---

### Test Cloud Provider Connectivity

**AWS**:
```bash
# Using AWS CLI
aws sts get-caller-identity
aws s3 ls
aws ec2 describe-instances --region us-east-1

# Using Python (boto3)
python -c "import boto3; print(boto3.client('sts').get_caller_identity())"
```

**GCP**:
```bash
gcloud auth activate-service-account --key-file=key.json
gcloud projects list
gcloud compute instances list
```

**Azure**:
```bash
az login --service-principal -u <client> -p <secret> --tenant <tenant>
az vm list
az storage account list
```

---

### Check Python Environment

```bash
# Python version
python --version

# Installed packages
pip list

# Virtual environment active?
where python  # Should show venv\Scripts\python.exe

# Check conflicting packages
pip check
```

---

### Reset to Factory Defaults

**Complete Reset** (loses all data):
```cmd
# 1. Uninstall (if using installer)
Settings → Apps → Aegis Cloud Scanner → Uninstall

# 2. Delete user data
rmdir /s "%LOCALAPPDATA%\AegisScanner"

# 3. Delete application data (if manual install)
rmdir /s "C:\Path\To\cloud-security-scanner"

# 4. Reinstall
Download fresh installer from GitHub
```

---

### Collect Diagnostic Information

When reporting issues, include:

1. **System Information**:
```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
python --version
pip --version
```

2. **Application Version**:
```bash
git log -1 --format="%H %s"
```

3. **Log Files**:
```
%LOCALAPPDATA%\AegisScanner\aegis_scanner_debug.log
```

4. **Error Messages**:
- Screenshot of error
- Complete error traceback
- Steps to reproduce

---

## Still Need Help?

### 📧 Email Support
aegis.aws.scanner@gmail.com

### 🐛 Report Bugs
[GitHub Issues](https://github.com/SubashUduwaka/cloud-security-scanner/issues)

**When reporting issues, include**:
- Operating System & version
- Python version
- Installation method (installer/manual)
- Complete error message
- Steps to reproduce
- Log file snippets (remove sensitive data)

### 💬 Community Help
[GitHub Discussions](https://github.com/SubashUduwaka/cloud-security-scanner/discussions)

### 📖 Documentation
- [README](../README.md)
- [FAQ](FAQ.md)
- [Installation Guide](INSTALLATION.md)
- [User Manual](USER_MANUAL.md)

---

<div align="center">

**Aegis Cloud Security Scanner**

*We're here to help!* 🛡️

[⬆ Back to Top](#troubleshooting-guide)

</div>
