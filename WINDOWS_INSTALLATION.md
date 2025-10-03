# 🪟 Aegis Cloud Scanner - Windows Installation Guide

This guide provides multiple options for running Aegis on Windows.

## 🚀 Quick Start (Easiest Method)

### Option 1: One-Click Launcher (Recommended)

1. **Install Python** (if not already installed):
   - Download from https://www.python.org/downloads/
   - ✅ Check "Add Python to PATH" during installation
   - Install Python 3.8 or higher

2. **Download Aegis**:
   - Clone or download this repository
   - Extract to a folder (e.g., `C:\Aegis`)

3. **Run the Launcher**:
   - Double-click `START_AEGIS.bat`
   - First run will install dependencies (5-10 minutes)
   - Subsequent runs start instantly

4. **Access Aegis**:
   - Open browser to `http://localhost:5000`
   - Complete the setup wizard

---

## 🐳 Option 2: Docker Desktop (Recommended for Production)

### Prerequisites:
- Install Docker Desktop from https://www.docker.com/products/docker-desktop/

### Steps:
```bash
# Open PowerShell or Command Prompt
cd path\to\aegis

# Build the image
docker build -t aegis-scanner .

# Run the container
docker run -d -p 5000:5000 --name aegis aegis-scanner

# Access at http://localhost:5000
```

### Docker Compose (Even Easier):
```bash
docker-compose up -d
```

---

## 💻 Option 3: Manual Installation

### 1. Install Python
- Download Python 3.8+ from https://www.python.org/downloads/
- During installation, check "Add Python to PATH"

### 2. Create Virtual Environment
```bash
# Open PowerShell or Command Prompt
cd path\to\aegis

# Create virtual environment
python -m venv venv

# Activate it
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Application
```bash
python app.py
```

### 4. Access
- Open browser to `http://localhost:5000`

---

## 📦 Option 4: Windows Installer (For Distribution)

Create a professional Windows installer for easy distribution to non-technical users.

### Prerequisites:
- Download and install **Inno Setup** from https://jrsoftware.org/isinfo.php
- Inno Setup is free, open-source, and widely used for Windows installers

### Steps to Create Installer:

1. **Open Inno Setup Compiler**
   - Launch "Inno Setup Compiler" from Start Menu

2. **Load the Script**
   - File → Open → Select `aegis_installer.iss` (included in the project)

3. **Compile the Installer**
   - Build → Compile (or press Ctrl+F9)
   - Wait for compilation to complete (~1-2 minutes)

4. **Find Your Installer**
   - Output folder: `installer_output/`
   - File: `AegisCloudScanner_Setup_v0.8.exe`

### What the Installer Does:

✅ **Checks for Python** - Prompts user to install Python if missing
✅ **Copies all files** - Installs to `C:\Program Files\AegisCloudScanner`
✅ **Creates shortcuts** - Desktop and Start Menu shortcuts
✅ **Professional UI** - Modern wizard-style installation
✅ **Uninstaller** - Clean uninstall support
✅ **Admin rights** - Requests elevation when needed

### Installer Features:

- **Size**: ~2-5 MB (compressed)
- **Install time**: 30-60 seconds
- **Includes**: All application files, documentation, and launcher
- **Shortcuts**: Desktop icon (optional) and Start Menu entry
- **Auto-launch**: Option to run Aegis after installation
- **Uninstall**: Complete removal via Windows Settings

### Distribution:

Share the `AegisCloudScanner_Setup_v0.8.exe` file with users:
1. Users download the setup file
2. Run the installer (requests admin rights)
3. Follow the wizard (Next → Next → Install)
4. Launch Aegis from Desktop or Start Menu
5. Access at `http://localhost:5000`

### For Developers:

The `aegis_installer.iss` script includes:
- Version information
- File associations
- Custom icons
- Python version check
- Post-install messaging
- Clean uninstall procedure

---

## 🛠️ Troubleshooting

### Python Not Found
```
Error: 'python' is not recognized as an internal or external command
```
**Solution**:
- Reinstall Python and check "Add Python to PATH"
- Or use full path: `C:\Python311\python.exe app.py`

### Port Already in Use
```
Error: Address already in use (Port 5000)
```
**Solution**:
- Change port in `app.py`: `app.run(port=8080)`
- Or kill the process using port 5000

### Dependencies Install Failed
```
Error: Could not install packages
```
**Solution**:
- Update pip: `python -m pip install --upgrade pip`
- Run as Administrator
- Check internet connection

### Virtual Environment Issues
```
Error: Cannot activate virtual environment
```
**Solution**:
- Delete `venv` folder
- Run `START_AEGIS.bat` again to recreate

---

## 🔄 Updating Aegis

### Method 1: Git Pull
```bash
git pull origin main
.\venv\Scripts\activate
pip install -r requirements.txt --upgrade
```

### Method 2: Manual
1. Download latest release from GitHub
2. Extract and replace files (keep `instance/` folder for database)
3. Run `START_AEGIS.bat`

---

## 🚦 Running as Windows Service

To run Aegis automatically on Windows startup:

### Using NSSM (Non-Sucking Service Manager):

1. Download NSSM from https://nssm.cc/download
2. Run as Administrator:
```bash
nssm install AegisScanner "C:\path\to\venv\Scripts\python.exe" "C:\path\to\app.py"
nssm start AegisScanner
```

---

## 📊 System Requirements

### Minimum:
- Windows 10/11 or Windows Server 2016+
- Python 3.8+
- 4GB RAM
- 2GB Disk Space
- Internet Connection

### Recommended:
- Windows 11
- Python 3.13
- 8GB+ RAM
- SSD Storage
- Stable Internet

---

## 🎯 Comparison of Methods

| Method | Pros | Cons | Best For |
|--------|------|------|----------|
| **Batch Launcher** | ✅ Easy<br>✅ Fast<br>✅ Updatable<br>✅ Small size | ❌ Needs Python | Most users |
| **Docker** | ✅ Isolated<br>✅ Professional<br>✅ Portable<br>✅ No dependencies | ❌ Needs Docker<br>❌ More setup | Production/Servers |
| **Manual Install** | ✅ Full control<br>✅ Easy debugging | ❌ More steps<br>❌ Needs Python knowledge | Developers |
| **Installer** | ✅ Professional<br>✅ Easy for end users<br>✅ Auto-shortcuts | ❌ Needs Inno Setup to create | Enterprise/Distribution |

---

## 💡 Recommendations

### 👤 For Individual Users (Development/Testing):
→ **Use `START_AEGIS.bat` launcher**
- Easiest setup (just double-click)
- Fast and lightweight
- Easy to update with git pull

### 🏢 For Enterprise/Production Deployment:
→ **Use Docker** or **Windows Service**
- Isolated environment
- Professional deployment
- Easy scaling and management

### 📦 For Software Distribution:
→ **Create Windows Installer with Inno Setup**
- Professional installation experience
- Automatic shortcuts and uninstaller
- Best for sharing with non-technical users
- Only 2-5 MB download size

---

## 📞 Support

Having issues?
- 📧 Email: aegis.aws.scanner@gmail.com
- 📖 Check [User Manual](docs/USER_MANUAL.md)
- 🐛 Report issues: https://github.com/SubashUduwaka/cloud-security-scanner/issues

---

**Made with ❤️ by Subash Dananjaya Uduwaka**
