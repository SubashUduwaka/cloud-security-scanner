# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.9.2] - 2025-10-23

### Added

- **Enhanced Logging**: Comprehensive error logging for license key viewing with detailed exception tracking
- **Password Verification Debugging**: Added structured logging for password hash validation debugging
- **Accurate 2FA Statistics**: Security configuration now displays real user 2FA adoption counts and percentages
  - Shows actual users with 2FA enabled vs total users
  - Calculates and displays adoption percentage
  - Located in Admin Panel → Security Configuration

### Changed

- **License Key Password Verification**: Switched from werkzeug.security to Flask-Bcrypt for password verification
  - Now uses `current_user.check_password()` method (Flask-Bcrypt)
  - Matches the password hashing library used during registration
  - Resolves "Invalid bcrypt hash method" errors
- **JavaScript Modal Logic**: Improved license key modal DOM manipulation
  - Better error handling with null checks
  - More reliable button and input hiding after password verification
  - Enhanced console logging for debugging
- **Security Configuration Display**: Updated to show real-time user 2FA statistics instead of just app config

### Fixed

- **License Key Viewing**: Fixed critical password verification bug preventing license key display
  - Root cause: Library mismatch between werkzeug.security and Flask-Bcrypt
  - Impact: Users could not view their license keys after entering password
  - Solution: Use User model's built-in `check_password()` method
  - Location: `app.py:6099-6139`
- **Real-Time Monitoring Notifications**: Removed annoying toast notifications appearing on every page refresh
  - Notifications were showing 3 toasts for real-time features on each page load
  - Now silently enables features with console logging only
  - Location: `static/js/app.js:8032-8040`
- **Database Restore CSRF Protection**: Fixed CSRF token handling for database backup restore
  - Added CSRF token to FormData for file uploads
  - Added X-CSRFToken header to fetch request
  - Resolves "Unexpected token '<'" error during restore
  - Location: `templates/admin.html:1490-1502`
- **License Modal DOM Issues**: Fixed JavaScript errors preventing modal display
  - Incorrect DOM traversal when hiding password input and buttons
  - Added proper modal container reference
  - Added null checks before element manipulation
  - Fixed in both Admin Panel and Settings page
  - Locations: `templates/admin.html:1908-1968`, `templates/settings.html:1203-1263`
- **Login Form Alignment**: Fixed misaligned login form inputs on authentication pages
  - Adjusted `.auth-wrapper` and `.auth-container` CSS
  - Added proper width and box-sizing properties
  - Location: `templates/auth_layout.html:156-177`

### Security

- **Password Verification**: Enhanced password verification security
  - Added validation for empty or null password hashes
  - Added format checking for bcrypt hash structure
  - Comprehensive audit logging for all license view attempts
  - Logs failed attempts with IP addresses
- **Error Handling**: Improved error messages without exposing sensitive details
  - Generic error messages to users
  - Detailed logging to server logs for debugging
  - No password hash exposure in client-side errors

### Technical Improvements

- **Error Messages**: More descriptive error responses for API endpoints
  - Includes exception types in development mode
  - Better user-facing error messages
  - Comprehensive server-side logging
- **Code Quality**: Simplified license viewing route
  - Reduced from 70+ lines to 40 lines
  - Removed redundant hash format validation
  - Leveraged existing User model methods
  - Better separation of concerns

## [v0.9.1] - 2025-10-20

### Added

- **Production WSGI Server**: Replaced Flask development server with production-ready Waitress
  - `run_production.py` - Production server launcher with multi-threading (4 threads)
  - `START_AEGIS_DEV.bat` - Separate development mode launcher for Windows
  - `start_aegis.sh` - Cross-platform launcher for Linux/macOS (production & dev modes)
  - Connection pooling (1000 connections), graceful shutdown, error handling
- **Enterprise Alerts API**: New `/api/v1/enterprise/alerts` endpoint for real-time security alert aggregation
- **Sri Lanka Timezone Support**: Complete timezone support for Sri Lanka (UTC+5:30) across all reporting features
  - PDF reports now display Sri Lanka time with timezone indicator
  - CSV exports include Sri Lanka time conversion
  - Report scheduling dropdown includes Colombo/Sri Lanka timezone option (set as default)
- **Project Organization**: Consolidated project structure with `project_files/` folder
  - Organized documentation by type (markdown, docx, pdf)
  - Centralized archives, installers, scripts, and backups
  - Cleaner root directory for GitHub standards
- **PRODUCTION_SERVER_GUIDE.md**: Comprehensive documentation for production deployment options

### Changed

- **Production Server**: `START_AEGIS.bat` now uses Waitress production server instead of Flask dev server
  - Multi-threaded request handling for better performance
  - Production-ready configuration
  - Supports 100+ concurrent users
- **Dashboard Performance**: Dramatically improved dashboard load time from 10+ seconds to under 1 second
  - Optimized credential loading with dedicated `/api/credentials/missing` endpoint
  - Reduced redundant API calls on page load
  - Streamlined data fetching architecture
- **Enterprise Hub UI**: Removed elliptical status indicator circles from module icons for cleaner appearance
- **Compliance Center Styling**: Enhanced stat box visibility with improved background transparency and backdrop filters
- **Server Architecture**: Hybrid WSGI server approach
  - Windows/Linux/macOS: Waitress (cross-platform)
  - Docker: Gunicorn (optimized for containers)
  - Development: Flask dev server (debugging features)

### Fixed

- **Missing Credentials API**: Resolved 404 error for credentials endpoint causing dashboard delays
- **Enterprise Alerts Loading**: Fixed missing alerts endpoint causing console errors in Enterprise Hub
- **Compliance Stats Visibility**: Fixed transparency issue preventing stat boxes (4, 127, 19) from being visible
- **Chart.js CDN**: Addressed Chart.js loading issues affecting dashboard visualizations

### Project Structure

- **Reorganized Files**: All non-essential files moved to `project_files/` directory
  - `project_files/archives/` - Release builds and installers (.exe, .tar)
  - `project_files/documents/` - Documentation organized by format
  - `project_files/installers/` - Inno Setup installer scripts
  - `project_files/scripts/` - Development and migration scripts
  - `project_files/backups/` - Code backups
- **GitHub Standards**: Root directory maintains only essential source code and GitHub-required files
  - README.md, LICENSE, CHANGELOG.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md
  - Core application files (app.py, config.py, wsgi.py, etc.)
  - Essential folders (scanners, templates, static, tools, licenses, docs)
- **Updated .gitignore**: Simplified to ignore consolidated `project_files/` folder

### Performance

- **Dashboard Load Time**: Reduced from 10+ seconds to <1 second (90% improvement)
- **API Response Time**: Missing credentials check optimized to return instantly
- **Page Rendering**: Eliminated blocking API calls during initial page load

## [v0.9.0] - 2025-10-07

### Added

- **Windows Installer**: First official Windows installer (`AegisCloudScanner_Professional_Setup_v0.8.exe`) with automatic dependency installation
- **GTK3 Runtime Integration**: Automatic GTK3 runtime installation for PDF generation support (WeasyPrint)
- **Desktop Shortcut**: One-click application launch from desktop with custom logo
- **License Generator GUI**: Professional graphical interface for generating Basic/Pro license keys
- **Offline Mode Support**: Credentials can be stored without AWS validation when offline
- **Installer Components**: Professional installer with selectable components (Core, Documentation, Docker)
- **Automatic Python Dependencies**: Installer automatically runs `pip install` for all requirements
- **Administrator Privileges**: Installer enforces admin rights for proper system integration
- **Custom Logo Integration**: Logo.ico integrated into all shortcuts and uninstaller

### Changed

- **Crypto Manager**: Salt file now stored in user AppData directory instead of Program Files
- **AWS Connection**: All boto3 clients now use explicit `us-east-1` region to avoid global endpoint errors
- **Credential Storage**: Enhanced error handling for network failures during credential validation
- **Session Timeout**: Added 5-second timeout for AWS credential validation
- **User Data Directory**: Consistent use of `%LOCALAPPDATA%\AegisScanner` for all user data

### Fixed

- **PermissionError**: Fixed salt file write permission issues in Program Files directory
- **AWS Endpoint Connection**: Resolved `sts.global.amazonaws.com` connection errors by specifying regional endpoints
- **Credential Validation**: Fixed network error handling to allow credential storage in offline mode
- **Inno Setup Compatibility**: Removed unsupported directives for Inno Setup 5.x compatibility
- **Database Path**: Fixed SQLite database path issues in installed applications
- **GTK3 PDF Generation**: PDF reports now work correctly with bundled GTK3 runtime

### Security

- **Non-Writable Installation**: Application files installed in protected Program Files directory
- **User Data Separation**: User-specific data properly isolated in AppData directory
- **Encrypted Credentials**: All credentials encrypted and stored securely in user profile
- **Administrator Installation**: Requires admin privileges preventing unauthorized installations

### Documentation

- **INSTALLER_BUILD_GUIDE.md**: Complete guide for building and testing Windows installers
- **Installation Instructions**: Detailed Python/pip setup and environment variable configuration
- **Cleanup Guide**: Instructions for removing old application versions
- **Docker Deployment**: Updated documentation for upcoming Docker image release

## [v1.0.0] - 2025-10-02

### Added

-   **Azure Support**: Complete scanning functionality for Microsoft Azure environments
-   **Professional License System**: Two-tier licensing (Basic/Pro) with activation, deactivation, and request functionality
-   **License Management**: Dedicated section in Settings for license management with one-time activation
-   **AI Chatbot**: Integrated Gemini AI assistant for security guidance and remediation help
-   **Compliance Center**: Real-time compliance tracking for SOC 2, ISO 27001, GDPR, and HIPAA
-   **Dark Mode**: Complete dark/light theme toggle with persistent state across all pages
-   **Enhanced Notifications**: Customizable email and in-app notifications for scan events
-   **Contact Support**: Integrated support request form with email routing to aegis.aws.scanner@gmail.com
-   **Account Data Management**: Ability to reset all account data with password confirmation
-   **Enhanced Docker Support**: Improved Dockerfile with non-root user, health checks, and optimized configuration

### Changed

-   **License Flow**: Removed confusing version selection from initial setup - all users start as Basic
-   **User Onboarding**: Streamlined initial setup process with better UX
-   **Email System**: Changed email sender to use configured SMTP account with reply-to headers
-   **Settings Page**: Reorganized with dedicated sections for License Management, Notifications, and Support
-   **CSRF Protection**: Unified CSRF handling across all forms using form_name pattern
-   **Database Queries**: Improved SQLAlchemy session handling to prevent session conflicts
-   **Gunicorn Configuration**: Increased workers to 4 with 2 threads for better performance

### Fixed

-   **License Persistence**: Fixed issue where license activation didn't persist to database
-   **SQLAlchemy Session Conflicts**: Resolved session attachment errors during license validation
-   **CSRF Token Errors**: Fixed form session expiration issues on license requests
-   **Contact Form**: Resolved HTTP 500 error caused by missing imports and incorrect email sender
-   **Account Reset**: Fixed password validation for account data reset functionality
-   **Dark Mode UI**: Fixed white cards in compliance center for proper dark mode display
-   **Notification Toggles**: Enhanced styling for better visibility and usability
-   **Dark Mode Toggle**: Improved header toggle appearance with sun/moon icons
-   **Duplicate Routes**: Removed conflicting route definitions causing endpoint conflicts

### Security

-   **Non-Root Container**: Docker container now runs as non-root user (aegis) for improved security
-   **Health Checks**: Added container health monitoring
-   **Session Management**: Enhanced CSRF protection across all forms
-   **Credential Encryption**: All cloud credentials encrypted at rest using Fernet

## [v0.7] - 2025-09-09

### Added

-   **Cloud Support**: Core scanning functionality for AWS and GCP
-   **Authentication**: Full user system including registration, login, email verification, password reset, and 2FA
-   **Dashboard**: Main dashboard with metrics, charts for security posture, and critical findings breakdown
-   **Scanning**: On-demand scanning with a real-time progress view option
-   **History**: View for historical scan results with pagination and filtering
-   **Settings**: Comprehensive page for managing user profile, security settings (password, 2FA), cloud credentials, and notification preferences
-   **Admin Panel**: Dashboard for administrators to manage application users, view global scan history, and review audit logs
-   **Reporting**: Feature to generate and download a PDF report of scan results
-   **Finding Management**: Ability to suppress individual findings to hide them from future reports

### Fixed

-   Corrected negative margin on the password strength meter container
-   Fixed alignment issues with the EULA checkbox on the registration form