# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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