# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.7] - 2025-09-09

### Added

-   **Cloud Support**: Core scanning functionality for AWS and GCP.
-   **Authentication**: Full user system including registration, login, email verification, password reset, and 2FA.
-   **Dashboard**: Main dashboard with metrics, charts for security posture, and critical findings breakdown.
-   **Scanning**: On-demand scanning with a real-time progress view option.
-   **History**: View for historical scan results with pagination and filtering.
-   **Settings**: Comprehensive page for managing user profile, security settings (password, 2FA), cloud credentials, and notification preferences.
-   **Admin Panel**: Dashboard for administrators to manage application users, view global scan history, and review audit logs.
-   **Reporting**: Feature to generate and download a PDF report of scan results.
-   **Finding Management**: Ability to suppress individual findings to hide them from future reports.

### Fixed

-   Corrected negative margin on the password strength meter container.
-   Fixed alignment issues with the EULA checkbox on the registration form.