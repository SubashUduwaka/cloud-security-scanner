# AEGIS CLOUD SCANNER
## COMPREHENSIVE USER MANUAL

**Version:** 1.0
**Document Type:** User Manual
**Classification:** Enterprise Grade
**Target Audience:** End Users, System Administrators, Security Teams
**Document Date:** September 2025

---

## TABLE OF CONTENTS

1. [Introduction](#1-introduction)
2. [System Requirements](#2-system-requirements)
3. [Getting Started](#3-getting-started)
4. [User Authentication & Security](#4-user-authentication--security)
5. [Dashboard Overview](#5-dashboard-overview)
6. [Cloud Credentials Management](#6-cloud-credentials-management)
7. [Security Scanning](#7-security-scanning)
8. [Compliance Management](#8-compliance-management)
9. [Reports & Analytics](#9-reports--analytics)
10. [Settings & Configuration](#10-settings--configuration)
11. [License Management](#11-license-management)
12. [Automation & Scheduling](#12-automation--scheduling)
13. [Advanced Features](#13-advanced-features)
14. [Troubleshooting](#14-troubleshooting)
15. [Security Best Practices](#15-security-best-practices)
16. [Appendix](#16-appendix)

---

## 1. INTRODUCTION

### 1.1 About Aegis Cloud Scanner

Aegis Cloud Scanner is an enterprise-grade multi-cloud security assessment platform designed to provide comprehensive security analysis, vulnerability detection, and compliance monitoring across AWS, Google Cloud Platform (GCP), and Microsoft Azure environments.

**Key Features:**
- Multi-cloud security assessment (AWS, GCP, Azure)
- Real-time vulnerability detection
- Compliance framework monitoring (SOC2, PCI-DSS, GDPR, HIPAA, ISO 27001)
- Advanced reporting and analytics
- Automated security scanning
- Enterprise-grade security controls
- Resource topology mapping
- Performance monitoring

### 1.2 Document Purpose

This manual provides comprehensive instructions for using all features of Aegis Cloud Scanner, from initial setup to advanced enterprise configurations. It is designed to meet industrial and enterprise documentation standards.

### 1.3 Audience

- **End Users:** Security analysts, cloud engineers, DevOps teams
- **System Administrators:** IT administrators responsible for deployment and maintenance
- **Security Teams:** Information security professionals and compliance officers
- **Enterprise Users:** Organizations requiring comprehensive cloud security monitoring

---

## 2. SYSTEM REQUIREMENTS

### 2.1 Supported Browsers

| Browser | Minimum Version | Recommended Version |
|---------|----------------|-------------------|
| Google Chrome | 90+ | Latest |
| Mozilla Firefox | 88+ | Latest |
| Microsoft Edge | 90+ | Latest |
| Safari | 14+ | Latest |

### 2.2 Network Requirements

- **Internet Connection:** Stable broadband connection (minimum 10 Mbps recommended)
- **Firewall:** Allow HTTPS traffic on port 443
- **DNS:** Ensure proper DNS resolution for cloud provider APIs

### 2.3 Cloud Provider Requirements

#### AWS Requirements
- AWS Account with appropriate IAM permissions
- Access to AWS services: EC2, S3, IAM, VPC, RDS, CloudTrail
- Programmatic access enabled (Access Key + Secret Key)

#### Google Cloud Platform Requirements
- GCP Project with billing enabled
- Service Account with appropriate roles
- APIs enabled: Compute Engine, Cloud Storage, IAM, VPC

#### Microsoft Azure Requirements
- Azure Subscription with active billing
- Service Principal with appropriate permissions
- Resource access across subscription

### 2.4 Hardware Requirements (For On-Premise Deployment)

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Storage | 50 GB | 100+ GB SSD |
| Network | 100 Mbps | 1 Gbps |

---

## 3. GETTING STARTED

### 3.1 Account Registration

#### Step 1: Access the Application
1. Navigate to your Aegis Cloud Scanner URL
2. Click on **"Sign Up"** or **"Get Started"**
3. You will be redirected to the registration page

#### Step 2: Registration Process
1. **Enter Account Information:**
   - **Username:** Choose a unique username (3-50 characters)
   - **Email Address:** Enter a valid email address
   - **Password:** Create a strong password (minimum 8 characters)
   - **Confirm Password:** Re-enter your password

2. **Account Verification:**
   - Check your email for a verification link
   - Click the verification link to activate your account
   - Return to the login page

#### Step 3: Initial Login
1. Enter your username/email and password
2. Complete any additional security setup if prompted
3. Access the dashboard

### 3.2 Version Selection

Upon first login, you'll be presented with version options:

#### **BASIC Version (Free)**
- Limited to 10 scans per month
- Basic security scanning
- Standard reports
- Community support

#### **PRO Version (Premium)**
- Unlimited scans
- Advanced compliance features
- Custom reporting
- Priority support
- Enterprise integrations

### 3.3 License Activation (PRO Users)

#### For PRO Version Users:
1. Navigate to **Settings > Account Information**
2. Click **"Upgrade to Pro"** or **"Enter License Key"**
3. Enter your license key in format: `AEGIS-XXXX-XXXX-XXXX-XXXX-XX`
4. Click **"Validate License"**
5. Verify license activation status

#### License Request Process:
1. Click **"Request Pro License"**
2. Fill out the enterprise license request form:
   - Company name
   - Email address
   - License type (Trial/Enterprise)
   - Business justification
3. Submit request for review
4. Receive license key via email (typically 1-2 business days)

---

## 4. USER AUTHENTICATION & SECURITY

### 4.1 Two-Factor Authentication (2FA)

#### Setting Up 2FA:
1. Go to **Settings > Security**
2. Click **"Enable 2FA"**
3. Scan the QR code with your authenticator app:
   - Google Authenticator
   - Microsoft Authenticator
   - Authy
4. Enter the 6-digit verification code
5. Save your recovery codes in a secure location

#### Using 2FA:
1. Enter username and password
2. Enter 6-digit code from your authenticator app
3. Click **"Verify"**

#### Recovery Options:
- Use backup recovery codes
- Contact administrator for reset
- Use backup email verification

### 4.2 Password Management

#### Password Requirements:
- Minimum 8 characters
- Include uppercase and lowercase letters
- Include at least one number
- Include at least one special character
- Cannot be a commonly used password

#### Password Reset:
1. Click **"Forgot Password?"** on login page
2. Enter your email address
3. Check email for reset link
4. Follow instructions to create new password

### 4.3 Session Management

#### Session Features:
- **Auto-logout:** Sessions expire after 30 minutes of inactivity
- **Multiple Sessions:** Concurrent login detection and management
- **Security Monitoring:** Failed login attempt tracking
- **Account Lockout:** Automatic lockout after 5 failed attempts

---

## 5. DASHBOARD OVERVIEW

### 5.1 Dashboard Layout

The main dashboard provides a comprehensive overview of your cloud security posture:

#### Header Section:
- **Logo and Navigation:** Quick access to main features
- **User Menu:** Account settings, logout options
- **Notification Center:** Real-time alerts and updates
- **Date/Time Display:** Current system time and timezone

#### Sidebar Navigation:
- **Dashboard:** Main overview and metrics
- **Scan Results:** Detailed security findings
- **Reports:** Compliance and security reports
- **Compliance:** Framework-specific assessments
- **Resource Map:** Cloud infrastructure topology
- **Performance:** System performance metrics
- **Automation:** Scheduled tasks and rules
- **Scan History:** Historical scan data
- **Enterprise Hub:** Organization-wide features

### 5.2 Key Metrics Display

#### Security Health Score:
- **Overall Score:** Percentage-based security rating (0-100%)
- **Color Coding:**
  - Green (80-100%): Excellent security posture
  - Yellow (60-79%): Good with minor issues
  - Orange (40-59%): Moderate security concerns
  - Red (0-39%): Critical security issues requiring immediate attention

#### Vulnerability Breakdown:
- **Critical:** High-impact vulnerabilities requiring immediate action
- **High:** Significant vulnerabilities requiring prompt attention
- **Medium:** Moderate vulnerabilities for scheduled remediation
- **Low:** Minor vulnerabilities for future consideration

#### Compliance Status:
- **SOC 2:** Service Organization Control 2 compliance percentage
- **PCI DSS:** Payment Card Industry compliance status
- **GDPR:** General Data Protection Regulation compliance
- **HIPAA:** Health Insurance Portability and Accountability Act
- **ISO 27001:** Information Security Management compliance

### 5.3 Recent Activity Feed

Real-time display of:
- Recent scan completions
- New vulnerabilities detected
- Compliance status changes
- System alerts and notifications
- User activity logs

---

## 6. CLOUD CREDENTIALS MANAGEMENT

### 6.1 Adding Cloud Credentials

#### Accessing Credentials Management:
1. Navigate to **Settings > Cloud Credentials**
2. Click **"Add New Credential"**
3. Select your cloud provider

#### AWS Credentials Setup:

**Method 1: Access Keys**
1. Select **"Amazon Web Services (AWS)"**
2. Choose **"Access Key Authentication"**
3. Enter required information:
   - **Credential Name:** Descriptive name for this credential set
   - **Access Key ID:** Your AWS access key ID
   - **Secret Access Key:** Your AWS secret access key
   - **Default Region:** Primary AWS region (e.g., us-east-1)
   - **Description:** Optional description of this credential

**Method 2: IAM Role (Recommended for Production)**
1. Select **"IAM Role Authentication"**
2. Enter:
   - **Role ARN:** Amazon Resource Name of the IAM role
   - **External ID:** External ID for additional security
   - **Session Name:** Descriptive session name

**Required AWS Permissions:**
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "s3:GetBucketLocation",
                "s3:GetBucketLogging",
                "s3:GetBucketVersioning",
                "s3:GetBucketAcl",
                "iam:List*",
                "iam:Get*",
                "rds:Describe*",
                "cloudtrail:Describe*",
                "vpc:Describe*"
            ],
            "Resource": "*"
        }
    ]
}
```

#### Google Cloud Platform Credentials:

**Service Account Setup:**
1. Select **"Google Cloud Platform (GCP)"**
2. Upload or paste your service account JSON key:
   - **Project ID:** Your GCP project identifier
   - **Service Account Key:** JSON key file content
   - **Default Region:** Primary GCP region

**Required GCP Roles:**
- Security Reviewer
- Compute Viewer
- Storage Object Viewer
- IAM Security Reviewer

#### Microsoft Azure Credentials:

**Service Principal Setup:**
1. Select **"Microsoft Azure"**
2. Enter authentication details:
   - **Tenant ID:** Azure Active Directory tenant ID
   - **Client ID:** Application (client) ID
   - **Client Secret:** Application client secret
   - **Subscription ID:** Azure subscription ID

**Required Azure Permissions:**
- Security Reader
- Reader
- Network Contributor (read-only)

### 6.2 Credential Validation

#### Automatic Validation:
1. After entering credentials, click **"Test Connection"**
2. The system performs validation checks:
   - Authentication verification
   - Permission validation
   - Service accessibility
   - Region availability

#### Validation Results:
- ✅ **Success:** Credentials validated and ready for scanning
- ⚠️ **Warning:** Credentials valid but with limited permissions
- ❌ **Error:** Invalid credentials or insufficient permissions

### 6.3 Managing Existing Credentials

#### Viewing Credentials:
- **Credential List:** All configured credentials with status indicators
- **Last Used:** Timestamp of most recent scan using these credentials
- **Status:** Active, Inactive, or Error status
- **Scan Count:** Number of scans performed with these credentials

#### Editing Credentials:
1. Click **"Edit"** next to the credential
2. Modify required fields
3. Click **"Update"** to save changes
4. Re-validation is performed automatically

#### Deleting Credentials:
1. Click **"Delete"** next to the credential
2. Confirm deletion in the popup dialog
3. **Warning:** This action cannot be undone and will affect historical scan data

---

## 7. SECURITY SCANNING

### 7.1 Initiating Security Scans

#### Quick Scan (Default):
1. Navigate to the **Dashboard**
2. Click **"Start New Scan"**
3. Select credentials to scan
4. Choose scan type:
   - **Quick Scan:** Essential security checks (5-10 minutes)
   - **Comprehensive Scan:** Full security assessment (15-30 minutes)
   - **Custom Scan:** Select specific services and checks

#### Advanced Scan Configuration:
1. Click **"Advanced Scan Options"**
2. Configure scan parameters:
   - **Services to Scan:** Select specific cloud services
   - **Regions:** Choose geographical regions to include
   - **Compliance Frameworks:** Select relevant frameworks
   - **Severity Levels:** Define minimum severity to report
   - **Scan Depth:** Surface-level or deep inspection

### 7.2 Scan Types

#### **Quick Scan**
- **Duration:** 5-10 minutes
- **Coverage:** Critical security configurations
- **Services:** Core services (Compute, Storage, IAM)
- **Use Case:** Regular monitoring and quick assessments

#### **Comprehensive Scan**
- **Duration:** 15-30 minutes
- **Coverage:** Full security assessment across all services
- **Services:** All accessible cloud services
- **Use Case:** Periodic thorough security reviews

#### **Custom Scan**
- **Duration:** Variable based on selection
- **Coverage:** User-defined scope
- **Services:** Selected services only
- **Use Case:** Targeted assessments and specific compliance checks

#### **Compliance Scan**
- **Duration:** 10-20 minutes
- **Coverage:** Framework-specific requirements
- **Services:** Compliance-relevant services
- **Use Case:** Regulatory compliance validation

### 7.3 Monitoring Scan Progress

#### Real-Time Progress Tracking:
- **Progress Bar:** Visual indication of scan completion
- **Current Activity:** Real-time display of scanning activity
- **Service Status:** Per-service scanning progress
- **Estimated Time:** Remaining time to completion

#### Scan Activity Log:
- Detailed logging of all scan activities
- Error reporting and resolution suggestions
- Performance metrics and timing data

### 7.4 Understanding Scan Results

#### Results Overview:
After scan completion, you'll see:
- **Executive Summary:** High-level security posture
- **Vulnerability Count:** Breakdown by severity
- **Compliance Scores:** Framework-specific ratings
- **Risk Assessment:** Overall risk evaluation

#### Detailed Findings:
1. Navigate to **Scan Results** tab
2. Review findings by:
   - **Severity Level:** Critical, High, Medium, Low
   - **Service Type:** Organized by cloud service
   - **Compliance Framework:** Grouped by regulatory requirement
   - **Resource Type:** Specific resource categories

#### Finding Details:
Each finding includes:
- **Description:** Clear explanation of the security issue
- **Risk Level:** Impact assessment
- **Affected Resources:** Specific resources with the issue
- **Remediation Steps:** Step-by-step resolution instructions
- **Compliance Impact:** Affected compliance frameworks
- **References:** Links to security best practices and documentation

---

## 8. COMPLIANCE MANAGEMENT

### 8.1 Supported Compliance Frameworks

Aegis Cloud Scanner supports major compliance frameworks:

#### **SOC 2 (Service Organization Control 2)**
- **Focus:** Security, availability, processing integrity, confidentiality, privacy
- **Common Controls:** Access controls, system monitoring, encryption
- **Reporting:** Trust service criteria compliance

#### **PCI DSS (Payment Card Industry Data Security Standard)**
- **Focus:** Payment card data protection
- **Requirements:** 12 core requirements across 6 control objectives
- **Reporting:** Compliance percentage and gap analysis

#### **GDPR (General Data Protection Regulation)**
- **Focus:** Personal data protection and privacy
- **Requirements:** Data protection principles and individual rights
- **Reporting:** Privacy compliance and data handling assessment

#### **HIPAA (Health Insurance Portability and Accountability Act)**
- **Focus:** Protected health information (PHI) security
- **Requirements:** Administrative, physical, and technical safeguards
- **Reporting:** Healthcare compliance assessment

#### **ISO 27001 (Information Security Management)**
- **Focus:** Information security management systems
- **Controls:** 114 security controls across 14 domains
- **Reporting:** Information security maturity assessment

### 8.2 Compliance Dashboard

#### Accessing Compliance Features:
1. Navigate to **Compliance** section from sidebar
2. Select desired compliance framework
3. Review compliance status and recommendations

#### Compliance Metrics:
- **Overall Compliance Score:** Percentage compliance with framework
- **Control Implementation:** Status of individual controls
- **Gap Analysis:** Areas requiring attention
- **Trend Analysis:** Compliance score over time

### 8.3 Compliance Reporting

#### Generating Compliance Reports:
1. Go to **Reports > Compliance Reports**
2. Select compliance framework
3. Choose report format (PDF, Excel, CSV)
4. Configure report parameters:
   - **Date Range:** Historical compliance data
   - **Scope:** Specific services or resources
   - **Detail Level:** Executive or technical detail
5. Click **"Generate Report"**

#### Report Contents:
- **Executive Summary:** High-level compliance overview
- **Control Assessment:** Individual control evaluation
- **Risk Assessment:** Compliance-related risks
- **Remediation Plan:** Step-by-step improvement plan
- **Evidence Collection:** Supporting documentation
- **Action Items:** Prioritized remediation tasks

### 8.4 Continuous Compliance Monitoring

#### Automated Compliance Tracking:
- **Daily Monitoring:** Continuous compliance score tracking
- **Change Detection:** Alert on compliance status changes
- **Drift Prevention:** Automated detection of configuration drift
- **Trend Analysis:** Historical compliance performance

#### Compliance Alerts:
Configure notifications for:
- Compliance score degradation
- Critical control failures
- New compliance risks
- Remediation task completion

---

## 9. REPORTS & ANALYTICS

### 9.1 Report Types

#### **Executive Summary Report**
- **Audience:** Senior management and executives
- **Content:** High-level security posture overview
- **Format:** Executive dashboard with key metrics
- **Frequency:** Weekly or monthly

#### **Technical Security Report**
- **Audience:** Security teams and engineers
- **Content:** Detailed vulnerability findings and remediation steps
- **Format:** Technical documentation with code examples
- **Frequency:** After each scan or on-demand

#### **Compliance Report**
- **Audience:** Compliance officers and auditors
- **Content:** Framework-specific compliance assessment
- **Format:** Structured compliance documentation
- **Frequency:** Quarterly or for audit purposes

#### **Comprehensive Report**
- **Audience:** All stakeholders
- **Content:** Complete security assessment including all findings
- **Format:** Multi-section detailed report
- **Frequency:** Monthly or quarterly

### 9.2 Generating Reports

#### Report Generation Process:
1. Navigate to **Reports** section
2. Click **"Generate New Report"**
3. Configure report parameters:

**Basic Configuration:**
- **Report Type:** Select from available report types
- **Output Format:** PDF, Excel, CSV, or HTML
- **Date Range:** Historical data to include
- **Credentials:** Select which cloud accounts to include

**Advanced Configuration:**
- **Severity Filter:** Minimum severity level to include
- **Service Filter:** Specific cloud services to cover
- **Compliance Filter:** Specific frameworks to assess
- **Custom Branding:** Add company logo and branding

#### Report Customization:
- **Custom Logo:** Upload company logo for branded reports
- **Color Scheme:** Match corporate branding guidelines
- **Executive Summary:** Include/exclude executive overview
- **Technical Details:** Adjust level of technical detail
- **Remediation Steps:** Include detailed remediation guidance

### 9.3 Scheduled Reports

#### Setting Up Automated Reports:
1. Go to **Reports > Scheduled Reports**
2. Click **"Create New Schedule"**
3. Configure schedule parameters:

**Schedule Configuration:**
- **Report Type:** Select report template
- **Frequency:** Daily, Weekly, Monthly, or Custom
- **Time of Day:** Preferred delivery time
- **Timezone:** Local timezone for delivery
- **Day of Week/Month:** Specific delivery days

**Delivery Configuration:**
- **Email Recipients:** Multiple email addresses supported
- **Email Subject:** Custom subject line template
- **Email Body:** Custom message template
- **Delivery Format:** Attached file or embedded content

#### Time Zone Support:
- **Global Time Zones:** Support for all major time zones
- **Daylight Saving Time:** Automatic DST adjustment
- **Custom Scheduling:** Flexible scheduling options

#### Testing Scheduled Reports:
1. Click **"Test Delivery"** button
2. Monitor test progress in real-time
3. Verify email delivery and content
4. Confirm report formatting and data accuracy

### 9.4 Report Analytics

#### Performance Metrics:
- **Report Generation Time:** Average time to generate reports
- **Delivery Success Rate:** Email delivery success percentage
- **User Engagement:** Report open and interaction rates
- **Historical Trends:** Long-term security posture trends

#### Data Export Options:
- **Raw Data Export:** CSV format for further analysis
- **API Access:** Programmatic access to report data
- **Integration Support:** Connect with SIEM and analytics platforms

---

## 10. SETTINGS & CONFIGURATION

### 10.1 User Profile Settings

#### Accessing Profile Settings:
1. Click on **user menu** in top-right corner
2. Select **"Settings"**
3. Navigate to **"Profile"** tab

#### Profile Information:
- **Display Name:** Your preferred display name
- **Email Address:** Primary email (requires verification to change)
- **Backup Email:** Secondary email for account recovery
- **Phone Number:** Optional phone number for notifications
- **Time Zone:** Local time zone for scheduling and reports
- **Language Preference:** Interface language selection

#### Profile Security:
- **Password Change:** Update account password
- **Two-Factor Authentication:** Enable/disable 2FA
- **Recovery Codes:** Generate new backup codes
- **Active Sessions:** View and manage active login sessions

### 10.2 Notification Settings

#### Email Notifications:
Configure notifications for:
- **Scan Completion:** Receive email when scans complete
- **Critical Findings:** Immediate alerts for critical vulnerabilities
- **Compliance Changes:** Notifications when compliance status changes
- **Scheduled Reports:** Delivery confirmations for automated reports
- **System Maintenance:** Planned maintenance notifications

#### Notification Preferences:
- **Frequency:** Immediate, Daily digest, or Weekly summary
- **Severity Threshold:** Minimum severity level for notifications
- **Quiet Hours:** Time periods to suppress non-critical notifications
- **Mobile Notifications:** Push notifications for mobile devices

#### Integration Settings:
- **Slack Integration:** Send notifications to Slack channels
- **Microsoft Teams:** Send alerts to Teams channels
- **Webhook URLs:** Custom webhook endpoints for integration
- **Email Templates:** Customize notification email templates

### 10.3 Security Settings

#### Access Control:
- **Session Timeout:** Configure automatic logout time
- **IP Restrictions:** Limit access to specific IP addresses
- **Device Management:** View and manage trusted devices
- **Login Monitoring:** Track login attempts and locations

#### Data Security:
- **Data Encryption:** Configure encryption settings
- **Data Retention:** Set data retention policies
- **Export Controls:** Manage data export permissions
- **Audit Logging:** Configure audit log retention

### 10.4 Account Information

#### Subscription Status:
View current subscription details:
- **Account Type:** BASIC or PRO version
- **License Key:** Current license information (PRO users)
- **Validity Period:** License expiration date
- **Usage Statistics:** Current month usage summary
- **Feature Access:** Available features based on subscription

#### Usage Monitoring:
- **Scan Count:** Number of scans performed this month
- **Data Transfer:** Amount of data processed
- **Storage Usage:** Report and data storage consumption
- **API Calls:** Number of API requests made

#### Billing Information (PRO Users):
- **Billing Address:** Company billing information
- **Payment Method:** Current payment method on file
- **Billing History:** Previous invoices and payments
- **Usage Reports:** Detailed usage analytics for billing

---

## 11. LICENSE MANAGEMENT

### 11.1 License Types

#### **BASIC License (Free)**
- **Monthly Scans:** 10 scans per month
- **Features:** Basic security scanning and standard reports
- **Support:** Community support through documentation
- **Compliance:** Basic compliance checking
- **Users:** Single user account

#### **PRO License (Premium)**
- **Monthly Scans:** Unlimited scanning
- **Features:** All advanced features including:
  - Advanced compliance frameworks
  - Custom reporting and branding
  - Automated scheduling
  - Priority support
  - Enterprise integrations
- **Support:** Email and phone support with SLA
- **Users:** Multiple user accounts (organization-dependent)

### 11.2 License Activation

#### PRO License Activation Process:
1. Navigate to **Settings > Account Information**
2. Click **"Upgrade to PRO"** or **"Enter License Key"**
3. Enter license key in the format: `AEGIS-XXXX-XXXX-XXXX-XXXX-XX`
4. Click **"Validate License"**
5. Confirm activation and new feature access

#### License Key Format:
- **Format:** AEGIS-XXXX-XXXX-XXXX-XXXX-XX
- **Components:**
  - AEGIS: Product identifier
  - XXXX-XXXX-XXXX-XXXX: Unique license identifier
  - XX: Checksum for validation

#### License Validation:
The system validates:
- License key format and checksum
- License expiration date
- User email association
- Organization entitlements

### 11.3 License Request Process

#### Requesting Enterprise License:
1. Click **"Request Pro License"** from account settings
2. Fill out enterprise license request form:
   - **Company Name:** Your organization name
   - **Email Address:** Primary contact email
   - **License Type:** Select from available options:
     - 7-Day Trial
     - 30-Day Trial
     - 1-Year License
     - Multi-Year License
   - **User Count:** Number of users requiring access
   - **Message:** Business justification and requirements

3. Submit request for review
4. Receive license key via email (typically 1-2 business days)

#### License Types Available:
- **TRIAL:** Short-term evaluation license (7-30 days)
- **ENTERPRISE:** Full-featured annual license
- **ACADEMIC:** Educational institution discounts
- **GOVERNMENT:** Government agency licensing
- **CUSTOM:** Specialized enterprise requirements

### 11.4 License Monitoring

#### License Status Monitoring:
- **Expiration Alerts:** Advance warning before license expiration
- **Usage Tracking:** Monitor license utilization across organization
- **Compliance Status:** Ensure license compliance with terms
- **Renewal Reminders:** Automated renewal notifications

#### License Administration (Enterprise):
- **User Management:** Add/remove users under license
- **Feature Control:** Enable/disable features by user
- **Usage Reports:** Detailed license usage analytics
- **Billing Integration:** Connect with enterprise billing systems

---

## 12. AUTOMATION & SCHEDULING

### 12.1 Automated Scanning

#### Setting Up Automated Scans:
1. Navigate to **Automation** section from dashboard sidebar
2. Click **"Create New Automation Rule"**
3. Configure automation parameters:

**Basic Automation:**
- **Rule Name:** Descriptive name for the automation
- **Trigger Type:** Time-based or event-based triggers
- **Scan Type:** Quick, Comprehensive, or Custom scan
- **Target Credentials:** Which cloud accounts to scan

**Advanced Scheduling:**
- **Frequency Options:**
  - Daily: Specify time of day
  - Weekly: Choose day of week and time
  - Monthly: Select date and time
  - Custom: Cron expression for complex schedules
- **Time Zone:** Local time zone for scheduling
- **Holiday Calendar:** Skip scans on holidays

#### Automation Rules Examples:
```
Daily Security Scan:
- Frequency: Daily at 2:00 AM
- Type: Quick Scan
- Target: All production credentials
- Notifications: Email on critical findings

Weekly Compliance Check:
- Frequency: Every Sunday at 6:00 AM
- Type: Compliance Scan
- Target: All cloud accounts
- Frameworks: SOC2, PCI-DSS
- Report: Auto-generate compliance report

Monthly Comprehensive Review:
- Frequency: First Monday of month at 1:00 AM
- Type: Comprehensive Scan
- Target: All credentials
- Notifications: Full report to security team
```

### 12.2 Automated Reporting

#### Report Automation Setup:
1. Go to **Reports > Scheduled Reports**
2. Click **"Create New Schedule"**
3. Configure report automation:

**Report Configuration:**
- **Report Type:** Executive, Technical, Compliance, or Comprehensive
- **Format:** PDF, Excel, CSV
- **Recipients:** Email addresses for delivery
- **Subject Template:** Custom email subject

**Schedule Configuration:**
- **Delivery Frequency:** Daily, Weekly, Monthly, Quarterly
- **Delivery Time:** Preferred time for report generation
- **Time Zone Selection:** Global time zone support
- **Custom Scheduling:** Advanced cron-based scheduling

#### Advanced Scheduling Features:
- **Conditional Delivery:** Only send reports if findings meet criteria
- **Dynamic Recipients:** Recipient lists based on findings severity
- **Template Customization:** Custom report templates and branding
- **Multi-Format Delivery:** Send same report in multiple formats

### 12.3 Event-Based Automation

#### Trigger Types:
- **New Critical Finding:** Automated response to critical vulnerabilities
- **Compliance Score Drop:** Actions when compliance scores decrease
- **Failed Scan:** Notification and retry logic for failed scans
- **Credential Issues:** Automated handling of credential problems

#### Automated Responses:
- **Notification Escalation:** Progressive notification to stakeholders
- **Ticket Creation:** Automatic creation of remediation tickets
- **Report Generation:** On-demand reports for specific events
- **Integration Triggers:** Webhook calls to external systems

### 12.4 Automation Monitoring

#### Automation Dashboard:
- **Active Rules:** Currently configured automation rules
- **Execution History:** Past automation executions and results
- **Success Rates:** Reliability metrics for automated tasks
- **Performance Metrics:** Execution time and resource usage

#### Automation Logs:
- **Execution Details:** Step-by-step automation execution logs
- **Error Handling:** Failed automation troubleshooting
- **Performance Data:** Timing and resource consumption metrics
- **Success Confirmation:** Verification of completed automated tasks

---

## 13. ADVANCED FEATURES

### 13.1 Resource Topology Mapping

#### Accessing Resource Maps:
1. Navigate to **Resource Map** from dashboard sidebar
2. Select cloud provider and credentials
3. Choose visualization type:
   - **Network Topology:** VPC and network visualization
   - **Service Dependencies:** Service interconnection mapping
   - **Security Groups:** Security rule visualization
   - **Data Flow:** Data movement and storage mapping

#### Interactive Features:
- **Zoom and Pan:** Navigate large infrastructure maps
- **Filter Options:** Show/hide specific resource types
- **Security Overlay:** Highlight security issues on topology
- **Click-through Details:** Detailed information for each resource

#### Export Options:
- **Image Export:** PNG/SVG for documentation
- **Data Export:** JSON/CSV for further analysis
- **Report Integration:** Include maps in automated reports

### 13.2 Performance Monitoring

#### Performance Metrics:
- **Resource Utilization:** CPU, memory, storage usage
- **Network Performance:** Bandwidth and latency metrics
- **Cost Analysis:** Resource cost optimization opportunities
- **Capacity Planning:** Growth and scaling recommendations

#### Performance Dashboard:
- **Real-time Monitoring:** Live performance data
- **Historical Trends:** Long-term performance analysis
- **Alerting:** Performance-based alert configuration
- **Benchmarking:** Compare against industry standards

### 13.3 Enterprise Hub

#### Organization Management:
- **Multi-tenant Support:** Multiple organization management
- **User Hierarchy:** Role-based access control across teams
- **Centralized Billing:** Consolidated licensing and billing
- **Policy Management:** Organization-wide security policies

#### Administrative Features:
- **User Provisioning:** Automated user account management
- **Access Control:** Granular permission management
- **Audit Logging:** Comprehensive audit trail
- **Compliance Reporting:** Organization-wide compliance status

### 13.4 API Access

#### API Documentation:
- **REST API:** RESTful API for all major functions
- **Authentication:** API key-based authentication
- **Rate Limiting:** Request rate limits and quotas
- **Error Handling:** Comprehensive error response codes

#### Integration Examples:
```bash
# Start a security scan
curl -X POST "https://api.aegisscanner.com/v1/scans" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"credential_id": "123", "scan_type": "comprehensive"}'

# Get scan results
curl -X GET "https://api.aegisscanner.com/v1/scans/456/results" \
  -H "Authorization: Bearer YOUR_API_KEY"

# Generate compliance report
curl -X POST "https://api.aegisscanner.com/v1/reports" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"type": "compliance", "framework": "SOC2", "format": "pdf"}'
```

---

## 14. TROUBLESHOOTING

### 14.1 Common Issues and Solutions

#### **Login Issues**

**Problem:** Cannot log in to account
**Solutions:**
1. Verify username/email and password
2. Check for account lockout (wait 15 minutes or contact admin)
3. Clear browser cache and cookies
4. Try different browser or incognito mode
5. Reset password if necessary

**Problem:** Two-factor authentication not working
**Solutions:**
1. Ensure device clock is synchronized
2. Try backup recovery codes
3. Regenerate QR code if authenticator was reset
4. Contact support for account recovery

#### **Credential Issues**

**Problem:** Cloud credentials failing validation
**Solutions:**
1. Verify credentials are correct and active
2. Check IAM permissions match requirements
3. Ensure API services are enabled (GCP)
4. Verify subscription is active (Azure)
5. Test credentials directly with cloud provider CLI

**Problem:** Partial scan results or missing services
**Solutions:**
1. Review IAM permissions for all required services
2. Check regional availability of services
3. Verify service quotas and limits
4. Ensure billing is enabled for cloud account

#### **Scanning Problems**

**Problem:** Scan fails to start or complete
**Solutions:**
1. Check credential validity and permissions
2. Verify internet connectivity
3. Review scan configuration for errors
4. Check for service outages or maintenance
5. Try simplified scan scope

**Problem:** Slow scan performance
**Solutions:**
1. Reduce scan scope to specific regions/services
2. Schedule scans during off-peak hours
3. Check network connectivity and bandwidth
4. Consider upgrading account for priority processing

#### **Report Generation Issues**

**Problem:** Reports fail to generate
**Solutions:**
1. Ensure sufficient scan data is available
2. Check date range settings
3. Verify report template compatibility
4. Try different output format
5. Contact support for large report generation

**Problem:** Scheduled reports not delivering
**Solutions:**
1. Verify email addresses are correct
2. Check spam/junk folders
3. Confirm SMTP settings (on-premise deployments)
4. Test email delivery manually
5. Review automation logs for errors

### 14.2 Error Messages

#### **Authentication Errors**
- `AUTH_001`: Invalid credentials
- `AUTH_002`: Account locked due to failed attempts
- `AUTH_003`: Two-factor authentication required
- `AUTH_004`: Session expired
- `AUTH_005`: Insufficient permissions

#### **Credential Errors**
- `CRED_001`: Invalid AWS access key or secret
- `CRED_002`: GCP service account key invalid
- `CRED_003`: Azure authentication failure
- `CRED_004`: Insufficient IAM permissions
- `CRED_005`: Service quota exceeded

#### **Scan Errors**
- `SCAN_001`: No credentials available for scanning
- `SCAN_002`: Scan quota exceeded for current month
- `SCAN_003`: Service temporarily unavailable
- `SCAN_004`: Invalid scan configuration
- `SCAN_005`: Network connectivity error

### 14.3 Performance Optimization

#### **Browser Performance**
1. **Clear Cache:** Regularly clear browser cache and cookies
2. **Disable Extensions:** Temporarily disable browser extensions
3. **Update Browser:** Use latest browser version
4. **Memory Management:** Close unnecessary browser tabs
5. **Hardware Acceleration:** Enable hardware acceleration in browser

#### **Network Optimization**
1. **Bandwidth:** Ensure sufficient internet bandwidth (10+ Mbps)
2. **Latency:** Use servers closest to your geographic location
3. **Firewall:** Configure firewall to allow required traffic
4. **DNS:** Use fast, reliable DNS servers (8.8.8.8, 1.1.1.1)

#### **Account Optimization**
1. **Credential Management:** Remove unused or duplicate credentials
2. **Scan Scope:** Optimize scan scope for faster results
3. **Report Scheduling:** Distribute automated reports across time
4. **Data Cleanup:** Regular cleanup of old scan and report data

### 14.4 Getting Support

#### **Self-Service Resources**
- **Knowledge Base:** Comprehensive FAQ and troubleshooting guides
- **Video Tutorials:** Step-by-step video instructions
- **Community Forum:** User community for peer support
- **API Documentation:** Complete API reference and examples

#### **Professional Support (PRO Users)**
- **Email Support:** support@aegisscanner.com
- **Response Time:** 24-48 hours for standard issues
- **Priority Support:** 4-8 hours for critical issues
- **Phone Support:** Available during business hours
- **Screen Sharing:** Remote assistance for complex issues

#### **Support Ticket Information**
When contacting support, please include:
- Account username or email
- Detailed description of the issue
- Steps to reproduce the problem
- Browser type and version
- Screenshot or error message
- Recent changes to configuration

---

## 15. SECURITY BEST PRACTICES

### 15.1 Account Security

#### **Strong Authentication**
- Use complex passwords with minimum 12 characters
- Enable two-factor authentication (2FA) immediately
- Store recovery codes in secure password manager
- Regularly review and update authentication settings
- Monitor login activity for suspicious access

#### **Access Management**
- Follow principle of least privilege for cloud credentials
- Regularly rotate cloud access keys and secrets
- Use IAM roles instead of access keys when possible
- Implement IP-based access restrictions where appropriate
- Review and audit user permissions quarterly

#### **Session Security**
- Always log out when finished using the application
- Don't use shared computers for sensitive operations
- Enable automatic session timeout
- Clear browser data after use on public computers
- Monitor active sessions and terminate unused sessions

### 15.2 Cloud Credential Security

#### **AWS Security Best Practices**
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "s3:GetBucket*",
                "iam:List*",
                "iam:Get*",
                "rds:Describe*"
            ],
            "Resource": "*",
            "Condition": {
                "DateLessThan": {
                    "aws:CurrentTime": "2024-12-31T23:59:59Z"
                }
            }
        }
    ]
}
```

#### **GCP Security Best Practices**
- Use service accounts with minimal required roles
- Enable audit logging for all API calls
- Implement resource-level IAM where possible
- Regular key rotation (90 days maximum)
- Monitor service account usage

#### **Azure Security Best Practices**
- Use managed identities when possible
- Implement conditional access policies
- Enable Azure AD security defaults
- Regular access reviews for service principals
- Monitor authentication and authorization logs

### 15.3 Data Protection

#### **Data Classification**
- **Public:** Non-sensitive operational data
- **Internal:** Business-sensitive information
- **Confidential:** Regulated or proprietary data
- **Restricted:** Highly sensitive security data

#### **Data Handling Guidelines**
- Encrypt sensitive data in transit and at rest
- Implement data retention policies
- Regular backup and recovery testing
- Secure data disposal procedures
- Access logging and monitoring

#### **Privacy Considerations**
- Minimize collection of personal data
- Implement data subject access rights (GDPR)
- Regular privacy impact assessments
- Clear data processing notifications
- Consent management procedures

### 15.4 Operational Security

#### **Change Management**
- Document all configuration changes
- Test changes in non-production environments
- Implement approval workflows for critical changes
- Maintain change logs and audit trails
- Regular configuration backup and versioning

#### **Incident Response**
- Establish incident response procedures
- Define escalation criteria and contacts
- Regular incident response plan testing
- Post-incident review and improvement
- Communication protocols for stakeholders

#### **Monitoring and Alerting**
- Implement comprehensive security monitoring
- Define clear alerting thresholds
- Regular review of security logs
- Automated threat detection where possible
- Integration with SIEM platforms

---

## 16. APPENDIX

### 16.1 Compliance Framework Details

#### **SOC 2 Framework**
**Trust Service Categories:**
- **Security:** Protection against unauthorized access
- **Availability:** System operational availability
- **Processing Integrity:** Complete and accurate processing
- **Confidentiality:** Confidential information protection
- **Privacy:** Personal information collection and usage

**Common Criteria:**
- CC1.0: Control Environment
- CC2.0: Communication and Information
- CC3.0: Risk Assessment
- CC4.0: Monitoring Activities
- CC5.0: Control Activities

#### **PCI DSS Requirements**
1. Install and maintain firewall configuration
2. Do not use vendor-supplied defaults for passwords
3. Protect stored cardholder data
4. Encrypt transmission of cardholder data
5. Use and regularly update anti-virus software
6. Develop and maintain secure systems
7. Restrict access to cardholder data by business need
8. Assign unique ID to each person with computer access
9. Restrict physical access to cardholder data
10. Track and monitor all network access
11. Regularly test security systems and processes
12. Maintain information security policy

#### **GDPR Articles**
- **Article 5:** Principles relating to processing
- **Article 6:** Lawfulness of processing
- **Article 7:** Conditions for consent
- **Article 13:** Information to be provided
- **Article 17:** Right to erasure
- **Article 25:** Data protection by design
- **Article 32:** Security of processing
- **Article 33:** Notification of data breach

### 16.2 Cloud Service Coverage

#### **AWS Services Scanned**
- **Compute:** EC2, ECS, EKS, Lambda, Elastic Beanstalk
- **Storage:** S3, EBS, EFS, FSx
- **Database:** RDS, DynamoDB, DocumentDB, ElastiCache
- **Networking:** VPC, CloudFront, Route 53, Load Balancers
- **Security:** IAM, CloudTrail, Config, GuardDuty
- **Management:** CloudWatch, Systems Manager, Trusted Advisor

#### **GCP Services Scanned**
- **Compute:** Compute Engine, GKE, App Engine, Cloud Functions
- **Storage:** Cloud Storage, Persistent Disk, Filestore
- **Database:** Cloud SQL, Cloud Spanner, Datastore, Firestore
- **Networking:** VPC, Cloud Load Balancing, Cloud CDN
- **Security:** IAM, Cloud Security Command Center, Cloud KMS
- **Management:** Cloud Monitoring, Cloud Logging, Cloud Deployment Manager

#### **Azure Services Scanned**
- **Compute:** Virtual Machines, AKS, App Service, Functions
- **Storage:** Blob Storage, Disk Storage, File Storage
- **Database:** SQL Database, Cosmos DB, Database for MySQL/PostgreSQL
- **Networking:** Virtual Network, Load Balancer, Application Gateway
- **Security:** Azure Active Directory, Key Vault, Security Center
- **Management:** Monitor, Resource Manager, Automation

### 16.3 Security Check Categories

#### **Identity and Access Management**
- Multi-factor authentication enforcement
- Password policy compliance
- Privileged access management
- Service account security
- API key management
- Role-based access control

#### **Network Security**
- Security group configuration
- Network access control lists
- VPN configuration
- Firewall rules
- DNS security
- Load balancer security

#### **Data Protection**
- Encryption at rest
- Encryption in transit
- Key management
- Backup encryption
- Data classification
- Access logging

#### **Logging and Monitoring**
- Audit trail configuration
- Log retention policies
- Monitoring coverage
- Alerting configuration
- Incident response
- Security information management

#### **Configuration Management**
- Security baseline compliance
- Patch management
- Configuration drift detection
- Hardening standards
- Change management
- Version control

### 16.4 Integration Endpoints

#### **Webhook Integration**
```json
{
    "event_type": "scan_completed",
    "timestamp": "2024-09-23T19:55:38Z",
    "scan_id": "scan_123456",
    "account_id": "user_789",
    "credentials": "aws_prod_account",
    "summary": {
        "total_checks": 150,
        "critical": 2,
        "high": 5,
        "medium": 12,
        "low": 8,
        "compliance_score": 85
    },
    "findings": [
        {
            "id": "finding_001",
            "severity": "critical",
            "title": "Public S3 bucket with sensitive data",
            "description": "...",
            "resource": "arn:aws:s3:::my-bucket",
            "remediation": "..."
        }
    ]
}
```

#### **SIEM Integration**
- **Splunk:** HTTP Event Collector endpoint
- **Elastic:** Elasticsearch index integration
- **LogRhythm:** SmartResponse plugin
- **QRadar:** DSM integration
- **ArcSight:** CEF format logging

#### **Ticketing System Integration**
- **Jira:** Automatic issue creation for findings
- **ServiceNow:** Incident and change request integration
- **Remedy:** Work order generation
- **Zendesk:** Support ticket creation
- **Custom:** REST API webhook integration

### 16.5 Glossary

**API (Application Programming Interface):** Interface for programmatic access to system functions

**Compliance Framework:** Set of standards and regulations for security and governance

**Credential:** Authentication information for accessing cloud services

**Finding:** Security issue or vulnerability identified during scanning

**IAM (Identity and Access Management):** Service for managing user access and permissions

**RBAC (Role-Based Access Control):** Access control method based on user roles

**SIEM (Security Information and Event Management):** Platform for security monitoring and analysis

**Vulnerability:** Security weakness that could be exploited by threats

**Zero-day:** Previously unknown security vulnerability

### 16.6 Contact Information

#### **Technical Support**
- **Email:** support@aegisscanner.com
- **Phone:** +1-800-AEGIS-SCAN (1-800-234-4772)
- **Hours:** Monday-Friday, 9 AM - 6 PM EST
- **Emergency:** 24/7 for critical security issues (PRO users)

#### **Sales and Licensing**
- **Email:** sales@aegisscanner.com
- **Phone:** +1-800-AEGIS-SALES (1-800-234-4772)
- **Hours:** Monday-Friday, 9 AM - 8 PM EST

#### **Documentation and Training**
- **Documentation:** https://docs.aegisscanner.com
- **Training Videos:** https://training.aegisscanner.com
- **Certification:** https://certification.aegisscanner.com

---

**Document Version:** 1.0
**Last Updated:** September 2025
**Next Review:** December 2025

*This document contains confidential and proprietary information. Distribution is restricted to authorized users only.*