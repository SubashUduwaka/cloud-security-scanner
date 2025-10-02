"""
Comprehensive Aegis Scanner Chatbot Knowledge Base
Contains all information needed for intelligent responses about cloud security,
troubleshooting, AWS/GCP/Azure issues, and application usage.
"""

# Quick Response Templates for Fast Answers
QUICK_RESPONSES = {
    "greetings": [
        "hello", "hi", "hey", "start", "help me", "assist"
    ],
    "scanning": [
        "scan", "run scan", "start scan", "how to scan", "scanning process"
    ],
    "credentials": [
        "credential", "aws", "gcp", "azure", "api key", "access key", "service account"
    ],
    "troubleshooting": [
        "error", "problem", "not working", "failed", "issue", "bug", "fix"
    ],
    "features": [
        "feature", "what can", "capabilities", "functions", "options"
    ],
    "dashboard": [
        "dashboard", "metrics", "charts", "statistics", "graphs"
    ],
    "automation": [
        "automation", "schedule", "cron", "automatic", "recurring"
    ],
    "reports": [
        "report", "pdf", "csv", "export", "download", "email"
    ],
    "settings": [
        "settings", "configuration", "setup", "preferences", "account"
    ]
}

# Fast Response Templates
FAST_RESPONSES = {
    "greetings": """👋 Hello! I'm your Aegis Scanner assistant. I can help with:
• Cloud security scanning (AWS/GCP/Azure)
• Troubleshooting connection issues
• Setting up credentials and automation
• Understanding dashboard features
• Generating reports and exports

What would you like help with?""",

    "scanning": """🔍 **How to Run a Cloud Security Scan:**

**Quick Start:**
1. Go to Dashboard
2. Select credential profile (AWS/GCP/Azure)
3. Choose regions or "All Regions"
4. Click "Run Scan"

**Advanced Options:**
• Enable "Live Progress" for real-time updates
• Use specific regions for faster scans
• Schedule automatic scans in Automation section

**Troubleshooting Scans:**
• Check credentials have proper permissions
• Ensure network connectivity
• Verify API limits aren't exceeded""",

    "credentials": """🔑 **Cloud Credentials Setup:**

**AWS Setup:**
1. Go to Settings → Cloud Credentials
2. Click "Add AWS Credential"
3. Enter Access Key ID and Secret Access Key
4. Required permissions: ReadOnlyAccess policy

**GCP Setup:**
1. Create Service Account in Google Cloud Console
2. Download JSON key file
3. Upload JSON in Settings → Cloud Credentials

**Azure Setup:**
1. Create App Registration in Azure Portal
2. Generate client secret
3. Add credentials in Settings

**Common Issues:**
• Invalid credentials: Double-check copy/paste
• Permission denied: Ensure ReadOnly access
• Region errors: Check service availability""",

    "troubleshooting": """🔧 **Common Issues & Solutions:**

**Scan Failures:**
• Check internet connection
• Verify credential permissions
• Try single region first
• Check API rate limits

**Dashboard Not Loading:**
• Refresh browser (Ctrl+F5)
• Clear browser cache
• Check JavaScript console for errors
• Ensure 2FA is completed

**Email Reports Failing:**
• Verify SMTP settings in admin
• Check email address validity
• Ensure firewall allows outgoing email

**Credential Errors:**
• Re-enter credentials carefully
• Check AWS/GCP console access
• Verify service account permissions
• Test with minimal permissions first

**Performance Issues:**
• Use specific regions instead of "All"
• Schedule scans during off-peak hours
• Check system resources""",

    "features": """⚡ **Aegis Scanner Features:**

**Core Security Scanning:**
• AWS, GCP, Azure multi-cloud support
• 100+ security checks per platform
• Real-time vulnerability detection
• Compliance framework mapping

**Dashboard & Analytics:**
• Live security metrics
• Interactive charts and graphs
• Risk trend analysis
• Resource discovery mapping

**Automation & Scheduling:**
• Recurring scans (daily/weekly/monthly)
• Automated email reports
• Background monitoring
• Custom time scheduling

**Reporting & Export:**
• PDF executive reports
• CSV data exports
• Email delivery
• Historical comparisons

**Advanced Features:**
• 2FA security
• Admin management
• Audit logging
• API integrations
• Guest demo mode""",

    "dashboard": """📊 **Dashboard Guide:**

**Main Metrics:**
• Resources Scanned: Total cloud resources analyzed
• Critical Findings: High-priority security issues
• Health Score: Overall security posture (0-100)

**Charts & Visualizations:**
• Security Posture: Breakdown by severity
• Findings by Service: Which services have issues
• Historical Trends: Security improvement over time
• Activity Heatmap: Scanning frequency

**Interactive Features:**
• Click chart segments to filter results
• Hover for detailed information
• Export charts as images
• Real-time updates during scans

**Sidebar Sections:**
• Dashboard: Main overview
• Scan Results: Detailed findings
• Automation: Scheduling & rules
• History: Past scan sessions
• Reporting: Generate reports""",

    "automation": """⏰ **Automation & Scheduling:**

**Quick Schedule:**
1. Go to Automation section
2. Select credential profile
3. Choose frequency (Daily/Weekly/Monthly)
4. Click "Schedule"

**Advanced Scheduling:**
• Set specific times (24-hour format)
• Multiple recurring schedules
• Different credentials per schedule
• Email notifications on completion

**Background Scanning:**
• Continuous monitoring mode
• Custom interval settings
• Automatic alerting
• Resource change detection

**Automation Rules:**
• Trigger actions on findings
• Email alerts for critical issues
• Automatic report generation
• Integration webhooks""",

    "reports": """📄 **Reports & Export Options:**

**PDF Reports:**
• Executive summary format
• Detailed findings breakdown
• Remediation recommendations
• Compliance mapping
• Charts and visualizations

**CSV Exports:**
• Raw data for analysis
• Custom field selection
• Historical data inclusion
• Spreadsheet compatible

**Email Delivery:**
• Scheduled report sending
• Multiple recipients
• Custom subject lines
• Automated frequency

**Report Types:**
• Quick PDF: Basic overview
• Advanced: Customizable
• Executive: High-level summary
• Technical: Detailed findings
• Compliance: Framework-specific""",

    "settings": """⚙️ **Settings & Configuration:**

**Account Settings:**
• Change password (8+ chars, mixed case)
• Enable/disable 2FA (recommended)
• Update email addresses
• Session timeout (5-120 minutes)

**Cloud Credentials:**
• Add/remove AWS/GCP/Azure accounts
• Test credential validity
• Manage access permissions
• Rotate keys regularly

**Notification Preferences:**
• Email alerts on scan completion
• Critical finding notifications
• System maintenance updates
• Report delivery settings

**API Configuration:**
• Gemini API key for chatbot
• Rate limiting settings
• Webhook endpoints
• Integration tokens

**Data Management:**
• Export all data
• Reset account data
• Suppressed findings management
• Audit log access"""
}

# AWS Specific Knowledge
AWS_KNOWLEDGE = {
    "setup": """**AWS Account Setup for Aegis Scanner:**

**1. Create IAM User:**
```bash
aws iam create-user --user-name aegis-scanner
```

**2. Attach ReadOnly Policy:**
```bash
aws iam attach-user-policy --user-name aegis-scanner --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

**3. Create Access Keys:**
```bash
aws iam create-access-key --user-name aegis-scanner
```

**Required Permissions:**
• EC2: DescribeInstances, DescribeSecurityGroups
• S3: ListBuckets, GetBucketPolicy, GetBucketAcl
• IAM: ListUsers, ListRoles, GetAccountSummary
• RDS: DescribeDBInstances, DescribeDBSecurityGroups
• VPC: DescribeVpcs, DescribeSubnets, DescribeRouteTables""",

    "troubleshooting": """**AWS Common Issues:**

**Permission Denied:**
• Check IAM policy attachment
• Verify user has ReadOnlyAccess
• Ensure MFA isn't required for API access

**Region Errors:**
• Some regions require explicit enablement
• Check service availability in target regions
• Use us-east-1 for initial testing

**Rate Limiting:**
• AWS has API rate limits per service
• Use specific regions instead of all
• Implement exponential backoff

**Access Key Issues:**
• Keys must be active (not disabled)
• Check for typos in key/secret
• Rotate keys if compromised""",

    "best_practices": """**AWS Security Best Practices:**

**IAM Security:**
• Use principle of least privilege
• Enable MFA for all users
• Rotate access keys regularly
• Use IAM roles instead of keys when possible

**Network Security:**
• Restrict security group rules
• Use VPC flow logs
• Implement NACLs for additional protection
• Avoid 0.0.0.0/0 in security groups

**Data Protection:**
• Enable S3 bucket encryption
• Use KMS for key management
• Enable CloudTrail logging
• Implement backup strategies"""
}

# GCP Specific Knowledge
GCP_KNOWLEDGE = {
    "setup": """**GCP Account Setup for Aegis Scanner:**

**1. Create Service Account:**
```bash
gcloud iam service-accounts create aegis-scanner --display-name="Aegis Scanner"
```

**2. Assign Viewer Role:**
```bash
gcloud projects add-iam-policy-binding PROJECT_ID --member="serviceAccount:aegis-scanner@PROJECT_ID.iam.gserviceaccount.com" --role="roles/viewer"
```

**3. Create JSON Key:**
```bash
gcloud iam service-accounts keys create aegis-key.json --iam-account=aegis-scanner@PROJECT_ID.iam.gserviceaccount.com
```

**Required Roles:**
• Viewer (roles/viewer)
• Security Reviewer (roles/iam.securityReviewer)
• Compute Viewer (roles/compute.viewer)""",

    "troubleshooting": """**GCP Common Issues:**

**Authentication Errors:**
• Verify JSON key file integrity
• Check service account is enabled
• Ensure project billing is active

**Permission Issues:**
• Service account needs Viewer role minimum
• Some APIs require explicit enablement
• Check project-level permissions

**API Limitations:**
• Enable required APIs in console
• Check quota limits per project
• Verify billing account status

**Network Issues:**
• Firewall rules may block API access
• VPC settings can affect connectivity
• Check organizational policies""",

    "best_practices": """**GCP Security Best Practices:**

**IAM Management:**
• Use principle of least privilege
• Regularly audit service accounts
• Enable audit logging
• Use IAM conditions for fine-grained access

**Network Security:**
• Configure VPC firewalls properly
• Use Private Google Access
• Implement network segmentation
• Enable VPC Flow Logs

**Data Protection:**
• Enable encryption at rest
• Use Cloud KMS for key management
• Implement data loss prevention
• Regular security scans"""
}

# Azure Specific Knowledge
AZURE_KNOWLEDGE = {
    "setup": """**Azure Account Setup for Aegis Scanner:**

**1. Create App Registration:**
```bash
az ad app create --display-name "Aegis Scanner"
```

**2. Create Service Principal:**
```bash
az ad sp create-for-rbac --name "aegis-scanner" --role Reader --scopes /subscriptions/SUBSCRIPTION_ID
```

**3. Note Credentials:**
• Application (client) ID
• Directory (tenant) ID
• Client secret

**Required Permissions:**
• Reader role on subscription
• Security Reader (if available)
• Specific resource group access""",

    "troubleshooting": """**Azure Common Issues:**

**Authentication Failures:**
• Verify client ID, tenant ID, and secret
• Check app registration status
• Ensure service principal is active

**Permission Denied:**
• Assign Reader role to service principal
• Check subscription-level permissions
• Verify resource group access

**API Errors:**
• Some services require registration
• Check region availability
• Verify subscription status

**Network Connectivity:**
• Firewall rules may block access
• VNet configuration affects connectivity
• Check NSG rules""",

    "best_practices": """**Azure Security Best Practices:**

**Identity Management:**
• Use managed identities when possible
• Implement conditional access
• Enable MFA for all accounts
• Regular access reviews

**Network Security:**
• Configure NSGs properly
• Use Azure Firewall
• Implement network segmentation
• Enable DDoS protection

**Data Protection:**
• Enable encryption in transit and at rest
• Use Azure Key Vault
• Implement backup strategies
• Regular vulnerability assessments"""
}

# Custom Code Examples
CODE_EXAMPLES = {
    "aws_boto3": """**AWS Boto3 Integration Example:**

```python
import boto3
from botocore.exceptions import ClientError

def scan_aws_resources(access_key, secret_key, region='us-east-1'):
    try:
        # Initialize clients
        ec2 = boto3.client('ec2',
                          aws_access_key_id=access_key,
                          aws_secret_access_key=secret_key,
                          region_name=region)

        # Get EC2 instances
        instances = ec2.describe_instances()

        # Security check: Find instances without tags
        untagged_instances = []
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                if not instance.get('Tags'):
                    untagged_instances.append(instance['InstanceId'])

        return {
            'total_instances': len(instances['Reservations']),
            'untagged_instances': untagged_instances,
            'region': region
        }

    except ClientError as e:
        return {'error': str(e)}
```""",

    "gcp_client": """**GCP Client Library Example:**

```python
from google.cloud import compute_v1
from google.oauth2 import service_account

def scan_gcp_resources(service_account_path, project_id):
    try:
        # Initialize credentials
        credentials = service_account.Credentials.from_service_account_file(
            service_account_path)

        # Initialize client
        client = compute_v1.InstancesClient(credentials=credentials)

        # List all zones
        zones_client = compute_v1.ZonesClient(credentials=credentials)
        zones = zones_client.list(project=project_id)

        all_instances = []
        for zone in zones:
            instances = client.list(project=project_id, zone=zone.name)
            for instance in instances:
                all_instances.append({
                    'name': instance.name,
                    'zone': zone.name,
                    'machine_type': instance.machine_type,
                    'status': instance.status
                })

        return {
            'total_instances': len(all_instances),
            'instances': all_instances,
            'project': project_id
        }

    except Exception as e:
        return {'error': str(e)}
```""",

    "azure_sdk": """**Azure SDK Example:**

```python
from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient

def scan_azure_resources(tenant_id, client_id, client_secret, subscription_id):
    try:
        # Initialize credentials
        credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )

        # Initialize clients
        compute_client = ComputeManagementClient(credential, subscription_id)
        resource_client = ResourceManagementClient(credential, subscription_id)

        # Get all VMs
        vms = list(compute_client.virtual_machines.list_all())

        # Security check: Find VMs without NSGs
        vms_without_nsg = []
        for vm in vms:
            has_nsg = False
            for nic_ref in vm.network_profile.network_interfaces:
                # Check if NIC has NSG attached
                # (Simplified check)
                if 'networkSecurityGroup' in nic_ref:
                    has_nsg = True
                    break

            if not has_nsg:
                vms_without_nsg.append(vm.name)

        return {
            'total_vms': len(vms),
            'vms_without_nsg': vms_without_nsg,
            'subscription': subscription_id
        }

    except Exception as e:
        return {'error': str(e)}
```"""
}

# Advanced Troubleshooting
ADVANCED_TROUBLESHOOTING = {
    "network_issues": """**Network Connectivity Troubleshooting:**

**Check Internet Connection:**
```bash
# Test DNS resolution
nslookup aws.amazon.com
nslookup googleapis.com
nslookup portal.azure.com

# Test HTTPS connectivity
curl -I https://aws.amazon.com
curl -I https://googleapis.com
curl -I https://portal.azure.com
```

**Firewall Issues:**
• Check corporate firewall settings
• Ensure ports 443, 80 are open
• Verify proxy configuration if applicable
• Test from different network if possible

**Proxy Configuration:**
```bash
export https_proxy=http://proxy.company.com:8080
export http_proxy=http://proxy.company.com:8080
```""",

    "permission_debugging": """**Permission Debugging Steps:**

**AWS Permission Testing:**
```bash
# Test basic access
aws sts get-caller-identity

# Test specific service access
aws ec2 describe-regions
aws s3 ls
aws iam get-account-summary
```

**GCP Permission Testing:**
```bash
# Test authentication
gcloud auth list

# Test project access
gcloud projects describe PROJECT_ID

# Test service access
gcloud compute instances list
gcloud storage buckets list
```

**Azure Permission Testing:**
```bash
# Test login
az account show

# Test subscription access
az account list

# Test resource access
az vm list
az storage account list
```""",

    "api_rate_limiting": """**API Rate Limiting Solutions:**

**Exponential Backoff Implementation:**
```python
import time
import random

def api_call_with_backoff(api_function, max_retries=5):
    for attempt in range(max_retries):
        try:
            return api_function()
        except Exception as e:
            if "rate limit" in str(e).lower() or "throttle" in str(e).lower():
                wait_time = (2 ** attempt) + random.uniform(0, 1)
                time.sleep(wait_time)
                continue
            else:
                raise e
    raise Exception("Max retries exceeded")
```

**Rate Limiting Best Practices:**
• Use specific regions instead of all regions
• Implement request queuing
• Cache results when possible
• Use batch operations when available
• Monitor API usage quotas"""
}

def get_knowledge_section(topic):
    """Get specific knowledge section by topic."""
    sections = {
        'aws': AWS_KNOWLEDGE,
        'gcp': GCP_KNOWLEDGE,
        'azure': AZURE_KNOWLEDGE,
        'code': CODE_EXAMPLES,
        'troubleshooting': ADVANCED_TROUBLESHOOTING
    }
    return sections.get(topic, {})

def get_fast_response(user_message):
    """Get fast response based on message content."""
    user_message_lower = user_message.lower()

    for category, keywords in QUICK_RESPONSES.items():
        if any(keyword in user_message_lower for keyword in keywords):
            return FAST_RESPONSES.get(category)

    return None