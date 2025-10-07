# API Documentation

**Aegis Cloud Security Scanner REST API**

Version: v1
Base URL: `http://localhost:5000/api/v1`

> **Note**: API access requires a Pro license. [Request a free Pro license](mailto:aegis.aws.scanner@gmail.com)

---

## Table of Contents

- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Error Handling](#error-handling)
- [Endpoints](#endpoints)
  - [Authentication](#authentication-endpoints)
  - [Scans](#scans)
  - [Findings](#findings)
  - [Credentials](#credentials)
  - [Reports](#reports)
  - [Compliance](#compliance)
  - [Users](#users)
  - [License](#license)
- [Webhooks](#webhooks)
- [Code Examples](#code-examples)

---

## Authentication

### API Token Authentication

All API requests require authentication using Bearer token.

#### Obtaining an API Token

**Endpoint**: `POST /api/v1/auth/token`

**Request**:
```json
{
  "username": "your_username",
  "password": "your_password",
  "totp_code": "123456"  // Optional, if 2FA enabled
}
```

**Response**:
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2025-10-08T12:00:00Z",
  "token_type": "Bearer"
}
```

#### Using the Token

Include token in Authorization header:
```http
Authorization: Bearer <your_token_here>
```

**Example**:
```bash
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1..." \
  http://localhost:5000/api/v1/scans
```

#### Token Refresh

**Endpoint**: `POST /api/v1/auth/refresh`

**Headers**:
```
Authorization: Bearer <expired_token>
```

**Response**:
```json
{
  "success": true,
  "token": "new_token_here",
  "expires_at": "2025-10-09T12:00:00Z"
}
```

---

## Rate Limiting

API requests are rate-limited based on license tier:

| License | Requests/Hour | Requests/Day |
|---------|---------------|--------------|
| Basic   | 100           | 500          |
| Pro     | 1000          | 10000        |

**Rate Limit Headers**:
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 995
X-RateLimit-Reset: 1633024800
```

**Error Response** (429 Too Many Requests):
```json
{
  "error": "Rate limit exceeded",
  "retry_after": 3600
}
```

---

## Error Handling

### Standard Error Response

```json
{
  "error": "Error message",
  "error_code": "ERROR_CODE",
  "details": {
    "field": "Additional context"
  },
  "timestamp": "2025-10-07T12:00:00Z"
}
```

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200  | Success |
| 201  | Created |
| 400  | Bad Request - Invalid parameters |
| 401  | Unauthorized - Invalid/missing token |
| 403  | Forbidden - Insufficient permissions |
| 404  | Not Found |
| 409  | Conflict - Resource already exists |
| 422  | Unprocessable Entity - Validation error |
| 429  | Too Many Requests - Rate limited |
| 500  | Internal Server Error |

---

## Endpoints

## Authentication Endpoints

### Generate API Token

`POST /api/v1/auth/token`

**Request Body**:
```json
{
  "username": "john_doe",
  "password": "SecurePass123!",
  "totp_code": "123456"
}
```

**Success Response** (200):
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2025-10-08T12:00:00Z",
  "user": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "license_tier": "PRO"
  }
}
```

---

### Validate Token

`GET /api/v1/auth/validate`

**Headers**:
```
Authorization: Bearer <token>
```

**Success Response** (200):
```json
{
  "valid": true,
  "user_id": 1,
  "expires_at": "2025-10-08T12:00:00Z"
}
```

---

### Revoke Token

`DELETE /api/v1/auth/token`

**Headers**:
```
Authorization: Bearer <token>
```

**Success Response** (200):
```json
{
  "success": true,
  "message": "Token revoked successfully"
}
```

---

## Scans

### List All Scans

`GET /api/v1/scans`

**Query Parameters**:
- `page` (integer): Page number (default: 1)
- `per_page` (integer): Results per page (default: 20, max: 100)
- `provider` (string): Filter by provider (aws/gcp/azure)
- `status` (string): Filter by status (completed/failed/in_progress)
- `sort` (string): Sort field (created_at/updated_at)
- `order` (string): Sort order (asc/desc)

**Example Request**:
```bash
curl -H "Authorization: Bearer <token>" \
  "http://localhost:5000/api/v1/scans?provider=aws&status=completed&page=1&per_page=10"
```

**Success Response** (200):
```json
{
  "success": true,
  "data": [
    {
      "id": 123,
      "provider": "aws",
      "status": "completed",
      "started_at": "2025-10-07T10:00:00Z",
      "completed_at": "2025-10-07T10:15:00Z",
      "duration_seconds": 900,
      "findings_count": {
        "critical": 3,
        "high": 12,
        "medium": 28,
        "low": 45
      },
      "resources_scanned": 234,
      "credential_profile": "production-aws"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 10,
    "total": 50,
    "pages": 5
  }
}
```

---

### Get Scan Details

`GET /api/v1/scans/{scan_id}`

**Success Response** (200):
```json
{
  "success": true,
  "data": {
    "id": 123,
    "provider": "aws",
    "status": "completed",
    "started_at": "2025-10-07T10:00:00Z",
    "completed_at": "2025-10-07T10:15:00Z",
    "duration_seconds": 900,
    "credential_profile": "production-aws",
    "regions_scanned": ["us-east-1", "us-west-2"],
    "services_scanned": ["iam", "s3", "ec2", "rds"],
    "findings_summary": {
      "total": 88,
      "by_severity": {
        "critical": 3,
        "high": 12,
        "medium": 28,
        "low": 45
      },
      "by_category": {
        "iam": 15,
        "storage": 20,
        "network": 18,
        "encryption": 10,
        "logging": 25
      }
    },
    "compliance_status": {
      "soc2": 78,
      "iso27001": 82,
      "gdpr": 75,
      "hipaa": 70
    }
  }
}
```

---

### Start New Scan

`POST /api/v1/scans`

**Request Body**:
```json
{
  "provider": "aws",
  "credential_id": 5,
  "regions": ["us-east-1", "us-west-2"],  // Optional, defaults to all
  "services": ["iam", "s3", "ec2"],  // Optional, defaults to all
  "compliance_frameworks": ["soc2", "iso27001"]  // Optional
}
```

**Success Response** (201):
```json
{
  "success": true,
  "scan_id": 124,
  "status": "initiated",
  "estimated_duration_minutes": 15,
  "message": "Scan started successfully"
}
```

**Error Response** (400):
```json
{
  "error": "Invalid provider specified",
  "valid_providers": ["aws", "gcp", "azure"]
}
```

---

### Cancel Scan

`DELETE /api/v1/scans/{scan_id}`

**Success Response** (200):
```json
{
  "success": true,
  "message": "Scan cancelled successfully",
  "scan_id": 124
}
```

---

### Get Scan Progress

`GET /api/v1/scans/{scan_id}/progress`

**Success Response** (200):
```json
{
  "success": true,
  "scan_id": 124,
  "status": "in_progress",
  "progress_percentage": 65,
  "current_service": "rds",
  "current_region": "us-west-2",
  "services_completed": 4,
  "services_total": 6,
  "elapsed_seconds": 540,
  "estimated_remaining_seconds": 300
}
```

---

## Findings

### List Findings

`GET /api/v1/findings`

**Query Parameters**:
- `scan_id` (integer): Filter by scan
- `severity` (string): critical/high/medium/low
- `category` (string): iam/storage/network/encryption/logging
- `status` (string): active/suppressed/resolved
- `page` (integer): Page number
- `per_page` (integer): Results per page

**Example Request**:
```bash
curl -H "Authorization: Bearer <token>" \
  "http://localhost:5000/api/v1/findings?scan_id=123&severity=critical&status=active"
```

**Success Response** (200):
```json
{
  "success": true,
  "data": [
    {
      "id": 4567,
      "scan_id": 123,
      "severity": "critical",
      "category": "storage",
      "title": "S3 Bucket Publicly Accessible",
      "description": "The S3 bucket 'my-public-bucket' allows public read access",
      "resource": {
        "type": "s3_bucket",
        "identifier": "my-public-bucket",
        "region": "us-east-1",
        "arn": "arn:aws:s3:::my-public-bucket"
      },
      "remediation": {
        "description": "Remove public access permissions from bucket",
        "steps": [
          "Go to S3 Console",
          "Select bucket 'my-public-bucket'",
          "Click 'Permissions' tab",
          "Edit 'Block public access' settings",
          "Enable 'Block all public access'"
        ],
        "aws_cli": "aws s3api put-public-access-block --bucket my-public-bucket --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true"
      },
      "compliance_mappings": {
        "soc2": ["CC6.1"],
        "iso27001": ["A.9.1.2"],
        "gdpr": ["Article 32"]
      },
      "risk_score": 9.5,
      "status": "active",
      "detected_at": "2025-10-07T10:05:30Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 3,
    "pages": 1
  }
}
```

---

### Get Finding Details

`GET /api/v1/findings/{finding_id}`

**Success Response** (200):
```json
{
  "success": true,
  "data": {
    "id": 4567,
    "scan_id": 123,
    "severity": "critical",
    "category": "storage",
    "title": "S3 Bucket Publicly Accessible",
    "description": "Detailed description...",
    "resource": { },
    "remediation": { },
    "evidence": {
      "bucket_policy": "{ policy json }",
      "acl": "public-read",
      "block_public_access": false
    },
    "history": [
      {
        "date": "2025-10-07T10:05:30Z",
        "status": "detected",
        "user": "scanner_system"
      }
    ]
  }
}
```

---

### Suppress Finding

`POST /api/v1/findings/{finding_id}/suppress`

**Request Body**:
```json
{
  "reason": "False positive - bucket is intentionally public for website hosting",
  "expiry_date": "2025-12-31"  // Optional
}
```

**Success Response** (200):
```json
{
  "success": true,
  "message": "Finding suppressed successfully",
  "finding_id": 4567,
  "status": "suppressed"
}
```

---

### Mark Finding as Resolved

`POST /api/v1/findings/{finding_id}/resolve`

**Request Body**:
```json
{
  "resolution_notes": "Removed public access from bucket",
  "verification_method": "manual"
}
```

**Success Response** (200):
```json
{
  "success": true,
  "message": "Finding marked as resolved",
  "finding_id": 4567,
  "status": "resolved"
}
```

---

## Credentials

### List Cloud Credentials

`GET /api/v1/credentials`

**Success Response** (200):
```json
{
  "success": true,
  "data": [
    {
      "id": 5,
      "profile_name": "production-aws",
      "provider": "aws",
      "created_at": "2025-09-15T08:00:00Z",
      "last_validated": "2025-10-07T09:00:00Z",
      "validation_status": "valid"
    },
    {
      "id": 6,
      "profile_name": "dev-gcp",
      "provider": "gcp",
      "created_at": "2025-09-20T10:00:00Z",
      "last_validated": "2025-10-07T09:05:00Z",
      "validation_status": "valid"
    }
  ]
}
```

**Note**: Actual credential values are never returned via API for security.

---

### Add Cloud Credentials

`POST /api/v1/credentials`

**Request Body (AWS)**:
```json
{
  "provider": "aws",
  "profile_name": "staging-aws",
  "credentials": {
    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }
}
```

**Request Body (GCP)**:
```json
{
  "provider": "gcp",
  "profile_name": "production-gcp",
  "credentials": {
    "service_account_json": "{ ... base64 encoded ... }"
  }
}
```

**Request Body (Azure)**:
```json
{
  "provider": "azure",
  "profile_name": "prod-azure",
  "credentials": {
    "client_id": "12345678-1234-1234-1234-123456789012",
    "client_secret": "secret_value",
    "tenant_id": "87654321-4321-4321-4321-210987654321",
    "subscription_id": "abcdefgh-ijkl-mnop-qrst-uvwxyz123456"
  }
}
```

**Success Response** (201):
```json
{
  "success": true,
  "credential_id": 7,
  "profile_name": "staging-aws",
  "provider": "aws",
  "validation_status": "valid"
}
```

---

### Delete Credentials

`DELETE /api/v1/credentials/{credential_id}`

**Success Response** (200):
```json
{
  "success": true,
  "message": "Credentials deleted successfully",
  "credential_id": 7
}
```

---

### Validate Credentials

`POST /api/v1/credentials/{credential_id}/validate`

**Success Response** (200):
```json
{
  "success": true,
  "credential_id": 5,
  "validation_status": "valid",
  "validated_at": "2025-10-07T12:00:00Z",
  "account_info": {
    "account_id": "123456789012",
    "account_alias": "my-aws-account",
    "regions_available": 16
  }
}
```

---

## Reports

### Generate PDF Report

`POST /api/v1/reports/pdf`

**Request Body**:
```json
{
  "scan_id": 123,
  "compliance_frameworks": ["soc2", "iso27001"],
  "include_suppressed": false,
  "severity_threshold": "medium",
  "format": "detailed"
}
```

**Success Response** (202):
```json
{
  "success": true,
  "report_id": "abc123",
  "status": "generating",
  "estimated_time_seconds": 30,
  "download_url": "/api/v1/reports/pdf/abc123/download"
}
```

---

### Check Report Status

`GET /api/v1/reports/pdf/{report_id}/status`

**Success Response** (200):
```json
{
  "success": true,
  "report_id": "abc123",
  "status": "completed",
  "generated_at": "2025-10-07T12:05:00Z",
  "file_size_mb": 2.5,
  "download_url": "/api/v1/reports/pdf/abc123/download",
  "expires_at": "2025-10-08T12:05:00Z"
}
```

---

### Download Report

`GET /api/v1/reports/pdf/{report_id}/download`

**Success Response** (200):
Returns PDF file

**Headers**:
```
Content-Type: application/pdf
Content-Disposition: attachment; filename="aegis-report-123.pdf"
```

---

### Export Findings (JSON/CSV)

`GET /api/v1/reports/export`

**Query Parameters**:
- `scan_id` (required): Scan ID
- `format`: json/csv
- `severity`: critical/high/medium/low
- `include_suppressed`: true/false

**Example**:
```bash
curl -H "Authorization: Bearer <token>" \
  "http://localhost:5000/api/v1/reports/export?scan_id=123&format=json&severity=critical"
```

**Success Response** (200):
Returns JSON or CSV file

---

## Compliance

### Get Compliance Overview

`GET /api/v1/compliance`

**Query Parameters**:
- `scan_id` (required): Scan ID

**Success Response** (200):
```json
{
  "success": true,
  "scan_id": 123,
  "frameworks": {
    "soc2": {
      "score": 78,
      "status": "non_compliant",
      "controls": {
        "total": 64,
        "passing": 50,
        "failing": 14
      },
      "categories": {
        "CC6.1": {"passing": 12, "failing": 2},
        "CC6.6": {"passing": 8, "failing": 3}
      }
    },
    "iso27001": {
      "score": 82,
      "status": "non_compliant",
      "controls": {
        "total": 114,
        "passing": 94,
        "failing": 20
      }
    }
  }
}
```

---

### Get Framework Details

`GET /api/v1/compliance/{framework}`

**Parameters**:
- `framework`: soc2/iso27001/gdpr/hipaa

**Query Parameters**:
- `scan_id` (required): Scan ID

**Success Response** (200):
```json
{
  "success": true,
  "framework": "soc2",
  "scan_id": 123,
  "score": 78,
  "controls": [
    {
      "control_id": "CC6.1",
      "title": "Logical and Physical Access Controls",
      "description": "The entity implements logical...",
      "status": "failing",
      "findings_count": 2,
      "related_findings": [4567, 4568]
    }
  ]
}
```

---

## Users

### Get Current User

`GET /api/v1/users/me`

**Success Response** (200):
```json
{
  "success": true,
  "user": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "license_tier": "PRO",
    "created_at": "2025-09-01T10:00:00Z",
    "last_login": "2025-10-07T08:00:00Z",
    "2fa_enabled": true,
    "api_rate_limit": {
      "hourly": 1000,
      "daily": 10000,
      "remaining_today": 9456
    }
  }
}
```

---

### Update User Profile

`PATCH /api/v1/users/me`

**Request Body**:
```json
{
  "email": "newemail@example.com",
  "notification_preferences": {
    "scan_complete": true,
    "critical_findings": true,
    "weekly_summary": false
  }
}
```

**Success Response** (200):
```json
{
  "success": true,
  "message": "Profile updated successfully"
}
```

---

## License

### Get License Info

`GET /api/v1/license`

**Success Response** (200):
```json
{
  "success": true,
  "license": {
    "tier": "PRO",
    "status": "active",
    "activated_at": "2025-09-15T10:00:00Z",
    "features": {
      "unlimited_scans": true,
      "all_cloud_providers": true,
      "ai_chatbot": true,
      "api_access": true,
      "scheduled_scans": true,
      "advanced_reporting": true
    },
    "usage": {
      "scans_this_month": 45,
      "api_calls_today": 234
    }
  }
}
```

---

## Webhooks

### Configure Webhook

`POST /api/v1/webhooks`

**Request Body**:
```json
{
  "url": "https://your-server.com/webhooks/aegis",
  "events": ["scan.completed", "finding.critical"],
  "secret": "webhook_signing_secret",
  "active": true
}
```

**Success Response** (201):
```json
{
  "success": true,
  "webhook_id": 5,
  "url": "https://your-server.com/webhooks/aegis",
  "events": ["scan.completed", "finding.critical"]
}
```

---

### Webhook Events

| Event | Description | Payload |
|-------|-------------|---------|
| `scan.started` | Scan initiated | `{scan_id, provider, started_at}` |
| `scan.completed` | Scan finished | `{scan_id, status, findings_count}` |
| `scan.failed` | Scan error | `{scan_id, error_message}` |
| `finding.critical` | Critical finding detected | `{finding_id, severity, resource}` |
| `finding.high` | High severity finding | `{finding_id, severity, resource}` |

**Example Webhook Payload**:
```json
{
  "event": "scan.completed",
  "timestamp": "2025-10-07T12:15:00Z",
  "data": {
    "scan_id": 123,
    "provider": "aws",
    "status": "completed",
    "findings_count": {
      "critical": 3,
      "high": 12,
      "medium": 28,
      "low": 45
    },
    "started_at": "2025-10-07T12:00:00Z",
    "completed_at": "2025-10-07T12:15:00Z"
  },
  "signature": "sha256=abc123..."
}
```

---

## Code Examples

### Python

```python
import requests

# Configuration
API_BASE_URL = "http://localhost:5000/api/v1"
USERNAME = "your_username"
PASSWORD = "your_password"

# 1. Authenticate
auth_response = requests.post(
    f"{API_BASE_URL}/auth/token",
    json={
        "username": USERNAME,
        "password": PASSWORD
    }
)
token = auth_response.json()["token"]

# 2. Set up headers
headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

# 3. Start a scan
scan_response = requests.post(
    f"{API_BASE_URL}/scans",
    headers=headers,
    json={
        "provider": "aws",
        "credential_id": 5
    }
)
scan_id = scan_response.json()["scan_id"]
print(f"Scan started: {scan_id}")

# 4. Poll for completion
import time
while True:
    progress = requests.get(
        f"{API_BASE_URL}/scans/{scan_id}/progress",
        headers=headers
    ).json()

    if progress["status"] == "completed":
        print("Scan completed!")
        break

    print(f"Progress: {progress['progress_percentage']}%")
    time.sleep(10)

# 5. Get findings
findings = requests.get(
    f"{API_BASE_URL}/findings",
    headers=headers,
    params={
        "scan_id": scan_id,
        "severity": "critical"
    }
).json()

for finding in findings["data"]:
    print(f"[{finding['severity']}] {finding['title']}")
    print(f"  Resource: {finding['resource']['identifier']}")
    print(f"  Remediation: {finding['remediation']['description']}")
    print()

# 6. Generate report
report = requests.post(
    f"{API_BASE_URL}/reports/pdf",
    headers=headers,
    json={
        "scan_id": scan_id,
        "compliance_frameworks": ["soc2", "iso27001"]
    }
).json()

# Wait for report generation
report_id = report["report_id"]
time.sleep(30)

# Download report
report_file = requests.get(
    f"{API_BASE_URL}/reports/pdf/{report_id}/download",
    headers=headers
)

with open(f"aegis-report-{scan_id}.pdf", "wb") as f:
    f.write(report_file.content)
print("Report downloaded!")
```

---

### JavaScript (Node.js)

```javascript
const axios = require('axios');

const API_BASE_URL = 'http://localhost:5000/api/v1';
const USERNAME = 'your_username';
const PASSWORD = 'your_password';

async function main() {
  try {
    // 1. Authenticate
    const authResponse = await axios.post(`${API_BASE_URL}/auth/token`, {
      username: USERNAME,
      password: PASSWORD
    });
    const token = authResponse.data.token;

    // Set up axios instance with auth header
    const api = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });

    // 2. Start scan
    const scanResponse = await api.post('/scans', {
      provider: 'aws',
      credential_id: 5
    });
    const scanId = scanResponse.data.scan_id;
    console.log(`Scan started: ${scanId}`);

    // 3. Wait for completion
    let completed = false;
    while (!completed) {
      const progress = await api.get(`/scans/${scanId}/progress`);
      if (progress.data.status === 'completed') {
        completed = true;
        console.log('Scan completed!');
      } else {
        console.log(`Progress: ${progress.data.progress_percentage}%`);
        await new Promise(resolve => setTimeout(resolve, 10000));
      }
    }

    // 4. Get critical findings
    const findings = await api.get('/findings', {
      params: {
        scan_id: scanId,
        severity: 'critical'
      }
    });

    findings.data.data.forEach(finding => {
      console.log(`[${finding.severity}] ${finding.title}`);
      console.log(`  Resource: ${finding.resource.identifier}`);
    });

  } catch (error) {
    console.error('Error:', error.response?.data || error.message);
  }
}

main();
```

---

### cURL

```bash
#!/bin/bash

API_BASE_URL="http://localhost:5000/api/v1"
USERNAME="your_username"
PASSWORD="your_password"

# 1. Get token
TOKEN=$(curl -s -X POST "$API_BASE_URL/auth/token" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}" \
  | jq -r '.token')

echo "Token: $TOKEN"

# 2. Start scan
SCAN_ID=$(curl -s -X POST "$API_BASE_URL/scans" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"provider":"aws","credential_id":5}' \
  | jq -r '.scan_id')

echo "Scan started: $SCAN_ID"

# 3. Check progress
curl -H "Authorization: Bearer $TOKEN" \
  "$API_BASE_URL/scans/$SCAN_ID/progress"

# 4. Get findings
curl -H "Authorization: Bearer $TOKEN" \
  "$API_BASE_URL/findings?scan_id=$SCAN_ID&severity=critical"

# 5. Generate report
REPORT_ID=$(curl -s -X POST "$API_BASE_URL/reports/pdf" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"scan_id\":$SCAN_ID}" \
  | jq -r '.report_id')

# 6. Download report
curl -H "Authorization: Bearer $TOKEN" \
  "$API_BASE_URL/reports/pdf/$REPORT_ID/download" \
  -o "aegis-report-$SCAN_ID.pdf"
```

---

## Best Practices

### Security
1. **Never commit API tokens** to version control
2. **Store tokens securely** (environment variables, key vault)
3. **Rotate tokens regularly** (every 90 days)
4. **Use HTTPS in production**
5. **Implement proper error handling**

### Performance
1. **Use webhooks** instead of polling for long operations
2. **Implement exponential backoff** for retries
3. **Cache responses** when appropriate
4. **Respect rate limits**
5. **Use pagination** for large result sets

### Error Handling
```python
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

def create_session():
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session
```

---

## Support

### 📧 API Support
aegis.aws.scanner@gmail.com

### 📖 Documentation
- [User Manual](USER_MANUAL.md)
- [FAQ](FAQ.md)
- [Troubleshooting](TROUBLESHOOTING.md)

### 🐛 Report API Issues
[GitHub Issues](https://github.com/SubashUduwaka/cloud-security-scanner/issues)

---

<div align="center">

**Aegis Cloud Security Scanner API**

*Automate your cloud security* 🛡️

[⬆ Back to Top](#api-documentation)

</div>
