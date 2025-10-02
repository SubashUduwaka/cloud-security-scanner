# Aegis Cloud Scanner - Developer Manual
## Part 6: Cloud Integration and Services

**Document Version:** 1.0
**Last Updated:** September 2024
**Target Audience:** Cloud Engineers, Integration Developers
**Classification:** Internal Development Documentation

---

## Table of Contents
1. [Cloud Integration Architecture](#cloud-integration-architecture)
2. [AWS Integration](#aws-integration)
3. [Google Cloud Platform Integration](#google-cloud-platform-integration)
4. [Microsoft Azure Integration](#microsoft-azure-integration)
5. [Multi-Cloud Orchestration](#multi-cloud-orchestration)
6. [Service Discovery and Enumeration](#service-discovery-and-enumeration)
7. [Authentication and Credential Management](#authentication-and-credential-management)
8. [Error Handling and Resilience](#error-handling-and-resilience)
9. [Performance Optimization](#performance-optimization)
10. [Extending Cloud Support](#extending-cloud-support)

---

## Cloud Integration Architecture

### Design Principles

The Aegis Cloud Scanner implements a pluggable cloud integration architecture that enables:
- **Provider Abstraction**: Common interface across all cloud providers
- **Modular Design**: Each provider is implemented as a separate module
- **Scalable Processing**: Parallel scanning across regions and services
- **Resilient Operations**: Automatic retry and error recovery
- **Extensible Framework**: Easy addition of new cloud providers

### Integration Framework

```python
class CloudIntegrationFramework:
    """Central orchestrator for cloud provider integrations"""

    def __init__(self):
        self.providers = {}
        self.credential_manager = CredentialManager()
        self.scanner_factory = ScannerFactory()

    def register_provider(self, provider_name, scanner_class):
        """Register a new cloud provider scanner"""
        self.providers[provider_name] = scanner_class

    def get_scanner(self, provider_name, credentials):
        """Get configured scanner for provider"""
        if provider_name not in self.providers:
            raise UnsupportedProviderError(f"Provider {provider_name} not supported")

        scanner_class = self.providers[provider_name]
        return scanner_class(credentials=credentials)

    def scan_multi_cloud(self, scan_config):
        """Orchestrate scanning across multiple cloud providers"""
        results = {}
        for provider_config in scan_config.providers:
            scanner = self.get_scanner(
                provider_config.name,
                provider_config.credentials
            )
            results[provider_config.name] = scanner.execute_scan(
                provider_config.scan_options
            )
        return results
```

### Provider Interface

```python
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class ScanResult:
    """Standardized scan result structure"""
    provider: str
    service: str
    resource_type: str
    resource_id: str
    region: str
    findings: List[Dict[str, Any]]
    metadata: Dict[str, Any]

class BaseCloudProvider(ABC):
    """Abstract base class for cloud provider integrations"""

    def __init__(self, credentials: Dict[str, Any]):
        self.credentials = credentials
        self.client = None
        self.regions = []
        self.services = []

    @abstractmethod
    def authenticate(self) -> bool:
        """Authenticate with cloud provider"""
        pass

    @abstractmethod
    def discover_regions(self) -> List[str]:
        """Discover available regions"""
        pass

    @abstractmethod
    def discover_services(self) -> List[str]:
        """Discover available services"""
        pass

    @abstractmethod
    def scan_service(self, service: str, region: str) -> List[ScanResult]:
        """Scan specific service in region"""
        pass

    @abstractmethod
    def get_resource_details(self, resource_type: str, resource_id: str) -> Dict[str, Any]:
        """Get detailed resource information"""
        pass

    def validate_credentials(self) -> Dict[str, Any]:
        """Validate credentials and return account information"""
        if self.authenticate():
            return self.get_account_info()
        raise AuthenticationError("Invalid credentials")

    def execute_full_scan(self, regions: Optional[List[str]] = None,
                         services: Optional[List[str]] = None) -> List[ScanResult]:
        """Execute comprehensive scan across regions and services"""
        if not self.authenticate():
            raise AuthenticationError("Authentication failed")

        scan_regions = regions or self.discover_regions()
        scan_services = services or self.discover_services()

        all_results = []
        for region in scan_regions:
            for service in scan_services:
                try:
                    results = self.scan_service(service, region)
                    all_results.extend(results)
                except Exception as e:
                    logger.error(f"Scan failed for {service} in {region}: {e}")

        return all_results
```

---

## AWS Integration

### AWS Scanner Implementation

```python
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from concurrent.futures import ThreadPoolExecutor, as_completed

class AWSCloudProvider(BaseCloudProvider):
    """AWS cloud provider implementation"""

    SUPPORTED_SERVICES = [
        'ec2', 's3', 'iam', 'rds', 'lambda', 'cloudtrail',
        'cloudwatch', 'vpc', 'elbv2', 'route53', 'kms'
    ]

    def __init__(self, credentials: Dict[str, Any]):
        super().__init__(credentials)
        self.session = None
        self.account_id = None

    def authenticate(self) -> bool:
        """Authenticate with AWS using provided credentials"""
        try:
            self.session = boto3.Session(
                aws_access_key_id=self.credentials.get('access_key_id'),
                aws_secret_access_key=self.credentials.get('secret_access_key'),
                aws_session_token=self.credentials.get('session_token'),
                region_name=self.credentials.get('region', 'us-east-1')
            )

            # Test authentication and get account info
            sts_client = self.session.client('sts')
            identity = sts_client.get_caller_identity()
            self.account_id = identity['Account']

            logger.info(f"AWS authentication successful for account: {self.account_id}")
            return True

        except (ClientError, NoCredentialsError) as e:
            logger.error(f"AWS authentication failed: {e}")
            return False

    def discover_regions(self) -> List[str]:
        """Discover available AWS regions"""
        try:
            ec2_client = self.session.client('ec2')
            response = ec2_client.describe_regions()
            regions = [region['RegionName'] for region in response['Regions']]

            # Filter regions based on service availability if needed
            return self._filter_available_regions(regions)

        except ClientError as e:
            logger.error(f"Failed to discover AWS regions: {e}")
            return ['us-east-1']  # Fallback to default region

    def discover_services(self) -> List[str]:
        """Return supported AWS services for scanning"""
        return self.SUPPORTED_SERVICES

    def scan_service(self, service: str, region: str) -> List[ScanResult]:
        """Scan specific AWS service in given region"""
        scanner_method = getattr(self, f'_scan_{service}', None)
        if not scanner_method:
            logger.warning(f"No scanner implemented for service: {service}")
            return []

        try:
            return scanner_method(region)
        except Exception as e:
            logger.error(f"Failed to scan {service} in {region}: {e}")
            return []

    def _scan_ec2(self, region: str) -> List[ScanResult]:
        """Scan EC2 instances and related resources"""
        results = []
        ec2_client = self.session.client('ec2', region_name=region)

        try:
            # Scan EC2 instances
            instances_response = ec2_client.describe_instances()
            for reservation in instances_response['Reservations']:
                for instance in reservation['Instances']:
                    findings = self._analyze_ec2_instance(instance, region)
                    if findings:
                        results.append(ScanResult(
                            provider='aws',
                            service='ec2',
                            resource_type='instance',
                            resource_id=instance['InstanceId'],
                            region=region,
                            findings=findings,
                            metadata={'instance_type': instance['InstanceType']}
                        ))

            # Scan Security Groups
            sg_response = ec2_client.describe_security_groups()
            for sg in sg_response['SecurityGroups']:
                findings = self._analyze_security_group(sg, region)
                if findings:
                    results.append(ScanResult(
                        provider='aws',
                        service='ec2',
                        resource_type='security_group',
                        resource_id=sg['GroupId'],
                        region=region,
                        findings=findings,
                        metadata={'group_name': sg['GroupName']}
                    ))

        except ClientError as e:
            logger.error(f"EC2 scan failed in {region}: {e}")

        return results

    def _analyze_ec2_instance(self, instance: Dict[str, Any], region: str) -> List[Dict[str, Any]]:
        """Analyze EC2 instance for security issues"""
        findings = []

        # Check for public IP exposure
        if instance.get('PublicIpAddress') or instance.get('PublicDnsName'):
            findings.append({
                'rule_id': 'aws-ec2-public-ip',
                'title': 'EC2 Instance with Public IP',
                'description': 'EC2 instance has a public IP address which may increase attack surface',
                'severity': 'medium',
                'resource_id': instance['InstanceId'],
                'evidence': {
                    'public_ip': instance.get('PublicIpAddress'),
                    'public_dns': instance.get('PublicDnsName')
                },
                'remediation': 'Consider using NAT Gateway or VPN for outbound connectivity'
            })

        # Check for unencrypted root volume
        for mapping in instance.get('BlockDeviceMappings', []):
            ebs = mapping.get('Ebs', {})
            if not ebs.get('Encrypted', False):
                findings.append({
                    'rule_id': 'aws-ec2-unencrypted-volume',
                    'title': 'Unencrypted EBS Volume',
                    'description': 'EBS volume is not encrypted at rest',
                    'severity': 'high',
                    'resource_id': ebs.get('VolumeId'),
                    'evidence': {'device_name': mapping['DeviceName']},
                    'remediation': 'Enable EBS encryption for all volumes'
                })

        # Check instance metadata service configuration
        metadata_options = instance.get('MetadataOptions', {})
        if metadata_options.get('HttpTokens') != 'required':
            findings.append({
                'rule_id': 'aws-ec2-imdsv1-enabled',
                'title': 'IMDSv1 Enabled',
                'description': 'Instance Metadata Service v1 is enabled, which is less secure',
                'severity': 'medium',
                'resource_id': instance['InstanceId'],
                'evidence': metadata_options,
                'remediation': 'Require IMDSv2 by setting HttpTokens to required'
            })

        return findings

    def _scan_s3(self, region: str) -> List[ScanResult]:
        """Scan S3 buckets for security issues"""
        results = []
        s3_client = self.session.client('s3', region_name=region)

        try:
            # List all buckets (S3 is global but we'll associate with the region)
            buckets_response = s3_client.list_buckets()

            for bucket in buckets_response['Buckets']:
                bucket_name = bucket['Name']

                # Check bucket region
                try:
                    bucket_region = s3_client.get_bucket_location(Bucket=bucket_name)
                    bucket_region = bucket_region.get('LocationConstraint') or 'us-east-1'

                    # Only process buckets in the current region
                    if bucket_region != region:
                        continue

                except ClientError:
                    continue

                findings = self._analyze_s3_bucket(bucket_name, s3_client)
                if findings:
                    results.append(ScanResult(
                        provider='aws',
                        service='s3',
                        resource_type='bucket',
                        resource_id=bucket_name,
                        region=bucket_region,
                        findings=findings,
                        metadata={'creation_date': bucket['CreationDate'].isoformat()}
                    ))

        except ClientError as e:
            logger.error(f"S3 scan failed: {e}")

        return results

    def _analyze_s3_bucket(self, bucket_name: str, s3_client) -> List[Dict[str, Any]]:
        """Analyze S3 bucket for security issues"""
        findings = []

        try:
            # Check bucket public access
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') in [
                        'http://acs.amazonaws.com/groups/global/AllUsers',
                        'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                    ]:
                        findings.append({
                            'rule_id': 'aws-s3-public-acl',
                            'title': 'S3 Bucket with Public ACL',
                            'description': 'S3 bucket has public read or write permissions via ACL',
                            'severity': 'high',
                            'resource_id': bucket_name,
                            'evidence': {'grant': grant},
                            'remediation': 'Remove public permissions from bucket ACL'
                        })
            except ClientError:
                pass

            # Check bucket policy for public access
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_doc = json.loads(policy['Policy'])
                if self._has_public_policy(policy_doc):
                    findings.append({
                        'rule_id': 'aws-s3-public-policy',
                        'title': 'S3 Bucket with Public Policy',
                        'description': 'S3 bucket policy allows public access',
                        'severity': 'high',
                        'resource_id': bucket_name,
                        'evidence': {'policy': policy_doc},
                        'remediation': 'Review and restrict bucket policy permissions'
                    })
            except ClientError:
                pass

            # Check bucket encryption
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            except ClientError:
                findings.append({
                    'rule_id': 'aws-s3-no-encryption',
                    'title': 'S3 Bucket Not Encrypted',
                    'description': 'S3 bucket does not have default encryption enabled',
                    'severity': 'medium',
                    'resource_id': bucket_name,
                    'evidence': {},
                    'remediation': 'Enable default encryption for the bucket'
                })

            # Check bucket versioning
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get('Status') != 'Enabled':
                    findings.append({
                        'rule_id': 'aws-s3-no-versioning',
                        'title': 'S3 Bucket Versioning Disabled',
                        'description': 'S3 bucket does not have versioning enabled',
                        'severity': 'low',
                        'resource_id': bucket_name,
                        'evidence': {'versioning_status': versioning.get('Status')},
                        'remediation': 'Enable versioning to protect against accidental deletion'
                    })
            except ClientError:
                pass

        except Exception as e:
            logger.error(f"Failed to analyze S3 bucket {bucket_name}: {e}")

        return findings

    def _scan_iam(self, region: str) -> List[ScanResult]:
        """Scan IAM for security issues"""
        results = []
        iam_client = self.session.client('iam')

        try:
            # Scan IAM users
            users_response = iam_client.list_users()
            for user in users_response['Users']:
                findings = self._analyze_iam_user(user, iam_client)
                if findings:
                    results.append(ScanResult(
                        provider='aws',
                        service='iam',
                        resource_type='user',
                        resource_id=user['UserName'],
                        region='global',  # IAM is global
                        findings=findings,
                        metadata={'create_date': user['CreateDate'].isoformat()}
                    ))

            # Scan IAM policies
            policies_response = iam_client.list_policies(Scope='Local')
            for policy in policies_response['Policies']:
                findings = self._analyze_iam_policy(policy, iam_client)
                if findings:
                    results.append(ScanResult(
                        provider='aws',
                        service='iam',
                        resource_type='policy',
                        resource_id=policy['PolicyName'],
                        region='global',
                        findings=findings,
                        metadata={'arn': policy['Arn']}
                    ))

        except ClientError as e:
            logger.error(f"IAM scan failed: {e}")

        return results

    def _analyze_iam_user(self, user: Dict[str, Any], iam_client) -> List[Dict[str, Any]]:
        """Analyze IAM user for security issues"""
        findings = []
        username = user['UserName']

        try:
            # Check for access keys
            keys_response = iam_client.list_access_keys(UserName=username)
            for key in keys_response['AccessKeyMetadata']:
                key_age = datetime.now(timezone.utc) - key['CreateDate'].replace(tzinfo=timezone.utc)

                if key_age.days > 90:
                    findings.append({
                        'rule_id': 'aws-iam-old-access-key',
                        'title': 'Old IAM Access Key',
                        'description': f'IAM access key is {key_age.days} days old',
                        'severity': 'medium',
                        'resource_id': key['AccessKeyId'],
                        'evidence': {
                            'key_age_days': key_age.days,
                            'create_date': key['CreateDate'].isoformat()
                        },
                        'remediation': 'Rotate access keys regularly (recommended every 90 days)'
                    })

            # Check for attached policies
            attached_policies = iam_client.list_attached_user_policies(UserName=username)
            for policy in attached_policies['AttachedPolicies']:
                if 'Admin' in policy['PolicyName'] or policy['PolicyArn'].endswith(':policy/PowerUserAccess'):
                    findings.append({
                        'rule_id': 'aws-iam-admin-access',
                        'title': 'IAM User with Administrative Access',
                        'description': 'IAM user has administrative privileges',
                        'severity': 'high',
                        'resource_id': username,
                        'evidence': {'policy': policy},
                        'remediation': 'Use roles for administrative access and follow principle of least privilege'
                    })

        except ClientError as e:
            logger.error(f"Failed to analyze IAM user {username}: {e}")

        return findings

    def get_account_info(self) -> Dict[str, Any]:
        """Get AWS account information"""
        try:
            sts_client = self.session.client('sts')
            identity = sts_client.get_caller_identity()

            return {
                'account_id': identity['Account'],
                'user_id': identity['UserId'],
                'arn': identity['Arn'],
                'provider': 'aws'
            }
        except ClientError as e:
            logger.error(f"Failed to get AWS account info: {e}")
            return {}

    def _filter_available_regions(self, regions: List[str]) -> List[str]:
        """Filter regions based on service availability and user preferences"""
        # Could implement logic to filter regions based on:
        # - Service availability
        # - User configuration
        # - Cost considerations
        return regions

    def _has_public_policy(self, policy_doc: Dict[str, Any]) -> bool:
        """Check if S3 bucket policy allows public access"""
        for statement in policy_doc.get('Statement', []):
            principal = statement.get('Principal')
            if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                return True
        return False
```

### AWS Service-Specific Scanners

```python
class AWSServiceScanner:
    """Base class for AWS service-specific scanners"""

    def __init__(self, session: boto3.Session, region: str):
        self.session = session
        self.region = region
        self.client = None

    def get_client(self, service_name: str):
        """Get or create service client"""
        if not self.client:
            self.client = self.session.client(service_name, region_name=self.region)
        return self.client

class RDSScanner(AWSServiceScanner):
    """Scanner for AWS RDS instances"""

    def scan(self) -> List[ScanResult]:
        """Scan RDS instances for security issues"""
        results = []
        rds_client = self.get_client('rds')

        try:
            # Scan RDS instances
            instances = rds_client.describe_db_instances()
            for instance in instances['DBInstances']:
                findings = self._analyze_rds_instance(instance)
                if findings:
                    results.append(ScanResult(
                        provider='aws',
                        service='rds',
                        resource_type='db_instance',
                        resource_id=instance['DBInstanceIdentifier'],
                        region=self.region,
                        findings=findings,
                        metadata={
                            'engine': instance['Engine'],
                            'engine_version': instance['EngineVersion']
                        }
                    ))

        except ClientError as e:
            logger.error(f"RDS scan failed in {self.region}: {e}")

        return results

    def _analyze_rds_instance(self, instance: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze RDS instance for security issues"""
        findings = []

        # Check for public accessibility
        if instance.get('PubliclyAccessible', False):
            findings.append({
                'rule_id': 'aws-rds-public-access',
                'title': 'RDS Instance Publicly Accessible',
                'description': 'RDS instance is configured to be publicly accessible',
                'severity': 'high',
                'resource_id': instance['DBInstanceIdentifier'],
                'evidence': {'publicly_accessible': True},
                'remediation': 'Disable public accessibility and use VPC endpoints'
            })

        # Check for unencrypted storage
        if not instance.get('StorageEncrypted', False):
            findings.append({
                'rule_id': 'aws-rds-unencrypted-storage',
                'title': 'RDS Instance Storage Not Encrypted',
                'description': 'RDS instance storage is not encrypted',
                'severity': 'high',
                'resource_id': instance['DBInstanceIdentifier'],
                'evidence': {'storage_encrypted': False},
                'remediation': 'Enable storage encryption for the RDS instance'
            })

        # Check backup retention
        backup_retention = instance.get('BackupRetentionPeriod', 0)
        if backup_retention < 7:
            findings.append({
                'rule_id': 'aws-rds-insufficient-backup',
                'title': 'Insufficient RDS Backup Retention',
                'description': f'RDS backup retention period is {backup_retention} days',
                'severity': 'medium',
                'resource_id': instance['DBInstanceIdentifier'],
                'evidence': {'backup_retention_period': backup_retention},
                'remediation': 'Set backup retention period to at least 7 days'
            })

        return findings

class LambdaScanner(AWSServiceScanner):
    """Scanner for AWS Lambda functions"""

    def scan(self) -> List[ScanResult]:
        """Scan Lambda functions for security issues"""
        results = []
        lambda_client = self.get_client('lambda')

        try:
            # List Lambda functions
            functions = lambda_client.list_functions()
            for function in functions['Functions']:
                findings = self._analyze_lambda_function(function, lambda_client)
                if findings:
                    results.append(ScanResult(
                        provider='aws',
                        service='lambda',
                        resource_type='function',
                        resource_id=function['FunctionName'],
                        region=self.region,
                        findings=findings,
                        metadata={
                            'runtime': function['Runtime'],
                            'handler': function['Handler']
                        }
                    ))

        except ClientError as e:
            logger.error(f"Lambda scan failed in {self.region}: {e}")

        return results

    def _analyze_lambda_function(self, function: Dict[str, Any], lambda_client) -> List[Dict[str, Any]]:
        """Analyze Lambda function for security issues"""
        findings = []
        function_name = function['FunctionName']

        # Check for environment variables with secrets
        env_vars = function.get('Environment', {}).get('Variables', {})
        for var_name, var_value in env_vars.items():
            if any(keyword in var_name.lower() for keyword in ['password', 'secret', 'key', 'token']):
                findings.append({
                    'rule_id': 'aws-lambda-env-secrets',
                    'title': 'Lambda Function with Potential Secrets in Environment',
                    'description': f'Environment variable {var_name} may contain sensitive information',
                    'severity': 'medium',
                    'resource_id': function_name,
                    'evidence': {'variable_name': var_name},
                    'remediation': 'Use AWS Systems Manager Parameter Store or Secrets Manager'
                })

        # Check function policy for public access
        try:
            policy = lambda_client.get_policy(FunctionName=function_name)
            policy_doc = json.loads(policy['Policy'])
            if self._has_public_access(policy_doc):
                findings.append({
                    'rule_id': 'aws-lambda-public-access',
                    'title': 'Lambda Function with Public Access',
                    'description': 'Lambda function allows public invocation',
                    'severity': 'high',
                    'resource_id': function_name,
                    'evidence': {'policy': policy_doc},
                    'remediation': 'Restrict function access to specific principals'
                })
        except ClientError:
            pass  # No policy attached

        return findings

    def _has_public_access(self, policy_doc: Dict[str, Any]) -> bool:
        """Check if Lambda policy allows public access"""
        for statement in policy_doc.get('Statement', []):
            principal = statement.get('Principal')
            if principal == '*':
                return True
        return False
```

---

## Google Cloud Platform Integration

### GCP Scanner Implementation

```python
from google.cloud import storage, compute_v1, resource_manager
from google.oauth2 import service_account
from googleapiclient import discovery
import google.auth

class GCPCloudProvider(BaseCloudProvider):
    """Google Cloud Platform provider implementation"""

    SUPPORTED_SERVICES = [
        'compute', 'storage', 'iam', 'sql', 'functions',
        'kubernetes', 'logging', 'monitoring', 'kms'
    ]

    def __init__(self, credentials: Dict[str, Any]):
        super().__init__(credentials)
        self.project_id = credentials.get('project_id')
        self.service_account_path = credentials.get('service_account_path')
        self.credentials_obj = None

    def authenticate(self) -> bool:
        """Authenticate with GCP using service account"""
        try:
            if self.service_account_path:
                self.credentials_obj = service_account.Credentials.from_service_account_file(
                    self.service_account_path
                )
            else:
                # Use default application credentials
                self.credentials_obj, _ = google.auth.default()

            # Test authentication
            resource_manager_client = resource_manager.ProjectsClient(
                credentials=self.credentials_obj
            )
            project = resource_manager_client.get_project(name=f"projects/{self.project_id}")

            logger.info(f"GCP authentication successful for project: {project.display_name}")
            return True

        except Exception as e:
            logger.error(f"GCP authentication failed: {e}")
            return False

    def discover_regions(self) -> List[str]:
        """Discover available GCP regions"""
        try:
            compute_client = compute_v1.RegionsClient(credentials=self.credentials_obj)
            regions_request = compute_v1.ListRegionsRequest(project=self.project_id)
            regions = compute_client.list(request=regions_request)

            return [region.name for region in regions]

        except Exception as e:
            logger.error(f"Failed to discover GCP regions: {e}")
            return ['us-central1']  # Fallback

    def discover_services(self) -> List[str]:
        """Return supported GCP services for scanning"""
        return self.SUPPORTED_SERVICES

    def scan_service(self, service: str, region: str) -> List[ScanResult]:
        """Scan specific GCP service in given region"""
        scanner_method = getattr(self, f'_scan_{service}', None)
        if not scanner_method:
            logger.warning(f"No scanner implemented for service: {service}")
            return []

        try:
            return scanner_method(region)
        except Exception as e:
            logger.error(f"Failed to scan {service} in {region}: {e}")
            return []

    def _scan_compute(self, region: str) -> List[ScanResult]:
        """Scan GCP Compute Engine instances"""
        results = []
        compute_client = compute_v1.InstancesClient(credentials=self.credentials_obj)

        try:
            instances_request = compute_v1.ListInstancesRequest(
                project=self.project_id,
                zone=f"{region}-a"  # Start with zone -a
            )
            instances = compute_client.list(request=instances_request)

            for instance in instances:
                findings = self._analyze_gcp_instance(instance, region)
                if findings:
                    results.append(ScanResult(
                        provider='gcp',
                        service='compute',
                        resource_type='instance',
                        resource_id=instance.name,
                        region=region,
                        findings=findings,
                        metadata={
                            'machine_type': instance.machine_type.split('/')[-1],
                            'zone': instance.zone.split('/')[-1]
                        }
                    ))

        except Exception as e:
            logger.error(f"GCP Compute scan failed in {region}: {e}")

        return results

    def _analyze_gcp_instance(self, instance, region: str) -> List[Dict[str, Any]]:
        """Analyze GCP Compute instance for security issues"""
        findings = []

        # Check for external IP
        for interface in instance.network_interfaces:
            for access_config in interface.access_configs:
                if access_config.nat_i_p:
                    findings.append({
                        'rule_id': 'gcp-compute-external-ip',
                        'title': 'Compute Instance with External IP',
                        'description': 'Compute instance has an external IP address',
                        'severity': 'medium',
                        'resource_id': instance.name,
                        'evidence': {'external_ip': access_config.nat_i_p},
                        'remediation': 'Use Cloud NAT for outbound connectivity'
                    })

        # Check for unencrypted disks
        for disk in instance.disks:
            if not disk.disk_encryption_key:
                findings.append({
                    'rule_id': 'gcp-compute-unencrypted-disk',
                    'title': 'Unencrypted Compute Disk',
                    'description': 'Compute instance disk is not encrypted with customer-managed key',
                    'severity': 'medium',
                    'resource_id': disk.source.split('/')[-1],
                    'evidence': {'disk_name': disk.source.split('/')[-1]},
                    'remediation': 'Use customer-managed encryption keys for disk encryption'
                })

        # Check for legacy metadata endpoints
        if hasattr(instance, 'metadata'):
            for item in instance.metadata.items:
                if item.key == 'enable-oslogin' and item.value.lower() != 'true':
                    findings.append({
                        'rule_id': 'gcp-compute-oslogin-disabled',
                        'title': 'OS Login Disabled',
                        'description': 'OS Login is not enabled for the instance',
                        'severity': 'medium',
                        'resource_id': instance.name,
                        'evidence': {'enable_oslogin': item.value},
                        'remediation': 'Enable OS Login for centralized SSH key management'
                    })

        return findings

    def _scan_storage(self, region: str) -> List[ScanResult]:
        """Scan GCP Cloud Storage buckets"""
        results = []
        storage_client = storage.Client(
            credentials=self.credentials_obj,
            project=self.project_id
        )

        try:
            buckets = storage_client.list_buckets()
            for bucket in buckets:
                # Filter by region if specified
                if region and bucket.location.lower() != region.lower():
                    continue

                findings = self._analyze_gcp_bucket(bucket)
                if findings:
                    results.append(ScanResult(
                        provider='gcp',
                        service='storage',
                        resource_type='bucket',
                        resource_id=bucket.name,
                        region=bucket.location,
                        findings=findings,
                        metadata={
                            'storage_class': bucket.storage_class,
                            'location': bucket.location
                        }
                    ))

        except Exception as e:
            logger.error(f"GCP Storage scan failed: {e}")

        return results

    def _analyze_gcp_bucket(self, bucket) -> List[Dict[str, Any]]:
        """Analyze GCP Storage bucket for security issues"""
        findings = []

        # Check for public access
        policy = bucket.get_iam_policy()
        for binding in policy.bindings:
            if 'allUsers' in binding['members'] or 'allAuthenticatedUsers' in binding['members']:
                findings.append({
                    'rule_id': 'gcp-storage-public-access',
                    'title': 'Storage Bucket with Public Access',
                    'description': 'Storage bucket allows public access',
                    'severity': 'high',
                    'resource_id': bucket.name,
                    'evidence': {
                        'role': binding['role'],
                        'members': binding['members']
                    },
                    'remediation': 'Remove public access from bucket IAM policy'
                })

        # Check for uniform bucket-level access
        if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
            findings.append({
                'rule_id': 'gcp-storage-uniform-access-disabled',
                'title': 'Uniform Bucket-Level Access Disabled',
                'description': 'Bucket does not have uniform bucket-level access enabled',
                'severity': 'medium',
                'resource_id': bucket.name,
                'evidence': {'uniform_access_enabled': False},
                'remediation': 'Enable uniform bucket-level access for better security'
            })

        # Check for encryption
        if not bucket.default_kms_key_name:
            findings.append({
                'rule_id': 'gcp-storage-no-cmek',
                'title': 'Storage Bucket Without Customer-Managed Encryption',
                'description': 'Bucket is not encrypted with customer-managed encryption key',
                'severity': 'low',
                'resource_id': bucket.name,
                'evidence': {'default_kms_key': None},
                'remediation': 'Configure customer-managed encryption key for the bucket'
            })

        return findings

    def get_account_info(self) -> Dict[str, Any]:
        """Get GCP project information"""
        try:
            resource_manager_client = resource_manager.ProjectsClient(
                credentials=self.credentials_obj
            )
            project = resource_manager_client.get_project(name=f"projects/{self.project_id}")

            return {
                'project_id': self.project_id,
                'project_name': project.display_name,
                'project_number': project.name.split('/')[-1],
                'provider': 'gcp'
            }
        except Exception as e:
            logger.error(f"Failed to get GCP project info: {e}")
            return {}
```

---

## Microsoft Azure Integration

### Azure Scanner Implementation

```python
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.sql import SqlManagementClient

class AzureCloudProvider(BaseCloudProvider):
    """Microsoft Azure provider implementation"""

    SUPPORTED_SERVICES = [
        'compute', 'storage', 'network', 'sql', 'keyvault',
        'monitor', 'security', 'functions', 'kubernetes'
    ]

    def __init__(self, credentials: Dict[str, Any]):
        super().__init__(credentials)
        self.subscription_id = credentials.get('subscription_id')
        self.tenant_id = credentials.get('tenant_id')
        self.client_id = credentials.get('client_id')
        self.client_secret = credentials.get('client_secret')
        self.credential = None

    def authenticate(self) -> bool:
        """Authenticate with Azure using service principal"""
        try:
            if self.client_id and self.client_secret and self.tenant_id:
                self.credential = ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id,
                    client_secret=self.client_secret
                )
            else:
                self.credential = DefaultAzureCredential()

            # Test authentication
            resource_client = ResourceManagementClient(
                self.credential,
                self.subscription_id
            )
            resource_groups = list(resource_client.resource_groups.list())

            logger.info(f"Azure authentication successful. Found {len(resource_groups)} resource groups")
            return True

        except Exception as e:
            logger.error(f"Azure authentication failed: {e}")
            return False

    def discover_regions(self) -> List[str]:
        """Discover available Azure regions"""
        try:
            from azure.mgmt.resource.subscriptions import SubscriptionClient
            subscription_client = SubscriptionClient(self.credential)
            locations = subscription_client.subscriptions.list_locations(self.subscription_id)

            return [location.name for location in locations]

        except Exception as e:
            logger.error(f"Failed to discover Azure regions: {e}")
            return ['eastus']  # Fallback

    def discover_services(self) -> List[str]:
        """Return supported Azure services for scanning"""
        return self.SUPPORTED_SERVICES

    def scan_service(self, service: str, region: str) -> List[ScanResult]:
        """Scan specific Azure service in given region"""
        scanner_method = getattr(self, f'_scan_{service}', None)
        if not scanner_method:
            logger.warning(f"No scanner implemented for service: {service}")
            return []

        try:
            return scanner_method(region)
        except Exception as e:
            logger.error(f"Failed to scan {service} in {region}: {e}")
            return []

    def _scan_compute(self, region: str) -> List[ScanResult]:
        """Scan Azure Virtual Machines"""
        results = []
        compute_client = ComputeManagementClient(self.credential, self.subscription_id)

        try:
            vms = compute_client.virtual_machines.list_all()
            for vm in vms:
                # Filter by region
                if region and vm.location != region:
                    continue

                findings = self._analyze_azure_vm(vm, compute_client)
                if findings:
                    results.append(ScanResult(
                        provider='azure',
                        service='compute',
                        resource_type='virtual_machine',
                        resource_id=vm.name,
                        region=vm.location,
                        findings=findings,
                        metadata={
                            'vm_size': vm.hardware_profile.vm_size,
                            'resource_group': vm.id.split('/')[4]
                        }
                    ))

        except Exception as e:
            logger.error(f"Azure Compute scan failed in {region}: {e}")

        return results

    def _analyze_azure_vm(self, vm, compute_client) -> List[Dict[str, Any]]:
        """Analyze Azure VM for security issues"""
        findings = []

        # Check for unencrypted OS disk
        if vm.storage_profile.os_disk.encryption_settings is None:
            findings.append({
                'rule_id': 'azure-vm-unencrypted-os-disk',
                'title': 'VM OS Disk Not Encrypted',
                'description': 'Virtual machine OS disk is not encrypted',
                'severity': 'high',
                'resource_id': vm.name,
                'evidence': {'os_disk_name': vm.storage_profile.os_disk.name},
                'remediation': 'Enable Azure Disk Encryption for OS disks'
            })

        # Check for public IP
        try:
            network_client = NetworkManagementClient(self.credential, self.subscription_id)
            for nic_ref in vm.network_profile.network_interfaces:
                nic_name = nic_ref.id.split('/')[-1]
                resource_group = nic_ref.id.split('/')[4]

                nic = network_client.network_interfaces.get(resource_group, nic_name)
                for ip_config in nic.ip_configurations:
                    if ip_config.public_ip_address:
                        findings.append({
                            'rule_id': 'azure-vm-public-ip',
                            'title': 'VM with Public IP Address',
                            'description': 'Virtual machine has a public IP address',
                            'severity': 'medium',
                            'resource_id': vm.name,
                            'evidence': {'public_ip_id': ip_config.public_ip_address.id},
                            'remediation': 'Use Azure Bastion or VPN for remote access'
                        })
        except Exception as e:
            logger.error(f"Failed to check network interfaces for VM {vm.name}: {e}")

        # Check for managed identity
        if vm.identity is None or vm.identity.type == 'None':
            findings.append({
                'rule_id': 'azure-vm-no-managed-identity',
                'title': 'VM Without Managed Identity',
                'description': 'Virtual machine does not have managed identity enabled',
                'severity': 'low',
                'resource_id': vm.name,
                'evidence': {'identity_type': 'None'},
                'remediation': 'Enable system-assigned managed identity for the VM'
            })

        return findings

    def _scan_storage(self, region: str) -> List[ScanResult]:
        """Scan Azure Storage Accounts"""
        results = []
        storage_client = StorageManagementClient(self.credential, self.subscription_id)

        try:
            storage_accounts = storage_client.storage_accounts.list()
            for account in storage_accounts:
                # Filter by region
                if region and account.location != region:
                    continue

                findings = self._analyze_azure_storage(account, storage_client)
                if findings:
                    results.append(ScanResult(
                        provider='azure',
                        service='storage',
                        resource_type='storage_account',
                        resource_id=account.name,
                        region=account.location,
                        findings=findings,
                        metadata={
                            'account_type': account.kind.value,
                            'resource_group': account.id.split('/')[4]
                        }
                    ))

        except Exception as e:
            logger.error(f"Azure Storage scan failed in {region}: {e}")

        return results

    def _analyze_azure_storage(self, account, storage_client) -> List[Dict[str, Any]]:
        """Analyze Azure Storage Account for security issues"""
        findings = []
        resource_group = account.id.split('/')[4]

        # Check for public blob access
        if hasattr(account, 'allow_blob_public_access') and account.allow_blob_public_access:
            findings.append({
                'rule_id': 'azure-storage-public-blob-access',
                'title': 'Storage Account Allows Public Blob Access',
                'description': 'Storage account is configured to allow public blob access',
                'severity': 'high',
                'resource_id': account.name,
                'evidence': {'allow_blob_public_access': True},
                'remediation': 'Disable public blob access at the storage account level'
            })

        # Check for HTTPS-only access
        if not account.enable_https_traffic_only:
            findings.append({
                'rule_id': 'azure-storage-http-allowed',
                'title': 'Storage Account Allows HTTP Traffic',
                'description': 'Storage account allows insecure HTTP traffic',
                'severity': 'medium',
                'resource_id': account.name,
                'evidence': {'enable_https_traffic_only': False},
                'remediation': 'Enable secure transfer (HTTPS only) for the storage account'
            })

        # Check for minimum TLS version
        if hasattr(account, 'minimum_tls_version') and account.minimum_tls_version != 'TLS1_2':
            findings.append({
                'rule_id': 'azure-storage-weak-tls',
                'title': 'Storage Account Uses Weak TLS Version',
                'description': f'Storage account minimum TLS version is {account.minimum_tls_version}',
                'severity': 'medium',
                'resource_id': account.name,
                'evidence': {'minimum_tls_version': account.minimum_tls_version},
                'remediation': 'Set minimum TLS version to TLS 1.2'
            })

        # Check for customer-managed encryption
        if account.encryption.key_source != 'Microsoft.Keyvault':
            findings.append({
                'rule_id': 'azure-storage-no-cmk',
                'title': 'Storage Account Not Using Customer-Managed Keys',
                'description': 'Storage account is not using customer-managed encryption keys',
                'severity': 'low',
                'resource_id': account.name,
                'evidence': {'key_source': account.encryption.key_source},
                'remediation': 'Configure customer-managed keys for encryption'
            })

        return findings

    def get_account_info(self) -> Dict[str, Any]:
        """Get Azure subscription information"""
        try:
            from azure.mgmt.resource.subscriptions import SubscriptionClient
            subscription_client = SubscriptionClient(self.credential)
            subscription = subscription_client.subscriptions.get(self.subscription_id)

            return {
                'subscription_id': self.subscription_id,
                'subscription_name': subscription.display_name,
                'tenant_id': self.tenant_id,
                'provider': 'azure'
            }
        except Exception as e:
            logger.error(f"Failed to get Azure subscription info: {e}")
            return {}
```

---

## Multi-Cloud Orchestration

### Multi-Cloud Scan Orchestrator

```python
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional
import threading
import time

class MultiCloudOrchestrator:
    """Orchestrate scanning across multiple cloud providers"""

    def __init__(self):
        self.providers = {}
        self.scan_progress = {}
        self.scan_results = {}
        self.progress_lock = threading.Lock()

    def register_provider(self, name: str, provider: BaseCloudProvider):
        """Register a cloud provider for scanning"""
        self.providers[name] = provider

    def execute_multi_cloud_scan(self, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute scan across multiple cloud providers"""
        scan_id = scan_config.get('scan_id', str(uuid.uuid4()))
        providers_to_scan = scan_config.get('providers', [])

        # Initialize progress tracking
        with self.progress_lock:
            self.scan_progress[scan_id] = {
                'status': 'running',
                'providers': {},
                'overall_progress': 0,
                'start_time': time.time()
            }

        # Execute scans in parallel
        with ThreadPoolExecutor(max_workers=len(providers_to_scan)) as executor:
            future_to_provider = {}

            for provider_config in providers_to_scan:
                provider_name = provider_config['name']
                if provider_name not in self.providers:
                    logger.error(f"Provider {provider_name} not registered")
                    continue

                future = executor.submit(
                    self._scan_provider,
                    scan_id,
                    provider_name,
                    provider_config
                )
                future_to_provider[future] = provider_name

            # Collect results
            provider_results = {}
            for future in as_completed(future_to_provider):
                provider_name = future_to_provider[future]
                try:
                    result = future.result()
                    provider_results[provider_name] = result
                except Exception as e:
                    logger.error(f"Scan failed for provider {provider_name}: {e}")
                    provider_results[provider_name] = {
                        'status': 'failed',
                        'error': str(e),
                        'results': []
                    }

        # Update final progress
        with self.progress_lock:
            self.scan_progress[scan_id]['status'] = 'completed'
            self.scan_progress[scan_id]['overall_progress'] = 100
            self.scan_progress[scan_id]['end_time'] = time.time()

        return {
            'scan_id': scan_id,
            'status': 'completed',
            'providers': provider_results,
            'summary': self._generate_multi_cloud_summary(provider_results)
        }

    def _scan_provider(self, scan_id: str, provider_name: str,
                      provider_config: Dict[str, Any]) -> Dict[str, Any]:
        """Scan individual cloud provider"""
        try:
            provider = self.providers[provider_name]

            # Update progress
            with self.progress_lock:
                self.scan_progress[scan_id]['providers'][provider_name] = {
                    'status': 'authenticating',
                    'progress': 0
                }

            # Authenticate
            if not provider.authenticate():
                raise Exception("Authentication failed")

            # Update progress
            with self.progress_lock:
                self.scan_progress[scan_id]['providers'][provider_name] = {
                    'status': 'discovering',
                    'progress': 10
                }

            # Discover resources
            regions = provider_config.get('regions') or provider.discover_regions()
            services = provider_config.get('services') or provider.discover_services()

            # Update progress
            with self.progress_lock:
                self.scan_progress[scan_id]['providers'][provider_name] = {
                    'status': 'scanning',
                    'progress': 20
                }

            # Execute scan
            scan_results = []
            total_tasks = len(regions) * len(services)
            completed_tasks = 0

            for region in regions:
                for service in services:
                    try:
                        service_results = provider.scan_service(service, region)
                        scan_results.extend(service_results)
                    except Exception as e:
                        logger.error(f"Failed to scan {service} in {region}: {e}")

                    completed_tasks += 1
                    progress = 20 + (completed_tasks / total_tasks) * 70

                    # Update progress
                    with self.progress_lock:
                        self.scan_progress[scan_id]['providers'][provider_name]['progress'] = progress

            # Update final progress
            with self.progress_lock:
                self.scan_progress[scan_id]['providers'][provider_name] = {
                    'status': 'completed',
                    'progress': 100
                }

            return {
                'status': 'completed',
                'results': scan_results,
                'summary': self._generate_provider_summary(scan_results)
            }

        except Exception as e:
            with self.progress_lock:
                self.scan_progress[scan_id]['providers'][provider_name] = {
                    'status': 'failed',
                    'progress': 0,
                    'error': str(e)
                }
            raise

    def get_scan_progress(self, scan_id: str) -> Dict[str, Any]:
        """Get current scan progress"""
        with self.progress_lock:
            if scan_id not in self.scan_progress:
                return {'status': 'not_found'}

            progress_data = self.scan_progress[scan_id].copy()

            # Calculate overall progress
            if progress_data['status'] == 'running':
                provider_progresses = [
                    p.get('progress', 0)
                    for p in progress_data['providers'].values()
                ]
                if provider_progresses:
                    progress_data['overall_progress'] = sum(provider_progresses) / len(provider_progresses)

            return progress_data

    def _generate_provider_summary(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Generate summary for provider scan results"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        service_counts = {}
        total_resources = len(results)

        for result in results:
            for finding in result.findings:
                severity = finding.get('severity', 'info')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            service = result.service
            service_counts[service] = service_counts.get(service, 0) + 1

        return {
            'total_resources': total_resources,
            'total_findings': sum(severity_counts.values()),
            'severity_breakdown': severity_counts,
            'service_breakdown': service_counts
        }

    def _generate_multi_cloud_summary(self, provider_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary across all cloud providers"""
        total_resources = 0
        total_findings = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        provider_breakdown = {}

        for provider_name, provider_result in provider_results.items():
            if provider_result['status'] == 'completed':
                summary = provider_result.get('summary', {})
                total_resources += summary.get('total_resources', 0)
                total_findings += summary.get('total_findings', 0)

                for severity, count in summary.get('severity_breakdown', {}).items():
                    severity_counts[severity] += count

                provider_breakdown[provider_name] = summary

        return {
            'total_resources': total_resources,
            'total_findings': total_findings,
            'severity_breakdown': severity_counts,
            'provider_breakdown': provider_breakdown
        }
```

---

## Service Discovery and Enumeration

### Service Discovery Framework

```python
class ServiceDiscovery:
    """Framework for discovering cloud services and resources"""

    def __init__(self, provider: BaseCloudProvider):
        self.provider = provider
        self.discovered_services = {}

    def discover_all_services(self) -> Dict[str, Any]:
        """Discover all available services in the cloud account"""
        discovery_results = {}

        for service in self.provider.discover_services():
            try:
                service_info = self.discover_service_details(service)
                discovery_results[service] = service_info
            except Exception as e:
                logger.error(f"Failed to discover service {service}: {e}")
                discovery_results[service] = {'status': 'failed', 'error': str(e)}

        return discovery_results

    def discover_service_details(self, service: str) -> Dict[str, Any]:
        """Discover detailed information about a specific service"""
        discovery_method = getattr(self, f'_discover_{service}', None)
        if not discovery_method:
            return {'status': 'not_supported'}

        return discovery_method()

    def _discover_compute(self) -> Dict[str, Any]:
        """Discover compute resources"""
        # Implementation depends on provider
        pass

    def _discover_storage(self) -> Dict[str, Any]:
        """Discover storage resources"""
        # Implementation depends on provider
        pass

class AWSServiceDiscovery(ServiceDiscovery):
    """AWS-specific service discovery"""

    def _discover_compute(self) -> Dict[str, Any]:
        """Discover AWS compute resources"""
        discovery_data = {
            'instances': [],
            'auto_scaling_groups': [],
            'load_balancers': [],
            'launch_templates': []
        }

        try:
            session = self.provider.session
            regions = self.provider.discover_regions()

            for region in regions:
                ec2_client = session.client('ec2', region_name=region)
                elbv2_client = session.client('elbv2', region_name=region)
                autoscaling_client = session.client('autoscaling', region_name=region)

                # Discover instances
                instances = ec2_client.describe_instances()
                for reservation in instances['Reservations']:
                    for instance in reservation['Instances']:
                        discovery_data['instances'].append({
                            'id': instance['InstanceId'],
                            'type': instance['InstanceType'],
                            'state': instance['State']['Name'],
                            'region': region,
                            'vpc_id': instance.get('VpcId'),
                            'subnet_id': instance.get('SubnetId')
                        })

                # Discover load balancers
                load_balancers = elbv2_client.describe_load_balancers()
                for lb in load_balancers['LoadBalancers']:
                    discovery_data['load_balancers'].append({
                        'arn': lb['LoadBalancerArn'],
                        'name': lb['LoadBalancerName'],
                        'type': lb['Type'],
                        'scheme': lb['Scheme'],
                        'region': region
                    })

                # Discover auto scaling groups
                asg_response = autoscaling_client.describe_auto_scaling_groups()
                for asg in asg_response['AutoScalingGroups']:
                    discovery_data['auto_scaling_groups'].append({
                        'name': asg['AutoScalingGroupName'],
                        'min_size': asg['MinSize'],
                        'max_size': asg['MaxSize'],
                        'desired_capacity': asg['DesiredCapacity'],
                        'region': region
                    })

        except Exception as e:
            logger.error(f"AWS compute discovery failed: {e}")

        return {
            'status': 'completed',
            'data': discovery_data,
            'summary': {
                'total_instances': len(discovery_data['instances']),
                'total_load_balancers': len(discovery_data['load_balancers']),
                'total_asg': len(discovery_data['auto_scaling_groups'])
            }
        }

    def _discover_storage(self) -> Dict[str, Any]:
        """Discover AWS storage resources"""
        discovery_data = {
            's3_buckets': [],
            'ebs_volumes': [],
            'efs_file_systems': []
        }

        try:
            session = self.provider.session
            s3_client = session.client('s3')

            # Discover S3 buckets
            buckets = s3_client.list_buckets()
            for bucket in buckets['Buckets']:
                try:
                    location = s3_client.get_bucket_location(Bucket=bucket['Name'])
                    region = location.get('LocationConstraint') or 'us-east-1'

                    # Get bucket details
                    try:
                        encryption = s3_client.get_bucket_encryption(Bucket=bucket['Name'])
                        is_encrypted = True
                    except:
                        is_encrypted = False

                    discovery_data['s3_buckets'].append({
                        'name': bucket['Name'],
                        'creation_date': bucket['CreationDate'].isoformat(),
                        'region': region,
                        'encrypted': is_encrypted
                    })
                except Exception as e:
                    logger.error(f"Failed to get details for bucket {bucket['Name']}: {e}")

            # Discover EBS volumes
            regions = self.provider.discover_regions()
            for region in regions:
                try:
                    ec2_client = session.client('ec2', region_name=region)
                    volumes = ec2_client.describe_volumes()

                    for volume in volumes['Volumes']:
                        discovery_data['ebs_volumes'].append({
                            'id': volume['VolumeId'],
                            'size': volume['Size'],
                            'type': volume['VolumeType'],
                            'encrypted': volume['Encrypted'],
                            'state': volume['State'],
                            'region': region
                        })
                except Exception as e:
                    logger.error(f"Failed to discover EBS volumes in {region}: {e}")

        except Exception as e:
            logger.error(f"AWS storage discovery failed: {e}")

        return {
            'status': 'completed',
            'data': discovery_data,
            'summary': {
                'total_s3_buckets': len(discovery_data['s3_buckets']),
                'total_ebs_volumes': len(discovery_data['ebs_volumes']),
                'total_efs_systems': len(discovery_data['efs_file_systems'])
            }
        }
```

---

## Authentication and Credential Management

### Credential Security Framework

```python
from cryptography.fernet import Fernet
import json
import os
from typing import Dict, Any, Optional

class CloudCredentialManager:
    """Secure management of cloud provider credentials"""

    def __init__(self, encryption_key: Optional[bytes] = None):
        self.encryption_key = encryption_key or self._get_encryption_key()
        self.fernet = Fernet(self.encryption_key)

    def _get_encryption_key(self) -> bytes:
        """Get or generate encryption key"""
        key_path = os.environ.get('CREDENTIAL_ENCRYPTION_KEY_PATH')
        if key_path and os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                return f.read()

        # Generate new key (in production, store securely)
        key = Fernet.generate_key()
        logger.warning("Generated new credential encryption key")
        return key

    def store_credentials(self, provider: str, credential_name: str,
                         credentials: Dict[str, Any]) -> str:
        """Store encrypted credentials"""
        try:
            # Encrypt credentials
            credentials_json = json.dumps(credentials)
            encrypted_credentials = self.fernet.encrypt(credentials_json.encode())

            # Store in database (using CloudCredential model)
            from models import CloudCredential
            credential_record = CloudCredential(
                name=credential_name,
                provider=provider,
                encrypted_credentials=encrypted_credentials.decode(),
                salt=os.urandom(16).hex()
            )
            credential_record.save()

            return credential_record.id

        except Exception as e:
            logger.error(f"Failed to store credentials: {e}")
            raise

    def retrieve_credentials(self, credential_id: str) -> Dict[str, Any]:
        """Retrieve and decrypt credentials"""
        try:
            from models import CloudCredential
            credential_record = CloudCredential.get_by_id(credential_id)

            if not credential_record:
                raise ValueError(f"Credentials not found: {credential_id}")

            # Decrypt credentials
            encrypted_data = credential_record.encrypted_credentials.encode()
            decrypted_data = self.fernet.decrypt(encrypted_data)
            credentials = json.loads(decrypted_data.decode())

            return credentials

        except Exception as e:
            logger.error(f"Failed to retrieve credentials: {e}")
            raise

    def validate_credentials(self, provider: str, credentials: Dict[str, Any]) -> bool:
        """Validate credentials with cloud provider"""
        try:
            # Create temporary provider instance for validation
            provider_class = self._get_provider_class(provider)
            temp_provider = provider_class(credentials)

            return temp_provider.authenticate()

        except Exception as e:
            logger.error(f"Credential validation failed: {e}")
            return False

    def _get_provider_class(self, provider: str):
        """Get provider class by name"""
        provider_classes = {
            'aws': AWSCloudProvider,
            'gcp': GCPCloudProvider,
            'azure': AzureCloudProvider
        }
        return provider_classes.get(provider)

class CredentialRotationManager:
    """Manage automatic credential rotation"""

    def __init__(self, credential_manager: CloudCredentialManager):
        self.credential_manager = credential_manager

    def check_credential_expiry(self, credential_id: str) -> Dict[str, Any]:
        """Check if credentials are approaching expiry"""
        try:
            credentials = self.credential_manager.retrieve_credentials(credential_id)
            provider = credentials.get('provider')

            if provider == 'aws':
                return self._check_aws_credential_expiry(credentials)
            elif provider == 'gcp':
                return self._check_gcp_credential_expiry(credentials)
            elif provider == 'azure':
                return self._check_azure_credential_expiry(credentials)

            return {'status': 'unknown', 'days_until_expiry': None}

        except Exception as e:
            logger.error(f"Failed to check credential expiry: {e}")
            return {'status': 'error', 'error': str(e)}

    def _check_aws_credential_expiry(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Check AWS credential expiry"""
        # AWS access keys don't have built-in expiry, but check last rotation
        try:
            import boto3
            session = boto3.Session(
                aws_access_key_id=credentials['access_key_id'],
                aws_secret_access_key=credentials['secret_access_key']
            )

            iam = session.client('iam')
            keys = iam.list_access_keys()

            for key in keys['AccessKeyMetadata']:
                if key['AccessKeyId'] == credentials['access_key_id']:
                    age_days = (datetime.now(timezone.utc) - key['CreateDate'].replace(tzinfo=timezone.utc)).days
                    return {
                        'status': 'active',
                        'age_days': age_days,
                        'rotation_recommended': age_days > 90
                    }

        except Exception as e:
            logger.error(f"AWS credential check failed: {e}")

        return {'status': 'unknown'}

    def rotate_credentials(self, credential_id: str) -> Dict[str, Any]:
        """Rotate cloud provider credentials"""
        # Implementation depends on provider and credential type
        # This would typically involve:
        # 1. Creating new credentials
        # 2. Testing new credentials
        # 3. Updating stored credentials
        # 4. Deactivating old credentials
        pass
```

---

## Error Handling and Resilience

### Resilient Cloud Operations

```python
import time
import random
from functools import wraps
from typing import Callable, Any, List, Type

class CloudOperationError(Exception):
    """Base exception for cloud operation errors"""
    pass

class TemporaryCloudError(CloudOperationError):
    """Temporary error that can be retried"""
    pass

class PermanentCloudError(CloudOperationError):
    """Permanent error that should not be retried"""
    pass

class RetryManager:
    """Manage retry logic for cloud operations"""

    def __init__(self, max_retries: int = 3, base_delay: float = 1.0,
                 max_delay: float = 60.0, backoff_factor: float = 2.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor

    def retry_on_exception(self, exceptions: List[Type[Exception]]):
        """Decorator for retrying operations on specific exceptions"""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                last_exception = None

                for attempt in range(self.max_retries + 1):
                    try:
                        return func(*args, **kwargs)
                    except tuple(exceptions) as e:
                        last_exception = e
                        if attempt == self.max_retries:
                            break

                        delay = min(
                            self.base_delay * (self.backoff_factor ** attempt),
                            self.max_delay
                        )
                        # Add jitter to prevent thundering herd
                        delay += random.uniform(0, 0.1) * delay

                        logger.warning(
                            f"Attempt {attempt + 1} failed: {e}. "
                            f"Retrying in {delay:.2f} seconds..."
                        )
                        time.sleep(delay)

                raise last_exception

            return wrapper
        return decorator

class CircuitBreaker:
    """Circuit breaker pattern for cloud service calls"""

    def __init__(self, failure_threshold: int = 5, timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'closed'  # closed, open, half-open

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        if self.state == 'open':
            if time.time() - self.last_failure_time >= self.timeout:
                self.state = 'half-open'
                logger.info("Circuit breaker entering half-open state")
            else:
                raise CloudOperationError("Circuit breaker is open")

        try:
            result = func(*args, **kwargs)

            if self.state == 'half-open':
                self.state = 'closed'
                self.failure_count = 0
                logger.info("Circuit breaker reset to closed state")

            return result

        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()

            if self.failure_count >= self.failure_threshold:
                self.state = 'open'
                logger.error(f"Circuit breaker opened after {self.failure_count} failures")

            raise

class CloudOperationResilience:
    """Combine retry logic and circuit breaker for resilient operations"""

    def __init__(self):
        self.retry_manager = RetryManager()
        self.circuit_breakers = {}

    def get_circuit_breaker(self, service_name: str) -> CircuitBreaker:
        """Get or create circuit breaker for service"""
        if service_name not in self.circuit_breakers:
            self.circuit_breakers[service_name] = CircuitBreaker()
        return self.circuit_breakers[service_name]

    def resilient_call(self, service_name: str, operation: Callable,
                      *args, **kwargs) -> Any:
        """Execute operation with full resilience (retry + circuit breaker)"""
        circuit_breaker = self.get_circuit_breaker(service_name)

        @self.retry_manager.retry_on_exception([TemporaryCloudError])
        def wrapped_operation():
            return circuit_breaker.call(operation, *args, **kwargs)

        return wrapped_operation()

# Usage example
resilience = CloudOperationResilience()

def scan_aws_service(service_name: str, region: str):
    """Example of resilient cloud operation"""
    try:
        return resilience.resilient_call(
            f"aws-{service_name}",
            _perform_aws_scan,
            service_name,
            region
        )
    except Exception as e:
        logger.error(f"Failed to scan {service_name} in {region} after all retries: {e}")
        raise
```

---

## Performance Optimization

### Parallel Processing Framework

```python
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import asyncio
import aiohttp
from typing import List, Dict, Any, Callable

class ParallelCloudScanner:
    """Optimize cloud scanning through parallel processing"""

    def __init__(self, max_threads: int = 10, max_processes: int = 4):
        self.max_threads = max_threads
        self.max_processes = max_processes

    def scan_regions_parallel(self, provider: BaseCloudProvider,
                            regions: List[str], services: List[str]) -> List[ScanResult]:
        """Scan multiple regions in parallel"""
        all_results = []

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit tasks for each region-service combination
            future_to_task = {}

            for region in regions:
                for service in services:
                    future = executor.submit(
                        self._scan_service_with_error_handling,
                        provider, service, region
                    )
                    future_to_task[future] = (service, region)

            # Collect results as they complete
            for future in as_completed(future_to_task):
                service, region = future_to_task[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                    logger.info(f"Completed scan of {service} in {region}")
                except Exception as e:
                    logger.error(f"Failed to scan {service} in {region}: {e}")

        return all_results

    def _scan_service_with_error_handling(self, provider: BaseCloudProvider,
                                        service: str, region: str) -> List[ScanResult]:
        """Scan service with proper error handling"""
        try:
            return provider.scan_service(service, region)
        except Exception as e:
            logger.error(f"Service scan failed for {service} in {region}: {e}")
            return []

    async def scan_async(self, provider: BaseCloudProvider,
                        scan_tasks: List[Dict[str, Any]]) -> List[ScanResult]:
        """Asynchronous scanning for I/O bound operations"""
        async with aiohttp.ClientSession() as session:
            tasks = []

            for task in scan_tasks:
                coroutine = self._scan_service_async(
                    session, provider, task['service'], task['region']
                )
                tasks.append(coroutine)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results and filter out exceptions
            all_results = []
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Async scan failed: {result}")
                else:
                    all_results.extend(result)

            return all_results

    async def _scan_service_async(self, session: aiohttp.ClientSession,
                                provider: BaseCloudProvider,
                                service: str, region: str) -> List[ScanResult]:
        """Async version of service scanning"""
        # This would implement async versions of cloud API calls
        # For now, we'll use the synchronous version in a thread
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, provider.scan_service, service, region
        )

class CachingOptimization:
    """Implement caching for expensive cloud operations"""

    def __init__(self, cache_ttl: int = 300):  # 5 minutes default
        self.cache = {}
        self.cache_ttl = cache_ttl

    def cached_operation(self, cache_key: str, operation: Callable) -> Any:
        """Execute operation with caching"""
        current_time = time.time()

        # Check if cached result is still valid
        if cache_key in self.cache:
            cached_result, timestamp = self.cache[cache_key]
            if current_time - timestamp < self.cache_ttl:
                logger.debug(f"Cache hit for {cache_key}")
                return cached_result

        # Execute operation and cache result
        logger.debug(f"Cache miss for {cache_key}, executing operation")
        result = operation()
        self.cache[cache_key] = (result, current_time)

        return result

    def clear_cache(self, pattern: str = None):
        """Clear cache entries matching pattern"""
        if pattern:
            keys_to_remove = [k for k in self.cache.keys() if pattern in k]
            for key in keys_to_remove:
                del self.cache[key]
        else:
            self.cache.clear()

# Usage example
scanner = ParallelCloudScanner(max_threads=20)
cache = CachingOptimization(cache_ttl=600)

def optimized_multi_region_scan(provider: BaseCloudProvider) -> List[ScanResult]:
    """Example of optimized scanning"""
    # Cache region discovery
    regions = cache.cached_operation(
        f"{provider.__class__.__name__}_regions",
        provider.discover_regions
    )

    # Cache service discovery
    services = cache.cached_operation(
        f"{provider.__class__.__name__}_services",
        provider.discover_services
    )

    # Scan in parallel
    return scanner.scan_regions_parallel(provider, regions, services)
```

---

## Extending Cloud Support

### Plugin Architecture for New Providers

```python
from typing import Protocol

class CloudProviderPlugin(Protocol):
    """Protocol for cloud provider plugins"""

    def get_provider_name(self) -> str:
        """Return provider name"""
        ...

    def get_supported_services(self) -> List[str]:
        """Return list of supported services"""
        ...

    def create_provider_instance(self, credentials: Dict[str, Any]) -> BaseCloudProvider:
        """Create provider instance with credentials"""
        ...

class PluginManager:
    """Manage cloud provider plugins"""

    def __init__(self):
        self.plugins = {}

    def register_plugin(self, plugin: CloudProviderPlugin):
        """Register a new cloud provider plugin"""
        provider_name = plugin.get_provider_name()
        self.plugins[provider_name] = plugin
        logger.info(f"Registered cloud provider plugin: {provider_name}")

    def get_available_providers(self) -> List[str]:
        """Get list of available cloud providers"""
        return list(self.plugins.keys())

    def create_provider(self, provider_name: str, credentials: Dict[str, Any]) -> BaseCloudProvider:
        """Create provider instance"""
        if provider_name not in self.plugins:
            raise ValueError(f"Unsupported provider: {provider_name}")

        plugin = self.plugins[provider_name]
        return plugin.create_provider_instance(credentials)

# Example: Adding support for Oracle Cloud Infrastructure
class OCICloudProvider(BaseCloudProvider):
    """Oracle Cloud Infrastructure provider"""

    def authenticate(self) -> bool:
        """Implement OCI authentication"""
        # Implementation using OCI SDK
        pass

    def discover_regions(self) -> List[str]:
        """Discover OCI regions"""
        # Implementation
        pass

    def scan_service(self, service: str, region: str) -> List[ScanResult]:
        """Scan OCI service"""
        # Implementation
        pass

class OCIPlugin:
    """OCI provider plugin"""

    def get_provider_name(self) -> str:
        return "oci"

    def get_supported_services(self) -> List[str]:
        return ["compute", "storage", "network", "database"]

    def create_provider_instance(self, credentials: Dict[str, Any]) -> BaseCloudProvider:
        return OCICloudProvider(credentials)

# Register the plugin
plugin_manager = PluginManager()
plugin_manager.register_plugin(OCIPlugin())
```

---

**End of Part 6**

**Next:** Part 7 will cover Security Implementation and Best Practices, including authentication mechanisms, authorization patterns, data protection, and security monitoring.