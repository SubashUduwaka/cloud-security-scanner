import boto3
import datetime
import csv
import io
import json
import logging
from functools import partial
from botocore.exceptions import ClientError

DEFAULT_AGE_DAYS = 90

def handle_aws_exception(resource_name, action_desc, e, default_remediation="Check IAM permissions and network connectivity."):
    """Helper function to create a standardized error result with specific remediation advice."""
    issue = f"Could not perform {action_desc}."
    remediation = default_remediation
    
    if isinstance(e, ClientError):
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'AccessDenied':
            issue = f"Access denied for {action_desc}."
            remediation = f"Ensure your IAM user has the necessary permissions (e.g., `s3:{action_desc.split(' ')[0]}`) for resource `{resource_name}`."
        elif error_code == 'NoSuchBucket':
            issue = f"Bucket `{resource_name}` not found."
            remediation = "The bucket may have been deleted or the name is incorrect."
    
    logging.warning(f"AWS Exception for resource '{resource_name}' while trying to '{action_desc}': {issue}")
    return {"service": "AWS Scanner", "resource": resource_name, "status": "ERROR", "issue": issue, "remediation": remediation}


def scan_s3_bucket_logging(s3_client):
    logging.debug("Starting scan: S3 Bucket Logging")
    results = []
    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        logging.debug(f"Found {len(buckets)} S3 buckets to check for logging.")
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                logging_status = s3_client.get_bucket_logging(Bucket=bucket_name)
                if 'LoggingEnabled' in logging_status:
                    results.append({"service": "S3", "resource": bucket_name, "status": "OK", "issue": "Server access logging is enabled."})
                else:
                    results.append({"service": "S3", "resource": bucket_name, "status": "CRITICAL", "issue": "Server access logging is not enabled.", "remediation": "Enable server access logging to record all requests made to your S3 bucket.", "doc_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html"})
            except ClientError as e:
                results.append(handle_aws_exception(bucket_name, "GetBucketLogging", e, default_remediation="Ensure your IAM user has `s3:GetBucketLogging` permissions for this bucket."))
            except Exception:
                results.append({"service": "S3", "resource": bucket_name, "status": "CRITICAL", "issue": "Could not determine server access logging status.", "remediation": "Ensure your IAM user has `s3:GetBucketLogging` permissions for this bucket."})
    except Exception as e:
        results.append(handle_aws_exception("N/A", "ListBuckets", e, "Ensure your IAM user has `s3:ListAllMyBuckets` permission."))
    logging.debug(f"Finished scan: S3 Bucket Logging. Found {len(results)} results.")
    return results

def scan_s3_buckets(s3_client):
    logging.debug("Starting scan: S3 Public Buckets")
    results = []
    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        logging.debug(f"Found {len(buckets)} S3 buckets to check for public access.")
        for bucket in buckets:
            bucket_name = bucket['Name']
            is_public = False
            try:
                pab = s3_client.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
                if not (pab.get('BlockPublicAcls') and pab.get('IgnorePublicAcls') and pab.get('BlockPublicPolicy') and pab.get('RestrictPublicBuckets')):
                    is_public = True
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') == 'NoSuchPublicAccessBlockConfiguration':
                    try:
                        policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                        if '"Principal":"*"' in policy.get('Policy', '') or '"Principal":{"AWS":"*"}' in policy.get('Policy', ''):
                            is_public = True
                    except ClientError as e_policy:
                         if e_policy.response.get('Error', {}).get('Code') != 'NoSuchBucketPolicy':
                             results.append(handle_aws_exception(bucket_name, "GetBucketPolicy", e_policy))
                             continue
                    except Exception as e_policy:
                        results.append(handle_aws_exception(bucket_name, "GetBucketPolicy", e_policy))
                        continue
                else:
                    results.append(handle_aws_exception(bucket_name, "GetPublicAccessBlock", e))
                    continue
            except Exception as e:
                results.append(handle_aws_exception(bucket_name, "GetPublicAccessBlock", e))
                continue

            logging.debug(f"  -> Bucket '{bucket_name}' is public: {is_public}.")
            result = {"service": "S3", "resource": bucket_name, "status": "CRITICAL" if is_public else "OK", "issue": "Bucket may be publicly accessible." if is_public else "Bucket is private."}
            if is_public:
                result["remediation"] = "Block all public access at the bucket level to prevent accidental data exposure."
                result["doc_url"] = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
            results.append(result)
    except Exception as e:
        results.append(handle_aws_exception("N/A", "ListBuckets", e))
    logging.debug(f"Finished scan: S3 Public Buckets. Found {len(results)} results.")
    return results

def scan_s3_versioning(s3_client):
    logging.debug("Starting scan: S3 Versioning")
    results = []
    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        logging.debug(f"Found {len(buckets)} S3 buckets to check for versioning.")
        for bucket in buckets:
            name = bucket['Name']
            try:
                v = s3_client.get_bucket_versioning(Bucket=name)
                if v.get('Status') == 'Enabled':
                    results.append({"service": "S3", "resource": name, "status": "OK", "issue": "Versioning is enabled."})
                else:
                    results.append({"service": "S3", "resource": name, "status": "WARNING", "issue": "Versioning is not enabled.", "remediation": "Enable S3 versioning to protect against accidental overwrites and deletions.", "doc_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"})
            except ClientError as e:
                results.append(handle_aws_exception(name, "GetBucketVersioning", e))
            except Exception as e:
                results.append(handle_aws_exception(name, "GetBucketVersioning", e))
    except Exception as e:
        results.append(handle_aws_exception("N/A", "ListBuckets", e))
    logging.debug(f"Finished scan: S3 Versioning. Found {len(results)} results.")
    return results

def scan_s3_lifecycle(s3_client):
    logging.debug("Starting scan: S3 Lifecycle Policies")
    results = []
    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        logging.debug(f"Found {len(buckets)} S3 buckets to check for lifecycle policies.")
        for bucket in buckets:
            name = bucket['Name']
            try:
                lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=name)
                rules = lifecycle.get('Rules', [])
                if rules:
                    results.append({"service": "S3", "resource": name, "status": "OK", "issue": "Bucket has lifecycle rules."})
                else:
                    results.append({"service": "S3", "resource": name, "status": "WARNING", "issue": "No lifecycle rules configured.", "remediation": "Create lifecycle rules to transition/delete objects and save cost.", "doc_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-configuration-examples.html"})
            except s3_client.exceptions.NoSuchLifecycleConfiguration:
                results.append({"service": "S3", "resource": name, "status": "WARNING", "issue": "No lifecycle rules configured.", "remediation": "Create lifecycle rules to transition/delete objects and save cost.", "doc_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-configuration-examples.html"})
            except ClientError as e:
                results.append(handle_aws_exception(name, "GetBucketLifecycleConfiguration", e))
            except Exception as e:
                results.append(handle_aws_exception(name, "GetBucketLifecycleConfiguration", e))
    except Exception as e:
        results.append(handle_aws_exception("N/A", "ListBuckets", e))
    logging.debug(f"Finished scan: S3 Lifecycle Policies. Found {len(results)} results.")
    return results

def scan_iam_root_mfa(iam_client):
    logging.debug("Starting scan: IAM Root MFA")
    try:
        summary = iam_client.get_account_summary()
        mfa_enabled = summary['SummaryMap'].get('AccountMFAEnabled', 0) == 1
        result = {"service": "IAM", "resource": "Root Account", "status": "OK" if mfa_enabled else "CRITICAL", "issue": "MFA is enabled for the root account." if mfa_enabled else "MFA is NOT enabled for the root account."}
        if not mfa_enabled:
            result["remediation"] = "Enable multi-factor authentication (MFA) for your root user to add an extra layer of protection to your AWS account."
            result["doc_url"] = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#root-user-mfa"
        logging.debug("Finished scan: IAM Root MFA. Found 1 result.")
        return [result]
    except Exception as e:
        logging.debug("Finished scan: IAM Root MFA with error.")
        return [handle_aws_exception("Root Account", "GetAccountSummary", e, default_remediation="Ensure your IAM user has `iam:GetAccountSummary` permission.")]

def scan_iam_password_policy(iam_client):
    logging.debug("Starting scan: IAM Password Policy")
    try:
        policy = iam_client.get_account_password_policy()['PasswordPolicy']
        weaknesses = []
        if not policy.get('RequireUppercaseCharacters'): weaknesses.append("no uppercase requirement")
        if not policy.get('RequireLowercaseCharacters'): weaknesses.append("no lowercase requirement")
        if not policy.get('RequireNumbers'): weaknesses.append("no number requirement")
        if not policy.get('RequireSymbols'): weaknesses.append("no symbol requirement")
        if policy.get('MinimumPasswordLength', 0) < 14: weaknesses.append("length less than 14")
        
        if weaknesses:
            issue = f"Password policy is weak: {', '.join(weaknesses)}."
            results = [{"service": "IAM", "resource": "Account Password Policy", "status": "CRITICAL", "issue": issue, "remediation": "Enforce a stronger password policy for all IAM users.", "doc_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"}]
        else:
            results = [{"service": "IAM", "resource": "Account Password Policy", "status": "OK", "issue": "A strong password policy is enforced."}]
    except iam_client.exceptions.NoSuchEntityException:
        results = [{"service": "IAM", "resource": "Account Password Policy", "status": "CRITICAL", "issue": "No password policy is set for the account.", "remediation": "Set an account password policy to enforce strong passwords for IAM users."}]
    except Exception as e:
        results = [handle_aws_exception("Account Password Policy", "GetAccountPasswordPolicy", e)]
    logging.debug(f"Finished scan: IAM Password Policy. Found {len(results)} result(s).")
    return results

def scan_iam_overly_permissive_roles(iam_client):
    logging.debug("Starting scan: IAM Overly Permissive Roles")
    results = []
    try:
        paginator = iam_client.get_paginator('list_roles')
        roles = [role for page in paginator.paginate() for role in page.get('Roles', [])]
        logging.debug(f"Found {len(roles)} IAM roles to analyze.")
        for role in roles:
            role_name = role['RoleName']
            is_admin = False
            try:
                attached = iam_client.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
                for p in attached:
                    if p.get('PolicyName') == 'AdministratorAccess' or p.get('PolicyArn', '').endswith(':AdministratorAccess'):
                        is_admin = True
                        break
                if not is_admin:
                    inline = iam_client.list_role_policies(RoleName=role_name).get('PolicyNames', [])
                    for pname in inline:
                        doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=pname)['PolicyDocument']
                        doc_str = json.dumps(doc)
                        if ('"Action": "*"' in doc_str) or ('"Resource": "*"' in doc_str) or ("Action': '*'" in doc_str):
                            is_admin = True
                            break
            except ClientError as e:
                results.append(handle_aws_exception(role_name, "Inspect Role", e))
                continue
            except Exception as e:
                results.append(handle_aws_exception(role_name, "Inspect Role", e))
                continue

            result = {"service": "IAM", "resource": role_name, "status": "CRITICAL" if is_admin else "OK", "issue": "Role has Administrator-like privileges." if is_admin else "Role appears scoped."}
            if is_admin:
                result["remediation"] = "Review the role and apply the principle of least privilege; avoid attaching full AdministratorAccess where possible."
                result["doc_url"] = "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
            results.append(result)
    except Exception as e:
        results.append(handle_aws_exception("N/A", "ListRoles", e))
    logging.debug(f"Finished scan: IAM Overly Permissive Roles. Found {len(results)} results.")
    return results

def scan_iam_users_and_keys(iam_client):
    logging.debug("Starting scan: IAM User Activity (Credential Report)")
    results = []
    try:
        try:
            iam_client.generate_credential_report()
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == 'ReportInProgress':
                logging.warning("Credential report generation is in progress. Skipping activity scan for now.")
                results.append({"service": "IAM", "resource": "Credential Report", "status": "WARNING", "issue": "Credential report generation is in progress. Skipping scan."})
                return results
            else:
                raise e
        report = iam_client.get_credential_report()
        content = report.get('Content')
        if content:
            csvfile = io.StringIO(content.decode('utf-8'))
            reader = csv.DictReader(csvfile)
            rows = list(reader)
            logging.debug(f"Analyzing {len(rows)} users from the credential report.")
            for row in rows:
                user = row.get('user')
                if user == '<root_account>': continue
                last_used_dates = []
                if row.get('password_last_used') and row.get('password_last_used') != 'N/A':
                    last_used_dates.append(row.get('password_last_used'))
                if row.get('access_key_1_last_used_date') and row.get('access_key_1_last_used_date') != 'N/A':
                    last_used_dates.append(row.get('access_key_1_last_used_date'))
                if row.get('access_key_2_last_used_date') and row.get('access_key_2_last_used_date') != 'N/A':
                    last_used_dates.append(row.get('access_key_2_last_used_date'))
                if last_used_dates:
                    most_recent = max(last_used_dates)
                    try:
                        dt = datetime.datetime.fromisoformat(most_recent.replace('Z', '+00:00'))
                        age_days = (datetime.datetime.now(datetime.timezone.utc) - dt).days
                        if age_days > DEFAULT_AGE_DAYS:
                            results.append({"service": "IAM", "resource": user, "status": "WARNING", "issue": f"User appears inactive for {age_days} days.", "remediation": "If user is inactive, consider deactivating credentials or removing the user."})
                        else:
                            results.append({"service": "IAM", "resource": user, "status": "OK", "issue": f"User active within {age_days} days."})
                    except Exception:
                        results.append({"service": "IAM", "resource": user, "status": "WARNING", "issue": "Could not parse last activity timestamp for user."})
                else:
                    results.append({"service": "IAM", "resource": user, "status": "WARNING", "issue": "No recorded activity for user. Manual review recommended.", "remediation": "Check console logins / access key usage and remove unused credentials."})
    except Exception as e:
        results.append(handle_aws_exception("IAM Users", "GetCredentialReport", e))
    logging.debug(f"Finished scan: IAM User Activity. Found {len(results)} results.")
    return results

def scan_iam_users(iam_client):
    logging.debug("Starting scan: IAM Access Key Age")
    results = []
    try:
        paginator = iam_client.get_paginator('list_users')
        users = [user for page in paginator.paginate() for user in page.get('Users', [])]
        logging.debug(f"Found {len(users)} IAM users to check for access key age.")
        for user in users:
            username = user['UserName']
            try:
                keys = iam_client.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
                for key in keys:
                    key_id = key['AccessKeyId']
                    create_date = key['CreateDate']
                    age = (datetime.datetime.now(datetime.timezone.utc) - create_date).days
                    if age > DEFAULT_AGE_DAYS:
                        results.append({"service": "IAM", "resource": f"{username}/{key_id}", "status": "CRITICAL", "issue": f"Access key is older than {DEFAULT_AGE_DAYS} days ({age} days).", "remediation": "Rotate IAM user access keys every 90 days or less.", "doc_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#rotate-access-keys"})
                    else:
                        results.append({"service": "IAM", "resource": f"{username}/{key_id}", "status": "OK", "issue": f"Access key age: {age} days."})
            except ClientError as e:
                results.append(handle_aws_exception(username, "ListAccessKeys", e))
            except Exception as e:
                results.append(handle_aws_exception(username, "ListAccessKeys", e))
    except Exception as e:
        results.append(handle_aws_exception("N/A", "ListUsers", e))
    logging.debug(f"Finished scan: IAM Access Key Age. Found {len(results)} results.")
    return results

def scan_rds_encryption_and_public(rds_client, region):
    logging.debug(f"[{region}] Starting scan: RDS Encryption & Public Access")
    results = []
    try:
        response = rds_client.describe_db_instances()
        db_instances = response.get('DBInstances', [])
        logging.debug(f"[{region}] Found {len(db_instances)} RDS instances to analyze.")
        if not db_instances:
            results.append({"service": "RDS", "resource": f"[{region}] N/A", "status": "OK", "issue": "No RDS instances found."})
        for db in db_instances:
            is_encrypted = db.get('StorageEncrypted', False)
            public = db.get('PubliclyAccessible', False)
            identifier = db.get('DBInstanceIdentifier')
            if is_encrypted:
                results.append({"service": "RDS", "resource": f"[{region}] {identifier}", "status": "OK", "issue": "Database storage is encrypted."})
            else:
                results.append({"service": "RDS", "resource": f"[{region}] {identifier}", "status": "CRITICAL", "issue": "Database storage is not encrypted.", "remediation": "Encrypt your RDS database instances at rest.", "doc_url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"})
            if public:
                results.append({"service": "RDS", "resource": f"[{region}] {identifier}", "status": "CRITICAL", "issue": "RDS instance is publicly accessible.", "remediation": "Disable public accessibility unless required.", "doc_url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ConnectToInstance.html"})
            else:
                results.append({"service": "RDS", "resource": f"[{region}] {identifier}", "status": "OK", "issue": "RDS instance is not publicly accessible."})
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "DescribeDBInstances", e))
    logging.debug(f"[{region}] Finished scan: RDS Encryption & Public Access. Found {len(results)} results.")
    return results

def scan_rds_backup_retention(rds_client, region):
    logging.debug(f"[{region}] Starting scan: RDS Backup Retention")
    results = []
    try:
        response = rds_client.describe_db_instances()
        db_instances = response.get('DBInstances', [])
        logging.debug(f"[{region}] Found {len(db_instances)} RDS instances to check for backup retention.")
        if not db_instances:
            results.append({"service": "RDS", "resource": f"[{region}] N/A", "status": "OK", "issue": "No RDS instances found."})
        for db in db_instances:
            identifier = db.get('DBInstanceIdentifier')
            retention_period = db.get('BackupRetentionPeriod', 0)
            if retention_period >= 7:
                results.append({"service": "RDS", "resource": f"[{region}] {identifier}", "status": "OK", "issue": f"Automated backups enabled with {retention_period}-day retention."})
            elif 0 < retention_period < 7:
                results.append({"service": "RDS", "resource": f"[{region}] {identifier}", "status": "WARNING", "issue": f"Backup retention period is only {retention_period} days.", "remediation": "Increase the backup retention period to 7 days or more for better data recovery options."})
            else:
                results.append({"service": "RDS", "resource": f"[{region}] {identifier}", "status": "CRITICAL", "issue": "Automated backups are disabled.", "remediation": "Enable automated backups for your RDS instances to ensure point-in-time recovery.", "doc_url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html"})
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "DescribeDBInstances", e))
    logging.debug(f"[{region}] Finished scan: RDS Backup Retention. Found {len(results)} results.")
    return results

def scan_ebs_encryption(ec2_client, region):
    logging.debug(f"[{region}] Starting scan: EBS Encryption")
    results = []
    try:
        instances_response = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped', 'stopping', 'pending']}])
        volume_ids = [device['Ebs']['VolumeId'] for res in instances_response.get('Reservations', []) for inst in res.get('Instances', []) for device in inst.get('BlockDeviceMappings', []) if 'Ebs' in device]
        if not volume_ids:
            results.append({"service": "EBS", "resource": f"[{region}] N/A", "status": "OK", "issue": "No attached EBS volumes found."})
        else:
            logging.debug(f"[{region}] Found {len(list(set(volume_ids)))} attached EBS volumes to analyze.")
            volumes_response = ec2_client.describe_volumes(VolumeIds=list(set(volume_ids)))
            for volume in volumes_response.get('Volumes', []):
                is_encrypted = volume.get('Encrypted', False)
                result = {"service": "EBS", "resource": f"[{region}] {volume['VolumeId']}", "status": "OK" if is_encrypted else "CRITICAL", "issue": "EBS volume is encrypted." if is_encrypted else "EBS volume is not encrypted."}
                if not is_encrypted:
                    result["remediation"] = "Encrypt your EBS volumes to protect the data at rest on your EC2 instances."
                    result["doc_url"] = "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html"
                results.append(result)
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "DescribeVolumes", e))
    logging.debug(f"[{region}] Finished scan: EBS Encryption. Found {len(results)} results.")
    return results

def scan_ebs_snapshot_public(ec2_client, region):
    logging.debug(f"[{region}] Starting scan: EBS Public Snapshots")
    results = []
    try:
        snaps = ec2_client.describe_snapshots(OwnerIds=['self']).get('Snapshots', [])
        logging.debug(f"[{region}] Found {len(snaps)} EBS snapshots to analyze.")
        if not snaps:
            results.append({"service": "EBS Snapshot", "resource": f"[{region}] N/A", "status": "OK", "issue": "No owned snapshots found."})
        for s in snaps:
            sid = s['SnapshotId']
            try:
                attr = ec2_client.describe_snapshot_attribute(SnapshotId=sid, Attribute='createVolumePermission')
                perms = attr.get('CreateVolumePermissions', [])
                if any(p.get('Group') == 'all' for p in perms):
                    results.append({"service": "EBS Snapshot", "resource": f"[{region}] {sid}", "status": "CRITICAL", "issue": "Snapshot is publicly shared.", "remediation": "Remove public createVolumePermission on snapshot.", "doc_url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html"})
                else:
                    results.append({"service": "EBS Snapshot", "resource": f"[{region}] {sid}", "status": "OK", "issue": "Snapshot is not publicly shared."})
            except ClientError as e:
                results.append(handle_aws_exception(f"[{region}] {sid}", "DescribeSnapshotAttribute", e))
            except Exception as e:
                results.append(handle_aws_exception(f"[{region}] {sid}", "DescribeSnapshotAttribute", e))
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "DescribeSnapshots", e))
    logging.debug(f"[{region}] Finished scan: EBS Public Snapshots. Found {len(results)} results.")
    return results

def scan_orphaned_ebs_volumes(ec2_client, region):
    logging.debug(f"[{region}] Starting scan: Orphaned EBS Volumes")
    results = []
    try:
        orphaned_volumes = ec2_client.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}]).get('Volumes', [])
        logging.debug(f"[{region}] Found {len(orphaned_volumes)} orphaned EBS volumes.")
        if not orphaned_volumes:
            results.append({"service": "EC2/EBS", "resource": f"[{region}] N/A", "status": "OK", "issue": "No orphaned (unattached) EBS volumes found."})
        for vol in orphaned_volumes:
            results.append({"service": "EC2/EBS", "resource": f"[{region}] {vol['VolumeId']}", "status": "WARNING", "issue": "EBS volume is unattached (orphaned).", "remediation": "Review unattached EBS volumes. Delete them if they are no longer needed to reduce costs."})
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "DescribeVolumes", e))
    logging.debug(f"[{region}] Finished scan: Orphaned EBS Volumes. Found {len(results)} results.")
    return results

def scan_unassociated_elastic_ips(ec2_client, region):
    logging.debug(f"[{region}] Starting scan: Unassociated Elastic IPs")
    results = []
    try:
        addresses = ec2_client.describe_addresses().get('Addresses', [])
        unassociated_ips = [addr for addr in addresses if 'AssociationId' not in addr]
        logging.debug(f"[{region}] Found {len(unassociated_ips)} unassociated Elastic IPs.")
        if not unassociated_ips:
            results.append({"service": "EC2/VPC", "resource": f"[{region}] N/A", "status": "OK", "issue": "No unassociated Elastic IPs found."})
        for ip in unassociated_ips:
            results.append({"service": "EC2/VPC", "resource": f"[{region}] {ip['PublicIp']}", "status": "WARNING", "issue": "Elastic IP is not associated with an instance.", "remediation": "Disassociate and release unused Elastic IPs to reduce costs."})
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "DescribeAddresses", e))
    logging.debug(f"[{region}] Finished scan: Unassociated Elastic IPs. Found {len(results)} results.")
    return results

def scan_ec2_public_access(ec2_client, region):
    logging.debug(f"[{region}] Starting scan: EC2 Public Access")
    results = []
    try:
        response = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped', 'stopping', 'pending']}])
        instances = [inst for res in response.get('Reservations', []) for inst in res.get('Instances', [])]
        logging.debug(f"[{region}] Found {len(instances)} EC2 instances to analyze.")
        if not instances:
            results.append({"service": "EC2", "resource": f"[{region}] N/A", "status": "OK", "issue": "No EC2 instances found."})
        for instance in instances:
            is_public = False
            reasons = []
            for sg in instance.get('SecurityGroups', []):
                try:
                    sg_response = ec2_client.describe_security_groups(GroupIds=[sg['GroupId']])
                    perms = sg_response['SecurityGroups'][0].get('IpPermissions', [])
                    for ip_permission in perms:
                        for ip_range in ip_permission.get('IpRanges', []):
                            cidr = ip_range.get('CidrIp')
                            if cidr == '0.0.0.0/0':
                                from_p = ip_permission.get('FromPort')
                                to_p = ip_permission.get('ToPort')
                                if from_p is None:
                                    port_descr = "all ports"
                                elif from_p == to_p:
                                    port_descr = f"port {from_p}"
                                else:
                                    port_descr = f"ports {from_p}-{to_p}"
                                reasons.append(f"SG {sg['GroupId']} allows {port_descr} from 0.0.0.0/0")
                                if (from_p in (22, 3389)) or (to_p in (22, 3389)) or (from_p is None):
                                    is_public = True
                except ClientError as e:
                    reasons.append(f"Could not inspect security group {sg.get('GroupId')}. Error: {e.response.get('Error',{}).get('Code')}")
                except Exception as e:
                    reasons.append(f"Could not inspect security group {sg.get('GroupId')}. Error: {str(e)}")
            result = {"service": "EC2", "resource": f"[{region}] {instance['InstanceId']}", "status": "CRITICAL" if is_public else ("WARNING" if reasons else "OK"), "issue": ", ".join(reasons) if reasons else "Instance security groups are private or non-public."}
            if is_public or reasons:
                result["remediation"] = "Avoid security group rules that allow unrestricted inbound traffic (0.0.0.0/0)."
                result["doc_url"] = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html"
            results.append(result)
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "DescribeInstances", e))
    logging.debug(f"[{region}] Finished scan: EC2 Public Access. Found {len(results)} results.")
    return results

def scan_security_groups(ec2_client, region):
    logging.debug(f"[{region}] Starting scan: VPC Security Groups")
    results = []
    try:
        sgs = ec2_client.describe_security_groups().get('SecurityGroups', [])
        logging.debug(f"[{region}] Found {len(sgs)} security groups to analyze.")
        for sg in sgs:
            sgid = sg['GroupId']
            too_open = False
            notes = []
            for perm in sg.get('IpPermissions', []):
                for ip_range in perm.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        too_open = True
                        fp = perm.get('FromPort')
                        tp = perm.get('ToPort')
                        if fp is None:
                            notes.append("Allows all ports from 0.0.0.0/0")
                        else:
                            notes.append(f"Allows ports {fp}-{tp} from 0.0.0.0/0")
            status = "CRITICAL" if too_open else "OK"
            results.append({"service": "VPC", "resource": f"[{region}] {sgid}", "status": status, "issue": "; ".join(notes) if notes else "No overly permissive rules found."})
            if too_open:
                results[-1]["remediation"] = "Tighten security group ingress rules to limit sources and ports."
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "DescribeSecurityGroups", e))
    logging.debug(f"[{region}] Finished scan: VPC Security Groups. Found {len(results)} results.")
    return results

def scan_lambda_permissions(iam_client, lambda_client, region):
    logging.debug(f"[{region}] Starting scan: Lambda Permissions")
    results = []
    try:
        functions = lambda_client.list_functions().get('Functions', [])
        logging.debug(f"[{region}] Found {len(functions)} Lambda functions to analyze.")
        if not functions:
            results.append({"service": "Lambda", "resource": f"[{region}] N/A", "status": "OK", "issue": "No Lambda functions found."})
        for func in functions:
            role_arn = func.get('Role')
            if not role_arn:
                results.append({"service": "Lambda", "resource": f"[{region}] {func.get('FunctionName')}", "status": "WARNING", "issue": "Lambda has no attached execution role."})
                continue
            role_name = role_arn.split('/')[-1]
            try:
                attached_policies = iam_client.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
                is_admin = any(p['PolicyArn'].endswith(':AdministratorAccess') or p['PolicyName'] == 'AdministratorAccess' for p in attached_policies)
                result = {"service": "Lambda", "resource": f"[{region}] {func.get('FunctionName')}", "status": "CRITICAL" if is_admin else "OK", "issue": "Function has 'AdministratorAccess' role." if is_admin else "Function has a scoped execution role."}
                if is_admin:
                    result["remediation"] = "Follow the principle of least privilege for Lambda execution roles."
                    result["doc_url"] = "https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html"
                results.append(result)
            except Exception as e:
                results.append(handle_aws_exception(f"[{region}] {func.get('FunctionName')}", "Inspect Lambda Role", e))
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "ListFunctions", e))
    logging.debug(f"[{region}] Finished scan: Lambda Permissions. Found {len(results)} results.")
    return results

def scan_ecs_task_role_admin(iam_client, ecs_client, region):
    logging.debug(f"[{region}] Starting scan: ECS Task Permissions")
    results = []
    try:
        clusters = ecs_client.list_clusters().get('clusterArns', [])
        if not clusters:
            results.append({"service": "ECS", "resource": f"[{region}] N/A", "status": "OK", "issue": "No ECS clusters found."})
        for cluster in clusters:
            tasks = ecs_client.list_tasks(cluster=cluster).get('taskArns', [])
            if not tasks:
                continue
            described = ecs_client.describe_tasks(cluster=cluster, tasks=tasks).get('tasks', [])
            for t in described:
                td_arn = t.get('taskDefinitionArn')
                if not td_arn:
                    continue
                td = ecs_client.describe_task_definition(taskDefinition=td_arn).get('taskDefinition', {})
                task_role = td.get('taskRoleArn')
                if not task_role:
                    results.append({"service": "ECS", "resource": f"[{region}] {td_arn}", "status": "WARNING", "issue": "Task definition has no taskRoleArn."})
                    continue
                role_name = task_role.split('/')[-1]
                try:
                    attached = iam_client.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
                    is_admin = any(p['PolicyArn'].endswith(':AdministratorAccess') or p['PolicyName'] == 'AdministratorAccess' for p in attached)
                    res = {"service": "ECS", "resource": f"[{region}] {role_name}", "status": "CRITICAL" if is_admin else "OK", "issue": "ECS task role has Administrator access." if is_admin else "ECS task role appears scoped."}
                    if is_admin:
                        res["remediation"] = "Reduce ECS task role privileges and follow least privilege."
                        res["doc_url"] = "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html"
                    results.append(res)
                except Exception as e:
                    results.append(handle_aws_exception(f"[{region}] {role_name}", "Inspect ECS Task Role", e))
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "ListClusters", e))
    logging.debug(f"[{region}] Finished scan: ECS Task Permissions. Found {len(results)} results.")
    return results

def scan_cloudtrail_logs(cloudtrail_client):
    logging.debug("Starting scan: CloudTrail Multi-Region Logging")
    results = []
    try:
        response = cloudtrail_client.describe_trails()
        is_enabled = any(trail.get('IsMultiRegionTrail', False) and trail.get('IsLogging', False) for trail in response.get('trailList', []))
        result = {"service": "CloudTrail", "resource": "All Regions", "status": "OK" if is_enabled else "CRITICAL", "issue": "A multi-region CloudTrail is enabled." if is_enabled else "A multi-region CloudTrail is not enabled."}
        if not is_enabled:
            result["remediation"] = "Ensure at least one CloudTrail trail is enabled for all regions."
            result["doc_url"] = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-a-trail-for-all-regions.html"
        results.append(result)
    except Exception as e:
        results.append(handle_aws_exception("N/A", "DescribeTrails", e))
    logging.debug(f"Finished scan: CloudTrail Multi-Region Logging. Found {len(results)} results.")
    return results

def scan_cloudtrail_log_file_validation(cloudtrail_client):
    logging.debug("Starting scan: CloudTrail Log File Validation")
    results = []
    try:
        trails = cloudtrail_client.describe_trails().get('trailList', [])
        logging.debug(f"Found {len(trails)} CloudTrail trails to analyze.")
        if not trails:
            results.append({"service": "CloudTrail", "resource": "N/A", "status": "OK", "issue": "No CloudTrail trails found."})
        for trail in trails:
            if trail.get('LogFileValidationEnabled'):
                results.append({"service": "CloudTrail", "resource": trail['Name'], "status": "OK", "issue": "Log file integrity validation is enabled."})
            else:
                results.append({"service": "CloudTrail", "resource": trail['Name'], "status": "CRITICAL", "issue": "Log file integrity validation is disabled.", "remediation": "Enable log file validation to ensure CloudTrail logs are not tampered with.", "doc_url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html"})
    except Exception as e:
        results.append(handle_aws_exception("N/A", "DescribeTrails", e))
    logging.debug(f"Finished scan: CloudTrail Log File Validation. Found {len(results)} results.")
    return results

def scan_guardduty_status(guardduty_client, region):
    logging.debug(f"[{region}] Starting scan: GuardDuty Status")
    results = []
    try:
        detectors = guardduty_client.list_detectors().get('DetectorIds', [])
        if detectors:
            results.append({"service": "GuardDuty", "resource": f"[{region}] Region", "status": "OK", "issue": "GuardDuty detector(s) active."})
        else:
            results.append({"service": "GuardDuty", "resource": f"[{region}] Region", "status": "CRITICAL", "issue": "GuardDuty is not enabled in this region.", "remediation": "Enable GuardDuty for threat detection.", "doc_url": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_setup.html"})
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "ListDetectors", e))
    logging.debug(f"[{region}] Finished scan: GuardDuty Status. Found {len(results)} results.")
    return results

def scan_config_status(config_client, region):
    logging.debug(f"[{region}] Starting scan: AWS Config Status")
    results = []
    try:
        status = config_client.describe_configuration_recorder_status().get('ConfigurationRecordersStatus', [])
        if not status:
            results.append({"service": "AWS Config", "resource": f"[{region}] Region", "status": "CRITICAL", "issue": "AWS Config is not enabled in this region.", "remediation": "Enable AWS Config to record and evaluate the configurations of your AWS resources.", "doc_url": "https://docs.aws.amazon.com/config/latest/developerguide/setting-up-aws-config.html"})
        elif not status[0].get('recording', False):
            results.append({"service": "AWS Config", "resource": f"[{region}] Region", "status": "CRITICAL", "issue": "AWS Config recorder is currently stopped.", "remediation": "Start the AWS Config recorder to resume configuration tracking."})
        else:
            results.append({"service": "AWS Config", "resource": f"[{region}] Region", "status": "OK", "issue": "AWS Config is enabled and recording."})
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "DescribeConfigurationRecorderStatus", e))
    logging.debug(f"[{region}] Finished scan: AWS Config Status. Found {len(results)} results.")
    return results

def scan_secrets_manager(secrets_client, region):
    logging.debug(f"[{region}] Starting scan: Secrets Manager Plaintext")
    results = []
    try:
        secrets = secrets_client.list_secrets().get('SecretList', [])
        logging.debug(f"[{region}] Found {len(secrets)} secrets to analyze.")
        if not secrets:
            results.append({"service": "SecretsManager", "resource": f"[{region}] N/A", "status": "OK", "issue": "No secrets found."})
        for s in secrets:
            name = s.get('Name')
            try:
                val = secrets_client.get_secret_value(SecretId=name)
                if 'SecretString' in val and val['SecretString']:
                    results.append({"service": "SecretsManager", "resource": f"[{region}] {name}", "status": "WARNING", "issue": "Secret contains a SecretString (potential plaintext). Manual review recommended.", "remediation": "Ensure secrets are stored correctly and rotated."})
                else:
                    results.append({"service": "SecretsManager", "resource": f"[{region}] {name}", "status": "OK", "issue": "Secret stored as binary or not exposed as a string."})
            except ClientError as e:
                results.append(handle_aws_exception(f"[{region}] {name}", "GetSecretValue", e))
            except Exception as e:
                results.append(handle_aws_exception(f"[{region}] {name}", "GetSecretValue", e))
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "ListSecrets", e))
    logging.debug(f"[{region}] Finished scan: Secrets Manager Plaintext. Found {len(results)} results.")
    return results

def scan_ssm_parameters(ssm_client, region):
    logging.debug(f"[{region}] Starting scan: SSM Parameter Plaintext")
    results = []
    try:
        paginator = ssm_client.get_paginator('describe_parameters')
        parameters = [p for page in paginator.paginate() for p in page.get('Parameters', [])]
        logging.debug(f"[{region}] Found {len(parameters)} SSM parameters to analyze.")
        for p in parameters:
            name = p.get('Name')
            ptype = p.get('Type')
            if ptype and ptype.lower() == 'string':
                results.append({"service": "SSM", "resource": f"[{region}] {name}", "status": "WARNING", "issue": "Parameter is stored as String (potential plaintext).", "remediation": "Use SecureString with KMS to encrypt sensitive parameters.", "doc_url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-security.html"})
            else:
                results.append({"service": "SSM", "resource": f"[{region}] {name}", "status": "OK", "issue": f"Parameter type: {ptype}"})
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "DescribeParameters", e))
    logging.debug(f"[{region}] Finished scan: SSM Parameter Plaintext. Found {len(results)} results.")
    return results

def get_all_scan_functions(credentials, regions=None):
    """
    Prepares and returns a list of all AWS scan functions ready to be executed.
    """
    functions_to_run = []
    
    aws_access_key_id = credentials.get('aws_access_key_id')
    aws_secret_access_key = credentials.get('aws_secret_access_key')
    
    session = boto3.Session(aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    iam_client = session.client('iam')
    s3_client = session.client('s3')
    
    # --- ADD GLOBAL SCANS ---
    functions_to_run.extend([
        ("IAM Root MFA", partial(scan_iam_root_mfa, iam_client)),
        ("IAM Password Policy", partial(scan_iam_password_policy, iam_client)),
        ("IAM Overly Permissive Roles", partial(scan_iam_overly_permissive_roles, iam_client)),
        ("IAM User Activity (Credential Report)", partial(scan_iam_users_and_keys, iam_client)),
        ("IAM Access Key Age", partial(scan_iam_users, iam_client)),
        ("S3 Public Buckets", partial(scan_s3_buckets, s3_client)),
        ("S3 Bucket Logging", partial(scan_s3_bucket_logging, s3_client)),
        ("S3 Versioning", partial(scan_s3_versioning, s3_client)),
        ("S3 Lifecycle Policies", partial(scan_s3_lifecycle, s3_client)),
    ])
    # CloudTrail is global but requires a specific region for the client
    functions_to_run.extend([
        ("CloudTrail Multi-Region Logging", partial(scan_cloudtrail_logs, session.client('cloudtrail', region_name='us-east-1'))),
        ("CloudTrail Log File Validation", partial(scan_cloudtrail_log_file_validation, session.client('cloudtrail', region_name='us-east-1'))),
    ])


    # --- PREPARE REGIONAL SCANS ---
    if not regions:
        try:
            # Use the provided session to create the client for region discovery
            ec2_global_client = session.client('ec2', region_name='us-east-1')
            regions = [r['RegionName'] for r in ec2_global_client.describe_regions(AllRegions=False).get('Regions', [])]
        except Exception as e:
            logging.error(f"Could not list regions, defaulting to us-east-1. Error: {e}")
            regions = ['us-east-1']

    for region in regions:
        try:
            ec2_client = session.client('ec2', region_name=region)
            rds_client = session.client('rds', region_name=region)
            lambda_client = session.client('lambda', region_name=region)
            ecs_client = session.client('ecs', region_name=region)
            guardduty_client = session.client('guardduty', region_name=region)
            secrets_client = session.client('secretsmanager', region_name=region)
            ssm_client = session.client('ssm', region_name=region)
            config_client = session.client('config', region_name=region)
            
            functions_to_run.extend([
                (f"[{region}] EBS Encryption", partial(scan_ebs_encryption, ec2_client, region)),
                (f"[{region}] EBS Public Snapshots", partial(scan_ebs_snapshot_public, ec2_client, region)),
                (f"[{region}] EC2 Public Access", partial(scan_ec2_public_access, ec2_client, region)),
                (f"[{region}] VPC Security Groups", partial(scan_security_groups, ec2_client, region)),
                (f"[{region}] RDS Public & Encrypted", partial(scan_rds_encryption_and_public, rds_client, region)),
                (f"[{region}] RDS Backup Retention", partial(scan_rds_backup_retention, rds_client, region)),
                (f"[{region}] Lambda Permissions", partial(scan_lambda_permissions, iam_client, lambda_client, region)),
                (f"[{region}] ECS Task Permissions", partial(scan_ecs_task_role_admin, iam_client, ecs_client, region)),
                (f"[{region}] GuardDuty Status", partial(scan_guardduty_status, guardduty_client, region)),
                (f"[{region}] AWS Config Status", partial(scan_config_status, config_client, region)),
                (f"[{region}] Secrets Manager Plaintext", partial(scan_secrets_manager, secrets_client, region)),
                (f"[{region}] SSM Parameter Plaintext", partial(scan_ssm_parameters, ssm_client, region)),
                (f"[{region}] Orphaned EBS Volumes", partial(scan_orphaned_ebs_volumes, ec2_client, region)),
                (f"[{region}] Unassociated Elastic IPs", partial(scan_unassociated_elastic_ips, ec2_client, region)),
            ])
        except Exception as e:
            logging.error(f"Could not initialize clients or add scans for region {region}. Error: {e}")

    return functions_to_run