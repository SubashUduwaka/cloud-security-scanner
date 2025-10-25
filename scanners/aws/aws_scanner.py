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

def scan_iam_overly_permissive_users(iam_client):
    """
    Scan IAM users for overly permissive policies.
    Checks both attached managed policies and inline policies for admin-like permissions.
    """
    logging.debug("Starting scan: IAM Overly Permissive Users")
    results = []
    try:
        paginator = iam_client.get_paginator('list_users')
        users = [user for page in paginator.paginate() for user in page.get('Users', [])]
        logging.debug(f"Found {len(users)} IAM users to analyze for overly permissive access.")

        for user in users:
            user_name = user['UserName']
            is_admin = False
            admin_policies = []

            try:
                # Check attached managed policies
                attached = iam_client.list_attached_user_policies(UserName=user_name).get('AttachedPolicies', [])
                for p in attached:
                    policy_name = p.get('PolicyName')
                    policy_arn = p.get('PolicyArn', '')

                    # Check for Administrator Access or PowerUser Access
                    if policy_name in ['AdministratorAccess', 'PowerUserAccess'] or policy_arn.endswith(':AdministratorAccess') or policy_arn.endswith(':PowerUserAccess'):
                        is_admin = True
                        admin_policies.append(policy_name)
                        break

                # Check inline policies if not already flagged as admin
                if not is_admin:
                    inline = iam_client.list_user_policies(UserName=user_name).get('PolicyNames', [])
                    for pname in inline:
                        doc = iam_client.get_user_policy(UserName=user_name, PolicyName=pname)['PolicyDocument']
                        doc_str = json.dumps(doc)

                        # Check for wildcard permissions
                        if ('"Action": "*"' in doc_str and '"Resource": "*"' in doc_str) or \
                           ('"Action":"*"' in doc_str and '"Resource":"*"' in doc_str) or \
                           ("'Action': '*'" in doc_str and "'Resource': '*'" in doc_str):
                            is_admin = True
                            admin_policies.append(f"Inline:{pname}")
                            break

            except ClientError as e:
                results.append(handle_aws_exception(user_name, "Inspect User Policies", e))
                continue
            except Exception as e:
                results.append(handle_aws_exception(user_name, "Inspect User Policies", e))
                continue

            # Create result based on findings
            if is_admin:
                policy_list = ", ".join(admin_policies) if admin_policies else "detected"
                result = {
                    "service": "IAM",
                    "resource": user_name,
                    "status": "CRITICAL",
                    "issue": f"User has overly permissive (Administrator-like) access via: {policy_list}",
                    "remediation": "Review user permissions and apply principle of least privilege. Avoid granting full AdministratorAccess to IAM users. Consider using roles instead.",
                    "doc_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
                }
                results.append(result)
            else:
                results.append({
                    "service": "IAM",
                    "resource": user_name,
                    "status": "OK",
                    "issue": "User has appropriately scoped permissions."
                })

    except Exception as e:
        results.append(handle_aws_exception("N/A", "ListUsers", e))

    logging.debug(f"Finished scan: IAM Overly Permissive Users. Found {len(results)} results.")
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

def scan_iam_user_mfa(iam_client):
    """Check if IAM users have MFA enabled"""
    logging.debug("Starting scan: IAM User MFA")
    results = []
    try:
        paginator = iam_client.get_paginator('list_users')
        users = [user for page in paginator.paginate() for user in page.get('Users', [])]
        logging.debug(f"Found {len(users)} IAM users to check for MFA.")

        for user in users:
            username = user['UserName']
            try:
                mfa_devices = iam_client.list_mfa_devices(UserName=username).get('MFADevices', [])
                if mfa_devices:
                    results.append({"service": "IAM", "resource": username, "status": "OK", "issue": "MFA is enabled for this user."})
                else:
                    results.append({"service": "IAM", "resource": username, "status": "CRITICAL", "issue": "MFA is not enabled for this user.", "remediation": "Enable MFA for all IAM users with console access to add an extra layer of security.", "doc_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"})
            except ClientError as e:
                results.append(handle_aws_exception(username, "ListMFADevices", e))
            except Exception as e:
                results.append(handle_aws_exception(username, "ListMFADevices", e))
    except Exception as e:
        results.append(handle_aws_exception("N/A", "ListUsers", e))

    logging.debug(f"Finished scan: IAM User MFA. Found {len(results)} results.")
    return results

def scan_iam_unused_credentials(iam_client):
    """Detect IAM users with credentials that haven't been used in 90+ days"""
    logging.debug("Starting scan: IAM Unused Credentials")
    results = []
    try:
        try:
            iam_client.generate_credential_report()
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') != 'ReportInProgress':
                raise e

        report = iam_client.get_credential_report()
        content = report.get('Content')
        if content:
            csvfile = io.StringIO(content.decode('utf-8'))
            reader = csv.DictReader(csvfile)

            for row in reader:
                user = row.get('user')
                if user == '<root_account>':
                    continue

                password_enabled = row.get('password_enabled') == 'true'
                password_last_used = row.get('password_last_used')

                ak1_active = row.get('access_key_1_active') == 'true'
                ak1_last_used = row.get('access_key_1_last_used_date')

                ak2_active = row.get('access_key_2_active') == 'true'
                ak2_last_used = row.get('access_key_2_last_used_date')

                unused_items = []

                # Check password
                if password_enabled:
                    if password_last_used in ['N/A', 'no_information']:
                        unused_items.append("password (never used)")
                    else:
                        try:
                            dt = datetime.datetime.fromisoformat(password_last_used.replace('Z', '+00:00'))
                            age_days = (datetime.datetime.now(datetime.timezone.utc) - dt).days
                            if age_days > 90:
                                unused_items.append(f"password (unused for {age_days} days)")
                        except:
                            pass

                # Check access key 1
                if ak1_active:
                    if ak1_last_used in ['N/A', 'no_information']:
                        unused_items.append("access key 1 (never used)")
                    else:
                        try:
                            dt = datetime.datetime.fromisoformat(ak1_last_used.replace('Z', '+00:00'))
                            age_days = (datetime.datetime.now(datetime.timezone.utc) - dt).days
                            if age_days > 90:
                                unused_items.append(f"access key 1 (unused for {age_days} days)")
                        except:
                            pass

                # Check access key 2
                if ak2_active:
                    if ak2_last_used in ['N/A', 'no_information']:
                        unused_items.append("access key 2 (never used)")
                    else:
                        try:
                            dt = datetime.datetime.fromisoformat(ak2_last_used.replace('Z', '+00:00'))
                            age_days = (datetime.datetime.now(datetime.timezone.utc) - dt).days
                            if age_days > 90:
                                unused_items.append(f"access key 2 (unused for {age_days} days)")
                        except:
                            pass

                if unused_items:
                    results.append({
                        "service": "IAM",
                        "resource": user,
                        "status": "WARNING",
                        "issue": f"User has unused credentials: {', '.join(unused_items)}",
                        "remediation": "Deactivate or remove unused credentials to reduce security risk.",
                        "doc_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html"
                    })
                else:
                    results.append({"service": "IAM", "resource": user, "status": "OK", "issue": "All credentials are actively used."})

    except Exception as e:
        results.append(handle_aws_exception("IAM Users", "GetCredentialReport", e))

    logging.debug(f"Finished scan: IAM Unused Credentials. Found {len(results)} results.")
    return results

def scan_s3_encryption(s3_client):
    """Check if S3 buckets have encryption enabled"""
    logging.debug("Starting scan: S3 Bucket Encryption")
    results = []
    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        logging.debug(f"Found {len(buckets)} S3 buckets to check for encryption.")

        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                results.append({"service": "S3", "resource": bucket_name, "status": "OK", "issue": "Bucket encryption is enabled."})
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') == 'ServerSideEncryptionConfigurationNotFoundError':
                    results.append({
                        "service": "S3",
                        "resource": bucket_name,
                        "status": "CRITICAL",
                        "issue": "Bucket does not have default encryption enabled.",
                        "remediation": "Enable default encryption (SSE-S3 or SSE-KMS) for your S3 bucket.",
                        "doc_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"
                    })
                else:
                    results.append(handle_aws_exception(bucket_name, "GetBucketEncryption", e))
            except Exception as e:
                results.append(handle_aws_exception(bucket_name, "GetBucketEncryption", e))

    except Exception as e:
        results.append(handle_aws_exception("N/A", "ListBuckets", e))

    logging.debug(f"Finished scan: S3 Bucket Encryption. Found {len(results)} results.")
    return results

def scan_s3_bucket_policies(s3_client):
    """Check S3 bucket policies for overly permissive access"""
    logging.debug("Starting scan: S3 Bucket Policies")
    results = []
    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        logging.debug(f"Found {len(buckets)} S3 buckets to check policies.")

        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy = json.loads(policy_response.get('Policy', '{}'))

                issues = []
                for statement in policy.get('Statement', []):
                    principal = statement.get('Principal', {})
                    action = statement.get('Action', [])
                    effect = statement.get('Effect', '')

                    if effect == 'Allow':
                        # Check for public access
                        if principal == '*' or principal == {"AWS": "*"}:
                            issues.append("allows public access")

                        # Check for wildcard actions
                        if action == '*' or 's3:*' in action:
                            issues.append("allows all S3 actions")

                if issues:
                    results.append({
                        "service": "S3",
                        "resource": bucket_name,
                        "status": "CRITICAL",
                        "issue": f"Bucket policy {', '.join(issues)}.",
                        "remediation": "Review and restrict bucket policy to follow principle of least privilege.",
                        "doc_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html"
                    })
                else:
                    results.append({"service": "S3", "resource": bucket_name, "status": "OK", "issue": "Bucket policy appears appropriately scoped."})

            except ClientError as e:
                if e.response.get('Error', {}).get('Code') == 'NoSuchBucketPolicy':
                    results.append({"service": "S3", "resource": bucket_name, "status": "OK", "issue": "No bucket policy configured."})
                else:
                    results.append(handle_aws_exception(bucket_name, "GetBucketPolicy", e))
            except Exception as e:
                results.append(handle_aws_exception(bucket_name, "GetBucketPolicy", e))

    except Exception as e:
        results.append(handle_aws_exception("N/A", "ListBuckets", e))

    logging.debug(f"Finished scan: S3 Bucket Policies. Found {len(results)} results.")
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

def scan_rds_multi_az(rds_client, region):
    """Check if RDS instances have Multi-AZ enabled for high availability"""
    logging.debug(f"[{region}] Starting scan: RDS Multi-AZ")
    results = []
    try:
        response = rds_client.describe_db_instances()
        db_instances = response.get('DBInstances', [])
        logging.debug(f"[{region}] Found {len(db_instances)} RDS instances to check Multi-AZ status.")

        if not db_instances:
            results.append({"service": "RDS", "resource": f"[{region}] N/A", "status": "OK", "issue": "No RDS instances found."})
        for db in db_instances:
            identifier = db.get('DBInstanceIdentifier')
            multi_az = db.get('MultiAZ', False)

            if multi_az:
                results.append({"service": "RDS", "resource": f"[{region}] {identifier}", "status": "OK", "issue": "Multi-AZ is enabled."})
            else:
                results.append({
                    "service": "RDS",
                    "resource": f"[{region}] {identifier}",
                    "status": "WARNING",
                    "issue": "Multi-AZ is not enabled.",
                    "remediation": "Enable Multi-AZ for production databases to ensure high availability and automatic failover.",
                    "doc_url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html"
                })
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "DescribeDBInstances", e))

    logging.debug(f"[{region}] Finished scan: RDS Multi-AZ. Found {len(results)} results.")
    return results

def scan_rds_deletion_protection(rds_client, region):
    """Check if RDS instances have deletion protection enabled"""
    logging.debug(f"[{region}] Starting scan: RDS Deletion Protection")
    results = []
    try:
        response = rds_client.describe_db_instances()
        db_instances = response.get('DBInstances', [])
        logging.debug(f"[{region}] Found {len(db_instances)} RDS instances to check deletion protection.")

        if not db_instances:
            results.append({"service": "RDS", "resource": f"[{region}] N/A", "status": "OK", "issue": "No RDS instances found."})
        for db in db_instances:
            identifier = db.get('DBInstanceIdentifier')
            deletion_protection = db.get('DeletionProtection', False)

            if deletion_protection:
                results.append({"service": "RDS", "resource": f"[{region}] {identifier}", "status": "OK", "issue": "Deletion protection is enabled."})
            else:
                results.append({
                    "service": "RDS",
                    "resource": f"[{region}] {identifier}",
                    "status": "WARNING",
                    "issue": "Deletion protection is not enabled.",
                    "remediation": "Enable deletion protection for production databases to prevent accidental deletion.",
                    "doc_url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html"
                })
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "DescribeDBInstances", e))

    logging.debug(f"[{region}] Finished scan: RDS Deletion Protection. Found {len(results)} results.")
    return results

def scan_ec2_imdsv2(ec2_client, region):
    """Check if EC2 instances enforce IMDSv2 (Instance Metadata Service v2)"""
    logging.debug(f"[{region}] Starting scan: EC2 IMDSv2")
    results = []
    try:
        instances_response = ec2_client.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}]
        )

        instances = [inst for res in instances_response.get('Reservations', []) for inst in res.get('Instances', [])]
        logging.debug(f"[{region}] Found {len(instances)} EC2 instances to check IMDSv2 enforcement.")

        if not instances:
            results.append({"service": "EC2", "resource": f"[{region}] N/A", "status": "OK", "issue": "No EC2 instances found."})

        for inst in instances:
            instance_id = inst.get('InstanceId')
            metadata_options = inst.get('MetadataOptions', {})
            http_tokens = metadata_options.get('HttpTokens', 'optional')

            if http_tokens == 'required':
                results.append({"service": "EC2", "resource": f"[{region}] {instance_id}", "status": "OK", "issue": "IMDSv2 is enforced (required)."})
            else:
                results.append({
                    "service": "EC2",
                    "resource": f"[{region}] {instance_id}",
                    "status": "WARNING",
                    "issue": "IMDSv2 is not enforced (optional or disabled).",
                    "remediation": "Require IMDSv2 to protect against SSRF attacks and improve security.",
                    "doc_url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"
                })
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "DescribeInstances", e))

    logging.debug(f"[{region}] Finished scan: EC2 IMDSv2. Found {len(results)} results.")
    return results

def scan_ec2_instances_without_iam_roles(ec2_client, region):
    """Check if EC2 instances have IAM roles attached"""
    logging.debug(f"[{region}] Starting scan: EC2 Instances without IAM Roles")
    results = []
    try:
        instances_response = ec2_client.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )

        instances = [inst for res in instances_response.get('Reservations', []) for inst in res.get('Instances', [])]
        logging.debug(f"[{region}] Found {len(instances)} running EC2 instances to check for IAM roles.")

        if not instances:
            results.append({"service": "EC2", "resource": f"[{region}] N/A", "status": "OK", "issue": "No running EC2 instances found."})

        for inst in instances:
            instance_id = inst.get('InstanceId')
            iam_instance_profile = inst.get('IamInstanceProfile')

            if iam_instance_profile:
                results.append({"service": "EC2", "resource": f"[{region}] {instance_id}", "status": "OK", "issue": "Instance has an IAM role attached."})
            else:
                results.append({
                    "service": "EC2",
                    "resource": f"[{region}] {instance_id}",
                    "status": "WARNING",
                    "issue": "Instance does not have an IAM role attached.",
                    "remediation": "Attach an IAM role to the instance instead of using hardcoded credentials.",
                    "doc_url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html"
                })
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "DescribeInstances", e))

    logging.debug(f"[{region}] Finished scan: EC2 Instances without IAM Roles. Found {len(results)} results.")
    return results

def scan_vpc_flow_logs(ec2_client, region):
    """Check if VPCs have flow logs enabled"""
    logging.debug(f"[{region}] Starting scan: VPC Flow Logs")
    results = []
    try:
        vpcs_response = ec2_client.describe_vpcs()
        vpcs = vpcs_response.get('Vpcs', [])
        logging.debug(f"[{region}] Found {len(vpcs)} VPCs to check for flow logs.")

        if not vpcs:
            results.append({"service": "VPC", "resource": f"[{region}] N/A", "status": "OK", "issue": "No VPCs found."})

        for vpc in vpcs:
            vpc_id = vpc.get('VpcId')

            # Check for flow logs
            flow_logs_response = ec2_client.describe_flow_logs(
                Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
            )
            flow_logs = flow_logs_response.get('FlowLogs', [])

            if flow_logs:
                results.append({"service": "VPC", "resource": f"[{region}] {vpc_id}", "status": "OK", "issue": "VPC Flow Logs are enabled."})
            else:
                results.append({
                    "service": "VPC",
                    "resource": f"[{region}] {vpc_id}",
                    "status": "CRITICAL",
                    "issue": "VPC Flow Logs are not enabled.",
                    "remediation": "Enable VPC Flow Logs to capture IP traffic information for network monitoring and security analysis.",
                    "doc_url": "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"
                })
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "DescribeVpcs", e))

    logging.debug(f"[{region}] Finished scan: VPC Flow Logs. Found {len(results)} results.")
    return results

def scan_kms_key_rotation(kms_client, region):
    """Check if KMS keys have automatic key rotation enabled"""
    logging.debug(f"[{region}] Starting scan: KMS Key Rotation")
    results = []
    try:
        keys_response = kms_client.list_keys()
        keys = keys_response.get('Keys', [])
        logging.debug(f"[{region}] Found {len(keys)} KMS keys to check rotation status.")

        if not keys:
            results.append({"service": "KMS", "resource": f"[{region}] N/A", "status": "OK", "issue": "No KMS keys found."})

        for key in keys:
            key_id = key.get('KeyId')

            try:
                # Get key metadata to check if it's customer-managed
                key_metadata = kms_client.describe_key(KeyId=key_id).get('KeyMetadata', {})
                key_manager = key_metadata.get('KeyManager')

                # Only check customer-managed keys
                if key_manager == 'CUSTOMER':
                    rotation_status = kms_client.get_key_rotation_status(KeyId=key_id)
                    key_rotation_enabled = rotation_status.get('KeyRotationEnabled', False)

                    if key_rotation_enabled:
                        results.append({"service": "KMS", "resource": f"[{region}] {key_id}", "status": "OK", "issue": "Automatic key rotation is enabled."})
                    else:
                        results.append({
                            "service": "KMS",
                            "resource": f"[{region}] {key_id}",
                            "status": "WARNING",
                            "issue": "Automatic key rotation is not enabled.",
                            "remediation": "Enable automatic key rotation for customer-managed KMS keys to enhance security.",
                            "doc_url": "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"
                        })
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') not in ['AccessDeniedException', 'UnsupportedOperationException']:
                    results.append(handle_aws_exception(f"[{region}] {key_id}", "GetKeyRotationStatus", e))
            except Exception as e:
                results.append(handle_aws_exception(f"[{region}] {key_id}", "GetKeyRotationStatus", e))

    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "ListKeys", e))

    logging.debug(f"[{region}] Finished scan: KMS Key Rotation. Found {len(results)} results.")
    return results

def scan_elb_access_logs(elb_client, elbv2_client, region):
    """Check if ELB/ALB have access logs enabled"""
    logging.debug(f"[{region}] Starting scan: ELB/ALB Access Logs")
    results = []

    # Check Classic Load Balancers
    try:
        classic_lbs = elb_client.describe_load_balancers().get('LoadBalancerDescriptions', [])
        logging.debug(f"[{region}] Found {len(classic_lbs)} Classic Load Balancers.")

        for lb in classic_lbs:
            lb_name = lb.get('LoadBalancerName')
            attributes = elb_client.describe_load_balancer_attributes(LoadBalancerName=lb_name)
            access_log = attributes.get('LoadBalancerAttributes', {}).get('AccessLog', {})
            enabled = access_log.get('Enabled', False)

            if enabled:
                results.append({"service": "ELB", "resource": f"[{region}] {lb_name}", "status": "OK", "issue": "Access logs are enabled."})
            else:
                results.append({
                    "service": "ELB",
                    "resource": f"[{region}] {lb_name}",
                    "status": "WARNING",
                    "issue": "Access logs are not enabled.",
                    "remediation": "Enable access logs for load balancers to capture detailed information about requests.",
                    "doc_url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/access-log-collection.html"
                })
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] Classic ELB", "DescribeLoadBalancers", e))

    # Check Application/Network Load Balancers
    try:
        albs = elbv2_client.describe_load_balancers().get('LoadBalancers', [])
        logging.debug(f"[{region}] Found {len(albs)} ALB/NLB Load Balancers.")

        for lb in albs:
            lb_arn = lb.get('LoadBalancerArn')
            lb_name = lb.get('LoadBalancerName')

            attributes = elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
            access_log_enabled = False

            for attr in attributes.get('Attributes', []):
                if attr.get('Key') == 'access_logs.s3.enabled':
                    access_log_enabled = attr.get('Value') == 'true'
                    break

            if access_log_enabled:
                results.append({"service": "ALB/NLB", "resource": f"[{region}] {lb_name}", "status": "OK", "issue": "Access logs are enabled."})
            else:
                results.append({
                    "service": "ALB/NLB",
                    "resource": f"[{region}] {lb_name}",
                    "status": "WARNING",
                    "issue": "Access logs are not enabled.",
                    "remediation": "Enable access logs for load balancers to capture detailed information about requests.",
                    "doc_url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html"
                })
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] ALB/NLB", "DescribeLoadBalancers", e))

    logging.debug(f"[{region}] Finished scan: ELB/ALB Access Logs. Found {len(results)} results.")
    return results

def scan_cloudwatch_log_retention(logs_client, region):
    """Check CloudWatch log groups for retention settings"""
    logging.debug(f"[{region}] Starting scan: CloudWatch Log Retention")
    results = []
    try:
        log_groups = []
        paginator = logs_client.get_paginator('describe_log_groups')
        for page in paginator.paginate():
            log_groups.extend(page.get('logGroups', []))

        logging.debug(f"[{region}] Found {len(log_groups)} CloudWatch log groups.")

        if not log_groups:
            results.append({"service": "CloudWatch Logs", "resource": f"[{region}] N/A", "status": "OK", "issue": "No log groups found."})

        for log_group in log_groups:
            log_group_name = log_group.get('logGroupName')
            retention_in_days = log_group.get('retentionInDays')

            if retention_in_days:
                results.append({"service": "CloudWatch Logs", "resource": f"[{region}] {log_group_name}", "status": "OK", "issue": f"Retention period is set to {retention_in_days} days."})
            else:
                results.append({
                    "service": "CloudWatch Logs",
                    "resource": f"[{region}] {log_group_name}",
                    "status": "WARNING",
                    "issue": "No retention period set (logs retained indefinitely).",
                    "remediation": "Set a retention period for CloudWatch log groups to control storage costs.",
                    "doc_url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html"
                })
    except Exception as e:
        results.append(handle_aws_exception(f"[{region}] N/A", "DescribeLogGroups", e))

    logging.debug(f"[{region}] Finished scan: CloudWatch Log Retention. Found {len(results)} results.")
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
    
    # Validate credentials before proceeding
    if not aws_access_key_id or not aws_secret_access_key:
        logging.error("AWS credentials are missing or invalid")
        return [("Credential Validation", lambda: [{"service": "AWS Scanner", "resource": "Credentials", "status": "ERROR", "issue": "Missing AWS access key ID or secret access key.", "remediation": "Please provide valid AWS credentials in the settings page."}])]
    
    if aws_access_key_id == "your_access_key_here" or aws_secret_access_key == "your_secret_key_here":
        logging.error("AWS credentials appear to be placeholder values")
        return [("Credential Validation", lambda: [{"service": "AWS Scanner", "resource": "Credentials", "status": "ERROR", "issue": "AWS credentials appear to be placeholder or test values.", "remediation": "Please replace the placeholder credentials with real AWS access keys from your AWS account."}])]
    
    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name='us-east-1'
        )

        # Test the credentials by making a simple call with explicit region
        sts_client = session.client('sts', region_name='us-east-1')
        identity = sts_client.get_caller_identity()
        logging.info(f"AWS credentials validated successfully for account: {identity.get('Account', 'unknown')}")

        # IAM is global but needs a region endpoint
        iam_client = session.client('iam', region_name='us-east-1')
        s3_client = session.client('s3', region_name='us-east-1')
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'InvalidUserID.NotFound':
            error_msg = "AWS credentials are invalid - access key not found."
        elif error_code == 'SignatureDoesNotMatch':
            error_msg = "AWS credentials are invalid - secret access key is incorrect."
        elif error_code == 'TokenRefreshRequired':
            error_msg = "AWS credentials have expired or require refresh."
        else:
            error_msg = f"AWS credential validation failed: {e.response.get('Error', {}).get('Message', str(e))}"
        
        logging.error(f"AWS credential validation failed: {error_msg}")
        return [("Credential Validation", lambda: [{"service": "AWS Scanner", "resource": "Credentials", "status": "ERROR", "issue": error_msg, "remediation": "Please check your AWS credentials and ensure they are valid and have the necessary permissions."}])]
        
    except Exception as e:
        error_msg = f"Failed to create AWS session: {str(e)}"
        logging.error(error_msg)
        return [("Credential Validation", lambda: [{"service": "AWS Scanner", "resource": "Credentials", "status": "ERROR", "issue": error_msg, "remediation": "Please check your AWS credentials and network connectivity."}])]
    

    functions_to_run.extend([
        ("IAM Root MFA", partial(scan_iam_root_mfa, iam_client)),
        ("IAM Password Policy", partial(scan_iam_password_policy, iam_client)),
        ("IAM Overly Permissive Roles", partial(scan_iam_overly_permissive_roles, iam_client)),
        ("IAM Overly Permissive Users", partial(scan_iam_overly_permissive_users, iam_client)),
        ("IAM User MFA Enforcement", partial(scan_iam_user_mfa, iam_client)),
        ("IAM Unused Credentials", partial(scan_iam_unused_credentials, iam_client)),
        ("IAM User Activity (Credential Report)", partial(scan_iam_users_and_keys, iam_client)),
        ("IAM Access Key Age", partial(scan_iam_users, iam_client)),
        ("S3 Public Buckets", partial(scan_s3_buckets, s3_client)),
        ("S3 Bucket Logging", partial(scan_s3_bucket_logging, s3_client)),
        ("S3 Bucket Encryption", partial(scan_s3_encryption, s3_client)),
        ("S3 Bucket Policies", partial(scan_s3_bucket_policies, s3_client)),
        ("S3 Versioning", partial(scan_s3_versioning, s3_client)),
        ("S3 Lifecycle Policies", partial(scan_s3_lifecycle, s3_client)),
    ])
    # Global AWS services (scanned once, not per region)
    functions_to_run.extend([
        ("CloudTrail Multi-Region Logging", partial(scan_cloudtrail_logs, session.client('cloudtrail', region_name='us-east-1'))),
        ("CloudTrail Log File Validation", partial(scan_cloudtrail_log_file_validation, session.client('cloudtrail', region_name='us-east-1'))),
        ("Route53 Domain Security", partial(scan_route53_domains, session.client('route53', region_name='us-east-1'))),
        ("Route53 Health Checks", partial(scan_route53_health_checks, session.client('route53', region_name='us-east-1'))),
        ("Organizations Account Security", partial(scan_organizations_accounts, session.client('organizations', region_name='us-east-1'))),
        ("Organizations SCPs", partial(scan_organizations_scps, session.client('organizations', region_name='us-east-1'))),
        ("AWS Shield Advanced Protection", partial(scan_shield_advanced, session.client('shield', region_name='us-east-1'))),
        ("Global CloudFront Distributions", partial(scan_cloudfront_distributions, session.client('cloudfront', region_name='us-east-1'))),
        ("Global WAF Classic Rules", partial(scan_waf_classic, session.client('waf', region_name='us-east-1'))),
        ("Trusted Advisor Checks", partial(scan_trusted_advisor, session.client('support', region_name='us-east-1'))),
        ("Cost Explorer Recommendations", partial(scan_cost_explorer, session.client('ce', region_name='us-east-1'))),
        ("AWS Budgets Configuration", partial(scan_budgets, session.client('budgets', region_name='us-east-1'))),
    ])

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
            
            # Additional AWS services for comprehensive scanning
            cloudformation_client = session.client('cloudformation', region_name=region)
            route53_client = session.client('route53', region_name='us-east-1')  # Route53 is global
            acm_client = session.client('acm', region_name=region)
            kms_client = session.client('kms', region_name=region)
            dynamodb_client = session.client('dynamodb', region_name=region)
            sns_client = session.client('sns', region_name=region)
            sqs_client = session.client('sqs', region_name=region)
            apigateway_client = session.client('apigateway', region_name=region)
            apigatewayv2_client = session.client('apigatewayv2', region_name=region)
            elasticache_client = session.client('elasticache', region_name=region)
            efs_client = session.client('efs', region_name=region)
            redshift_client = session.client('redshift', region_name=region)
            elasticsearch_client = session.client('es', region_name=region)
            elbv2_client = session.client('elbv2', region_name=region)
            elb_client = session.client('elb', region_name=region)
            autoscaling_client = session.client('autoscaling', region_name=region)
            cloudwatch_client = session.client('cloudwatch', region_name=region)
            logs_client = session.client('logs', region_name=region)
            kinesis_client = session.client('kinesis', region_name=region)
            firehose_client = session.client('firehose', region_name=region)
            backup_client = session.client('backup', region_name=region)
            glue_client = session.client('glue', region_name=region)
            emr_client = session.client('emr', region_name=region)
            batch_client = session.client('batch', region_name=region)
            codebuild_client = session.client('codebuild', region_name=region)
            codecommit_client = session.client('codecommit', region_name=region)
            codepipeline_client = session.client('codepipeline', region_name=region)
            organizations_client = session.client('organizations', region_name='us-east-1')  # Global service
            inspector_client = session.client('inspector', region_name=region)
            macie_client = session.client('macie2', region_name=region)
            wafv2_client = session.client('wafv2', region_name=region)
            shield_client = session.client('shield', region_name='us-east-1')  # Global service
            
            functions_to_run.extend([
                # Existing scans
                (f"[{region}] EBS Encryption", partial(scan_ebs_encryption, ec2_client, region)),
                (f"[{region}] EBS Public Snapshots", partial(scan_ebs_snapshot_public, ec2_client, region)),
                (f"[{region}] EC2 Public Access", partial(scan_ec2_public_access, ec2_client, region)),
                (f"[{region}] VPC Security Groups", partial(scan_security_groups, ec2_client, region)),
                (f"[{region}] RDS Public & Encrypted", partial(scan_rds_encryption_and_public, rds_client, region)),
                (f"[{region}] RDS Backup Retention", partial(scan_rds_backup_retention, rds_client, region)),
                (f"[{region}] RDS Multi-AZ", partial(scan_rds_multi_az, rds_client, region)),
                (f"[{region}] RDS Deletion Protection", partial(scan_rds_deletion_protection, rds_client, region)),
                (f"[{region}] EC2 IMDSv2 Enforcement", partial(scan_ec2_imdsv2, ec2_client, region)),
                (f"[{region}] EC2 Instances without IAM Roles", partial(scan_ec2_instances_without_iam_roles, ec2_client, region)),
                (f"[{region}] VPC Flow Logs", partial(scan_vpc_flow_logs, ec2_client, region)),
                (f"[{region}] CloudWatch Log Retention", partial(scan_cloudwatch_log_retention, logs_client, region)),
                (f"[{region}] ELB/ALB Access Logs", partial(scan_elb_access_logs, elb_client, elbv2_client, region)),
                (f"[{region}] Lambda Permissions", partial(scan_lambda_permissions, iam_client, lambda_client, region)),
                (f"[{region}] ECS Task Permissions", partial(scan_ecs_task_role_admin, iam_client, ecs_client, region)),
                (f"[{region}] GuardDuty Status", partial(scan_guardduty_status, guardduty_client, region)),
                (f"[{region}] AWS Config Status", partial(scan_config_status, config_client, region)),
                (f"[{region}] Secrets Manager Plaintext", partial(scan_secrets_manager, secrets_client, region)),
                (f"[{region}] SSM Parameter Plaintext", partial(scan_ssm_parameters, ssm_client, region)),
                (f"[{region}] Orphaned EBS Volumes", partial(scan_orphaned_ebs_volumes, ec2_client, region)),
                (f"[{region}] Unassociated Elastic IPs", partial(scan_unassociated_elastic_ips, ec2_client, region)),
                
                # New comprehensive scans
                (f"[{region}] CloudFormation Stack Drift", partial(scan_cloudformation_drift, cloudformation_client, region)),
                (f"[{region}] CloudFormation Stack Protection", partial(scan_cloudformation_termination_protection, cloudformation_client, region)),
                (f"[{region}] ACM Certificate Expiry", partial(scan_acm_certificates, acm_client, region)),
                (f"[{region}] KMS Key Rotation", partial(scan_kms_key_rotation, kms_client, region)),
                (f"[{region}] KMS Key Usage", partial(scan_kms_unused_keys, kms_client, region)),
                (f"[{region}] DynamoDB Encryption", partial(scan_dynamodb_encryption, dynamodb_client, region)),
                (f"[{region}] DynamoDB Backup", partial(scan_dynamodb_backup, dynamodb_client, region)),
                (f"[{region}] SNS Topic Encryption", partial(scan_sns_encryption, sns_client, region)),
                (f"[{region}] SQS Queue Encryption", partial(scan_sqs_encryption, sqs_client, region)),
                (f"[{region}] API Gateway Logging", partial(scan_api_gateway_logging, apigateway_client, region)),
                (f"[{region}] API Gateway V2 Logging", partial(scan_api_gateway_v2_logging, apigatewayv2_client, region)),
                (f"[{region}] EFS Encryption", partial(scan_efs_encryption, efs_client, region)),
                (f"[{region}] ElastiCache Clusters", partial(scan_elasticache_clusters, elasticache_client, region)),
                (f"[{region}] Redshift Clusters", partial(scan_redshift_clusters, redshift_client, region)),
                (f"[{region}] Elasticsearch Encryption", partial(scan_elasticsearch_encryption, elasticsearch_client, region)),
                (f"[{region}] Load Balancer Security", partial(scan_load_balancer_security, elbv2_client, elb_client, region)),
                (f"[{region}] Auto Scaling Health Checks", partial(scan_autoscaling_health_checks, autoscaling_client, region)),
                (f"[{region}] CloudWatch Log Retention", partial(scan_cloudwatch_log_retention, logs_client, region)),
                (f"[{region}] Kinesis Encryption", partial(scan_kinesis_encryption, kinesis_client, region)),
                (f"[{region}] Kinesis Firehose Encryption", partial(scan_firehose_encryption, firehose_client, region)),
                (f"[{region}] AWS Backup Configuration", partial(scan_backup_configuration, backup_client, region)),
                (f"[{region}] Glue Data Catalog Encryption", partial(scan_glue_encryption, glue_client, region)),
                (f"[{region}] EMR Cluster Security", partial(scan_emr_security, emr_client, region)),
                (f"[{region}] Batch Job Security", partial(scan_batch_security, batch_client, region)),
                (f"[{region}] CodeBuild Project Security", partial(scan_codebuild_security, codebuild_client, region)),
                (f"[{region}] CodeCommit Repository Encryption", partial(scan_codecommit_encryption, codecommit_client, region)),
                (f"[{region}] CodePipeline Encryption", partial(scan_codepipeline_encryption, codepipeline_client, region)),
                (f"[{region}] Inspector Assessment Targets", partial(scan_inspector_targets, inspector_client, region)),
                (f"[{region}] Macie Classification Jobs", partial(scan_macie_jobs, macie_client, region)),
                (f"[{region}] WAF Web ACLs", partial(scan_waf_web_acls, wafv2_client, region)),
                (f"[{region}] VPC Flow Logs", partial(scan_vpc_flow_logs, ec2_client, region)),
                (f"[{region}] EC2 Instance Metadata", partial(scan_ec2_metadata_service, ec2_client, region)),
                (f"[{region}] RDS Performance Insights", partial(scan_rds_performance_insights, rds_client, region)),
                (f"[{region}] Lambda Dead Letter Queues", partial(scan_lambda_dlq, lambda_client, region)),
                (f"[{region}] CloudWatch Alarms", partial(scan_cloudwatch_alarms, cloudwatch_client, region)),
            ])
        except Exception as e:
            logging.error(f"Could not initialize clients or add scans for region {region}. Error: {e}")

    return functions_to_run


def scan_route53_domains(route53_client):
    """Scan Route53 registered domains for security configurations."""
    findings = []
    try:
        domains = route53_client.list_domains().get('Domains', [])
        for domain in domains:
            domain_name = domain['DomainName']
            
            # Check if domain has auto-renew enabled
            if not domain.get('AutoRenew', False):
                findings.append({
                    "service": "Route53 Domains",
                    "resource": domain_name,
                    "status": "WARNING",
                    "issue": "Domain auto-renewal is disabled.",
                    "remediation": "Enable auto-renewal to prevent accidental domain expiration."
                })
            
            # Check domain expiration
            expiry_date = domain.get('Expiry')
            if expiry_date and (expiry_date - datetime.now(timezone.utc)).days < 30:
                findings.append({
                    "service": "Route53 Domains",
                    "resource": domain_name,
                    "status": "WARNING",
                    "issue": f"Domain expires within 30 days ({expiry_date.strftime('%Y-%m-%d')}).",
                    "remediation": "Renew domain or verify auto-renewal is configured."
                })
                
    except ClientError as e:
        if e.response.get('Error', {}).get('Code') != 'AccessDenied':
            findings.append({
                "service": "Route53 Domains",
                "resource": "Domain List",
                "status": "ERROR",
                "issue": f"Could not retrieve domain list: {e.response.get('Error', {}).get('Message', str(e))}",
                "remediation": "Ensure the user has route53domains:ListDomains permission."
            })
    except Exception as e:
        logging.error(f"Error scanning Route53 domains: {e}")
        findings.append({
            "service": "Route53 Domains",
            "resource": "Domain Scan",
            "status": "ERROR", 
            "issue": f"Unexpected error during domain scan: {str(e)}",
            "remediation": "Check service availability and permissions."
        })
    
    return findings


def scan_route53_health_checks(route53_client):
    """Scan Route53 health checks for proper configuration."""
    findings = []
    try:
        health_checks = route53_client.list_health_checks().get('HealthChecks', [])
        for health_check in health_checks:
            hc_id = health_check['Id']
            config = health_check['HealthCheckConfig']
            
            # Check if health check has insufficient failure threshold
            failure_threshold = config.get('FailureThreshold', 3)
            if failure_threshold > 5:
                findings.append({
                    "service": "Route53 Health Checks", 
                    "resource": hc_id,
                    "status": "WARNING",
                    "issue": f"High failure threshold ({failure_threshold}) may delay failure detection.",
                    "remediation": "Consider reducing failure threshold for faster failure detection."
                })
            
            # Check for missing SNS alarm notifications
            try:
                cloud_watch_config = health_check.get('CloudWatchAlarmRegion')
                if not cloud_watch_config:
                    findings.append({
                        "service": "Route53 Health Checks",
                        "resource": hc_id, 
                        "status": "WARNING",
                        "issue": "Health check has no CloudWatch alarms configured.",
                        "remediation": "Configure CloudWatch alarms for health check failure notifications."
                    })
            except KeyError:
                pass
                
    except ClientError as e:
        if e.response.get('Error', {}).get('Code') != 'AccessDenied':
            findings.append({
                "service": "Route53 Health Checks",
                "resource": "Health Check List",
                "status": "ERROR", 
                "issue": f"Could not retrieve health checks: {e.response.get('Error', {}).get('Message', str(e))}",
                "remediation": "Ensure the user has route53:ListHealthChecks permission."
            })
    except Exception as e:
        logging.error(f"Error scanning Route53 health checks: {e}")
        findings.append({
            "service": "Route53 Health Checks",
            "resource": "Health Check Scan",
            "status": "ERROR",
            "issue": f"Unexpected error during health check scan: {str(e)}",
            "remediation": "Check service availability and permissions."
        })
    
    return findings


def scan_organizations_accounts(organizations_client):
    """
    Scan AWS Organizations accounts for security configuration issues.
    """
    findings = []
    
    try:
        # Get the organization information
        org_response = organizations_client.describe_organization()
        org_id = org_response['Organization']['Id']
        
        # List all accounts in the organization
        paginator = organizations_client.get_paginator('list_accounts')
        for page in paginator.paginate():
            for account in page['Accounts']:
                account_id = account['Id']
                account_name = account['Name']
                account_status = account['Status']
                
                # Check for inactive accounts
                if account_status != 'ACTIVE':
                    findings.append({
                        "service": "Organizations Accounts",
                        "resource": f"{account_name} ({account_id})",
                        "status": "WARNING",
                        "issue": f"Account status is {account_status}",
                        "remediation": "Review inactive accounts and close if no longer needed."
                    })
                
                # Check for accounts without MFA enforcement (this requires additional checks)
                # This would typically require cross-account access which may not be available
                
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        if error_code == 'AccessDenied':
            findings.append({
                "service": "Organizations Accounts",
                "resource": "Account List",
                "status": "ERROR",
                "issue": "Access denied to Organizations service",
                "remediation": "Ensure the user has organizations:ListAccounts and organizations:DescribeOrganization permissions."
            })
        elif error_code == 'AWSOrganizationsNotInUseException':
            findings.append({
                "service": "Organizations Accounts",
                "resource": "Organization",
                "status": "INFO",
                "issue": "AWS Organizations is not enabled for this account",
                "remediation": "This scan only applies to AWS Organizations master accounts."
            })
        else:
            findings.append({
                "service": "Organizations Accounts",
                "resource": "Account List",
                "status": "ERROR",
                "issue": f"Could not retrieve organization accounts: {e.response.get('Error', {}).get('Message', str(e))}",
                "remediation": "Check Organizations service availability and permissions."
            })
    except Exception as e:
        logging.error(f"Error scanning Organizations accounts: {e}")
        findings.append({
            "service": "Organizations Accounts",
            "resource": "Account Scan",
            "status": "ERROR",
            "issue": f"Unexpected error during account scan: {str(e)}",
            "remediation": "Check service availability and permissions."
        })
    
    return findings


def scan_organizations_scps(organizations_client):
    """
    Scan AWS Organizations Service Control Policies (SCPs) for security configuration.
    """
    findings = []
    
    try:
        # Get the organization information first
        org_response = organizations_client.describe_organization()
        org_id = org_response['Organization']['Id']
        
        # List all policies of type SERVICE_CONTROL_POLICY
        paginator = organizations_client.get_paginator('list_policies')
        for page in paginator.paginate(Filter='SERVICE_CONTROL_POLICY'):
            for policy in page['Policies']:
                policy_id = policy['Id']
                policy_name = policy['Name']
                policy_description = policy.get('Description', 'No description')
                
                # Get detailed policy information
                try:
                    policy_details = organizations_client.describe_policy(PolicyId=policy_id)
                    policy_document = policy_details['Policy']['Content']
                    
                    # Check for overly permissive policies
                    if '"Effect": "Allow"' in policy_document and '"Resource": "*"' in policy_document:
                        findings.append({
                            "service": "Organizations SCPs",
                            "resource": f"{policy_name} ({policy_id})",
                            "status": "WARNING",
                            "issue": "SCP contains overly permissive Allow statements with wildcard resources",
                            "remediation": "Review and restrict SCP to follow principle of least privilege."
                        })
                    
                    # Check if policy denies critical security services
                    security_services = ['cloudtrail', 'config', 'guardduty', 'securityhub']
                    for service in security_services:
                        if f'"{service}:*"' in policy_document and '"Effect": "Deny"' in policy_document:
                            findings.append({
                                "service": "Organizations SCPs",
                                "resource": f"{policy_name} ({policy_id})",
                                "status": "CRITICAL",
                                "issue": f"SCP may be blocking access to {service.title()} security service",
                                "remediation": f"Review SCP to ensure {service.title()} access is not blocked for security operations."
                            })
                            
                except ClientError as policy_error:
                    findings.append({
                        "service": "Organizations SCPs",
                        "resource": f"{policy_name} ({policy_id})",
                        "status": "ERROR",
                        "issue": f"Could not retrieve policy details: {policy_error.response.get('Error', {}).get('Message', str(policy_error))}",
                        "remediation": "Ensure adequate permissions to read policy details."
                    })
        
        # Check if there are any SCPs at all
        if not findings:
            findings.append({
                "service": "Organizations SCPs",
                "resource": "Policy Configuration",
                "status": "INFO",
                "issue": "No Service Control Policies found or no policy issues detected",
                "remediation": "Consider implementing SCPs to enforce security controls across your organization."
            })
            
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        if error_code == 'AccessDenied':
            findings.append({
                "service": "Organizations SCPs",
                "resource": "Policy List",
                "status": "ERROR",
                "issue": "Access denied to Organizations service",
                "remediation": "Ensure the user has organizations:ListPolicies and organizations:DescribePolicy permissions."
            })
        elif error_code == 'AWSOrganizationsNotInUseException':
            findings.append({
                "service": "Organizations SCPs",
                "resource": "Organization",
                "status": "INFO",
                "issue": "AWS Organizations is not enabled for this account",
                "remediation": "This scan only applies to AWS Organizations master accounts."
            })
        else:
            findings.append({
                "service": "Organizations SCPs",
                "resource": "Policy List", 
                "status": "ERROR",
                "issue": f"Could not retrieve organization policies: {e.response.get('Error', {}).get('Message', str(e))}",
                "remediation": "Check Organizations service availability and permissions."
            })
    except Exception as e:
        logging.error(f"Error scanning Organizations SCPs: {e}")
        findings.append({
            "service": "Organizations SCPs",
            "resource": "Policy Scan",
            "status": "ERROR",
            "issue": f"Unexpected error during SCP scan: {str(e)}",
            "remediation": "Check service availability and permissions."
        })
    
    return findings


def scan_shield_advanced(shield_client):
    """
    Scan AWS Shield Advanced protection status.
    """
    findings = []
    
    try:
        # Check if Shield Advanced is enabled
        response = shield_client.describe_subscription()
        subscription = response.get('Subscription')
        
        if not subscription:
            findings.append({
                "service": "AWS Shield Advanced",
                "resource": "Subscription",
                "status": "WARNING",
                "issue": "AWS Shield Advanced subscription not found",
                "remediation": "Consider enabling AWS Shield Advanced for enhanced DDoS protection."
            })
        else:
            # Check subscription status
            if subscription.get('SubscriptionLimits', {}).get('ProtectedResourceTypeLimits'):
                findings.append({
                    "service": "AWS Shield Advanced",
                    "resource": "Subscription",
                    "status": "PASS",
                    "issue": "AWS Shield Advanced is properly configured",
                    "remediation": "Continue monitoring DDoS protection coverage."
                })
                
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        if error_code == 'ResourceNotFoundException':
            findings.append({
                "service": "AWS Shield Advanced",
                "resource": "Subscription",
                "status": "INFO",
                "issue": "AWS Shield Advanced is not subscribed",
                "remediation": "Shield Advanced provides enhanced DDoS protection. Consider subscription based on your needs."
            })
        else:
            findings.append({
                "service": "AWS Shield Advanced",
                "resource": "Subscription",
                "status": "ERROR",
                "issue": f"Could not check Shield Advanced status: {e.response.get('Error', {}).get('Message', str(e))}",
                "remediation": "Ensure adequate permissions to access Shield service."
            })
    except Exception as e:
        logging.error(f"Error scanning Shield Advanced: {e}")
        findings.append({
            "service": "AWS Shield Advanced",
            "resource": "Subscription Scan",
            "status": "ERROR",
            "issue": f"Unexpected error during Shield scan: {str(e)}",
            "remediation": "Check service availability and permissions."
        })
    
    return findings


def scan_cloudfront_distributions(cloudfront_client):
    """
    Scan CloudFront distributions for security configuration.
    """
    findings = []
    
    try:
        # List all CloudFront distributions
        paginator = cloudfront_client.get_paginator('list_distributions')
        for page in paginator.paginate():
            for distribution in page.get('DistributionList', {}).get('Items', []):
                dist_id = distribution['Id']
                dist_domain = distribution['DomainName']
                
                # Check if distribution has logging enabled
                if not distribution.get('Logging', {}).get('Enabled', False):
                    findings.append({
                        "service": "CloudFront Distributions",
                        "resource": f"{dist_domain} ({dist_id})",
                        "status": "WARNING",
                        "issue": "CloudFront distribution does not have access logging enabled",
                        "remediation": "Enable access logging to monitor and analyze traffic patterns."
                    })
                
                # Check ViewerProtocolPolicy for HTTPS
                for origin in distribution.get('Origins', {}).get('Items', []):
                    if origin.get('CustomOriginConfig', {}).get('OriginProtocolPolicy') == 'http-only':
                        findings.append({
                            "service": "CloudFront Distributions",
                            "resource": f"{dist_domain} ({dist_id})",
                            "status": "CRITICAL",
                            "issue": "Origin configured with HTTP-only protocol policy",
                            "remediation": "Configure origin to use HTTPS or redirect HTTP to HTTPS."
                        })
                
    except ClientError as e:
        findings.append({
            "service": "CloudFront Distributions",
            "resource": "Distribution List",
            "status": "ERROR",
            "issue": f"Could not retrieve distributions: {e.response.get('Error', {}).get('Message', str(e))}",
            "remediation": "Ensure the user has cloudfront:ListDistributions permission."
        })
    except Exception as e:
        logging.error(f"Error scanning CloudFront distributions: {e}")
        findings.append({
            "service": "CloudFront Distributions",
            "resource": "Distribution Scan",
            "status": "ERROR",
            "issue": f"Unexpected error during CloudFront scan: {str(e)}",
            "remediation": "Check service availability and permissions."
        })
    
    return findings


def scan_waf_classic(waf_client):
    """
    Scan WAF Classic rules and web ACLs.
    """
    findings = []
    
    try:
        # List WAF Classic Web ACLs
        response = waf_client.list_web_acls()
        web_acls = response.get('WebACLs', [])
        
        if not web_acls:
            findings.append({
                "service": "WAF Classic",
                "resource": "Web ACLs",
                "status": "WARNING",
                "issue": "No WAF Classic Web ACLs configured",
                "remediation": "Consider implementing WAF rules to protect against common web exploits."
            })
        else:
            for acl in web_acls:
                acl_id = acl['WebACLId']
                acl_name = acl['Name']
                
                # Get detailed ACL information
                acl_details = waf_client.get_web_acl(WebACLId=acl_id)
                rules = acl_details.get('WebACL', {}).get('Rules', [])
                
                if not rules:
                    findings.append({
                        "service": "WAF Classic",
                        "resource": f"{acl_name} ({acl_id})",
                        "status": "WARNING",
                        "issue": "WAF Web ACL has no rules configured",
                        "remediation": "Add rules to the Web ACL to provide meaningful protection."
                    })
                
    except ClientError as e:
        findings.append({
            "service": "WAF Classic",
            "resource": "WAF Configuration",
            "status": "ERROR",
            "issue": f"Could not retrieve WAF configuration: {e.response.get('Error', {}).get('Message', str(e))}",
            "remediation": "Ensure the user has waf:ListWebACLs and waf:GetWebACL permissions."
        })
    except Exception as e:
        logging.error(f"Error scanning WAF Classic: {e}")
        findings.append({
            "service": "WAF Classic",
            "resource": "WAF Scan",
            "status": "ERROR",
            "issue": f"Unexpected error during WAF scan: {str(e)}",
            "remediation": "Check service availability and permissions."
        })
    
    return findings


def scan_trusted_advisor(support_client):
    """
    Scan Trusted Advisor checks for recommendations.
    """
    findings = []
    
    try:
        # List available Trusted Advisor checks
        response = support_client.describe_trusted_advisor_checks(language='en')
        checks = response.get('checks', [])
        
        # Get results for security-related checks
        security_checks = [check for check in checks if 'security' in check['name'].lower() or 'Security' in check['category']]
        
        if not security_checks:
            findings.append({
                "service": "Trusted Advisor",
                "resource": "Security Checks",
                "status": "INFO",
                "issue": "No security-related Trusted Advisor checks available",
                "remediation": "Ensure you have appropriate support plan for Trusted Advisor access."
            })
        else:
            for check in security_checks[:5]:  # Limit to first 5 to avoid API throttling
                try:
                    check_result = support_client.describe_trusted_advisor_check_result(
                        checkId=check['id'], language='en'
                    )
                    result = check_result.get('result', {})
                    status = result.get('status', 'unknown')
                    
                    if status in ['warning', 'error']:
                        findings.append({
                            "service": "Trusted Advisor",
                            "resource": check['name'],
                            "status": "WARNING" if status == 'warning' else "CRITICAL",
                            "issue": f"Trusted Advisor flagged: {check['name']}",
                            "remediation": f"Review Trusted Advisor recommendations for: {check['name']}"
                        })
                except Exception as check_error:
                    continue
                
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        if error_code == 'SubscriptionRequiredException':
            findings.append({
                "service": "Trusted Advisor",
                "resource": "Service Access",
                "status": "INFO",
                "issue": "Trusted Advisor requires Business or Enterprise support plan",
                "remediation": "Upgrade support plan to access Trusted Advisor recommendations."
            })
        else:
            findings.append({
                "service": "Trusted Advisor",
                "resource": "Service Access",
                "status": "ERROR",
                "issue": f"Could not access Trusted Advisor: {e.response.get('Error', {}).get('Message', str(e))}",
                "remediation": "Ensure adequate permissions and support plan for Trusted Advisor access."
            })
    except Exception as e:
        logging.error(f"Error scanning Trusted Advisor: {e}")
        findings.append({
            "service": "Trusted Advisor",
            "resource": "Advisor Scan",
            "status": "ERROR",
            "issue": f"Unexpected error during Trusted Advisor scan: {str(e)}",
            "remediation": "Check service availability and permissions."
        })
    
    return findings


def scan_cost_explorer(ce_client):
    """
    Scan Cost Explorer for cost optimization recommendations.
    """
    findings = []
    
    try:
        # Get cost and usage for the last 7 days
        end_date = datetime.now().strftime('%Y-%m-%d')
        start_date = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
        
        response = ce_client.get_cost_and_usage(
            TimePeriod={'Start': start_date, 'End': end_date},
            Granularity='DAILY',
            Metrics=['BlendedCost'],
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
        )
        
        results = response.get('ResultsByTime', [])
        if results:
            # Analyze top spending services
            total_cost = 0
            for result in results:
                groups = result.get('Groups', [])
                for group in groups:
                    cost = float(group.get('Metrics', {}).get('BlendedCost', {}).get('Amount', '0'))
                    total_cost += cost
            
            if total_cost > 100:  # Threshold for recommendation
                findings.append({
                    "service": "Cost Explorer",
                    "resource": "Cost Analysis",
                    "status": "INFO",
                    "issue": f"Weekly cost: ${total_cost:.2f}",
                    "remediation": "Review Cost Explorer for optimization opportunities and consider implementing cost controls."
                })
        
        # Get rightsizing recommendations
        try:
            rightsizing = ce_client.get_rightsizing_recommendation(
                Service='AmazonEC2'
            )
            recommendations = rightsizing.get('RightsizingRecommendations', [])
            if recommendations:
                findings.append({
                    "service": "Cost Explorer",
                    "resource": "Rightsizing Recommendations",
                    "status": "INFO",
                    "issue": f"Found {len(recommendations)} EC2 rightsizing recommendations",
                    "remediation": "Review and implement rightsizing recommendations to optimize costs."
                })
        except Exception:
            pass  # Rightsizing API may not be available in all regions
        
    except ClientError as e:
        findings.append({
            "service": "Cost Explorer",
            "resource": "Cost Analysis",
            "status": "ERROR",
            "issue": f"Could not retrieve cost data: {e.response.get('Error', {}).get('Message', str(e))}",
            "remediation": "Ensure the user has ce:GetCostAndUsage permission."
        })
    except Exception as e:
        logging.error(f"Error scanning Cost Explorer: {e}")
        findings.append({
            "service": "Cost Explorer",
            "resource": "Cost Scan",
            "status": "ERROR",
            "issue": f"Unexpected error during Cost Explorer scan: {str(e)}",
            "remediation": "Check service availability and permissions."
        })
    
    return findings


def scan_budgets(budgets_client):
    """
    Scan AWS Budgets configuration.
    """
    findings = []
    
    try:
        # Get account ID dynamically
        import boto3
        sts = boto3.client('sts', region_name='us-east-1')
        account_id = sts.get_caller_identity()['Account']
        
        # List all budgets
        response = budgets_client.describe_budgets(AccountId=account_id)
        budgets = response.get('Budgets', [])
        
        if not budgets:
            findings.append({
                "service": "AWS Budgets",
                "resource": "Budget Configuration",
                "status": "WARNING",
                "issue": "No budgets configured",
                "remediation": "Create budgets to monitor and control AWS spending."
            })
        else:
            for budget in budgets:
                budget_name = budget['BudgetName']
                budget_limit = budget.get('BudgetLimit', {})
                
                # Check if budget has notifications
                try:
                    notifications = budgets_client.describe_notifications_for_budget(
                        AccountId=account_id,
                        BudgetName=budget_name
                    )
                    if not notifications.get('Notifications'):
                        findings.append({
                            "service": "AWS Budgets",
                            "resource": f"Budget: {budget_name}",
                            "status": "WARNING",
                            "issue": "Budget has no notifications configured",
                            "remediation": "Add notifications to be alerted when budget thresholds are exceeded."
                        })
                except Exception:
                    pass
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        if error_code in ['AccessDenied', 'UnauthorizedOperation']:
            findings.append({
                "service": "AWS Budgets",
                "resource": "Budget Access",
                "status": "ERROR",
                "issue": "Access denied to Budgets service",
                "remediation": "Ensure the user has budgets:DescribeBudgets permission."
            })
        else:
            findings.append({
                "service": "AWS Budgets",
                "resource": "Budget Configuration",
                "status": "ERROR",
                "issue": f"Could not retrieve budget information: {e.response.get('Error', {}).get('Message', str(e))}",
                "remediation": "Check Budgets service availability and permissions."
            })
    except Exception as e:
        logging.error(f"Error scanning AWS Budgets: {e}")
        findings.append({
            "service": "AWS Budgets",
            "resource": "Budget Scan",
            "status": "ERROR",
            "issue": f"Unexpected error during Budgets scan: {str(e)}",
            "remediation": "Check service availability and permissions."
        })
    
    return findings


# Additional comprehensive AWS service scanners for 200+ resources

def scan_efs_encryption(efs_client, region):
    """Scan EFS file systems for encryption configuration."""
    findings = []
    try:
        response = efs_client.describe_file_systems()
        
        for efs in response.get('FileSystems', []):
            fs_id = efs['FileSystemId']
            if not efs.get('Encrypted', False):
                findings.append({
                    "service": "Amazon EFS",
                    "resource": f"File System: {fs_id}",
                    "status": "CRITICAL",
                    "issue": "EFS file system is not encrypted at rest",
                    "remediation": "Enable encryption at rest for EFS file systems to protect sensitive data."
                })
    except ClientError as e:
        if e.response.get('Error', {}).get('Code') not in ['AccessDenied', 'UnauthorizedOperation']:
            logging.error(f"Error scanning EFS encryption in {region}: {e}")
    return findings

def scan_elasticache_clusters(elasticache_client, region):
    """Scan ElastiCache clusters for security configurations."""
    findings = []
    try:
        redis_response = elasticache_client.describe_replication_groups()
        for group in redis_response.get('ReplicationGroups', []):
            group_id = group['ReplicationGroupId']
            if not group.get('EncryptionAtRest', {}).get('Enabled', False):
                findings.append({
                    "service": "Amazon ElastiCache",
                    "resource": f"Redis Group: {group_id}",
                    "status": "HIGH",
                    "issue": "ElastiCache Redis cluster lacks encryption at rest",
                    "remediation": "Enable encryption at rest for ElastiCache Redis clusters."
                })
        
        memcached_response = elasticache_client.describe_cache_clusters()
        for cluster in memcached_response.get('CacheClusters', []):
            if cluster.get('Engine') == 'memcached':
                cluster_id = cluster['CacheClusterId']
                findings.append({
                    "service": "Amazon ElastiCache",
                    "resource": f"Memcached Cluster: {cluster_id}",
                    "status": "MEDIUM",
                    "issue": "Memcached cluster detected - review security configuration",
                    "remediation": "Review Memcached security groups and access patterns."
                })
                
    except ClientError as e:
        if e.response.get('Error', {}).get('Code') not in ['AccessDenied', 'UnauthorizedOperation']:
            logging.error(f"Error scanning ElastiCache in {region}: {e}")
    return findings

def scan_redshift_clusters(redshift_client, region):
    """Scan Redshift clusters for security configurations."""
    findings = []
    try:
        response = redshift_client.describe_clusters()
        
        for cluster in response.get('Clusters', []):
            cluster_id = cluster['ClusterIdentifier']
            
            if not cluster.get('Encrypted', False):
                findings.append({
                    "service": "Amazon Redshift",
                    "resource": f"Cluster: {cluster_id}",
                    "status": "CRITICAL",
                    "issue": "Redshift cluster is not encrypted",
                    "remediation": "Enable encryption for Redshift cluster to protect sensitive data."
                })
            
            if cluster.get('PubliclyAccessible', False):
                findings.append({
                    "service": "Amazon Redshift",
                    "resource": f"Cluster: {cluster_id}",
                    "status": "HIGH",
                    "issue": "Redshift cluster is publicly accessible",
                    "remediation": "Disable public accessibility for Redshift clusters unless required."
                })
                
    except ClientError as e:
        if e.response.get('Error', {}).get('Code') not in ['AccessDenied', 'UnauthorizedOperation']:
            logging.error(f"Error scanning Redshift in {region}: {e}")
    return findings

def scan_kinesis_streams(kinesis_client, region):
    """Scan Kinesis data streams for security configurations."""
    findings = []
    try:
        response = kinesis_client.list_streams()
        
        for stream_name in response.get('StreamNames', []):
            stream_info = kinesis_client.describe_stream(StreamName=stream_name)
            stream_details = stream_info['StreamDescription']
            
            if not stream_details.get('EncryptionType') or stream_details.get('EncryptionType') == 'NONE':
                findings.append({
                    "service": "Amazon Kinesis",
                    "resource": f"Stream: {stream_name}",
                    "status": "HIGH",
                    "issue": "Kinesis stream is not encrypted",
                    "remediation": "Enable server-side encryption for Kinesis data streams."
                })
                
    except ClientError as e:
        if e.response.get('Error', {}).get('Code') not in ['AccessDenied', 'UnauthorizedOperation']:
            logging.error(f"Error scanning Kinesis in {region}: {e}")
    return findings

def scan_sns_topics(sns_client, region):
    """Scan SNS topics for security configurations."""
    findings = []
    try:
        response = sns_client.list_topics()
        
        for topic in response.get('Topics', []):
            topic_arn = topic['TopicArn']
            attrs = sns_client.get_topic_attributes(TopicArn=topic_arn)
            attributes = attrs.get('Attributes', {})
            
            if not attributes.get('KmsMasterKeyId'):
                findings.append({
                    "service": "Amazon SNS",
                    "resource": f"Topic: {topic_arn.split(':')[-1]}",
                    "status": "MEDIUM",
                    "issue": "SNS topic is not encrypted with KMS",
                    "remediation": "Enable KMS encryption for SNS topics containing sensitive data."
                })
                
    except ClientError as e:
        if e.response.get('Error', {}).get('Code') not in ['AccessDenied', 'UnauthorizedOperation']:
            logging.error(f"Error scanning SNS in {region}: {e}")
    return findings

def scan_sqs_queues(sqs_client, region):
    """Scan SQS queues for security configurations."""
    findings = []
    try:
        response = sqs_client.list_queues()
        
        for queue_url in response.get('QueueUrls', []):
            queue_name = queue_url.split('/')[-1]
            attrs = sqs_client.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=['KmsMasterKeyId', 'RedrivePolicy']
            )
            attributes = attrs.get('Attributes', {})
            
            if not attributes.get('KmsMasterKeyId'):
                findings.append({
                    "service": "Amazon SQS",
                    "resource": f"Queue: {queue_name}",
                    "status": "MEDIUM",
                    "issue": "SQS queue is not encrypted with KMS",
                    "remediation": "Enable KMS encryption for SQS queues containing sensitive data."
                })
                
    except ClientError as e:
        if e.response.get('Error', {}).get('Code') not in ['AccessDenied', 'UnauthorizedOperation']:
            logging.error(f"Error scanning SQS in {region}: {e}")
    return findings

def scan_dynamodb_tables(dynamodb_client, region):
    """Scan DynamoDB tables for security configurations."""
    findings = []
    try:
        response = dynamodb_client.list_tables()
        
        for table_name in response.get('TableNames', []):
            table_info = dynamodb_client.describe_table(TableName=table_name)
            table = table_info['Table']
            
            sse_description = table.get('SSEDescription', {})
            if not sse_description.get('Status') == 'ENABLED':
                findings.append({
                    "service": "Amazon DynamoDB",
                    "resource": f"Table: {table_name}",
                    "status": "HIGH",
                    "issue": "DynamoDB table is not encrypted at rest",
                    "remediation": "Enable encryption at rest for DynamoDB tables."
                })
                
    except ClientError as e:
        if e.response.get('Error', {}).get('Code') not in ['AccessDenied', 'UnauthorizedOperation']:
            logging.error(f"Error scanning DynamoDB in {region}: {e}")
    return findings