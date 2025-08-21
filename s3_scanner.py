import boto3
import datetime

def scan_s3_buckets():
    results = []
    s3 = boto3.client('s3')
    try:
        response = s3.list_buckets()
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            is_public = False
            try:
                public_access_block = s3.get_public_access_block(Bucket=bucket_name)
                if not (public_access_block['PublicAccessBlockConfiguration']['BlockPublicAcls'] and
                        public_access_block['PublicAccessBlockConfiguration']['IgnorePublicAcls'] and
                        public_access_block['PublicAccessBlockConfiguration']['BlockPublicPolicy'] and
                        public_access_block['PublicAccessBlockConfiguration']['RestrictPublicBuckets']):
                    is_public = True
            except Exception:
                try:
                    policy = s3.get_bucket_policy(Bucket=bucket_name)
                    if '"Principal":"*"' in policy['Policy'] or '"Principal":{"AWS":"*"}' in policy['Policy']:
                        is_public = True
                except Exception:
                    pass
            results.append({
                "service": "S3",
                "resource": bucket_name,
                "status": "CRITICAL" if is_public else "OK",
                "issue": "Bucket may be publicly accessible." if is_public else "Bucket seems to be private."
            })
    except Exception as e:
        results.append({"service": "S3", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan S3 buckets: {str(e)}"})
    return results

def scan_rds_encryption():
    results = []
    rds = boto3.client('rds')
    try:
        response = rds.describe_db_instances()
        if not response['DBInstances']:
            return [{"service": "RDS", "resource": "N/A", "status": "OK", "issue": "No RDS instances found."}]
        for db in response['DBInstances']:
            is_encrypted = db.get('StorageEncrypted', False)
            results.append({
                "service": "RDS",
                "resource": db['DBInstanceIdentifier'],
                "status": "OK" if is_encrypted else "CRITICAL",
                "issue": "Database is encrypted." if is_encrypted else "Database is not encrypted."
            })
    except Exception as e:
        results.append({"service": "RDS", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan RDS instances: {str(e)}"})
    return results

def scan_ec2_public_access():
    results = []
    ec2 = boto3.client('ec2')
    try:
        response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        instances_found = False
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instances_found = True
                instance_id = instance['InstanceId']
                is_public = False
                for sg in instance.get('SecurityGroups', []):
                    sg_response = ec2.describe_security_groups(GroupIds=[sg['GroupId']])
                    for ip_permission in sg_response['SecurityGroups'][0]['IpPermissions']:
                        if any(ip_range.get('CidrIp') == '0.0.0.0/0' for ip_range in ip_permission.get('IpRanges', [])):
                            is_public = True
                            break
                    if is_public: break
                results.append({
                    "service": "EC2",
                    "resource": instance_id,
                    "status": "CRITICAL" if is_public else "OK",
                    "issue": "Instance has a public security group rule." if is_public else "Instance's security groups are private."
                })
        if not instances_found:
            return [{"service": "EC2", "resource": "N/A", "status": "OK", "issue": "No running EC2 instances found."}]
    except Exception as e:
        results.append({"service": "EC2", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan EC2 instances: {str(e)}"})
    return results

def scan_iam_users():
    results = []
    iam = boto3.client('iam')
    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                key_response = iam.list_access_keys(UserName=username)
                if not key_response['AccessKeyMetadata']:
                    results.append({"service": "IAM", "resource": username, "status": "OK", "issue": "User has no access keys."})
                    continue
                for key in key_response['AccessKeyMetadata']:
                    create_date = key['CreateDate']
                    age = (datetime.datetime.now(datetime.timezone.utc) - create_date).days
                    if age > 90:
                        results.append({"service": "IAM", "resource": username, "status": "CRITICAL", "issue": f"Access key is older than 90 days ({age} days old)."})
                    else:
                        results.append({"service": "IAM", "resource": username, "status": "OK", "issue": f"Access key is fresh ({age} days old)."})
    except Exception as e:
        results.append({"service": "IAM", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan IAM users: {str(e)}"})
    return results

def scan_cloudtrail_logs():
    results = []
    cloudtrail = boto3.client('cloudtrail')
    try:
        response = cloudtrail.describe_trails()
        is_enabled = any(trail.get('IsMultiRegionTrail', False) and trail.get('IsLogging', False) for trail in response['trailList'])
        results.append({
            "service": "CloudTrail",
            "resource": "All Regions",
            "status": "OK" if is_enabled else "CRITICAL",
            "issue": "Multi-region CloudTrail is enabled." if is_enabled else "Multi-region CloudTrail is not enabled."
        })
    except Exception as e:
        results.append({"service": "CloudTrail", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan CloudTrail: {str(e)}"})
    return results

def scan_vpc_flow_logs():
    results = []
    ec2 = boto3.client('ec2')
    try:
        vpcs = ec2.describe_vpcs()['Vpcs']
        if not vpcs:
            return [{"service": "VPC", "resource": "N/A", "status": "OK", "issue": "No VPCs found."}]
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            flow_logs = ec2.describe_flow_logs(Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}])['FlowLogs']
            results.append({
                "service": "VPC",
                "resource": vpc_id,
                "status": "OK" if flow_logs else "CRITICAL",
                "issue": "VPC Flow Logs are enabled." if flow_logs else "VPC Flow Logs are not enabled."
            })
    except Exception as e:
        results.append({"service": "VPC", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan VPCs: {str(e)}"})
    return results

def scan_lambda_permissions():
    results = []
    iam = boto3.client('iam')
    lambda_client = boto3.client('lambda')
    try:
        functions = lambda_client.list_functions()['Functions']
        if not functions:
            return [{"service": "Lambda", "resource": "N/A", "status": "OK", "issue": "No Lambda functions found."}]
        for func in functions:
            role_arn = func['Role']
            role_name = role_arn.split('/')[-1]
            attached_policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
            is_admin = any(policy['PolicyArn'] == 'arn:aws:iam::aws:policy/AdministratorAccess' for policy in attached_policies)
            results.append({
                "service": "Lambda",
                "resource": func['FunctionName'],
                "status": "CRITICAL" if is_admin else "OK",
                "issue": "Function has an overly permissive 'AdministratorAccess' role." if is_admin else "Function has a secure execution role."
            })
    except Exception as e:
        results.append({"service": "Lambda", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan Lambda functions: {str(e)}"})
    return results

def run_all_scans():
    all_results = []
    all_results.extend(scan_s3_buckets())
    all_results.extend(scan_rds_encryption())
    all_results.extend(scan_ec2_public_access())
    all_results.extend(scan_iam_users())
    all_results.extend(scan_cloudtrail_logs())
    all_results.extend(scan_vpc_flow_logs())
    all_results.extend(scan_lambda_permissions())
    return all_results