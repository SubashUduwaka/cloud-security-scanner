# s3_scanner.py
import boto3
import datetime

def scan_s3_buckets():
    """
    Time to check if any S3 buckets are left wide open.
    """
    results = []
    s3 = boto3.client('s3')

    try:
        response = s3.list_buckets()
        buckets = response['Buckets']

        # Looping through all the buckets we found... hope there aren't too many.
        for bucket in buckets:
            bucket_name = bucket['Name']
            is_public = False
            
            # Public Access Block is the new hotness, let's check that first.
            try:
                public_access_block = s3.get_public_access_block(Bucket=bucket_name)
                if not (public_access_block['PublicAccessBlockConfiguration']['BlockPublicAcls'] and
                        public_access_block['PublicAccessBlockConfiguration']['IgnorePublicAcls'] and
                        public_access_block['PublicAccessBlockConfiguration']['BlockPublicPolicy'] and
                        public_access_block['PublicAccessBlockConfiguration']['RestrictPublicBuckets']):
                    is_public = True
            except Exception as e:
                # Ugh, fallback to checking the old school bucket policy if PAB fails.
                try:
                    policy = s3.get_bucket_policy(Bucket=bucket_name)
                    if '"Principal":"*"' in policy['Policy']:
                        is_public = True
                except:
                    # No policy? Probably private. Let's move on.
                    pass

            if is_public:
                results.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "status": "CRITICAL",
                    "issue": "Bucket may be publicly accessible."
                })
            else:
                results.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "status": "OK",
                    "issue": "Bucket seems to be private."
                })

    except Exception as e:
        # Well, something went wrong. Probably bad credentials.
        results.append({
            "service": "S3",
            "error": "An error occurred during S3 scanning.",
            "details": str(e),
            "remediation": "Please check your AWS credentials and IAM permissions."
        })
        
    return results

def scan_rds_encryption():
    """
    Checking if our databases are naked... I mean, unencrypted.
    """
    results = []
    rds = boto3.client('rds')
    
    try:
        response = rds.describe_db_instances()
        db_instances = response['DBInstances']

        if not db_instances:
            results.append({
                "service": "RDS",
                "resource": "N/A",
                "status": "OK",
                "issue": "No RDS instances found."
            })
            return results

        for db in db_instances:
            db_identifier = db['DBInstanceIdentifier']
            is_encrypted = db.get('StorageEncrypted', False)

            if is_encrypted:
                results.append({
                    "service": "RDS",
                    "resource": db_identifier,
                    "status": "OK",
                    "issue": "Database is encrypted."
                })
            else:
                results.append({
                    "service": "RDS",
                    "resource": db_identifier,
                    "status": "CRITICAL",
                    "issue": "Database is not encrypted."
                })
    except Exception as e:
        results.append({
            "service": "RDS",
            "error": "An error occurred during RDS scanning.",
            "details": str(e),
            "remediation": "Please check your AWS credentials and IAM permissions."
        })
        
    return results

def scan_ec2_public_access():
    """
    Is the front door (security group) open to the whole internet (0.0.0.0/0)?
    """
    results = []
    ec2 = boto3.client('ec2')

    try:
        response = ec2.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                
                is_public = False
                public_ports = []
                
                # An instance can have multiple security groups, so we gotta check them all.
                for security_group in instance['SecurityGroups']:
                    sg_id = security_group['GroupId']
                    sg_response = ec2.describe_security_groups(GroupIds=[sg_id])
                    
                    for ip_permission in sg_response['SecurityGroups'][0]['IpPermissions']:
                        for ip_range in ip_permission.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                from_port = ip_permission.get('FromPort', 'all')
                                to_port = ip_permission.get('ToPort', 'all')
                                public_ports.append(f"{from_port}-{to_port}")
                                is_public = True
                
                if is_public:
                    results.append({
                        "service": "EC2",
                        "resource": instance_id,
                        "status": "CRITICAL",
                        "issue": f"Instance has a public security group rule on ports: {', '.join(public_ports)}."
                    })
                else:
                    results.append({
                        "service": "EC2",
                        "resource": instance_id,
                        "status": "OK",
                        "issue": "Instance's security groups are private."
                    })
    except Exception as e:
        results.append({
            "service": "EC2",
            "error": "An error occurred during EC2 scanning.",
            "details": str(e),
            "remediation": "Please check your AWS credentials and IAM permissions."
        })
        
    return results

def scan_iam_users():
    """
    Let's check if anyone has an ancient access key they should have rotated ages ago.
    """
    results = []
    iam = boto3.client('iam')
    
    try:
        # Paginator is a fancy way to handle lots of users without crashing.
        paginator = iam.get_paginator('list_users')
        for response in paginator.paginate():
            for user in response['Users']:
                username = user['UserName']

                key_response = iam.list_access_keys(UserName=username)
                for key in key_response['AccessKeyMetadata']:
                    last_used_response = iam.get_access_key_last_used(
                        AccessKeyId=key['AccessKeyId']
                    )
                    
                    last_used_date = last_used_response['AccessKeyLastUsed'].get('LastUsedDate')
                    
                    if last_used_date:
                        # Time for some date math...
                        days_since_rotation = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc) - last_used_date).days
                        if days_since_rotation > 90:
                            results.append({
                                "service": "IAM",
                                "resource": username,
                                "status": "CRITICAL",
                                "issue": f"Access key has not been rotated in over 90 days."
                            })
                        else:
                             results.append({
                                "service": "IAM",
                                "resource": username,
                                "status": "OK",
                                "issue": f"Access key was last used {days_since_rotation} days ago."
                            })
                    else:
                        # Never used? That's fine I guess.
                        results.append({
                                "service": "IAM",
                                "resource": username,
                                "status": "OK",
                                "issue": "Access key has never been used."
                        })
    except Exception as e:
        results.append({
            "service": "IAM",
            "error": "An error occurred during IAM scanning.",
            "details": str(e),
            "remediation": "Please check your AWS credentials and IAM permissions."
        })
    
    return results

def run_all_scans():
    """
    The big boss function. Tells all the other scanners to get to work.
    """
    all_results = []
    all_results.extend(scan_s3_buckets())
    all_results.extend(scan_rds_encryption())
    all_results.extend(scan_ec2_public_access())
    all_results.extend(scan_iam_users()) # The new guy.
    return all_results

# If we run this file directly, just print the results to the screen. Good for testing.
if __name__ == '__main__':
    scan_results = run_all_scans()
    for result in scan_results:
        print(result)
