# s3_scanner.py
import boto3

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

def run_all_scans():
    """
    The big boss function. Tells all the other scanners to get to work.
    """
    all_results = []
    all_results.extend(scan_s3_buckets())
    all_results.extend(scan_rds_encryption())
    all_results.extend(scan_ec2_public_access())
    return all_results

# If we run this file directly, just print the results to the screen. Good for testing.
if __name__ == '__main__':
    scan_results = run_all_scans()
    for result in scan_results:
        print(result)
        # get all buckets in the account
        buckets = s3.list_buckets().get('Buckets', [])

        for bucket in buckets:
            bucket_name = bucket['Name']
            is_public = False # assume it's private

            try:
                # check public access block settings first
                pab = s3.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
                if not (pab['BlockPublicAcls'] and pab['IgnorePublicAcls'] and
                        pab['BlockPublicPolicy'] and pab['RestrictPublicBuckets']):
                    is_public = True
            except:
                # if no pab, check the policy
                try:
                    policy = s3.get_bucket_policy(Bucket=bucket_name)
                    # simple check for public policy
                    if '"Principal":"*"' in policy['Policy'] or '"Principal":{"AWS":"*"}' in policy['Policy']:
                        is_public = True
                except:
                    # no policy found, so it's not public
                    pass

            if is_public:
                results.append({"bucket": bucket_name, "status": "CRITICAL", "issue": "Might be public."})
            else:
                results.append({"bucket": bucket_name, "status": "OK", "issue": "Looks private."})

    except Exception as e:
        results.append({"error": "Scan failed", "details": str(e), "fix": "Check AWS creds or permissions."})

    return results

# to test this file directly
if __name__ == '__main__':
    scan_results = scan_s3_buckets()
    # just print the results
    for r in scan_results:
        print(r)

