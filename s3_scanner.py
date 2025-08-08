import boto3

# scans s3 buckets for public access
def scan_s3_buckets():
    results = []
    s3 = boto3.client('s3')

    try:
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

        # grab buckets
        response = s3.list_buckets()
        buckets = response.get('Buckets', [])

        for bucket in buckets:
            bucket_name = bucket['Name']
            is_public = False # default to private
            
            try:
                # check the public access block first
                pab = s3.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
                if not (pab['BlockPublicAcls'] and pab['IgnorePublicAcls'] and 
                        pab['BlockPublicPolicy'] and pab['RestrictPublicBuckets']):
                    is_public = True
            except:
                # if that fails, check the bucket policy
                try:
                    policy = s3.get_bucket_policy(Bucket=bucket_name)
                    # quick and dirty check for public policy
                    if '"Principal":"*"' in policy['Policy'] or '"Principal":{"AWS":"*"}' in policy['Policy']:
                        is_public = True
                except:
                    # no policy, so it's not public
                    pass

            # add to results list
            if is_public:
                results.append({ "bucket": bucket_name, "status": "PUBLIC" })
            else:
                results.append({ "bucket": bucket_name, "status": "private" })

    except Exception as e:
        # just capture the error and stop
        results.append({ "error": str(e), "remediation": "check creds/permissions" })
        
    return results

# for testing it directly
if __name__ == '__main__':
    scan_results = scan_s3_buckets()
    # just dump the results
    for r in scan_results:
        print(r)