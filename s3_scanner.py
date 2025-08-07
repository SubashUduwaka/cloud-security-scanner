# s3 boto client
import boto3

s3 = boto3.client('s3')

try:
    # get all buckets
    response = s3.list_buckets()
    buckets = response.get('Buckets', [])
    print(f"buckets found: {len(buckets)}")

    # check each bucket
    for bucket in buckets:
        bucket_name = bucket['Name']
        is_public = False # assume private

        try:
            # check public access block
            pab = s3.get_public_access_block(Bucket=bucket_name)
            config = pab.get('PublicAccessBlockConfiguration', {})
            
            # if any of these are off, it could be public
            if not (config.get('BlockPublicAcls', True) and
                    config.get('IgnorePublicAcls', True) and
                    config.get('BlockPublicPolicy', True) and
                    config.get('RestrictPublicBuckets', True)):
                is_public = True

        except Exception:
            # no access block, so check policy status instead
            try:
                status = s3.get_bucket_policy_status(Bucket=bucket_name)
                if status.get('PolicyStatus', {}).get('IsPublic', False):
                    is_public = True
            except Exception:
                # no policy, so probably not public
                pass

        # print results
        if is_public:
            print(f"  [!] {bucket_name} -> MIGHT BE PUBLIC")
        else:
            print(f"  [ok] {bucket_name} -> private")

except Exception as e:
    print(f"error: {e}")
    print("check aws creds/permissions")