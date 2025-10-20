import os  
import boto3
from botocore.exceptions import ClientError

# ===== AWS / S3 Configuration =====
AWS_PROFILE = "CAB432-STUDENT"
AWS_REGION = "ap-southeast-2"
AWS_BUCKET = "justinsinghatwalbucket"

def get_s3_client():
    """
    Initialize and return a boto3 S3 client using the specified AWS CLI profile.
    Performs a sanity check by listing buckets to verify authentication.
    """
    try:
        session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)
        client = session.client("s3")
        client.list_buckets()  # sanity check
        return client
    except Exception as e:
        raise Exception(
            f"S3 client initialization failed. Run `aws sso login --profile {AWS_PROFILE}` and ensure ~/.aws is mounted."
        )

def upload_file_to_s3(file_bytes, key, content_type=None, expiration=3600):
    """
    Upload a file to S3 or generate a presigned URL for uploading if `file_bytes` is None.
    Returns the uploaded file URL or presigned URL.
    """
    s3 = get_s3_client()
    if file_bytes is None:
        params = {"Bucket": AWS_BUCKET, "Key": key}
        if content_type:
            params["ContentType"] = content_type
        presigned_url = s3.generate_presigned_url(
            ClientMethod="put_object",
            Params=params,
            ExpiresIn=expiration
        )
        return presigned_url
    else:
        kwargs = {"Bucket": AWS_BUCKET, "Key": key, "Body": file_bytes}
        if content_type:
            kwargs["ContentType"] = content_type
        s3.put_object(**kwargs)
        return f"https://{AWS_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{key}"

def get_presigned_download_url(key, expiration=3600):
    """
    Generate a presigned GET URL for securely downloading a file from S3.
    """
    s3 = get_s3_client()
    try:
        url = s3.generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": AWS_BUCKET, "Key": key},
            ExpiresIn=expiration
        )
        return url
    except ClientError as e:
        raise
