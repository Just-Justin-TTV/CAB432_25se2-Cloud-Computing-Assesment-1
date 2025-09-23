import boto3
from uuid import uuid4
import os

# === AWS config ===
AWS_PROFILE = "CAB432-STUDENT"
AWS_REGION = "ap-southeast-2"
AWS_BUCKET = "justinsinghatwalbucket"

def get_s3_client():
    session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)
    return session.client("s3")

def upload_file(file_path):
    s3 = get_s3_client()
    file_name = os.path.basename(file_path)
    key = f"test_uploads/{uuid4()}_{file_name}"
    
    try:
        with open(file_path, "rb") as f:
            s3.put_object(Bucket=AWS_BUCKET, Key=key, Body=f)
        url = f"https://{AWS_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{key}"
        print(f"Upload successful! File URL: {url}")
    except Exception as e:
        print(f"Upload failed: {e}")

if __name__ == "__main__":
    file_path = input("Enter the path to the file you want to upload: ").strip()
    if not os.path.isfile(file_path):
        print("File not found!")
    else:
        upload_file(file_path)
