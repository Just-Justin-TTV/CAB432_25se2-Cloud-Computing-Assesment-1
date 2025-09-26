# check_dynamodb.py - List all uploaded resumes nicely
import boto3
import json

# ---------- CONFIG ----------
qut_username = "n12008192@qut.edu.au"
table_name = "n12008192-activity"
region = "ap-southeast-2"
# ---------------------------

# Create DynamoDB client
dynamodb = boto3.client("dynamodb", region_name=region)

def list_uploaded_resumes():
    try:
        # Query all items for this username
        response = dynamodb.query(
            TableName=table_name,
            KeyConditionExpression="#pk = :username",
            ExpressionAttributeNames={"#pk": "qut-username"},
            ExpressionAttributeValues={":username": {"S": qut_username}},
        )

        items = response.get("Items", [])
        if not items:
            print(f"No resumes found for {qut_username}")
            return

        print(f"Found {len(items)} resume(s) for {qut_username}:")
        for i, item in enumerate(items, 1):
            # Parse the metadata JSON
            metadata = json.loads(item["metadata"]["S"])
            print(f"\nResume {i}:")
            print(f"  Resume ID : {metadata.get('resume_id')}")
            print(f"  S3 URL    : {metadata.get('s3')}")
            print(f"  Uploaded at : {item.get('timestamp', {}).get('S')}")  # optional timestamp
            print(f"  Action      : {item.get('action', {}).get('S')}")

    except Exception as e:
        print(f"Error accessing DynamoDB: {e}")

if __name__ == "__main__":
    list_uploaded_resumes()
