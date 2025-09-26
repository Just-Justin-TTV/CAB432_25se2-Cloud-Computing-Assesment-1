# dynamodb_demo.py - Enhanced with better error handling
import boto3
from botocore.exceptions import ClientError
from uuid import uuid4
from datetime import datetime
import time
import json

# ---------- CONFIGURE THIS ----------
qut_username = "n12008192@qut.edu.au"   # <-- REPLACE with your QUT username (full email)
region = "ap-southeast-2"
table_name = "n12008192-activity"       # <-- REPLACE: use your qut id prefix (e.g. n1234567-activity)
sort_key = "event_id"
# ------------------------------------

# Create a low-level client
dynamodb = boto3.client("dynamodb", region_name=region)
event_id = f"evt-{uuid4()}" 

def table_exists():
    try:
        response = dynamodb.describe_table(TableName=table_name)
        print(f"Table '{table_name}' exists with status: {response['Table']['TableStatus']}")
        return response['Table']['TableStatus'] == 'ACTIVE'
    except dynamodb.exceptions.ResourceNotFoundException:
        print(f"Table '{table_name}' does not exist")
        return False
    except ClientError as e:
        print(f"Error checking table existence: {e.response['Error']['Code']} - {e.response['Error']['Message']}")
        return False

def create_table():
    if table_exists():
        print(f"Table '{table_name}' already exists and is active.")
        return True
    
    try:
        print(f"Creating table '{table_name}'...")
        resp = dynamodb.create_table(
            TableName=table_name,
            AttributeDefinitions=[
                {"AttributeName": "qut-username", "AttributeType": "S"},
                {"AttributeName": sort_key, "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "qut-username", "KeyType": "HASH"},  # partition key (required by CAB432)
                {"AttributeName": sort_key, "KeyType": "RANGE"},       # sort key
            ],
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        )
        print(f"Create Table response: HTTP {resp['ResponseMetadata']['HTTPStatusCode']}")
        
        print("Waiting for table to become ACTIVE...")
        waiter = dynamodb.get_waiter('table_exists')
        waiter.wait(TableName=table_name, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})
        
        # Verify table is active
        time.sleep(2)
        if table_exists():
            print(f"Table '{table_name}' is now ACTIVE!")
            return True
        else:
            print("Table creation completed but not active")
            return False
            
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = e.response['Error']['Message']
        print(f"Create table failed: {error_code} - {error_msg}")
        
        if error_code == 'ResourceInUseException':
            print("Table already exists, checking status...")
            return table_exists()
        return False

def put_item():
    print(f"\nAttempting to put item with partition key: '{qut_username}'")
    try:
        response = dynamodb.put_item(
            TableName=table_name,
            Item={
                "qut-username": {"S": qut_username},
                sort_key: {"S": "evt-0001"},
                "action": {"S": "resume_uploaded"},
                "timestamp": {"S": "2025-09-26T12:00:00Z"},
                "metadata": {"S": json.dumps({"resume_id":"42","s3":"s3://mybucket/resumes/42.docx"})},
            },
        )
        print(f"✓ PutItem successful! HTTP Status: {response['ResponseMetadata']['HTTPStatusCode']}")
        return True
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = e.response['Error']['Message']
        print(f"✗ PutItem failed: {error_code} - {error_msg}")
        
        # Specific error handling
        if error_code == 'AccessDeniedException':
            print("  → This is a permission issue. You may not have dynamodb:PutItem permission.")
        elif error_code == 'ResourceNotFoundException':
            print("  → Table doesn't exist or isn't accessible.")
        elif error_code == 'ValidationException':
            print("  → There's an issue with the item format or table schema.")
        
        print(f"  → Full error details: {e}")
        return False

def get_item():
    print(f"\nAttempting to get item with partition key: '{qut_username}'")
    try:
        response = dynamodb.get_item(
            TableName=table_name,
            Key={
                "qut-username": {"S": qut_username},
                sort_key: {"S": "evt-0001"},
            },
        )
        
        if 'Item' in response:
            print("✓ GetItem successful!")
            print("Item data:", response["Item"])
        else:
            print("GetItem successful, but no item found with that key")
        return True
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = e.response['Error']['Message']
        print(f"✗ GetItem failed: {error_code} - {error_msg}")
        return False

def query_items():
    print(f"\nQuerying items for partition key: '{qut_username}'")
    try:
        response = dynamodb.query(
            TableName=table_name,
            KeyConditionExpression="#pk = :username AND begins_with(#sk, :start)",
            ExpressionAttributeNames={"#pk": "qut-username", "#sk": sort_key},
            ExpressionAttributeValues={":username": {"S": qut_username}, ":start": {"S": "evt"}},
        )
        
        items = response.get("Items", [])
        print(f"✓ Query successful! Found {len(items)} items")
        
        if items:
            print("Items found:")
            for i, item in enumerate(items, 1):
                print(f"  {i}. {item}")
        return True
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = e.response['Error']['Message']
        print(f"✗ Query failed: {error_code} - {error_msg}")
        return False

def test_basic_access():
    """Test basic DynamoDB access"""
    print("Testing basic DynamoDB access...")
    try:
        tables = dynamodb.list_tables()
        print(f"✓ Can list tables. Found {len(tables['TableNames'])} tables")
        return True
    except ClientError as e:
        print(f"✗ Cannot list tables: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("DynamoDB Demo with Enhanced Error Handling")
    print("=" * 60)
    print(f"Username: {qut_username}")
    print(f"Table: {table_name}")
    print(f"Region: {region}")
    print("=" * 60)
    
    # Test basic access first
    if not test_basic_access():
        print("Basic access test failed. Check your AWS credentials.")
        exit(1)
    
    # Create table if needed
    if not create_table():
        print("Failed to create or verify table. Exiting.")
        exit(1)
    
    # Try operations in sequence
    print("\n" + "=" * 40)
    print("TESTING OPERATIONS")
    print("=" * 40)
    
    # Try put first
    put_success = put_item()
    
    # Try get (whether put succeeded or not)
    get_item()
    
    # Try query
    query_items()
    
    print("\n" + "=" * 40)
    print("SUMMARY")
    print("=" * 40)
    if put_success:
        print("✓ All operations completed successfully!")
    else:
        print("✗ Put operation failed. Check the error messages above.")
        print("This might be a permission issue that needs to be resolved with your instructors.")