import os
import logging
from datetime import datetime
import boto3

AWS_REGION = os.environ.get("AWS_REGION", "ap-southeast-2")
DDB_TABLE_NAME = "n11605618table"  # your existing table
dynamodb = boto3.client("dynamodb", region_name=AWS_REGION)

def save_progress(user_id, progress):
    """
    Save progress for a user to DynamoDB.
    """
    dynamodb.put_item(
        TableName=DDB_TABLE_NAME,
        Item={
            'qut-username': {'S': str(user_id)},
            'progress': {'N': str(progress)},
            'last_update': {'S': datetime.utcnow().isoformat()}
        }
    )
    logging.debug(f"Progress saved: user={user_id}, progress={progress}")

def load_progress(user_id):
    """
    Load progress for a user from DynamoDB.
    Returns 0 if not found.
    """
    response = dynamodb.get_item(
        TableName=DDB_TABLE_NAME,
        Key={
            'qut-username': {'S': str(user_id)}
        }
    )
    if 'Item' in response and 'progress' in response['Item']:
        progress = int(response['Item']['progress']['N'])
        logging.debug(f"Progress loaded: user={user_id}, progress={progress}")
        return progress
    return 0
