# dynamo_utils.py

import boto3
import time
from decimal import Decimal
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb", region_name="ap-southeast-2")
table = dynamodb.Table("n11605618dynamo")

def save_progress(user_id, task_name, progress):
    """
    Save progress for a task. Use progress=None to clear.
    """
    try:
        if progress is None:
            table.delete_item(Key={"user_id": user_id, "task_name": task_name})
            return
        progress = max(0, min(100, int(progress)))
        table.put_item(Item={"user_id": user_id, "task_name": task_name, "progress": Decimal(progress)})
    except ClientError as e:
        print(f"[ERROR] Failed to save progress: {e}")

def load_progress(user_id, task_name):
    """
    Load current task progress from DynamoDB.
    """
    try:
        resp = table.get_item(Key={"user_id": user_id, "task_name": task_name})
        return float(resp.get("Item", {}).get("progress", 0))
    except ClientError as e:
        print(f"[ERROR] Failed to load progress: {e}")
        return 0

def update_progress_smoothly(user_id, task_name, start, end, steps=5, delay=0.2):
    """
    Gradually increase progress from start to end.
    """
    for i in range(steps):
        val = start + (end - start) * (i + 1) / steps
        save_progress(user_id, task_name, val)
        time.sleep(delay)

def process_resume_chunks(resume_text, chunk_size=500):
    """
    Break resume text into smaller chunks for AI processing.
    """
    words = resume_text.split()
    for i in range(0, len(words), chunk_size):
        yield " ".join(words[i:i + chunk_size])



def delete_progress(qut_username: str, task_name: str):
    """Optional: delete a progress entry."""
    try:
        table.delete_item(
            Key={
                'qut-username': qut_username,
                'task_name': task_name
            }
        )
        print(f"Deleted progress: {qut_username} - {task_name}")
    except ClientError as e:
        print(f"Error deleting progress: {e.response['Error']['Message']}")
