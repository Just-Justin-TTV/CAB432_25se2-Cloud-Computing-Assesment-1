import boto3 
from botocore.exceptions import ClientError
from datetime import datetime, timezone
from decimal import Decimal
import time

# Initialize DynamoDB
dynamodb = boto3.resource("dynamodb", region_name="ap-southeast-2")
table = dynamodb.Table("n11605618dynamo")


def display_progress(progress_value):
    """
    Convert a numeric progress value to an integer percentage.
    """
    try:
        return int(round(float(progress_value)))
    except (ValueError, TypeError):
        return 0


def save_progress(username: str, task_name: str, progress_value):
    """
    Save a user's task progress to DynamoDB.
    """
    if not username or progress_value is None:
        raise ValueError("Username and progress value must be provided")

    try:
        table.put_item(
            Item={
                "username": str(username),
                "task_name": str(task_name),
                "progress": Decimal(str(progress_value)),
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        )
        return True
    except ClientError:
        return False


def load_progress(username: str, task_name: str):
    """
    Retrieve a user's task progress from DynamoDB.
    Returns 0 if not found or on error.
    """
    if not username or not task_name:
        raise ValueError("Username and task_name must be provided")
    
    try:
        response = table.get_item(Key={'username': username, 'task_name': task_name})
        item = response.get('Item', {})
        return float(item.get('progress', 0))
    except ClientError:
        return 0


def update_progress_smoothly(username: str, task_name: str, target_value, step=0.1):
    """
    Incrementally update a user's task progress to a target value.
    """
    if not username:
        raise ValueError("Username must be provided")

    current = Decimal(str(load_progress(username, task_name)))
    target = Decimal(str(target_value))
    step = Decimal(str(step))

    while current < target:
        current += step
        if current > target:
            current = target
        save_progress(username, task_name, current)

    return current


def process_resume_chunks(username: str, chunks: list):
    """
    Sequentially process resume chunks and update overall progress.
    """
    if not username:
        raise ValueError("Username must be provided")

    total_chunks = len(chunks)
    for i, chunk in enumerate(chunks, start=1):
        try:
            # Placeholder: actual chunk processing
            time.sleep(0.1)
        except Exception:
            pass

        progress = Decimal(str(i / total_chunks))
        save_progress(username, 'resume_chunks', progress)

    save_progress(username, 'resume_chunks', Decimal("1.0"))
    return True
