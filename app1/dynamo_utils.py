import boto3
from botocore.exceptions import ClientError
import logging
import time
from datetime import datetime, timezone
from decimal import Decimal


# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Change to logging.INFO if too verbose
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# Initialize DynamoDB
logging.info("Initializing DynamoDB resource...")
dynamodb = boto3.resource("dynamodb", region_name="ap-southeast-2")
table = dynamodb.Table("n11605618dynamo")
logging.info(f"DynamoDB table '{table.name}' initialized successfully.")

def display_progress(progress_value):
    """
    Convert a float progress (0-1 or 0-100) to an integer percentage.
    """
    try:
        return int(round(float(progress_value)))
    except (ValueError, TypeError):
        return 0


def save_progress(username: str, task_name: str, progress_value):
    """
    Save progress to DynamoDB using Decimal for numeric values.
    """
    if not username or progress_value is None:
        raise ValueError("Username and progress value must be provided")

    try:
        table.put_item(
            Item={
                "username": str(username),
                "task_name": str(task_name),
                "progress": Decimal(str(progress_value)),  # ✅ Use Decimal
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        )
        return True
    except ClientError as e:
        logging.error(f"[save_progress] Error: {e}")
        return False


def load_progress(username: str, task_name: str):
    """
    Load progress for a given task for a user.
    Returns 0 if not found or on error.
    """
    if not username or not task_name:
        raise ValueError("Username and task_name must be provided")
    
    try:
        response = table.get_item(Key={'username': username, 'task_name': task_name})
        item = response.get('Item', {})
        return float(item.get('progress', 0))
    except ClientError as e:
        logging.error(f"[load_progress] Error: {e}")
        return 0


def update_progress_smoothly(username: str, task_name: str, target_value, step=0.1):
    """
    Gradually update progress to a target value in increments.
    """
    if not username:
        raise ValueError("Username must be provided")

    from decimal import Decimal

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
    Process resume chunks sequentially and update progress.
    """
    if not username:
        raise ValueError("Username must be provided")

    total_chunks = len(chunks)
    for i, chunk in enumerate(chunks, start=1):
        try:
            # Placeholder: actual chunk processing
            time.sleep(0.1)
        except Exception as e:
            print(f"[ERROR] Failed to process chunk {i}: {e}")

        progress = Decimal(str(i / total_chunks))
        save_progress(username, 'resume_chunks', progress)

    save_progress(username, 'resume_chunks', Decimal("1.0"))
    return True