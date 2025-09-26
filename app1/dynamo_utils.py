import boto3
from botocore.exceptions import ClientError
import logging
import time

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


def save_progress(username: str, task_name: str, progress_value):
    """
    Save progress for a given task for a user.
    Ensures username is string and progress_value is not None.
    """
    if not username or progress_value is None:
        raise ValueError("Username and progress value must be provided")
    
    try:
        table.update_item(
            Key={'username': str(username)},
            UpdateExpression='SET #task = :val',
            ExpressionAttributeNames={'#task': task_name},
            ExpressionAttributeValues={':val': progress_value}
        )
        return True
    except ClientError as e:
        print(f"[save_progress] Error: {e}")
        return False


def load_progress(username: str, task_name: str):
    """
    Load progress for a given task for a user.
    Returns 0 if not found or on error.
    """
    if not username:
        raise ValueError("Username must be provided")
    
    try:
        response = table.get_item(Key={'username': str(username)})
        item = response.get('Item', {})
        return item.get(task_name, 0)
    except ClientError as e:
        print(f"[load_progress] Error: {e}")
        return 0


def update_progress_smoothly(username: str, task_name: str, target_value: float, step: float = 0.1):
    """
    Gradually update progress to a target value in increments.
    Returns the final value.
    """
    if not username:
        raise ValueError("Username must be provided")
    
    current = load_progress(username, task_name)
    while current < target_value:
        current += step
        if current > target_value:
            current = target_value
        save_progress(username, task_name, current)
    return current


def process_resume_chunks(username: str, chunks: list):
    """
    Process resume chunks sequentially and update progress.
    Saves progress incrementally in DynamoDB.
    """
    if not username:
        raise ValueError("Username must be provided")
    
    total_chunks = len(chunks)
    for i, chunk in enumerate(chunks, start=1):
        try:
            # Placeholder for actual chunk processing (e.g., NLP, indexing)
            # e.g., nlp_analyze_chunk(chunk)
            time.sleep(0.1)  # simulate processing delay
        except Exception as e:
            print(f"[ERROR] Failed to process chunk {i}: {e}")
        
        progress = i / total_chunks
        save_progress(username, 'resume_chunks', progress)
    
    save_progress(username, 'resume_chunks', 1.0)  # mark complete
    return True