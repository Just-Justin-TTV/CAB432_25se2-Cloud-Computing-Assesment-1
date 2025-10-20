import os
import json
import time
from decimal import Decimal

# Directory to store local progress files
PROGRESS_DIR = "progress"
os.makedirs(PROGRESS_DIR, exist_ok=True)


# ===== Progress Helpers =====
def display_progress(progress_value):
    """
    Convert a numeric progress value to an integer percentage.
    """
    try:
        return int(round(float(progress_value)))
    except (ValueError, TypeError):
        return 0


def save_progress(username, task_name, value):
    """
    Save progress to a local JSON file.
    """
    path = os.path.join(PROGRESS_DIR, f"{username}_{task_name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"progress": float(value)}, f)


def load_progress(username, task_name):
    """
    Load progress from a local JSON file.
    """
    path = os.path.join(PROGRESS_DIR, f"{username}_{task_name}.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return Decimal(str(data.get("progress", 0)))
    return Decimal("0")


def safe_save_progress(username, task_name, progress_value):
    """
    Save progress only if it's higher than the previous value.
    """
    current = load_progress(username, task_name)
    new_value = Decimal(str(progress_value))
    if new_value > current:
        save_progress(username, task_name, new_value)


def update_progress_smoothly(username: str, task_name: str, target_value, step=0.1):
    """
    Incrementally update a user's task progress to a target value.
    """
    if not username:
        raise ValueError("Username must be provided")

    current = load_progress(username, task_name)
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
        safe_save_progress(username, 'resume_chunks', progress)

    safe_save_progress(username, 'resume_chunks', Decimal("1.0"))
    return True
