import os
import json
from decimal import Decimal

PROGRESS_DIR = "progress"
os.makedirs(PROGRESS_DIR, exist_ok=True)

def load_progress(username, task_name):
    path = os.path.join(PROGRESS_DIR, f"{username}_{task_name}.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            return Decimal(str(json.load(f).get("progress", 0)))
    return Decimal("0")

def save_progress(username, task_name, value):
    path = os.path.join(PROGRESS_DIR, f"{username}_{task_name}.json")
    with open(path, "w") as f:
        json.dump({"progress": float(value)}, f)

def safe_save_progress(username, task_name, progress_value):
    current = load_progress(username, task_name)
    new_value = Decimal(str(progress_value))
    if new_value > current:
        save_progress(username, task_name, new_value)
