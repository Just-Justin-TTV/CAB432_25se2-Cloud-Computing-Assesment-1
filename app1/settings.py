import os
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# ------------------------------
# Local secrets helper
# ------------------------------
SECRETS_FILE = os.path.join(BASE_DIR, "secrets.json")

def get_secrets(secret_file=SECRETS_FILE):
    """Load secrets from a local JSON file."""
    if not os.path.exists(secret_file):
        raise FileNotFoundError(f"Secrets file not found: {secret_file}")
    with open(secret_file, "r") as f:
        return json.load(f)

secrets = get_secrets()

# Example secret access
API_KEY = secrets.get("API_KEY", "")
DB_USER = secrets.get("username", "")
DB_PASSWORD = secrets.get("password", "")
DB_NAME = secrets.get("dbname", "")
DB_HOST = secrets.get("host", "localhost")
DB_PORT = secrets.get("port", 5432)

# ------------------------------
# Ollama / AI service
# ------------------------------
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")

# ------------------------------
# Local file storage (instead of S3)
# ------------------------------
USE_LOCAL_STORAGE = True
LOCAL_STORAGE_PATH = os.path.join(BASE_DIR, "local_storage")

os.makedirs(LOCAL_STORAGE_PATH, exist_ok=True)

def get_storage_path(filename):
    """Return full path for a file in local storage."""
    return os.path.join(LOCAL_STORAGE_PATH, filename)

# ------------------------------
# Optional: local DB connection config
# ------------------------------
DATABASE_CONFIG = {
    "user": DB_USER,
    "password": DB_PASSWORD,
    "dbname": DB_NAME,
    "host": DB_HOST,
    "port": DB_PORT
}

# ------------------------------
# Other app constants
# ------------------------------
DEBUG = True
