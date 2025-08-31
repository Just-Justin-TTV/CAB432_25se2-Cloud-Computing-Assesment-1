import sys
import os
import django
import time
import psutil
import requests
from datetime import datetime
from bs4 import BeautifulSoup
import signal

# Add project root to Python path
sys.path.append("/code")

# Setup Django environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "app1.settings")
django.setup()

from django.contrib.auth.models import User

# Configuration
USERNAME = os.environ.get("TEST_USERNAME", "testuser")
PASSWORD = os.environ.get("TEST_PASSWORD", "password123")
ITERATIONS_DELAY = 2
CPU_LOG_FILE = "/code/load_test_cpu.log"
BASE_URL = os.environ.get("APP_URL", "http://localhost:8000")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://cab432-ollama:11434")

# Create test user if missing
if not User.objects.filter(username=USERNAME).exists():
    print(f"Creating test user: {USERNAME}")
    User.objects.create_user(username=USERNAME, password=PASSWORD)
else:
    print(f"Test user '{USERNAME}' already exists")

# Start session and authenticate
session = requests.Session()
login_page = session.get(f"{BASE_URL}/login/")
soup = BeautifulSoup(login_page.text, "html.parser")
csrf_token = soup.find("input", {"name": "csrfmiddlewaretoken"})
csrf_token = csrf_token.get("value") if csrf_token else ""

login_resp = session.post(
    f"{BASE_URL}/login/",
    data={
        "username": USERNAME,
        "password": PASSWORD,
        "csrfmiddlewaretoken": csrf_token,
    },
    headers={"Referer": f"{BASE_URL}/login/"}
)

if login_resp.status_code not in (200, 302):
    print("Failed to log in, check credentials:", login_resp.status_code)
    exit(1)
else:
    print(f"Logged in as {USERNAME} successfully")

# Graceful shutdown
stop_flag = False
def signal_handler(sig, frame):
    global stop_flag
    print("\nGraceful shutdown requested, exiting...")
    stop_flag = True

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Monitoring loop
iteration = 1
with open(CPU_LOG_FILE, "a") as f:
    while not stop_flag:
        start_time = time.time()
        try:
            resp = session.get(f"{BASE_URL}/dashboard/")
            status_code = resp.status_code
        except Exception as e:
            status_code = f"Error: {e}"

        end_time = time.time()
        duration = end_time - start_time
        cpu_percent = psutil.cpu_percent(interval=1) / psutil.cpu_count() * 100

        log_line = f"{datetime.now()} | Iteration {iteration} | Duration: {duration:.2f}s | CPU: {cpu_percent:.1f}% | Status: {status_code}\n"
        print(log_line.strip())
        f.write(log_line)
        f.flush()

        iteration += 1
        time.sleep(ITERATIONS_DELAY)
