import json
import uuid
import time
import threading
import random
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# In-memory progress storage for mock
MOCK_PROGRESS = {}

def get_progress(task_id):
    """Return the current progress of a task."""
    return MOCK_PROGRESS.get(task_id, 0)

@csrf_exempt
def mock_resume_process(request):
    """
    Simulate Dev B processing a resume.
    Returns a task_id immediately and simulates progress over time.
    """
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    # Handle POST JSON payload
    try:
        data = json.loads(request.body)
    except Exception:
        data = {}

    task_id = str(uuid.uuid4())
    
    # Initialize progress
    MOCK_PROGRESS[task_id] = 0

    # Fake async task: increase progress over time (simulate Dev B)
    def simulate_progress():
        for i in range(1, 11):
            time.sleep(0.5)  # half-second per step
            MOCK_PROGRESS[task_id] = i * 10  # 0 → 100%
        # Once complete, store result as 100%
        MOCK_PROGRESS[task_id] = 100

    threading.Thread(target=simulate_progress, daemon=True).start()

    return JsonResponse({
        "task_id": task_id,
        "status": "started"
    })


@csrf_exempt
def mock_resume_progress(request):
    """Return the current progress and fake result if complete."""
    task_id = request.GET.get("task_id")
    if not task_id or task_id not in MOCK_PROGRESS:
        return JsonResponse({"error": "Invalid task_id"}, status=400)

    progress = MOCK_PROGRESS[task_id]

    result = {}
    if progress >= 100:
        # Fake result
        result = {
            "score": round(random.uniform(0.6, 0.95), 2),
            "feedback": "Mock feedback: resume matches job description."
        }

    return JsonResponse({
        "task_id": task_id,
        "progress": progress,
        "result": result
    })
