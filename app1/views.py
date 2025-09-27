import os
import json
import re
import io
import time
import base64
from functools import wraps
from uuid import uuid4
import logging
import datetime
import requests
from docx import Document
from PyPDF2 import PdfReader
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse
from django.core.cache import cache
from django.conf import settings
response = requests.get(f"{settings.OLLAMA_URL}/api/tags")
from .models import Resume, JobApplication
from . import s3_utils

logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')
import os
import logging
import datetime
import requests
from django.core.cache import cache

logger = logging.getLogger(__name__)

# ===== Ollama Tags / Cache =====
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://cab432-ollama:11434")
import requests
import logging
from django.core.cache import cache

logger = logging.getLogger(__name__)
# ===== Dummy User Setup for Headless Testing =====
from django.contrib.auth import get_user_model
User = get_user_model()

def get_django_user_from_cognito(request):
    """
    Return a dummy Django user for testing.
    """
    dummy_username = "testuser"
    user, created = User.objects.get_or_create(username=dummy_username)
    if created:
        user.is_staff = False
        user.is_superuser = False
        user.save()
    return user

def cognito_login_required(view_func):
    """Allow all requests (Cognito disabled)."""
    return view_func

def cognito_group_required(group_name=None):
    """Allow all requests (Cognito disabled)."""
    def decorator(view_func):
        return view_func
    return decorator

# ===== Ollama Tags / Cache =====
def get_api_tags():
    """
    Fetch available Ollama API tags, using Memcached (AWS ElastiCache) for caching.
    """
    cache_key = "api_tags"
    now = datetime.datetime.now().isoformat()

    # Try fetching from cache first
    tags = cache.get(cache_key)
    if tags:
        logger.debug(f"[{now}] [CACHE HIT] Returning cached tags: {tags}")
        return tags

    # Cache miss: fetch from Ollama API
    logger.debug(f"[{now}] [CACHE MISS] Fetching from Ollama...")
    try:
        response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=10)
        response.raise_for_status()
        tags = response.json()

        # Store in cache for 5 minutes
        cache.set(cache_key, tags, timeout=300)
        logger.debug(f"[{now}] [CACHE SET] Cached tags for 5 min")
        return tags

    except requests.RequestException as e:
        logger.error(f"[{now}] [ERROR] Failed to fetch tags from Ollama: {e}")
        return {"models": []}


def test_api_tags():
    """
    Return the currently available API tags.
    """
    tags = get_api_tags()
    return tags

# ===== Resume Helpers =====
def read_resume_text(resume):
    text = ""
    if not resume.s3_file_path:
        return text
    resp = requests.get(resume.s3_file_path)
    file_bytes = resp.content
    ext = os.path.splitext(resume.s3_file_path)[1].lower()
    try:
        if ext == ".txt":
            text = file_bytes.decode('utf-8', errors='ignore')
        elif ext == ".docx":
            doc = Document(io.BytesIO(file_bytes))
            text = "\n".join([p.text for p in doc.paragraphs])
        elif ext == ".pdf":
            reader = PdfReader(io.BytesIO(file_bytes))
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
    except Exception as e:
        print(f"[ERROR] Failed to read resume: {e}")
    return text

def call_ollama(payload, retries=10, delay=3):
    """
    Call Ollama API with retry.
    """
    url = f"{os.environ.get('OLLAMA_HOST', 'http://cab432-ollama:11434')}/api/generate"
    for attempt in range(retries):
        try:
            response = requests.post(url, json=payload, timeout=600)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"[WARNING] Ollama request failed (attempt {attempt+1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                raise e

# ===== Views =====
@cognito_login_required
def home(request):
    """
    Home view for any logged-in (dummy) user.
    """
    django_user = get_django_user_from_cognito(request)
    return render(request, "home.html", {"username": django_user.username if django_user else "Guest"})


# views.py
@cognito_login_required
def login_view(request):
    """
    Dummy login view for headless testing.
    """
    django_user = get_django_user_from_cognito(request)
    messages.info(request, f"Logged in as {django_user.username}")
    return redirect('home')

# views.py
@cognito_login_required
def logout_view(request):
    """
    Dummy logout view for headless testing.
    """
    messages.info(request, "Logged out (dummy).")
    return redirect('home')
# views.py
@cognito_login_required
def register_view(request):
    """
    Dummy register view for headless testing.
    """
    messages.info(request, "Registered (dummy).")
    return redirect('home')

@cognito_login_required
def confirm_view(request):
    """
    Dummy confirm view for headless testing.
    """
    messages.info(request, "Account confirmed (dummy).")
    return redirect('home')

@cognito_login_required
def test_login(request):
    """
    Dummy test login view for headless testing.
    """
    django_user = get_django_user_from_cognito(request)
    messages.info(request, f"Logged in as {django_user.username} (dummy)")
    return redirect('home')

@cognito_login_required
def dashboard_view(request):
    """
    Dummy dashboard view for headless testing.
    """
    django_user = get_django_user_from_cognito(request)
    return render(request, "dashboard.html", {"username": django_user.username if django_user else "Guest"})

@cognito_login_required
def admin_dashboard_view(request):
    """
    Dummy admin dashboard view for headless testing.
    """
    django_user = get_django_user_from_cognito(request)
    return render(request, "admin_dashboard.html", {"username": django_user.username if django_user else "Admin"})

@cognito_login_required
def upload_resume(request):
    """
    Dummy upload resume view for headless testing.
    """
    django_user = get_django_user_from_cognito(request)
    if request.method == "POST":
        messages.success(request, "Dummy resume uploaded!")
        return redirect("home")
    return render(request, "resume/upload.html", {"username": django_user.username if django_user else "Guest"})


@cognito_login_required
def get_presigned_url(request):
    """
    Dummy view to return a fake presigned URL for testing.
    """
    dummy_url = "https://example.com/fake_presigned_url"
    return JsonResponse({"url": dummy_url})

@cognito_login_required
def download_file(request):
    """
    Dummy view for downloading a file.
    Returns a simple JSON response for testing.
    """
    return JsonResponse({"status": "success", "message": "Download triggered (dummy)"})

@cognito_login_required
def confirm_upload(request):
    """
    Dummy view for confirming a resume upload.
    Returns a simple JSON response for testing.
    """
    return JsonResponse({"status": "success", "message": "Upload confirmed (dummy)"})

@cognito_login_required
def match_resume_to_job(request, resume_id):
    """
    Match resume to job using Ollama and cache.
    """
    django_user = get_django_user_from_cognito(request)
    resume = get_object_or_404(Resume, id=resume_id, user=django_user)

    if request.method == "POST":
        job_position = request.POST.get("job_position")
        if not job_position:
            messages.error(request, "Please enter a job position.")
            return redirect("match_resume_to_job", resume_id=resume.id)

        try:
            resume_text = read_resume_text(resume)
            prompt = f"""
            You are an assistant that evaluates resumes against job positions.
            Job Position: {job_position}
            Resume Text: {resume_text}

            Return JSON with keys: score, feedback
            """
            payload = {"model": "mistral", "prompt": prompt, "stream": False}
            response = call_ollama(payload)

            ai_text = response.get("response", "")
            score, feedback = 50, ""
            if ai_text:
                try:
                    parsed = json.loads(re.search(r"\{.*\}", ai_text, re.DOTALL).group(0))
                    score = parsed.get("score", 50)
                    feedback = parsed.get("feedback", "")
                    if isinstance(feedback, dict):
                        feedback = json.dumps(feedback, indent=4)
                    else:
                        feedback = str(feedback)
                except Exception as parse_err:
                    print(f"[ERROR] AI parsing error: {parse_err}")
                    feedback = ai_text

            key = f"feedback/{django_user.username}/{uuid4()}_resume_{resume.id}_feedback.txt"
            feedback_s3_url = s3_utils.upload_file_to_s3(feedback.encode('utf-8'), key)

            job_app = JobApplication.objects.create(
                user=django_user,
                resume=resume,
                job_description=job_position,
                ai_model="mistral",
                score=float(score)/100.0,
                status="completed",
                feedback=feedback,
                feedback_s3_url=feedback_s3_url
            )
            messages.success(request, f"Match analysis complete! Score: {score}")
            return redirect("view_job_application", job_app_id=job_app.id)
        except Exception as e:
            print(f"[ERROR] AI processing failed: {e}")
            messages.error(request, f"AI processing failed: {e}")
            return redirect("match_resume_to_job", resume_id=resume.id)

    return render(request, "resume/match.html", {"resume": resume})

@cognito_login_required
def view_job_application(request, job_app_id):
    """
    View a specific job application.
    """
    django_user = get_django_user_from_cognito(request)
    job_app = get_object_or_404(JobApplication, id=job_app_id, user=django_user)
    return render(request, 'resume/view_job_application.html', {'job_app': job_app})

@cognito_login_required
def job_application_detail(request, pk):
    """
    Detailed view of a job application.
    """
    django_user = get_django_user_from_cognito(request)
    job_app = get_object_or_404(JobApplication, pk=pk, user=django_user)
    return render(request, "resume/job_application_detail.html", {"job_app": job_app})
