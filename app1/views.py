import os
import json
import re
import io
import time
import base64
import hmac
import logging
from functools import wraps
from uuid import uuid4
from decimal import Decimal
import datetime

import requests
import jwt
import boto3
from botocore.exceptions import ClientError
from docx import Document
from PyPDF2 import PdfReader

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login as django_login, get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
from django.views.decorators.clickjacking import xframe_options_exempt
from django.http import JsonResponse
from django.conf import settings
from django.urls import reverse
from django.core.cache import cache
from django.contrib.auth import login
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User


from app1.models import TaskProgress, Resume, JobApplication
from app1.api_cache import test_api_tags
from .dynamo_utils import (
    save_progress,
    load_progress,
    update_progress_smoothly,
    process_resume_chunks,
    display_progress
)
from . import s3_utils

# ===== Ollama Tags / Cache =====
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")


# Example: initial request to Ollama API


# Logger
logger = logging.getLogger(__name__)

def simulate_resume_upload(request):
    """
    Simulates a resume upload and runs the existing processing logic.
    """
    test_file_path = os.path.join(settings.BASE_DIR, "test_resumes", "TestResume.pdf")

    # Call your existing processing function
    from .resume_processing import process_resume  # adjust import
    result = process_resume(test_file_path)  # could be a dict with match info, etc.

    # Return a JSON response to simulate front-end consumption
    return JsonResponse({
        "status": "success",
        "file_name": "TestResume.pdf",
        "match_result": result,  # whatever your process_resume returns
        "download_url": "/static/test_resumes/TestResume.pdf"  # optional
    })


def test_ollama_connection():
    import os
    import requests
    import logging

    OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    test_url = f"{OLLAMA_URL}/api/tags"
    logging.info(f"Testing connection to Ollama API at {test_url}")

    try:
        response = requests.get(test_url, timeout=10)
        response.raise_for_status()
        models = response.json().get("models", [])
        logging.info(f"Ollama connection successful, models available: {[m['name'] for m in models]}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to connect to Ollama API: {e}")


def call_ollama(payload, retries=3, delay=2):
    """
    Call the Ollama API and return JSON response.
    Logs each attempt for debugging.
    """
    url = f"{OLLAMA_URL}/api/generate"
    logging.info(f"Calling Ollama API at: {url}")
    logging.debug(f"Payload: {payload}")

    for attempt in range(1, retries + 1):
        try:
            response = requests.post(url, json=payload, timeout=60)
            response.raise_for_status()
            logging.info(f"Successfully received response from Ollama on attempt {attempt}")
            logging.debug(f"Response: {response.text}")
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.warning(f"Attempt {attempt} failed: {e}")
            if attempt < retries:
                logging.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                logging.error("All Ollama attempts failed")
                raise
# ===== Ollama Tags / Cache =====


from .models import Resume, JobApplication
from . import s3_utils
from app1.api_cache import test_api_tags

dynamodb = boto3.resource('dynamodb', region_name="ap-southeast-2")
table = dynamodb.Table("n11605618dynamo")

logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')
import threading
from django.http import JsonResponse

from .models import Resume, JobApplication
# ===== Cognito / AWS Setup =====
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
COGNITO_CLIENT_SECRET = os.environ.get("COGNITO_CLIENT_SECRET", "")
COGNITO_REGION = os.environ.get("COGNITO_REGION", "ap-southeast-2")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")

AWS_PROFILE = "CAB432-STUDENT"
AWS_REGION = "ap-southeast-2"
AWS_BUCKET = "justinsinghatwalbucket"



def trigger_resume_match(request, resume_id):
    username = request.user.username if request.user.is_authenticated else "guest"
    job_position = request.GET.get("job_position", "Software Engineer")

    # The file path for the resume (assuming it's saved locally)
    resume_path = f"resumes/{resume_id}.pdf"

    if settings.USE_LOCAL_CPU:
        # Use local processing directly (optional)
        
        score, feedback_file = match_resume_to_job(username, resume_path, job_position)
    else:
        # Call your Ollama app (DevB)
        data = {
            "username": username,
            "resume_path": resume_path,
            "job_position": job_position
        }
        try:
            response = requests.post(settings.DEVB_URL, json=data, timeout=600)
            response.raise_for_status()
            result = response.json()
            score = result.get("score", 0)
            feedback_file = result.get("feedback_file", "none")
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({
        "score": score,
        "feedback_file": feedback_file,
        "message": "Resume match completed successfully"
    })


def task_progress_api(request, task_name):
    """Return JSON with progress (0-100) and optional result for a task."""
    username = request.user.username
    progress = load_progress(username, task_name) or Decimal("0")

    result = {}
    if progress >= 100:
        from .models import JobApplication
        job_app = JobApplication.objects.filter(user__username=username).order_by("-id").first()
        if job_app:
            result = {
                "score": float(job_app.score)*100,
                "feedback": job_app.feedback,
            }

    return JsonResponse({"progress": float(progress), "result": result})


def safe_save_progress(username: str, task_name: str, progress_value):
    """Save task progress only if the new value is greater than the current value."""
    current = Decimal(str(load_progress(username, task_name) or 0))
    new_value = Decimal(str(progress_value))
    if new_value > current:
        save_progress(username, task_name, new_value)


User = get_user_model()

def secret_hash(username):
    """Compute Cognito secret hash for a given username."""
    if not COGNITO_CLIENT_SECRET:
        return None
    msg = username + COGNITO_CLIENT_ID
    dig = hmac.new(
        str(COGNITO_CLIENT_SECRET).encode("utf-8"),
        msg.encode("utf-8"),
        digestmod="sha256"
    ).digest()
    sh = base64.b64encode(dig).decode()
    return sh


def is_cognito_admin(username):
    """Check if the Cognito user is in the 'Admin' group."""
    if not username:
        return False

    client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    try:
        response = client.admin_list_groups_for_user(
            Username=username,
            UserPoolId=COGNITO_USER_POOL_ID
        )
        groups = [g['GroupName'] for g in response.get('Groups', [])]
        return "Admin" in groups
    except client.exceptions.UserNotFoundException:
        return False
    except Exception:
        return False


def debug_tags(request):
    """Debug endpoint to test API tags."""
    tags = test_api_tags()
    return JsonResponse({"tags": tags})


def cognito_authenticate(username, password):
    """Authenticate a user with Cognito and return authentication tokens."""
    client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    auth_params = {"USERNAME": username, "PASSWORD": password}
    sh = secret_hash(username)
    if sh:
        auth_params["SECRET_HASH"] = sh

    try:
        response = client.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters=auth_params,
            ClientId=COGNITO_CLIENT_ID
        )

        if "ChallengeName" in response:
            return None

        auth_result = response.get("AuthenticationResult")
        return auth_result

    except client.exceptions.NotAuthorizedException:
        pass
    except client.exceptions.UserNotFoundException:
        pass
    except Exception:
        pass
    return None

def cognito_signup(username, password, email):
    client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    kwargs = {
        "ClientId": COGNITO_CLIENT_ID,
        "Username": username,
        "Password": password,
        "UserAttributes": [{"Name": "email", "Value": email}]
    }
    sh = secret_hash(username)
    if sh:
        kwargs["SecretHash"] = sh
    try:
        return client.sign_up(**kwargs)
    except Exception as e:
        print(f"[ERROR] Cognito sign-up failed: {e}")
        return None

def cognito_confirm_signup(username, confirmation_code):
    """Confirm a new Cognito user signup with a confirmation code."""
    client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    kwargs = {
        "ClientId": COGNITO_CLIENT_ID,
        "Username": username,
        "ConfirmationCode": confirmation_code
    }
    sh = secret_hash(username)
    if sh:
        kwargs["SecretHash"] = sh
    try:
        return client.confirm_sign_up(**kwargs)
    except Exception:
        return None


def cognito_send_reset_code(username):
    """Send a password reset code to the user via Cognito."""
    client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    kwargs = {"ClientId": COGNITO_CLIENT_ID, "Username": username}
    sh = secret_hash(username)
    if sh:
        kwargs["SecretHash"] = sh
    try:
        return client.forgot_password(**kwargs)
    except Exception:
        return None


def cognito_confirm_reset(username, code, new_password):
    """Confirm a password reset in Cognito and return new authentication tokens."""
    client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    kwargs = {
        "ClientId": COGNITO_CLIENT_ID,
        "Username": username,
        "ConfirmationCode": code,
        "Password": new_password
    }
    sh = secret_hash(username)
    if sh:
        kwargs["SecretHash"] = sh
    try:
        client.confirm_forgot_password(**kwargs)
        return cognito_authenticate(username, new_password)
    except Exception:
        return None


def get_django_user_from_cognito(request):
    """Return the Django User object corresponding to the Cognito session."""
    User = get_user_model()
    cognito_user = request.session.get("cognito_user")
    if not cognito_user:
        return None
    username = cognito_user.get("username")
    try:
        return User.objects.get(username=username)
    except User.DoesNotExist:
        return None


def get_cognito_username(request):
    """Get the Cognito username from the session."""
    user = request.session.get('cognito_user')
    return user.get('username') if user else None


def sync_cognito_user_to_django(request):
    """Sync Cognito user session to Django User and set staff/superuser flags."""
    User = get_user_model()
    cognito_user = request.session.get("cognito_user")
    if not cognito_user:
        return None

    username = cognito_user.get("username")

    client = boto3.client('cognito-idp', region_name=COGNITO_REGION)
    try:
        response = client.admin_list_groups_for_user(
            Username=username,
            UserPoolId=COGNITO_USER_POOL_ID
        )
        groups = [g['GroupName'] for g in response.get("Groups", [])]
    except Exception:
        groups = []

    user, created = User.objects.get_or_create(username=username)
    user.is_staff = 'admin' in [g.lower() for g in groups]
    user.is_superuser = 'admin' in [g.lower() for g in groups]
    user.save()

    login(request, user)
    return user


# ===== Decorators =====
def cognito_login_required(view_func):
    """Decorator to enforce Cognito login for a view."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if 'cognito_user' not in request.session:
            messages.warning(request, "Please log in first.")
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper


def cognito_group_required(group_name=None):
    """Decorator to enforce Cognito group membership for a view."""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            user_data = request.session.get("cognito_user")
            if not user_data or "id_token" not in user_data:
                return redirect("login")
            if not group_name:
                return view_func(request, *args, **kwargs)
            try:
                decoded = jwt.decode(user_data["id_token"], options={"verify_signature": False})
                groups = decoded.get("cognito:groups", [])
                if group_name in groups:
                    return view_func(request, *args, **kwargs)
                else:
                    return redirect("unauthorized")
            except Exception:
                return redirect("login")
        return _wrapped_view
    return decorator


# ===== Views ===== 

@csrf_exempt
@never_cache
@xframe_options_exempt
def unauthorized(request):
    """Render a 401 Unauthorized page."""
    return render(request, 'unauthorized.html', status=401)


@csrf_exempt
@never_cache
@xframe_options_exempt
def register_view(request):
    """Handle user registration via Django auth."""
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password1 = request.POST.get("password1")
        password2 = request.POST.get("password2")

        if not all([username, email, password1, password2]):
            messages.error(request, "All fields are required.")
            return render(request, "register.html")

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return render(request, "register.html")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return render(request, "register.html")

        user = User.objects.create_user(username=username, email=email, password=password1)
        user.save()
        messages.success(request, "Registration successful! You can now log in.")
        return redirect("login")

    return render(request, "register.html")


@csrf_exempt
def confirm_view(request):
    """Handle user signup confirmation via Cognito."""
    if request.method == "POST":
        username = request.POST.get("username")
        code = request.POST.get("confirmation_code")
        if cognito_confirm_signup(username, code):
            messages.success(request, "Confirmation successful! You can now log in.")
            return redirect("login")
        else:
            messages.error(request, "Confirmation failed.")
    return render(request, "confirm.html")


@csrf_exempt
def login_view(request):
    """Handle user login using Django auth."""
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        # Authenticate against Django's user model
        user = authenticate(request, username=username, password=password)
        if user:
            # Log in the user with Django
            login(request, user)

            # Set session info for Cognito decorators
            # Add a dummy id_token to satisfy @cognito_group_required / @cognito_login_required
            request.session['cognito_user'] = {
                "username": user.username,
                "id_token": "fake-token-for-django-login"
            }

            messages.success(request, f"Login successful! Welcome {user.username}.")
            return redirect("home")  # Redirect to home/dashboard

        else:
            messages.error(request, "Invalid username or password.")

    return render(request, "login.html")




@csrf_exempt
def reset_password_confirm_view(request):
    """Confirm a password reset via Cognito using a confirmation code."""
    if request.method == "POST":
        username = request.POST.get("username")
        code = request.POST.get("code")
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")

        if not all([username, code, new_password, confirm_password]):
            messages.error(request, "All fields are required.")
            return redirect("reset_password_confirm")

        if new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect("reset_password_confirm")

        client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
        try:
            client.confirm_forgot_password(
                ClientId=COGNITO_CLIENT_ID,
                Username=username,
                ConfirmationCode=code,
                Password=new_password,
                SecretHash=secret_hash(username)
            )
            messages.success(request, "Password reset successful! You can now log in.")
            return redirect("login")
        except Exception as e:
            messages.error(request, f"Password reset failed: {str(e)}")
            return redirect("reset_password_confirm")

    return render(request, "reset_password_confirm.html")


@cognito_login_required
def logout_view(request):
    """Log out the user and clear session data."""
    request.session.pop('cognito_user', None)
    request.session.flush()
    messages.success(request, "Logged out successfully.")
    return redirect("login")


@cognito_login_required
def dashboard_view(request):
    """Render the dashboard showing job applications and admin status."""
    username = get_cognito_username(request)
    django_user = get_django_user_from_cognito(request)

    if django_user is None:
        job_applications = JobApplication.objects.none()
    else:
        job_applications = JobApplication.objects.filter(user=django_user).select_related('resume')

    client = boto3.client('cognito-idp', region_name=COGNITO_REGION)
    try:
        response = client.admin_list_groups_for_user(
            Username=username,
            UserPoolId=COGNITO_USER_POOL_ID
        )
        groups = [g['GroupName'].lower() for g in response.get('Groups', [])]
        is_admin = 'admin' in groups
    except Exception as e:
        is_admin = False

    return render(request, 'dashboard.html', {
        'is_admin': is_admin,
        'job_applications': job_applications,
    })





def get_resume_progress(request):
    """Return the progress of a user's resume processing task as JSON."""
    django_user = get_django_user_from_cognito(request)
    if not django_user:
        return JsonResponse({"progress": 0})

    task_name = request.GET.get("task_name") or "resume_processing"
    progress = load_progress(django_user.username, task_name) or 0
    return JsonResponse({'progress': progress})


def get_progress(request, username: str, task_name: str):
    """Return the current progress for a given username and task."""
    if not username:
        return 0
    return load_progress(username, task_name) or 0


@cognito_group_required("admin")
def admin_dashboard_view(request):
    """Render admin dashboard showing all job applications."""
    if not request.user.is_authenticated:
        return redirect('login')

    job_applications = JobApplication.objects.all().select_related('resume')
    return render(request, 'admin_dashboard.html', {
        'job_applications': job_applications,
    })


def update_progress(username: str, task_name: str, increment: float = 1.0):
    """Increment the progress of a task and return the new value."""
    if not username:
        raise ValueError("Username must be provided")
    
    current = load_progress(username, task_name)
    new_value = current + increment
    save_progress(username, task_name, new_value)
    return new_value


# ===== Resume Helpers =====

def match_resume_to_job(request, resume_id):
    """
    Trigger the resume-to-job matching process in Dev B.
    Returns a task ID immediately so the frontend can poll progress.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid method"}, status=405)

    user = request.user.username
    task_id = str(uuid.uuid4())  # unique task identifier

    # Send request to Dev B API
    dev_b_url = settings.DEVB_URL

    payload = {
        "task_id": task_id,
        "username": user,
        "resume_id": resume_id
    }

    try:
        # Fire-and-forget trigger; you can also use Celery/RabbitMQ for async
        requests.post(dev_b_url, json=payload, timeout=5)
    except requests.exceptions.RequestException as e:
        return JsonResponse({"error": f"Failed to trigger Dev B: {str(e)}"}, status=500)

    return JsonResponse({"task_id": task_id, "status": "started"})


# ===== Resume Upload / Confirm =====

@cognito_login_required
def upload_resume(request):
    """Render the resume upload page."""
    return render(request, 'resume/upload.html')


@csrf_exempt
def get_presigned_url(request):
    """Generate a presigned S3 URL for uploading a resume file."""
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=400)
    data = json.loads(request.body)
    filename = data.get("filename")
    content_type = data.get("content_type")
    if not filename:
        return JsonResponse({"error": "filename required"}, status=400)
    key = f"resumes/uploads/{uuid4()}_{filename}"
    try:
        url = s3_utils.upload_file_to_s3(None, key, content_type)
        return JsonResponse({"url": url, "key": key})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
def confirm_upload(request):
    """Confirm that a resume file has been uploaded and create a Resume record."""
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=400)
    data = json.loads(request.body)
    key = data.get("key")
    if not key:
        return JsonResponse({"error": "key required"}, status=400)

    django_user = get_django_user_from_cognito(request)
    resume_url = f"https://{AWS_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{key}"
    try:
        resume = Resume.objects.create(s3_file_path=resume_url, user=django_user)
        
        return JsonResponse({
            "success": True,
            "resume_id": resume.id,
            "key": key,
            "download_url": f"/resume/download_file/?key={key}",
            "match_url": f"/resume/{resume.id}/match/"
        })
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


# ===== File Download =====

@cognito_login_required
def download_file(request):
    """Redirect user to a presigned download URL for a resume file."""
    key = request.GET.get("key")
    if not key:
        messages.error(request, "No file specified for download.")
        return redirect("dashboard")
    try:
        url = s3_utils.get_presigned_download_url(key)
        return redirect(url)
    except Exception as e:
        messages.error(request, f"Download failed: {e}")
        return redirect("dashboard")


# ===== Ollama / AI Matching =====







@cognito_login_required
def view_job_application(request, job_app_id):
    """
    Display a single job application for the logged-in user.
    """
    django_user = get_django_user_from_cognito(request)
    job_app = get_object_or_404(JobApplication, id=job_app_id, user=django_user)
    return render(request, 'resume/view_job_application.html', {'job_app': job_app})


@cognito_login_required
def job_application_detail(request, pk):
    """
    Show detailed view of a job application for the logged-in user.
    """
    django_user = get_django_user_from_cognito(request)
    job_app = get_object_or_404(JobApplication, pk=pk, user=django_user)
    return render(request, "resume/job_application_detail.html", {"job_app": job_app})


def test_login(request):
    """
    Render a test login page.
    """
    return render(request, "login.html", {"test": "ok"})


def wait_for_ollama(timeout=60):
    """
    Wait until Ollama API is available, or raise an exception after timeout.
    """
    url = f"{os.environ.get('OLLAMA_HOST', 'http://ollama:11434')}/api/tags"
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return True
        except requests.exceptions.RequestException:
            time.sleep(2)
    raise Exception("Ollama not available after waiting.")


@cognito_group_required()  # no group restriction
def home(request):
    """
    Render the home page for any logged-in user.
    """
    django_user = get_django_user_from_cognito(request)
    return render(request, "home.html", {"username": django_user.username if django_user else "Guest"})





