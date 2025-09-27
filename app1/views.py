import os
import json
import re
import io
import time
import base64
import hmac
from functools import wraps
from uuid import uuid4
import logging

import boto3
from botocore.exceptions import ClientError
import jwt
import requests
from docx import Document
from PyPDF2 import PdfReader
from app1.models import TaskProgress
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login as django_login, get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
from django.views.decorators.clickjacking import xframe_options_exempt
from django.http import JsonResponse
from django.contrib.auth import login
from django.core.cache import cache
from .dynamo_utils import save_progress, load_progress, update_progress_smoothly, process_resume_chunks
from django.urls import reverse
from .dynamo_utils import display_progress
from decimal import Decimal

from .models import Resume, JobApplication
from . import s3_utils
from app1.api_cache import test_api_tags

dynamodb = boto3.resource('dynamodb', region_name="ap-southeast-2")
table = dynamodb.Table("n11605618dynamo")

logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

# ===== Cognito / AWS Setup =====
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
COGNITO_CLIENT_SECRET = os.environ.get("COGNITO_CLIENT_SECRET", "")
COGNITO_REGION = os.environ.get("COGNITO_REGION", "ap-southeast-2")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")

AWS_PROFILE = "CAB432-STUDENT"
AWS_REGION = "ap-southeast-2"
AWS_BUCKET = "justinsinghatwalbucket"


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


def register_view(request):
    """Handle user registration via Cognito and show appropriate messages."""
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if not all([username, email, password1, password2]):
            messages.error(request, "All fields are required.")
            return render(request, 'register.html')

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return render(request, 'register.html')

        if not cognito_signup(username, password1, email):
            messages.error(request, "Registration failed. Try again.")
            return render(request, 'register.html')

        messages.success(request, "Check your email to confirm registration.")
        return redirect('confirm')

    return render(request, 'register.html')


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
    """Handle user login, password reset, and Cognito authentication."""
    
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        if username and password:
            cognito_user = cognito_authenticate(username, password)
            if cognito_user:
                request.session['cognito_user'] = {
                    'username': username,
                    'id_token': cognito_user.get('IdToken'),
                    'access_token': cognito_user.get('AccessToken'),
                    'refresh_token': cognito_user.get('RefreshToken'),
                }
                django_user = sync_cognito_user_to_django(request)
                if django_user:
                    messages.success(request, f"Login successful! Welcome {django_user.username}.")
                    return redirect("home")
                else:
                    messages.error(request, "Failed to sync user with Django.")
            else:
                messages.error(request, "Invalid username or password.")

        elif "send_code" in request.POST:
            reset_username = request.POST.get("reset_username")
            result = cognito_send_reset_code(reset_username)
            messages.success(
                request,
                "Check your email for the reset code." if result else "Failed to send reset code."
            )

        elif "confirm_reset" in request.POST:
            reset_username = request.POST.get("reset_username")
            code = request.POST.get("reset_code")
            new_password = request.POST.get("new_password")

            result = cognito_confirm_reset(reset_username, code, new_password)
            if result:
                request.session['cognito_user'] = {
                    'username': reset_username,
                    'id_token': result.get('IdToken'),
                    'access_token': result.get('AccessToken'),
                    'refresh_token': result.get('RefreshToken'),
                }
                django_user = sync_cognito_user_to_django(request)
                if django_user:
                    messages.success(request, f"Password reset successful! Logged in as {django_user.username}.")
                    return redirect("home")
                else:
                    messages.error(request, "Password reset succeeded, but failed to sync with Django.")
            else:
                messages.error(request, "Password reset failed. Check your code and try again.")

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


def process_resume_matching(username: str, resumes: list):
    """Process multiple resumes sequentially and track progress."""
    if not username or not resumes:
        return False

    total_resumes = len(resumes)
    task_name = "resume_matching"

    for i, resume in enumerate(resumes, start=1):
        try:
            time.sleep(0.1)
        except Exception as e:
            logging.error(f"Failed to process resume {i}: {e}")

        progress = Decimal(str(i / total_resumes * 100))
        safe_save_progress(username, task_name, progress)

    safe_save_progress(username, task_name, Decimal("100"))
    return True


def get_resume_progress(request):
    """Return the progress of a user's resume processing task as JSON."""
    django_user = get_django_user_from_cognito(request)
    if not django_user:
        return JsonResponse({"progress": 0})

    task_name = request.GET.get("task_name") or "resume_processing"
    progress = load_progress(django_user.username, task_name) or 0
    return JsonResponse({'progress': progress})


def get_progress(username: str, task_name: str):
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

def read_resume_text(resume):
    """Read the text content from a resume file (.txt, .docx, .pdf) stored on S3."""
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
        logging.error(f"Failed to read resume: {e}")
    return text


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

def call_ollama(payload, retries=10, delay=3):
    """
    Send a request to the Ollama API with retries and return the JSON response.
    """
    url = f"{os.environ.get('OLLAMA_HOST', 'http://cab432-ollama:11434')}/api/generate"
    for attempt in range(retries):
        try:
            response = requests.post(url, json=payload, timeout=600)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                raise e


@csrf_exempt
@cognito_login_required
def match_resume_to_job(request, resume_id):
    """
    Handle a resume-to-job matching request using AI evaluation and track progress.
    Saves feedback to S3 and records results in JobApplication.
    """
    django_user = get_django_user_from_cognito(request)
    if not django_user:
        messages.error(request, "User not found.")
        return redirect("login")

    resume = get_object_or_404(Resume, id=resume_id, user=django_user)
    task_name = f"match_resume_{resume.id}"

    progress = load_progress(django_user.username, task_name) or Decimal("0")
    task_progress_url = reverse('task_progress_api', kwargs={'task_name': task_name})

    if request.method == "POST":
        job_position = request.POST.get("job_position")
        if not job_position:
            messages.error(request, "Please enter a job position.")
            return redirect("match_resume_to_job", resume_id=resume.id)

        try:
            safe_save_progress(django_user.username, task_name, Decimal("10"))
            resume_text = read_resume_text(resume)
            safe_save_progress(django_user.username, task_name, Decimal("25"))

            prompt = f"""
            You are a highly intelligent assistant that evaluates resumes against job positions in extreme detail.
            Job Position: {job_position}
            Resume Text: {resume_text}
            
            Return JSON with keys: score, feedback
            """
            payload = {"model": "mistral", "prompt": prompt, "stream": False}
            safe_save_progress(django_user.username, task_name, Decimal("40"))

            response = call_ollama(payload)
            safe_save_progress(django_user.username, task_name, Decimal("70"))

            ai_text = response.get("response", "")
            score, feedback = 50, ""
            if ai_text:
                try:
                    parsed = json.loads(re.search(r"\{.*\}", ai_text, re.DOTALL).group(0))
                    score = parsed.get("score", 50)
                    feedback = parsed.get("feedback", "")
                    feedback = json.dumps(feedback, indent=4) if isinstance(feedback, dict) else str(feedback)
                except Exception as parse_err:
                    logging.error(f"AI parsing error: {parse_err}")
                    feedback = ai_text

            key = f"feedback/{django_user.username}/{uuid4()}_resume_{resume.id}_feedback.txt"
            feedback_s3_url = s3_utils.upload_file_to_s3(feedback.encode('utf-8'), key)
            safe_save_progress(django_user.username, task_name, Decimal("90"))

            JobApplication.objects.create(
                user=django_user,
                resume=resume,
                job_description=job_position,
                ai_model="mistral",
                score=float(score)/100.0,
                status="completed",
                feedback=feedback,
                feedback_s3_url=feedback_s3_url
            )

            safe_save_progress(django_user.username, task_name, Decimal("100"))
            messages.success(request, f"Match analysis complete! Score: {score}")
            return redirect("dashboard")

        except Exception as e:
            logging.error(f"[ERROR] AI processing failed: {e}")
            messages.error(request, f"AI processing failed: {e}")
            return redirect("match_resume_to_job", resume_id=resume.id)

    return render(request, "resume/match.html", {
        "resume": resume,
        "progress": progress,
        "task_progress_url": task_progress_url,
    })


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





