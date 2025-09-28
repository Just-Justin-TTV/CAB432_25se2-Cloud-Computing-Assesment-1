import os
import json
import re
import io
import time
import base64
import hmac
import logging
import hashlib
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
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://cab432-ollama:11434")

# Example: initial request to Ollama API
response = requests.get(f"{OLLAMA_URL}/api/tags")

# Logger
logger = logging.getLogger(__name__)


# ===== Ollama Tags / Cache =====
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://cab432-ollama:11434")from django.conf import settings
from django.contrib.auth import login

import pyotp
import qrcode
from io import BytesIO

from .models import Resume, JobApplication
from . import s3_utils
from app1.api_cache import test_api_tags

dynamodb = boto3.resource('dynamodb', region_name="ap-southeast-2")
table = dynamodb.Table("n11605618dynamo")

logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

COGNITO_REGION = "ap-southeast-2"
COGNITO_USER_POOL_ID = settings.COGNITO_USER_POOL_ID
COGNITO_ADMIN_GROUP = "admin"

AWS_BUCKET = "justinsinghatwalbucket"
AWS_REGION = "ap-southeast-2"


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

def get_secret_hash(username: str) -> str:
    """Compute Cognito secret hash for a given username."""
    """
    Compute the Cognito SECRET_HASH for a given username using the client secret.
    """
    message = username + CLIENT_ID
    dig = hmac.new(
        str(COGNITO_CLIENT_SECRET).encode("utf-8"),
        msg=message.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()
    sh = base64.b64encode(dig).decode()
    return sh


def is_cognito_admin(username):
    """Check if the Cognito user is in the 'Admin' group."""
    if not username:
        return False

    client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    try:
        resp = client.confirm_sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            ConfirmationCode=confirmation_code,
            SecretHash=get_secret_hash(username),
        )
        return resp
    except ClientError as e:
        return {"error": str(e)}

def cognito_initiate_auth(username, password):
    try:
        resp = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
                "SECRET_HASH": get_secret_hash(username),
            },
        )
        return resp
    except ClientError as e:
        return {"error": str(e)}

def cognito_forgot_password(username):
    try:
        resp = client.forgot_password(
            ClientId=CLIENT_ID,
            Username=username,
            SecretHash=get_secret_hash(username),
        )
        return resp
    except ClientError as e:
        return {"error": str(e)}

def cognito_confirm_forgot_password(username, confirmation_code, new_password):
    try:
        resp = client.confirm_forgot_password(
            ClientId=CLIENT_ID,
            Username=username,
            ConfirmationCode=confirmation_code,
            Password=new_password,
            SecretHash=get_secret_hash(username),
        )
        return resp
    except ClientError as e:
        return {"error": str(e)}

# ===== Cognito/Django User Helpers =====
def get_django_user_from_cognito(request):
    class UserObj:
        def __init__(self, username):
            self.username = username
    username = get_cognito_username(request)
    return UserObj(username) if username else None

def get_cognito_username(request):
    token = request.session.get("cognito_token")
    if not token:
        return None
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded.get("username") or decoded.get("cognito:username")
    except Exception:
        return None

def get_cognito_username(request):
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
        def wrapper(request, *args, **kwargs):
            token = request.session.get("cognito_token")
            if not token:
                return redirect("login")
            try:
                decoded = jwt.decode(token, options={"verify_signature": False})
                groups = decoded.get("cognito:groups", [])
                if group_name in groups:
                    return view_func(request, *args, **kwargs)
                else:
                    return redirect("unauthorized")
            except Exception:
                return redirect("login")
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

def mfa_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get("mfa_verified"):
            messages.warning(request, "You must complete MFA verification first.")
            return redirect("mfa_verify")
        return view_func(request, *args, **kwargs)
    return wrapper

# ===== MFA Views =====
@cognito_login_required
def mfa_setup_view(request):
    username = get_cognito_username(request)
    if not username:
        messages.error(request, "You must be logged in to set up MFA.")
        return redirect("login")
    secret = cache.get(f"mfa_secret_{username}")
    if not secret:
        secret = pyotp.random_base32()
        cache.set(f"mfa_secret_{username}", secret, timeout=3600)
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="CAB432App")
    qr = qrcode.make(uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
    buffer.close()
    return render(request, "mfa_setup.html", {"qr_code": qr_b64})

def mfa_verify_view(request):
    if request.method == "POST":
        code = request.POST.get("otp_code")
        username = request.session.get("username")
        challenge_name = request.session.get("challenge_name")
        session = request.session.get("cognito_session")
        if not code:
            messages.error(request, "Please enter the MFA code.")
            return render(request, "mfa_verify.html", {"challenge_type": challenge_name})
        try:
            response = client.respond_to_auth_challenge(
                ClientId=CLIENT_ID,
                ChallengeName=challenge_name,
                Session=session,
                ChallengeResponses={
                    'USERNAME': username,
                    'SECRET_HASH': get_secret_hash(username),
                    'SOFTWARE_TOKEN_MFA_CODE' if challenge_name=="SOFTWARE_TOKEN_MFA" else 'EMAIL_OTP_CODE': code
                }
            )
        except client.exceptions.CodeMismatchException:
            messages.error(request, "Invalid code. Please try again.")
            return render(request, "mfa_verify.html", {"challenge_type": challenge_name})
        except Exception as e:
            messages.error(request, f"Error: {str(e)}")
            return render(request, "mfa_verify.html", {"challenge_type": challenge_name})
        request.session['user'] = username
        return redirect("home")
    return render(request, "mfa_verify.html", {"challenge_type": request.session.get("challenge_name")})




def some_view(request):
    try:
        tags = test_api_tags()
    except Exception as e:
        tags = []
        print(f"[WARNING] test_api_tags failed: {e}")
    return render(request, "template.html", {"tags": tags})

# ==================================
# Main Views
# ==================================

@cognito_group_required()
@mfa_required
def home(request):
    django_user = get_django_user_from_cognito(request)
    return render(request, "home.html", {"username": django_user.username if django_user else "Guest"})


@cognito_group_required()
@mfa_required
def dashboard_view(request):
    return render(request, "dashboard.html")

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
        try:
            response = client.initiate_auth(
                ClientId=CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password,
                    'SECRET_HASH': get_secret_hash(username)
                }
            )
        except client.exceptions.NotAuthorizedException:
            messages.error(request, "Invalid username or password.")
            return render(request, "login.html")
        except Exception as e:
            messages.error(request, f"Error: {str(e)}")
            return render(request, "login.html")

        # Check if Cognito returned a challenge
        if response.get("ChallengeName"):
            challenge = response["ChallengeName"]
            request.session['cognito_session'] = response["Session"]
            request.session['username'] = username
            request.session['challenge_name'] = challenge

            if challenge == "SOFTWARE_TOKEN_MFA":
                return redirect("mfa_verify")
            elif challenge == "EMAIL_OTP":
                return redirect("email_otp_verify")
            else:
                messages.error(request, f"Unsupported challenge: {challenge}")
                return render(request, "login.html")

        # No challenge → login successful
        request.session['user'] = username
        return redirect("home")

    return render(request, "login.html")


def mfa_email_post(request):
    if request.method == "POST":
        otp_code = request.POST.get("otp")
        username = request.session.get("cognito_username")

        # Send OTP to Cognito
        resp = client.respond_to_auth_challenge(
            ClientId=CLIENT_ID,
            ChallengeName="EMAIL_OTP",
            Session=request.session.get("cognito_session"),
            ChallengeResponses={
                "USERNAME": username,
                "SECRET_HASH": get_secret_hash(username),
                "EMAIL_OTP_CODE": otp_code
            }
        )

        # If authentication successful, log the user into Django
        if "AuthenticationResult" in resp:
            user, created = User.objects.get_or_create(username=username)
            login(request, user)  # <--- this is key

            return redirect("home")  # or your home.html URL name
        
        messages.error(request, "Invalid OTP")
        return redirect("mfa_email")


def mfa_email(request):
    if request.method == "POST":
        otp_code = request.POST.get("otp")
        username = request.session.get("cognito_username")
        session_token = request.session.get("cognito_session")

        if not username or not session_token:
            messages.error(request, "Session expired. Please login again.")
            return redirect("login")

        try:
            response = client.respond_to_auth_challenge(
                ClientId=CLIENT_ID,
                ChallengeName="EMAIL_OTP",
                Session=session_token,
                ChallengeResponses={
                    "USERNAME": username,
                    "SECRET_HASH": get_secret_hash(username),
                    "EMAIL_OTP_CODE": otp_code
                }
            )

            if "AuthenticationResult" in response:
                # Create or get Django user
                user, created = User.objects.get_or_create(username=username)

                # Log user in
                login(request, user)

                # Clear session MFA data
                request.session.pop("cognito_username", None)
                request.session.pop("cognito_session", None)

                return redirect("home")  # replace with your home URL name

            else:
                messages.error(request, "MFA failed. Try again.")
                return redirect("mfa_email")

        except client.exceptions.NotAuthorizedException:
            messages.error(request, "Invalid OTP or credentials.")
            return redirect("mfa_email")

    # GET request
    return render(request, "mfa_email.html")

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





