import os
import json
import re
import io
import time
import base64
import hmac
import hashlib
from functools import wraps
from uuid import uuid4
import logging

import boto3
from botocore.exceptions import ClientError
import jwt
import requests
from docx import Document
from PyPDF2 import PdfReader

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login as django_login, get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
from django.views.decorators.clickjacking import xframe_options_exempt
from django.http import JsonResponse
from django.contrib.auth import login
from django.core.cache import cache
from django.conf import settings
from django.contrib.auth import login

import pyotp
import qrcode
from io import BytesIO

from .models import Resume, JobApplication
from . import s3_utils
from .api_cache import test_api_tags

# Cognito client setup
client = boto3.client('cognito-idp', region_name='ap-southeast-2')
CLIENT_ID = settings.COGNITO_CLIENT_ID
COGNITO_CLIENT_SECRET = settings.COGNITO_CLIENT_SECRET

logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

COGNITO_REGION = "ap-southeast-2"
COGNITO_USER_POOL_ID = settings.COGNITO_USER_POOL_ID
COGNITO_ADMIN_GROUP = "admin"

AWS_BUCKET = "justinsinghatwalbucket"
AWS_REGION = "ap-southeast-2"

User = get_user_model()

def get_secret_hash(username: str) -> str:
    """
    Compute the Cognito SECRET_HASH for a given username using the client secret.
    """
    message = username + CLIENT_ID
    dig = hmac.new(
        str(COGNITO_CLIENT_SECRET).encode("utf-8"),
        msg=message.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()
    return base64.b64encode(dig).decode()

# ===== Cognito Signup/Login =====
def cognito_signup(username, password, email):
    try:
        resp = client.sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            Password=password,
            SecretHash=get_secret_hash(username),
            UserAttributes=[{"Name": "email", "Value": email}],
        )
        return resp
    except ClientError as e:
        return {"error": str(e)}

def cognito_confirm_signup(username, confirmation_code):
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

def sync_cognito_user_to_django(request):
    User = get_user_model()
    cognito_user = request.session.get("cognito_user")
    if not cognito_user:
        logging.debug("No cognito_user in session.")
        return None
    username = cognito_user.get("username")
    client = boto3.client('cognito-idp', region_name=COGNITO_REGION)
    try:
        response = client.admin_list_groups_for_user(
            Username=username,
            UserPoolId=COGNITO_USER_POOL_ID
        )
        groups = [g['GroupName'] for g in response.get("Groups", [])]
    except Exception as e:
        logging.error(f"Failed to fetch groups for {username}: {e}")
        groups = []
    user, created = User.objects.get_or_create(username=username)
    user.is_staff = 'admin' in [g.lower() for g in groups]
    user.is_superuser = 'admin' in [g.lower() for g in groups]
    user.save()
    login(request, user)
    return user

# ===== Decorators =====
def cognito_login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if 'cognito_user' not in request.session:
            messages.warning(request, "Please log in first.")
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper

def cognito_group_required(required_group="user"):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            token = request.session.get("cognito_token")
            if not token:
                return redirect("login")
            try:
                decoded = jwt.decode(token, options={"verify_signature": False})
                groups = decoded.get("cognito:groups", [])
                if required_group not in groups:
                    messages.error(request, "Access denied.")
                    return redirect("login")
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
    return render(request, 'unauthorized.html', status=401)

def register_view(request):
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
    if request.method == "POST":
        username = request.POST.get("username")
        code = request.POST.get("confirmation_code")
        if cognito_confirm_signup(username, code):
            messages.success(request, "Confirmation successful! You can now log in.")
            return redirect("login")
        else:
            messages.error(request, "Confirmation failed.")
    return render(request, "confirm.html")

def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

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
                SecretHash=secret_hash(username)  # <-- added SecretHash
            )
            messages.success(request, "Password reset successful! You can now log in.")
            return redirect("login")
        except Exception as e:
            messages.error(request, f"Password reset failed: {str(e)}")
            return redirect("reset_password_confirm")

    return render(request, "reset_password_confirm.html")





@cognito_login_required
def logout_view(request):
    request.session.pop('cognito_user', None)
    request.session.flush()
    messages.success(request, "Logged out successfully.")
    return redirect("login")



# ===== Dashboard / Admin using Cognito only =====
@cognito_login_required
def dashboard_view(request):
    username = get_cognito_username(request)
    logging.debug(f"Dashboard accessed by username={username}")

    django_user = get_django_user_from_cognito(request)
    logging.debug(f"Django user: {django_user}")

    # Regular dashboard shows only user's own entries, regardless of admin status
    if django_user is None:
        job_applications = JobApplication.objects.none()
        logging.warning("No Django user found. Returning empty queryset.")
    else:
        job_applications = JobApplication.objects.filter(user=django_user).select_related('resume')

    logging.debug(f"Job applications returned: {job_applications.count()}")
    
    # Check admin group just to display the "Admin Dashboard" link
    client = boto3.client('cognito-idp', region_name=COGNITO_REGION)
    try:
        response = client.admin_list_groups_for_user(
            Username=username,
            UserPoolId=COGNITO_USER_POOL_ID
        )
        groups = [g['GroupName'].lower() for g in response.get('Groups', [])]
        is_admin = 'admin' in groups
    except Exception as e:
        logging.error(f"Failed to fetch groups for {username}: {e}")
        is_admin = False

    return render(request, 'dashboard.html', {
        'is_admin': is_admin,  # only for showing the admin link
        'job_applications': job_applications,
    })




@cognito_group_required("admin")
def admin_dashboard_view(request):
    logging.debug(f"Accessing admin dashboard: request.user={request.user}")
    if not request.user.is_authenticated:
        logging.warning("User not authenticated.")
        return redirect('login')

    job_applications = JobApplication.objects.all().select_related('resume')
    return render(request, 'admin_dashboard.html', {
        'job_applications': job_applications,
    })




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

# ===== Resume Upload / Confirm =====
@cognito_login_required
def upload_resume(request):
    return render(request, 'resume/upload.html')

@csrf_exempt
def get_presigned_url(request):
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
        
        # Return download & match URLs for frontend
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
    key = request.GET.get("key")
    if not key:
        messages.error(request, "No file specified for download.")
        return redirect("dashboard")
    try:
        url = s3_utils.get_presigned_download_url(key)
        return redirect(url)
    except Exception as e:
        print(f"[ERROR] Download failed: {e}")
        messages.error(request, f"Download failed: {e}")
        return redirect("dashboard")

# ===== Ollama / AI Matching =====
def call_ollama(payload, retries=10, delay=3):
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

@csrf_exempt
@cognito_login_required
def match_resume_to_job(request, resume_id):
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
            You are a highly intelligent assistant that evaluates resumes against job positions in extreme detail.
            Job Position: {job_position}
            Resume Text: {resume_text}

            Return JSON with keys: score, feedback
            """
            payload = {"model": "gemma:2b", "prompt": prompt, "stream": False}
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
            ai_model="gemma:2b",
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

def upload_tailored_resume(request, job_app_id):
    django_user = get_django_user_from_cognito(request)
    job_app = get_object_or_404(JobApplication, id=job_app_id, user=django_user)
    if request.method == "POST" and request.FILES.get("tailored_resume"):
        file_obj = request.FILES["tailored_resume"]
        key = f"resumes/tailored/{job_app.user.username}/{uuid4()}_{file_obj.name}"
        try:
            file_bytes = file_obj.read()
            if not file_bytes:
                raise Exception("Uploaded file is empty!")
            s3_url = s3_utils.upload_file_to_s3(file_bytes, key)
            job_app.tailored_resume_s3_url = s3_url
            job_app.save(update_fields=["tailored_resume_s3_url"])
            messages.success(request, "Tailored resume uploaded successfully!")
        except Exception as e:
            print(f"[ERROR] Tailored resume upload failed: {e}")
            messages.error(request, f"Failed to upload tailored resume: {e}")
    return redirect("job_application_detail", pk=job_app.id)

@cognito_login_required
def view_job_application(request, job_app_id):
    django_user = get_django_user_from_cognito(request)
    job_app = get_object_or_404(JobApplication, id=job_app_id, user=django_user)
    return render(request, 'resume/view_job_application.html', {'job_app': job_app})

@cognito_login_required
def job_application_detail(request, pk):
    django_user = get_django_user_from_cognito(request)
    job_app = get_object_or_404(JobApplication, pk=pk, user=django_user)
    return render(request, "resume/job_application_detail.html", {"job_app": job_app})

def test_login(request):
    return render(request, "login.html", {"test": "ok"})

def wait_for_ollama(timeout=60):
    url = f"{os.environ.get('OLLAMA_HOST', 'http://ollama:11434')}/api/tags"
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                print("[INFO] Ollama is ready!")
                return True
        except requests.exceptions.RequestException:
            time.sleep(2)
    raise Exception("Ollama not available after waiting.")

# ===== Home View Restricted to 'User' Group =====
# ===== Home View (any logged-in user) =====
@cognito_group_required()  # no group restriction
def home(request):
    django_user = get_django_user_from_cognito(request)
    return render(request, "home.html", {"username": django_user.username if django_user else "Guest"})


