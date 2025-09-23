import os, json, re, io, base64, hmac
from functools import wraps
from uuid import uuid4
import time

import boto3
from botocore.exceptions import ClientError
import requests
from docx import Document
from PyPDF2 import PdfReader

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.conf import settings

from .models import Resume, JobApplication
from . import s3_utils

# ===== AWS / S3 Setup =====
AWS_PROFILE = "CAB432-STUDENT"
AWS_REGION = "ap-southeast-2"
AWS_BUCKET = "justinsinghatwalbucket"

# ===== Cognito Setup =====
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
COGNITO_CLIENT_SECRET = os.environ.get("COGNITO_CLIENT_SECRET", "")
COGNITO_REGION = os.environ.get("COGNITO_REGION", "ap-southeast-2")

def secret_hash(username):
    message = bytes(username + COGNITO_CLIENT_ID, 'utf-8')
    key = bytes(COGNITO_CLIENT_SECRET, 'utf-8')
    return base64.b64encode(hmac.new(key, message, digestmod='sha256').digest()).decode()

def cognito_authenticate(username, password):
    client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    try:
        response = client.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
                "SECRET_HASH": secret_hash(username)
            },
            ClientId=COGNITO_CLIENT_ID
        )
        return response.get("AuthenticationResult")
    except Exception as e:
        print(f"[ERROR] Cognito authentication failed: {e}")
        return None

def cognito_signup(username, password, email):
    client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    try:
        return client.sign_up(
            ClientId=COGNITO_CLIENT_ID,
            Username=username,
            Password=password,
            SecretHash=secret_hash(username),
            UserAttributes=[{"Name": "email", "Value": email}]
        )
    except Exception as e:
        print(f"[ERROR] Cognito sign-up failed: {e}")
        return None

def cognito_confirm_signup(username, confirmation_code):
    client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    try:
        return client.confirm_sign_up(
            ClientId=COGNITO_CLIENT_ID,
            Username=username,
            ConfirmationCode=confirmation_code,
            SecretHash=secret_hash(username)
        )
    except Exception as e:
        print(f"[ERROR] Cognito confirmation failed: {e}")
        return None

def get_cognito_username(request):
    user = request.session.get('cognito_user')
    return user.get('username') if user else None

def get_django_user_from_cognito(request):
    username = get_cognito_username(request)
    if not username:
        return None
    User = get_user_model()
    user, _ = User.objects.get_or_create(username=username)
    return user

# ===== Login Decorators =====
def cognito_login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if 'cognito_user' not in request.session:
            messages.warning(request, "Please log in first.")
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper

def api_login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if 'cognito_user' not in request.session:
            return JsonResponse({"error": "Authentication required"}, status=401)
        return view_func(request, *args, **kwargs)
    return wrapper

# ===== Views (Login / Register / Logout / Home / Dashboard) =====
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

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        tokens = cognito_authenticate(username, password)
        if tokens:
            request.session['cognito_user'] = {
                "username": username,
                "id_token": tokens.get("IdToken"),
                "access_token": tokens.get("AccessToken"),
                "refresh_token": tokens.get("RefreshToken")
            }
            messages.success(request, "Login successful!")
            return redirect('home')
        messages.error(request, "Invalid username or password.")
    return render(request, 'login.html')

@login_required(login_url='/login/')
def logout_view(request):
    request.session.pop('cognito_user', None)
    request.session.flush()
    messages.success(request, "Logged out successfully.")
    return redirect("login")

@cognito_login_required
def home(request):
    return render(request, 'home.html')

@cognito_login_required
def dashboard_view(request):
    apps = JobApplication.objects.select_related('user', 'resume').order_by('-created_at')
    return render(request, 'dashboard.html', {'job_applications': apps})

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
@api_login_required
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
@api_login_required
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

# ===== Retry Logic for Ollama =====
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

# ===== Match Resume to Job =====
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

# ===== Tailored Resume Upload =====
@cognito_login_required
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

# ===== Job Application Views =====
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

# ===== Test Login Page =====
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
