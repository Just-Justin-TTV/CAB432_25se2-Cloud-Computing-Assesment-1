# Standard library
import os, json, re, threading, hmac, hashlib, base64

# Django imports
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import logout as django_logout


# Local app imports
from .models import Resume, JobApplication
from .forms import ResumeUploadForm
from .aws_param_store import get_parameter

# Third-party imports
from docx import Document
from PyPDF2 import PdfReader
import requests
import boto3

from functools import wraps
from django.shortcuts import redirect

def get_cognito_username(request):
    """
    Returns the username stored in Cognito session.
    Returns None if user is not logged in.
    """
    user = request.session.get('cognito_user')
    return user.get('username') if user else None


# Custom decorator for Cognito session-based authentication
def cognito_login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if 'cognito_user' not in request.session:
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper

# ===== AWS Cognito Configuration =====
COGNITO_CLIENT_ID = get_parameter("/n12008192/assessment2/COGNITO_CLIENT_ID") \
                    or os.environ.get("COGNITO_CLIENT_ID", "")

COGNITO_CLIENT_SECRET = get_parameter("/n12008192/assessment2/COGNITO_CLIENT_SECRET") \
                        or os.environ.get("COGNITO_CLIENT_SECRET", "")

COGNITO_REGION = os.environ.get("COGNITO_REGION", "ap-southeast-2")

def secret_hash(username):
    message = bytes(username + COGNITO_CLIENT_ID, 'utf-8')
    key = bytes(COGNITO_CLIENT_SECRET, 'utf-8')
    return base64.b64encode(hmac.new(key, message, digestmod=hashlib.sha256).digest()).decode()

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
        print(f"Cognito authentication error: {e}")
        return None

def cognito_signup(username, password, email):
    client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    try:
        response = client.sign_up(
            ClientId=COGNITO_CLIENT_ID,
            Username=username,
            Password=password,
            SecretHash=secret_hash(username),
            UserAttributes=[{"Name": "email", "Value": email}]
        )
        return response
    except Exception as e:
        print(f"Cognito sign-up error: {e}")
        return None

def cognito_confirm_signup(username, confirmation_code):
    client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    try:
        response = client.confirm_sign_up(
            ClientId=COGNITO_CLIENT_ID,
            Username=username,
            ConfirmationCode=confirmation_code,
            SecretHash=secret_hash(username)
        )
        return response
    except Exception as e:
        print(f"Cognito confirmation error: {e}")
        return None

@csrf_exempt
def confirm_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        confirmation_code = request.POST.get("confirmation_code")

        response = cognito_confirm_signup(username, confirmation_code)
        if response:
            messages.success(request, "Confirmation successful! You can now log in.")
            return redirect("login")
        else:
            messages.error(request, "Invalid code or confirmation failed.")

    return render(request, "confirm.html")

def test_login(request):
    return render(request, "login.html", {"test": "ok"})

# ===== Authentication Views =====
def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if not username or not email or not password1 or not password2:
            messages.error(request, "All fields are required.")
            return render(request, 'register.html')

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return render(request, 'register.html')

        # Cognito sign-up
        signup_response = cognito_signup(username, password1, email)
        if not signup_response:
            messages.error(request, "Registration failed. Try again.")
            return render(request, 'register.html')

        
        messages.success(request, "Registration successful! Check your email to confirm.")
        return redirect('confirm')

    return render(request, 'register.html')


def login_view(request):
    # DO NOT redirect here on GET to avoid redirect loop
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        tokens = cognito_authenticate(username, password)
        if tokens:
            # Save JWTs in session
            request.session['cognito_user'] = {
                "username": username,
                "id_token": tokens.get("IdToken"),
                "access_token": tokens.get("AccessToken"),
                "refresh_token": tokens.get("RefreshToken")
            }
            messages.success(request, "Login successful!")
            return redirect('home')
        else:
            messages.error(request, "Invalid username or password.")

    return render(request, 'login.html')



@login_required(login_url='/login/')
def logout_view(request):
    # Remove Cognito session
    request.session.pop('cognito_user', None)
    request.session.flush()
    messages.success(request, "Logged out successfully.")
    return redirect('login')



# ===== Pages =====
@cognito_login_required
def home(request):
    return render(request, 'home.html')


@cognito_login_required
def dashboard_view(request):
    username = get_cognito_username(request)
    job_applications = JobApplication.objects.select_related('user', 'resume').order_by('-created_at')
    return render(request, 'dashboard.html', {'job_applications': job_applications})


# ===== Resume Helper =====
def read_resume_text(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    text = ""
    if ext == ".txt":
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    elif ext == ".docx":
        doc = Document(file_path)
        text = "\n".join([p.text for p in doc.paragraphs])
    elif ext == ".pdf":
        reader = PdfReader(file_path)
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"
    return text


# ===== Resume Upload =====
@cognito_login_required
def upload_resume(request):
    username = get_cognito_username(request)
    if request.method == "POST":
        form = ResumeUploadForm(request.POST, request.FILES)
        if form.is_valid():
            resume = form.save(commit=False)
            resume.user = request.user
            resume.save()
            return redirect('match_resume_to_job', resume_id=resume.id)
    else:
        form = ResumeUploadForm()
    return render(request, 'resume/upload.html', {'form': form})


# ===== View Job Application =====
@cognito_login_required
def view_job_application(request, job_app_id):
    username = get_cognito_username(request)
    job_app = get_object_or_404(JobApplication, id=job_app_id)
    return render(request, 'resume/view_job_application.html', {'job_app': job_app})


@csrf_exempt
@cognito_login_required
def match_resume_to_job(request, resume_id):
    username = get_cognito_username(request)
    resume = get_object_or_404(Resume, id=resume_id, user=request.user)

    if request.method == "POST":
        job_position = request.POST.get("job_position")
        if not job_position:
            messages.error(request, "Please enter a job position.")
            return redirect("match_resume_to_job", resume_id=resume.id)

        try:
            resume_text = read_resume_text(resume.original_file.path)
            prompt = f"""
            You are a highly intelligent assistant that evaluates resumes against job positions in extreme detail.
            Consider every possible factor that could make a candidate suitable or unsuitable:
            - Skills (technical, soft, and transferable)
            - Experience (roles, achievements, relevance)
            - Education (degrees, certifications, coursework)
            - Projects and portfolio work
            - Language proficiency
            - Keywords alignment with the job description
            - Overall candidate fit

            Job Position: {job_position}
            Resume Text: {resume_text}

            Provide an extremely detailed analysis. Return JSON ONLY with keys:
            - score (0–100)
            - additional_scores (optional, multiple sub-scores like technical, soft skills, education)
            - feedback (detailed explanation why it scored that way)
            """
            ollama_host = os.environ.get("OLLAMA_HOST", "http://cab432-ollama:11434")

            results = []
            def ai_worker():
                for _ in range(2):
                    response = requests.post(
                        f"{ollama_host}/api/generate",
                        json={"model": "mistral", "prompt": prompt, "stream": False},
                        timeout=600,
                    )
                    response.raise_for_status()
                    data = response.json()
                    results.append(data.get("response", ""))

            threads = []
            for _ in range(2):
                t = threading.Thread(target=ai_worker)
                t.start()
                threads.append(t)

            for t in threads:
                t.join()

            ai_text = next((r for r in results if r), "")
            score, feedback = 50, ""

            if ai_text:
                try:
                    json_match = re.search(r"\{.*\}", ai_text, re.DOTALL)
                    parsed = json.loads(json_match.group(0)) if json_match else json.loads(ai_text)
                    score = parsed.get("score", 50)
                    feedback = parsed.get("feedback", "")
                    if isinstance(feedback, dict):
                        feedback = json.dumps(feedback, indent=4)
                    else:
                        feedback = str(feedback)
                except Exception as e:
                    feedback = f"⚠ JSON parsing failed: {e}\n\nRaw output:\n{ai_text}"

            feedback_path = os.path.join(settings.MEDIA_ROOT, "feedback")
            os.makedirs(feedback_path, exist_ok=True)
            feedback_filename = f"{request.user.username}_resume_{resume.id}_feedback.txt"
            feedback_file_path = os.path.join(feedback_path, feedback_filename)
            with open(feedback_file_path, "w", encoding="utf-8") as f:
                if isinstance(feedback, dict):
                    f.write(json.dumps(feedback, indent=4))
                else:
                    f.write(str(feedback))

            job_app = JobApplication.objects.create(
                user=request.user,
                resume=resume,
                job_description=job_position,
                ai_model="mistral",
                score=float(score)/100.0,
                status="completed",
                error_message=None,
                feedback=feedback
            )

            messages.success(request, f"Match analysis complete! Score: {score}")
            return redirect("view_job_application", job_app_id=job_app.id)

        except Exception as e:
            messages.error(request, f"AI processing failed: {e}")
            return redirect("match_resume_to_job", resume_id=resume.id)

    return render(request, "resume/match.html", {"resume": resume})


@cognito_login_required
def job_application_detail(request, pk):
    job_app = get_object_or_404(JobApplication, pk=pk, user=request.user)
    return render(request, "resume/job_application_detail.html", {"job_app": job_app})
