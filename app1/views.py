from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from .models import Resume, JobApplication
from .forms import ResumeUploadForm
import os, json, re
from django.conf import settings
from docx import Document
from PyPDF2 import PdfReader
import requests
from django.views.decorators.csrf import csrf_exempt
import threading
import time

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

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return render(request, 'register.html')
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return render(request, 'register.html')

        user = User.objects.create_user(username=username, email=email, password=password1)
        login(request, user)
        messages.success(request, "Registration successful!")
        return redirect('home')

    return render(request, 'register.html')


def login_view(request):
    if request.user.is_authenticated:
        return redirect('home') 

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, "Invalid username or password.")
    return render(request, 'login.html')


@login_required(login_url='/login/')
def logout_view(request):
    logout(request)
    messages.success(request, "Logged out successfully.")
    return redirect('login')


# ===== Pages =====
@login_required(login_url='/login/')
def home(request):
    return render(request, 'home.html')


@login_required(login_url='/login/')
def dashboard_view(request):
    # Get all job applications, newest first
    job_applications = JobApplication.objects.select_related('user', 'resume').order_by('-created_at')

    return render(request, 'dashboard.html', {
        'job_applications': job_applications
    })



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
@login_required(login_url='/login/')
def upload_resume(request):
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
@login_required(login_url='/login/')
def view_job_application(request, job_app_id):
    job_app = get_object_or_404(JobApplication, id=job_app_id)
    return render(request, 'resume/view_job_application.html', {'job_app': job_app})



@csrf_exempt
@login_required(login_url='/login/')
def match_resume_to_job(request, resume_id):
    resume = get_object_or_404(Resume, id=resume_id, user=request.user)

    if request.method == "POST":
        job_position = request.POST.get("job_position")
        if not job_position:
            messages.error(request, "Please enter a job position.")
            return redirect("match_resume_to_job", resume_id=resume.id)

        try:
            resume_text = read_resume_text(resume.original_file.path)

            # ===== Bigger, more detailed prompt =====
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

            # ===== CPU-Intensive Parallel Threads =====
            results = []
            def ai_worker():
                for _ in range(1):
                    response = requests.post(
                        f"{ollama_host}/api/generate",
                        json={"model": "mistral", "prompt": prompt, "stream": False},
                        timeout=600,
                    )
                    response.raise_for_status()
                    data = response.json()
                    results.append(data.get("response", ""))

            threads = []
            num_threads = 1
            for _ in range(num_threads):
                t = threading.Thread(target=ai_worker)
                t.start()
                threads.append(t)

            for t in threads:
                t.join()

            # Process combined results from threads
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

            # Save feedback to a file
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




@login_required(login_url='/login/')
def job_application_detail(request, pk):
    job_app = get_object_or_404(JobApplication, pk=pk, user=request.user)
    return render(request, "resume/job_application_detail.html", {"job_app": job_app})
