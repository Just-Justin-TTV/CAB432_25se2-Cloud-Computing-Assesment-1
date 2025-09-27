

# ----------------------------
# RDS (PostgreSQL) Functions
# ----------------------------

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": DB_NAME,
        "USER": DB_USER,
        "PASSWORD": DB_PASSWORD,
        "HOST": DB_HOST,
        "PORT": DB_PORT,
        "OPTIONS": {"sslmode": "require"},
    }
}

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

@cognito_group_required("admin")
def admin_dashboard_view(request):
    """Render admin dashboard showing all job applications."""
    if not request.user.is_authenticated:
        return redirect('login')

    job_applications = JobApplication.objects.all().select_related('resume')
    return render(request, 'admin_dashboard.html', {
        'job_applications': job_applications,
    })

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


