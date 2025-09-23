import os
import base64
import hmac
from functools import wraps

import boto3
import jwt
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
from django.views.decorators.clickjacking import xframe_options_exempt
import logging
from django.contrib.auth import login as django_login
from .models import JobApplication
import boto3
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, get_user_model
from django.views.decorators.csrf import csrf_exempt
import json
from uuid import uuid4
from django.http import JsonResponse



logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

# ===== Cognito / AWS Setup =====
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
COGNITO_CLIENT_SECRET = os.environ.get("COGNITO_CLIENT_SECRET", "")
COGNITO_REGION = os.environ.get("COGNITO_REGION", "ap-southeast-2")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")

AWS_PROFILE = "CAB432-STUDENT"
AWS_REGION = "ap-southeast-2"
AWS_BUCKET = "justinsinghatwalbucket"

User = get_user_model()

def secret_hash(username):
    if not COGNITO_CLIENT_SECRET:
        return None
    msg = username + COGNITO_CLIENT_ID
    dig = hmac.new(
        str(COGNITO_CLIENT_SECRET).encode("utf-8"),
        msg.encode("utf-8"),
        digestmod="sha256"
    ).digest()
    sh = base64.b64encode(dig).decode()
    logging.debug(f"Secret hash for {username}: {sh}")
    return sh

def is_cognito_admin(username):
    """
    Checks if a Cognito user is in the 'Admin' group.
    """
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
    except Exception as e:
        print(f"[ERROR] Failed to check admin status for {username}: {e}")
        return False


def cognito_authenticate(username, password):
    """
    Authenticate a user with Cognito using USER_PASSWORD_AUTH.
    Returns AuthenticationResult dict on success, None on failure.
    """
    logging.debug(f"Attempting login for user: {username}")
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
        logging.debug(f"Cognito full response: {response}")

        if "ChallengeName" in response:
            logging.warning(f"Login challenge for {username}: {response['ChallengeName']}")
            # You may handle NEW_PASSWORD_REQUIRED or other challenges here
            return None

        auth_result = response.get("AuthenticationResult")
        logging.debug(f"Auth result: {auth_result}")
        return auth_result

    except client.exceptions.NotAuthorizedException as e:
        logging.error(f"Login failed (NotAuthorizedException) for {username}: {e}")
    except client.exceptions.UserNotFoundException as e:
        logging.error(f"Login failed (UserNotFoundException) for {username}: {e}")
    except Exception as e:
        logging.error(f"Login failed (Other) for {username}: {e}")
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
    except Exception as e:
        print(f"[ERROR] Cognito confirmation failed: {e}")
        return None

# ===== Forgot Password / Reset =====
def cognito_send_reset_code(username):
    client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    kwargs = {"ClientId": COGNITO_CLIENT_ID, "Username": username}
    sh = secret_hash(username)
    if sh:
        kwargs["SecretHash"] = sh
    try:
        return client.forgot_password(**kwargs)
    except Exception as e:
        print(f"[ERROR] Sending reset code failed: {e}")
        return None

def cognito_confirm_reset(username, code, new_password):
    """
    Confirm password reset in Cognito and optionally login the user.
    """
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
        logging.info(f"Password reset confirmed for {username}")
        # Try auto-login after reset
        return cognito_authenticate(username, new_password)
    except Exception as e:
        logging.error(f"Confirm reset failed for {username}: {e}")
        return None

# ===== Cognito / Django User Helper =====
def get_django_user_from_cognito(request):
    """
    Given a request with a Cognito session, return the corresponding Django User object.
    """
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
    user = request.session.get('cognito_user')
    return user.get('username') if user else None

def sync_cognito_user_to_django(request):
    """
    Sync the Cognito user session to a Django User and log them in.
    """
    from django.contrib.auth import get_user_model
    User = get_user_model()
    cognito_user = request.session.get("cognito_user")
    if not cognito_user:
        logging.debug("No cognito_user in session.")
        return None

    username = cognito_user.get("username")
    logging.debug(f"Syncing Cognito user: {username}")

    # Get Cognito groups
    client = boto3.client('cognito-idp', region_name=COGNITO_REGION)
    try:
        response = client.admin_list_groups_for_user(
            Username=username,
            UserPoolId=COGNITO_USER_POOL_ID
        )
        groups = [g['GroupName'] for g in response.get("Groups", [])]
        logging.debug(f"Cognito groups for {username}: {groups}")
    except Exception as e:
        logging.error(f"Failed to fetch Cognito groups for {username}: {e}")
        groups = []

    # Create or update Django user
    user, created = User.objects.get_or_create(username=username)
    user.is_staff = 'admin' in [g.lower() for g in groups]
    user.is_superuser = 'admin' in [g.lower() for g in groups]
    user.save()
    logging.debug(f"Django user flags for {username}: is_staff={user.is_staff}, is_superuser={user.is_superuser}")

    # Log user in
    login(request, user)
    logging.info(f"User {username} synced and logged in. Created new Django user? {created}")
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

def cognito_group_required(group_name=None):
    """
    Decorator to allow Cognito users in a specific group.
    If group_name is None, any logged-in user is allowed.
    """
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
            except Exception as e:
                print(f"[ERROR] Token decoding failed: {e}")
                return redirect("login")
        return _wrapped_view
    return decorator


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

@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        client = boto3.client('cognito-idp', region_name=COGNITO_REGION)

        try:
            # Authenticate user with Cognito
            response = client.initiate_auth(
                ClientId=COGNITO_CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password
                }
            )

            # If authentication succeeds
            auth_result = response.get('AuthenticationResult')
            if auth_result:
                access_token = auth_result.get('AccessToken')
                id_token = auth_result.get('IdToken')
                refresh_token = auth_result.get('RefreshToken')

                # Get or create a corresponding Django user
                user, created = User.objects.get_or_create(username=username)
                # Optionally, you can update user details here from Cognito claims

                # Log the user in (Django session)
                login(request, user)

                messages.success(request, f'Welcome, {username}!')
                return redirect('dashboard')  # Replace with your dashboard URL

        except client.exceptions.NotAuthorizedException:
            messages.error(request, 'Invalid username or password.')
        except client.exceptions.UserNotFoundException:
            messages.error(request, 'User does not exist.')
        except Exception as e:
            messages.error(request, f'Login error: {str(e)}')

    return render(request, 'login.html')



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
    client = boto3.client('cognito-idp', region_name=COGNITO_REGION)

    try:
        response = client.admin_list_groups_for_user(
            Username=username,
            UserPoolId=COGNITO_USER_POOL_ID
        )
        groups = [g['GroupName'] for g in response.get('Groups', [])]
        is_admin = 'admin' in [g.lower() for g in groups]
        logging.debug(f"Cognito groups: {groups}, is_admin={is_admin}")
    except Exception as e:
        logging.error(f"Failed to fetch groups for {username}: {e}")
        is_admin = False

    django_user = get_django_user_from_cognito(request)
    logging.debug(f"Django user: {django_user}")
    job_applications = JobApplication.objects.filter(user=django_user).select_related('resume') if django_user else []

    return render(request, 'dashboard.html', {
        'is_admin': is_admin,
        'job_applications': job_applications,
    })




@cognito_group_required("admin")  # match the exact Cognito group name
def admin_dashboard_view(request):
    logging.debug(f"Accessing admin dashboard: request.user={request.user}")
    if not request.user.is_authenticated:
        logging.warning("User not authenticated.")
        return redirect('login')

    logging.debug(f"User flags: is_staff={request.user.is_staff}, is_superuser={request.user.is_superuser}")
    if not request.user.is_staff:
        logging.warning("User is not staff. Redirecting to login.")
        return redirect('login')

    return render(request, 'admin_dashboard.html')




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
@cognito_login_required
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
@cognito_login_required

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



