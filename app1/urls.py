from django.contrib import admin  
from django.urls import path, include
from app1 import views

urlpatterns = [
    # Admin site
    path('admin/', admin.site.urls),

    # Auth
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
    path('confirm/', views.confirm_view, name='confirm'),
    path('test-login/', views.test_login, name='test_login'),

    # MFA
    path("mfa/setup/", views.mfa_setup_view, name="mfa_setup"),
    path("mfa/verify/", views.mfa_verify_view, name="mfa_verify"),

    # Home and dashboard
    path('', views.home, name='home'),                           # Home page (any logged-in user)
    path('dashboard/', views.dashboard_view, name='dashboard'),  # User dashboard
    path('admin-dashboard/', views.admin_dashboard_view, name='admin_dashboard'),  # Admin-only dashboard

    # Resume management
    path('resume/upload/', views.upload_resume, name='upload_resume'),                        # Resume upload page
    path('resume/<int:resume_id>/match/', views.match_resume_to_job, name='match_resume_to_job'),  # Match resume to job using AI
    path('resume/<int:job_app_id>/view/', views.view_job_application, name='view_job_application'),  # View individual job application
    path('resume/get_presigned_url/', views.get_presigned_url, name='get_presigned_url'),      # Get S3 presigned upload URL
    path('resume/confirm_upload/', views.confirm_upload, name='confirm_upload'),              # Confirm resume upload
    path('resume/download_file/', views.download_file, name='download_file'),                 # Download resume or feedback file

    # Progress APIs
    path('api/progress/<str:username>/', views.get_resume_progress, name='resume_progress'),             # Get overall resume processing progress
    path('api/progress/<str:username>/<str:task_name>/', views.get_progress, name='get_progress'),      # Get specific task progress
    path('task-progress/<str:task_name>/', views.task_progress_api, name='task_progress_api'),          # API endpoint for frontend polling of task progress

    # Job application detail
    path('job_app/<int:pk>/', views.job_application_detail, name='job_application_detail'),
    path('mfa_verify/', views.mfa_verify_view, name='otp_verify'),  # <-- add this
    path("mfa/email/", views.mfa_verify_view, name="email_otp_verify"),

    path("mfa/software/", views.mfa_verify_view, name="mfa_verify"),

    # Browser reload (development only)
    path("__reload__/", include("django_browser_reload.urls")),  # Live-reload for frontend development
]
