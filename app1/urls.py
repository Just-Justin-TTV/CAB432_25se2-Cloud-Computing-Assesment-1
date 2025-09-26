from django.contrib import admin
from django.urls import path, include
from app1 import views

urlpatterns = [
    path('admin/', admin.site.urls),

    # Auth
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
    path('confirm/', views.confirm_view, name='confirm'),
    path('test-login/', views.test_login, name='test_login'),

    # Home / Dashboard
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('admin-dashboard/', views.admin_dashboard_view, name='admin_dashboard'),

    # Resume
    path('resume/upload/', views.upload_resume, name='upload_resume'),
    path('resume/<int:resume_id>/match/', views.match_resume_to_job, name='match_resume_to_job'),
    path('resume/<int:job_app_id>/view/', views.view_job_application, name='view_job_application'),
    path('resume/get_presigned_url/', views.get_presigned_url, name='get_presigned_url'),
    path('resume/confirm_upload/', views.confirm_upload, name='confirm_upload'),
    path('resume/download_file/', views.download_file, name='download_file'),

    # Progress APIs
    path('api/progress/<str:user_id>/', views.get_resume_progress, name='resume_progress'),
    path('api/progress/<str:user_id>/<str:task_name>/', views.get_progress, name='get_progress'),
    path('task-progress/<int:task_id>/', views.task_progress_api, name='task_progress_api'),

    # Job application detail
    path('job_app/<int:pk>/', views.job_application_detail, name='job_application_detail'),

    # Browser reload (dev only)
    path("__reload__/", include("django_browser_reload.urls")),
]
