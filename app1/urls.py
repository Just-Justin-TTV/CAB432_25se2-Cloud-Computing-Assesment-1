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

    # Resume
    path('resume/upload/', views.upload_resume, name='upload_resume'),
    path('resume/<int:resume_id>/match/', views.match_resume_to_job, name='match_resume_to_job'),
    path('resume/<int:job_app_id>/view/', views.view_job_application, name='view_job_application'),
    path('resume/get_presigned_url/', views.get_presigned_url, name='get_presigned_url'),
    path('resume/confirm_upload/', views.confirm_upload, name='confirm_upload'),
    path('resume/download_file/', views.download_file, name='download_file'),  # <--- added
    path('unauthorized/', views.unauthorized, name='unauthorized'),

    

    # Job application detail
    path('job_app/<int:pk>/', views.job_application_detail, name='job_application_detail'),
    path('admin_dashboard/', views.admin_dashboard_view, name='admin_dashboard'),


    # Browser reload (dev)
    path("__reload__/", include("django_browser_reload.urls")),
]
