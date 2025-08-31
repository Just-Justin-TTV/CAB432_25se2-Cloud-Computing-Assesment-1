from django.contrib import admin
from django.urls import path, include
from app1 import views

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),

    # Authentication
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),

    # Main pages
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard_view, name='dashboard'),

    # Resume URLs
    path('resume/upload/', views.upload_resume, name='upload_resume'),
    path('resume/<int:resume_id>/match/', views.match_resume_to_job, name='match_resume_to_job'),
    path('resume/<int:job_app_id>/view/', views.view_job_application, name='view_job_application'),

    # Job application detail
    path('job_app/<int:pk>/', views.job_application_detail, name='job_application_detail'),

    # Django Browser Reload (development only)
    path("__reload__/", include("django_browser_reload.urls")),
]
