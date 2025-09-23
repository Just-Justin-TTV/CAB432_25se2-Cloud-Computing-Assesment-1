from django.db import models
from django.contrib.auth.models import User
from uuid import uuid4

def original_resume_s3_path(instance, filename):
    return f"resumes/{instance.user.username}/{uuid4()}_{filename}"

def tailored_resume_s3_path(instance, filename):
    return f"resumes/tailored/{instance.user.username}_{filename}"

def feedback_s3_path(instance, filename):
    return f"feedback/{instance.user.username}_{filename}"

class Resume(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    s3_file_path = models.URLField(max_length=1024, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.s3_file_path}"

class JobApplication(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("processing", "Processing"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    resume = models.ForeignKey(Resume, on_delete=models.CASCADE)
    job_description = models.TextField()
    tailored_resume_s3_url = models.URLField(max_length=1024, blank=True, null=True)
    score = models.FloatField(null=True, blank=True)
    ai_model = models.CharField(max_length=50, default="mistral")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    error_message = models.TextField(null=True, blank=True)
    feedback = models.TextField(null=True, blank=True)
    feedback_s3_url = models.URLField(max_length=1024, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - Resume {self.resume.id} ({self.get_status_display()})"
from django.db import models
from django.contrib.auth.models import User
from uuid import uuid4

def original_resume_s3_path(instance, filename):
    return f"resumes/{instance.user.username}/{uuid4()}_{filename}"

def tailored_resume_s3_path(instance, filename):
    return f"resumes/tailored/{instance.user.username}_{filename}"

def feedback_s3_path(instance, filename):
    return f"feedback/{instance.user.username}_{filename}"

class Resume(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    s3_file_path = models.URLField(max_length=1024, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.s3_file_path}"

class JobApplication(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("processing", "Processing"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    resume = models.ForeignKey(Resume, on_delete=models.CASCADE)
    job_description = models.TextField()
    tailored_resume_s3_url = models.URLField(max_length=1024, blank=True, null=True)
    score = models.FloatField(null=True, blank=True)
    ai_model = models.CharField(max_length=50, default="mistral")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    error_message = models.TextField(null=True, blank=True)
    feedback = models.TextField(null=True, blank=True)
    feedback_s3_url = models.URLField(max_length=1024, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - Resume {self.resume.id} ({self.get_status_display()})"
