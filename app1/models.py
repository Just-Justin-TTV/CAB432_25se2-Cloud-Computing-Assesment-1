from django.db import models
from django.contrib.auth.models import User
import os

# Functions to determine file upload paths
def original_resume_upload_path(instance, filename):
    # Save directly under 'resumes/' with username prefix
    return os.path.join("resumes", f"{instance.user.username}_{filename}")

def tailored_resume_upload_path(instance, filename):
    return os.path.join("resumes", "tailored", f"{instance.user.username}_{filename}")

def feedback_upload_path(instance, filename):
    return os.path.join("feedback", f"{instance.user.username}_{filename}")

# Model representing a user's uploaded resume
class Resume(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    original_file = models.FileField(upload_to=original_resume_upload_path)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.original_file.name}"

# Model representing a job application using a resume
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
    tailored_resume_file = models.FileField(
        upload_to=tailored_resume_upload_path, null=True, blank=True
    )
    score = models.FloatField(null=True, blank=True)
    ai_model = models.CharField(
        max_length=50, default="mistral", help_text="The Ollama model used"
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    error_message = models.TextField(null=True, blank=True)
    feedback = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.resume.original_file.name} for job ({self.get_status_display()})"
