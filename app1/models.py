from django.db import models
from django.contrib.auth.models import User
from uuid import uuid4
import os

# ===== Local File Path Helpers =====
def original_resume_path(instance, filename):
    """
    Generate local path for storing the original uploaded resume for a user.
    """
    return os.path.join("resumes", instance.user.username, f"{uuid4()}_{filename}")

def tailored_resume_path(instance, filename):
    """
    Generate local path for storing a tailored resume for a user.
    """
    return os.path.join("resumes", "tailored", f"{instance.user.username}_{filename}")

def feedback_path(instance, filename):
    """
    Generate local path for storing feedback files for a user's resume.
    """
    return os.path.join("feedback", f"{instance.user.username}_{filename}")


# ===== Models =====
class Resume(models.Model):
    """
    Represents a user's uploaded resume stored locally.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    file_path = models.FileField(upload_to=original_resume_path, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {os.path.basename(self.file_path.name) if self.file_path else 'No File'}"


class TaskProgress(models.Model):
    """
    Tracks the progress of a long-running task for a user.
    """
    task_name = models.CharField(max_length=100)
    progress = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.task_name}: {self.progress}%"


class JobApplication(models.Model):
    """
    Represents a job application created from a user's resume, 
    including AI evaluation results and feedback.
    """
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("processing", "Processing"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    resume = models.ForeignKey(Resume, on_delete=models.CASCADE)
    job_description = models.TextField()
    tailored_resume_path = models.FileField(upload_to=tailored_resume_path, blank=True, null=True)
    score = models.FloatField(null=True, blank=True)
    ai_model = models.CharField(max_length=50, default="mistral")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    error_message = models.TextField(null=True, blank=True)
    feedback = models.TextField(null=True, blank=True)
    feedback_file_path = models.FileField(upload_to=feedback_path, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - Resume {self.resume.id} ({self.get_status_display()})"
