from django.db import models  # Django ORM base classes
from django.contrib.auth.models import User  # Built-in User model
import os  # Standard library for file paths


# Function to determine where the original uploaded resume should be stored
def original_resume_upload_path(instance, filename):
    # Stores files under 'resumes/original/' and prefixes with the user's username
    return os.path.join("resumes", "original", f"{instance.user.username}_{filename}")


# Function to determine where the AI-tailored resume should be stored
def tailored_resume_upload_path(instance, filename):
    # Stores files under 'resumes/tailored/' and prefixes with the user's username
    return os.path.join("resumes", "tailored", f"{instance.user.username}_{filename}")

def feedback_upload_path(instance, filename):
    return os.path.join("feedback", f"{instance.user.username}_{filename}")


# Model representing a user's uploaded resume
class Resume(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Link to user
    original_file = models.FileField(upload_to=original_resume_upload_path)  # Uploaded resume
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp

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

    user = models.ForeignKey(User, on_delete=models.CASCADE)  # User who submitted
    resume = models.ForeignKey(Resume, on_delete=models.CASCADE)  # Original resume
    job_description = models.TextField()  # Job description pasted by user
    
    tailored_resume_file = models.FileField(
        upload_to=tailored_resume_upload_path, null=True, blank=True
    )  # AI-generated tailored resume
    score = models.FloatField(null=True, blank=True)  # Match score
    ai_model = models.CharField(
        max_length=50, default="mistral", help_text="The Ollama model used"
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    error_message = models.TextField(null=True, blank=True)
    feedback = models.TextField(null=True, blank=True)  # AI feedback text
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.resume.original_file.name} for job ({self.get_status_display()})"
