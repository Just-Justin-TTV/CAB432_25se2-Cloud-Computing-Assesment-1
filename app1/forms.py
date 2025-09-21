from django import forms
from .models import Resume

# Form for uploading a resume file (S3 only)
class ResumeUploadForm(forms.ModelForm):
    resume_file = forms.FileField(
        required=True,
        widget=forms.ClearableFileInput(attrs={'class': 'form-input'}),
        label="Upload Resume"
    )

    class Meta:
        model = Resume
        fields = []  # No local file fields are used

# Form for job description input
class JobDescriptionForm(forms.Form):
    job_description = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 5, "placeholder": "Paste job description here"}),
        label="Job Description"
    )
    generate_multiple = forms.BooleanField(
        required=False,
        label="Generate multiple tailored versions"
    )
