from django import forms
from .models import Resume

# Form for uploading a resume file
class ResumeUploadForm(forms.ModelForm):
    class Meta:
        model = Resume
        fields = ['original_file']  # Correct field name
        widgets = {
            'original_file': forms.ClearableFileInput(attrs={'class': 'form-input'}),
        }

# Optional: Form for job description input
class JobDescriptionForm(forms.Form):
    job_description = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 5, "placeholder": "Paste job description here"}),
        label="Job Description"
    )
    generate_multiple = forms.BooleanField(
        required=False,
        label="Generate multiple tailored versions"
    )
