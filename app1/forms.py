from django import forms 

class ResumeUploadForm(forms.Form):
    """
    Form for uploading a resume file.
    """
    resume_file = forms.FileField(
        required=True,
        widget=forms.ClearableFileInput(attrs={'class': 'form-input'}),
        label="Upload Resume"
    )


class JobDescriptionForm(forms.Form):
    """
    Form for entering a job description and optionally generating multiple tailored resumes.
    """
    job_description = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 5, "placeholder": "Paste job description here"}),
        label="Job Description"
    )
    generate_multiple = forms.BooleanField(
        required=False,
        label="Generate multiple tailored versions"
    )
