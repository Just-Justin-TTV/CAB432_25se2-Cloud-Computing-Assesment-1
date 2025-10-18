Step 1: Activate the Python environment

In the project root (CAB432_25se2 Cloud Computing Assesment 1):

cd "C:\Users\Justin\Downloads\CAB432_25se2 Cloud Computing Assesment 1"
.\venv\Scripts\activate


Step 2: Make sure required Python packages are installed
Your script uses docx, PyPDF2, requests, etc. Install them:

pip install -r requirements.txt


If docx is missing:
pip install python-docx PyPDF2 requests

Step 3: Add test resumes

Create the resumes folder if it doesn’t exist:
mkdir resumes
Copy a test resume there:
copy "C:\Users\Justin\Documents\TestResume.pdf" ".\resumes\TestResume.pdf"


Step 4: Run the resume processing script

The script is inside app1:

python app1\resume_processing.py

It will read all resumes in the resumes folder.
It will try calling Ollama (http://localhost:11434/api/generate) — if the model isn’t ready, it will retry a few times and give warnings.
Local progress will be saved in the progress folder.
Feedback files will appear in job_results.


Step 5: Check Ollama model status

Inside another terminal, your group member can verify if the model is ready:

docker exec -it cab432-ollama bash
ollama list


If gemma:2b is listed, the API endpoint /api/generate is ready.
Otherwise, they’ll need to wait until the pull finishes.


Step 6: Check the output

Once the script completes:
Progress: progress\<username>_<task>.json
Feedback/results: job_results\<username>_<uuid>_feedback.txt
They can open the feedback text file to see the AI evaluation.