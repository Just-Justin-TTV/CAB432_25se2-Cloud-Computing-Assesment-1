import os
import io
import time
import json
import logging
from uuid import uuid4
from decimal import Decimal
from docx import Document
from PyPDF2 import PdfReader
import requests

# Logger
logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

# ===== Local Progress Storage =====
PROGRESS_DIR = "progress"
os.makedirs(PROGRESS_DIR, exist_ok=True)

def load_progress(username, task_name):
    path = os.path.join(PROGRESS_DIR, f"{username}_{task_name}.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            return Decimal(str(json.load(f).get("progress", 0)))
    return Decimal("0")

def save_progress(username, task_name, value):
    path = os.path.join(PROGRESS_DIR, f"{username}_{task_name}.json")
    with open(path, "w") as f:
        json.dump({"progress": float(value)}, f)

def safe_save_progress(username, task_name, progress_value):
    current = load_progress(username, task_name)
    new_value = Decimal(str(progress_value))
    if new_value > current:
        save_progress(username, task_name, new_value)

# ===== Resume Parsing =====
RESUME_DIR = "resumes"
os.makedirs(RESUME_DIR, exist_ok=True)

def read_resume_text(file_path):
    """Read .txt, .docx, .pdf resume locally."""
    text = ""
    ext = os.path.splitext(file_path)[1].lower()
    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()
        if ext == ".txt":
            text = file_bytes.decode('utf-8', errors='ignore')
        elif ext == ".docx":
            doc = Document(io.BytesIO(file_bytes))
            text = "\n".join([p.text for p in doc.paragraphs])
        elif ext == ".pdf":
            reader = PdfReader(io.BytesIO(file_bytes))
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
    except Exception as e:
        logging.error(f"Failed to read resume {file_path}: {e}")
    return text

# ===== Ollama AI Call =====
OLLAMA_URL = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

def call_ollama(payload, retries=5, delay=3):
    url = f"{OLLAMA_URL}/api/generate"
    for attempt in range(retries):
        try:
            response = requests.post(url, json=payload, timeout=600)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.warning(f"Ollama attempt {attempt+1} failed: {e}")
            time.sleep(delay)
    raise Exception("Ollama API request failed after retries.")

# ===== Resume Matching =====
JOB_RESULTS_DIR = "job_results"
os.makedirs(JOB_RESULTS_DIR, exist_ok=True)

def match_resume_to_job_local(username, resume_file_path, job_position):
    task_name = f"match_{os.path.basename(resume_file_path)}"
    safe_save_progress(username, task_name, Decimal("10"))

    # Read resume text
    resume_text = read_resume_text(resume_file_path)
    safe_save_progress(username, task_name, Decimal("25"))

    # AI prompt
    prompt = f"""
    You are a highly intelligent assistant that evaluates resumes against job positions in extreme detail.
    Job Position: {job_position}
    Resume Text: {resume_text}
    
    Return JSON with keys: score, feedback
    """
    payload = {"model": "mistral", "prompt": prompt, "stream": False}
    safe_save_progress(username, task_name, Decimal("40"))

    # Call AI
    response = call_ollama(payload)
    safe_save_progress(username, task_name, Decimal("70"))

    # Parse AI response
    ai_text = response.get("response", "")
    score, feedback = 50, ""
    try:
        parsed = json.loads(ai_text)
        score = parsed.get("score", 50)
        feedback = parsed.get("feedback", "")
        feedback = json.dumps(feedback, indent=4) if isinstance(feedback, dict) else str(feedback)
    except Exception as parse_err:
        logging.error(f"AI parsing error: {parse_err}")
        feedback = ai_text

    # Save results locally
    result_file = os.path.join(JOB_RESULTS_DIR, f"{username}_{uuid4()}_feedback.txt")
    with open(result_file, "w", encoding="utf-8") as f:
        f.write(feedback)

    safe_save_progress(username, task_name, Decimal("100"))
    logging.info(f"Match complete! Score: {score}, Feedback saved to: {result_file}")
    return score, result_file

# ===== Batch Resume Processing =====
def process_resume_batch(username, resume_files, job_position):
    total = len(resume_files)
    for i, resume_path in enumerate(resume_files, start=1):
        logging.info(f"Processing resume {i}/{total}: {resume_path}")
        try:
            match_resume_to_job_local(username, resume_path, job_position)
        except Exception as e:
            logging.error(f"Failed to process {resume_path}: {e}")
        progress = Decimal(i / total * 100)
        safe_save_progress(username, "resume_batch", progress)
    safe_save_progress(username, "resume_batch", Decimal("100"))
    logging.info("All resumes processed.")

# ===== CLI Example =====
if __name__ == "__main__":
    username = "test_user"
    job_position = "Software Engineer"
    resumes = [os.path.join(RESUME_DIR, f) for f in os.listdir(RESUME_DIR) if f.endswith((".pdf", ".docx", ".txt"))]
    process_resume_batch(username, resumes, job_position)
