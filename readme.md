# CAB432 Cloud Computing Assessment 1

<!-- This README provides instructions for running the CAB432 web application
     both locally and using Docker Compose, along with environment variables
     and quick notes for developers. -->

This repository contains the **CAB432 web application**, which uses Django, MariaDB, and Ollama AI for resume-job matching.

---

# How to install virtual environment:

cd "YOUR DIRECTORY e.g, C:\Users\Justin\Downloads\CAB432_25se2 Cloud Computing Assesment 1"
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt


# Run the app, 
docker compose up --build

# You need Docker App Running, you need Ollama installed and you need to copy the file structure

## Git Clone

```bash
git clone git@github.com:Just-Justin-TTV/CAB432_25se2-Cloud-Computing-Assesment-1.git
cd CAB432_25se2-Cloud-Computing-Assesment-1


# Build and start containers
docker compose up --build

# Stop containers
docker compose down

# View web service logs
docker compose logs -f web

# Local development

# 1. Create a virtual environment
python -m venv venv

# 2. Activate the virtual environment
source venv/bin/activate  # Linux / MacOS
venv\Scripts\activate     # Windows

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Apply database migrations
python manage.py migrate

# 5. Start Django development server
python manage.py runserver
