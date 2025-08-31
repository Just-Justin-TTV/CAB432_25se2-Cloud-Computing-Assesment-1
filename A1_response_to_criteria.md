Assignment 1 - REST API Project - Response to Criteria

## Overview

- **Name:** Justin Singh-Atwal  
- **Student number:** n11605618 
- **Application name:** CAB432 Web App  
- **Two-line description:** This REST API provides resume management, user authentication, and AI-based resume-to-job matching. It allows users to upload resumes, match them to job positions using AI, and view detailed feedback.

---

## Core Criteria

### Containerise the App
- **ECR Repository name:** `901444280953.dkr.ecr.ap-southeast-2.amazonaws.com/cab432-web`  
- **Description:** The web app, database, and AI service are containerized to ensure consistent deployment and environment isolation.  
- **Relevant files:**
  - `Dockerfile` – Defines the web app container environment.  
  - `requirements.txt` – Lists Python dependencies.  
  - `docker-compose.yml` – Orchestrates the web app, database, and Ollama AI service.

### Deploy the Container
- **Description:** The application is deployed on AWS, it uses Docker Compose to launch all required containers for web, database, and AI services.

### User Login
- **One-line description:** Users can register and log in with a username and password using Django’s authentication system.  
- **Implementation Details:** Includes user registration, login, and logout views with proper form validation and session management.  
- **Relevant files:**
  - `app1/views.py` – `register_view`, `login_view`, `logout_view`.  
  - `templates/login.html` – User login form.  
  - `templates/register.html` – User registration form.

### REST API
- **One-line description:** Provides endpoints for managing resumes and job applications, including AI matching and job application retrieval.  
- **Implementation Details:** REST endpoints handle CRUD for resumes and job applications. AI integration via Ollama is exposed through a POST endpoint that evaluates resumes against job positions.  
- **Relevant files:**
  - `app1/views.py` – Main logic for REST endpoints and AI matching.  
  - `app1/urls.py` – URL routing for API endpoints.  
  - `app1/models.py` – Database models for Resume and JobApplication.

### Data Types
- **One-line description:** Uses relational database tables to store users, resumes, and job applications.  
- **Relevant files:**
  - `app1/models.py` – Defines fields, types, and relationships.  
  - `docker-compose.yml` – Defines database service and volume persistence.

#### First Kind
- **One-line description:** User and authentication data stored in Django auth tables.  
- **Type:** String, DateTime, ForeignKey  
- **Rationale:** Standard Django user management ensures secure authentication and session handling.  
- **Relevant files:**
  - `auth_user`, `auth_group`, `auth_permission` – Default Django tables for user authentication and permissions.

#### Second Kind
- **One-line description:** Resume and JobApplication tables store uploaded resumes and job application info.  
- **Type:** Text, FileField, ForeignKey  
- **Rationale:** To store user-submitted resumes and link them to specific applications for AI analysis.  
- **Relevant files:**
  - `app1_resume` – Stores resume file paths and metadata.  
  - `app1_jobapplication` – Stores job position, AI feedback, and score.

### CPU-Intensive Task
- **One-line description:** The AI resume-to-job matching process simulates a CPU-intensive operation by running multiple threads and performing JSON processing.  
- **Implementation Details:**  
  - Reads the resume file content.  
  - Sends the text to the Ollama AI model for analysis.  
  - Parses JSON response and stores detailed feedback in the database and as a text file.  
- **Relevant files:**
  - `load_test.py` – Script for simulating CPU load.  
  - `app1/views.py` – `match_resume_to_job` function.

### CPU Load Testing
- **One-line description:** Automated load test simulates multiple users uploading resumes and triggering AI matching to monitor CPU performance.  
- **Relevant files:**
  - `load_test.py` – Script initiating multiple parallel API requests.  
  - `load_test.log` – Stores runtime logs.  
  - `load_test_cpu.log` – Tracks CPU usage during tests.

---

## Additional Criteria

### Extensive REST API Features
- **One-line description:** The Ollama AI API provides a structured JSON response with score, feedback, and optional sub-scores for technical and soft skills.  
- **Relevant files:**
  - `views.py` – Handles AI request, JSON parsing, and error handling.

### External API(s)
- **One-line description:** Ollama AI is used as an external API to evaluate resumes.  
- **Relevant files:**
  - `app1/views.py` – Interacts with Ollama’s REST API via `requests`.

### Additional Types of Data
- **One-line description:** Feedback data from AI is stored as `.txt` files, and CPU usage logs from load tests are stored as `.log` files.  
- **Relevant files:**  
  - Feedback: `MEDIA_ROOT/feedback/*.txt`  
  - CPU logs: `load_test_cpu.log`

### Custom Processing
- **One-line description:** Ollama AI processes resumes based on structured prompts designed to extract technical, soft skills, education, and overall candidate fit.  
- **Relevant files:**  
  - `app1/views.py` – `match_resume_to_job` function with prompt construction and parsing logic.

### Infrastructure as Code
- **One-line description:** Docker and Docker Compose are used to provision and orchestrate the web app, database, and AI service.  
- **Relevant files:**  
  - `docker-compose.yml`  
  - `Dockerfile`

### Web Client
- **One-line description:** The web client provides a clean, functional UI for uploading resumes, viewing dashboards, and accessing AI feedback.  
- **Relevant files:**  
  - `templates/` – HTML templates for dashboard, login, register, and resume views.  
  

### Upon Request (User interface)
- **One-line description:**  Alot of time was used up on the UI
- **Relevant files:**
  - `templates/` – HTML templates for dashboard, login, register, and resume views.  
  
