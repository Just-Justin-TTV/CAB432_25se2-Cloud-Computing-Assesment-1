Assignment 2 - Cloud Services Exercises - Response to Criteria
================================================

Instructions
------------------------------------------------
- Keep this file named A2_response_to_criteria.md, do not change the name
- Upload this file along with your code in the root directory of your project
- Upload this file in the current Markdown format (.md extension)
- Do not delete or rearrange sections.  If you did not attempt a criterion, leave it blank
- Text inside [ ] like [eg. S3 ] are examples and should be removed


Overview
------------------------------------------------

- **Name:** Justin Singh-Atwal
- **Student number:** n11605618, n12008192
- **Partner name (if applicable):** Reny Ann Cherian (N12008192)
- **Application name:** ResumeHelper
- **Two line description:** We implemented a application which allows users to upload a resume and receive ai generated feedback based on the job role they request,
                            users can view their past entries via the dashboard and if the user is in the Admin group they can use the admin dashboard to see all entries
- **EC2 instance name or ID:** Justin Singh-Atwal ec2 instance, i-0c32d69a0e81389c4

------------------------------------------------

### Core - First data persistence service

- **AWS service name:**  Amazon S3
- **What data is being stored?:** Uploaded resumes and AI-generated feedback files (text and document files).
- **Why is this service suited to this data?:** S3 is ideal for storing large and unstructured files like resumes and AI feedback, 
                                                using S3 avoids size limitations and complexity associated with relational databases.

- **Why is are the other services used not suitable for this data?:** RDS: Designed for structured data, not large files and the same with 
                                                                      DynamoDB as its optimised for key-value and document data, but not for large binary files.
- **Bucket/instance/table name:** justinsinghatwalbucket, resumes/ - storing resumes feedback/ - storing ai generated feedback
- **Video timestamp:** 00:00 - 00:30
- **Relevant files:**
    -   views.py – manages file uploads and AI processing, upload_resume(request), 
    -   settings.py – stores AWS credentials and bucket info
    -   s3_utils.py – saves files to S3 and creates pre-signed URLs, upload_file_to_s3(file, bucket_name, key), generate_presigned_url(bucket_name, key, expiration=3600)
    -   models.py – defines database models for S3 file paths, Resume, JobApplication
    -   forms.py – user upload form, ResumeUploadForm,
    -   upload.html – upload page, <form> – triggers upload_resume
    -   match.html – AI job matching page
    -   view_job_application.html – displays resumes and AI feedback

### Core - Second data persistence service

- **AWS service name:**  Amazon RDS
- **What data is being stored?:**   User accounts, login credentials, uploaded resume paths, job applications, and AI match results.
- **Why is this service suited to this data?:** RDS is ideal for structured relational data with relationships, queries, and transactional needs.
                                                RDS dbs have good data integrity, which is important for user accounts and job application tracking.
- **Why is are the other services used not suitable for this data?:** S3: Only suitable for file storage, not structured relational data.
                                                                      DynamoDB: Optimized for key-value/document data, not relational tables with complex queries.  
- **Bucket/instance/table name:**   cohort_2025 - db name, auth_user – user credentials, app1_resume – S3 file paths for resumes, 
                                    app1_jobapplication – AI feedback and job matching results
- **Video timestamp:** 00:31 - 00:52
- **Relevant files:**
    -   views.py – updates and retrieves database records, upload_resume(request), update_job_application(request, application_id), get_user_applications(request)
    -   models.py – defines database tables and relationships, Resume, JobApplication, User
    -   s3_utils.py – links uploaded files to RDS records, link_s3_to_rds(resume_instance, s3_key)
    -   upload.html – triggers database record creation on upload
    -   match.html – updates job applications and AI feedback in RDS
    -   view_job_application.html – displays database records


### Third data service

- **AWS service name:**  Amazon DynamoDB
- **What data is being stored?:** AI processing progress for each uploaded resume (task ID, progress percentage, user ID).
- **Why is this service suited to this data?:** DynamoDB is ideal for fast, real-time updates of data, allowing the front-end
                                                to display live progress bars and track ongoing AI tasks efficiently.
- **Why is are the other services used not suitable for this data?:** RDS: Real-time frequent updates could overload a relational database.
                                                                      S3: Cannot handle structured, rapidly changing metadata.
- **Bucket/instance/table name:**  n11605618dynamo - table name, username - users username, task_name - current task, progress - ai progress
                                   updated_at - date which last update occurred 
- **Video timestamp:** 00:53 - 01:38
- **Relevant files:**
    -   views.py – updates task progress during AI processing, start_ai_task(request, resume_id), update_ai_progress(task_id, progress), get_task_progress(task_id)
    -   match.html – triggers AI processing and updates progress, JS triggers start_ai_task and periodically calls get_task_progress upload.html
    -   upload.html – starts task for new resume
    -   dynamo_utils.py

### S3 Pre-signed URLs

- **S3 Bucket names:**  justinsinghatwalbucket
- **Video timestamp:** 01:39 - 02:21
- **Relevant files:**   
    -   views.py – generates pre-signed URLs for download, download_resume(request, resume_id), download_feedback(request, application_id)
    -   s3_utils.py – helper functions to create pre-signed URLs, generate_presigned_url(bucket_name, key, expiration=3600)
    -   models.py – stores pre-signed URLs in RDS tables (app1_resume and app1_jobapplication)
    -   upload.html – shows download button for resumes, <a href="{{ resume_download_url }}">Download Resume</a>
    -   view_job_application.html – shows feedback download links

### In-memory cache

- **ElastiCache instance name:**    n11605618-ollama-memcached
- **What data is being cached?:** Requests and responses from the Ollama AI server, including AI match results and temporary computation data.
- **Why is this data likely to be accessed frequently?:** Multiple users may request AI matches or view previously processed resumes,
                                                          so caching reduces repeated processing and improves response speed.
- **Video timestamp:** 02:22 - 02:59
- **Relevant files:**
    -   views.py – interacts with Memcached to cache AI results, get_ai_result(request, application_id), cache_ai_result(application_id, result),
    -   match.html – retrieves cached AI results for faster display
    -   api_cache.py - used to retieve api tags, get_api_tags()

### Core - Statelessness

- **What data is stored within your application that is not stored in cloud data services?:** Temporary AI processing data, such as intermediate results during
                                                                                              resume matching and memory used for live progress updates.
- **Why is this data not considered persistent state?:** These intermediate results can be recreated from the original resume files in S3 and the task metadata
                                                         in RDS or DynamoDB, so losing them does not result in permanent data loss.
- **How does your application ensure data consistency if the app suddenly stops?:** Progress and results are continuously saved to DynamoDB and RDS as soon as they are generated.
                                                                                    If the app crashes or is restarted, the front-end can resume processing using the persisted data 
                                                                                    in the cloud, ensuring continuity and consistency.
- **Relevant files:**
    -   views.py – handles AI processing and temporary in-memory data, upload_resume, process_ai_feedback
    -   match.html – triggers AI tasks and reads live progress
    -   upload.html – initiates tasks and uploads resumes
    -   s3_utils.py – manages temporary access to S3 files during processing

### Graceful handling of persistent connections

- **Type of persistent connection and use:** The application relies on cloud-backed data services (RDS, DynamoDB, S3) to track AI processing tasks and progress. 
                                             This ensures that even if the front-end or server restarts, the AI task can continue from where it left off.
- **Method for handling lost connections:**  If the app or browser is restarted, the front-end reads the current task state from DynamoDB and RDS. 
                                             This allows the AI process to resume without losing progress, giving users a seamless experience.
- **Relevant files:**
    -   views.py – manages AI task execution and updates cloud storage with progress, update_ai_progress, get_task_progress
    -   match.html – reads progress from DynamoDB to update the live progress bar
    -   upload.html – initiates tasks and stores resume metadata


### Core - Authentication with Cognito

- **User pool name:** n12008192_assessment2_group8
- **How are authentication tokens handled by the client?:** Upon login, Cognito issues authentication tokens that the client stores locally and includes in the Authorization header for API requests.
- **Video timestamp:** 03:00 - 04:27
- **Relevant files:** views.py, urls.py, settings.py, register.html, login.html, forms.py
    -

### Cognito multi-factor authentication

- **What factors are used for authentication:** [eg. password, SMS code]
- **Video timestamp:**
- **Relevant files:**
    -

### Cognito federated identities

- **Identity providers used:**
- **Video timestamp:**
- **Relevant files:**
    -

### Cognito groups

- **How are groups used to set permissions?:** Users in the admin group have elevated privileges. Admin has a specical dashboard where admin can view the uploaded resumes by the user, download it, view feedbacks, while users in the user group have standard access rights.
- **Video timestamp:** 04:28 - 05:35
- **Relevant files:** views.py, urls.py
    -

### Core - DNS with Route53

- **Subdomain**:  http://justinsinghatwal.cab432.com/
- **Video timestamp:** 05:36 - 06:28

### Parameter store

- **Parameter names:** /n12008192/assessment2/COGNITO_CLIENT_ID, /n12008192/assessment2/COGNITO_CLIENT_SECRET
- **Video timestamp:** 06:29 - 07:19
- **Relevant files:** settings.py, views.py
    -

### Secrets manager

- **Secrets names:** n11605618-a2RDSecret
- **Video timestamp:** 07:20 - 07:59
- **Relevant files:** settings.py, docker-compose.yml
    -

### Infrastructure as code

- **Technology used:**
- **Services deployed:**
- **Video timestamp:**
- **Relevant files:**
    -

### Other (with prior approval only)

- **Description:**
- **Video timestamp:**
- **Relevant files:**
    -

### Other (with prior permission only)

- **Description:**
- **Video timestamp:**
- **Relevant files:**
    -
