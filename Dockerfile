# ----- Base Image -----
FROM python:3.12-slim
# Lightweight Python 3.12 image for faster builds

# ----- Set Working Directory -----
WORKDIR /code
# All following commands run inside /code

# ----- Install System Dependencies -----
RUN apt-get update && apt-get install -y \
    default-libmysqlclient-dev \
    gcc \
    pkg-config \
    libmariadb-dev \
    curl && \
    rm -rf /var/lib/apt/lists/*
# Installs MariaDB client libs, GCC, pkg-config, curl, and development headers
# Cleans apt cache to reduce image size

# ----- Install Python Dependencies -----
COPY requirements.txt /code/
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt
# Upgrades pip and installs Python packages without caching to save space

# ----- Copy Project Code -----
COPY . /code/
# Copies the entire project into the container

# ----- Environment Configuration -----
ENV PYTHONUNBUFFERED=1
# Ensures Python outputs logs directly without buffering

# ----- Default Command -----
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
# Starts Django development server on all interfaces
