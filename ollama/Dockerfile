# Base Image
FROM python:3.12-slim

# Set Working Directory
WORKDIR /code

# Install System Dependencies (added MySQL dev headers, pkg-config, build tools)
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    default-libmysqlclient-dev \
    pkg-config \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python Dependencies
COPY requirements.txt /code/
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy Project Code
COPY . /code/

# Environment Configuration
ENV PYTHONUNBUFFERED=1

# Default Command
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
