# Base image
FROM python:3.12-slim

# Set working directory
WORKDIR /code

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    default-libmysqlclient-dev \
    pkg-config \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies first (for caching)
COPY requirements.txt /code/

# Install Python dependencies globally (no venv issues)
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy the project code
COPY . /code/

# Environment variables
ENV PYTHONUNBUFFERED=1

# Use entrypoint script for Django commands
CMD ["/code/entrypoint.sh"]
