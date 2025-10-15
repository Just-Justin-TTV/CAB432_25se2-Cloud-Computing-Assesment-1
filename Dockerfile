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

# Copy requirements first for caching
COPY requirements.txt /code/
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy entrypoint.sh **explicitly** and make it executable
COPY code/entrypoint.sh /code/entrypoint.sh
RUN chmod +x /code/entrypoint.sh

# Copy the rest of the project
COPY code/ /code/

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Set entrypoint
ENTRYPOINT ["/code/entrypoint.sh"]
