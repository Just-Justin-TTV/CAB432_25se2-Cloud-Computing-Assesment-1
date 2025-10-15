# Base image
FROM python:3.12-slim

# Set working directory
WORKDIR /code

# Install system dependencies including pkg-config for mysqlclient
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    default-libmysqlclient-dev \
    build-essential \
    curl \
    git \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies first (for caching)
COPY requirements.txt /code/

# Install Python dependencies
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy the entire project (including entrypoint.sh)
COPY code/ /code/

# Make entrypoint.sh executable
RUN chmod +x /code/entrypoint.sh

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Set the entrypoint
ENTRYPOINT ["/code/entrypoint.sh"]
