# Base Image 
FROM python:3.12-slim

# Set Working Directory
WORKDIR /code

# Install System Dependencies (needed for mysqlclient, lxml, numpy, etc.)
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    default-libmysqlclient-dev \
    pkg-config \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies first for caching
COPY requirements.txt /code/

# Install Python Dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy Project Code
COPY . /code/

# Environment Configuration
ENV PYTHONUNBUFFERED=1

# Copy entrypoint script
COPY entrypoint.sh /code/entrypoint.sh
RUN chmod +x /code/entrypoint.sh

# Use entrypoint to handle migrations and runserver
ENTRYPOINT ["/code/entrypoint.sh"]
