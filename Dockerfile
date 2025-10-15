# Base image
FROM python:3.12-slim

# Set working directory
WORKDIR /code

# Install system dependencies needed for MySQL, lxml, etc.
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    default-libmysqlclient-dev \
    pkg-config \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies first (caching layer)
COPY requirements.txt /code/

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the project code
COPY . /code/

# Set environment variables
ENV PYTHONUNBUFFERED=1

