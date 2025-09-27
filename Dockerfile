# Use Python 3.12 slim image as the base
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /code

# Install system dependencies required for MySQL, lxml, and other packages
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    default-libmysqlclient-dev \
    pkg-config \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy the Python dependencies file to leverage Docker layer caching
COPY requirements.txt /code/

# Install Python dependencies from requirements.txt
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the full project code into the container
COPY . /code/

# Ensure Python outputs are immediately flushed (no buffering)
ENV PYTHONUNBUFFERED=1
