FROM python:3.12-slim

WORKDIR /code

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    default-libmysqlclient-dev \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /code/
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy the entire project (including entrypoint.sh)
COPY . /code/

# Make entrypoint.sh executable
RUN chmod +x /code/entrypoint.sh

# Environment
ENV PYTHONUNBUFFERED=1

# Entry point
ENTRYPOINT ["/code/entrypoint.sh"]
