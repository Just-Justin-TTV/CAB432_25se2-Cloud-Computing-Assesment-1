# Base image
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
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt /code/

RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy the rest of the code
COPY . /code/

ENV PYTHONUNBUFFERED=1

# Default: keep container alive headless
CMD ["tail", "-f", "/dev/null"]
# Or run Django directly:
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
