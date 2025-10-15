FROM python:3.12-slim

WORKDIR /code

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    default-libmysqlclient-dev \
    pkg-config \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /code/
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy everything (project files, entrypoint.sh, manage.py, etc.)
COPY . /code/

# Make entrypoint.sh executable
RUN chmod +x /code/entrypoint.sh

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/code/entrypoint.sh"]
