FROM python:3.12-slim

WORKDIR /app

# Environment variables for Ollama
ENV OLLAMA_MODELS=/root/.ollama/models
ENV COMPOSE_BAKE=true

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    bash \
    procps \
    git \
    build-essential \
    default-libmysqlclient-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Ollama
RUN curl -sSL https://ollama.com/install.sh | bash

# Copy app files
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./

# Install Gunicorn
RUN pip install --no-cache-dir gunicorn

# Expose Flask port
EXPOSE 80

# Start Ollama in the background, then Gunicorn
CMD sh -c "ollama serve & gunicorn --bind 0.0.0.0:80 app:app --log-level info"
