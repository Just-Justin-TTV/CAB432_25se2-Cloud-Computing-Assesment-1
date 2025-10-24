# Use Python slim as base
FROM python:3.12-slim

# Set working directory for Ollama
WORKDIR /root/.ollama

# Environment variables for Ollama
ENV OLLAMA_MODELS=/root/.ollama/models
ENV COMPOSE_BAKE=true

# Install dependencies including pkill and other essential tools
RUN apt-get update && apt-get install -y \
    curl \
    bash \
    python3-pip \
    procps \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Ollama
RUN curl -sSL https://ollama.com/install.sh | bash

# Pull Gemma model safely
RUN ollama serve & \
    echo "Waiting for Ollama server to start..." && \
    sleep 20 && \
    ollama pull gemma:2b && \
    pkill ollama || true

# Set working directory for Flask app
WORKDIR /app

# Copy Flask app code
COPY app.py /app/
COPY resume_utils.py /app/

# Install Python dependencies
RUN pip install flask requests

# Expose Ollama port and Flask port
EXPOSE 11434
EXPOSE 8001

# Start both Ollama and Flask when the container runs
CMD sh -c "ollama serve & echo 'Waiting for Ollama...' && sleep 10 && python app.py"
