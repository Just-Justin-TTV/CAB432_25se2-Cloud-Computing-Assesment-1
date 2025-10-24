# Use Python slim as base
FROM python:3.12-slim

# Set working directory
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

# Expose default Ollama port
EXPOSE 11434

# Command to start Ollama server when container runs
CMD ["ollama", "serve"]
