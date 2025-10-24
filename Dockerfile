# Use Python slim as base
FROM python:3.12-slim

# Set working directory for Ollama
WORKDIR /root/.ollama

# Environment variables for Ollama
ENV OLLAMA_MODELS=/root/.ollama/models
ENV COMPOSE_BAKE=true

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    bash \
    procps \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Ollama
RUN curl -sSL https://ollama.com/install.sh | bash

# Expose Ollama port
EXPOSE 11434

# Start Ollama in foreground, wait until server is ready, then pull Gemma
CMD sh -c "\
    ollama serve & \
    echo 'Waiting for Ollama to start...' && \
    until curl -s http://localhost:11434/api/tags >/dev/null 2>&1; do sleep 2; done && \
    echo 'Ollama ready, pulling Gemma...' && \
    ollama pull gemma:2b && wait \
"
