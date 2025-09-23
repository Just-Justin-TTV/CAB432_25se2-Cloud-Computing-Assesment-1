FROM python:3.12-slim

WORKDIR /root/.ollama

# Copy start script into container
COPY ollama_start.sh /root/.ollama/ollama_start.sh
RUN chmod +x /root/.ollama/ollama_start.sh

# Install any dependencies Ollama CLI might need
RUN apt-get update && apt-get install -y curl

# Expose Ollama port
EXPOSE 11434
