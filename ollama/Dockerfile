FROM python:3.12-slim

WORKDIR /root/.ollama

# Install dependencies
RUN apt-get update && apt-get install -y curl bash

# Install Ollama CLI
RUN curl -sSL https://ollama.com/install.sh | bash

# Copy start script
COPY ollama_start.sh /root/.ollama/ollama_start.sh
RUN chmod +x /root/.ollama/ollama_start.sh

# Expose Ollama port
EXPOSE 11434

# Default command
CMD ["/root/.ollama/ollama_start.sh"]
