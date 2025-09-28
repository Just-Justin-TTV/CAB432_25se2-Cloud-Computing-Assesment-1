FROM python:3.12-slim

WORKDIR /root/.ollama

# Install necessary system dependencies
RUN apt-get update && apt-get install -y curl bash

# Install Ollama CLI
RUN curl -sSL https://ollama.com/install.sh | bash

# Copy the startup script into the container and make it executable
COPY ollama_start.sh /root/.ollama/ollama_start.sh
RUN chmod +x /root/.ollama/ollama_start.sh

# Expose the default port used by Ollama
EXPOSE 11434

# Run the Ollama startup script when the container launches
CMD ["/root/.ollama/ollama_start.sh"]
