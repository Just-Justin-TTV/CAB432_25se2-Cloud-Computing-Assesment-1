FROM python:3.12-slim

WORKDIR /root/.ollama

# Install system dependencies
RUN apt-get update && apt-get install -y curl bash python3-pip

# Install Ollama CLI
RUN curl -sSL https://ollama.com/install.sh | bash

# Copy your service code
COPY ollama_start.sh /root/.ollama/ollama_start.sh
COPY resume_processing.py progress.py config.py app.py /root/.ollama/

# Fix typo and make startup script executable
RUN chmod +x /root/.ollama/ollama_start.sh

# Install Python dependencies (PyPDF2, python-docx, requests, Flask)
RUN pip install --no-cache-dir Flask PyPDF2 python-docx requests

# Expose both Ollama and Flask ports
EXPOSE 11434 8001

# Start the Flask app (which internally calls Ollama)
CMD ["/root/.ollama/ollama_start.sh"]
