#!/usr/bin/env bash
set -e

# Pull the mistral model if not present
if ! ollama list | grep -q "mistral"; then
    echo "Pulling mistral model..."
    ollama pull mistral
fi

# Serve Ollama
exec ollama serve
