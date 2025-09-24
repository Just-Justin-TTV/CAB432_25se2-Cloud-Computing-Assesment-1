#!/usr/bin/env bash
set -e

# Pull the mistral model if not present
if ! ollama list | grep -q "mistral"; then
    echo "Pulling mistral model..."
    ollama pull gemma:2b
fi

# Serve Ollama
exec ollama serve
