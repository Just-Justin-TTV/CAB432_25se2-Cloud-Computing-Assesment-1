#!/usr/bin/env bash
set -e

# Check if the Mistral model is already downloaded; pull it if missing
if ! ollama list | grep -q "gemma:2b"; then
    ollama pull gemma:2b
fi

# Start the Ollama server
exec ollama serve
