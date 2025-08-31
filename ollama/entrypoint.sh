#!/usr/bin/env bash

# Exit immediately if any command fails
set -e

# Start the Ollama server in the background so we can continue running other setup commands
ollama serve &

# Poll the Ollama API to check if it's ready to accept requests
# This loop keeps trying until the /api/tags endpoint responds successfully
until curl -s http://localhost:11434/api/tags >/dev/null; do
  echo "Waiting for Ollama to start..."  # Let the user know we're still waiting
  sleep 2  # Pause for 2 seconds before retrying
done

# Check if the "mistral" model is already available locally
# If it isn't, pull it from the Ollama model repository
if ! ollama list | grep -q "mistral"; then
  echo "Pulling mistral model..."  # Inform the user that the model is being downloaded
  ollama pull mistral
fi

# Keep the Ollama process running in the foreground
# 'wait -n' ensures the script stays alive while background processes are running
wait -n
