#!/usr/bin/env python3
import subprocess
import time

model_name = "gemma:2b"

def wait_for_server(timeout=60):
    """Wait until Ollama server responds."""
    print("Waiting for Ollama server to be ready...")
    start_time = time.time()
    while True:
        try:
            subprocess.run(["ollama", "list"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("Ollama server is ready.")
            return
        except subprocess.CalledProcessError:
            if time.time() - start_time > timeout:
                raise TimeoutError("Ollama server did not start in time.")
            time.sleep(2)

def start_server():
    """Start the Ollama server in the background."""
    print("Starting Ollama server...")
    subprocess.Popen(["ollama", "serve"])
    wait_for_server()

def pull_model():
    """Pull the model if not already present."""
    output = subprocess.run(
        ["ollama", "list"],
        capture_output=True, text=True, check=True
    )
    if model_name not in output.stdout:
        print(f"Pulling model {model_name}...")
        subprocess.run(["ollama", "pull", model_name], check=True)
    else:
        print(f"Model {model_name} already exists.")

if __name__ == "__main__":
    start_server()
    pull_model()
    print("Ollama setup complete. Server is running.")
    # Keep container alive
    subprocess.run(["tail", "-f", "/dev/null"])
