from flask import Flask, Response, request, jsonify
import subprocess
import sys
import logging

APP_VERSION = "1.0"

# Configure logging to stdout so CloudWatch can capture it
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger(__name__)
logger.info(f"Starting resume-processor Flask app, version {APP_VERSION}")

app = Flask(__name__)

@app.route("/pull_model_stream")
def pull_model_stream():
    def generate():
        process = subprocess.Popen(
            ["ollama", "pull", "gemma:2b"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        for line in iter(process.stdout.readline, ''):
            yield line + "\n"
        process.stdout.close()
        process.wait()
    return Response(generate(), mimetype="text/plain")

@app.route("/health")
def health():
    return "OK", 200


@app.route("/api/generate", methods=["POST"])
def generate():
    """
    Receive JSON payload with keys:
    - "model": Ollama model name (e.g., gemma:2b)
    - "prompt": The text to process
    - Optional "max_tokens": int
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON payload provided"}), 400

        model = data.get("model")
        prompt = data.get("prompt")
        max_tokens = data.get("max_tokens", 200)

        if not model or not prompt:
            return jsonify({"error": "Both 'model' and 'prompt' are required"}), 400

        # Call Ollama CLI
        cmd = ["ollama", "generate", model, "-p", prompt, "--max-tokens", str(max_tokens)]
        logger.info(f"Running command: {' '.join(cmd)}")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            logger.error(f"Ollama error: {stderr}")
            return jsonify({"error": "Ollama failed", "details": stderr}), 500

        return jsonify({"response": stdout.strip()})

    except Exception as e:
        logger.exception("Error processing request")
        return jsonify({"error": str(e)}), 500