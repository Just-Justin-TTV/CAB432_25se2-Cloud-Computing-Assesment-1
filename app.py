import requests
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


# ------------------------
# HTTP Ollama API
# ------------------------
@app.route("/api/generate", methods=["POST"])
def generate_http():
    data = request.get_json()
    model = data.get("model")
    prompt = data.get("prompt")

    if not model or not prompt:
        return jsonify({"error": "Both 'model' and 'prompt' are required"}), 400

    try:
        logger.info(f"Sending prompt to Ollama HTTP API: {model}")
        res = requests.post(
            "http://127.0.0.1:11434/api/generate",
            json={"model": model, "prompt": prompt}
        )
        # Return raw text instead of trying to parse JSON
        return jsonify({"response": res.text}), res.status_code
    except Exception as e:
        logger.error(f"Ollama HTTP call failed: {e}")
        return jsonify({"error": str(e)}), 500

# ------------------------
# Subprocess Ollama CLI
# ------------------------
@app.route("/api/generate1", methods=["POST"])
def generate_subprocess():
    data = request.get_json()
    model = data.get("model")
    prompt = data.get("prompt")

    if not model or not prompt:
        return jsonify({"error": "Both 'model' and 'prompt' are required"}), 400

    try:
        process = subprocess.Popen(
            ["ollama", "run", model, prompt],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        output, error = process.communicate()

        if process.returncode != 0:
            return jsonify({"error": "Ollama failed", "details": error}), 500

        return jsonify({"response": output.strip()}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    
    # ------------------------
# 3️⃣ List models
# ------------------------
@app.route("/api/models", methods=["GET"])
def list_models():
    try:
        res = requests.get("http://127.0.0.1:11434/api/tags")
        return jsonify(res.json()), res.status_code
    except Exception as e:
        return jsonify({"error": f"Could not connect to Ollama: {str(e)}"}), 500


# ------------------------
# 4️⃣ Start Ollama if not running
# ------------------------
@app.route("/api/start_ollama", methods=["POST"])
def start_ollama():
    try:
        # Check if Ollama is already running
        try:
            res = requests.get("http://127.0.0.1:11434/health")
            if res.status_code == 200:
                return jsonify({"status": "Ollama already running"}), 200
        except Exception:
            pass

        # Start Ollama in background
        subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return jsonify({"status": "Ollama starting..."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
