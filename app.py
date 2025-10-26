from flask import Flask, Response
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
