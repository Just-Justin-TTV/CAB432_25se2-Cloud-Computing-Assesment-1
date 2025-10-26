from flask import Flask, Response
import subprocess
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Log version on startup
APP_VERSION = "1.0"
logger.info(f"Starting resume-processor Flask app, version {APP_VERSION}")

@app.route("/pull_model_stream")
def pull_model_stream():
    def generate():
        try:
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
        except Exception as e:
            logger.error(f"Failed to pull model: {e}")
            yield f"ERROR: {e}\n"
    return Response(generate(), mimetype="text/plain")

@app.route("/health")
def health():
    return "OK", 200

if __name__ == "__main__":
    logger.info("Flask app is running on all interfaces, port 80")
    app.run(host="0.0.0.0", port=80)
