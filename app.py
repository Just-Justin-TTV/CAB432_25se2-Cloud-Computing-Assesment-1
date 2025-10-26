from flask import Flask, Response
import subprocess
import sys

app = Flask(__name__)

APP_VERSION = "1.0"

# This goes BEFORE app.run
print(f"Starting resume-processor Flask app, version {APP_VERSION}", flush=True)

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

if __name__ == "__main__":
    print("Flask app running on 0.0.0.0:80", flush=True)
    app.run(host="0.0.0.0", port=80)
