from flask import Flask, Response
import subprocess

app = Flask(__name__)

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
            yield f"ERROR: {e}\n"
    return Response(generate(), mimetype="text/plain")


@app.route("/health")
def health():
    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)