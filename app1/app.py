from flask import Flask, request, jsonify
from resume_utils import match_resume_to_job

app = Flask(__name__)

@app.route("/api/process_resume/", methods=["POST"])
def process_resume():
    """
    Receives a JSON payload from Django like:
    {
        "username": "justin",
        "resume_path": "resumes/Resume1.pdf",
        "job_position": "Software Engineer"
    }
    """
    try:
        data = request.get_json()
        username = data.get("username")
        resume_path = data.get("resume_path")
        job_position = data.get("job_position")

        if not all([username, resume_path, job_position]):
            return jsonify({"error": "Missing required fields"}), 400

        # Run the matching function
        score, feedback_file = match_resume_to_job(username, resume_path, job_position)

        return jsonify({
            "score": score,
            "feedback_file": feedback_file,
            "message": "Resume processed successfully"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/ollama/api/<path:endpoint>", methods=["GET", "POST"])
def ollama_proxy(endpoint):
    url = f"http://localhost:11434/api/{endpoint}"
    if request.method == "POST":
        response = requests.post(url, json=request.json)
    else:
        response = requests.get(url)
    return jsonify(response.json())


if __name__ == "__main__":
    # Run the Flask app on localhost:8001 (you can change this if needed)
    app.run(host="0.0.0.0", port=8001)
