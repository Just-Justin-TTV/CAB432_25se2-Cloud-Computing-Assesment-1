
from resume_utils import match_resume_to_job


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
