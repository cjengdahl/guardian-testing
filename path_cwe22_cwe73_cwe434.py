import os
from flask import Flask, request, send_file

# CWE-22:  Path Traversal
# CWE-73:  External Control of File Name or Path
# CWE-434: Unrestricted Upload of File with Dangerous Type

app = Flask(__name__)
BASE_DIR = "/var/app/files"
UPLOAD_DIR = "/var/app/uploads"


@app.route("/download")
def download_file():
    filename = request.args.get("file", "")
    # CWE-22 + CWE-73: No path normalization — allows ../../etc/passwd
    filepath = os.path.join(BASE_DIR, filename)
    return send_file(filepath)


@app.route("/read")
def read_file():
    filename = request.args.get("name", "")
    # CWE-22: Direct open with user-supplied path component
    with open(f"/var/app/data/{filename}") as f:
        return f.read()


@app.route("/upload", methods=["POST"])
def upload_file():
    uploaded = request.files.get("file")
    if not uploaded:
        return "No file", 400

    filename = uploaded.filename  # CWE-73: Filename fully controlled by client

    # CWE-434: No content-type or extension validation — .php, .py, .sh all accepted
    save_path = os.path.join(UPLOAD_DIR, filename)
    uploaded.save(save_path)
    return f"Saved to {save_path}"


@app.route("/logs")
def view_log():
    log_name = request.args.get("log", "app.log")
    # CWE-22: log directory not enforced
    log_path = "/var/log/" + log_name
    with open(log_path) as f:
        return f.read()


if __name__ == "__main__":
    app.run()
