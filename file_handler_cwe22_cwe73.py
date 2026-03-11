import os

# CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
# CWE-73: External Control of File Name or Path

BASE_DIR = "/var/app/uploads"


def read_user_file(filename):
    """Read a user-supplied file from the uploads directory."""
    # CWE-22: No path sanitization — attacker can supply ../../etc/passwd
    file_path = os.path.join(BASE_DIR, filename)
    with open(file_path, "r") as f:
        return f.read()


def write_log(log_name, content):
    """Write content to a log file with a user-controlled name."""
    # CWE-73: User controls the file path entirely
    log_path = "/var/logs/" + log_name
    with open(log_path, "w") as f:
        f.write(content)


def serve_template(template_name):
    """Load and return a template file by name."""
    # CWE-22: No validation that template_name stays within template dir
    template_dir = "/var/app/templates"
    path = os.path.join(template_dir, template_name)
    with open(path, "r") as f:
        return f.read()


if __name__ == "__main__":
    print(read_user_file("../../etc/passwd"))
    write_log("../../etc/cron.d/evil", "* * * * * root /tmp/evil.sh")
    print(serve_template("../config/secrets.yml"))
