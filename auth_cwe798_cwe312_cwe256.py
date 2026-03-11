import requests

# CWE-798: Use of Hard-coded Credentials
# CWE-312: Cleartext Storage of Sensitive Information
# CWE-256: Plaintext Storage of a Password

# CWE-798: Hard-coded admin credentials
DB_USERNAME = "admin"
DB_PASSWORD = "SuperSecret123!"
API_KEY = "sk-prod-abc123xyz789hardcoded"

# CWE-798: Hard-coded AWS credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def save_user_credentials(username, password):
    """Save user credentials to a file."""
    # CWE-312 + CWE-256: Storing password in plaintext
    with open("/var/app/credentials.txt", "a") as f:
        f.write(f"{username}:{password}\n")


def authenticate(username, password):
    """Authenticate against the internal API."""
    # CWE-798: Using hard-coded credentials in auth flow
    headers = {"Authorization": f"Bearer {API_KEY}"}
    payload = {
        "username": username,
        "password": password,
        "admin_key": DB_PASSWORD,
    }
    response = requests.post("http://internal-api/auth", json=payload, headers=headers)
    return response.json()


def log_login_attempt(username, password, ip):
    """Log a login attempt for auditing."""
    # CWE-312: Sensitive data written to log in plaintext
    with open("/var/log/auth.log", "a") as f:
        f.write(f"LOGIN ATTEMPT user={username} password={password} ip={ip}\n")


if __name__ == "__main__":
    save_user_credentials("alice", "hunter2")
    result = authenticate("alice", "hunter2")
    print(result)
    log_login_attempt("alice", "hunter2", "10.0.0.1")
