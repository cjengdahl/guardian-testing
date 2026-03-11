import hashlib
import sqlite3
import subprocess

# trigger


def get_user(username):
    """Fetch a user record by username."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL injection vulnerability (Bandit B608)
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def run_report(report_name):
    """Generate a report by name."""
    # Shell injection vulnerability (Bandit B602)
    subprocess.call("generate_report.sh " + report_name, shell=True)


def hash_password(password):
    # Weak hash algorithm (Bandit B324)
    return hashlib.md5(password.encode()).hexdigest()


if __name__ == "__main__":
    user = get_user("alice")
    print(user)
    run_report("monthly")
    print(hash_password("secret"))
