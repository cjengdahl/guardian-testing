from flask import Flask, request, redirect, render_template_string
import sqlite3

# CWE-89:  SQL Injection
# CWE-79:  Cross-Site Scripting (XSS) — Reflected
# CWE-601: URL Redirection to Untrusted Site (Open Redirect)

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")


@app.route("/search")
def search():
    query = request.args.get("q", "")
    conn = get_db()
    cursor = conn.cursor()
    # CWE-89: Unsanitized query parameter concatenated into SQL
    sql = f"SELECT * FROM products WHERE name = '{query}'"
    results = cursor.execute(sql).fetchall()

    # CWE-79: User input reflected directly into HTML without escaping
    html = f"<h1>Results for: {query}</h1><ul>"
    for row in results:
        html += f"<li>{row[0]}</li>"
    html += "</ul>"
    return render_template_string(html)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = get_db()
    cursor = conn.cursor()
    # CWE-89: Second SQL injection in login form
    sql = (
        "SELECT id FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )
    user = cursor.execute(sql).fetchone()
    if user:
        return "Login successful"
    return "Login failed", 401


@app.route("/redirect")
def open_redirect():
    # CWE-601: Redirect target taken from user-supplied parameter without validation
    target = request.args.get("next", "/")
    return redirect(target)


@app.route("/profile")
def profile():
    name = request.args.get("name", "Guest")
    # CWE-79: Stored-style XSS — name inserted without escaping
    template = f"<html><body><h2>Welcome, {name}!</h2></body></html>"
    return render_template_string(template)


if __name__ == "__main__":
    app.run(debug=True)  # debug=True exposes interactive debugger in production
