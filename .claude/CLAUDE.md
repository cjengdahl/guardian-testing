# AI Code Assistant — Secure Coding & Generation Instructions

- Revision plan (high-level)
  - Forbid subprocess usage with shell=True and unvalidated shell strings; require list-argument subprocess calls, shutil.which checks, whitelisting/validation, and error handling.
  - Ban string-built SQL with untrusted input; require parameterized queries or ORM and explicit whitelist validation for any dynamic identifiers.
  - Prohibit MD5/SHA1 for security-sensitive uses; require Argon2/Bcrypt/Scrypt for passwords and SHA-256+ for non-security checksums (MD5 only with usedforsecurity=False and documented justification).
  - Enforce checks in CI (Bandit + explicit pattern grep) to fail on regressions for these patterns; include pre-commit/PR checklist and remediation guidance.
  - Make the assistant refuse to produce insecure patterns; always return a secure alternative with concise rationale and examples including validation and error handling.

## Purpose
Provide concise, enforceable guidance so the AI Code Assistant will not generate code that recreates recurring security problems found during automated scans (subprocess misuse, shell=True, string-built SQL injection, and MD5/SHA1 for security). These rules are mandatory for any code produced by the assistant for this repository.

## High-level policies
- Forbidden patterns (the assistant must never generate):
  - subprocess.run(..., shell=True), subprocess.Popen(..., shell=True), os.system(), or any pattern that constructs shell strings from untrusted input.
  - SQL constructed via f-strings, %-formatting, or string concatenation that include untrusted values.
  - Use of MD5 or SHA1 for passwords, token signing, HMAC keys, or other security-sensitive functionality.
- Required/Preferred patterns:
  - Use subprocess.run/Popen with a sequence (list/tuple) of arguments and shell=False. Validate command existence with shutil.which() and validate/whitelist user-provided args.
  - Use DB-API parameterized queries (cursor.execute(query, params)) or an ORM (SQLAlchemy/Django ORM) for all data-bound queries. If dynamic identifiers are required (table/column names), validate them against a server-side whitelist before interpolation.
  - Use Argon2 (argon2-cffi), bcrypt, or scrypt for password hashing. Use SHA-256+ for non-security checksums.
- Refusal behavior:
  - If a user requests code containing any forbidden pattern, refuse and provide a secure alternative with a short explanation and example(s). Always include input validation and error handling in examples.

## Subprocess & shell execution rules
- Forbidden:
  - Any subprocess/OS invocation with shell=True or direct shell string execution (os.system, popen with shell=True).
  - Passing unsanitized/unvalidated user input into subprocess arguments (including strings that will be split by the shell).
- Required:
  - Always pass subprocess arguments as a list/tuple and ensure shell=False.
  - Validate the tool/command is available with shutil.which() before execution.
  - Validate and/or whitelist all user-provided arguments (filenames, flags, options). Reject or sanitize unsafe input.
  - Use subprocess.run(..., check=True, capture_output=True, text=True) and handle subprocess.CalledProcessError to avoid leaking raw stack traces or secrets.
  - Prefer library APIs over shelling out. If shelling out is necessary, provide justification in code comments and PR description.
- Example — safe subprocess usage:
```python
import shutil
import subprocess
from typing import Sequence

def run_tool(args: Sequence[str]) -> str:
    if not isinstance(args, (list, tuple)) or not args:
        raise ValueError("args must be a non-empty list/tuple of command and arguments")
    # ensure executable exists and is an expected command
    if shutil.which(args[0]) is None:
        raise FileNotFoundError(f"Command not found: {args[0]}")
    # Example of strict filename validation (implement appropriate checks)
    # if not is_allowed_filename(args[1]):
    #     raise ValueError("disallowed filename")
    try:
        res = subprocess.run(args, check=True, capture_output=True, text=True)
        return res.stdout
    except subprocess.CalledProcessError as e:
        # sanitize error before re-raising or logging
        raise RuntimeError("external command failed") from e
```
- Prohibited example (assistant must refuse to generate):
```python
# DO NOT GENERATE
subprocess.run(f"tar -xzf {user_input}", shell=True)
```
- Safer alternative (assistant must offer):
```python
# validate filename strictly and pass list
user_file = sanitize_filename(user_input)  # implement strict validation/whitelist
subprocess.run(["tar", "-xzf", user_file], check=True, capture_output=True, text=True)
```

## SQL query construction rules
- Forbidden:
  - Building SQL statements with string concatenation, f-strings, or %-formatting that include untrusted values.
- Required:
  - Use DB-API parameterized queries (cursor.execute(query, params)) or a proven ORM for all queries that include user data.
  - If dynamic SQL identifiers are necessary (table/column names, ORDER BY columns), validate them against a server-side whitelist and raise on invalid values. Never insert unvalidated identifiers into SQL.
  - Show explicit input validation and error handling for values used in queries.
- Examples:
```python
# Parameterized query (DB-API)
import sqlite3

def get_user_by_email(conn: sqlite3.Connection, email: str):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE email = ?", (email,))
    return cur.fetchone()
```
```python
# Whitelist dynamic identifiers (safe)
ALLOWED_SORT_COLS = {"id", "email", "created_at"}

def fetch_sorted(conn, sort_col: str):
    if sort_col not in ALLOWED_SORT_COLS:
        raise ValueError("Invalid sort column")
    query = f"SELECT id, email FROM users ORDER BY {sort_col} DESC"
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()
```

## Hashing and password storage rules
- Forbidden:
  - Using MD5 or SHA1 for password hashing, token signing, HMAC keys, or any security-sensitive function.
- Required:
  - Use Argon2 (argon2-cffi) or passlib wrappers for password hashing. Acceptable alternatives: bcrypt or scrypt.
  - Use SHA-256 or stronger for non-security integrity/checksum tasks. If MD5 is used only for legacy/non-adversarial deduplication, document it and call hashlib.md5(..., usedforsecurity=False) on Python 3.9+, and explain why it's safe in comments and PR description.
- Example — Argon2 password hashing:
```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return False
```
- Example — non-security checksum with SHA-256:
```python
import hashlib

def sha256_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
```
- Example — MD5 only for non-security deduplication (explicitly documented):
```python
import hashlib

# MD5 used only for non-security deduplication; not for authentication or signing.
# Document in PR why MD5 is safe here and that this is non-security-critical.
def md5_checksum(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()
```

## AI generation rules (enforced)
- The assistant must never output code that:
  - Uses subprocess with shell=True or os.system().
  - Constructs SQL via f-strings/string concatenation using untrusted input.
  - Uses MD5 or SHA1 for security-sensitive functions (passwords, tokens, HMAC).
- When asked for insecure examples, the assistant must:
  - Refuse to provide the insecure pattern.
  - Provide a secure alternative, a brief rationale, and example code with input validation and error handling.
- All generated examples must include input validation and sanitized error handling suitable for production use.

## CI & automated enforcement
- Add security scanning to CI and fail builds on forbidden patterns (shell=True, os.system, unparameterized SQL, md5/sha1 usage). Use Bandit plus explicit pattern checks on the codebase and PR diff.
- Recommended GitHub Action (example):
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.10"
      - name: Install tools
        run: |
          python -m pip install --upgrade pip
          pip install bandit
      - name: Run bandit
        run: bandit -r . -ll -f json -o bandit-output.json || true
      - name: Fail on forbidden patterns
        run: |
          # Patterns: shell=True, os.system(, subprocess.*shell=, f"SELECT, %(...), md5(, sha1(
          if git grep -n --line-number -E "shell=True|os\\.system\\(|subprocess\\.[A-Za-z_]+\\(.*shell=|f\"SELECT|%\\s*\\(|\\bmd5\\(|\\bsha1\\(" -- ':!*venv/*' ; then
            echo "Forbidden security patterns detected"; exit 1
          fi
```
- Recommended additional checks:
  - Pre-commit hook to run Bandit and grep for forbidden patterns.
  - PR bot that scans diffs for the same forbidden patterns and comments with remediation guidance when found.
  - Fail CI on high/medium findings related to subprocess shell usage, unparameterized SQL, or weak hashes.

## Examples — forbidden vs allowed (concise)
Forbidden:
```python
# DO NOT GENERATE
subprocess.run(f"tar -xzf {user_input}", shell=True)
cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
pwd_hash = hashlib.md5(password.encode()).hexdigest()
```
Allowed:
```python
# safe subprocess
subprocess.run(["tar", "-xzf", user_file], check=True, capture_output=True, text=True)

# parameterized SQL
cur.execute("SELECT * FROM users WHERE username = ?", (username,))

# secure password hashing
from argon2 import PasswordHasher
hash = PasswordHasher().hash(password)
```

## Minimal PR code-review checklist (apply to AI-generated PRs)
- No use of shell=True, os.system(), or unvalidated shell strings.
- All subprocess invocations use list arguments, shutil.which checks, and proper error handling.
- No SQL constructed via f-strings/concatenation with untrusted input; parameters or ORM used. Any dynamic identifiers validated by whitelist.
- No MD5/SHA1 used for authentication or signing; Argon2/Bcrypt used for passwords.
- CI passes Bandit and custom pattern checks; fix any flagged findings before merge.
- Code examples and new APIs include input validation and safe error handling.

## Maintenance & updates
- Keep this file adjacent to AI tooling configuration and update when new scan patterns or vulnerabilities appear.
- Ensure CI rules, pre-commit hooks, and PR checks reflect these constraints so generation and merges are blocked on regressions.
- When adding exceptions (e.g., legacy MD5 usage), document the justification in code comments and PR description and require an explicit security review.