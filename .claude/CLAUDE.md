# AI Code Assistant — Secure Coding & Generation Instructions

- Revision checklist (high-level)
  - Replace any use of shell=True, os.system, popen with shell=True, or unvalidated shell strings with safe subprocess usage (list args, shell=False), tool existence checks, and strict validation/whitelisting.
  - Replace all string-built SQL (f-strings, %-formatting, concatenation) with DB-API parameterized queries or ORM; validate any dynamic identifiers via server-side whitelist.
  - Replace MD5/SHA1 for security-sensitive uses with Argon2/Bcrypt/Scrypt for passwords and SHA-256+ for non-security checksums; allow MD5 only for non-security deduplication with usedforsecurity=False and documented justification.
  - Enforce CI checks (Bandit + explicit grep patterns) that fail on regressions (forbidden subprocess patterns, unparameterized SQL, md5/sha1 usage); add pre-commit hooks and PR diff scanning.
  - Ensure assistant refuses to produce any forbidden pattern and always returns a secure alternative with validation and error handling examples.

## Purpose
Provide concise, enforceable rules so the AI Code Assistant will not generate code that reproduces recurring security problems (unsafe subprocess usage, shell=True, string-built SQL injection, and MD5/SHA1 for security). These rules are mandatory for any code produced by the assistant for this repository.

## High-level policy (must be followed by the assistant)
- The assistant must never output code that:
  - Uses subprocess with shell=True, subprocess.Popen(..., shell=True), os.system(), or any pattern that constructs shell strings from untrusted input.
  - Constructs SQL statements with f-strings, %-formatting, or string concatenation that include untrusted values.
  - Uses MD5 or SHA1 for password hashing, token signing, HMAC keys, or any security-sensitive functionality.
- When asked for insecure examples, the assistant must:
  - Refuse to provide the insecure pattern.
  - Provide a secure alternative, a brief rationale, and example code that includes input validation and sanitized error handling.
- All examples and generated code must prefer library APIs over shelling out. If shelling out is necessary, require a justification in code comments and the PR description.

## Forbidden patterns (do not generate)
- Any subprocess/OS invocation with shell=True or direct shell string execution (os.system, subprocess.run(..., shell=True), subprocess.Popen(..., shell=True)).
- Passing unsanitized/unvalidated user input into subprocess commands or arguments.
- SQL constructed by f-strings, %-formatting, or concatenation containing user-controlled data.
- Use of hashlib.md5(...) or hashlib.sha1(...) for authentication, password hashing, token signing, or HMAC. (MD5 allowed only for legacy non-security deduplication with usedforsecurity=False and documented justification.)

## Subprocess & shell execution rules
- Preferred:
  - Use library APIs whenever possible (e.g., Python tarfile, shutil, GitPython for Git ops, etc.).
  - If an external command is required, always call subprocess with a sequence (list/tuple) of arguments and shell=False.
  - Validate the command and arguments: use shutil.which() to ensure the executable exists and whitelist/validate user-supplied arguments (filenames, flags).
  - Use subprocess.run(args, check=True, capture_output=True, text=True) and catch subprocess.CalledProcessError. Sanitize error messages before logging or re-raising.
  - Limit allowed external commands to a strict whitelist when possible and enforce least privilege.
- Required input validation:
  - Validate type and shape of argument lists.
  - Strictly validate filenames (no .., absolute paths only when allowed, match allowed patterns, enforce ownership/permissions checks if applicable).
  - Reject or sanitize any argument containing shell metacharacters if it originates from untrusted input.
- Error handling:
  - Do not expose raw exception tracebacks or command output to end-users. Log sanitized diagnostics to internal logs and return user-safe error messages.
- Safe subprocess example:
```python
import shutil
import subprocess
import re
from typing import Sequence

ALLOWED_COMMANDS = {"tar", "gzip", "jq"}  # example whitelist
_ALLOWED_FILENAME = re.compile(r"^[a-zA-Z0-9_\-./]+$")

def _validate_filename(name: str) -> str:
    if not isinstance(name, str) or not name:
        raise ValueError("filename must be a non-empty string")
    if ".." in name or name.startswith("/tmp/unsafe"):
        raise ValueError("disallowed filename")
    if not _ALLOWED_FILENAME.match(name):
        raise ValueError("filename contains invalid characters")
    return name

def run_command(args: Sequence[str]) -> str:
    if not isinstance(args, (list, tuple)) or not args:
        raise ValueError("args must be a non-empty list/tuple")
    if args[0] not in ALLOWED_COMMANDS:
        raise ValueError("command not permitted")
    if shutil.which(args[0]) is None:
        raise FileNotFoundError(f"Command not found: {args[0]}")
    # Validate other args explicitly (example for a single filename)
    if len(args) > 1:
        _ = _validate_filename(args[1])
    try:
        res = subprocess.run(list(args), check=True, capture_output=True, text=True)
        return res.stdout
    except subprocess.CalledProcessError as e:
        # Log sanitized details internally and raise generic error to caller
        # logger.error("external command failed: %s exit=%s", args[0], e.returncode)
        raise RuntimeError("external command failed") from e
```
- Prohibited example (assistant must refuse to generate):
```python
# DO NOT GENERATE
subprocess.run(f"tar -xzf {user_input}", shell=True)
```
- Safer alternative (assistant must offer):
```python
# Validate filename strictly and pass as list; do not use shell=True
user_file = sanitize_filename(user_input)
subprocess.run(["tar", "-xzf", user_file], check=True, capture_output=True, text=True)
```

## SQL query construction rules
- Forbidden:
  - Building SQL via f-strings, %-formatting, or string concatenation when user input is present.
- Required:
  - Use DB-API parameterized queries (cursor.execute(query, params)) or a vetted ORM (SQLAlchemy, Django ORM) for all queries that include user data.
  - If dynamic SQL identifiers are required (table/column names, ORDER BY columns), validate them against a server-side whitelist before interpolating them into SQL. Do not accept client-provided identifiers without server-side validation.
  - Validate types and ranges for numeric parameters and enforce maximum lengths for strings.
  - Use explicit error handling for database exceptions and do not leak SQL or parameter values in error messages.
- Safe SQL examples:
```python
# Parameterized DB-API (sqlite3 example)
import sqlite3
from typing import Optional

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    if not isinstance(email, str) or "@" not in email:
        raise ValueError("invalid email")
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE email = ?", (email,))
    return cur.fetchone()
```
```python
# Whitelist dynamic identifiers
ALLOWED_SORT_COLS = {"id", "email", "created_at"}

def fetch_sorted(conn: sqlite3.Connection, sort_col: str):
    if sort_col not in ALLOWED_SORT_COLS:
        raise ValueError("invalid sort column")
    query = f"SELECT id, email FROM users ORDER BY {sort_col} DESC"  # safe because of whitelist
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()
```
- Example of refusing insecure pattern:
  - If a user requests code that builds SQL via f-strings with user data, respond: “I cannot provide that insecure pattern. Here is a parameterized alternative...” and include validated examples.

## Hashing and password storage rules
- Forbidden:
  - Use of MD5 or SHA1 for password hashing, token signing, HMAC, or any security-sensitive function.
- Required:
  - Use Argon2 (argon2-cffi) or passlib wrappers for password hashing. Acceptable alternatives: bcrypt or scrypt if Argon2 is not available and with documented justification.
  - Use SHA-256 or stronger (e.g., SHA-3) for non-security checksums and integrity tasks.
  - If MD5 must be used for non-security legacy deduplication, call hashlib.md5(..., usedforsecurity=False) (Python 3.9+) and document the reason in code comments and PR description; require an explicit security review and approval.
- Password hashing example (argon2-cffi):
```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

def hash_password(password: str) -> str:
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("password must be a string of at least 8 characters")
    return ph.hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return False
```
- Non-security checksum example (SHA-256):
```python
import hashlib

def sha256_checksum(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("data must be bytes")
    return hashlib.sha256(data).hexdigest()
```
- MD5 allowed only with explicit justification:
```python
import hashlib

# MD5 used ONLY for non-security deduplication (legacy). Security review required;
# do not use for authentication, signing, or HMAC.
def md5_dedup(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()
```

## Assistant refusal and remediation behavior
- If the user requests code containing any forbidden pattern, the assistant must:
  - Refuse to provide that insecure pattern.
  - Explain briefly why it is insecure (one sentence).
  - Provide a secure alternative with input validation, error handling, and minimal comments explaining choices.
- All generated code samples must be ready for production review (no toy validation only).

## CI & automated enforcement
- Add security scanning to CI and fail builds on forbidden patterns (shell=True, os.system, unparameterized SQL via f-strings/concatenation, md5/sha1 usage for security). Use Bandit and explicit pattern checks on the diff.
- Example GitHub Actions job:
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
          set -e
          # Patterns to detect unsafe usage: shell=True, os.system(, subprocess.*shell=, f"SELECT, % formatting SQL, hashlib.md5, hashlib.sha1
          if git --no-pager grep -n --line-number -E "shell=True|os\\.system\\(|subprocess\\.[A-Za-z_]+\\(.*shell=|f\".*SELECT|%(\\s*\\(|\\bhashlib\\.md5\\b|\\bhashlib\\.sha1\\b" -- ':!venv/*' ; then
            echo "Forbidden security patterns detected"; exit 1
          fi
```
- Pre-commit and PR bot recommendations:
  - Add pre-commit hooks to run Bandit and the same grep patterns; block commits that match.
  - Run a PR diff scanner that comments on files added/modified if forbidden patterns are present and fail CI with actionable remediation steps.
- CI policy: failing the security job must block merging until resolved and approved.

## Minimal PR reviewer checklist (apply to AI-generated PRs)
- No use of shell=True, os.system(), or unvalidated shell strings.
- All subprocess invocations use list arguments, shutil.which checks, and proper error handling or are replaced with library APIs.
- No SQL constructed via f-strings/concatenation with untrusted input; parameters or ORM used. Any dynamic identifiers validated by whitelist.
- No MD5/SHA1 used for authentication/signing; Argon2/Bcrypt used for passwords.
- CI passes Bandit and custom pattern checks.

## Maintenance & exceptions
- Keep this file adjacent to AI tooling configuration and update when new scan patterns or vulnerabilities appear.
- Exceptions (e.g., legacy MD5) are allowed only with:
  - A code comment explaining non-security-only use.
  - Use of hashlib.md5(..., usedforsecurity=False) where supported.
  - An explicit entry in the PR description documenting the business justification and an approved security review.
- Record and document any approved exceptions in a central security exceptions file and add an expiration/review date.

## Concise examples — forbidden vs allowed
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

# secure password hashing (argon2)
from argon2 import PasswordHasher
hash = PasswordHasher().hash(password)
```

## Quick reference for assistant implementers
- Always refuse and replace insecure patterns for subprocess, SQL, and hashing.
- Prefer library APIs; whitelist commands and SQL identifiers; validate inputs strictly.
- Add CI checks that fail on forbidden patterns and require remediation before merge.
- Document any unavoidable legacy exceptions with justification and security review.

<!-- End of instruction file -->