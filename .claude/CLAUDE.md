# AI Code Assistant — Secure Coding & Generation Instructions

## Purpose
Provide concise, enforceable rules so the AI Code Assistant will not generate code that reproduces recurring security problems (unsafe subprocess usage, shell=True, string-built SQL injection, and MD5/SHA1 for security). These rules are mandatory for any code produced by the assistant for this repository and are tuned to prevent the vulnerabilities flagged by automated scans (subprocess shell use, general subprocess risks, stringed SQL, and MD5 usage).

## High-level policy (must be followed)
- The assistant must never output code that:
  - Uses subprocess with shell=True, subprocess.Popen(..., shell=True), os.system(), popen with shell strings, or any pattern that executes a constructed shell string from untrusted input.
  - Constructs SQL statements by f-strings, %-formatting, or string concatenation that include untrusted values.
  - Uses hashlib.md5(...) or hashlib.sha1(...) for password hashing, token signing, HMAC, or any security-sensitive functionality.
- If asked for insecure examples, the assistant must refuse to provide the insecure pattern, briefly explain why it's insecure, and supply a secure alternative with validation and sanitized error handling.
- Prefer library APIs over shelling out (e.g., tarfile, shutil, GitPython, builtin DB drivers, ORMs, argon2 libraries).

## Forbidden patterns (strict)
Do not generate any code that contains the following patterns:
- subprocess.run(..., shell=True), subprocess.Popen(..., shell=True), os.system(...), os.popen(...), or any shell invocation that builds a shell command string from user input.
- Passing unsanitized/unvalidated user input into subprocess commands or arguments.
- SQL built with f-strings, %-formatting, or string concatenation that interpolate user-controlled values.
- hashlib.md5(...) or hashlib.sha1(...) for authentication, password hashing, token signing, or HMAC. MD5 is permitted only for legacy non-security deduplication under strict conditions (see Hashing rules).

## Subprocess & shell execution rules
- Prefer library APIs for operations (file extraction, compression, VCS operations, JSON processing).
- If an external command is required:
  - Always use sequence form and shell=False: subprocess.run([...], check=True, capture_output=True, text=True).
  - Validate executable existence with shutil.which() and restrict allowed commands to a strict server-side whitelist.
  - Validate every user-supplied argument: enforce types, maximum lengths, deny shell metacharacters, ban "../" unless explicitly allowed and canonicalize paths.
  - Disallow any argument that originates from an untrusted source unless explicitly validated/whitelisted.
  - Catch subprocess.CalledProcessError, log sanitized diagnostics internally, and return a generic, user-safe error message.
- Do not expose raw stdout/stderr or stack traces to end users.
- Use least privilege: avoid running commands as root; if escalation is necessary document justification in PR and limit scope.

### Safe subprocess example
```python
import shutil
import subprocess
import re
from typing import Sequence

ALLOWED_COMMANDS = {"tar", "gzip", "jq"}  # server-side whitelist
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
    # Validate additional args explicitly
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

### Prohibited example (assistant must refuse)
```python
# DO NOT GENERATE
subprocess.run(f"tar -xzf {user_input}", shell=True)
```

### Safer alternative (assistant must offer)
```python
# Validate filename strictly and pass as list; do not use shell=True
user_file = _validate_filename(user_input)
subprocess.run(["tar", "-xzf", user_file], check=True, capture_output=True, text=True)
```

## SQL query construction rules
- Always use DB-API parameterized queries or a vetted ORM. Forbidden: f-strings, %-formatting, concatenation for queries with user input.
- If dynamic identifiers (table, column, ORDER BY) are necessary, validate them against a server-side whitelist before interpolation. Never accept client-provided identifiers without server-side validation.
- Validate types, ranges, and maximum lengths for numeric and string parameters.
- Catch database exceptions and do not return SQL or parameter values to clients; log sanitized errors internally.

### Safe SQL examples
```python
# Parameterized DB-API (sqlite3 example)
import sqlite3
from typing import Optional

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    if not isinstance(email, str) or "@" not in email or len(email) > 254:
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
    query = f"SELECT id, email FROM users ORDER BY {sort_col} DESC"  # safe via whitelist
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()
```

## Hashing and password storage rules
- Forbidden: MD5 or SHA1 for password hashing, token signing, HMAC, or any security-sensitive function.
- Required: use Argon2 (argon2-cffi) or passlib wrappers for password hashing. Acceptable alternatives: bcrypt or scrypt only if Argon2 is not available (document justification).
- Use SHA-256+ for non-security integrity or checksums.
- MD5 is allowed only for non-security legacy deduplication and only if:
  - The code calls hashlib.md5(..., usedforsecurity=False) (Python 3.9+), and
  - The use is documented in code comments and the PR description, and
  - A security review/approval is recorded in the PR and central exceptions file.

### Password hashing example (argon2-cffi)
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

### Non-security checksum example (SHA-256)
```python
import hashlib

def sha256_checksum(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("data must be bytes")
    return hashlib.sha256(data).hexdigest()
```

### Explicit legacy MD5 example (only with review)
```python
import hashlib

# MD5 used ONLY for legacy non-security deduplication. Security review required;
# do not use for authentication, signing, or HMAC.
def md5_dedup(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()
```

## Assistant refusal and remediation behavior
- If the user requests code containing any forbidden pattern, the assistant must:
  - Refuse to provide that insecure pattern.
  - Explain in one sentence why it is insecure (e.g., "Using shell=True allows command injection from untrusted input.").
  - Provide a secure alternative with:
    - Input validation (types, lengths, allowed characters, path canonicalization).
    - Whitelisting where applicable (commands, SQL identifiers).
    - Proper error handling (catching, sanitizing logs, user-friendly messages).
    - Short code comment(s) explaining choices.
- All generated examples must be production-ready for security review (not toy-only validation).

## CI & automated enforcement
- Add a GitHub Actions security job that runs Bandit and enforces explicit grep patterns on diffs and the repo. It must fail the build on detection of forbidden patterns.
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
          # Detect forbidden patterns in changed files (exclude venv)
          if git --no-pager grep -n --line-number -E "shell=True|subprocess\\..*shell=|\\bos\\.system\\(|\\bos\\.popen\\(|f\".*SELECT|f'.*SELECT|%\\s*\\(|\\bhashlib\\.md5\\b|\\bhashlib\\.sha1\\b" -- ':!venv/*' ; then
            echo "Forbidden security patterns detected"; exit 1
          fi
```
- The CI must:
  - Fail the PR if forbidden patterns are introduced anywhere in the diff.
  - Provide actionable remediation messages linking to secure examples in this document.

## Pre-commit hooks & PR bot
- Add pre-commit hooks to run:
  - bandit
  - the same grep detection used in CI
- Configure a PR bot to scan diffs and post inline comments for any forbidden patterns and block merging until resolved.
- Pre-commit should be configured to block commits with matches and provide guidance to replace with secure alternatives.

## Minimal PR reviewer checklist (apply to AI-generated PRs)
- No use of shell=True, subprocess.* with shell=True, os.system(), or os.popen() on modified lines.
- All subprocess invocations use list arguments, shutil.which checks, whitelists, and explicit validation.
- No SQL constructed via f-strings/concatenation with user input; parameterized queries or ORM used. Any interpolated identifier validated with a server-side whitelist.
- No hashlib.md5 or hashlib.sha1 used for security-sensitive purposes. Argon2/Bcrypt used for passwords.
- CI security job and pre-commit hooks pass for the PR diff.

## Exceptions & maintenance
- Exceptions (e.g., legacy MD5) are allowed only with:
  - Inline code comment documenting non-security-only use.
  - Call to hashlib.md5(..., usedforsecurity=False) where supported.
  - A documented business justification in the PR description.
  - Explicit security review and recorded approval in a central exceptions registry (create SECURITY_EXCEPTIONS.md).
- Review this file whenever new scan patterns or vulnerabilities appear and update CI/grep rules accordingly.

## Quick reference — forbidden vs allowed
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

## Enforcement summary
- The assistant must refuse unsafe patterns and always present validated secure alternatives.
- CI (Bandit + grep) and pre-commit hooks must block forbidden patterns on diffs.
- All exceptions must be documented, reviewed, and timebound.

<!-- End of instruction file -->