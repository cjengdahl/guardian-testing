# AI Code Assistant — Secure Code Generation & Enforcement Instructions

## Purpose
Provide concise, enforceable rules so the AI Code Assistant never generates insecure code patterns (unsafe subprocess/shell usage, string-built SQL injection, and weak hashing like MD5/SHA1 for security). These rules are mandatory for any code produced by the assistant for this repository and are tuned to eliminate recurring vulnerabilities flagged by automated scanners.

## High-level policy (must be followed)
- The assistant must never output code that:
  - Invokes or constructs shell strings for execution (e.g., subprocess.run(..., shell=True), subprocess.Popen(..., shell=True), os.system(), os.popen()).
  - Constructs SQL statements by f-strings, %-formatting, or string concatenation that include untrusted values.
  - Uses hashlib.md5(...) or hashlib.sha1(...) for authentication, password hashing, token signing, or HMAC.
- If a user requests an insecure pattern, the assistant must refuse, explain briefly why it is insecure, and provide a secure, validated alternative with error handling.
- Prefer library APIs (tarfile, shutil, GitPython, DB driver parameterization/ORMs, argon2-cffi) over shelling out.

## Forbidden patterns (strict — do not generate)
Do not generate any code containing:
- subprocess.run(..., shell=True) or subprocess.Popen(..., shell=True)
- os.system(...), os.popen(...), or any construction that builds/executes a shell string from user input
- Passing unsanitized/unvalidated user input into subprocess commands or arguments
- SQL constructed via f-strings, "%"-formatting, or string concatenation where user input is interpolated
- hashlib.md5(...) or hashlib.sha1(...) for security-sensitive uses

Prohibited example (assistant must refuse)
```python
# DO NOT GENERATE
subprocess.run(f"tar -xzf {user_input}", shell=True)
cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
pwd_hash = hashlib.md5(password.encode()).hexdigest()
```

## Subprocess & shell execution rules
- Prefer built-in libraries/APIs. If an external command is required:
  - Use sequence form and shell=False:
    subprocess.run([...], check=True, capture_output=True, text=True)
  - Restrict executables to a server-side ALLOWED_COMMANDS whitelist.
  - Validate executable existence with shutil.which().
  - Rigorously validate every user-supplied argument:
    - Types and maximum lengths
    - Reject shell metacharacters (e.g., `;`, `&&`, `|`, `>`, `<`, backticks)
    - Deny path-traversal (no "../") unless canonicalized and explicitly allowed
    - Enforce a strict character whitelist via regex when appropriate
  - Catch subprocess.CalledProcessError, log only sanitized diagnostics internally, and return a generic user-friendly error message.
  - Do not expose raw stdout/stderr or stack traces to end users.
  - Use least privilege. Avoid running commands as root; any escalation must be documented in the PR and narrowly scoped.

Safe subprocess example
```python
import shutil
import subprocess
import re
from typing import Sequence

ALLOWED_COMMANDS = {"tar", "gzip", "jq"}
_ALLOWED_FILENAME = re.compile(r"^[A-Za-z0-9._\-]+$")  # no spaces or shell metacharacters

def _validate_filename(name: str) -> str:
    if not isinstance(name, str) or not name:
        raise ValueError("filename must be a non-empty string")
    if ".." in name or name.startswith("/tmp/unsafe"):
        raise ValueError("disallowed filename")
    if len(name) > 255:
        raise ValueError("filename too long")
    if not _ALLOWED_FILENAME.match(name):
        raise ValueError("filename contains invalid characters")
    return name

def run_command(args: Sequence[str]) -> str:
    if not isinstance(args, (list, tuple)) or not args:
        raise ValueError("args must be a non-empty list/tuple")
    cmd = args[0]
    if cmd not in ALLOWED_COMMANDS:
        raise ValueError("command not permitted")
    if shutil.which(cmd) is None:
        raise FileNotFoundError(f"Command not found: {cmd}")
    # Validate additional args explicitly
    for a in args[1:]:
        _validate_filename(a)
    try:
        res = subprocess.run(list(args), check=True, capture_output=True, text=True)
        # Return only sanitized output or structured data; avoid leaking internal errors
        return res.stdout
    except subprocess.CalledProcessError as e:
        # Log sanitized details internally; do not include user input or raw stderr in responses
        # logger.error("external command failed: %s exit=%s", cmd, e.returncode)
        raise RuntimeError("external command failed") from e
```

## SQL query construction rules
- Always use parameterized DB-API queries or a vetted ORM. Forbidden: f-strings, %-formatting, + concatenation with user input.
- If dynamic identifiers are required (table/column/ORDER BY), validate against a server-side whitelist before interpolation. Never accept client-provided identifiers without validation.
- Validate types, ranges, and maximum lengths for numeric and string parameters.
- Catch database exceptions and do not return SQL statements, parameter values, or stack traces to clients; log sanitized errors internally.

Safe SQL examples
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

Whitelist dynamic identifiers
```python
ALLOWED_SORT_COLS = {"id", "email", "created_at"}

def fetch_sorted(conn: sqlite3.Connection, sort_col: str):
    if sort_col not in ALLOWED_SORT_COLS:
        raise ValueError("invalid sort column")
    query = f"SELECT id, email FROM users ORDER BY {sort_col} DESC"  # safe because of whitelist
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()
```

## Hashing and password storage rules
- Forbidden: MD5 or SHA1 for password hashing, token signing, HMAC, or any security-sensitive function.
- Required: use Argon2 (argon2-cffi) or passlib wrappers. Acceptable fallback: bcrypt or scrypt only if Argon2 is unavailable (document justification in PR).
- Use SHA-256 (or better) for non-security integrity or checksums.
- Legacy MD5 allowed only when ALL of the following are true:
  - Use hashlib.md5(..., usedforsecurity=False) (Python 3.9+) is explicitly called.
  - Inline code comment documents the non-security-only purpose.
  - The PR description contains a business justification and a link to an approved entry in SECURITY_EXCEPTIONS.md.
  - A security review approval is recorded in the exceptions registry.

Password hashing example (argon2-cffi)
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

Non-security checksum example (SHA-256)
```python
import hashlib

def sha256_checksum(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("data must be bytes")
    return hashlib.sha256(data).hexdigest()
```

Explicit legacy MD5 example (only with review)
```python
import hashlib

# MD5 used ONLY for legacy non-security deduplication; must use usedforsecurity=False,
# include inline rationale, and reference SECURITY_EXCEPTIONS.md approval.
def md5_dedup(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()
```

## Assistant refusal and remediation behavior
- If the user requests code containing any forbidden pattern, the assistant must:
  - Refuse to provide that insecure pattern.
  - Explain in one sentence why it is insecure (e.g., "Using shell=True allows command injection from untrusted input.").
  - Provide a secure alternative that includes:
    - Strong input validation (types, lengths, allowed characters, path canonicalization).
    - Server-side whitelisting where applicable (commands, SQL identifiers).
    - Proper error handling (catch exceptions, log sanitized diagnostics, return user-friendly messages).
    - Short code comments explaining the security choices.
- All generated examples must be production-ready for security review (not toy-only).

## CI & automated enforcement
- Add a GitHub Actions security job that runs Bandit and rejects diffs that introduce forbidden patterns. The job must fail the build if forbidden patterns are detected anywhere in the PR diff.
- The job must also run a grep-based detection that scans changed files for forbidden constructs including shell=True, subprocess.*shell=, os.system, os.popen, f-string SQL patterns, string concatenation used to build SQL, and hashlib.md5/hashlib.sha1. It should require usedforsecurity=False and an exceptions registry for MD5 usage.
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
      - name: Fail on forbidden patterns in diff
        run: |
          set -euo pipefail
          # Only inspect changed files in the PR/commit range
          git fetch --no-tags --depth=1 origin +refs/heads/*:refs/remotes/origin/*
          CHANGED_FILES=$(git diff --name-only HEAD origin/HEAD || git diff --name-only HEAD~1)
          if [ -z "$CHANGED_FILES" ]; then
            echo "No changed files detected"; exit 0
          fi
          echo "$CHANGED_FILES" | xargs git --no-pager grep -n --line-number -E \
            "shell=True|subprocess\\.[A-Za-z_]+\\(.*shell=|\\bos\\.system\\(|\\bos\\.popen\\(|f\".*SELECT|f'.*SELECT|\\+\\s*\".*SELECT|\\bhashlib\\.md5\\b|\\bhashlib\\.sha1\\b" -- ':!venv/*' || true
          # If any matches found exit with message
          if git --no-pager grep -n --line-number -E "shell=True|subprocess\\.[A-Za-z_]+\\(.*shell=|\\bos\\.system\\(|\\bos\\.popen\\(|f\".*SELECT|f'.*SELECT|\\+\\s*\".*SELECT|\\bhashlib\\.md5\\b|\\bhashlib\\.sha1\\b" $CHANGED_FILES -- ':!venv/*' ; then
            echo "Forbidden security patterns detected in changed files. See repository security policy for remediation." >&2
            exit 1
          fi
```
- CI must:
  - Fail the PR if forbidden patterns are introduced in the diff.
  - Provide actionable remediation messages linking to secure examples in this document.
  - Enforce MD5 exceptions: if hashlib.md5 is detected, CI should require a matching SECURITY_EXCEPTIONS.md entry and the inline code comment reference; otherwise fail.

## Pre-commit hooks & PR bot
- Add pre-commit hooks to run:
  - bandit
  - the same grep detection used in CI
- Configure a PR bot to scan diffs and post inline comments for any forbidden patterns and block merging until resolved.
- Pre-commit configuration snippet (example .pre-commit-config.yaml):
```yaml
repos:
  - repo: local
    hooks:
      - id: bandit-scan
        name: bandit-scan
        entry: bandit -r . -ll
        language: system
      - id: forbidden-patterns
        name: forbidden-patterns
        entry: grep -n --line-number -E "shell=True|subprocess\\.[A-Za-z_]+\\(.*shell=|\\bos\\.system\\(|\\bos\\.popen\\(|f\".*SELECT|f'.*SELECT|\\+\\s*\".*SELECT|\\bhashlib\\.md5\\b|\\bhashlib\\.sha1\\b" -- ':!venv/*'
        language: system
        pass_filenames: false
```

## Minimal PR reviewer checklist (apply to AI-generated PRs)
- No use of shell=True, subprocess.* with shell=True, os.system(), or os.popen() on modified lines.
- All subprocess invocations use list arguments, shutil.which checks, whitelists, and explicit validation.
- No SQL constructed via f-strings/concatenation with user input; parameterized queries or ORM used. Any interpolated identifier validated with a server-side whitelist.
- No hashlib.md5 or hashlib.sha1 used for security-sensitive purposes. If MD5 appears, confirm usedforsecurity=False, inline justification, and an approved SECURITY_EXCEPTIONS.md entry.
- CI security job and pre-commit hooks pass for the PR diff.

## Exceptions & maintenance
- Exceptions (e.g., legacy MD5) allowed only with:
  - Inline code comment documenting non-security-only use and link to SECURITY_EXCEPTIONS.md.
  - Use of hashlib.md5(..., usedforsecurity=False).
  - Business justification in the PR description.
  - Explicit security review and recorded approval in SECURITY_EXCEPTIONS.md.
- Update this instruction file whenever new scan patterns or vulnerabilities appear and adjust CI/grep rules accordingly.

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
- All MD5 exceptions require explicit review and documentation in SECURITY_EXCEPTIONS.md and must use usedforsecurity=False.
- Security reviews and PR checklist items are mandatory for any exception or deviation.