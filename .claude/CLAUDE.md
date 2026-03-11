# AI Code Assistant — Secure Code Generation & Enforcement Instructions

## Purpose & Scope
These concise, enforceable rules ensure the AI Code Assistant never generates insecure code patterns (unsafe shell use, string-built SQL, weak hashing) and that automated CI and pre-commit checks reject PRs introducing them. This document applies to all AI-generated code, code review guidance, CI, and pre-commit hooks for the repository.

## High-level policy (must be followed)
- The assistant must never output code that:
  - Executes shell strings (e.g., subprocess.run(..., shell=True), subprocess.Popen(..., shell=True), os.system(), os.popen()).
  - Constructs SQL by interpolating untrusted values (f-strings, %-format, or concatenation) for user input.
  - Uses hashlib.md5(...) or hashlib.sha1(...) for authentication, password hashing, token signing, or HMAC.
- If a user requests an insecure pattern the assistant must refuse, give a one-sentence security rationale, and provide a secure alternative including validation, whitelists, and robust error-handling.
- Prefer library APIs over shelling out (tarfile, shutil, GitPython, DB drivers/ORMs, argon2-cffi).

## Assistant refusal & remediation behavior
When asked for code containing forbidden constructs the assistant must:
- Refuse to provide the insecure pattern.
- Provide a one-sentence explanation (e.g., "Using shell=True allows command injection from untrusted input.").
- Provide a secure alternative that:
  - Validates inputs (types, max lengths, allowed character sets, canonicalized paths).
  - Uses server-side whitelists for commands and dynamic DB identifiers.
  - Uses parameterized DB queries or vetted ORM APIs.
  - Catches and sanitizes exceptions; logs only sanitized diagnostics; returns user-friendly errors.
  - Includes short inline comments explaining security choices.
- Never return insecure snippets even for examples; always show the safe replacement.

## Forbidden constructs (strict)
Do not generate any code containing:
- subprocess.run(..., shell=True) or subprocess.Popen(..., shell=True)
- os.system(...), os.popen(...), any call constructing/executing shell strings from user input
- Passing unsanitized/unvalidated user input into subprocess arguments
- SQL constructed by f-strings, "%"-formatting, or concatenation with user input
- hashlib.md5(...) or hashlib.sha1(...) for security-sensitive operations

Prohibited example (must refuse)
```python
# DO NOT GENERATE
subprocess.run(f"tar -xzf {user_input}", shell=True)
cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
pwd_hash = hashlib.md5(password.encode()).hexdigest()
```

## Subprocess & shell execution rules (addresses subprocess-related findings)
- Prefer built-in libraries. If an external process is required:
  - Always use list-form args and shell=False:
    subprocess.run([...], check=True, capture_output=True, text=True)
  - Require server-side ALLOWED_COMMANDS whitelist and verify with shutil.which().
  - Validate every user-supplied argument:
    - Type checks, non-empty, and maximum lengths.
    - Deny path traversal (".." segments) and disallow absolute paths unless canonicalized and explicitly allowed.
    - Deny shell metacharacters (; & | > < ` $ \n) and whitespace unless explicitly permitted.
    - Use a strict whitelist regex where applicable (e.g., r"^[A-Za-z0-9._\-]+$").
  - Catch subprocess.CalledProcessError and other exceptions; log sanitized diagnostics internally; return a generic user-facing error. Do not leak raw stdout/stderr or stack traces.
  - Avoid running commands as root; any escalation must be documented and narrowly scoped.
- Never generate code using shell=True, os.system, or os.popen. If code previously used shell=True, rewrite to list-form with validation and whitelisting.

Safe subprocess utility example:
```python
import shutil
import subprocess
import re
from typing import Sequence

ALLOWED_COMMANDS = {"tar", "gzip", "jq"}
_ALLOWED_ARG = re.compile(r"^[A-Za-z0-9._\-]+$")  # no spaces or shell metacharacters

def _validate_arg(arg: str) -> str:
    if not isinstance(arg, str) or not arg:
        raise ValueError("argument must be a non-empty string")
    if ".." in arg or arg.startswith("/"):
        raise ValueError("disallowed path or traversal")
    if len(arg) > 255:
        raise ValueError("argument too long")
    if not _ALLOWED_ARG.match(arg):
        raise ValueError("argument contains invalid characters")
    return arg

def run_command(args: Sequence[str]) -> str:
    # args must be a list/tuple where args[0] is a whitelisted command
    if not isinstance(args, (list, tuple)) or not args:
        raise ValueError("args must be a non-empty list/tuple")
    cmd = args[0]
    if cmd not in ALLOWED_COMMANDS:
        raise ValueError("command not permitted")
    if shutil.which(cmd) is None:
        raise FileNotFoundError(f"Command not found: {cmd}")
    for a in args[1:]:
        _validate_arg(a)
    try:
        res = subprocess.run(list(args), check=True, capture_output=True, text=True)
        # Return sanitized or structured output only
        return res.stdout
    except subprocess.CalledProcessError as e:
        # logger.error("external command failed: %s exit=%s", cmd, e.returncode)
        raise RuntimeError("external command failed") from e
```

## SQL query construction rules (addresses SQL injection findings)
- Always use parameterized DB-API queries or a vetted ORM. Forbidden: f-strings, %-formatting, or concatenation to build SQL with user data.
- If dynamic identifiers (table/column names, ORDER BY) are required:
  - Validate them against a server-side whitelist prior to interpolation.
  - Only interpolate identifiers that match the whitelist and strict naming rules.
- Validate all parameter types, ranges, and maximum lengths.
- Catch database exceptions; log sanitized errors internally; return user-friendly messages. Do not return SQL statements, parameter values, or stack traces to clients.

Parameterized SQL example (sqlite3):
```python
import sqlite3
from typing import Optional

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    if not isinstance(email, str) or "@" not in email or len(email) > 254:
        raise ValueError("invalid email")
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE email = ?", (email,))
    return cur.fetchone()
```

Whitelisted identifier example:
```python
ALLOWED_SORT_COLS = {"id", "email", "created_at"}

def fetch_sorted(conn: sqlite3.Connection, sort_col: str):
    if sort_col not in ALLOWED_SORT_COLS:
        raise ValueError("invalid sort column")
    # safe because sort_col is whitelisted and validated
    query = f"SELECT id, email FROM users ORDER BY {sort_col} DESC"
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()
```

## Hashing, password storage & cryptographic usage (addresses weak-hash findings)
- Forbidden: MD5 or SHA1 for password hashing, token signing, HMAC, or any security-sensitive function.
- Required: use Argon2 (argon2-cffi) or a vetted library like passlib wrapping Argon2. Acceptable fallback only with documented justification: bcrypt or scrypt, recorded in PR.
- Use SHA-256+ for non-security integrity/checksums.
- Legacy MD5 allowed only when ALL are satisfied:
  - Use hashlib.md5(..., usedforsecurity=False) (Python 3.9+).
  - Include inline code comment documenting non-security-only purpose and reference SECURITY_EXCEPTIONS.md.
  - PR description contains business justification and link to approved entry in SECURITY_EXCEPTIONS.md.
  - Security review approval recorded in SECURITY_EXCEPTIONS.md.
- The assistant must refuse any MD5/SHA1 usage for security purposes and provide an Argon2-based alternative.

Argon2 password hashing example:
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

Non-security checksum example:
```python
import hashlib

def sha256_checksum(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("data must be bytes")
    return hashlib.sha256(data).hexdigest()
```

Explicit legacy MD5 example (only with review):
```python
import hashlib

# MD5 used ONLY for legacy non-security deduplication; must use usedforsecurity=False,
# include inline rationale, and reference SECURITY_EXCEPTIONS.md.
def md5_dedup(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()
```

## Assistant generation constraints (enforced for every response that could include code)
- The assistant must scan its proposed code for forbidden constructs before returning it. If any forbidden construct is present, the assistant must refuse and return a secure alternative.
- All generated code must include:
  - Validation of all external inputs (types, maximum length, allowed characters).
  - Explicit server-side whitelists for commands and dynamic DB identifiers where applicable.
  - Exception handling that sanitizes logs and returns user-friendly errors.
- Examples must be realistic and ready for review (with comments and error handling).
- The assistant must annotate generated code with inline comments documenting the security rationale for non-obvious decisions.

## CI & automated enforcement (Bandit + strict diff scanning)
Add a GitHub Actions job named "security" that:
- Runs Bandit.
- Gathers changed files in the PR/commit range and scans only changed files for forbidden constructs via robust grep/regex checks.
- Fails the job (and the PR) if any forbidden patterns are detected.
- Enforces MD5 exceptions: if hashlib.md5 appears in changed files, require usedforsecurity=False in the same file, an inline comment referencing SECURITY_EXCEPTIONS.md, and an approval entry in SECURITY_EXCEPTIONS.md; otherwise fail.

Example GitHub Actions job:
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
      - name: Run bandit (report only)
        run: bandit -r . -ll -f json -o bandit-output.json || true
      - name: Fail on forbidden patterns in diff
        shell: bash
        run: |
          set -euo pipefail
          git fetch --no-tags --depth=1 origin +refs/heads/*:refs/remotes/origin/* || true
          CHANGED_FILES=$(git diff --name-only HEAD origin/HEAD || git diff --name-only HEAD~1 || true)
          if [ -z "${CHANGED_FILES:-}" ]; then
            echo "No changed files detected"; exit 0
          fi
          echo "Changed files:"
          echo "$CHANGED_FILES"
          # Strong forbidden pattern checks (covers shell usage, SQL string building, and weak hashes)
          # Patterns: shell=True, subprocess.* shell=, os.system, os.popen, f-string SELECT/INSERT/UPDATE, string concat SELECT, hashlib.md5, hashlib.sha1
          PATTERN='(\bshell=True\b|subprocess\.[A-Za-z_]+\([^)]*shell=|\\bos\\.system\\(|\\bos\\.popen\\(|f"[^"]*(SELECT|INSERT|UPDATE|DELETE)|f'\''[^'\'']*(SELECT|INSERT|UPDATE|DELETE)|(\"|\')\s*\+\s*.*(SELECT|INSERT|UPDATE|DELETE)|\\bhashlib\\.md5\\b|\\bhashlib\\.sha1\\b)'
          # Exclude virtual envs and third-party libs
          if git --no-pager grep -n -E "$PATTERN" $CHANGED_FILES -- ':!venv/*' ':!site-packages/*' ; then
            echo "Forbidden security patterns detected in changed files. See repository security policy for remediation." >&2
            exit 1
          fi
          # Special MD5 exception enforcement
          MD5_FILES=$(git --no-pager grep -l -E "\\bhashlib\\.md5\\b" $CHANGED_FILES -- ':!venv/*' ':!site-packages/*' || true)
          if [ -n "$MD5_FILES" ]; then
            while read -r f; do
              echo "MD5 usage found in $f; enforcing exception requirements."
              if ! grep -n "usedforsecurity=False" "$f" >/dev/null 2>&1; then
                echo "hashlib.md5 used without usedforsecurity=False in $f" >&2
                exit 1
              fi
              if ! grep -n "SECURITY_EXCEPTIONS.md" "$f" >/dev/null 2>&1; then
                echo "hashlib.md5 used without inline SECURITY_EXCEPTIONS.md reference in $f" >&2
                exit 1
              fi
            done <<< "$MD5_FILES"
            if ! grep -q "MD5" SECURITY_EXCEPTIONS.md >/dev/null 2>&1; then
              echo "MD5 usage detected in diff but SECURITY_EXCEPTIONS.md lacks an approval entry." >&2
              exit 1
            fi
          fi
```

## Pre-commit hooks & PR bot
- Add pre-commit hooks that block forbidden constructs on staged files:
  - Run bandit.
  - Run the same grep detection used in CI (operates on staged files).
- Sample .pre-commit-config.yaml:
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
        entry: grep -n --line-number -E "shell=True|subprocess\\.[A-Za-z_]+\\([^)]*shell=|\\bos\\.system\\(|\\bos\\.popen\\(|f\"[^\"']*(SELECT|INSERT|UPDATE|DELETE)|\\+\\s*\"[^\"']*(SELECT|INSERT|UPDATE|DELETE)|\\bhashlib\\.md5\\b|\\bhashlib\\.sha1\\b" -- ':!venv/*' ':!site-packages/*'
        language: system
        pass_filenames: false
```
- Configure a PR bot or GitHub Checks to scan diffs and post inline comments for any forbidden patterns and block merging until resolved.

## Minimal PR reviewer checklist (apply to AI-generated PRs)
- No shell=True, subprocess.* with shell=True, os.system(), or os.popen() on modified lines.
- All subprocess invocations use list arguments, shutil.which checks, server-side whitelists, and explicit validation of each argument.
- No SQL constructed via f-strings/concatenation with user input; parameterized queries or vetted ORM used. Any interpolated identifier validated against a server-side whitelist.
- No hashlib.md5 or hashlib.sha1 used for security-sensitive purposes. If MD5 appears, confirm usedforsecurity=False, inline justification referencing SECURITY_EXCEPTIONS.md, and an approved entry in SECURITY_EXCEPTIONS.md.
- CI security job and pre-commit hooks pass for the PR diff.

## Exceptions & maintenance
- MD5 exceptions (legacy, non-security) require:
  - Inline code comment documenting non-security-only purpose and referencing SECURITY_EXCEPTIONS.md.
  - Use of hashlib.md5(..., usedforsecurity=False).
  - Business justification and a link to an approved entry in SECURITY_EXCEPTIONS.md in the PR description.
  - Security review approval recorded in SECURITY_EXCEPTIONS.md.
- Update this document whenever new scanner patterns, vulnerabilities, or library deprecations appear. Adjust CI/grep rules accordingly.

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
- The assistant must refuse unsafe patterns and always present validated secure alternatives with input validation, whitelists, and error handling.
- CI (Bandit + strict diff grep) and pre-commit hooks will block forbidden patterns introduced in diffs.
- All MD5 exceptions require usedforsecurity=False, an inline justification referencing SECURITY_EXCEPTIONS.md, and an approved entry in that file.
- Security reviews and PR checklist items are mandatory for any exception or deviation.