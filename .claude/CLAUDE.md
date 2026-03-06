# AI Code Assistant — Secure Code Generation & Enforcement Instructions

- Checklist (high-level revision plan)
  - Forbid any use of shell=True, os.system/os.popen, or dynamic shell construction; require list-form subprocess with strict validation and command whitelists.
  - Prohibit string-built SQL (f-strings, %-format, concatenation) for user data; require parameterized queries/ORMs and whitelist any dynamic identifiers.
  - Forbid MD5/SHA1 for security-sensitive uses; require Argon2 (argon2-cffi) or justified fallback and strict legacy MD5 exception rules.
  - Enforce the rules with CI (Bandit + grep), pre-commit hooks, and PR bot checks that fail PRs introducing forbidden patterns.
  - Provide refusal behavior for insecure requests and secure, validated alternatives with error handling.

## Purpose
Concise, enforceable rules so the AI Code Assistant never generates insecure code patterns (unsafe subprocess/shell usage, string-built SQL, weak hashing) and to ensure automated scans and reviewers can reject PRs that introduce them.

## High-level policy (must be followed)
- The assistant must never output code that:
  - Executes shell strings (e.g., subprocess.run(..., shell=True), subprocess.Popen(..., shell=True), os.system(), os.popen()).
  - Constructs SQL by interpolating untrusted values (f-strings, %-formatting, or concatenation).
  - Uses hashlib.md5(...) or hashlib.sha1(...) for authentication, password hashing, token signing, or HMAC.
- If asked for an insecure pattern, refuse, explain briefly why, and provide a secure, validated alternative with robust error handling.
- Prefer library APIs (tarfile, shutil, GitPython, DB driver parameterization/ORMs, argon2-cffi) to shelling out.

## Assistant refusal and remediation behavior
- When a user requests code containing any forbidden pattern the assistant must:
  - Refuse to provide the insecure pattern.
  - Provide a one-sentence explanation (e.g., "Using shell=True allows command injection from untrusted input.").
  - Provide a secure alternative that includes:
    - Strong input validation (types, lengths, allowed character set, canonicalization for paths).
    - Server-side whitelisting where applicable (commands, table/column names).
    - Proper error handling (catch exceptions, log sanitized diagnostics internally, return user-friendly messages).
    - Short inline comments explaining security choices.
- All provided alternatives must be production-ready for security review.

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

## Subprocess & shell execution rules (addresses B404, B602)
- Prefer built-in libraries. If an external process is required:
  - Always use sequence form (list) and shell=False:
    subprocess.run([...], check=True, capture_output=True, text=True)
  - Enforce a server-side ALLOWED_COMMANDS whitelist and use shutil.which() to verify existence.
  - Validate every user-supplied argument:
    - Type checks and maximum lengths.
    - Deny path traversal (".." or leading "/") unless canonicalized and explicitly allowed.
    - Reject shell metacharacters (e.g., ; && | > < ` $).
    - Use a strict character whitelist regex when appropriate.
  - Catch subprocess.CalledProcessError and other exceptions; log only sanitized diagnostics internally and return generic, user-friendly messages. Do not leak raw stdout/stderr or stack traces to users.
  - Avoid running commands as root; any escalation must be documented in the PR and narrowly scoped.
- Never generate code using shell=True, os.system, or os.popen. If code previously used shell=True, rewrite to list-form calls with validation and whitelisting.

Safe subprocess example
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
    if ".." in arg or arg.startswith("/tmp/unsafe"):
        raise ValueError("disallowed path or traversal")
    if len(arg) > 255:
        raise ValueError("argument too long")
    if not _ALLOWED_ARG.match(arg):
        raise ValueError("argument contains invalid characters")
    return arg

def run_command(args: Sequence[str]) -> str:
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
        # Return sanitized output only (or structured data); avoid exposing raw error details
        return res.stdout
    except subprocess.CalledProcessError as e:
        # logger.error("external command failed: %s exit=%s", cmd, e.returncode)
        raise RuntimeError("external command failed") from e
```

## SQL query construction rules (addresses B608)
- Always use parameterized DB-API queries or a vetted ORM. Forbidden: f-strings, %-formatting, or string concatenation to build SQL with user data.
- If dynamic identifiers are required (table/column names or ORDER BY), validate them against a server-side whitelist before interpolation. Never accept client-provided identifiers without validation.
- Validate all parameter types, ranges, and maximum lengths.
- Catch database exceptions; do not return SQL statements, parameter values, or stack traces to clients; log sanitized errors internally.

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
    query = f"SELECT id, email FROM users ORDER BY {sort_col} DESC"  # safe because sort_col is whitelisted
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()
```

## Hashing and password storage rules (addresses B324)
- Forbidden: MD5 or SHA1 for password hashing, token signing, HMAC, or any security-sensitive function.
- Required: use Argon2 (argon2-cffi) or passlib wrappers. Acceptable fallback only with documented justification: bcrypt or scrypt (documented in PR).
- Use SHA-256 or better for non-security integrity or checksums.
- Legacy MD5 allowed only when ALL the following are satisfied:
  - Code uses hashlib.md5(..., usedforsecurity=False) (Python 3.9+).
  - Inline code comment documents the non-security-only purpose and references SECURITY_EXCEPTIONS.md.
  - The PR description contains a business justification and link to an approved entry in SECURITY_EXCEPTIONS.md.
  - A security review approval is recorded in SECURITY_EXCEPTIONS.md.
- The assistant must refuse any MD5/SHA1 usage for security purposes and provide an Argon2-based alternative.

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

## Assistant generation constraints (enforced for every response that could include code)
- The assistant must scan its proposed code for forbidden constructs before returning it. If any forbidden construct is present, the assistant must refuse and return a secure alternative.
- All generated code must include:
  - Validation of all external inputs (types, maximum length, allowed characters).
  - Explicit server-side whitelists for commands and dynamic DB identifiers.
  - Exception handling that sanitizes logs and returns user-friendly errors.
- Examples must be realistic and ready for review (with comments and error handling).

## CI & automated enforcement (Bandit + grep; fail PRs introducing forbidden patterns)
- Add a GitHub Actions job named "security" that:
  - Runs Bandit.
  - Fetches changed files in the PR/commit range and scans only changed files for forbidden constructs via grep.
  - Fails the job (and thus the PR) if any forbidden patterns are detected.
  - Enforces MD5 exceptions: if hashlib.md5 appears in changed files, the CI requires (a) presence of usedforsecurity=False in the same file, (b) an inline comment referencing SECURITY_EXCEPTIONS.md, and (c) an approved entry in SECURITY_EXCEPTIONS.md; otherwise fail.
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
      - name: Run bandit (report only)
        run: bandit -r . -ll -f json -o bandit-output.json || true
      - name: Fail on forbidden patterns in diff
        shell: bash
        run: |
          set -euo pipefail
          # Determine changed files for the PR/commit
          git fetch --no-tags --depth=1 origin +refs/heads/*:refs/remotes/origin/* || true
          CHANGED_FILES=$(git diff --name-only HEAD origin/HEAD || git diff --name-only HEAD~1 || true)
          if [ -z "$CHANGED_FILES" ]; then
            echo "No changed files detected"; exit 0
          fi
          echo "Changed files:"
          echo "$CHANGED_FILES"
          # Forbidden pattern list (covers shell usage, SQL string building, and weak hashes)
          PATTERN='shell=True|subprocess\.[A-Za-z_]+\(.*shell=|\\bos\.system\(|\\bos\.popen\(|f"[^"]*SELECT|f'\"\"'[^']*SELECT|(\+|\%)-format.*SELECT|\bhashlib\.md5\b|\bhashlib\.sha1\b'
          # Check changed files for forbidden patterns (exclude venv)
          if git --no-pager grep -n -E "$PATTERN" $CHANGED_FILES -- ':!venv/*' ; then
            echo "Forbidden security patterns detected in changed files. See repository security policy for remediation." >&2
            exit 1
          fi
          # Special MD5 exception enforcement: if hashlib.md5 seen, require usedforsecurity=False and inline reference
          MD5_FILES=$(git --no-pager grep -l -E "\bhashlib\.md5\b" $CHANGED_FILES -- ':!venv/*' || true)
          if [ -n "$MD5_FILES" ]; then
            while read -r f; do
              echo "MD5 usage found in $f; enforcing exception requirements."
              # require usedforsecurity=False in the same file
              if ! grep -n "usedforsecurity=False" "$f" >/dev/null 2>&1; then
                echo "hashlib.md5 used without usedforsecurity=False in $f" >&2
                exit 1
              fi
              # require inline comment referencing SECURITY_EXCEPTIONS.md
              if ! grep -n "SECURITY_EXCEPTIONS.md" "$f" >/dev/null 2>&1; then
                echo "hashlib.md5 used without inline SECURITY_EXCEPTIONS.md reference in $f" >&2
                exit 1
              fi
            done <<< "$MD5_FILES"
            # require repository SECURITY_EXCEPTIONS.md contains an approval entry (simple existence check)
            if ! grep -q "MD5" SECURITY_EXCEPTIONS.md >/dev/null 2>&1; then
              echo "MD5 usage detected in diff but SECURITY_EXCEPTIONS.md lacks an approval entry." >&2
              exit 1
            fi
          fi
```

## Pre-commit hooks & PR bot
- Add pre-commit hooks to run:
  - bandit
  - the same grep detection used in CI (operates on staged files)
- Example .pre-commit-config.yaml:
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
        entry: grep -n --line-number -E "shell=True|subprocess\\.[A-Za-z_]+\\(.*shell=|\\bos\\.system\\(|\\bos\\.popen\\(|f\"[^\"']*SELECT|\\+\\s*\"[^\"']*SELECT|\\bhashlib\\.md5\\b|\\bhashlib\\.sha1\\b" -- ':!venv/*'
        language: system
        pass_filenames: false
```
- Configure a PR bot (or GitHub Checks) to scan diffs and post inline comments for any forbidden patterns and block merging until resolved.

## Minimal PR reviewer checklist (apply to AI-generated PRs)
- No use of shell=True, subprocess.* with shell=True, os.system(), or os.popen() on modified lines.
- All subprocess invocations use list arguments, shutil.which checks, server-side whitelists, and explicit validation of each argument.
- No SQL constructed via f-strings/concatenation with user input; parameterized queries or vetted ORM used. Any interpolated identifier validated against a server-side whitelist.
- No hashlib.md5 or hashlib.sha1 used for security-sensitive purposes. If MD5 appears, confirm usedforsecurity=False, inline justification including SECURITY_EXCEPTIONS.md reference, and an approved entry in SECURITY_EXCEPTIONS.md.
- CI security job and pre-commit hooks pass for the PR diff.

## Exceptions & maintenance
- MD5 exceptions (legacy, non-security) require:
  - Inline code comment documenting non-security-only purpose and referencing SECURITY_EXCEPTIONS.md.
  - Use of hashlib.md5(..., usedforsecurity=False).
  - Business justification and a link to an approved entry in SECURITY_EXCEPTIONS.md in the PR description.
  - Explicit security review approval recorded in SECURITY_EXCEPTIONS.md.
- Update this document whenever new scan patterns or vulnerabilities appear; adjust CI/grep rules accordingly.

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
- CI (Bandit + grep) and pre-commit hooks will block forbidden patterns introduced in diffs.
- All MD5 exceptions require usedforsecurity=False, an inline justification referencing SECURITY_EXCEPTIONS.md, and an approved entry in that file.
- Security reviews and PR checklist items are mandatory for any exception or deviation.