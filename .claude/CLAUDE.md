# AI Code Assistant Security Instructions

- Enforce no hardcoded credentials or keys in generated code, examples, tests, or docs; always use placeholders and environment-backed secret retrieval.
- Require all HTTP calls in generated code to include explicit timeouts and sensible retry/backoff behavior.
- Add pre-commit and CI scanning (detect-secrets, bandit, regex) to reject secrets and missing-timeout patterns before merge.
- Provide canonical code patterns and short snippets for secret access and safe HTTP usage that the assistant must use in generated output.
- Specify assistant behavior when prompted to include secrets: redact, refuse, and provide secure alternatives and remediation steps.

## Purpose
These concise instructions govern how the AI Code Assistant must generate code and repository artifacts to prevent re-introduction of: hardcoded credentials (Bandit B105 / CWE-259) and requests without timeouts (Bandit B113 / CWE-400). They are minimal, prescriptive rules and example snippets the assistant must follow for this repository.

## Secret Handling Policy (Covers B105 / CWE-259)
- The assistant must never generate code that contains real credentials, API keys, passwords, private keys, or secret tokens.
- Replace any credential in generated code, docs, or examples with a clear placeholder (e.g., "<MY_API_KEY>" or os.getenv("MY_API_KEY")).
- Always prefer secure storage patterns:
  - Environment variables (os.getenv or os.environ).
  - Secret manager APIs (AWS Secrets Manager, Azure KeyVault, GCP Secret Manager).
  - CI/CD secret stores (e.g., GitHub Actions secrets) for pipeline injection.
- For tests and examples use mocking or ephemeral test-only fixtures (do not embed real secrets).
- If the user supplies a secret in a prompt:
  - Do not echo it into generated files. Replace occurrences with a placeholder and show how to load the secret from a secure source.
  - Advise the user to rotate any secret that was accidentally committed and to remove it from git history.

Example (Python, environment variable pattern):
```python
import os

# Secure pattern: no default secret in code
MY_API_KEY = os.getenv("MY_API_KEY")
if not MY_API_KEY:
    raise RuntimeError("MY_API_KEY must be set in environment or secret store")

# Use MY_API_KEY in API client initialization (do not print or log)
```

Example (AWS Secrets Manager):
```python
import boto3
import json
from botocore.exceptions import ClientError

def get_secret(secret_name, region_name="us-east-1"):
    client = boto3.client("secretsmanager", region_name=region_name)
    try:
        resp = client.get_secret_value(SecretId=secret_name)
        return json.loads(resp["SecretString"])
    except ClientError as exc:
        raise RuntimeError("Unable to retrieve secret") from exc
```

Guidance for generated examples and docs:
- Use placeholders like "<REDACTED_API_KEY>" and show the exact env var name to set.
- Use mocking libraries in tests (e.g., unittest.mock, pytest-mock) — include short code snippet demonstrating mocking.

Remediation steps the assistant should include if it flags an accidental secret:
- Remove secret from code and replace with placeholder.
- Rotate/replace the compromised credential immediately.
- Remove secret from VCS history (git filter-repo or BFG) and validate removal.
- Add the secret to secret scanning baselines so similar secrets are caught.

## Network Calls and Timeouts Policy (Covers B113 / CWE-400)
- All generated HTTP/HTTPS calls must include an explicit timeout parameter. Do not rely on library defaults.
- Prefer short, sensible timeouts (e.g., connect=3s, read=10s) and recommend configurable timeout constants.
- Provide small helper wrappers or session patterns to centralize timeouts and retry logic.

Example (requests, safe default timeout and wrapper):
```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_TIMEOUT = (3, 10)  # (connect_timeout, read_timeout)

def requests_session_with_retries(retries=3, backoff_factor=0.3, status_forcelist=(500,502,503,504)):
    session = requests.Session()
    retry = Retry(total=retries, backoff_factor=backoff_factor, status_forcelist=status_forcelist)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

# Usage: always pass timeout
session = requests_session_with_retries()
resp = session.get("https://api.example.com/data", timeout=DEFAULT_TIMEOUT)
resp.raise_for_status()
```

Minimal example (single request):
```python
import requests

resp = requests.get("https://api.example.com/data", timeout=(3, 10))
```

Assistant rule: For any generated code that calls requests (or other HTTP clients), include a timeout argument and recommend using a session with retries where appropriate.

## Static Scanning and Pre-commit / CI (Prevent recurrence)
- Add and maintain pre-commit hooks and CI steps that run secret scanning and static checks:
  - detect-secrets (or git-secrets/truffleHog) to find potential secrets
  - bandit for Python security checks (fail on B105, B113)
  - custom regex scans for common patterns (AWS access key ids starting with AKIA, long base64-like strings, private-key PEM blocks)
- The assistant should generate or update repository config snippets to include these checks.

Example .pre-commit-config.yaml snippet:
```yaml
repos:
- repo: https://github.com/Yelp/detect-secrets
  rev: v1.1.0
  hooks:
    - id: detect-secrets
      args: ['--baseline', '.secrets.baseline']
- repo: https://github.com/pre-commit/mirrors-mypy
  rev: v0.812
  hooks:
    - id: mypy
- repo: https://github.com/PyCQA/bandit
  rev: 1.7.0
  hooks:
    - id: bandit
```

Example GitHub Actions CI steps (concise):
```yaml
name: security-scan
on: [pull_request]
jobs:
  scans:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run detect-secrets
        run: pip install detect-secrets && detect-secrets scan > .secrets.baseline && detect-secrets audit .secrets.baseline
      - name: Run bandit
        run: pip install bandit && bandit -r . -ll -iii B101,B303 || exit 1
      - name: Run custom regex scan
        run: |
          git grep -n -I --hidden -E "(AKIA|ASIA|wJalrXUtnFEMI|SuperSecret123!)" || true
```
- CI must be configured to fail the build on any discovered hardcoded secret or on bandit rules B105/B113 violations.

## Generation Constraints & Assistant Behavior
- Never output real secrets. When asked, refuse to embed secrets and provide secure alternatives and templates.
- Always use placeholders in generated examples and include brief instructions for secret provisioning (env var, secret manager, CI injection).
- For network code, always add timeout and recommend a session + retry wrapper; include comments explaining why.
- If a user-provided code snippet contains hardcoded secrets, the assistant must:
  - Highlight and redact the secret in suggested edits.
  - Provide code to retrieve the secret from a secure source.
  - Provide remediation steps (rotate credential, scrub git history).
- The assistant should include unit-test-friendly patterns (dependency injection for clients, environment variable retrieval) and show how to mock secrets and HTTP calls in tests.

Example assistant refusal pattern:
- If user asks to "put my API key here", respond with a short refusal to embed secrets and supply a code snippet that reads the key from environment or secret manager.

## Detection Patterns to Include in Tooling
- Treat these patterns as high-priority signals and catch them in baseline scans:
  - Common plaintext examples: "SuperSecret123!", "password", "passwd", "secret"
  - AWS-looking access key ids: ^AKIA[0-9A-Z]{16}$
  - Probable secret keys (long base64/ASCII strings)
  - PEM private key headers: "-----BEGIN (RSA|PRIVATE) KEY-----"
- Flag any code that assigns string literals to variables like PASSWORD, API_KEY, SECRET_KEY, ACCESS_KEY, SECRET_ACCESS_KEY.

## Remediation Checklist (what the assistant should recommend when a secret is found)
- Immediately remove the secret from the repository and replace with a placeholder.
- Rotate / revoke the exposed credential.
- Purge the secret from git history using a tool such as git-filter-repo or BFG and push force-update protected by policies.
- Add the secret pattern to detect-secrets baseline and CI rules to prevent recurrence.
- Add an entry to the incident log describing the leak and mitigation performed.

## Minimal Boilerplate Templates the Assistant May Insert
- Environment-backed config snippet:
```python
# config.py
import os
from typing import Any

def get_required_env(name: str) -> str:
    val = os.getenv(name)
    if not val:
        raise RuntimeError(f"Environment variable {name} is required")
    return val

API_KEY = get_required_env("MY_API_KEY")
```

- HTTP client wrapper (always include timeout and retries):
```python
# http_client.py
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_TIMEOUT = (3, 10)

def create_session(retries=3):
    s = requests.Session()
    retry = Retry(total=retries, backoff_factor=0.2, status_forcelist=(500,502,503,504))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    return s

def get(url, session=None, timeout=DEFAULT_TIMEOUT, **kwargs):
    session = session or create_session()
    return session.get(url, timeout=timeout, **kwargs)
```

## Enforcement & Maintenance
- Ensure repository templates, CONTRIBUTING.md, and the assistant’s generation templates conform to these rules.
- Periodically update detect-secrets baselines and CI patterns to catch novel secret formats.
- Keep bandit and request-timeout rules enabled and failing in CI.

By following these instructions, the AI Code Assistant will avoid producing hardcoded credentials and will always generate network code that includes explicit timeouts and robust retry handling, while tooling and CI will prevent regression.