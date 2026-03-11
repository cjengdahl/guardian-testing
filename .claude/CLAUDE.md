# AI Code Assistant Security Guidelines

## Revision checklist (high-level plan)
- Replace any literal secrets in generated code with explicit placeholders and enforce environment/secret-manager patterns.
- Enforce network-call rules: explicit timeouts, retries/backoff, and error handling in all generated code.
- Add/require CI and pre-commit gates (detect-secrets, bandit, regex checks) that fail PRs on findings and produce remediation guidance.
- Require automatic secret-rotation & git-history scrub guidance on any detected exposure; refuse to re-emit leaked secrets.
- Add generation-time validation in the assistant: scan outputs for secret patterns and deny or sanitize outputs that would reintroduce hardcoded credentials.

## Purpose / Scope
These guidelines govern the AI Code Assistant tool so it never emits hardcoded credentials (addressing B105) or network calls without timeouts (addressing B113), and so the repository contains CI/pre-merge enforcement and clear remediation for any discovered exposures. They apply to all generated code, examples, tests, docs, and PRs produced by the assistant.

## Core Policies for Generated Code
- Never emit real secrets, tokens, API keys, passwords, or private keys. Use only clearly-labeled placeholders (e.g., <DB_PASSWORD>, REDACTED_SECRET, EXAMPLE_KEY_XXXX) or environment variable names (e.g., os.environ["DB_PASSWORD"]).
- Never emit realistic-looking credentials or secret-like strings that match common patterns (AWS access key, OAuth tokens, private key headers, etc.). If a user requests example credentials, provide only obvious dummy placeholders and a prior brief warning explaining why.
- All outbound network calls must include explicit timeouts and robust error handling. Use retries and backoff where appropriate. Do not rely on implicit library defaults.
- Generated configuration must obtain secrets via:
  1. Secret Manager SDK (preferred) with placeholder secret names.
  2. Environment variables (os.environ, dotenv).
  3. Encrypted config files decrypted by a KMS/secret-manager (show SDK use with placeholders).
- Any code or doc example that would otherwise include a secret must include a comment pointing to how to supply the secret securely (env var, secret manager, CI secret store).

## Assistant Generation Enforcement (must be implemented in the tool)
- Pre-output scanning: before returning code, the assistant must scan generated text for secret patterns (literal secrets, common key formats, high-entropy strings, password-like tokens) using detect-secrets-style checks and regex for common cloud key formats. If any match:
  - Replace the detected value(s) with a clear placeholder (e.g., <REDACTED_SECRET> or ENV var name).
  - Insert a comment explaining where to store and load the secret (secret manager/env).
  - Add a short remediation note instructing to rotate and scrub any leaked values if they already exist in the repo.
  - If the user explicitly requests reproducing an identified leaked secret or the exact string, refuse and provide remediation instructions instead.
- Generation-time CI suggestion: automatically include (or update) a .github/workflows/security-scan.yml snippet in PRs that adds detect-secrets and bandit (or language equivalents) to the repo if not present.
- If a previously generated output in the session included a secret, proactively notify the user and provide remediation steps rather than repeating the secret.

## Secret Management Requirements (B105)
- Use the preferred order for secrets:
  1. Secret Manager (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) — show SDK usage with placeholder secret name.
  2. Environment variables — demonstrate loading and validate presence.
  3. Encrypted files — show decryption via KMS/secret-manager.
- All examples must use placeholders. Example (Python env var):
```python
import os
from typing import Optional

def get_db_password() -> Optional[str]:
    # Do NOT hardcode credentials. Set DB_PASSWORD in your CI/secret manager and inject into env.
    return os.environ.get("DB_PASSWORD")  # placeholder: set DB_PASSWORD securely
```
- Example (AWS Secrets Manager, Python):
```python
import boto3
import json
from botocore.exceptions import ClientError

def get_secret(secret_name: str, region: str = "us-east-1") -> dict:
    # secret_name must be a placeholder like "my-app/db-password"
    client = boto3.client("secretsmanager", region_name=region)
    try:
        resp = client.get_secret_value(SecretId=secret_name)
        secret_string = resp.get("SecretString")
        return json.loads(secret_string) if secret_string else {}
    except ClientError as exc:
        # propagate or handle specific errors; do not log secrets
        raise
```
- Example .env.example:
```env
DB_USER=example_user
DB_PASSWORD=<DB_PASSWORD_PLACEHOLDER>
```
- Tests must never include real credentials. Use fixtures that load from environment variables or test secrets from a CI-managed secret store.

## Network Calls & Timeouts (B113)
- Every generated HTTP call must include an explicit timeout and error handling. Prefer separate connect/read timeouts where supported and implement retries/backoff for idempotent requests.
- Python requests example with retries and explicit timeouts:
```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def make_session(retries: int = 3, backoff: float = 0.5) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=retries, backoff_factor=backoff, status_forcelist=[429, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session

def fetch_json(url: str, timeout: tuple = (3.0, 10.0)):
    session = make_session()
    try:
        resp = session.get(url, timeout=timeout)  # timeout: (connect, read)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        # Handle or propagate without leaking sensitive data in logs
        raise
```
- Async example (aiohttp):
```python
import aiohttp
import asyncio

async def fetch_async(url: str, timeout_total: float = 10.0):
    timeout = aiohttp.ClientTimeout(total=timeout_total)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            async with session.get(url) as resp:
                resp.raise_for_status()
                return await resp.json()
        except aiohttp.ClientError:
            raise
```
- Where libraries do not support separate timeouts, always use a finite overall timeout and document recommended values.

## CI / Pre-merge Scans and Enforcement
- Every generated PR must include or require the repository to have CI jobs that run on pull_request and fail on findings:
  - Secret detection: detect-secrets, truffleHog, or equivalent. Fail the job if any new secrets are found.
  - Static analysis: bandit (or language-equivalent) configured to fail on rules covering hardcoded secrets (B105) and network timeouts (B113).
  - Lint/format: pre-commit with detect-secrets and bandit hooks.
- Example GitHub Actions job (fails on findings):
```yaml
name: security-scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.10"
      - name: Install security tools
        run: pip install detect-secrets bandit
      - name: Run detect-secrets
        run: |
          detect-secrets scan > .secrets.new || true
          if detect-secrets-hook --baseline .secrets.baseline --diff .secrets.new; then
            echo "::error::Secrets detected in PR"
            exit 1
          fi
      - name: Run bandit
        run: |
          bandit -r . -lll -ii || exit $?
```
- CI output must include remediation instructions and a link to rotation & scrub guidance when secrets are found.
- Enforce branch-protection rules to deny merge unless the security-scan job passes.

## Pre-commit / Local Hooks
- Provide and require a pre-commit configuration that includes detect-secrets and bandit hooks. Example .pre-commit-config.yaml snippet:
```yaml
repos:
- repo: https://github.com/Yelp/detect-secrets
  rev: v1.0.3
  hooks:
    - id: detect-secrets
- repo: https://github.com/PyCQA/bandit
  rev: 1.7.4
  hooks:
    - id: bandit
```
- Developers must run detect-secrets locally before committing; CI must enforce the same baseline.

## Remediation Guidance (If secrets are detected)
- Immediate steps (required in PR description and automated CI comment):
  1. Rotate the exposed credential(s) immediately with the provider (DB, cloud IAM, API provider).
  2. Remove the secret from the repository and all branches. Rewrite history using git filter-repo or BFG, then force-push a scrubbed branch.
     - git filter-repo example:
       ```bash
       pip install git-filter-repo
       git clone --mirror git@github.com:org/repo.git
       cd repo.git
       git filter-repo --path <file-containing-secret> --invert-paths
       git push --force --all
       git push --force --tags
       ```
     - BFG example:
       ```bash
       java -jar bfg.jar --delete-files <filename> repo.git
       ```
  3. Update the PR with a short incident note documenting which credentials were rotated and which systems were affected.
  4. Re-run detect-secrets and CI scans after history rewrite to confirm no remaining exposures.
- If the assistant previously emitted the secret in the same session, include the session note in the PR and explain steps that were taken.

## Tests, Examples, and Documentation
- Example files and tests must use placeholders and environment variables only. Provide .env.example and CONTRIBUTING snippet instructing developers to never commit .env with secrets.
- README must include a "Secrets and Configuration" section describing:
  - How to use secret manager or environment variables for local development.
  - How CI injects secrets into builds.
  - How to rotate and scrub secrets if leaked.

## Minimal Safe Templates (for quick reuse)
- Python env var template:
```python
import os

SECRET = os.environ.get("MY_SERVICE_SECRET")
if not SECRET:
    raise RuntimeError("MY_SERVICE_SECRET not set; see README for secure setup")
```
- Python requests template:
```python
import requests

def http_get(url: str, timeout=(3.0, 10.0)):
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException:
        raise
```

## Logging and Secrets
- Never log secrets or secret-like values. Mask or redact sensitive fields before logging. Use structured logs and ensure logging frameworks do not inadvertently record environment variables or responses that contain secrets.

## Detection Rules / Patterns (for implementers)
- The assistant/tool must include built-in regex checks for:
  - Common cloud keys (AWS access key IDs: ^AKIA[0-9A-Z]{16}$, etc.), OAuth tokens, JWTs, private key PEM headers, Base64 high-entropy strings, and common password-like patterns.
- Any match must trigger the pre-output sanitization rules above.

## PR/Contributor Requirements
- PRs produced by the assistant must include:
  - A short note if any placeholders replaced previously committed secrets and guidance to rotate/scrub.
  - An enforced checklist confirming that detect-secrets and bandit run and pass.
  - A link to the README "Secrets and Configuration" and the incident note if applicable.

## Notes for Maintainers / Implementation Checklist
- Add detect-secrets baseline, pre-commit config, and security-scan CI workflow to the repository.
- Configure CI to fail on new detections and show remediation guidance.
- Educate contributors: add CONTRIBUTING.md snippet instructing not to commit secrets and how to use .env.example and secret manager.
- Review and update the detect-secrets baseline carefully before adding exceptions; prefer no exceptions for secret-like patterns.

By enforcing these rules within the AI Code Assistant tool and the repository CI, the assistant will avoid generating hardcoded secrets (B105) and network calls without explicit timeouts/retries (B113), and the repository will have robust pre-merge protections and clear remediation steps for any accidental exposures.