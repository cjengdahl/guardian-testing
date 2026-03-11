# AI Code Assistant — Security & Usage Instructions

## Overview
This instruction file defines secure coding, generation, and CI policies for the AI Code Assistant tool. It is intended to prevent unsafe serialization/deserialization patterns and unsafe YAML usage (the vulnerabilities flagged by automated scans: B301, B403, B506). The AI assistant must follow these rules when producing code, examples, or templates and the repository must enforce them with automated checks and code-review requirements.

## High-level policy (mandatory)
- Do not generate code that deserializes untrusted or network/externally-provided data with pickle, dill, shelve, joblib, or similar binary-Python serializers.
- Do not generate code that calls yaml.load(...) without explicitly using yaml.safe_load(...) or yaml.load(..., Loader=yaml.SafeLoader).
- Prefer text-based, schema-driven serialization (JSON, Protobuf, MessagePack with schema, or libraries like pydantic/marshmallow) and message authentication/integrity checks for data from untrusted sources.
- Any exception to the above (internal-only, fully-trusted data, or tooling scenarios) requires an explicit inline justification comment in the code and an approver from security during PR review.

## AI generation constraints (required for the assistant)
When generating code or modifying files, the assistant must:
- Never produce code that calls any of:
  - pickle.load, pickle.loads, pickle.Unpickler, pickle.Pickler
  - dill.load, dill.loads, dill.Unpickler
  - shelve.open used for exchanging untrusted data
  - joblib.load which may wrap pickle for persisted model files
  - yaml.load(...) without SafeLoader
- Replace any yaml.load(...) usage with one of:
  - yaml.safe_load(...)
  - yaml.load(stream, Loader=yaml.SafeLoader)
- Prefer and generate examples using safe alternatives (JSON, yaml.safe_load, protobuf, pydantic) and show integrity/authentication patterns where relevant.
- If the assistant must produce code that uses pickle-like mechanisms (for backward compatibility or strictly internal tooling), it must:
  - Include a clear inline comment describing why it is restricted to fully-trusted data and list the threat model.
  - Add a TODO or FIXME that requires a security review and link to the repository’s security approval process.
  - Not be generated as part of default examples or templates.
- Do not suggest third-party libraries that are thin wrappers around pickle/dill or that are known to deserialize arbitrary objects unless the assistant documents safe usage and alternatives.

## Secure patterns and examples

- Safe YAML loading (preferred):
```python
import yaml

# When loading YAML from any non-fully-trusted source, use safe_load
with open("config.yaml") as f:
    data = yaml.safe_load(f)
```

- Using SafeLoader explicitly:
```python
import yaml

with open("config.yaml") as f:
    data = yaml.load(f, Loader=yaml.SafeLoader)
```

- Safe JSON usage for interchange with untrusted sources:
```python
import json

with open("data.json") as f:
    data = json.load(f)
```

- Example: authenticated JSON payloads (integrity/authentication when receiving serialized data from an external source):
```python
import json
import hmac
import hashlib
from typing import Tuple

SECRET = b"repository-wide-secret"  # rotate and protect via secrets manager

def sign_payload(payload: bytes) -> str:
    return hmac.new(SECRET, payload, hashlib.sha256).hexdigest()

def verify_and_load_signed_json(payload_bytes: bytes, signature: str):
    expected = sign_payload(payload_bytes)
    if not hmac.compare_digest(expected, signature):
        raise ValueError("Invalid signature: payload integrity check failed")
    return json.loads(payload_bytes)
```

- Recommended alternative when serialising complex Python objects:
  - Use explicit schema formats: Protobuf, Avro, or MessagePack with a schema, or pydantic models with JSON encoding.
  - Example with pydantic:
```python
from pydantic import BaseModel

class Item(BaseModel):
    id: int
    name: str

# Serialize
item_json = Item(id=1, name="x").json()

# Deserialize (safe)
item = Item.parse_raw(item_json)
```

## Disallowed/flagged APIs (do not generate)
- pickle.load, pickle.loads, pickle.Unpickler, pickle.Pickler
- dill.load, dill.loads
- joblib.load (when used to load untrusted artifacts)
- any use of yaml.load(...) without SafeLoader
- shelve (for exchange of untrusted data)

If you see these in code generation, replace with a safe alternative and add a comment explaining the change.

## Repository enforcement (CI & pre-commit)
Add automated scans and blocking checks to ensure violations are caught before merge.

- GitHub Actions snippet (add to .github/workflows/security-scan.yml):
```yaml
name: security-scan
on: [push, pull_request]
jobs:
  bandit_scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install security tooling
        run: pip install bandit PyYAML
      - name: Run bandit
        run: |
          # Fail the job if bandit finds medium/high severity issues (default behavior)
          bandit -r . -lll
```
- Add a lightweight grep-based check to block common unsafe patterns (add to .github/actions or as a pre-commit hook). Example script (scripts/check_unsafe_serialization.py):
```python
#!/usr/bin/env python3
import sys
import re
from pathlib import Path

PATTERNS = [
    r"\bpickle\.(load|loads|Unpickler|Pickler)\b",
    r"\bdill\.(load|loads|Unpickler|Pickler)\b",
    r"\bjoblib\.load\b",
    r"\byaml\.load\b(?!\s*,\s*Loader=|\.safe_load\b)",
    r"\bshelve\.open\b",
]

def main():
    repo_root = Path(".")
    bad = []
    for p in repo_root.rglob("*.py"):
        text = p.read_text(encoding="utf8")
        for pat in PATTERNS:
            if re.search(pat, text):
                bad.append((p, pat))
    if bad:
        for p, pat in bad:
            print(f"Unsafe usage ({pat}) found in {p}")
        sys.exit(1)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```
- Hook this script as a pre-commit hook and in CI to fail PRs if unsafe constructs are found.
- Add bandit and the script to pre-commit configuration (.pre-commit-config.yaml), and require passing pre-commit in CI.

## Code-review and PR requirements
- Any PR that adds code touching serialization/deserialization or YAML:
  - Must include a short risk assessment in the PR description (source of data, threat model, why chosen format is safe).
  - Must reference security review if using non-text or non-schema formats.
  - Must address tooling warnings (Bandit, pre-commit checks) or include a justification for an approved exception (see Exceptions section).

## Exceptions & approvals
- Acceptable limited exception: use of pickle (or similar) for internal-only, never-written-to-disk, ephemeral, fully-trusted in-process caching where no untrusted input can reach the deserializer.
- Exception process:
  - Add an inline code comment explaining why it’s safe (data source, isolation boundaries, why alternative cannot be used).
  - Add a TODO linking to the PR and request approval from the repository security approver(s).
  - Record the exception and approval in the PR and relevant security backlog.

## Developer guidance and examples for reviewers
- When reviewing PRs, pay attention for:
  - Any use of yaml.load(...) without safe_load or SafeLoader.
  - Any appearance of pickle/dill/joblib/shelve or other binary Python serializers.
  - Third-party libraries that may internally use pickle-like deserialization for persisted artifacts (ML model loaders, plugin loaders).
- If detected, request changes to adopt safe alternatives, add HMAC/signatures, or move to schema-based formats.

## References and tools
- Use yaml.safe_load or yaml.load(..., Loader=yaml.SafeLoader) instead of yaml.load.
- Use JSON/Protobuf/Pydantic/Marshmallow for external interchange.
- Use bandit for automated static checks: https://bandit.readthedocs.io
- For stricter CI, block PRs when the repository script (scripts/check_unsafe_serialization.py) or bandit fails.

## Maintenance notes
- Keep the PATTERNS list in scripts/check_unsafe_serialization.py updated for new dangerous APIs discovered (e.g., new libraries that allow arbitrary object instantiation).
- Update CI tooling versions regularly and review bandit rules to ensure B301, B403, B506 and similar are enforced.
- Periodically audit dependencies that may deserialize data (ML model libs, plugin systems) and document safe usage patterns.

<!-- End of instruction file -->