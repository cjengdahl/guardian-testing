# AI Code Assistant — Security and Code-Generation Instructions

This instruction file defines secure coding, dependency, and generation policies for the AI Code Assistant tool (Guardian Action integrated). It focuses on preventing the generation of known insecure crypto patterns detected by recent vulnerability scans (deprecated pyCrypto/ DES/ARC4 usage, insecure RNG usage, and weak hashes such as MD5/SHA1). Follow these rules when generating, modifying, or repairing code.

## Policies (must be enforced on every generated change)
- Never introduce or reintroduce pyCrypto (package name: crypto/pycrypto) or any Crypto.Cipher.* usage. If code references pyCrypto or Crypto.Cipher, replace it with pyca/cryptography or other endorsed modern libraries.
- Do not use legacy/insecure ciphers (DES, 3DES, RC4/ARC4). Use AEAD ciphers such as AES-GCM, AES-CCM, or ChaCha20-Poly1305 for authenticated encryption.
- Do not use the stdlib random module (random.random/choice/randint) for any security-sensitive purpose (key generation, nonces, tokens, salts). Use the secrets module or cryptography-provided secure RNGs.
- Do not use MD5 or SHA1 for security (hashing passwords, signatures, HMAC, checksums for tamper detection). Use SHA-2 family (sha256/sha512) or SHA-3 for security-sensitive hashing. For password storage, use Argon2, bcrypt, or scrypt.
- For any non-security use of MD5/SHA1 (e.g., checksums where collision resistance is not required), document the justification and mark the call with usedforsecurity=False where supported, and include an automated scan allowance comment.
- Always provide a short security rationale/comments in generated code explaining choice of algorithm, key sizes, and nonce/IV handling.
- When generating dependency updates, update requirements.txt/pyproject.toml and include pinned/minimum safe versions. New code using cryptography must add/update cryptography >= 3.3.2 (or a current secure maintenance release).

## Secure Cryptography Requirements (code-level rules)
- Key sizes and algorithms:
  - AES: use 128/192/256-bit keys; prefer AES-256 for confidentiality where appropriate.
  - Use authenticated modes (AES-GCM, AES-CCM) or ChaCha20-Poly1305. Do not use AES in ECB/CBC without an AEAD construction and proper authentication.
- Nonces/IVs:
  - Nonces/IVs must be unique per key. Use cryptographically secure random nonces or counter-based nonces as required by the algorithm. Never use predictable values (timestamps or sequential numbers) unless algorithm-spec requires and is correctly implemented.
  - For AES-GCM use 12-byte nonces when possible.
- Key generation and storage:
  - Generate keys using secrets.token_bytes() or cryptography utilities. Protect keys at rest (do not hard-code).
  - Use KDFs for deriving keys from passwords (PBKDF2HMAC with adequate iterations and salt, or prefer Argon2).
- Hashing:
  - Use hashlib.sha256/sha512 or cryptography.hazmat.primitives.hashes.SHA256/SHA512 for security-sensitive uses.
  - For message authentication use HMAC with SHA-256 (hmac/HMAC from cryptography) or use AEAD ciphers instead.
- Randomness:
  - Use secrets.token_bytes(), secrets.token_urlsafe(), os.urandom(), or cryptography.hazmat.primitives.osrandom_engine() for security randomness.
  - Do not use random.SystemRandom as a substitute without explicit justification — prefer secrets for clarity.

## Required library choices and migration guidance
- Replace pyCrypto/Crypto.* usages with pyca/cryptography or cryptography.io high-level APIs.
- Examples:

AES-GCM (cryptography) example
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

# Generate a 256-bit key
key = secrets.token_bytes(32)
aesgcm = AESGCM(key)

# 12-byte nonce is recommended for AES-GCM
nonce = secrets.token_bytes(12)
plaintext = b"secret message"
aad = b"associated data"
ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
# Decrypt
decrypted = aesgcm.decrypt(nonce, ciphertext, aad)
```

ChaCha20-Poly1305 example
```python
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import secrets

key = secrets.token_bytes(32)
aead = ChaCha20Poly1305(key)
nonce = secrets.token_bytes(12)  # 12-bytes is common
ct = aead.encrypt(nonce, b"plaintext", b"aad")
pt = aead.decrypt(nonce, ct, b"aad")
```

Secure hashing and HMAC (sha256) example
```python
import hashlib
import hmac

data = b"message"
digest = hashlib.sha256(data).digest()

# HMAC
key = secrets.token_bytes(32)
tag = hmac.new(key, data, hashlib.sha256).digest()
```

Key derivation (PBKDF2HMAC) example
```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets, base64

password = b"correcthorsebatterystaple"
salt = secrets.token_bytes(16)
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
key = kdf.derive(password)
```

Migration tips
- Code that contains:
  - "from Crypto.Cipher import DES" or "Crypto.Cipher.DES.new(...)" -> migrate to AESGCM/ChaCha20Poly1305; adjust API accordingly.
  - "Crypto.Cipher.ARC4.new(...)" or RC4/ARC4 usage -> migrate to ChaCha20-Poly1305 or AES-GCM.
  - "import Crypto" or "pycrypto" in requirements -> remove and add "cryptography" with an appropriate pinned version.
- If encountering legacy formats (DES-encrypted data), do not attempt to "fix" by re-implementing DES. Preserve compatibility only where required, and add security migration plans (re-encrypting data with AES-GCM and rotating keys).

## Code-generation constraints and required outputs from the AI
When the AI Code Assistant generates or updates code, it must:
- Never output examples that use Crypto.Cipher.*, DES, ARC4, md5(), sha1(), or random for security.
- Include a one-paragraph security rationale in the code comment header for any crypto-related file explaining chosen algorithms, key sizes, nonce policy, and why insecure primitives were avoided.
- Provide unit tests exercising encryption/decryption and verifying nonce uniqueness/non-reuse where applicable.
- Provide dependency updates (requirements.txt, pyproject.toml) with pinned safe versions and a short migration note in the PR description.
- Add or update static analysis configuration (see CI section) so subsequent PRs are automatically scanned for regressions.

## CI / Scanning / Pre-commit configuration (required)
- Ensure repository CI runs the following checks on every PR:
  - bandit (security linter for Python)
  - pip-audit or pipdeptree/pip-audit to detect vulnerable dependencies
  - A small grep-based blacklist scan to fail PRs that contain banned patterns (fail-fast for the most critical issues)
    - Patterns to scan (case-sensitive): "from Crypto", "import Crypto", "Crypto.Cipher", "DES.new", "ARC4", "hashlib.md5(", "hashlib.sha1(", "random.random(", "random.choice(", "random.randint("
  - Optionally: safety / pip-audit to catch known package vulnerabilities

Example GitHub Actions snippet (add to .github/workflows/crypto-scan.yml)
```yaml
name: crypto-scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install tooling
        run: pip install bandit pip-audit
      - name: Run bandit
        run: bandit -r .
      - name: Fail on banned crypto patterns
        run: |
          set -eu
          patterns=("from Crypto" "import Crypto" "Crypto.Cipher" "DES.new" "ARC4" "hashlib.md5(" "hashlib.sha1(" "random.random(" "random.choice(" "random.randint(")
          matches=0
          for p in "${patterns[@]}"; do
            if grep -R --line-number --exclude-dir=.venv --exclude-dir=.git --exclude='*.pyc' "$p" .; then
              matches=$((matches+1))
            fi
          done
          if [ "$matches" -gt 0 ]; then
            echo "Banned crypto pattern(s) found. Please remove deprecated/insecure usage (DES/ARC4/md5/sha1/random)."
            exit 1
          fi
      - name: pip-audit
        run: pip-audit
```

Pre-commit hooks (add to .pre-commit-config.yaml)
```yaml
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: v1.7.5
    hooks:
      - id: bandit
  - repo: local
    hooks:
      - id: banned-crypto-patterns
        name: banned-crypto-patterns
        entry: bash -c 'python scripts/check_banned_crypto.py'
        language: system
        files: \.py$
```
Provide scripts/check_banned_crypto.py that mirrors the CI grep checks and exits non-zero on matches.

## Dependency guidance
- Add or update requirements with a pinned cryptography package:
  - Example: cryptography>=40.0.0 (use latest vetted release)
- Remove pycrypto/crypto packages; if legacy compatibility is required, document a migration plan and add an exception only after review.
- Run pip-audit/pipdeptree and add remediation steps in the PR.

## Documentation and PR checklist
For any PR that adds/changes crypto code, include:
- Which insecure patterns were removed and what replaced them.
- Updated requirements and their pinned versions.
- Unit tests demonstrating correct behavior and tests ensuring nonces are unique and decrypt properly.
- Statement that bandit/pip-audit ran cleanly and CI scanning passed.

## When MD5/SHA1 must be used (rare, legacy)
- If a non-security use justifies MD5/SHA1 (e.g., non-adversarial checksum for caching), include:
  - A clear inline comment explaining the non-security justification.
  - Use hashlib.new('md5', data, usedforsecurity=False) when running on Python versions that support usedforsecurity (and still include justification).
  - Add a TODO or migration ticket to move off MD5/SHA1 as soon as feasible.

## Enforcement for the AI Code Assistant tool
- The assistant must refuse to produce code that violates the above policies. If asked to reproduce legacy insecure code, provide a migration plan and secure alternative rather than insecure sample code.
- For every code generation involving cryptography, the assistant must:
  - Add a security rationale comment.
  - Add/modify tests and dependency pins.
  - Add or update CI/pre-commit configuration to detect regressions.

---

This file is maintained by Guardian Action. Additions to these instructions must preserve the prohibition of pyCrypto/Crypto.Cipher/ DES/ARC4, the avoidance of insecure RNG and weak hashes, and the requirement for CI scanning and dependency updates.