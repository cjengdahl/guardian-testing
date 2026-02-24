# guardian-testing

A test repository demonstrating [Guardian Action](https://github.com/SecurityJourney/guardian-action) — a GitHub Action that automatically updates AI instruction files based on security scan results.

## How it works

1. A pull request is opened with Python code changes
2. [Bandit](https://bandit.readthedocs.io/) scans the changed `.py` files for vulnerabilities
3. Guardian Action sends the results + the AI instruction file to the Guardian API
4. The API analyzes the vulnerabilities and updates `.claude/CLAUDE.md` with security guidance
5. The updated instruction file is auto-committed back to the PR branch

## Setup

Add your Guardian API token as a repository secret:

```
Settings → Secrets and variables → Actions → New repository secret
Name: GUARDIAN_API_TOKEN
```

## Repository structure

```
.
├── app.py                          # Sample Python app (contains intentional vulnerabilities)
├── .claude/
│   └── CLAUDE.md                   # AI instruction file — updated automatically by Guardian
└── .github/
    └── workflows/
        └── security-scan.yml       # Bandit + Guardian Action workflow
```

## Triggering the workflow

Open a pull request that modifies any `.py` file. The workflow will run automatically on `pull_request` events (`opened`, `synchronize`).

## Vulnerabilities in app.py

`app.py` contains three intentional issues used to demonstrate Guardian:

| Issue | Bandit ID | Description |
|-------|-----------|-------------|
| SQL injection | B608 | String-concatenated SQL query |
| Shell injection | B602 | `subprocess.call` with `shell=True` |
| Weak hash | B324 | MD5 used for password hashing |
