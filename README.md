# Secure CI/CD Pipeline

A GitHub Actions pipeline that enforces **four automated security gates** on every push and pull request. Vulnerable code is blocked before it can merge — not caught after deployment.

**Live demo:** open a PR from the `vuln-demo` branch to see all four gates trigger and block the merge.

---

## How the pipeline works

```
Push / Pull Request
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│  GATE 1 ── Secrets Detection          Gitleaks                  │
│            Scans full git history for credentials               │
│            ↓ BLOCKS on any matched secret                       │
│                                                                 │
│  GATE 2 ── Static Analysis (SAST)     CodeQL                    │
│            Traces data flow for injection, path traversal, etc. │
│            ↓ BLOCKS on error-level findings                     │
│                                                                 │
│  BUILD ─── Docker image               docker/build-push-action  │
│            Multi-stage, non-root, read-only filesystem          │
│            ↓                                                    │
│                                                                 │
│  GATE 3 ── Container Scanning         Trivy                     │
│            CVEs in OS packages + pip dependencies               │
│            ↓ BLOCKS on unfixed HIGH/CRITICAL CVEs               │
│                                                                 │
│  GATE 4 ── Dynamic Analysis (DAST)    OWASP ZAP                 │
│            Spins up the live container, active + passive scan   │
│            ↓ BLOCKS on FAIL-severity HTTP security alerts       │
│                                                                 │
│  SUMMARY ─ Aggregated gate result                               │
│            Required status check → blocks PR merge              │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼
  ✅ Safe to deploy  /  ❌ Blocked with findings in Security tab
```

All findings are uploaded as SARIF and surface in **GitHub → Security → Code scanning alerts**, giving a single triage interface across all four tools.

---

## Why these four tools

Each layer catches a different class of vulnerability that the others miss.

### Gitleaks — Secrets detection

Secrets committed to git history are permanently compromised, even after deletion. Gitleaks scans the **entire commit history** (not just the diff) against 130+ patterns covering AWS keys, GitHub tokens, private keys, connection strings, and more.

It runs **first** as a fast-fail: no point spending 5 minutes on SAST if a hardcoded credential is already in the tree.

Configured via `.gitleaks.toml` with custom rules for Flask `SECRET_KEY`, database URLs, and internal API keys, plus an allowlist to suppress false positives in test fixtures.

### CodeQL — Static Application Security Testing (SAST)

CodeQL models code as a queryable database and traces **data flow** from untrusted input sources (HTTP parameters, environment variables) to dangerous sinks (SQL queries, shell commands, file paths). This catches vulnerabilities that regex-based scanners miss because it understands control flow.

Uses the `security-extended` query suite, which covers:
- SQL injection, command injection, path traversal
- Hardcoded credentials and weak cryptography
- Insecure deserialization and unsafe reflection
- XSS and open redirect

The gate script parses the SARIF output and fails the build on any `error`-level finding. `warning`-level findings are visible in the Security tab but do not block.

### Trivy — Container scanning

A container is a supply-chain artifact: it bundles the OS, system libraries, and language packages, each of which may have known CVEs. Trivy scans the **built image** (not just `requirements.txt`) because the OS layer is invisible to pip-based scanners.

Three passes:
1. **Image CVEs** — OS packages and pip dependencies in the built image  
2. **Filesystem** — source repo for secrets and Dockerfile misconfigurations  
3. **IaC** — Dockerfile best-practice checks (non-root user, HEALTHCHECK, etc.)

The gate blocks on `HIGH` and `CRITICAL` unfixed CVEs. CVE exceptions require an entry in `.trivyignore` with written justification and a review date.

### OWASP ZAP — Dynamic Application Security Testing (DAST)

SAST analyses source code; DAST tests the **running application**. ZAP discovers vulnerabilities that only appear at runtime: missing security headers, CSRF exposure, authentication bypass, and injection surfaces that weren't visible statically.

The workflow spins up the exact Docker image that passed Trivy (same artifact), seeds test data, then runs a baseline scan (passive spider + active checks). Alert handling is controlled per-rule in `.github/zap/zap-rules.tsv`:

| Classification | Effect |
|---|---|
| `FAIL` | Non-zero exit → pipeline blocked |
| `WARN` | Logged in report, does not block |
| `IGNORE` | Suppressed entirely |

---

## Security gates demo

The `vuln-demo` branch contains intentional vulnerabilities to show each gate triggering. Open a PR from it to `main` and observe:

| Gate | Finding | Vulnerable code |
|------|---------|----------------|
| Gitleaks | Hardcoded API key | `examples/vulnerable_app.py:7` |
| CodeQL | SQL injection (CWE-89) | `examples/vulnerable_app.py:26` |
| CodeQL | OS command injection (CWE-78) | `examples/vulnerable_app.py:34` |
| CodeQL | Path traversal (CWE-22) | `examples/vulnerable_app.py:40` |
| Trivy | Depends on base image CVE state | Image scan |
| ZAP | Missing security headers | Runtime scan |

To create the demo branch:
```bash
git checkout -b vuln-demo
# CodeQL scans app/ — move or copy examples/vulnerable_app.py there temporarily
cp examples/vulnerable_app.py app/vulnerable_routes.py
git add app/vulnerable_routes.py
git commit -m "demo: add vulnerable routes to trigger security gates"
git push origin vuln-demo
# Open PR: vuln-demo → main
```

---

## Repository structure

```
.
├── .github/
│   ├── codeql/
│   │   └── codeql-config.yml       # Query suite (security-extended) + path filters
│   ├── scripts/
│   │   └── zap-to-sarif.py         # Converts ZAP JSON report → SARIF 2.1.0
│   ├── workflows/
│   │   └── security-pipeline.yml   # All four gates + summary job
│   ├── zap/
│   │   └── zap-rules.tsv           # Per-alert FAIL / WARN / IGNORE thresholds
│   └── dependabot.yml              # Weekly updates: Actions, pip, Docker base image
├── app/
│   ├── app.py                      # Hardened Flask REST API (the scan target)
│   ├── docker-compose.yml          # Local development
│   ├── Dockerfile                  # Multi-stage, non-root, read-only filesystem
│   └── requirements.txt
├── examples/
│   └── vulnerable_app.py           # Annotated vulnerable code — gates demo
├── .gitleaks.toml                  # Custom rules + allowlist
├── .trivyignore                    # CVE exceptions (require justification)
├── SECURITY.md                     # Disclosure policy + gate configuration guide
└── README.md
```

---

## What the target application demonstrates

`app/app.py` is a Flask REST API written to show secure-by-default patterns — the contrast to `examples/vulnerable_app.py`:

| Concern | Secure implementation |
|---------|----------------------|
| SQL queries | Parameterized (`?` placeholders) — no string formatting |
| Password storage | PBKDF2-SHA256, 260,000 iterations, per-user random salt |
| Security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options on every response |
| Rate limiting | Per-endpoint limits via `flask-limiter` |
| Input validation | Length, type, and character class checks before any processing |
| Container user | UID 1001 non-root, read-only filesystem, all capabilities dropped |

---

## Setup

### 1. Push to GitHub

```bash
git init
git remote add origin https://github.com/<org>/secure-cicd-pipeline.git
git add .
git commit -m "feat: secure CI/CD pipeline with four security gates"
git push -u origin main
```

### 2. Enable Code Scanning

**Settings → Security → Code security:**
- ✅ Dependency graph  
- ✅ Dependabot alerts + security updates  
- ✅ Code scanning (CodeQL + Trivy + ZAP SARIF upload here)  
- ✅ Secret scanning  

### 3. Require the gate as a merge check

**Settings → Branches → Add rule → `main`:**
```
✅ Require status checks to pass before merging
   → Required check: "Security Gate Summary"
✅ Require branches to be up to date before merging
✅ Require signed commits
✅ Do not allow bypassing the above settings
```

With this in place, no PR can merge unless all four gates pass.

### 4. Optional secrets

| Secret | Purpose |
|--------|---------|
| `GITLEAKS_LICENSE` | Advanced Gitleaks ruleset (private repos) |

---

## Running locally

```bash
# Start the API
cd app && docker-compose up --build

# Test endpoints
curl http://localhost:5000/health
curl -X POST http://localhost:5000/api/users \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"Str0ng!Pass"}'
curl -X POST http://localhost:5000/api/items \
     -H "Content-Type: application/json" \
     -d '{"name":"Widget","description":"A test item"}'

# Run Gitleaks
docker run --rm -v "$(pwd):/repo" zricethezav/gitleaks:latest \
  detect --source=/repo -c /repo/.gitleaks.toml -v

# Run Trivy
trivy image --severity HIGH,CRITICAL secure-api:local

# Run ZAP baseline
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://host.docker.internal:5000 -I
```

---

## Adjusting thresholds

| File | What to change |
|------|---------------|
| `.github/workflows/security-pipeline.yml` | `FAIL_SEVERITY` env var (`CRITICAL` / `HIGH` / `MEDIUM`) |
| `.github/codeql/codeql-config.yml` | Query suites, `paths`, `paths-ignore` |
| `.github/zap/zap-rules.tsv` | Per-alert `FAIL` / `WARN` / `IGNORE` |
| `.trivyignore` | CVE exceptions with justification comments |
| `.gitleaks.toml` | Custom patterns and allowlist entries |

---

## License

MIT
