# Secure CI/CD Pipeline

A production-ready GitHub Actions pipeline that enforces **four sequential security gates** before any code can merge or deploy.

```
Push / PR
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  Gate 1 — Secrets Detection          Gitleaks           │
│  ↓ (blocks on any leaked credential)                    │
│  Gate 2 — Static Analysis (SAST)     CodeQL             │
│  ↓ (blocks on error-level findings)                     │
│  BUILD — Docker image (artifact)                        │
│  ↓                                                      │
│  Gate 3 — Container Scanning         Trivy              │
│  ↓ (blocks on unfixed HIGH/CRITICAL CVEs)               │
│  Gate 4 — Dynamic Analysis (DAST)    OWASP ZAP          │
│  ↓ (blocks on FAIL-severity alerts)                     │
│  Security Summary (aggregates all gates)                │
└─────────────────────────────────────────────────────────┘
    │
    ▼
  Safe to deploy ✅  (or blocked ❌)
```

All findings appear in **GitHub → Security → Code scanning alerts** (SARIF upload).

---

## Repository Structure

```
.
├── .github/
│   ├── codeql/
│   │   └── codeql-config.yml       # CodeQL query suite + path filters
│   ├── scripts/
│   │   └── zap-to-sarif.py         # Converts ZAP JSON report → SARIF 2.1.0
│   ├── workflows/
│   │   └── security-pipeline.yml   # Main CI/CD pipeline (all four gates)
│   ├── zap/
│   │   └── zap-rules.tsv           # Per-alert FAIL/WARN/IGNORE thresholds
│   └── dependabot.yml              # Automated dependency updates
├── app/
│   ├── app.py                      # Flask REST API (sample scan target)
│   ├── docker-compose.yml          # Local development / DAST testing
│   ├── Dockerfile                  # Multi-stage, hardened, non-root
│   └── requirements.txt
├── .gitleaks.toml                  # Gitleaks custom rules + allowlist
├── .trivyignore                    # CVE exceptions (require justification)
├── SECURITY.md                     # Vulnerability disclosure + gate policy
└── README.md
```

---

## Gates In Detail

### Gate 1 — Gitleaks (Secrets Detection)

Scans the **entire git history** (not just the latest diff) for secrets matching:
- 130+ built-in patterns (AWS keys, GH tokens, private keys, connection strings, …)
- Custom rules in `.gitleaks.toml` (Flask secret keys, internal API keys, DB URLs)

Runs **first** — a credential in the tree stops everything downstream immediately.

**Required secret:** `GITLEAKS_LICENSE` (optional — enables the advanced ruleset for private repos)

### Gate 2 — CodeQL (SAST)

Uses the `security-extended` query suite, which covers:

| Category | Examples |
|----------|---------|
| Injection | SQL injection, command injection, path traversal |
| Data flow | Unsanitized input reaching sensitive sinks |
| Crypto | Weak hash algorithms, hardcoded IV |
| Auth | Missing authentication, insecure deserialization |

Results are uploaded as SARIF; `error`-level findings block the build.

### Gate 3 — Trivy (Container Scanning)

Three scan passes:
1. **Image CVEs** — OS packages and pip dependencies in the built image
2. **Filesystem scan** — source repo for secrets and misconfigurations
3. **IaC scan** — Dockerfile best-practice checks

`HIGH` and `CRITICAL` unfixed CVEs fail the gate. Exceptions require an entry in `.trivyignore` with justification and a review date.

### Gate 4 — OWASP ZAP (DAST)

Spins up the built Docker container on the runner's host network, seeds test data, then runs a ZAP **baseline scan** (passive + active spider) against the live API.

Alert handling is driven by `.github/zap/zap-rules.tsv`:
- `FAIL` → pipeline error (e.g., missing CSP header, SQL injection surface)
- `WARN` → logged, does not block (e.g., informational disclosures)
- `IGNORE` → suppressed entirely

---

## Enabling the Pipeline

### 1. Push to GitHub

```bash
git init
git remote add origin https://github.com/<org>/<repo>.git
git add .
git commit -m "feat: initial secure CI/CD pipeline"
git push -u origin main
```

### 2. Enable GitHub Advanced Security

Go to **Settings → Security → Code security** and enable:
- ✅ Dependency graph
- ✅ Dependabot alerts
- ✅ Dependabot security updates
- ✅ Code scanning (CodeQL + Trivy + ZAP results appear here)
- ✅ Secret scanning

### 3. Configure Branch Protection

**Settings → Branches → Add rule** for `main`:

```
✅ Require status checks to pass before merging
   → Add: "Security Gate Summary"
✅ Require branches to be up to date before merging
✅ Require signed commits
✅ Do not allow bypassing the above settings
```

### 4. (Optional) Add Secrets

| Secret | Purpose |
|--------|---------|
| `GITLEAKS_LICENSE` | Advanced Gitleaks ruleset for private repos |
| `GHCR_TOKEN` | Push to GHCR on release (auto-provided for public repos) |

---

## Running Locally

```bash
# Start the API
cd app
docker-compose up --build

# Test endpoints
curl http://localhost:5000/health
curl -X POST http://localhost:5000/api/users \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"hunter2!!"}'
curl -X POST http://localhost:5000/api/items \
     -H "Content-Type: application/json" \
     -d '{"name":"Widget","description":"A fine widget"}'
curl http://localhost:5000/api/items

# Run Gitleaks locally
docker run --rm -v "$(pwd):/repo" zricethezav/gitleaks:latest detect --source=/repo -c /repo/.gitleaks.toml

# Run Trivy locally
trivy image --severity HIGH,CRITICAL secure-api:local

# Run ZAP baseline locally
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://host.docker.internal:5000 -I
```

---

## Customising Thresholds

| File | What to change |
|------|---------------|
| `.github/workflows/security-pipeline.yml` | `FAIL_SEVERITY` env var (default: `HIGH`) |
| `.github/codeql/codeql-config.yml` | Query suites, path filters |
| `.github/zap/zap-rules.tsv` | Per-alert FAIL/WARN/IGNORE |
| `.trivyignore` | CVE exceptions (add justification comments) |
| `.gitleaks.toml` | Custom rules and allowlists |

---

## License

MIT
