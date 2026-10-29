# Provenance — revenue assurance & data trust for multi-channel commerce

## The problem
Any company that sells through several channels (own web store, marketplaces, quick-commerce, B2B/wholesale) moves money
through systems it does not control: partner payout files, payment-gateway webhooks, refund tools, staff exports. Nobody
reconciles all of it end to end, so errors and abuse go unnoticed: partners over-deduct commission, payouts go missing or
arrive twice, fulfilled orders were never paid, a staff member quietly refunds one customer at 2 a.m., an export walks
out the door. Meanwhile enterprises are wiring LLMs to this same data, where one malicious order note can become an
attack on the AI. Provenance is the control layer that makes this data **trustworthy before anyone, human or AI, acts on it**.

## What it does
| Discipline | Capability | Where |
|---|---|---|
| **Data engineering** | Bronze (immutable, idempotent by file hash) → Silver (typed, tz/currency-normalised, PII-tokenised, contract-validated, bad rows quarantined with reason) → Gold (reconciled facts). Replayable. 10 DQ checks + score, lineage, per-stage throughput. **Config-driven connectors:** partner column mappings and channel terms are JSON, so onboarding a partner needs no code; file upload API/UI; scheduler polls the landing folder. | `pipeline.py`, `server.py` |
| **Data analysis** | Three-way reconciliation (order ↔ payment ↔ partner settlement vs contract) with 8 cause codes; value-at-stake by cause; channel contribution margin; repeat rate; exact Poisson/binomial anomaly tests for sparse series; supplier-lot recall blast radius. | `recon.py`, `analytics.py` |
| **GenAI** | "Ask your data" copilot constrained to a **governed metric catalog**: the model (or offline rules) only emits a JSON plan, validated against a whitelist and turned into parameterised SQL. Never writes SQL, never sees customer rows. Case briefs withhold poisoned free text. | `copilot.py` |
| **Cybersecurity** | HMAC-chained audit log **anchored externally** (detects tail truncation); scrypt auth, lockout, password policy, TOTP MFA (RFC 6238, single-use codes), revocable sessions; 5-role RBAC with masking; insider/fraud/export/prompt-injection detectors; PII redaction; strict CSP; CEF export for SIEM. | `security.py`, `server.py` |
| **Operations workflow** | Every exception becomes an SLA-tracked **case** (assign, dispute, recover, comment). Write-offs need a justification and a *different* authorised approver (segregation of duties). Recovery rate and aging KPIs. | `cases.py` |
| **Storage** | SQLite (default) or **PostgreSQL 18** through one adapter; pure-stdlib wire client with SCRAM-SHA-256 and TLS (incl. `verify-full`); pooled connections; advisory-lock-serialised audit chain; verified SQLite→Postgres migration. | `db.py`, `pgdb.py`, `pgwire.py`, `migrate.py` |
| **Production plumbing** | `/healthz`, `/readyz`, Prometheus `/metrics`, JSON request logs with request ids, graceful SIGTERM, Dockerfile (non-root, read-only FS, healthcheck), compose, CI workflow. | `deploy/`, `.github/` |

Docs: [architecture](docs/ARCHITECTURE.md) · [security model](docs/SECURITY.md) · [operations](docs/OPERATIONS.md)

## Run it
Python 3.10+, **no third-party packages**.
```bash
python3 -m provenance init      # users, synthetic data with injected faults, full pipeline
python3 -m provenance serve --schedule-minutes 5   # http://127.0.0.1:8787  (logins: data/demo_credentials.txt, mode 0600)
python3 -m provenance ask "leakage by cause in the last 30 days"
python3 -m provenance verify-audit
python3 -m unittest discover -s tests
# on Postgres (needs an EMPTY database):
PROVENANCE_DATABASE_URL=postgresql://user:pass@127.0.0.1:5432/pv_test python3 -m unittest discover -s tests
```
Optional: set `ANTHROPIC_API_KEY` to let a Claude model produce the query plan (`PROVENANCE_LLM_MODEL` to choose the model).
The plan goes through the same validator, so the model cannot widen access.

## How it is verified
The generator injects known faults and writes `ground_truth.json`. **56 tests** (unit + live-server integration), run on **both SQLite and a real PostgreSQL 18** assert, on the 2,140-order demo set:
every injected payout/payment error is found with **zero false positives**; insider, bulk-export, velocity and prompt-injection cases fire; anomaly
detection flags exactly the two injected incidents; editing/deleting/**truncating** audit rows and forging or replaying tokens/MFA codes is detected;
lockout, rate limiting, RBAC denials and revocation work; a new partner is onboarded through mapping config alone; malicious uploads are rejected;
write-off segregation of duties holds through the API; health/metrics/headers behave.
