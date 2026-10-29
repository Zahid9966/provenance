# Architecture

```
 partner files / API upload ─► landing/ ─► BRONZE (immutable, sha256-idempotent)
                                              │ replay
                                              ▼
        mapping profiles + channel terms ─► SILVER  typed · UTC · paise · PII-tokenised · contract-validated ─► quarantine
                                              │
                 DQ checks · lineage ◄────────┤
                                              ▼
              GOLD  three-way reconciliation → gold_order_fin / gold_item_fin
                      │                │                 │                  │
                  analytics        cases (SLA,       detectors →         governed metric
                 + anomalies      SoD write-off)      alerts             catalog → copilot
                      └──────────── API (RBAC, MFA, audit chain, rate limit) ──► UI · SIEM(CEF) · /metrics
```
**Design rules**
1. *Bronze is evidence.* Raw files are never edited; silver/gold are always rebuilt from bronze, so any result is reproducible.
2. *Money is integer paise.* No floats in reconciliation. Tolerance is an explicit constant.
3. *PII never crosses the silver boundary in clear.* Identity is a keyed HMAC token; free text is redacted.
4. *The model chooses, it does not execute.* The copilot emits a plan validated against a whitelist catalog; SQL is built from fixed fragments with bound parameters.
5. *Every privileged action is audited,* including denials, and the audit chain is anchored outside the database.
6. *Onboarding a partner is configuration:* `channels.json` (commercial terms) + `mappings.json` (column layout). No code change.

**Storage backends.** SQLite (default, zero-config) or PostgreSQL 18 via `PROVENANCE_DATABASE_URL=postgresql://user:pass@host:5432/db?sslmode=verify-full&sslrootcert=/ca.pem`.
All application SQL is written once; `pgdb.py` adapts it (placeholders, `INSERT OR IGNORE/REPLACE`, `lastrowid`, BIGINT/BIGSERIAL schema). The audit chain is serialised across processes
with a transaction-scoped advisory lock on Postgres. Connections are pooled. The Postgres client (`pgwire.py`) is a small stdlib implementation: SCRAM-SHA-256, TLS, bound parameters.
Existing SQLite deployments move with `python -m provenance migrate-to-postgres` (verifies counts and the audit chain).

**Scaling path:** swap `pgwire` for psycopg behind `pgdb.py` (pipelining/COPY); run the pipeline from an orchestrator instead of the in-process scheduler; read replicas for the analytics API.
