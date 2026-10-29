# Operations
| Task | How |
|---|---|
| Start (demo) | `PROVENANCE_DEMO=1 docker compose up --build` or `python3 -m provenance init && python3 -m provenance serve --schedule-minutes 5` |
| Create a user | `python3 -m provenance create-user alice finance` (prompts; 12+ chars, 3 classes) |
| Onboard a partner | add terms to `data/channels.json`, column map to `data/mappings.json`, drop `settlements_<PARTNER>.csv` in `data/landing/` (or upload in the UI) |
| Health / readiness | `GET /healthz` (liveness), `GET /readyz` (503 until first successful run) |
| Metrics | `GET /metrics` (Prometheus text; loopback only unless `PROVENANCE_METRICS_TOKEN` is set) |
| Logs | JSON lines on stdout, one per request with request id |
| Verify audit trail | `python3 -m provenance verify-audit` (exit code 2 on tamper) |
| Anchor the chain | automatic on each run and scheduler tick; or `python3 -m provenance anchor` |
| SIEM | `python3 -m provenance export-siem --since N` (CEF) or `GET /api/audit/siem` |
| Use Postgres | `export PROVENANCE_DATABASE_URL='postgresql://user:pass@host:5432/db?sslmode=verify-full&sslrootcert=/path/ca.pem'` then `init`/`serve` as usual. Use `sslmode=require` or stronger off-host. Database user needs CREATE on its schema (first start creates tables). |
| Move SQLite → Postgres | stop the app; set the URL to an **empty** database; `python3 -m provenance migrate-to-postgres` (copies all tables, advances sequences, verifies row counts and the audit chain) |
| Backup | SQLite: copy `data/provenance.db`; Postgres: `pg_dump`. Always also `data/keys.json`; the anchor directory separately |
Suggested alerts: `provenance_audit_chain_ok == 0`, `provenance_cases_sla_breached > 0`, `time() - provenance_last_pipeline_success_timestamp > 86400`, `provenance_alerts_open{} > 0`.
