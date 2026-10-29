"""One-shot SQLite -> Postgres migration that preserves users, cases, alerts and the audit chain byte-for-byte
(MACs are copied verbatim, so the chain and the external anchors still verify under the same keys)."""
from . import db, pgdb, security

TABLES = ["users", "login_state", "audit_log", "bronze_files", "bronze_raw", "silver_orders", "silver_items", "silver_payments", "silver_settlements", "silver_refunds",
          "silver_staff_actions", "silver_products", "silver_lots", "quarantine", "pipeline_runs", "pipeline_stages", "dq_results", "lineage", "gold_order_fin", "gold_item_fin",
          "cases", "case_events", "alerts"]
SERIAL = [("bronze_raw", "id"), ("quarantine", "id"), ("alerts", "id"), ("case_events", "id"), ("cases", "case_id")]


def migrate(src, dst) -> dict:
    meta = pgdb.table_meta(db.SCHEMA)
    for t in ("users", "audit_log", "cases"):
        if dst.execute(f"SELECT count(*) FROM {t}").fetchone()[0]: raise RuntimeError(f"target database is not empty ({t}); refusing to merge into live data")
    report = {}
    for t in TABLES:
        cols = meta[t][0]; sel = ", ".join(cols); ins = f"INSERT INTO {t}({sel}) VALUES({','.join('?' * len(cols))})"
        rows = [tuple(r) for r in src.execute(f"SELECT {sel} FROM {t}")]
        for r in rows: dst.execute(ins, r)
        dst.commit(); report[t] = len(rows)
    if getattr(dst, "is_pg", False):   # explicit ids were copied: move each sequence past them
        for t, pk in SERIAL:
            dst.execute(f"SELECT setval(pg_get_serial_sequence('{t}','{pk}'), COALESCE(max({pk}),1), max({pk}) IS NOT NULL) FROM {t}")
        dst.commit()
    for t, n in report.items():
        got = dst.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
        if got != n: raise RuntimeError(f"row count mismatch in {t}: source {n}, target {got}")
    v = security.verify_audit(dst)
    if not v["ok"]: raise RuntimeError(f"audit chain does not verify after migration: {v}")
    return {"rows": report, "audit": v}
