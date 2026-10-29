import os, sqlite3
from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS bronze_files(file_hash TEXT PRIMARY KEY, source TEXT, file_name TEXT, rows INTEGER, ingested_at TEXT, batch_id TEXT);
CREATE TABLE IF NOT EXISTS bronze_raw(id INTEGER PRIMARY KEY, source TEXT, file_name TEXT, batch_id TEXT, row_no INTEGER, payload TEXT);
CREATE INDEX IF NOT EXISTS ix_bronze_source ON bronze_raw(source);

CREATE TABLE IF NOT EXISTS silver_orders(order_id TEXT PRIMARY KEY, channel TEXT, customer_token TEXT, email_masked TEXT, placed_at TEXT, day TEXT,
  total INTEGER, discount INTEGER, shipping INTEGER, status TEXT, notes TEXT, pincode TEXT);
CREATE TABLE IF NOT EXISTS silver_items(order_id TEXT, sku TEXT, qty INTEGER, unit_price INTEGER, lot_id TEXT);
CREATE INDEX IF NOT EXISTS ix_items_order ON silver_items(order_id);
CREATE INDEX IF NOT EXISTS ix_items_lot ON silver_items(lot_id);
CREATE TABLE IF NOT EXISTS silver_payments(payment_id TEXT PRIMARY KEY, order_id TEXT, gateway TEXT, amount INTEGER, status TEXT, ts TEXT, card_fp TEXT);
CREATE INDEX IF NOT EXISTS ix_pay_order ON silver_payments(order_id);
CREATE TABLE IF NOT EXISTS silver_settlements(settlement_id TEXT PRIMARY KEY, channel TEXT, order_id TEXT, gross INTEGER, commission INTEGER, fixed_fee INTEGER, withheld INTEGER, net INTEGER, settled_on TEXT);
CREATE INDEX IF NOT EXISTS ix_set_order ON silver_settlements(order_id);
CREATE TABLE IF NOT EXISTS silver_refunds(refund_id TEXT PRIMARY KEY, order_id TEXT, amount INTEGER, reason TEXT, ts TEXT, approved_by TEXT);
CREATE INDEX IF NOT EXISTS ix_ref_order ON silver_refunds(order_id);
CREATE TABLE IF NOT EXISTS silver_staff_actions(actor TEXT, action TEXT, ts TEXT, rows INTEGER);
CREATE TABLE IF NOT EXISTS silver_products(sku TEXT PRIMARY KEY, name TEXT, category TEXT, price INTEGER, cost INTEGER);
CREATE TABLE IF NOT EXISTS silver_lots(lot_id TEXT PRIMARY KEY, sku TEXT, supplier TEXT, received_on TEXT, status TEXT);

CREATE TABLE IF NOT EXISTS quarantine(id INTEGER PRIMARY KEY, run_id TEXT, source TEXT, reason TEXT, payload TEXT);
CREATE TABLE IF NOT EXISTS pipeline_runs(run_id TEXT PRIMARY KEY, started_at TEXT, finished_at TEXT, status TEXT, summary TEXT);
CREATE TABLE IF NOT EXISTS pipeline_stages(run_id TEXT, stage TEXT, rows_in INTEGER, rows_out INTEGER, rows_quarantined INTEGER, rows_duplicate INTEGER);
CREATE TABLE IF NOT EXISTS dq_results(run_id TEXT, check_name TEXT, tbl TEXT, severity TEXT, total INTEGER, failed INTEGER);
CREATE TABLE IF NOT EXISTS lineage(target TEXT, source TEXT, transform TEXT);

CREATE TABLE IF NOT EXISTS gold_order_fin(order_id TEXT PRIMARY KEY, channel TEXT, day TEXT, week TEXT, month TEXT, status TEXT, customer_token TEXT,
  total INTEGER, cogs INTEGER, refunded INTEGER, fees INTEGER, billable INTEGER, expected_net INTEGER, actual_net INTEGER, variance INTEGER,
  leak INTEGER, recon_state TEXT, recon_reason TEXT);
CREATE TABLE IF NOT EXISTS gold_item_fin(order_id TEXT, channel TEXT, day TEXT, week TEXT, month TEXT, sku TEXT, category TEXT, qty INTEGER, revenue INTEGER, cogs INTEGER, lot_id TEXT);

CREATE TABLE IF NOT EXISTS audit_log(seq INTEGER PRIMARY KEY, ts TEXT, actor TEXT, role TEXT, action TEXT, resource TEXT, detail TEXT, prev_mac TEXT, mac TEXT);
CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, role TEXT, pw_hash TEXT, salt TEXT, mfa_secret TEXT, mfa_last INTEGER DEFAULT 0, token_version INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS login_state(username TEXT PRIMARY KEY, failures INTEGER DEFAULT 0, locked_until REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS cases(case_id INTEGER PRIMARY KEY, order_id TEXT, channel TEXT, reason TEXT, at_stake INTEGER, priority TEXT, status TEXT, assignee TEXT,
  recovered INTEGER DEFAULT 0, created_at TEXT, due_at TEXT, updated_at TEXT, requested_by TEXT, UNIQUE(order_id, reason));
CREATE INDEX IF NOT EXISTS ix_cases_status ON cases(status);
CREATE TABLE IF NOT EXISTS case_events(id INTEGER PRIMARY KEY, case_id INTEGER, ts TEXT, actor TEXT, kind TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, kind TEXT, severity TEXT, subject TEXT, detail TEXT, created_at TEXT, status TEXT DEFAULT 'open', UNIQUE(kind, subject));
"""


def connect(path=None):
    """SQLite by default; Postgres when PROVENANCE_DATABASE_URL=postgresql://user:pass@host:5432/db?sslmode=require is set."""
    url = os.environ.get("PROVENANCE_DATABASE_URL")
    if url and path is None:
        from . import pgdb
        return pgdb.connect(url, SCHEMA)
    config.HOME.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path or config.DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)")}   # migrate pre-0.2 databases
    for c, ddl in (("mfa_secret", "TEXT"), ("mfa_last", "INTEGER DEFAULT 0"), ("token_version", "INTEGER DEFAULT 0")):
        if c not in cols: conn.execute(f"ALTER TABLE users ADD COLUMN {c} {ddl}")
    return conn


def begin_write(conn):
    """Start a write transaction that serialises the audit chain across threads/processes."""
    if getattr(conn, "is_pg", False):
        if not conn.in_txn: conn.simple("BEGIN")
        conn.execute("SELECT pg_advisory_xact_lock(7311)")
    else:
        conn.execute("BEGIN IMMEDIATE")
