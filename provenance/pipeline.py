"""Medallion pipeline. Bronze = immutable raw landing (idempotent by file hash). Silver = typed, conformed,
PII-tokenized, contract-validated (bad rows quarantined with a reason). Gold = reconciled facts for analytics/GenAI.
Silver and gold are fully rebuilt from bronze each run, so any run is replayable and deterministic."""
import csv, hashlib, io, json, uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from . import config, security
from .recon import reconcile
from . import cases

IST = timezone(timedelta(hours=5, minutes=30))
SOURCES = {  # file-name prefix -> (source, format)
    "store_orders": ("orders_json", "jsonl"), "b2b_orders": ("orders_json", "jsonl"), "mkt_orders": ("orders_mkt", "csv"),
    "gateway_events": ("gateway", "jsonl"), "settlements": ("settlements", "csv"), "refunds": ("refunds", "jsonl"),
    "staff_actions": ("staff", "jsonl"), "catalog": ("catalog", "csv"), "lots": ("lots", "csv"),
}


class Bad(ValueError): pass

def rupees(v) -> int:
    try:
        d = Decimal(str(v).replace(",", "").strip())
    except InvalidOperation:
        raise Bad(f"unparseable amount {v!r}")
    return int(d * 100)

def ts_utc(v, ist_fmt=None) -> datetime:
    try:
        if ist_fmt:
            return datetime.strptime(v, ist_fmt).replace(tzinfo=IST).astimezone(timezone.utc)
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
        return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except (ValueError, AttributeError):
        raise Bad(f"unparseable timestamp {v!r}")

def iso(d): return d.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------- bronze ----------
def ingest_bronze(conn, landing=None) -> dict:
    landing = landing or config.LANDING
    batch, stats = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S"), {"new_files": 0, "skipped_files": 0, "rows": 0}
    for f in sorted(landing.iterdir()):
        prefix = next((k for k in SOURCES if f.name.startswith(k)), None)
        if not prefix or f.suffix not in (".csv", ".jsonl"): continue
        raw = f.read_bytes(); h = hashlib.sha256(raw).hexdigest()
        if conn.execute("SELECT 1 FROM bronze_files WHERE file_hash=?", (h,)).fetchone():
            stats["skipped_files"] += 1; continue
        text = raw.decode("utf-8")
        if SOURCES[prefix][1] == "csv": recs = list(csv.DictReader(io.StringIO(text)))
        else: recs = [json.loads(l) for l in text.splitlines() if l.strip()]
        src = SOURCES[prefix][0]
        conn.executemany("INSERT INTO bronze_raw(source,file_name,batch_id,row_no,payload) VALUES(?,?,?,?,?)",
                         [(src, f.name, batch, i, json.dumps({**r, "_file": f.name}, sort_keys=True)) for i, r in enumerate(recs)])
        conn.execute("INSERT INTO bronze_files VALUES(?,?,?,?,?,?)", (h, src, f.name, len(recs), security.now_iso(), batch))
        stats["new_files"] += 1; stats["rows"] += len(recs)
    conn.commit()
    return stats


# ---------- silver ----------
def _bronze(conn, source, mappings=None):
    """Yield raw records; apply a partner mapping profile ({canonical: partner_column}) selected by file-name prefix."""
    mappings = mappings if mappings is not None else config.load_mappings()
    for r in conn.execute("SELECT payload FROM bronze_raw WHERE source=? ORDER BY id", (source,)):
        rec = json.loads(r["payload"])
        prof = next((m for pre, m in mappings.items() if rec["_file"].startswith(pre)), None)
        if prof:
            rec = {**rec, **{canon: rec[theirs] for canon, theirs in prof.items() if theirs in rec}}
        yield rec

class Stage:
    def __init__(self, conn, run, name): self.conn, self.run, self.name, self.i, self.o, self.q, self.d = conn, run, name, 0, 0, 0, 0
    def quarantine(self, rec, why):
        self.q += 1
        self.conn.execute("INSERT INTO quarantine(run_id,source,reason,payload) VALUES(?,?,?,?)", (self.run, self.name, why, json.dumps(rec)[:1500]))
    def close(self):
        self.conn.execute("INSERT INTO pipeline_stages VALUES(?,?,?,?,?,?)", (self.run, self.name, self.i, self.o, self.q, self.d))

def build_silver(conn, run):
    config.load_channels()
    for t in ("silver_orders", "silver_items", "silver_payments", "silver_settlements", "silver_refunds", "silver_staff_actions", "silver_products", "silver_lots"):
        conn.execute(f"DELETE FROM {t}")
    conn.execute("DELETE FROM quarantine")

    st = Stage(conn, run, "catalog")
    for r in _bronze(conn, "catalog"):
        st.i += 1
        try: conn.execute("INSERT INTO silver_products VALUES(?,?,?,?,?)", (r["sku"], r["name"], r["category"], rupees(r["price"]), rupees(r["cost"]))); st.o += 1
        except (Bad, KeyError, Exception) as e: st.quarantine(r, str(e))
    st.close()

    st = Stage(conn, run, "lots")
    for r in _bronze(conn, "lots"):
        st.i += 1
        conn.execute("INSERT OR REPLACE INTO silver_lots VALUES(?,?,?,?,?)", (r["lot_id"], r["sku"], r["supplier"], r["received_on"], r["status"])); st.o += 1
    st.close()
    lots_by_sku = {}
    for l in conn.execute("SELECT * FROM silver_lots ORDER BY received_on"): lots_by_sku.setdefault(l["sku"], []).append((l["received_on"], l["lot_id"]))
    def lot_for(sku, day):
        cands = [lid for rec, lid in lots_by_sku.get(sku, []) if rec <= day]
        return cands[-1] if cands else None

    def put_order(st, oid, ch, when, ident, email_masked, items, disc, ship, status, notes, pin, rec):
        if not oid: raise Bad("missing order id")
        if ch not in config.CHANNELS: raise Bad(f"unknown channel {ch!r}")
        if not items: raise Bad("order has no items")
        for it in items:
            if it["qty"] <= 0: raise Bad(f"non-positive quantity {it['qty']}")
            if it["price"] < 0: raise Bad("negative price")
        total = sum(i["qty"] * i["price"] for i in items) - disc + ship
        day = when.strftime("%Y-%m-%d")
        cur = conn.execute("INSERT OR IGNORE INTO silver_orders VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (oid, ch, security.tokenize(ident), email_masked, iso(when), day, total, disc, ship, status, security.redact(notes or ""), pin))   # free text may carry PII
        if cur.rowcount == 0: st.d += 1; return
        conn.executemany("INSERT INTO silver_items VALUES(?,?,?,?,?)", [(oid, i["sku"], i["qty"], i["price"], lot_for(i["sku"], day)) for i in items])
        st.o += 1

    st = Stage(conn, run, "orders_json")
    for r in _bronze(conn, "orders_json"):
        st.i += 1
        try:
            em = r["customer"]["email"].strip().lower()
            put_order(st, r["orderId"], r["channel"], ts_utc(r["placedAt"]), em, security.mask_email(em),
                      [{"sku": i["sku"], "qty": int(i["qty"]), "price": rupees(i["unitPrice"])} for i in r["items"]],
                      rupees(r["discount"]), rupees(r["shipping"]), r["status"], r.get("notes"), r["customer"].get("pincode"), r)
        except (Bad, KeyError, ValueError, TypeError) as e: st.quarantine(r, f"{type(e).__name__}: {e}")
    st.close()

    st = Stage(conn, run, "orders_mkt")
    groups = {}
    for r in _bronze(conn, "orders_mkt"):
        st.i += 1; groups.setdefault((r["_file"], r["OrderRef"]), []).append(r)
    smap = {"Delivered": "DELIVERED", "Cancelled": "CANCELLED", "Returned": "RETURNED", "Shipped": "PLACED"}
    for (fname, ref), rows in groups.items():
        r0 = rows[0]
        try:
            ch = fname.split("_")[2].split(".")[0]
            put_order(st, ref, ch, ts_utc(r0["OrderDate"], "%d/%m/%Y %H:%M"), r0["BuyerId"], "buyer:" + r0["BuyerId"][-4:],
                      [{"sku": x["Sku"], "qty": int(x["Qty"]), "price": rupees(x["ItemPrice"])} for x in rows],
                      sum(rupees(x["OrderDiscount"]) for x in rows), sum(rupees(x["ShipFee"]) for x in rows), smap[r0["Status"]], "", r0["Pincode"], r0)
        except (Bad, KeyError, ValueError) as e: st.quarantine(r0, f"{type(e).__name__}: {e}")
    st.d += sum(len(v) for v in groups.values()) - len(groups) - st.q * 0
    st.d = 0  # item rows folded into orders are not duplicates
    st.close()

    st = Stage(conn, run, "gateway")
    for r in _bronze(conn, "gateway"):
        st.i += 1
        try:
            status = {"payment.captured": "captured", "payment.failed": "failed"}[r["type"]]
            cur = conn.execute("INSERT OR IGNORE INTO silver_payments VALUES(?,?,?,?,?,?,?)",
                (r["event_id"], r["order_id"], r["gateway"], int(r["amount_paise"]), status, iso(ts_utc(r["ts"])), r.get("card_fp")))
            if cur.rowcount: st.o += 1
            else: st.d += 1
        except (Bad, KeyError, ValueError) as e: st.quarantine(r, f"{type(e).__name__}: {e}")
    st.close()

    st = Stage(conn, run, "settlements")
    for r in _bronze(conn, "settlements"):
        st.i += 1
        try:
            ch = r["_file"].split("_")[1].split(".")[0]
            sd = datetime.strptime(r["SettledOn"], "%d-%m-%Y")
            conn.execute("INSERT OR IGNORE INTO silver_settlements VALUES(?,?,?,?,?,?,?,?,?)", (r["SettlementId"], ch, r["OrderRef"], rupees(r["Gross"]),
                rupees(r["Commission"]), rupees(r["FixedFee"]), rupees(r["TaxWithheld"]), rupees(r["NetPayout"]), sd.strftime("%Y-%m-%d"))); st.o += 1
        except (Bad, KeyError, ValueError) as e: st.quarantine(r, f"{type(e).__name__}: {e}")
    st.close()

    st = Stage(conn, run, "refunds")
    for r in _bronze(conn, "refunds"):
        st.i += 1
        try:
            conn.execute("INSERT OR IGNORE INTO silver_refunds VALUES(?,?,?,?,?,?)", (r["refund_id"], r["order_id"], int(r["amount_paise"]), r["reason"], iso(ts_utc(r["ts"])), r["approved_by"])); st.o += 1
        except (Bad, KeyError, ValueError) as e: st.quarantine(r, f"{type(e).__name__}: {e}")
    st.close()

    st = Stage(conn, run, "staff")
    for r in _bronze(conn, "staff"):
        st.i += 1
        conn.execute("INSERT INTO silver_staff_actions VALUES(?,?,?,?)", (r["actor"], r["action"], iso(ts_utc(r["ts"])), int(r["rows"]))); st.o += 1
    st.close()
    conn.commit()


# ---------- data quality ----------
def run_dq(conn, run):
    def chk(name, tbl, sev, total_sql, bad_sql):
        total = conn.execute(total_sql).fetchone()[0]; bad = conn.execute(bad_sql).fetchone()[0]
        conn.execute("INSERT INTO dq_results VALUES(?,?,?,?,?,?)", (run, name, tbl, sev, total, bad))
    chk("order total = Σ items − discount + shipping", "silver_orders", "critical", "SELECT count(*) FROM silver_orders",
        "SELECT count(*) FROM silver_orders o WHERE total <> (SELECT sum(qty*unit_price) FROM silver_items i WHERE i.order_id=o.order_id) - discount + shipping")
    chk("payments reference a known order", "silver_payments", "high", "SELECT count(*) FROM silver_payments",
        "SELECT count(*) FROM silver_payments WHERE order_id NOT IN (SELECT order_id FROM silver_orders)")
    chk("settlements reference a known order", "silver_settlements", "high", "SELECT count(*) FROM silver_settlements",
        "SELECT count(*) FROM silver_settlements WHERE order_id NOT IN (SELECT order_id FROM silver_orders)")
    chk("settlement arithmetic: gross − fees = net", "silver_settlements", "high", "SELECT count(*) FROM silver_settlements",
        "SELECT count(*) FROM silver_settlements WHERE abs(gross-commission-fixed_fee-withheld-net) > 2")
    chk("one settlement per order", "silver_settlements", "medium", "SELECT count(DISTINCT order_id) FROM silver_settlements",
        "SELECT count(*) FROM (SELECT order_id FROM silver_settlements GROUP BY order_id HAVING count(*)>1) dup")
    chk("every item SKU exists in catalogue", "silver_items", "high", "SELECT count(*) FROM silver_items",
        "SELECT count(*) FROM silver_items WHERE sku NOT IN (SELECT sku FROM silver_products)")
    chk("every item traces to a supplier lot", "silver_items", "medium", "SELECT count(*) FROM silver_items",
        "SELECT count(*) FROM silver_items WHERE lot_id IS NULL")
    chk("refund does not exceed order total", "silver_refunds", "high", "SELECT count(*) FROM silver_refunds",
        "SELECT count(*) FROM silver_refunds r JOIN silver_orders o USING(order_id) WHERE r.amount > o.total")
    chk("refunds reference a known order", "silver_refunds", "high", "SELECT count(*) FROM silver_refunds",
        "SELECT count(*) FROM silver_refunds WHERE order_id NOT IN (SELECT order_id FROM silver_orders)")
    chk("source rows not quarantined", "quarantine", "medium", "SELECT sum(rows_in) FROM pipeline_stages WHERE run_id='%s'" % run,
        "SELECT count(*) FROM quarantine")
    conn.commit()

def dq_score(conn, run):
    rows = conn.execute("SELECT severity, total, failed FROM dq_results WHERE run_id=?", (run,)).fetchall()
    w = {"critical": 5, "high": 3, "medium": 1}
    tot = sum(w[r["severity"]] for r in rows) or 1
    return round(100 * sum(w[r["severity"]] * (1 - (r["failed"] / r["total"] if r["total"] else 0)) for r in rows) / tot, 2)


# ---------- gold ----------
def build_gold(conn, as_of):
    reconcile(conn, as_of)  # fills gold_order_fin recon columns
    conn.execute("DELETE FROM gold_item_fin")
    conn.execute("""INSERT INTO gold_item_fin SELECT i.order_id, o.channel, o.day, g.week, g.month, i.sku, p.category,
        i.qty, i.qty*i.unit_price, i.qty*p.cost, i.lot_id FROM silver_items i JOIN silver_orders o ON o.order_id=i.order_id JOIN silver_products p ON p.sku=i.sku
        JOIN gold_order_fin g ON g.order_id=i.order_id WHERE o.status<>'CANCELLED'""")
    conn.commit()

LINEAGE = [
    ("silver_orders", "bronze:orders_json + bronze:orders_mkt", "parse, tz→UTC, money→paise, PII tokenize, dedupe on order_id, contract-validate"),
    ("silver_items", "bronze:orders_json + bronze:orders_mkt", "explode line items, assign supplier lot by receipt date (FEFO-lite)"),
    ("silver_payments", "bronze:gateway", "map event types, dedupe on event_id"),
    ("silver_settlements", "bronze:settlements", "parse partner CSV, dd-mm-yyyy→ISO, money→paise"),
    ("silver_refunds", "bronze:refunds", "typed copy, dedupe on refund_id"),
    ("gold_order_fin", "silver_orders + silver_payments + silver_settlements + silver_refunds + silver_items + silver_products", "three-way reconciliation vs channel contract terms; cost of goods; fees"),
    ("gold_item_fin", "silver_items + silver_orders + silver_products", "line-level revenue and COGS by SKU/category/lot"),
    ("cases", "gold_order_fin", "one SLA-tracked case per reconciliation exception; auto-resolved when the exception clears"),
    ("alerts", "silver_refunds + silver_staff_actions + silver_payments + silver_orders", "insider/fraud/export/prompt-injection detectors"),
]

def run_pipeline(conn, landing=None, actor="system") -> dict:
    run = uuid.uuid4().hex[:10]
    conn.execute("INSERT INTO pipeline_runs VALUES(?,?,?,?,?)", (run, security.now_iso(), None, "running", "{}"))
    try:
        bronze = ingest_bronze(conn, landing)
        build_silver(conn, run)
        run_dq(conn, run)
        as_of = conn.execute("SELECT max(day) FROM silver_orders").fetchone()[0]
        build_gold(conn, datetime.strptime(as_of, "%Y-%m-%d") + timedelta(days=1))
        conn.execute("DELETE FROM lineage"); conn.executemany("INSERT INTO lineage VALUES(?,?,?)", LINEAGE)
        alerts = security.run_detections(conn)
        case_stats = cases.sync(conn)
        summary = {"bronze": bronze, "dq_score": dq_score(conn, run), "new_alerts": alerts,
                   "quarantined": conn.execute("SELECT count(*) FROM quarantine").fetchone()[0], "cases": case_stats}
        conn.execute("UPDATE pipeline_runs SET finished_at=?, status='success', summary=? WHERE run_id=?", (security.now_iso(), json.dumps(summary), run))
        conn.commit()
        security.audit(conn, actor, "system" if actor in ("system", "scheduler") else "admin", "pipeline.run", run, summary)
        security.anchor(conn)
        return {"run_id": run, **summary}
    except Exception as e:
        conn.rollback()
        conn.execute("UPDATE pipeline_runs SET finished_at=?, status='failed', summary=? WHERE run_id=?", (security.now_iso(), json.dumps({"error": str(e)}), run))
        conn.commit(); raise


def pending_files(conn, landing=None):
    """Landing files not yet ingested (by content hash): lets a scheduler skip no-op runs cheaply."""
    landing = landing or config.LANDING; out = []
    if not landing.exists(): return out
    for f in sorted(landing.iterdir()):
        if any(f.name.startswith(k) for k in SOURCES) and f.suffix in (".csv", ".jsonl"):
            if not conn.execute("SELECT 1 FROM bronze_files WHERE file_hash=?", (hashlib.sha256(f.read_bytes()).hexdigest(),)).fetchone(): out.append(f.name)
    return out
