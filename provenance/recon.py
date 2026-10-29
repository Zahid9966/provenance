"""Three-way reconciliation: order (what was billed) <-> payment (cash in) <-> settlement (partner payout vs contract)."""
from datetime import datetime
from . import config

def reconcile(conn, as_of: datetime):
    pay = {r[0]: r[1] for r in conn.execute("SELECT order_id, sum(amount) FROM silver_payments WHERE status='captured' GROUP BY order_id")}
    ref = {r[0]: r[1] for r in conn.execute("SELECT order_id, sum(amount) FROM silver_refunds GROUP BY order_id")}
    sett = {r["order_id"]: r for r in conn.execute("""SELECT order_id, count(*) n, sum(gross) gross, sum(commission) comm, sum(fixed_fee) fee, sum(withheld) tds, sum(net) net
                                                      FROM silver_settlements GROUP BY order_id""")}
    cogs = {r[0]: r[1] for r in conn.execute("SELECT i.order_id, sum(i.qty*p.cost) FROM silver_items i JOIN silver_products p USING(sku) GROUP BY i.order_id")}
    tol, rows = config.TOLERANCE, []
    for o in conn.execute("SELECT * FROM silver_orders"):
        oid, cfg, total, status = o["order_id"], config.CHANNELS[o["channel"]], o["total"], o["status"]
        refunded, s = ref.get(oid, 0), sett.get(oid)
        age = (as_of - datetime.strptime(o["day"], "%Y-%m-%d")).days
        billable = 0 if status == "CANCELLED" else total
        fees = (s["comm"] + s["fee"] + s["tds"]) if s else 0
        state, reason, exp, act = "MATCHED", "", billable, 0
        if status == "PLACED":
            state, reason = "PENDING", "in_flight"; exp = act = 0
        elif cfg["kind"] == "gateway":
            captured = pay.get(oid, 0); act = captured; exp = billable
            if captured - billable < -tol: state, reason = "EXCEPTION", ("PAYMENT_MISSING" if captured == 0 else "SHORT_PAYMENT")
            elif captured - billable > tol and status != "CANCELLED": state, reason = "EXCEPTION", "OVERCAPTURE"
        else:
            if status in ("CANCELLED", "RETURNED"):
                exp = 0; act = s["net"] if s else 0
                if act > tol: state, reason = "EXCEPTION", "SETTLED_BUT_REVERSED"
            else:
                comm = round(total * cfg["commission"]); tds = round(total * cfg["withholding"])
                exp = total - comm - cfg["fixed_fee"] - tds
                if not s:
                    act = 0
                    if age > config.SETTLEMENT_SLA_DAYS: state, reason = "EXCEPTION", "MISSING_SETTLEMENT"
                    else: state, reason = "PENDING", "awaiting_settlement"
                else:
                    act = s["net"]
                    if s["n"] > 1: state, reason = "EXCEPTION", "DUPLICATE_SETTLEMENT"
                    elif s["comm"] - comm > tol: state, reason = "EXCEPTION", "COMMISSION_OVERCHARGE"
                    elif act - exp < -tol: state, reason = "EXCEPTION", "SHORT_PAY"
                    elif act - exp > tol: state, reason = "EXCEPTION", "OVERPAID"
        var = act - exp
        leak = -var if (state == "EXCEPTION" and var < 0) else 0
        d = o["day"]
        rows.append((oid, o["channel"], d, datetime.strptime(d, "%Y-%m-%d").strftime("%Y-W%W"), d[:7], status, o["customer_token"], total,
                     cogs.get(oid, 0), refunded, fees, billable, exp, act, var, leak, state, reason))
    conn.execute("DELETE FROM gold_order_fin")
    conn.executemany("INSERT INTO gold_order_fin VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    conn.commit()
