"""Case management: every reconciliation exception becomes an owned, SLA-tracked case with a controlled lifecycle.
Write-offs need a second person (segregation of duties). Every transition is recorded in case_events and the audit chain."""
from datetime import datetime, timedelta, timezone
from . import security

TERMINAL = {"RECOVERED", "WRITTEN_OFF", "AUTO_RESOLVED"}
TRANSITIONS = {
    "OPEN": {"INVESTIGATING", "DISPUTED", "WRITEOFF_REQUESTED"},
    "INVESTIGATING": {"DISPUTED", "WRITEOFF_REQUESTED", "RECOVERED"},
    "DISPUTED": {"INVESTIGATING", "RECOVERED", "WRITEOFF_REQUESTED"},
    "WRITEOFF_REQUESTED": {"WRITTEN_OFF", "INVESTIGATING"},
}
SLA_DAYS = {"high": 3, "medium": 7, "low": 14}

def _now(): return datetime.now(timezone.utc)
def _iso(d): return d.strftime("%Y-%m-%dT%H:%M:%SZ")

def priority(reason, at_stake):
    if reason == "MISSING_SETTLEMENT" or at_stake >= 100_000: return "high"
    return "medium" if at_stake >= 10_000 else "low"

def event(conn, case_id, actor, kind, detail=""):
    conn.execute("INSERT INTO case_events(case_id,ts,actor,kind,detail) VALUES(?,?,?,?,?)", (case_id, security.now_iso(), actor, kind, security.redact(detail)[:1000]))

def sync(conn) -> dict:
    """Idempotently open a case per (order, cause) exception; auto-resolve open cases whose exception has cleared."""
    opened = resolved = 0
    for e in conn.execute("SELECT order_id, channel, recon_reason, variance FROM gold_order_fin WHERE recon_state='EXCEPTION'").fetchall():
        stake = abs(e["variance"]); pr = priority(e["recon_reason"], stake)
        cur = conn.execute("INSERT OR IGNORE INTO cases(order_id,channel,reason,at_stake,priority,status,created_at,due_at,updated_at) VALUES(?,?,?,?,?,'OPEN',?,?,?)",
                           (e["order_id"], e["channel"], e["recon_reason"], stake, pr, security.now_iso(), _iso(_now() + timedelta(days=SLA_DAYS[pr])), security.now_iso()))
        if cur.rowcount: event(conn, cur.lastrowid, "system", "opened", f"{e['recon_reason']} ₹{stake/100:,.2f}"); opened += 1
    for c in conn.execute("""SELECT case_id FROM cases WHERE status NOT IN ('RECOVERED','WRITTEN_OFF','AUTO_RESOLVED')
                             AND NOT EXISTS (SELECT 1 FROM gold_order_fin g WHERE g.order_id=cases.order_id AND g.recon_state='EXCEPTION' AND g.recon_reason=cases.reason)""").fetchall():
        conn.execute("UPDATE cases SET status='AUTO_RESOLVED', updated_at=? WHERE case_id=?", (security.now_iso(), c["case_id"]))
        event(conn, c["case_id"], "system", "auto_resolved", "exception no longer present after pipeline re-run"); resolved += 1
    conn.commit()
    return {"opened": opened, "auto_resolved": resolved}

def get(conn, case_id):
    c = conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
    if not c: raise KeyError("unknown case")
    return c

def transition(conn, case_id, to, actor, role, comment="", recovered=None):
    c = get(conn, case_id); frm = c["status"]
    if to not in TRANSITIONS.get(frm, ()): raise ValueError(f"cannot move {frm} → {to}")
    if to == "WRITTEN_OFF":
        if not security.can(role, "case_approve"): raise PermissionError("write-off approval requires the approver role")
        if actor == c["requested_by"]: raise PermissionError("segregation of duties: the requester cannot approve their own write-off")
    if to == "WRITEOFF_REQUESTED":
        if not comment.strip(): raise ValueError("a justification is required to request a write-off")
        conn.execute("UPDATE cases SET requested_by=? WHERE case_id=?", (actor, case_id))
    if to == "RECOVERED":
        recovered = int(recovered or 0)
        if not 0 < recovered <= c["at_stake"] * 1.01: raise ValueError("recovered amount must be > 0 and no more than the amount at stake")
        conn.execute("UPDATE cases SET recovered=? WHERE case_id=?", (recovered, case_id))
    conn.execute("UPDATE cases SET status=?, updated_at=? WHERE case_id=?", (to, security.now_iso(), case_id))
    event(conn, case_id, actor, "status", f"{frm} → {to}" + (f": {comment}" if comment else ""))
    conn.commit()

def assign(conn, case_id, assignee, actor):
    c = get(conn, case_id)
    if c["status"] in TERMINAL: raise ValueError("case is closed")
    if not conn.execute("SELECT 1 FROM users WHERE username=?", (assignee,)).fetchone(): raise ValueError("unknown assignee")
    conn.execute("UPDATE cases SET assignee=?, updated_at=? WHERE case_id=?", (assignee, security.now_iso(), case_id))
    event(conn, case_id, actor, "assigned", assignee); conn.commit()

def comment(conn, case_id, actor, text):
    get(conn, case_id)
    if not text.strip(): raise ValueError("empty comment")
    event(conn, case_id, actor, "comment", text); conn.commit()

def stats(conn):
    now = security.now_iso()
    q = lambda sql, *a: conn.execute(sql, a).fetchone()[0] or 0
    openq = "status NOT IN ('RECOVERED','WRITTEN_OFF','AUTO_RESOLVED')"
    claimable = q("SELECT sum(at_stake) FROM cases WHERE status IN ('RECOVERED','WRITTEN_OFF') OR " + openq)
    return {"by_status": {r[0]: r[1] for r in conn.execute("SELECT status, count(*) FROM cases GROUP BY 1")},
            "open_cases": q(f"SELECT count(*) FROM cases WHERE {openq}"), "open_at_stake": q(f"SELECT sum(at_stake) FROM cases WHERE {openq}"),
            "sla_breached": q(f"SELECT count(*) FROM cases WHERE {openq} AND due_at<?", now), "recovered": q("SELECT sum(recovered) FROM cases"),
            "written_off": q("SELECT sum(at_stake) FROM cases WHERE status='WRITTEN_OFF'"),
            "recovery_rate_pct": round(100 * q("SELECT sum(recovered) FROM cases") / claimable, 1) if claimable else 0.0}

def listing(conn, status=None, assignee=None, limit=100):
    q, a = "SELECT * FROM cases WHERE 1=1", []
    if status: q += " AND status=?"; a.append(status)
    if assignee: q += " AND assignee=?"; a.append(assignee)
    return [dict(r) for r in conn.execute(q + " ORDER BY CASE priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, at_stake DESC LIMIT ?", (*a, min(limit, 500)))]
