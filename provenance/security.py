"""Security layer: PII tokenization, tamper-evident audit chain, auth/RBAC, detections, LLM guards."""
import base64, hashlib, hmac, json, os, re, secrets, statistics, struct, time
from datetime import datetime, timezone
from . import config, db

# ---------- PII ----------
def _k(name): return bytes.fromhex(config.keys()[name])

def tokenize(value: str) -> str:
    """Keyed one-way token: joinable across tables, not reversible, useless without the install key."""
    return hmac.new(_k("pii"), value.strip().lower().encode(), hashlib.sha256).hexdigest()[:16]

def mask_email(e: str) -> str:
    u, _, d = e.partition("@")
    return (u[:1] + "***@" + d) if d else "***"

_PII = [
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[EMAIL]"),
    (re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), "[PAN]"),
    (re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"), "[ID12]"),
    (re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)"), "[PHONE]"),
]
def _luhn(digits: str) -> bool:
    d = [int(c) for c in digits][::-1]
    return (sum(d[0::2]) + sum(sum(divmod(x * 2, 10)) for x in d[1::2])) % 10 == 0

def redact(text: str) -> str:
    """Strip PII before any text leaves the trust boundary (e.g. to an LLM)."""
    def card(m):
        digits = re.sub(r"\D", "", m.group())
        return "[CARD]" if 13 <= len(digits) <= 19 and _luhn(digits) else m.group()
    text = re.sub(r"\b(?:\d[ -]?){12,18}\d\b", card, text)   # cards first so ID/phone rules don't split them
    for rx, rep in _PII:
        text = rx.sub(rep, text)
    return text

_INJ = [re.compile(p, re.I) for p in (
    r"ignore (all |any |the )?(previous|prior|above) (instructions|prompts?|rules)",
    r"disregard (all |any |the )?(previous|prior|above|system)",
    r"you are now\b", r"system prompt", r"reveal .{0,40}(email|password|key|secret|customer)",
    r"(act|respond) as (an? )?(admin|root|developer)", r"<\s*/?\s*(system|assistant|instructions?)\s*>",
    r"\b(exfiltrate|jailbreak)\b", r"curl\s+https?://", r"base64[:,]",
)]
def injection_score(text: str) -> int:
    return sum(1 for rx in _INJ if rx.search(text or ""))


# ---------- tamper-evident audit log (HMAC hash chain) ----------
def _mac(prev, seq, ts, actor, role, action, resource, detail):
    msg = "\x1f".join([prev, str(seq), ts, actor, role, action, resource, detail]).encode()
    return hmac.new(_k("audit"), msg, hashlib.sha256).hexdigest()

def now_iso(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def audit(conn, actor, role, action, resource="", detail=None):
    detail = json.dumps(detail or {}, sort_keys=True, separators=(",", ":"))
    db.begin_write(conn)   # SQLite: BEGIN IMMEDIATE; Postgres: transaction-scoped advisory lock
    try:
        row = conn.execute("SELECT seq, mac FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        seq, prev = (row["seq"] + 1, row["mac"]) if row else (1, "GENESIS")
        ts = now_iso()
        conn.execute("INSERT INTO audit_log VALUES(?,?,?,?,?,?,?,?,?)",
                     (seq, ts, actor, role, action, resource, detail, prev, _mac(prev, seq, ts, actor, role, action, resource, detail)))
        conn.commit()
    except Exception:
        conn.rollback(); raise
    return seq

def anchor(conn) -> dict:
    """Append the current chain head, HMAC-signed, to an external anchor log. Defeats tail-truncation and wholesale rewrite
    by anyone who can alter the database but not the anchor location (use a separate WORM/append-only mount in production)."""
    row = conn.execute("SELECT seq, mac FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    if not row: return {}
    ts = now_iso()
    rec = {"seq": row["seq"], "mac": row["mac"], "ts": ts, "sig": hmac.new(_k("audit"), f"{row['seq']}|{row['mac']}|{ts}".encode(), hashlib.sha256).hexdigest()}
    config.ANCHOR_DIR.mkdir(parents=True, exist_ok=True)
    with open(config.ANCHOR_DIR / "audit_anchors.log", "a") as f: f.write(json.dumps(rec) + "\n")
    return rec

def _check_anchors(conn):
    path = config.ANCHOR_DIR / "audit_anchors.log"
    if not path.exists(): return None
    n = 0
    for line in path.read_text().splitlines():
        try: a = json.loads(line)
        except ValueError: return {"ok": False, "reason": "anchor log is corrupt"}
        if not hmac.compare_digest(a["sig"], hmac.new(_k("audit"), f"{a['seq']}|{a['mac']}|{a['ts']}".encode(), hashlib.sha256).hexdigest()):
            return {"ok": False, "broken_at": a["seq"], "reason": "anchor signature invalid"}
        r = conn.execute("SELECT mac FROM audit_log WHERE seq=?", (a["seq"],)).fetchone()
        if not r or r["mac"] != a["mac"]:
            return {"ok": False, "broken_at": a["seq"], "reason": "history before an external anchor was truncated or rewritten"}
        n += 1
    return {"ok": True, "anchors": n}

def verify_audit(conn) -> dict:
    """Recompute the chain, then cross-check external anchors. Detects edits, mid-chain deletion, reordering, insertion and tail truncation."""
    prev, expected_seq, n = "GENESIS", 1, 0
    for r in conn.execute("SELECT * FROM audit_log ORDER BY seq"):
        if r["seq"] != expected_seq:
            return {"ok": False, "entries": n, "broken_at": expected_seq, "reason": "sequence gap (deleted or reordered rows)"}
        if r["prev_mac"] != prev or not hmac.compare_digest(
                r["mac"], _mac(prev, r["seq"], r["ts"], r["actor"], r["role"], r["action"], r["resource"], r["detail"])):
            return {"ok": False, "entries": n, "broken_at": r["seq"], "reason": "MAC mismatch (row altered)"}
        prev, expected_seq, n = r["mac"], expected_seq + 1, n + 1
    res = {"ok": True, "entries": n, "head": prev[:16] if n else None}
    an = _check_anchors(conn)
    if an is not None:
        if not an["ok"]: return {**an, "entries": n}
        res["anchors"] = an["anchors"]
    return res

def siem_events(conn, since_seq=0):
    """Audit + alert events as ArcSight CEF lines for any SIEM."""
    esc = lambda v: str(v).replace("\\", "\\\\").replace("=", "\\=").replace("|", "/").replace("\n", " ")
    sev = lambda a: 8 if a.startswith(("access.denied", "login.failure")) else 3
    for r in conn.execute("SELECT * FROM audit_log WHERE seq>? ORDER BY seq", (since_seq,)):
        yield f"CEF:0|Provenance|Provenance|0.2|{esc(r['action'])}|{esc(r['action'])}|{sev(r['action'])}|rt={esc(r['ts'])} suser={esc(r['actor'])} cs1Label=role cs1={esc(r['role'])} request={esc(r['resource'])} msg={esc(r['detail'])} cn1Label=seq cn1={r['seq']}"
    for r in conn.execute("SELECT * FROM alerts"):
        yield f"CEF:0|Provenance|Provenance|0.2|{esc(r['kind'])}|{esc(r['kind'])}|{ {'critical':10,'high':8,'medium':5}.get(r['severity'],3) }|rt={esc(r['created_at'])} cs1Label=subject cs1={esc(r['subject'])} msg={esc(r['detail'])}"


# ---------- auth + RBAC ----------
PERMS = {
    "admin":    {"overview", "recon", "pipeline_view", "pipeline_run", "ask", "security", "audit", "alerts_ack", "customer_ref", "recall", "investigate", "ingest", "cases_view", "cases_manage", "case_approve", "account"},
    "finance":  {"overview", "recon", "ask", "recall", "investigate", "ingest", "cases_view", "cases_manage", "account"},
    "analyst":  {"overview", "recon", "pipeline_view", "ask", "cases_view", "account"},
    "security": {"overview", "security", "audit", "alerts_ack", "customer_ref", "investigate", "cases_view", "account"},
    "auditor":  {"audit", "security", "recon", "cases_view", "account"},
}

def hash_pw(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    return hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1).hex(), salt.hex()

def check_password_policy(username, pw):
    if len(pw) < 12: raise ValueError("password must be at least 12 characters")
    if username.lower() in pw.lower(): raise ValueError("password must not contain the username")
    if sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")) < 3:
        raise ValueError("password needs at least 3 of: lowercase, uppercase, digit, symbol")

def create_user(conn, username, role, password, enforce_policy=True):
    if role not in PERMS: raise ValueError("unknown role")
    if enforce_policy: check_password_policy(username, password)
    h, s = hash_pw(password)
    conn.execute("INSERT OR REPLACE INTO users(username,role,pw_hash,salt) VALUES(?,?,?,?)", (username, role, h, s))
    conn.commit()

def change_password(conn, username, old, new):
    u = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not u or not hmac.compare_digest(hash_pw(old, bytes.fromhex(u["salt"]))[0], u["pw_hash"]): raise ValueError("current password is incorrect")
    check_password_policy(username, new)
    h, s = hash_pw(new)
    conn.execute("UPDATE users SET pw_hash=?, salt=?, token_version=token_version+1 WHERE username=?", (h, s, username)); conn.commit()   # revokes all sessions

# TOTP (RFC 6238 / HMAC-SHA1, 30 s, 6 digits) with one-time-use enforcement
def totp(secret_b32, t=None, step=30, digits=6):
    counter = int((t if t is not None else time.time()) // step)
    h = hmac.new(base64.b32decode(secret_b32), struct.pack(">Q", counter), "sha1").digest()
    o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)

def _verify_totp(conn, user_row, code):
    now = int(time.time() // 30)
    for c in (now - 1, now, now + 1):
        if hmac.compare_digest(totp(user_row["mfa_secret"], c * 30), str(code).strip()) and c > (user_row["mfa_last"] or 0):
            conn.execute("UPDATE users SET mfa_last=? WHERE username=?", (c, user_row["username"])); return True   # a code can never be replayed
    return False

def mfa_begin(conn, username):
    secret = base64.b32encode(secrets.token_bytes(20)).decode()
    conn.execute("UPDATE users SET mfa_secret=?, mfa_last=0 WHERE username=?", ("PENDING:" + secret, username)); conn.commit()
    return {"secret": secret, "otpauth": f"otpauth://totp/Provenance:{username}?secret={secret}&issuer=Provenance"}

def mfa_confirm(conn, username, code):
    u = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not u or not (u["mfa_secret"] or "").startswith("PENDING:"): raise ValueError("no MFA enrolment in progress")
    pending = {**dict(u), "mfa_secret": u["mfa_secret"][8:]}
    if not _verify_totp(conn, pending, code): raise ValueError("invalid code")
    conn.execute("UPDATE users SET mfa_secret=? WHERE username=?", (pending["mfa_secret"], username)); conn.commit()

MAX_FAILURES, LOCK_SECONDS = 5, 900

def login(conn, username, password, otp=None):
    """Returns {'token':...} or {'error':..., 'mfa_required':bool}. Locks an account after repeated failures."""
    st = conn.execute("SELECT * FROM login_state WHERE username=?", (username,)).fetchone()
    if st and st["locked_until"] > time.time(): return {"error": "account temporarily locked", "locked": True}
    r = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    h, _ = hash_pw(password, bytes.fromhex(r["salt"]) if r else b"\0" * 16)   # equal work for unknown users
    ok = bool(r) and hmac.compare_digest(h, r["pw_hash"])
    if ok and r["mfa_secret"] and not r["mfa_secret"].startswith("PENDING:"):
        if not otp: return {"error": "one-time code required", "mfa_required": True}
        ok = _verify_totp(conn, r, otp)
    if not ok:
        n = (st["failures"] if st else 0) + 1
        conn.execute("INSERT OR REPLACE INTO login_state VALUES(?,?,?)", (username, 0 if n >= MAX_FAILURES else n, time.time() + LOCK_SECONDS if n >= MAX_FAILURES else 0)); conn.commit()
        return {"error": "invalid credentials"}
    conn.execute("DELETE FROM login_state WHERE username=?", (username,)); conn.commit()
    return {"token": issue_token(r["username"], r["role"], tv=r["token_version"] or 0)}

def issue_token(user, role, ttl=3600, tv=0):
    body = base64.urlsafe_b64encode(json.dumps({"u": user, "r": role, "exp": int(time.time()) + ttl, "tv": tv}).encode()).decode().rstrip("=")
    return body + "." + hmac.new(_k("session"), body.encode(), hashlib.sha256).hexdigest()

def read_token(tok, conn=None):
    """Verify signature, expiry and (when a connection is given) that the session has not been revoked."""
    try:
        body, sig = tok.rsplit(".", 1)
        if not hmac.compare_digest(sig, hmac.new(_k("session"), body.encode(), hashlib.sha256).hexdigest()): return None
        d = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if d["exp"] <= time.time() or d["r"] not in PERMS: return None
        if conn is not None:
            u = conn.execute("SELECT role, token_version FROM users WHERE username=?", (d["u"],)).fetchone()
            if not u or (u["token_version"] or 0) != d.get("tv", 0) or u["role"] != d["r"]: return None
        return d
    except Exception:
        return None

def revoke_sessions(conn, username):
    conn.execute("UPDATE users SET token_version=token_version+1 WHERE username=?", (username,)); conn.commit()

def can(role, perm): return perm in PERMS.get(role, ())

def mask_token(role, token):
    return token if can(role, "customer_ref") else "••••" + (token or "")[-4:]

class RateLimiter:
    def __init__(self, rate=30, per=10.0): self.rate, self.per, self.b = rate, per, {}
    def allow(self, key):
        t = time.monotonic(); n, start = self.b.get(key, (0, t))
        if t - start > self.per: n, start = 0, t
        self.b[key] = (n + 1, start)
        return n + 1 <= self.rate


# ---------- detections ----------
def _alert(conn, kind, sev, subject, detail):
    cur = conn.execute("INSERT OR IGNORE INTO alerts(kind,severity,subject,detail,created_at) VALUES(?,?,?,?,?)",
                       (kind, sev, subject, json.dumps(detail, sort_keys=True), now_iso()))
    return cur.rowcount

def _mad_outliers(vals, k=6.0):
    med = statistics.median(vals); mad = statistics.median(abs(v - med) for v in vals) or 1.0
    return [i for i, v in enumerate(vals) if (v - med) / (1.4826 * mad) > k]

def run_detections(conn) -> dict:
    new = {"insider_refund": 0, "bulk_export": 0, "velocity_fraud": 0, "prompt_injection": 0}
    # 1. insider refund abuse: one approver, off-hours, repeatedly refunding the same customer
    rows = conn.execute("""SELECT r.approved_by a, o.customer_token c, count(*) n, sum(r.amount) amt,
                 sum(CASE WHEN CAST(substr(r.ts,12,2) AS INTEGER) BETWEEN 0 AND 4 THEN 1 ELSE 0 END) AS off
               FROM silver_refunds r JOIN silver_orders o ON o.order_id=r.order_id GROUP BY r.approved_by, o.customer_token
               HAVING count(*)>=4 AND 2*sum(CASE WHEN CAST(substr(r.ts,12,2) AS INTEGER) BETWEEN 0 AND 4 THEN 1 ELSE 0 END)>=count(*)""").fetchall()
    for r in rows:
        new["insider_refund"] += _alert(conn, "insider_refund", "high", f"{r['a']}→{r['c'][:6]}",
            {"approver": r["a"], "refunds": r["n"], "off_hours": r["off"], "amount_paise": r["amt"],
             "why": "same approver repeatedly refunds one customer, mostly 00:00–04:59 UTC"})
    # 2. bulk export outlier vs everyone else's export sizes
    ex = conn.execute("SELECT actor, ts, rows FROM silver_staff_actions WHERE action='export_customers' ORDER BY ts").fetchall()
    if len(ex) >= 8:
        for i in _mad_outliers([e["rows"] for e in ex]):
            if ex[i]["rows"] >= 5000:
                new["bulk_export"] += _alert(conn, "bulk_export", "critical", f"{ex[i]['actor']}@{ex[i]['ts']}",
                    {"actor": ex[i]["actor"], "rows": ex[i]["rows"], "ts": ex[i]["ts"], "why": "export size is a robust-statistics outlier vs. peers"})
    # 3. card-testing / velocity: many orders, many distinct cards, one identity, one hour
    rows = conn.execute("""SELECT o.customer_token c, substr(o.placed_at,1,13) h, count(DISTINCT o.order_id) n, count(DISTINCT p.card_fp) cards
               FROM silver_orders o JOIN silver_payments p ON p.order_id=o.order_id WHERE o.channel='STORE' GROUP BY o.customer_token, substr(o.placed_at,1,13)
               HAVING count(DISTINCT o.order_id)>=4 AND count(DISTINCT p.card_fp)>=3""").fetchall()
    for r in rows:
        new["velocity_fraud"] += _alert(conn, "velocity_fraud", "high", f"{r['c'][:6]}@{r['h']}",
            {"orders": r["n"], "distinct_cards": r["cards"], "hour": r["h"], "why": "multiple cards on one identity within an hour"})
    # 4. prompt-injection payloads sitting in free-text fields that a GenAI feature may later read
    for r in conn.execute("SELECT order_id, notes FROM silver_orders WHERE notes<>''"):
        s = injection_score(r["notes"])
        if s:
            new["prompt_injection"] += _alert(conn, "prompt_injection", "medium", r["order_id"],
                {"patterns_matched": s, "excerpt": redact(r["notes"])[:120], "why": "order note contains LLM-instruction patterns; excluded from AI context"})
    conn.commit()
    return new
