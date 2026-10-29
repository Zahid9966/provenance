import base64, binascii, json, mimetypes, os, re, signal, sys, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from . import analytics, cases, config, copilot, db, pipeline, security

STATIC = Path(__file__).parent / "static"
LIMITER, LOGIN_LIMITER = security.RateLimiter(120, 10), security.RateLimiter(10, 60)
RUN_LOCK = threading.Lock()
TRUST_PROXY = os.environ.get("PROVENANCE_TRUST_PROXY") == "1"
MAX_JSON, MAX_UPLOAD = 8192, 8 * 1024 * 1024
STARTED = time.time()
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
HSTS = os.environ.get("PROVENANCE_HSTS") == "1"   # enable when served behind TLS


def log(**kw):
    sys.stdout.write(json.dumps({"ts": security.now_iso(), **kw}) + "\n"); sys.stdout.flush()


def run_pipeline_locked(actor):
    if not RUN_LOCK.acquire(blocking=False): return None
    try:
        conn = db.connect()
        try: return pipeline.run_pipeline(conn, actor=actor)
        finally: conn.close()
    finally: RUN_LOCK.release()


class Scheduler(threading.Thread):
    """Polls the landing folder (the SFTP/object-sync drop point) and runs the pipeline only when new files arrive; anchors the audit chain."""
    def __init__(self, minutes): super().__init__(daemon=True); self.every, self.stop_ev = max(1, minutes) * 60, threading.Event()
    def run(self):
        while not self.stop_ev.wait(self.every if self.every else 60):
            try:
                conn = db.connect()
                try:
                    new = pipeline.pending_files(conn)
                    if new and (r := run_pipeline_locked("scheduler")): log(event="scheduled_run", files=new, run_id=r["run_id"])
                    security.anchor(conn)
                finally: conn.close()
            except Exception as e: log(event="scheduler_error", error=str(e))


def metrics_text(conn):
    run = conn.execute("SELECT * FROM pipeline_runs WHERE status='success' ORDER BY started_at DESC LIMIT 1").fetchone()
    cs = cases.stats(conn)
    g = lambda n, h, v: f"# HELP {n} {h}\n# TYPE {n} gauge\n{n} {v}\n"
    return "".join([
        g("provenance_up", "Service up", 1), g("provenance_uptime_seconds", "Process uptime", int(time.time() - STARTED)),
        g("provenance_alerts_open", "Open security alerts", conn.execute("SELECT count(*) FROM alerts WHERE status='open'").fetchone()[0]),
        g("provenance_recon_exceptions", "Reconciliation exceptions", conn.execute("SELECT count(*) FROM gold_order_fin WHERE recon_state='EXCEPTION'").fetchone()[0]),
        g("provenance_cases_open", "Open cases", cs["open_cases"]), g("provenance_cases_sla_breached", "Open cases past SLA", cs["sla_breached"]),
        g("provenance_value_at_stake_paise", "Open value at stake", cs["open_at_stake"]), g("provenance_recovered_paise", "Recovered value", cs["recovered"]),
        g("provenance_dq_score", "Latest data-quality score", pipeline.dq_score(conn, run["run_id"]) if run else 0),
        g("provenance_last_pipeline_success_timestamp", "Unix time of last successful run", int(time.mktime(time.strptime(run["finished_at"], "%Y-%m-%dT%H:%M:%SZ"))) if run else 0),
        g("provenance_audit_chain_ok", "1 if audit chain verifies", int(security.verify_audit(conn)["ok"]))])


class H(BaseHTTPRequestHandler):
    server_version = "Provenance"; protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass

    def ip(self):
        return (self.headers.get("X-Forwarded-For", "").split(",")[0].strip() or self.client_address[0]) if TRUST_PROXY else self.client_address[0]

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
        self.status = code
        self.send_response(code)
        hdrs = [("Content-Type", ctype), ("Content-Length", str(len(data))), ("Cache-Control", "no-store"), ("Content-Security-Policy", CSP), ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer"), ("X-Request-Id", self.rid)]
        if HSTS: hdrs.append(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
        for k, v in hdrs: self.send_header(k, v)
        self.end_headers(); self.wfile.write(data)

    def _route(self, method):
        self.rid, self.status, t0 = uuid.uuid4().hex[:12], 0, time.monotonic()
        u = urlparse(self.path)
        try: self._dispatch(method, u)
        except Exception as e:
            log(event="unhandled", rid=self.rid, error=repr(e)); self._send(500, {"error": "internal error", "request_id": self.rid})
        log(event="http", rid=self.rid, method=method, path=u.path, status=self.status, ms=round(1000 * (time.monotonic() - t0), 1), ip=self.ip())

    def _body(self, limit):
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit: self.close_connection = True; self._send(413, {"error": "body too large"}); return None   # unread body: do not reuse the socket
        try: return json.loads(self.rfile.read(n) or b"{}")
        except ValueError: self._send(400, {"error": "invalid json"}); return None

    def _dispatch(self, method, u):
        q = {k: v[0] for k, v in parse_qs(u.query).items()}; path = u.path
        if path == "/healthz": return self._send(200, {"status": "ok"})
        if path == "/readyz":
            conn = db.connect()
            try:
                conn.execute("SELECT 1 FROM pipeline_runs LIMIT 1"); last = conn.execute("SELECT max(finished_at) FROM pipeline_runs WHERE status='success'").fetchone()[0]
                return self._send(200 if last else 503, {"ready": bool(last), "last_pipeline_success": last})
            finally: conn.close()
        if path == "/metrics":
            tok = os.environ.get("PROVENANCE_METRICS_TOKEN")
            if (tok and self.headers.get("Authorization") != f"Bearer {tok}") or (not tok and self.client_address[0] not in ("127.0.0.1", "::1")):
                return self._send(403, {"error": "forbidden"})
            conn = db.connect()
            try: return self._send(200, metrics_text(conn).encode(), "text/plain; version=0.0.4")
            finally: conn.close()
        if method == "GET" and not path.startswith("/api/"):
            f = (STATIC / ("index.html" if path == "/" else path.lstrip("/"))).resolve()
            if STATIC.resolve() not in f.parents or not f.is_file(): return self._send(404, {"error": "not found"})
            return self._send(200, f.read_bytes(), mimetypes.guess_type(f.name)[0] or "application/octet-stream")
        body = {}
        if method == "POST":
            body = self._body(MAX_UPLOAD * 2 if path == "/api/ingest" else MAX_JSON)
            if body is None: return
        conn = db.connect()
        try: self._api(conn, method, path, q, body)
        except (ValueError, KeyError) as e: self._send(400, {"error": str(e.args[0] if e.args else e)})
        except PermissionError as e: self._send(403, {"error": str(e)})
        finally: conn.close()

    def _api(self, conn, method, path, q, body):
        if path == "/api/login" and method == "POST":
            if not LOGIN_LIMITER.allow(self.ip()): return self._send(429, {"error": "too many attempts"})
            user = str(body.get("username", ""))[:64]
            res = security.login(conn, user, str(body.get("password", ""))[:200], str(body.get("otp", ""))[:10] or None)
            security.audit(conn, user or "?", "-", "login.success" if "token" in res else "login.failure", self.ip(), {"mfa": bool(res.get("mfa_required")), "locked": bool(res.get("locked"))})
            return self._send(200 if "token" in res else (423 if res.get("locked") else 401), res)
        h = self.headers.get("Authorization", "")
        me = security.read_token(h[7:], conn) if h.startswith("Bearer ") else None
        if not me: return self._send(401, {"error": "authentication required"})
        if not LIMITER.allow(me["u"]): return self._send(429, {"error": "rate limited"})
        role, user = me["r"], me["u"]
        def need(perm, audit=None, detail=None):
            if not security.can(role, perm):
                security.audit(conn, user, role, "access.denied", path, {"needed": perm}); self._send(403, {"error": f"role '{role}' lacks '{perm}'"}); return False
            if audit: security.audit(conn, user, role, audit, path, detail if detail is not None else (q or None))
            return True
        int_q = lambda k, d=0: int(q.get(k, d))

        if path == "/api/me":
            u = conn.execute("SELECT mfa_secret FROM users WHERE username=?", (user,)).fetchone()
            return self._send(200, {"user": user, "role": role, "perms": sorted(security.PERMS[role]), "mfa": bool(u and u["mfa_secret"] and not u["mfa_secret"].startswith("PENDING:"))})
        if path == "/api/logout" and method == "POST": security.revoke_sessions(conn, user); security.audit(conn, user, role, "logout", ""); return self._send(200, {"ok": True})
        if path == "/api/account/password" and method == "POST" and need("account"):
            security.change_password(conn, user, str(body.get("old", "")), str(body.get("new", ""))); security.audit(conn, user, role, "account.password_changed", "")
            return self._send(200, {"ok": True, "note": "all sessions revoked; sign in again"})
        if path == "/api/account/mfa/begin" and method == "POST" and need("account", "account.mfa_begin"): return self._send(200, security.mfa_begin(conn, user))
        if path == "/api/account/mfa/confirm" and method == "POST" and need("account", "account.mfa_enabled"):
            security.mfa_confirm(conn, user, str(body.get("code", ""))); return self._send(200, {"ok": True})
        if path == "/api/overview" and need("overview"): return self._send(200, {**analytics.overview(conn), "cases": cases.stats(conn)})
        if path == "/api/anomalies" and need("overview"): return self._send(200, analytics.anomalies(conn))
        if path == "/api/recon" and need("recon"):
            rows = analytics.exceptions(conn, q.get("state", "EXCEPTION"), q.get("channel"), q.get("reason"), int_q("limit", 100))
            for r in rows: r["customer_token"] = security.mask_token(role, r["customer_token"])
            return self._send(200, rows)
        if path == "/api/pipeline" and need("pipeline_view"):
            runs = [dict(r) for r in conn.execute("SELECT * FROM pipeline_runs ORDER BY started_at DESC LIMIT 8")]; rid = runs[0]["run_id"] if runs else ""
            return self._send(200, {"runs": runs, "stages": [dict(r) for r in conn.execute("SELECT * FROM pipeline_stages WHERE run_id=?", (rid,))],
                "dq": [dict(r) for r in conn.execute("SELECT * FROM dq_results WHERE run_id=?", (rid,))], "score": pipeline.dq_score(conn, rid) if rid else None,
                "quarantine": [dict(r) for r in conn.execute("SELECT source, reason FROM quarantine LIMIT 20")], "lineage": [dict(r) for r in conn.execute("SELECT * FROM lineage")],
                "pending_files": pipeline.pending_files(conn)})
        if path == "/api/pipeline/run" and method == "POST" and need("pipeline_run", "pipeline.run"):
            r = run_pipeline_locked(user); return self._send(200, r) if r else self._send(409, {"error": "a run is already in progress"})
        if path == "/api/ingest" and method == "POST" and need("ingest"):
            name = str(body.get("filename", ""))
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name) or name.startswith("."): raise ValueError("invalid filename")
            if not any(name.startswith(k) for k in pipeline.SOURCES) or not name.endswith((".csv", ".jsonl")): raise ValueError("filename must start with a known source prefix and end in .csv/.jsonl")
            try: raw = base64.b64decode(str(body.get("content_b64", "")), validate=True)
            except (binascii.Error, ValueError): raise ValueError("content_b64 is not valid base64")
            if not raw or len(raw) > MAX_UPLOAD: raise ValueError("file empty or over 8 MB")
            try: txt = raw.decode("utf-8")
            except UnicodeDecodeError: raise ValueError("file must be UTF-8")
            first = txt.lstrip().splitlines()[0] if txt.strip() else ""
            if name.endswith(".jsonl"):
                try: json.loads(first)
                except ValueError: raise ValueError("first line is not valid JSON")
            elif "," not in first: raise ValueError("CSV header row missing")
            config.LANDING.mkdir(parents=True, exist_ok=True)
            dest = config.LANDING / name
            if dest.exists() and dest.read_bytes() != raw: dest = config.LANDING / f"{dest.stem}.{int(time.time())}{dest.suffix}"; name = dest.name   # never overwrite evidence
            dest.write_bytes(raw)
            security.audit(conn, user, role, "ingest.upload", name, {"bytes": len(raw), "sha256": __import__("hashlib").sha256(raw).hexdigest()[:16]})
            res = {"stored": name, "bytes": len(raw)}
            if body.get("run"): res["run"] = run_pipeline_locked(user)
            return self._send(200, res)
        if path == "/api/alerts" and need("security", "alerts.view"):
            return self._send(200, [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END, id")])
        if path == "/api/alerts/ack" and method == "POST" and need("alerts_ack", "alerts.ack", {"id": body.get("id")}):
            conn.execute("UPDATE alerts SET status='acknowledged' WHERE id=?", (int(body.get("id", 0)),)); conn.commit(); return self._send(200, {"ok": True})
        if path == "/api/audit" and need("audit", "audit.view"):
            return self._send(200, {"verify": security.verify_audit(conn), "entries": [dict(r) for r in conn.execute("SELECT seq,ts,actor,role,action,resource,detail,substr(mac,1,12) mac FROM audit_log ORDER BY seq DESC LIMIT 60")]})
        if path == "/api/audit/siem" and need("audit", "audit.siem_export"): return self._send(200, ("\n".join(security.siem_events(conn, int_q("since"))) + "\n").encode(), "text/plain")
        if path == "/api/ask" and method == "POST" and need("ask"):
            res = copilot.ask(conn, str(body.get("question", "")))
            security.audit(conn, user, role, "copilot.blocked" if res.get("blocked") else "copilot.ask", "", {"q": security.redact(str(body.get("question")))[:200], "plan": res.get("plan")})
            return self._send(200, res)
        if path == "/api/investigate" and need("investigate", "investigate.view"):
            r = copilot.investigate(conn, q.get("order_id", ""), role); return self._send(200 if r else 404, r or {"error": "unknown order"})
        if path == "/api/recall" and need("recall", "recall.trace"):
            r = analytics.recall_exposure(conn, q.get("lot", "")); return self._send(200 if r else 404, r or {"error": "unknown lot"})
        if path == "/api/lots" and need("recall"): return self._send(200, [dict(r) for r in conn.execute("SELECT lot_id, sku, supplier FROM silver_lots ORDER BY lot_id")])
        # ---- cases ----
        if path == "/api/cases" and need("cases_view"): return self._send(200, {"stats": cases.stats(conn), "cases": cases.listing(conn, q.get("status"), q.get("assignee"), int_q("limit", 100))})
        if path == "/api/case" and need("cases_view"):
            c = cases.get(conn, int_q("id")); return self._send(200, {"case": dict(c), "events": [dict(r) for r in conn.execute("SELECT ts,actor,kind,detail FROM case_events WHERE case_id=? ORDER BY id", (c["case_id"],))]})
        if path == "/api/case/transition" and method == "POST" and need("cases_manage"):
            cid, to = int(body.get("id", 0)), str(body.get("to", ""))
            try: cases.transition(conn, cid, to, user, role, str(body.get("comment", "")), body.get("recovered_paise"))
            except PermissionError as e: security.audit(conn, user, role, "access.denied", f"case/{cid}", {"to": to, "why": str(e)}); raise
            security.audit(conn, user, role, "case.transition", f"case/{cid}", {"to": to}); return self._send(200, {"ok": True})
        if path == "/api/case/assign" and method == "POST" and need("cases_manage", "case.assign", {"id": body.get("id"), "to": body.get("assignee")}):
            cases.assign(conn, int(body.get("id", 0)), str(body.get("assignee", "")), user); return self._send(200, {"ok": True})
        if path == "/api/case/comment" and method == "POST" and need("cases_manage"):
            cases.comment(conn, int(body.get("id", 0)), user, str(body.get("text", ""))); return self._send(200, {"ok": True})
        if path == "/api/users" and need("cases_manage"): return self._send(200, [r[0] for r in conn.execute("SELECT username FROM users ORDER BY 1")])
        return self._send(404, {"error": "not found"})

    def do_GET(self): self._route("GET")
    def do_POST(self): self._route("POST")


class Server(ThreadingHTTPServer):
    daemon_threads = True
    def handle_error(self, request, client_address):
        log(event="connection_error", error=repr(sys.exc_info()[1]), ip=client_address[0])   # resets/broken pipes are routine, not tracebacks


def make_server(port=8787, bind="127.0.0.1"):
    return Server((bind, port), H)


def serve(port=8787, bind=None, schedule_minutes=0):
    bind = bind or os.environ.get("PROVENANCE_BIND", "127.0.0.1")
    srv = make_server(port, bind); sched = None
    if schedule_minutes: sched = Scheduler(schedule_minutes); sched.start()
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=srv.shutdown).start())   # graceful stop for orchestrators
    log(event="listening", bind=bind, port=port, scheduler_minutes=schedule_minutes)
    try: srv.serve_forever()
    except KeyboardInterrupt: pass
    finally:
        if sched: sched.stop_ev.set()
        srv.server_close(); log(event="stopped")
