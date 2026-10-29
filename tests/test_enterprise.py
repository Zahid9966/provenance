import base64, csv, io, json, os, sys, tempfile, threading, time, unittest, urllib.error, urllib.request
from pathlib import Path
os.environ.setdefault("PROVENANCE_HOME", tempfile.mkdtemp())
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from provenance import analytics, cases, cli, config, db, pipeline, security, server

PW = "Str0ng!Passw0rd#1"

def ensure_initialised():
    c = db.connect()
    if not c.execute("SELECT 1 FROM pipeline_runs WHERE status='success'").fetchone(): cli.init()
    return c

class Http:
    def __init__(self, port): self.base = f"http://127.0.0.1:{port}"
    def call(self, method, path, body=None, token=None, raw=False):
        req = urllib.request.Request(self.base + path, json.dumps(body).encode() if body is not None else None, method=method,
                                     headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
        try:
            with urllib.request.urlopen(req) as r: data, code, hdr = r.read(), r.status, r.headers
        except urllib.error.HTTPError as e: data, code, hdr = e.read(), e.code, e.headers
        return code, (data.decode() if raw else json.loads(data)), hdr
    def login(self, user, pw=PW, otp=None):
        c, j, _ = self.call("POST", "/api/login", {"username": user, "password": pw, **({"otp": otp} if otp else {})}); return c, j

class Ent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = ensure_initialised()
        for u, r in (("e.admin", "admin"), ("e.fin1", "finance"), ("e.fin2", "finance"), ("e.analyst", "analyst"), ("e.aud", "auditor")):
            security.create_user(cls.c, u, r, PW)
        server.LOGIN_LIMITER = security.RateLimiter(10_000, 60)   # the real limiter has its own test below
        cls.srv = server.make_server(0); cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start(); cls.h = Http(cls.port)
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown(); cls.srv.server_close()
    def tok(self, u): return self.h.login(u)[1]["token"]

class TestAuthHardening(Ent):
    def test_totp_rfc6238_vectors(self):
        k = base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(security.totp(k, 59, digits=8), "94287082"); self.assertEqual(security.totp(k, 1111111109, digits=8), "07081804")
    def test_password_policy(self):
        for bad in ("short1!A", "alllowercaseletters", "e.adminAdmin123!!x"):
            with self.assertRaises(ValueError): security.check_password_policy("e.admin", bad)
        security.check_password_policy("x", PW)
    def test_mfa_enrol_login_and_replay_protection(self):
        security.create_user(self.c, "e.mfa", "finance", PW)
        b = security.mfa_begin(self.c, "e.mfa"); self.assertIn("token", security.login(self.c, "e.mfa", PW))   # pending enrolment does not yet gate login
        code = security.totp(b["secret"]); security.mfa_confirm(self.c, "e.mfa", code)
        self.assertTrue(security.login(self.c, "e.mfa", PW)["mfa_required"])
        self.assertNotIn("token", security.login(self.c, "e.mfa", PW, "000000"))
        nxt = security.totp(b["secret"], time.time() + 30); self.assertIn("token", security.login(self.c, "e.mfa", PW, nxt))
        self.assertNotIn("token", security.login(self.c, "e.mfa", PW, nxt))   # same code cannot be replayed
    def test_lockout_then_correct_password_still_refused(self):
        security.create_user(self.c, "e.lock", "analyst", PW)
        for _ in range(5): security.login(self.c, "e.lock", "wrong")
        r = security.login(self.c, "e.lock", PW); self.assertTrue(r.get("locked")); self.assertNotIn("token", r)
    def test_password_change_revokes_existing_sessions(self):
        security.create_user(self.c, "e.pw", "analyst", PW); t = self.tok("e.pw")
        self.assertEqual(self.h.call("GET", "/api/me", token=t)[0], 200)
        self.assertEqual(self.h.call("POST", "/api/account/password", {"old": PW, "new": "An0ther!LongPass9"}, t)[0], 200)
        self.assertEqual(self.h.call("GET", "/api/me", token=t)[0], 401)
    def test_logout_revokes_token(self):
        t = self.tok("e.analyst"); self.h.call("POST", "/api/logout", {}, t); self.assertEqual(self.h.call("GET", "/api/me", token=t)[0], 401)

class TestAuditAnchoring(Ent):
    def test_tail_truncation_detected_via_external_anchor(self):
        security.audit(self.c, "t", "admin", "before"); security.anchor(self.c); self.assertTrue(security.verify_audit(self.c)["ok"])
        for i in range(3): security.audit(self.c, "t", "admin", f"later{i}")
        security.anchor(self.c)
        rows = [tuple(r) for r in self.c.execute("SELECT * FROM audit_log ORDER BY seq DESC LIMIT 2")]
        self.c.execute("DELETE FROM audit_log WHERE seq>=?", (rows[-1][0],)); self.c.commit()      # attacker truncates the tail; chain alone still looks valid
        r = security.verify_audit(self.c); self.assertFalse(r["ok"]); self.assertIn("truncated", r["reason"])
        for row in reversed(rows): self.c.execute("INSERT INTO audit_log VALUES(?,?,?,?,?,?,?,?,?)", row)
        self.c.commit(); self.assertTrue(security.verify_audit(self.c)["ok"])
    def test_siem_cef_export(self):
        lines = list(security.siem_events(self.c)); self.assertTrue(lines and all(l.startswith("CEF:0|Provenance|") for l in lines))

class TestCases(Ent):
    def test_one_case_per_exception_and_idempotent(self):
        n_exc = self.c.execute("SELECT count(*) FROM gold_order_fin WHERE recon_state='EXCEPTION'").fetchone()[0]
        self.assertEqual(self.c.execute("SELECT count(*) FROM cases").fetchone()[0], n_exc)
        self.assertEqual(cases.sync(self.c), {"opened": 0, "auto_resolved": 0})
    def test_lifecycle_and_segregation_of_duties(self):
        cid = self.c.execute("SELECT case_id FROM cases WHERE status='OPEN' LIMIT 1").fetchone()[0]
        with self.assertRaises(ValueError): cases.transition(self.c, cid, "RECOVERED", "e.fin1", "finance", recovered=1)      # illegal jump
        cases.transition(self.c, cid, "INVESTIGATING", "e.fin1", "finance")
        with self.assertRaises(ValueError): cases.transition(self.c, cid, "WRITEOFF_REQUESTED", "e.fin1", "finance", "  ")   # needs justification
        cases.transition(self.c, cid, "WRITEOFF_REQUESTED", "e.fin1", "finance", "partner insolvent")
        with self.assertRaises(PermissionError): cases.transition(self.c, cid, "WRITTEN_OFF", "e.fin2", "finance")          # wrong role
        with self.assertRaises(PermissionError): cases.transition(self.c, cid, "WRITTEN_OFF", "e.fin1", "admin")            # requester cannot approve own
        cases.transition(self.c, cid, "WRITTEN_OFF", "e.admin", "admin")
        with self.assertRaises(ValueError): cases.transition(self.c, cid, "INVESTIGATING", "e.admin", "admin")              # terminal
        self.assertGreaterEqual(self.c.execute("SELECT count(*) FROM case_events WHERE case_id=?", (cid,)).fetchone()[0], 4)
    def test_recovery_amount_bounded(self):
        cid = self.c.execute("SELECT case_id, at_stake FROM cases WHERE status='OPEN' ORDER BY case_id DESC LIMIT 1").fetchone()
        cases.transition(self.c, cid[0], "DISPUTED", "e.fin1", "finance")
        with self.assertRaises(ValueError): cases.transition(self.c, cid[0], "RECOVERED", "e.fin1", "finance", recovered=cid[1] * 3)
        cases.transition(self.c, cid[0], "RECOVERED", "e.fin1", "finance", recovered=cid[1])
        self.assertGreater(cases.stats(self.c)["recovered"], 0)
    def test_api_sod_and_rbac(self):
        f1, ad, an = (self.tok(u) for u in ("e.fin1", "e.admin", "e.analyst"))
        cid = self.c.execute("SELECT case_id FROM cases WHERE status='OPEN' LIMIT 1").fetchone()[0]
        tr = lambda to, tok, **kw: self.h.call("POST", "/api/case/transition", {"id": cid, "to": to, **kw}, tok)[0]
        self.assertEqual(tr("INVESTIGATING", an), 403)                                       # analyst is read-only
        self.assertEqual(tr("WRITEOFF_REQUESTED", f1), 400)                                  # justification required
        self.assertEqual(tr("WRITEOFF_REQUESTED", f1, comment="partner insolvent"), 200)
        self.assertEqual(tr("WRITTEN_OFF", f1), 403)                                         # finance cannot approve
        self.assertEqual(self.h.call("GET", f"/api/case?id={cid}", token=f1)[1]["case"]["status"], "WRITEOFF_REQUESTED")
        self.assertEqual(tr("WRITTEN_OFF", ad), 200)                                         # a different, authorised person can
    def test_requester_admin_cannot_self_approve(self):
        ad = self.tok("e.admin"); cid = self.c.execute("SELECT case_id FROM cases WHERE status='OPEN' LIMIT 1").fetchone()[0]
        self.assertEqual(self.h.call("POST", "/api/case/transition", {"id": cid, "to": "WRITEOFF_REQUESTED", "comment": "x"}, ad)[0], 200)
        self.assertEqual(self.h.call("POST", "/api/case/transition", {"id": cid, "to": "WRITTEN_OFF"}, ad)[0], 403)
    def test_assign_and_comment_via_api(self):
        f1 = self.tok("e.fin1"); cid = self.c.execute("SELECT case_id FROM cases WHERE status='OPEN' LIMIT 1").fetchone()[0]
        self.assertEqual(self.h.call("POST", "/api/case/assign", {"id": cid, "assignee": "e.fin2"}, f1)[0], 200)
        self.assertEqual(self.h.call("POST", "/api/case/assign", {"id": cid, "assignee": "nobody"}, f1)[0], 400)
        self.assertEqual(self.h.call("POST", "/api/case/comment", {"id": cid, "text": "mail a@b.com about it"}, f1)[0], 200)
        ev = self.h.call("GET", f"/api/case?id={cid}", token=f1)[1]["events"]; self.assertNotIn("a@b.com", json.dumps(ev))

class TestConnectors(Ent):
    def _upload(self, name, content, token, run=False):
        return self.h.call("POST", "/api/ingest", {"filename": name, "content_b64": base64.b64encode(content).decode(), "run": run}, token)
    def test_upload_validation(self):
        t = self.tok("e.fin1")
        for name in ("../etc/passwd", "settlements_X.exe", "unknown_file.csv", ".hidden.csv", "a" * 90 + ".csv"):
            self.assertEqual(self._upload(name, b"a,b\n1,2\n", t)[0], 400, name)
        self.assertEqual(self.h.call("POST", "/api/ingest", {"filename": "settlements_Z.csv", "content_b64": "!!notbase64"}, t)[0], 400)
        self.assertEqual(self._upload("refunds_x.jsonl", b"not json\n", t)[0], 400)
        self.assertEqual(self._upload("settlements_Z.csv", b"x\n", t)[0], 400)
        self.assertEqual(self._upload("settlements_Z.csv", b"a,b\n1,2\n", self.tok("e.analyst"))[0], 403)
        self.assertEqual(self._upload("settlements_Z.csv", b"a,b\n1,2\n", None)[0], 401)
    def test_oversize_rejected(self):
        req = urllib.request.Request(self.h.base + "/api/login", b"{" + b" " * 20000 + b"}", {"Content-Type": "application/json"}, method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm: urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 413)
    def test_new_partner_onboarded_by_mapping_profile_no_code_change(self):
        (config.HOME / "channels.json").write_text(json.dumps({"ACME": {"kind": "marketplace", "commission": 0.10, "fixed_fee": 0, "withholding": 0.0}}))
        (config.HOME / "mappings.json").write_text(json.dumps({"settlements_ACME": {"SettlementId": "TxnId", "OrderRef": "Reference", "SettledOn": "PaidDate", "Gross": "OrderValue",
            "Commission": "Fee", "FixedFee": "Fixed", "TaxWithheld": "Tax", "NetPayout": "Payout"}}))
        order = self.c.execute("SELECT order_id, total FROM silver_orders WHERE channel='QCOM' AND status='DELIVERED' LIMIT 1").fetchone()
        out = io.StringIO(); w = csv.writer(out); w.writerow(["TxnId", "Reference", "PaidDate", "OrderValue", "Fee", "Fixed", "Tax", "Payout"])
        tot = order["total"] / 100; w.writerow(["ACME-1", order["order_id"], "01-10-2026", f"{tot:.2f}", f"{tot*.1:.2f}", "0.00", "0.00", f"{tot*.9:.2f}"])
        try:
            code, j, _ = self._upload("settlements_ACME.csv", out.getvalue().encode(), self.tok("e.admin"), run=True)
            self.assertEqual(code, 200); self.assertIsNotNone(j["run"])
            row = self.c.execute("SELECT channel, net FROM silver_settlements WHERE settlement_id='ACME-1'").fetchone()
            self.assertEqual(row["channel"], "ACME"); self.assertAlmostEqual(row["net"], tot * 90, delta=2)
            self.assertEqual(self.c.execute("SELECT count(*) FROM quarantine WHERE source='settlements'").fetchone()[0], 0)
        finally:   # leave shared state as found
            for f in ("mappings.json", "channels.json"): (config.HOME / f).unlink(missing_ok=True)
            (config.LANDING / "settlements_ACME.csv").unlink(missing_ok=True)
            self.c.execute("DELETE FROM bronze_raw WHERE file_name LIKE 'settlements_ACME%'"); self.c.execute("DELETE FROM bronze_files WHERE file_name LIKE 'settlements_ACME%'"); self.c.commit()
            config.CHANNELS.pop("ACME", None); pipeline.run_pipeline(self.c)

class TestOps(Ent):
    def test_login_rate_limit_returns_429(self):
        lim = server.LOGIN_LIMITER; server.LOGIN_LIMITER = security.RateLimiter(3, 60)
        try: codes = [self.h.call("POST", "/api/login", {"username": "nobody", "password": "x"})[0] for _ in range(5)]
        finally: server.LOGIN_LIMITER = lim
        self.assertEqual(codes, [401, 401, 401, 429, 429])
    def test_health_ready_metrics(self):
        self.assertEqual(self.h.call("GET", "/healthz")[0], 200); self.assertEqual(self.h.call("GET", "/readyz")[0], 200)
        code, txt, _ = self.h.call("GET", "/metrics", raw=True)
        self.assertEqual(code, 200)
        for m in ("provenance_cases_open", "provenance_dq_score", "provenance_audit_chain_ok 1", "provenance_value_at_stake_paise"): self.assertIn(m, txt)
    def test_security_headers_and_request_id(self):
        _, _, hd = self.h.call("GET", "/", raw=True); self.assertIn("default-src 'none'", hd["Content-Security-Policy"]); self.assertEqual(hd["X-Frame-Options"], "DENY"); self.assertTrue(hd["X-Request-Id"])
    def test_rbac_denials_are_audited_and_siem_export_gated(self):
        before = self.c.execute("SELECT count(*) FROM audit_log WHERE action='access.denied'").fetchone()[0]
        self.assertEqual(self.h.call("GET", "/api/audit", token=self.tok("e.analyst"))[0], 403)
        self.assertEqual(self.c.execute("SELECT count(*) FROM audit_log WHERE action='access.denied'").fetchone()[0], before + 1)
        self.assertEqual(self.h.call("GET", "/api/audit/siem", token=self.tok("e.aud"), raw=True)[0], 200)
        self.assertEqual(self.h.call("GET", "/api/audit/siem", token=self.tok("e.fin1"), raw=True)[0], 403)
    def test_pending_files_and_scheduler_skips_noop(self):
        self.assertEqual(pipeline.pending_files(self.c), [])

if __name__ == "__main__": unittest.main()
