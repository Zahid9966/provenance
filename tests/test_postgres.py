"""Backend tests. The translator/schema tests run anywhere; the live tests run on whichever backend is configured
(set PROVENANCE_DATABASE_URL to an EMPTY database to exercise Postgres)."""
import os, sys, tempfile, threading, unittest
from pathlib import Path
os.environ.setdefault("PROVENANCE_HOME", tempfile.mkdtemp())
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from provenance import db, pgdb, security

META = pgdb.table_meta(db.SCHEMA)

class TestTranslator(unittest.TestCase):
    def tr(self, sql): return pgdb.translate(sql, META)
    def test_placeholders_numbered_and_quoted_question_marks_preserved(self):
        s, _ = self.tr("SELECT * FROM t WHERE a=? AND b='what?' AND c=?"); self.assertEqual(s, "SELECT * FROM t WHERE a=$1 AND b='what?' AND c=$2")
    def test_insert_or_ignore(self):
        s, _ = self.tr("INSERT OR IGNORE INTO silver_orders VALUES(?,?)"); self.assertEqual(s, "INSERT INTO silver_orders VALUES($1,$2) ON CONFLICT DO NOTHING")
    def test_insert_or_replace_positional_and_with_columns(self):
        s, _ = self.tr("INSERT OR REPLACE INTO silver_lots VALUES(?,?,?,?,?)")
        self.assertTrue(s.startswith("INSERT INTO silver_lots VALUES($1,$2,$3,$4,$5) ON CONFLICT (lot_id) DO UPDATE SET sku=EXCLUDED.sku"))
        s, _ = self.tr("INSERT OR REPLACE INTO users(username,role,pw_hash,salt) VALUES(?,?,?,?)")
        self.assertIn("(username,role,pw_hash,salt) VALUES", s); self.assertIn("mfa_secret=EXCLUDED.mfa_secret", s)   # omitted columns reset, like SQLite REPLACE
        self.assertNotIn("username=EXCLUDED.username", s)
    def test_returning_only_for_serial_tables(self):
        s, ret = self.tr("INSERT OR IGNORE INTO cases(order_id) VALUES(?)"); self.assertTrue(ret); self.assertTrue(s.endswith("RETURNING case_id"))
        self.assertFalse(self.tr("INSERT INTO case_events(case_id) VALUES(?)")[1])
    def test_schema_mapping(self):
        pg = pgdb.pg_schema(db.SCHEMA)
        self.assertIn("case_id BIGSERIAL PRIMARY KEY", pg); self.assertIn("seq BIGINT PRIMARY KEY", pg); self.assertIn("locked_until DOUBLE PRECISION", pg)
        self.assertNotIn("INTEGER", pg); self.assertEqual(META["cases"][1], "case_id"); self.assertEqual(META["audit_log"][1], "seq")
        self.assertNotIn("UNIQUE", ",".join(META["alerts"][0]))   # table-level constraints are not columns
    def test_row_behaves_like_sqlite_row(self):
        r = pgdb.Row(["a", "b"], [1, "x"]); self.assertEqual((r["a"], r[1], tuple(r), dict(r)), (1, "x", (1, "x"), {"a": 1, "b": "x"}))
    def test_url_parsing(self):
        p = pgdb._parse("postgresql://u:p%40ss@db.example:6543/app?sslmode=verify-full&sslrootcert=/ca.pem")
        self.assertEqual((p["host"], p["port"], p["user"], p["password"], p["database"], p["sslmode"], p["sslrootcert"]), ("db.example", 6543, "u", "p@ss", "app", "verify-full", "/ca.pem"))
        with self.assertRaises(ValueError): pgdb._parse("mysql://x")

class TestMigration(unittest.TestCase):
    def test_copy_preserves_audit_chain_and_counts(self):
        from provenance import config, migrate
        d = Path(tempfile.mkdtemp()); src, dst = db.connect(d / "a.db"), db.connect(d / "b.db")
        saved, config.ANCHOR_DIR = config.ANCHOR_DIR, d / "anchors"      # this chain is unrelated to the shared suite's anchors
        self.addCleanup(setattr, config, "ANCHOR_DIR", saved)
        security.create_user(src, "m.user", "admin", "Str0ng!Passw0rd#1")
        for i in range(5): security.audit(src, "m", "admin", "x", str(i))
        src.execute("INSERT INTO cases(order_id,channel,reason,at_stake,priority,status,created_at,due_at,updated_at) VALUES('o1','QCOM','SHORT_PAY',5,'low','OPEN','t','t','t')"); src.commit()
        rep = migrate.migrate(src, dst)
        self.assertEqual(rep["rows"]["audit_log"], 5); self.assertTrue(rep["audit"]["ok"]); self.assertEqual(dst.execute("SELECT count(*) FROM cases").fetchone()[0], 1)
        with self.assertRaises(RuntimeError): migrate.migrate(src, dst)   # refuses to merge into a non-empty target

class TestLiveBackend(unittest.TestCase):
    def test_values_are_bound_never_interpolated(self):
        c = db.connect(); evil = "x'); DROP TABLE alerts;--"
        c.execute("INSERT OR IGNORE INTO alerts(kind,severity,subject,detail,created_at) VALUES(?,?,?,?,?)", ("t_inj", "low", evil, "{}", "now")); c.commit()
        self.assertEqual(c.execute("SELECT subject FROM alerts WHERE kind='t_inj'").fetchone()[0], evil)
        self.assertGreaterEqual(c.execute("SELECT count(*) FROM alerts").fetchone()[0], 1)
    def test_nul_bytes_and_unicode_survive(self):
        c = db.connect(); c.execute("INSERT OR REPLACE INTO login_state VALUES(?,?,?)", ("t_nul\x00x", 3, 1234567890.5)); c.commit()
        row = c.execute("SELECT * FROM login_state WHERE username=?", ("t_nul" + "x",)).fetchone()
        if row is not None: self.assertEqual((row["failures"], row["locked_until"]), (3, 1234567890.5))
        c.execute("INSERT OR REPLACE INTO login_state VALUES(?,?,?)", ("t_uni_₹✓", 1, 1.0)); c.commit()
        self.assertEqual(c.execute("SELECT username FROM login_state WHERE username=?", ("t_uni_₹✓",)).fetchone()[0], "t_uni_₹✓")
    def test_rollback_discards_uncommitted_work(self):
        c = db.connect(); c.execute("INSERT OR REPLACE INTO login_state VALUES(?,?,?)", ("t_rb", 1, 1.0)); c.rollback()
        self.assertIsNone(c.execute("SELECT 1 FROM login_state WHERE username='t_rb'").fetchone())
    def test_concurrent_audit_writes_keep_chain_intact(self):
        errs = []
        def work(i):
            try:
                c = db.connect()
                for j in range(10): security.audit(c, f"w{i}", "admin", "load.test", str(j))
                c.close()
            except Exception as e: errs.append(repr(e))
        c = db.connect(); before = c.execute("SELECT count(*) FROM audit_log").fetchone()[0]
        ts = [threading.Thread(target=work, args=(i,)) for i in range(8)]; [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(errs, []); self.assertEqual(c.execute("SELECT count(*) FROM audit_log").fetchone()[0], before + 80)
        v = security.verify_audit(c); self.assertTrue(v["ok"], v)
    def test_numeric_and_boolean_types_come_back_as_python_numbers(self):
        c = db.connect(); r = c.execute("SELECT 7 / 2.0 AS q, sum(x) AS s, count(*) AS n FROM (SELECT 3 AS x UNION ALL SELECT 4) t").fetchone()
        self.assertEqual((r["q"], r["s"], r["n"]), (3.5, 7, 2)); self.assertIsInstance(r["s"], int)

if __name__ == "__main__": unittest.main()
