import argparse, json, secrets, sys
from . import config, db, generate, pipeline, security

ROLES = {"admin.demo": "admin", "finance.demo": "finance", "analyst.demo": "analyst", "security.demo": "security", "auditor.demo": "auditor"}

def init(seed=7):
    conn = db.connect()
    creds = config.HOME / "demo_credentials.txt"
    if not creds.exists():
        lines = []
        for u, r in ROLES.items():
            while True:
                pw = secrets.token_urlsafe(14)
                try: security.check_password_policy(u, pw); break
                except ValueError: continue
            security.create_user(conn, u, r, pw); lines.append(f"{u}\t{pw}")
        creds.write_text("\n".join(lines) + "\n"); creds.chmod(0o600)
    generate.generate(seed=seed)
    return pipeline.run_pipeline(conn)

def main(argv=None):
    ap = argparse.ArgumentParser(prog="provenance")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create demo users, generate landing data, run the pipeline").add_argument("--if-empty", action="store_true", help="do nothing if a pipeline run already exists")
    sub.add_parser("run", help="re-run pipeline on current landing files")
    sub.add_parser("migrate-to-postgres", help="copy the SQLite database into the (empty) Postgres at $PROVENANCE_DATABASE_URL, then verify counts and the audit chain")
    s = sub.add_parser("serve"); s.add_argument("--port", type=int, default=8787); s.add_argument("--bind", default=None, help="default 127.0.0.1 (or $PROVENANCE_BIND)")
    s.add_argument("--schedule-minutes", type=int, default=0, help="poll the landing folder and run the pipeline when new files arrive")
    sub.add_parser("anchor", help="write a signed audit-chain head to the external anchor log")
    sub.add_parser("export-siem", help="print audit + alert events as CEF").add_argument("--since", type=int, default=0)
    u = sub.add_parser("create-user"); u.add_argument("username"); u.add_argument("role", choices=sorted(security.PERMS))
    sub.add_parser("verify-audit")
    a = sub.add_parser("ask"); a.add_argument("question", nargs="+")
    args = ap.parse_args(argv)
    if args.cmd == "init":
        if args.if_empty and db.connect().execute("SELECT 1 FROM pipeline_runs WHERE status='success'").fetchone(): print("already initialised"); return
        print(json.dumps(init(), indent=1)); print(f"demo logins: {config.HOME/'demo_credentials.txt'}")
    elif args.cmd == "run": print(json.dumps(pipeline.run_pipeline(db.connect()), indent=1))
    elif args.cmd == "migrate-to-postgres":
        import os; from . import migrate
        if not os.environ.get("PROVENANCE_DATABASE_URL"): sys.exit("set PROVENANCE_DATABASE_URL=postgresql://... first")
        print(json.dumps(migrate.migrate(db.connect(config.DB_PATH), db.connect()), indent=1))
    elif args.cmd == "verify-audit":
        r = security.verify_audit(db.connect()); print(json.dumps(r)); sys.exit(0 if r["ok"] else 2)
    elif args.cmd == "ask":
        from . import copilot; print(json.dumps(copilot.ask(db.connect(), " ".join(args.question)), indent=1, default=str))
    elif args.cmd == "serve":
        from . import server; server.serve(args.port, args.bind, args.schedule_minutes)
    elif args.cmd == "anchor": print(json.dumps(security.anchor(db.connect())))
    elif args.cmd == "export-siem": print("\n".join(security.siem_events(db.connect(), args.since)))
    elif args.cmd == "create-user":
        import getpass; pw = getpass.getpass("password: "); security.create_user(db.connect(), args.username, args.role, pw); print("created")

if __name__ == "__main__": main()
