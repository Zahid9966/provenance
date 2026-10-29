"""sqlite3-compatible adapter over the Postgres wire client, so the rest of the code is backend-agnostic.
Translates the three SQLite-isms the code uses (? placeholders, INSERT OR IGNORE/REPLACE, lastrowid) and maps the schema."""
import re, threading
from urllib.parse import parse_qs, unquote, urlparse
from . import pgwire

_INT, _FLOAT = {20, 21, 23, 26}, {700, 701}
SERIAL = {"cases": "case_id"}   # tables whose generated key callers read back via cursor.lastrowid


def pg_schema(schema: str) -> str:
    s = re.sub(r"\b(id|case_id) INTEGER PRIMARY KEY", r"\1 BIGSERIAL PRIMARY KEY", schema)
    s = re.sub(r"\bINTEGER\b", "BIGINT", s)                     # amounts are integer paise; avoid int32 overflow
    return re.sub(r"\bREAL\b", "DOUBLE PRECISION", s)

def _split_top(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(": depth += 1
        elif ch == ")": depth -= 1
        if ch == "," and depth == 0: out.append(cur.strip()); cur = ""
        else: cur += ch
    return out + ([cur.strip()] if cur.strip() else [])

def table_meta(schema: str):
    meta = {}
    for m in re.finditer(r"CREATE TABLE IF NOT EXISTS (\w+)\((.*?)\);\n", schema + "\n", re.S):
        cols, pk = [], None
        for item in _split_top(m.group(2)):
            if item.upper().startswith(("UNIQUE", "PRIMARY")): continue
            name = item.split()[0]; cols.append(name)
            if "PRIMARY KEY" in item.upper(): pk = name
        meta[m.group(1)] = (cols, pk)
    return meta


def translate(sql: str, meta: dict):
    """-> (postgres_sql, expects_returning_id)"""
    out, n, i, q = [], 0, 0, False
    while i < len(sql):                                        # ? -> $n, leaving quoted literals alone
        ch = sql[i]
        if ch == "'": q = not q
        if ch == "?" and not q: n += 1; out.append(f"${n}")
        else: out.append(ch)
        i += 1
    s = "".join(out).rstrip().rstrip(";")
    ret = False
    m = re.match(r"\s*INSERT OR (IGNORE|REPLACE) INTO (\w+)\s*(\([^)]*\))?(.*)$", s, re.S | re.I)
    if m:
        mode, table, cols, rest = m.group(1).upper(), m.group(2), m.group(3), m.group(4)
        s = f"INSERT INTO {table}{cols or ''} {rest.lstrip()}"
        if mode == "IGNORE": s += " ON CONFLICT DO NOTHING"
        else:
            tcols, pk = meta[table]
            s += f" ON CONFLICT ({pk}) DO UPDATE SET " + ", ".join(f"{c}=EXCLUDED.{c}" for c in tcols if c != pk)   # = SQLite REPLACE (omitted cols reset to defaults)
        m2 = re.match(r"\s*INSERT INTO (\w+)", s)
    else: m2 = re.match(r"\s*INSERT INTO (\w+)", s, re.I)
    if m2 and m2.group(1) in SERIAL: s += f" RETURNING {SERIAL[m2.group(1)]}"; ret = True
    return s, ret


class Row:
    __slots__ = ("_k", "_v")
    def __init__(self, keys, values): self._k, self._v = keys, values
    def __getitem__(self, i): return self._v[i] if isinstance(i, (int, slice)) else self._v[self._k.index(i)]
    def keys(self): return list(self._k)
    def __iter__(self): return iter(self._v)
    def __len__(self): return len(self._v)
    def __repr__(self): return f"Row({dict(zip(self._k, self._v))})"


class Cursor:
    def __init__(self, rows, rowcount, lastrowid): self._rows, self.rowcount, self.lastrowid, self._i = rows, rowcount, lastrowid, 0
    def fetchone(self):
        if self._i >= len(self._rows): return None
        self._i += 1; return self._rows[self._i - 1]
    def fetchall(self): r = self._rows[self._i:]; self._i = len(self._rows); return r
    def __iter__(self): return iter(self.fetchall())


def _conv(oid, v):
    if v is None: return None
    if oid in _INT: return int(v)
    if oid in _FLOAT: return float(v)
    if oid == 1700: return float(v) if "." in v else int(v)
    if oid == 16: return 1 if v == "t" else 0
    return v


class PgConn:
    is_pg = True
    def __init__(self, wire, meta, pool=None): self.w, self.meta, self._pool = wire, meta, pool

    @property
    def in_txn(self): return self.w.status != "I"

    def execute(self, sql, params=()):
        s, ret = translate(sql, self.meta)
        if re.match(r"\s*(INSERT|UPDATE|DELETE)", s, re.I) and not self.in_txn: self.w.simple("BEGIN")   # mirror sqlite3's implicit transactions
        cols, oids, rows, tag = self.w.query(s, params)
        out = [Row(cols, [_conv(o, v) for o, v in zip(oids, r)]) for r in rows]
        parts = tag.split()
        rc = int(parts[-1]) if parts and parts[0] in ("INSERT", "UPDATE", "DELETE") else -1
        return Cursor(out, rc, out[0][0] if ret and out else None)

    def executemany(self, sql, seq):
        for p in seq: self.execute(sql, p)

    def executescript(self, script):
        for stmt in (x.strip() for x in script.split(";")):
            if stmt: self.w.simple(stmt)

    def simple(self, sql): self.w.simple(sql)
    def commit(self):
        if self.in_txn: self.w.simple("COMMIT")
    def rollback(self):
        if self.in_txn: self.w.simple("ROLLBACK")
    def close(self):
        try: self.rollback(); ok = self._pool is not None and self._pool.give(self)
        except Exception: ok = False
        if not ok: self.w.close()


class Pool:
    def __init__(self, size=8): self.idle, self.size, self.lock = [], size, threading.Lock()
    def take(self):
        with self.lock: return self.idle.pop() if self.idle else None
    def give(self, conn):
        with self.lock:
            if len(self.idle) < self.size: self.idle.append(conn); return True
        return False


_state = {"pool": Pool(), "ready": False, "lock": threading.Lock()}

def _parse(url):
    u = urlparse(url); q = {k: v[0] for k, v in parse_qs(u.query).items()}
    if u.scheme not in ("postgresql", "postgres"): raise ValueError("PROVENANCE_DATABASE_URL must start with postgresql://")
    return dict(host=u.hostname or "localhost", port=u.port or 5432, user=unquote(u.username or ""), password=unquote(u.password or ""),
                database=(u.path or "/postgres").lstrip("/"), sslmode=q.get("sslmode", "prefer"), sslrootcert=q.get("sslrootcert"))

def connect(url, schema):
    meta = table_meta(schema)
    conn = _state["pool"].take()
    if conn is not None:
        try: conn.w.simple("SELECT 1"); return conn          # discard connections the server dropped
        except Exception: conn.w.close()
    conn = PgConn(pgwire.Wire(**_parse(url)), meta, _state["pool"])
    with _state["lock"]:
        if not _state["ready"]:
            conn.simple("SELECT pg_advisory_lock(7310)")
            try:
                conn.executescript(pg_schema(schema))
                for col, ddl in (("mfa_secret", "TEXT"), ("mfa_last", "BIGINT DEFAULT 0"), ("token_version", "BIGINT DEFAULT 0")):
                    conn.simple(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {col} {ddl}")
            finally: conn.simple("SELECT pg_advisory_unlock(7310)")
            _state["ready"] = True
    return conn
