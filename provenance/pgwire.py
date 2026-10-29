"""Minimal PostgreSQL v3 wire-protocol client (stdlib only): SCRAM-SHA-256 / md5 / cleartext auth, TLS (SSLRequest),
extended query protocol with bound text parameters (no string interpolation, so no SQL injection through values).
Deliberately small. For heavy production use swap in psycopg behind provenance/pgdb.py: the adapter is the only consumer."""
import base64, hashlib, hmac, os, socket, ssl, struct


class PgError(Exception):
    def __init__(self, fields):
        self.fields = fields; self.code = fields.get("C", ""); super().__init__(fields.get("M", "postgres error"))


def _xor(a, b): return bytes(x ^ y for x, y in zip(a, b))


class Wire:
    def __init__(self, host, port, user, password, database, sslmode="prefer", sslrootcert=None, timeout=30, statement_timeout_ms=120000):
        self.user, self.password, self.status = user, password, "I"
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)   # small request/response messages: avoid Nagle + delayed-ACK stalls
        try:
            self._tls(host, sslmode, sslrootcert)
            params = {"user": user, "database": database, "client_encoding": "UTF8", "application_name": "provenance", "statement_timeout": str(statement_timeout_ms)}
            body = struct.pack("!I", 196608) + b"".join(k.encode() + b"\0" + v.encode() + b"\0" for k, v in params.items()) + b"\0"
            self.sock.sendall(struct.pack("!I", len(body) + 4) + body)
            self._auth()
        except BaseException:
            self.sock.close(); raise

    # ----- transport -----
    def _tls(self, host, mode, rootcert):
        if mode == "disable": return
        self.sock.sendall(struct.pack("!II", 8, 80877103))
        if self._read(1) == b"S":
            if mode == "verify-full": ctx = ssl.create_default_context(cafile=rootcert)
            else:
                ctx = ssl.create_default_context(cafile=rootcert) if rootcert else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                if not rootcert: ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE   # libpq 'require': encrypt, do not authenticate
                else: ctx.check_hostname = False
            self.sock = ctx.wrap_socket(self.sock, server_hostname=host)
        elif mode in ("require", "verify-full"): raise ConnectionError("server does not support TLS but sslmode=" + mode)

    def _read(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk: raise ConnectionError("connection closed by server")
            buf += chunk
        return buf

    def _msg(self):
        t = self._read(1); (n,) = struct.unpack("!I", self._read(4)); return t, self._read(n - 4)

    def _send(self, t, body=b""): self.sock.sendall(t + struct.pack("!I", len(body) + 4) + body)

    @staticmethod
    def _err(body):
        f, i = {}, 0
        while i < len(body) and body[i]:
            end = body.index(b"\0", i + 1); f[chr(body[i])] = body[i + 1:end].decode(errors="replace"); i = end + 1
        return PgError(f)

    # ----- authentication -----
    def _auth(self):
        nonce = base64.b64encode(os.urandom(18)).decode(); first_bare = salted = auth_msg = None
        while True:
            t, b = self._msg()
            if t == b"E": raise self._err(b)
            if t == b"R":
                (code,) = struct.unpack("!I", b[:4])
                if code == 0: continue
                if code == 3: self._send(b"p", self.password.encode() + b"\0")
                elif code == 5:
                    inner = hashlib.md5(self.password.encode() + self.user.encode()).hexdigest()
                    self._send(b"p", b"md5" + hashlib.md5(inner.encode() + b[4:8]).hexdigest().encode() + b"\0")
                elif code == 10:
                    if b"SCRAM-SHA-256" not in b: raise ConnectionError("server offers no SCRAM-SHA-256")
                    first_bare = f"n=,r={nonce}"; data = ("n,," + first_bare).encode()
                    self._send(b"p", b"SCRAM-SHA-256\0" + struct.pack("!i", len(data)) + data)
                elif code == 11:
                    srv_first = b[4:].decode(); kv = dict(p.split("=", 1) for p in srv_first.split(","))
                    if not kv["r"].startswith(nonce): raise ConnectionError("SCRAM: server nonce mismatch")
                    salted = hashlib.pbkdf2_hmac("sha256", self.password.encode(), base64.b64decode(kv["s"]), int(kv["i"]))
                    final_wo = f"c=biws,r={kv['r']}"; auth_msg = f"{first_bare},{srv_first},{final_wo}".encode()
                    ck = hmac.new(salted, b"Client Key", "sha256").digest()
                    proof = _xor(ck, hmac.new(hashlib.sha256(ck).digest(), auth_msg, "sha256").digest())
                    self._send(b"p", f"{final_wo},p={base64.b64encode(proof).decode()}".encode())
                elif code == 12:
                    sig = hmac.new(hmac.new(salted, b"Server Key", "sha256").digest(), auth_msg, "sha256").digest()
                    if not hmac.compare_digest(b[4:].decode().split("v=", 1)[1].encode(), base64.b64encode(sig)): raise ConnectionError("SCRAM: server signature invalid")
                else: raise ConnectionError(f"unsupported authentication method {code}")
            elif t == b"Z": self.status = chr(b[0]); return

    # ----- queries -----
    def simple(self, sql):
        self._send(b"Q", sql.encode() + b"\0"); self._collect()

    def query(self, sql, params=()):
        """Extended protocol, unnamed statement/portal, text format. Returns (columns, type_oids, rows, command_tag)."""
        enc = [None if p is None else str(p).replace("\0", "").encode() for p in params]
        parse = b"\0" + sql.encode() + b"\0" + struct.pack("!H", 0)
        bind = b"\0\0" + struct.pack("!HH", 0, len(enc)) + b"".join(struct.pack("!i", -1) if p is None else struct.pack("!i", len(p)) + p for p in enc) + struct.pack("!H", 0)
        frame = lambda t, body: t + struct.pack("!I", len(body) + 4) + body
        self.sock.sendall(frame(b"P", parse) + frame(b"B", bind) + frame(b"D", b"P\0") + frame(b"E", b"\0" + struct.pack("!I", 0)) + frame(b"S", b""))   # one write per query
        return self._collect()

    def _collect(self):
        cols, oids, rows, tag, err = [], [], [], "", None
        while True:
            t, b = self._msg()
            if t == b"T":
                (n,) = struct.unpack("!H", b[:2]); i = 2; cols, oids = [], []
                for _ in range(n):
                    end = b.index(b"\0", i); cols.append(b[i:end].decode()); i = end + 1
                    oids.append(struct.unpack("!I", b[i + 6:i + 10])[0]); i += 18
            elif t == b"D":
                (n,) = struct.unpack("!H", b[:2]); i = 2; row = []
                for _ in range(n):
                    (ln,) = struct.unpack("!i", b[i:i + 4]); i += 4
                    if ln < 0: row.append(None)
                    else: row.append(b[i:i + ln].decode()); i += ln
                rows.append(row)
            elif t == b"C": tag = b[:-1].decode()
            elif t == b"E": err = self._err(b)
            elif t == b"Z":
                self.status = chr(b[0])
                if err: raise err
                return cols, oids, rows, tag

    def close(self):
        try: self._send(b"X"); self.sock.close()
        except OSError: pass
