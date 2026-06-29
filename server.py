#!/usr/bin/env python3
"""
tiptech-clipboard - zero-knowledge encrypted clipboard.

The server NEVER sees your plaintext. All encryption and decryption happens in
the browser (WebCrypto). The server only stores an opaque ciphertext blob it
cannot read: there is no master key, no admin decryption, no way for the
operator to recover content. The decryption key lives in the URL fragment
(#...), which browsers never send to the server.

Single file, Python standard library only. No third-party dependencies.

Config via environment variables (see config.example.env).
"""
import json, os, re, time, hmac, hashlib, base64, random, sqlite3, threading, secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------- config
def _env(name, default):
    v = os.environ.get(name)
    return v if v not in (None, "") else default

HOST       = _env("CLIPBOARD_HOST", "0.0.0.0")
PORT       = int(_env("CLIPBOARD_PORT", "8470"))
BASE_URL   = _env("CLIPBOARD_BASE_URL", f"http://localhost:{PORT}").rstrip("/")
DATA_DIR   = _env("CLIPBOARD_DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
STATIC_DIR = _env("CLIPBOARD_STATIC_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"))

# Max ciphertext size. The blob is already encrypted client-side, so this is the
# upper bound on the encrypted payload (a bit larger than the raw content).
MAX_BLOB   = int(_env("CLIPBOARD_MAX_MB", "20")) * 1024 * 1024
CAPTCHA    = _env("CLIPBOARD_CAPTCHA", "1") not in ("0", "false", "no")
RATE_CREATE = int(_env("CLIPBOARD_RATE_CREATE", "30"))      # max creates / IP / 10 min
RATE_WINDOW = 600

DB_PATH   = os.path.join(DATA_DIR, "clipboard.db")
BLOB_DIR  = os.path.join(DATA_DIR, "blobs")
EXPIRY_OPTS = {"1h": 3600, "1d": 86400, "7d": 7*86400, "30d": 30*86400, "never": 0}
DEFAULT_EXPIRY = _env("CLIPBOARD_DEFAULT_EXPIRY", "7d")

os.makedirs(BLOB_DIR, exist_ok=True)
try:
    os.chmod(DATA_DIR, 0o700)
except OSError:
    pass

# A per-deployment secret for signing the anti-bot challenge tokens. Persisted so
# tokens survive restarts. This secret has NOTHING to do with content; it cannot
# decrypt anything (the server has no decryption key at all).
_SECRET_PATH = os.path.join(DATA_DIR, "challenge.secret")
if not os.path.exists(_SECRET_PATH):
    with open(os.open(_SECRET_PATH, os.O_CREAT | os.O_WRONLY, 0o600), "wb") as fh:
        fh.write(secrets.token_bytes(32))
with open(_SECRET_PATH, "rb") as fh:
    CHALLENGE_SECRET = fh.read()

# ---------------------------------------------------------------- storage
_dblock = threading.Lock()
def db():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with _dblock, db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS entries(
            id TEXT PRIMARY KEY,
            size INTEGER,
            created INTEGER,
            expires INTEGER,
            burn INTEGER DEFAULT 0,
            del_token TEXT,
            ip TEXT)""")
init_db()

def blob_path(eid):
    return os.path.join(BLOB_DIR, eid + ".bin")

def purge(c, eid):
    c.execute("DELETE FROM entries WHERE id=?", (eid,))
    try:
        os.remove(blob_path(eid))
    except OSError:
        pass

def cleanup_expired():
    while True:
        try:
            now = int(time.time())
            with _dblock, db() as c:
                rows = c.execute("SELECT id FROM entries WHERE expires>0 AND expires<?", (now,)).fetchall()
                for r in rows:
                    purge(c, r["id"])
        except Exception:
            pass
        time.sleep(300)

# ---------------------------------------------------------------- anti-bot challenge
def make_challenge(lang="en"):
    a, b = random.randint(2, 9), random.randint(2, 9)
    payload = f"{a + b}:{int(time.time()) + 1800}"
    sig = hmac.new(CHALLENGE_SECRET, payload.encode(), hashlib.sha256).hexdigest()[:20]
    token = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=") + "." + sig
    q = (f"Koľko je {a} + {b}?" if str(lang).lower().startswith("sk")
         else f"What is {a} + {b}?")
    return {"q": q, "token": token}

_used = {}
def check_challenge(token, ans):
    try:
        b64, sig = str(token).split(".", 1)
        payload = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4)).decode()
        expected, exp = payload.split(":")
        good = hmac.new(CHALLENGE_SECRET, payload.encode(), hashlib.sha256).hexdigest()[:20]
        if not hmac.compare_digest(good, sig) or int(exp) < time.time():
            return False
        return int(str(ans).strip()) == int(expected)
    except Exception:
        return False

def consume_token(token):
    now = time.time()
    for k, v in list(_used.items()):
        if v < now:
            _used.pop(k, None)
    try:
        sig = str(token).split(".", 1)[1]
    except Exception:
        return False
    if sig in _used:
        return False
    _used[sig] = now + 1800
    return True

# ---------------------------------------------------------------- rate limit
_create_hits = {}
def rate_create(ip):
    now = time.time()
    h = [t for t in _create_hits.get(ip, []) if now - t < RATE_WINDOW]
    h.append(now)
    _create_hits[ip] = h
    return len(h) <= RATE_CREATE

def client_ip(h):
    xff = h.headers.get("X-Forwarded-For", "")
    return (h.headers.get("X-Real-IP")
            or (xff.split(",")[0].strip() if xff else "")
            or h.client_address[0])

# ---------------------------------------------------------------- static files
_STATIC_CACHE = {}
_CTYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
           ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml",
           ".ico": "image/x-icon", ".png": "image/png", ".webmanifest": "application/manifest+json"}

def read_static(name):
    name = name.lstrip("/")
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", name) or ".." in name:
        return None, None
    p = os.path.normpath(os.path.join(STATIC_DIR, name))
    if not p.startswith(os.path.abspath(STATIC_DIR)) or not os.path.isfile(p):
        return None, None
    ext = os.path.splitext(p)[1].lower()
    with open(p, "rb") as fh:
        return fh.read(), _CTYPES.get(ext, "application/octet-stream")

# ---------------------------------------------------------------- HTTP handler
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "tiptech-clipboard"
    def log_message(self, *a):
        pass

    def _send(self, code, obj=None, body=None, ctype="application/json", extra=None):
        if obj is not None:
            body = json.dumps(obj, ensure_ascii=False).encode()
        body = body or b""
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_json(self):
        n = int(self.headers.get("Content-Length", 0))
        if n > MAX_BLOB + 65536:
            raise ValueError("payload too large")
        return json.loads(self.rfile.read(n) or b"{}")

    # ---- routing
    def do_GET(self):
        path = self.path.split("?")[0]
        qs = dict(re.findall(r"([^=&?]+)=([^&]*)", self.path.split("?", 1)[1] if "?" in self.path else ""))
        if path == "/api/config":
            return self._send(200, {"max_mb": MAX_BLOB // (1024*1024), "captcha": CAPTCHA,
                                    "expiry_opts": list(EXPIRY_OPTS.keys()), "default_expiry": DEFAULT_EXPIRY,
                                    "base_url": BASE_URL})
        if path == "/api/challenge":
            return self._send(200, make_challenge(qs.get("lang", "en")))
        # SPA routes -> index.html
        if path in ("/", "") or path.startswith("/c/"):
            body, ct = read_static("index.html")
            return self._send(200, body=body or b"index.html missing", ctype=ct or "text/html")
        # static assets
        body, ct = read_static(path)
        if body is not None:
            return self._send(200, body=body, ctype=ct, extra={"Cache-Control": "public, max-age=3600"})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        try:
            if path == "/api/create":
                return self._create()
            if path == "/api/get":
                return self._get()
            if path == "/api/delete":
                return self._delete()
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        except Exception:
            return self._send(500, {"error": "internal error"})
        return self._send(404, {"error": "not found"})

    # ---- API: create
    def _create(self):
        ip = client_ip(self)
        if not rate_create(ip):
            return self._send(429, {"error": "Too many requests. Try again later."})
        d = self._read_json()
        if CAPTCHA:
            if not check_challenge(d.get("captcha_token"), d.get("captcha_answer")) or not consume_token(d.get("captcha_token")):
                return self._send(400, {"error": "Wrong challenge answer."})
        # ct = client-side ciphertext, base64. The server cannot read it.
        ct_b64 = d.get("ct")
        if not isinstance(ct_b64, str) or not ct_b64:
            return self._send(400, {"error": "Missing ciphertext."})
        try:
            blob = base64.b64decode(ct_b64, validate=True)
        except Exception:
            return self._send(400, {"error": "Malformed ciphertext."})
        if not blob or len(blob) > MAX_BLOB:
            return self._send(400, {"error": f"Payload too large (max {MAX_BLOB//(1024*1024)} MB)."})
        exp_key = d.get("expiry", DEFAULT_EXPIRY)
        if exp_key not in EXPIRY_OPTS:
            exp_key = DEFAULT_EXPIRY
        burn = 1 if d.get("burn") else 0
        eid = secrets.token_urlsafe(9)[:12]
        now = int(time.time())
        expires = 0 if exp_key == "never" else now + EXPIRY_OPTS[exp_key]
        del_token = secrets.token_urlsafe(16)
        with open(os.open(blob_path(eid), os.O_CREAT | os.O_WRONLY, 0o600), "wb") as fh:
            fh.write(blob)
        with _dblock, db() as c:
            c.execute("INSERT INTO entries(id,size,created,expires,burn,del_token,ip) VALUES(?,?,?,?,?,?,?)",
                      (eid, len(blob), now, expires, burn, del_token, ip))
        return self._send(200, {"id": eid, "del_token": del_token,
                                "url_base": f"{BASE_URL}/c/{eid}"})

    # ---- API: get (retrieve ciphertext; POST so link-preview bots never burn it)
    def _get(self):
        d = self._read_json()
        eid = str(d.get("id", ""))[:16]
        with _dblock, db() as c:
            r = c.execute("SELECT * FROM entries WHERE id=?", (eid,)).fetchone()
            if r and r["expires"] and r["expires"] < time.time():
                purge(c, eid)
                r = None
        if not r:
            return self._send(404, {"error": "This clipboard does not exist or has expired."})
        try:
            with open(blob_path(eid), "rb") as fh:
                blob = fh.read()
        except OSError:
            with _dblock, db() as c:
                purge(c, eid)
            return self._send(404, {"error": "This clipboard does not exist or has expired."})
        resp = {"ct": base64.b64encode(blob).decode(), "created": r["created"],
                "expires": r["expires"], "burn": bool(r["burn"])}
        if r["burn"]:
            with _dblock, db() as c:
                purge(c, eid)   # burn after reading
        return self._send(200, resp)

    # ---- API: delete (creator only, via del_token)
    def _delete(self):
        d = self._read_json()
        eid = str(d.get("id", ""))[:16]
        token = str(d.get("del_token", ""))
        with _dblock, db() as c:
            r = c.execute("SELECT del_token FROM entries WHERE id=?", (eid,)).fetchone()
            if not r:
                return self._send(404, {"error": "Already gone."})
            if not token or not hmac.compare_digest(token, r["del_token"] or ""):
                return self._send(403, {"error": "Invalid delete token."})
            purge(c, eid)
        return self._send(200, {"ok": True})

if __name__ == "__main__":
    threading.Thread(target=cleanup_expired, daemon=True).start()
    srv = ThreadingHTTPServer((HOST, PORT), H)
    print(f"tiptech-clipboard listening on {HOST}:{PORT}  base_url={BASE_URL}  captcha={'on' if CAPTCHA else 'off'}  data={DATA_DIR}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
