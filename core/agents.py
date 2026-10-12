"""Windows agents: the receiver inside Toner, the certificate and tokens that protect it, and the agent script.

A Windows computer runs a small PowerShell script on a schedule. It collects the same data Toner can collect over WinRM
(core/winmon.py) and POSTs it to Toner over HTTPS. The script only ever sends: it opens no port and takes no
commands. Two things keep a stranger out of Toner:
  * a certificate Toner made for itself. The script is given its SHA-256 fingerprint and refuses any server that
    does not match, so there is nothing to trust-on-first-use and no certificate authority to set up.
  * a long random token per device. Only a hash of it is kept in Toner's database; the token itself is in
    Windows Credential Manager (and in that device's script).
"""
import hashlib
import hmac
import http.server
import ipaddress
import json
import re
import secrets
import socket
import sqlite3
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone

from core import audit, db, paths, winmon
from core.version import VERSION
from core import quiet

MAX_BODY = 1_000_000
DEFAULT_PORT = 8750
AGENT_VERSION = VERSION                 # the agent is always the same version as Toner; an agent on an older one updates itself
TOKEN_GRACE_DAYS = 7                    # an old token still works this long after it was replaced


# ---------------------------------------------------------------- certificate
def cert_dir():
    d = paths.data_dir() / "agent"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_cert(renew=False):
    """(certificate path, key path). Made once; renew=True replaces it (every agent script must then be re-created)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    cert_file, key_file = cert_dir() / "toner-agent.crt", cert_dir() / "toner-agent.key"
    if renew or not (cert_file.exists() and key_file.exists()):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Toner agent receiver")])
        now = datetime.now(timezone.utc)
        names = [x509.DNSName("localhost")]
        try:
            names.append(x509.DNSName(socket.gethostname()))
        except Exception:
            quiet.ignored()
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=3650)).add_extension(x509.SubjectAlternativeName(names), False)
                .sign(key, hashes.SHA256()))
        key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(cert_file), str(key_file)


def fingerprint():
    """SHA-256 of the receiver's certificate, as the agent script pins it (lower-case hex)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    cert_file, _ = ensure_cert()
    with open(cert_file, "rb") as f:
        return x509.load_pem_x509_certificate(f.read()).fingerprint(hashes.SHA256()).hex()


def renew_cert():
    ensure_cert(renew=True)
    stop()
    apply()
    return fingerprint()


# ---------------------------------------------------------------- tokens and stored reports
def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def token_for(device, rotate=False):
    """The device's token. One is made if there is none (or rotate=True, which stops the old agent working)."""
    name = db.secret_name(device, "agent")
    import keyring
    token = None if rotate else keyring.get_password(db.SERVICE, name)
    if not token:
        token = secrets.token_urlsafe(32)
        db.set_secret(name, token)
        with db.connect() as c:
            c.execute("INSERT INTO agent_reports(device, token_hash, issued_at) VALUES(?,?,?) "
                      "ON CONFLICT(device) DO UPDATE SET token_hash=excluded.token_hash, issued_at=excluded.issued_at, "
                      "prev_hash='', prev_until=''", (device, _hash(token), _now()))
    else:
        with db.connect() as c:                       # make sure the table knows the saved token (restored profile, etc.)
            c.execute("INSERT INTO agent_reports(device, token_hash, issued_at) VALUES(?,?,?) "
                      "ON CONFLICT(device) DO UPDATE SET token_hash=excluded.token_hash, "
                      "issued_at=CASE WHEN issued_at='' THEN excluded.issued_at ELSE issued_at END", (device, _hash(token), _now()))
    return token


def replace_token(device):
    """A new token for the device. The old one keeps working for TOKEN_GRACE_DAYS, so an agent that does not manage to save the
    new one is not locked out."""
    import keyring
    name = db.secret_name(device, "agent")
    old = keyring.get_password(db.SERVICE, name)
    token = secrets.token_urlsafe(32)
    db.set_secret(name, token)
    until = (datetime.now(timezone.utc) + timedelta(days=TOKEN_GRACE_DAYS)).isoformat(timespec="seconds")
    with db.connect() as c:
        c.execute("INSERT INTO agent_reports(device, token_hash, issued_at) VALUES(?,?,?) "
                  "ON CONFLICT(device) DO UPDATE SET token_hash=excluded.token_hash, issued_at=excluded.issued_at, "
                  "prev_hash=?, prev_until=?", (device, _hash(token), _now(), _hash(old) if old else "", until if old else ""))
    return token


def token_due(device):
    """True when tokens are set to be replaced (Settings > Agents) and this one is old enough."""
    days = int(db.get_setting("agent_token_days") or 0)
    if days <= 0:
        return False
    with db.connect() as c:
        row = c.execute("SELECT issued_at FROM agent_reports WHERE device=?", (device,)).fetchone()
    try:
        return bool(row and row["issued_at"]) and datetime.now(timezone.utc) - datetime.fromisoformat(row["issued_at"]) > timedelta(days=days)
    except ValueError:
        return False


def revoke(device):
    """Stop a computer's agent being accepted (the device stays in the inventory). Make a new script or package to start again."""
    db.delete_secret(db.secret_name(device, "agent"))
    with db.connect() as c:
        c.execute("UPDATE agent_reports SET token_hash='', prev_hash='', prev_until='' WHERE device=?", (device,))


def rename(old, new):
    """A renamed device keeps its token (the secret itself moves with db.move_device_secrets) and its last report."""
    with db.connect() as c:
        for table in ("agent_reports", "agent_seen"):
            c.execute(f"DELETE FROM {table} WHERE device=?", (new,))
            c.execute(f"UPDATE {table} SET device=? WHERE device=?", (new, old))
        c.execute("UPDATE agent_metrics SET device=? WHERE device=?", (new, old))


def forget(name):
    """A deleted device's token (the secret itself goes with db.delete_device_secrets) and last report."""
    with db.connect() as c:
        for table in ("agent_reports", "agent_seen", "agent_metrics"):
            c.execute(f"DELETE FROM {table} WHERE device=?", (name,))


# ---------------------------------------------------------------- signing computers up (the package)
ENROLL_SECRET = "service:agent-enroll"
_failures = {}                                       # source address -> times of wrong keys, to slow down guessing


def enroll_key(rotate=False):
    """The sign-up key that goes in the package. Made once; rotate=True replaces it (old packages stop signing computers up)."""
    import keyring
    key = None if rotate else keyring.get_password(db.SERVICE, ENROLL_SECRET)
    if not key:
        key = secrets.token_urlsafe(24)
        db.set_secret(ENROLL_SECRET, key)
    return key


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9_.\-]+", "-", text or "").strip("-.")[:60]


def enroll(computer, key, source=""):
    """A computer asks to be added. Returns (HTTP status, answer). Needs sign-up turned on and the right key."""
    if not db.get_setting("agent_enroll"):
        return 403, {"ok": False, "error": "Toner is not accepting new computers (Settings > Agents)."}
    now = time.time()
    recent = [t for t in _failures.get(source, []) if now - t < 300]
    if len(recent) >= 10:
        return 429, {"ok": False, "error": "too many wrong keys; try again later"}
    if not hmac.compare_digest(key.encode(), enroll_key().encode()):
        _failures[source] = recent + [now]
        return 401, {"ok": False, "error": "the sign-up key is wrong (the package is out of date?)"}
    name = safe_name(computer)
    if not name:
        return 400, {"ok": False, "error": "no computer name"}
    existing = next((d for d in db.list_devices() if d["name"].lower() == name.lower()), None)
    if existing:
        with db.connect() as c:
            row = c.execute("SELECT token_hash FROM agent_reports WHERE device=?", (existing["name"],)).fetchone()
        if not (existing["vendor"] == "windows" and existing["platform"] == "agent" and not (row and row["token_hash"])):
            return 409, {"ok": False, "error": f"Toner already has a device named {existing['name']}. Delete it in Toner, or use its own agent script."}
        name = existing["name"]                       # a device someone added by hand, waiting for its agent
    else:
        try:
            db.save_device({"name": name, "vendor": "windows", "host": name, "port": 0, "platform": "agent", "username": "",
                            "site": "default", "verify_ssl": 0, "ha_expected": 0, "enabled": 1, "location": "",
                            "details": "Signed up with the agent package " + datetime.now().strftime("%Y-%m-%d"),
                            "folder_id": None, "tags": "", "fields": "", "profile_id": None})
        except sqlite3.IntegrityError:
            return 409, {"ok": False, "error": f"Toner already has a device named {name}."}
    token = token_for(name)
    audit.log("agent signed up", f"{name} from {source}")
    if not existing:                                         # a new computer appeared: say so (in the background: it is a network call)
        threading.Thread(target=_announce_new, args=(name, source), daemon=True).start()
    return 200, {"ok": True, "token": token, "name": name}


def _announce_new(name, source):
    try:
        from core import notify
        notify.announce(name, "agent sign-up", "new computer", f"signed itself up from {source}. If you did not install the agent there, "
                        "turn off sign-up or renew the key in Settings > Agents.")
    except Exception:
        quiet.ignored()


def device_for_token(token):
    """Inventory name for a token, or ''."""
    if not token:
        return ""
    want = _hash(token)
    now = _now()
    with db.connect() as c:
        rows = c.execute("SELECT device, token_hash, prev_hash, prev_until FROM agent_reports WHERE token_hash<>''").fetchall()
    for r in rows:
        if hmac.compare_digest(r["token_hash"], want):
            return r["device"]
        if r["prev_hash"] and r["prev_until"] > now and hmac.compare_digest(r["prev_hash"], want):
            return r["device"]
    return ""


_last_purge = [0.0]


def _numbers(text):
    return tuple(int(x) for x in str(text).split("."))


def agent_kind(text):
    """What an agent's version header says: ('none', ...) it did not say (a script from before updates, or something else),
    ('legacy', n) the plain whole numbers early package agents sent (they update), or ('current', version) a Toner version like 1.3.4."""
    text = str(text or "").strip()
    if re.fullmatch(r"\d+", text):
        return ("legacy", int(text)) if int(text) >= 2 else ("none", 0)
    if re.fullmatch(r"\d+(\.\d+){1,3}", text):
        return "current", text
    return "none", 0


def agent_outdated(text):
    """True if an agent on this version should be updated: it is older than this Toner (or from before versions matched Toner's)."""
    kind, value = agent_kind(text)
    if kind == "legacy":
        return True
    if kind != "current":
        return False
    a, b = _numbers(AGENT_VERSION), _numbers(value)
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) > b + (0,) * (n - len(b))


def store(device, report, source="", version=0):
    """Keep the newest report, and a row of numbers for the charts."""
    with db.connect() as c:
        c.execute("UPDATE agent_reports SET received_at=?, source=?, report=?, version=? WHERE device=?",
                  (_now(), source, json.dumps(report, separators=(",", ":")), str(version or ""), device))
        mem = None
        if report.get("mem_total_mb"):
            mem = (report["mem_total_mb"] - (report.get("mem_free_mb") or 0)) / report["mem_total_mb"] * 100
        worst = max(((1 - d["free"] / d["size"]) * 100 for d in report.get("disks") or [] if d.get("size")), default=None)
        c.execute("INSERT INTO agent_metrics(device, at, cpu, memory, disk, uptime_h) VALUES(?,?,?,?,?,?)",
                  (device, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), report.get("cpu"), mem, worst, report.get("uptime_h")))
        c.execute("INSERT INTO agent_seen(device, first_seen, last_ip) VALUES(?,?,?) "
                  "ON CONFLICT(device) DO UPDATE SET last_ip=excluded.last_ip", (device, _now(), source))
        if time.time() - _last_purge[0] > 3600:                # once an hour: keep as long as run history is kept
            _last_purge[0] = time.time()
            cutoff = (datetime.now() - timedelta(days=int(db.get_setting("retention_days")))).strftime("%Y-%m-%d %H:%M:%S")
            c.execute("DELETE FROM agent_metrics WHERE at < ?", (cutoff,))


def facts(device):
    """What was installed, who was an administrator and which ports listened, as of the last check (None the first time)."""
    with db.connect() as c:
        row = c.execute("SELECT facts FROM agent_seen WHERE device=?", (device,)).fetchone()
    try:
        return json.loads(row["facts"]) if row and row["facts"] else None
    except ValueError:
        return None


def set_facts(device, data):
    with db.connect() as c:
        c.execute("INSERT INTO agent_seen(device, first_seen, facts) VALUES(?,?,?) "
                  "ON CONFLICT(device) DO UPDATE SET facts=excluded.facts", (device, _now(), json.dumps(data, separators=(",", ":"))))


def latest(device):
    """(report dict, age in minutes) of the newest report for a device, or (None, None)."""
    with db.connect() as c:
        row = c.execute("SELECT received_at, report FROM agent_reports WHERE device=?", (device,)).fetchone()
    if not row or not row["report"]:
        return None, None
    try:
        report = json.loads(row["report"])
        at = datetime.fromisoformat(row["received_at"])
    except ValueError:
        return None, None
    return report, max(0.0, (datetime.now(timezone.utc) - at).total_seconds() / 60)


def overview():
    """[{device, received_at, source, age (minutes) or None, has_token}] for the Settings page."""
    out = []
    with db.connect() as c:
        rows = c.execute("SELECT device, token_hash, received_at, source, version, issued_at, report FROM agent_reports "
                         "ORDER BY device COLLATE NOCASE").fetchall()
    now = datetime.now(timezone.utc)
    for r in rows:
        try:
            age = max(0.0, (now - datetime.fromisoformat(r["received_at"])).total_seconds() / 60) if r["received_at"] else None
        except ValueError:
            age = None
        try:
            rep = json.loads(r["report"]) if r["report"] else {}
        except ValueError:
            rep = {}
        out.append({"device": r["device"], "received_at": r["received_at"], "source": r["source"], "age": age,
                    "has_token": bool(r["token_hash"]), "version": r["version"], "issued_at": r["issued_at"],
                    "computer": rep.get("computer", ""), "os": rep.get("os", ""), "domain": rep.get("domain", "") if rep.get("joined") else "",
                    "pending_reboot": bool(rep.get("reboot")), "uptime_h": rep.get("uptime_h")})
    return out


def cert_days_left():
    """Days until the receiver's certificate expires (agents pin it, so a new one means new scripts and packages)."""
    from cryptography import x509
    cert_file, _ = ensure_cert()
    with open(cert_file, "rb") as f:
        return (x509.load_pem_x509_certificate(f.read()).not_valid_after_utc - datetime.now(timezone.utc)).days


def check_cert(warn_days=90):
    """Warn (log, and notification channels once) when the certificate is close to the end. Returns the days left."""
    left = cert_days_left()
    if left < warn_days:
        import logging
        logging.getLogger("toner").warning("The agent certificate expires in %d days: renew it in Settings > Agents and redeploy the agents", left)
        if db.get_setting("agent_cert_warned") != datetime.now().strftime("%Y-%m"):
            db.set_setting("agent_cert_warned", datetime.now().strftime("%Y-%m"))
            threading.Thread(target=notify_cert, args=(left,), daemon=True).start()
    return left


def notify_cert(left):
    try:
        from core import notify
        notify.announce("Toner", "agent certificate", f"{left} days left",
                        "Renew it in Settings > Agents, then give each agent a new package or script.", "FAIL" if left < 30 else "WARN")
    except Exception:
        quiet.ignored()


# ---------------------------------------------------------------- the receiver
class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "Toner"
    protocol_version = "HTTP/1.1"

    def setup(self):
        # the TLS handshake happens here, in the connection's own thread, so a client that never finishes it cannot
        # hold up the others
        self.request.settimeout(20)
        self.request = self.server.tls.wrap_socket(self.request, server_side=True)
        super().setup()

    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/ping":
            return self._send(200, b"Toner agent receiver\n", "text/plain")
        if self.path == "/agent.ps1":                      # an agent fetching its own update: only for a known token
            auth = self.headers.get("Authorization", "")
            if auth.lower().startswith("bearer ") and device_for_token(auth[7:].strip()):
                return self._send(200, ("\ufeff" + package_script()).encode("utf-8"), "text/plain; charset=utf-8")
            self.close_connection = True
            return self._send(401, b'{"ok":false}')
        self._send(404)

    def _drain(self):
        """Read and drop a request body we are not going to use, so the answer is not lost to a connection reset."""
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if 0 < n <= MAX_BODY:
                self.rfile.read(n)
        except (ValueError, OSError):
            pass

    def _enroll(self):
        owner = self.server.owner
        try:
            n = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(n).decode("utf-8-sig", "replace")) if 0 < n <= 10_000 else None
        except (ValueError, OSError):
            data = None
        if not isinstance(data, dict):
            owner.rejected += 1
            return self._send(400, b'{"ok":false,"error":"bad request"}')
        code, answer = enroll(str(data.get("computer") or ""), str(data.get("key") or ""), self.client_address[0])
        if code == 200:
            owner.accepted += 1
        else:
            owner.rejected += 1
            self.close_connection = True
        self._send(code, json.dumps(answer).encode())

    def do_POST(self):
        owner = self.server.owner
        if self.path == "/enroll":
            return self._enroll()
        if self.path != "/report":
            self._drain()
            return self._send(404)
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        auth = self.headers.get("Authorization", "")
        device = device_for_token(auth[7:].strip()) if auth.lower().startswith("bearer ") else ""
        if not device:
            owner.rejected += 1
            self._drain()
            self.close_connection = True
            return self._send(401, b'{"ok":false,"error":"unknown token"}')
        if n <= 0 or n > MAX_BODY:
            owner.rejected += 1
            self.close_connection = True
            return self._send(413 if n > MAX_BODY else 400, b'{"ok":false,"error":"bad size"}')
        try:
            report = winmon.parse_report(self.rfile.read(n).decode("utf-8-sig", "replace"))
        except (ValueError, OSError):
            owner.rejected += 1
            return self._send(400, b'{"ok":false,"error":"not a report"}')
        version = (self.headers.get("X-Toner-Agent") or "").strip()[:20]
        kind, _ = agent_kind(version)
        store(device, report, self.client_address[0], version if kind != "none" else "")
        owner.accepted += 1
        answer = {"ok": True}
        if kind != "none":                                  # only the package agent knows how to take these
            if agent_outdated(version):
                answer["update"] = True
            if token_due(device):
                answer["token"] = replace_token(device)
        self._send(200, json.dumps(answer).encode())


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass                                      # a client that drops the connection or fails the handshake is not news


class Receiver:
    def __init__(self, port, bind="0.0.0.0"):
        self.port, self.bind = int(port), bind
        self.accepted = self.rejected = 0
        self.error = ""
        self.httpd = None
        self.thread = None

    def start(self):
        cert, key = ensure_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        try:
            ipaddress.ip_address(self.bind)
        except ValueError:
            raise OSError(f"'{self.bind}' is not an IP address to listen on") from None
        httpd = _Server((self.bind, self.port), _Handler)
        httpd.owner, httpd.tls = self, ctx
        self.httpd = httpd
        self.port = httpd.server_address[1]
        self.thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.3}, daemon=True)
        self.thread.start()

    def stop(self):
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                quiet.ignored()
            self.httpd = None
        if self.thread:
            self.thread.join(3)
            self.thread = None


_receiver = None


def running():
    return _receiver is not None and _receiver.httpd is not None


def _configured_port():
    """The port set in Settings > Agents. 0 means any free port (what the tests use); only a missing value falls back to the default."""
    value = db.get_setting("agent_port")
    return DEFAULT_PORT if value in (None, "") else int(value)


def status():
    """{'running', 'port', 'error', 'accepted', 'rejected'}"""
    r = _receiver
    return {"running": running(), "port": r.port if running() else _configured_port(),
            "error": r.error if r else "", "accepted": r.accepted if r else 0, "rejected": r.rejected if r else 0}


def stop():
    global _receiver
    if _receiver:
        _receiver.stop()
        _receiver = None


def apply():
    """Start, stop or restart the receiver to match Settings. Returns an error text ('' when fine)."""
    global _receiver
    want = bool(db.get_setting("agent_enabled"))
    port = _configured_port()
    bind = db.get_setting("agent_bind") or "0.0.0.0"
    if _receiver and want and running() and _receiver.port == port and _receiver.bind == bind:
        return ""
    stop()
    if not want:
        return ""
    r = Receiver(port, bind)
    try:
        r.start()
    except Exception as e:
        r.error = f"{type(e).__name__}: {e}"
        _receiver = r
        return r.error
    _receiver = r
    return ""


# ---------------------------------------------------------------- the script
def address():
    """What agents should call this computer: the setting, else its DNS name."""
    return (db.get_setting("agent_address") or "").strip() or socket.getfqdn() or socket.gethostname()


def url_for(host=None, port=None):
    port = int(port or db.get_setting("agent_port") or DEFAULT_PORT)
    return f"https://{host or address()}:{port}/report"


# The server must have exactly the pinned certificate: no certificate authority, no trust on first use.
PIN_TYPE = r"""Add-Type -TypeDefinition @'
using System;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
public static class TonerPin {
    public static string Pin = "";
    public static bool Check(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
        if (cert == null) return false;
        using (SHA256 sha = SHA256.Create()) {
            return BitConverter.ToString(sha.ComputeHash(cert.GetRawCertData())).Replace("-", "").ToLowerInvariant() == Pin;
        }
    }
    public static RemoteCertificateValidationCallback Callback { get { return new RemoteCertificateValidationCallback(Check); } }
}
'@"""

SCRIPT = r"""<#
Toner agent for @@DEVICE@@  -  made @@MADE@@

Sends one report about this computer to Toner over HTTPS. It only sends: it opens no port and accepts no commands.
Toner is identified by its certificate fingerprint (pinned below), and this computer by the token below, so keep
this file private. Run it from an elevated PowerShell:

    powershell -ExecutionPolicy Bypass -File .\toner-agent.ps1 -Install      sets it up to report every @@MINUTES@@ minutes
    powershell -ExecutionPolicy Bypass -File .\toner-agent.ps1               sends one report now (what the task does)
    powershell -ExecutionPolicy Bypass -File .\toner-agent.ps1 -Uninstall    removes it
#>
param([switch]$Install, [switch]$Uninstall)
$Server  = '@@SERVER@@'
$Pin     = '@@PIN@@'
$Token   = '@@TOKEN@@'
$Minutes = @@MINUTES@@
$Dir     = Join-Path $env:ProgramData 'Toner Agent'
$Task    = 'Toner Agent'
$ErrorActionPreference = 'Stop'

function Test-Admin { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }

if ($Uninstall) {
    if (-not (Test-Admin)) { throw 'Run this from an elevated (Administrator) PowerShell.' }
    Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Dir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'Toner agent removed.'
    return
}
if ($Install) {
    if (-not (Test-Admin)) { throw 'Run this from an elevated (Administrator) PowerShell.' }
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    $dest = Join-Path $Dir 'toner-agent.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $dest -Force
    & icacls.exe $Dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null     # SYSTEM and Administrators only: the token is in the file
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $dest + '"')
    $start   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $Minutes)
    $boot    = New-ScheduledTaskTrigger -AtStartup
    $set     = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $Task -Action $action -Trigger @($start, $boot) -Settings $set -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    Write-Host "Toner agent installed. It reports every $Minutes minutes. Sending the first report now..."
}

# ---- collect
function Get-TonerReport {
@@COLLECTOR@@
}

# ---- send (the server must have exactly the pinned certificate)
@@PINTYPE@@
[TonerPin]::Pin = $Pin.ToLowerInvariant()
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = [TonerPin]::Callback
$json = Get-TonerReport
$bytes = [Text.Encoding]::UTF8.GetBytes($json)
try {
    $r = Invoke-WebRequest -Uri $Server -Method Post -Body $bytes -ContentType 'application/json' -Headers @{ Authorization = "Bearer $Token" } -UseBasicParsing -TimeoutSec 30
    Write-Host ('Toner answered: ' + $r.StatusCode)
} catch {
    Write-Error ('Could not send the report to Toner: ' + $_.Exception.Message)
    exit 1
}
"""


def script_for(device, minutes=5, host=None, port=None, rotate=False):
    """The agent script for a device (creates its token if it has none)."""
    minutes = max(1, min(60, int(minutes or 5)))
    token = token_for(device, rotate=rotate)
    out = (SCRIPT.replace("@@COLLECTOR@@", winmon.COLLECTOR.strip("\n"))
           .replace("@@DEVICE@@", re.sub(r"[^\w .\-]", "", device))
           .replace("@@MADE@@", datetime.now().strftime("%Y-%m-%d %H:%M"))
           .replace("@@SERVER@@", url_for(host, port))
           .replace("@@PIN@@", fingerprint())
           .replace("@@TOKEN@@", token)
           .replace("@@MINUTES@@", str(minutes))
           .replace("@@PINTYPE@@", PIN_TYPE))
    return out


# ---------------------------------------------------------------- the package (one download for every computer)
PACKAGE_SCRIPT = r"""<#
Toner agent  -  made @@MADE@@

Sends one report about this computer to Toner over HTTPS. It only sends: it opens no port and accepts no commands.
It trusts only the Toner whose certificate fingerprint is in agent.json, and the first time it runs it signs this computer
up with Toner (using the key in agent.json) and keeps the token Toner gives it.

    Install-TonerAgent.cmd       installs it (asks for administrator permission), reporting every @@MINUTES@@ minutes
    Uninstall-TonerAgent.cmd     removes it
Or from PowerShell:  toner-agent.ps1 -Install | -Uninstall | (no switch: send one report now)
#>
param([switch]$Install, [switch]$Uninstall, [switch]$Pause)
$ErrorActionPreference = 'Stop'
$AgentVersion = '@@VERSION@@'
$Dir  = Join-Path $env:ProgramData 'Toner Agent'
$Task = 'Toner Agent'
$Here = Split-Path -Parent $PSCommandPath
$ConfigPath = Join-Path $Here 'agent.json'

function Test-Admin { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
function Finish([string]$text, [int]$code = 0) { Write-Host $text; if ($Pause) { Read-Host 'Press Enter to close' | Out-Null }; exit $code }

if (($Install -or $Uninstall) -and -not (Test-Admin)) {
    $what = if ($Install) { '-Install' } else { '-Uninstall' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'), $what, '-Pause')
    exit 0
}
if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Dir -Recurse -Force -ErrorAction SilentlyContinue
    Finish 'Toner agent removed. (The computer stays listed in Toner until you delete it there.)'
}

$Cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$Minutes = [int]$Cfg.minutes

if ($Install) {
    try {
        New-Item -ItemType Directory -Force -Path $Dir | Out-Null
        $dest = Join-Path $Dir 'toner-agent.ps1'
        if ((Resolve-Path -LiteralPath $Here).Path -ne (Resolve-Path -LiteralPath $Dir).Path) {
            Copy-Item -LiteralPath $PSCommandPath -Destination $dest -Force
            Copy-Item -LiteralPath $ConfigPath -Destination (Join-Path $Dir 'agent.json') -Force
        }
        & icacls.exe $Dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null     # SYSTEM and Administrators only: the token is kept here
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $dest + '"')
        $start  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $Minutes)
        $boot   = New-ScheduledTaskTrigger -AtStartup
        $set    = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $Task -Action $action -Trigger @($start, $boot) -Settings $set -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    } catch { Finish ('Could not install the agent: ' + $_.Exception.Message) 1 }
    Write-Host "Toner agent installed. It reports every $Minutes minutes. Signing up with Toner and sending the first report..."
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $dest
    Finish $(if ($LASTEXITCODE -eq 0) { 'Done. This computer will appear in Toner.' } else { 'The agent is installed but could not reach Toner yet. It will keep trying every few minutes.' }) 0
}

# ---- collect
function Get-TonerReport {
@@COLLECTOR@@
}

# ---- talk to Toner
@@PINTYPE@@
[TonerPin]::Pin = ([string]$Cfg.pin).ToLowerInvariant()
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = [TonerPin]::Callback

if (-not $Cfg.token) {
    if (-not $Cfg.key) { Write-Error 'This agent has no token and no sign-up key.'; exit 1 }
    try {
        $body = [Text.Encoding]::UTF8.GetBytes((@{ key = [string]$Cfg.key; computer = $env:COMPUTERNAME } | ConvertTo-Json -Compress))
        $r = Invoke-WebRequest -Uri $Cfg.enroll -Method Post -Body $body -ContentType 'application/json' -UseBasicParsing -TimeoutSec 30
        $answer = $r.Content | ConvertFrom-Json
    } catch {
        $detail = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $detail = $_.ErrorDetails.Message }
        else { try { $detail = (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd() } catch {} }
        try { $detail = [string](($detail | ConvertFrom-Json).error) } catch {}
        Write-Error ('Could not sign up with Toner: ' + $detail)
        exit 1
    }
    $Cfg.token = [string]$answer.token
    $Cfg.key = ''
    [IO.File]::WriteAllText($ConfigPath, ($Cfg | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))      # the sign-up key is not kept
    Write-Host ('Signed up with Toner as ' + $answer.name)
}

$json = Get-TonerReport
$bytes = [Text.Encoding]::UTF8.GetBytes($json)
try {
    $r = Invoke-WebRequest -Uri $Cfg.server -Method Post -Body $bytes -ContentType 'application/json' -Headers @{ Authorization = ('Bearer ' + $Cfg.token); 'X-Toner-Agent' = "$AgentVersion" } -UseBasicParsing -TimeoutSec 30
    Write-Host ('Toner answered: ' + $r.StatusCode)
} catch {
    Write-Error ('Could not send the report to Toner: ' + $_.Exception.Message)
    exit 1
}

# ---- what Toner asked for in its answer: a replacement token, or a newer copy of this script
try {
    $answer = $r.Content | ConvertFrom-Json
    if ($answer.token) {
        $Cfg.token = [string]$answer.token
        [IO.File]::WriteAllText($ConfigPath, ($Cfg | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))
        Write-Host 'Toner gave this computer a new token.'
    }
    if ($answer.update) {
        $new = (Invoke-WebRequest -Uri (([string]$Cfg.server) -replace '/report$', '/agent.ps1') -Headers @{ Authorization = ('Bearer ' + $Cfg.token) } -UseBasicParsing -TimeoutSec 30).Content
        $new = $new.TrimStart([char]0xFEFF)
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($new, [ref]$null, [ref]$errors)
        if ($errors.Count -eq 0 -and $new -match 'Toner agent') {         # only a script that parses, and says what it is
            [IO.File]::WriteAllText($PSCommandPath + '.new', $new, (New-Object Text.UTF8Encoding($true)))
            Move-Item -LiteralPath ($PSCommandPath + '.new') -Destination $PSCommandPath -Force
            Write-Host 'The agent updated itself.'
        } else { Write-Host 'The update from Toner did not look right, so it was not applied.' }
    }
} catch { Write-Host ('Note: ' + $_.Exception.Message) }
"""

INSTALL_CMD = """@echo off
rem Installs the Toner agent on this computer. Windows will ask for administrator permission.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0toner-agent.ps1" -Install
"""
UNINSTALL_CMD = """@echo off
rem Removes the Toner agent from this computer. Windows will ask for administrator permission.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0toner-agent.ps1" -Uninstall
"""
PACKAGE_README = """Toner agent

What it is
  A small PowerShell script that sends a report about this computer (CPU, memory, disks, services, event errors, updates,
  certificates) to Toner over HTTPS every @@MINUTES@@ minutes. It only sends: it opens no port and accepts no commands.

Install
  1. Copy this whole folder to the Windows computer (unzip it first).
  2. Double-click Install-TonerAgent.cmd and allow the administrator prompt.
  The computer then appears in Toner (Inventory) under its own name. Windows may warn about a file from the internet: right-click
  the zip > Properties > Unblock before unzipping, or choose "Run anyway".

Without a prompt (Intune, Group Policy, a script), run as administrator:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File toner-agent.ps1 -Install

Where it lives
  C:\\ProgramData\\Toner Agent  (only SYSTEM and Administrators can read it), and a scheduled task called "Toner Agent" running as SYSTEM.

Trust
  agent.json holds Toner's address, the fingerprint of Toner's certificate (the agent talks only to a Toner that has it), and a
  sign-up key. The key is used once, to get this computer's own token, and is then removed from the installed copy. Anyone holding
  this package can sign computers up while Toner allows it, so keep it private and turn sign-up off in Toner when you are done.

Remove
  Double-click Uninstall-TonerAgent.cmd. Delete the computer in Toner too.
"""


def package_script(minutes=None):
    """The agent script in the package (the same text for every computer: its settings are in agent.json)."""
    return (PACKAGE_SCRIPT.replace("@@COLLECTOR@@", winmon.COLLECTOR.strip("\n"))
            .replace("@@MADE@@", datetime.now().strftime("%Y-%m-%d")).replace("@@MINUTES@@", str(minutes) if minutes else "few")
            .replace("@@PINTYPE@@", PIN_TYPE).replace("@@VERSION@@", str(AGENT_VERSION)))


def package_bytes(minutes=5, host=None, port=None):
    """The agent package (a .zip): the same files and sign-up key for every computer. Each one gets its own token on first run."""
    import io
    import zipfile
    minutes = max(1, min(60, int(minutes or 5)))
    url = url_for(host, port)
    cfg = {"server": url, "enroll": url.rsplit("/", 1)[0] + "/enroll", "pin": fingerprint(), "key": enroll_key(),
           "minutes": minutes, "token": ""}
    script = package_script(minutes)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("toner-agent/toner-agent.ps1", "\ufeff" + script.replace("\n", "\r\n"))     # a BOM, so Windows PowerShell reads UTF-8
        z.writestr("toner-agent/agent.json", json.dumps(cfg, indent=2))
        z.writestr("toner-agent/Install-TonerAgent.cmd", INSTALL_CMD.replace("\n", "\r\n"))
        z.writestr("toner-agent/Uninstall-TonerAgent.cmd", UNINSTALL_CMD.replace("\n", "\r\n"))
        z.writestr("toner-agent/README.txt", PACKAGE_README.replace("@@MINUTES@@", str(minutes)).replace("\n", "\r\n"))
    return buf.getvalue()
