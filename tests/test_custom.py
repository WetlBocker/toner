# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import datetime, http.server, os, socket, ssl, sys, tempfile, threading, time
pass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\cu%d.db").replace("\\", os.sep) % int(time.time())
from core import db, custom, snmp
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
from drivers import DRIVERS

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def dev(**kw):
    d = dict(name="srv", vendor="snmp", host="127.0.0.1", port=0, platform="", username="", site="default", verify_ssl=0,
             ha_expected=0, enabled=1, location="", details="", folder_id=None); d.update(kw); return d

print("== definitions")
base = {"name": "Disk C", "kind": "ssh", "target": "show disk", "mode": "number", "warn": 80, "fail": 90, "higher_worse": 1, "unit": "%"}
for bad_chk, why in (({**base, "name": ""}, "name"), ({**base, "kind": "x"}, "kind"), ({**base, "target": ""}, "command"),
                     ({**base, "kind": "tcp", "port": 0}, "port"), ({**base, "kind": "snmp", "target": "nonsense.0"}, "OID"),
                     ({**base, "mode": "match", "parse": ""}, "pattern"), ({**base, "mode": "match", "parse": "("}, "regular"),
                     ({**base, "warn": 95, "fail": 90}, "WARN")):
    try: custom.validate(bad_chk); check(f"rejects bad {why}", False)
    except ValueError as e: check(f"rejects bad {why}", why.lower() in str(e).lower() or why in str(e), e)
cid = custom.save_check({**base, "scope": ["Vendor: Cisco"]})
check("saved and listed with its scope", custom.list_checks()[0]["scope"] == ["Vendor: Cisco"] and custom.list_checks()[0]["name"] == "Disk C")
custom.save_check({**base, "id": cid, "scope": [], "enabled": 0})
check("edit in place; disabled checks do not apply", len(custom.list_checks()) == 1 and custom.for_device(dev(vendor="cisco")) == [])
custom.save_check({**base, "id": cid, "enabled": 1, "scope": ["Vendor: Cisco"]})
check("scope limits where it applies", len(custom.for_device(dev(vendor="cisco"))) == 1 and custom.for_device(dev(vendor="juniper")) == [])
try: custom.save_check({**base, "name": "disk c"}); check("duplicate names refused", False)
except Exception: check("duplicate names refused", True)

print("== evaluation of command output")
chk = {**base, "higher_worse": 1}
r = custom.evaluate(chk, "d", "Filesystem 85% used"); check("number above WARN", r.status == "WARN" and r.value == "85%" and r.numeric == 85.0, r)
check("number above FAIL", custom.evaluate(chk, "d", "95").status == "FAIL")
check("number fine", custom.evaluate(chk, "d", "12").status == "OK")
low = {**base, "higher_worse": 0, "warn": 20, "fail": 10, "unit": " GB"}
check("lower is worse: low value fails", custom.evaluate(low, "d", "free 8 GB").status == "FAIL" and custom.evaluate(low, "d", "free 15").status == "WARN" and custom.evaluate(low, "d", "free 50").status == "OK")
check("capture group picks the right number", custom.evaluate({**base, "parse": r"free=(\d+)"}, "d", "used=99 free=3").numeric == 3.0)
check("no number is an ERROR, not an OK", custom.evaluate(chk, "d", "n/a").status == "ERROR")
check("thousands separators", custom.evaluate({**base, "parse": r"([\d,]+) users"}, "d", "12,500 users").numeric == 12500.0)
m = {**base, "mode": "match", "parse": r"state:\s*Established"}
check("match: found = OK", custom.evaluate(m, "d", "state: Established").status == "OK")
r = custom.evaluate(m, "d", "state: Idle"); check("match: missing = FAIL with the output", r.status == "FAIL" and "Idle" in r.message, r)
nm = {**base, "mode": "nomatch", "parse": r"(?i)error|fail"}
check("no-match: clean = OK, error text = FAIL", custom.evaluate(nm, "d", "all good").status == "OK" and custom.evaluate(nm, "d", "Link ERROR").status == "FAIL")

print("== SSH custom checks run inside the device session")
class Conn:
    def __init__(self): self.sent = []
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def send_command(self, c, **k):
        self.sent.append(c)
        if c == "boom": raise RuntimeError("channel closed")
        return {"show disk": "used 88%", "show cpu": "cpu 3"}.get(c, "")
th = db.thresholds_for(dev(vendor="juniper"))
drv = DRIVERS["juniper"](dev(vendor="juniper", username="u", password="p", platform="juniper_junos"), th, db.runtime_options())
drv.custom = [{**base, "target": "show disk"}, {**base, "name": "Boom", "target": "boom"}, {**base, "name": "Web", "kind": "tcp", "port": 22}]
conn = Conn(); drv.connect = lambda: conn
rows = {x.check: x for x in drv.run()}
check("the custom command is sent in the same session", "show disk" in conn.sent and rows["Disk C"].status == "WARN", rows.get("Disk C"))
check("a failing command is an ERROR row, others still run", rows["Boom"].status == "ERROR" and "channel closed" in rows["Boom"].message)
check("non-SSH kinds are not run in the session", "Web" not in rows)

print("== TCP, HTTP, TLS and ping against local servers")
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5); TCP = srv.getsockname()[1]
threading.Thread(target=lambda: [srv.accept() for _ in range(50)], daemon=True).start()
r = custom.run_tcp({"name": "T", "kind": "tcp", "port": TCP, "warn": None, "fail": None}, dev())
check("open port is OK with a latency", r.status == "OK" and r.numeric is not None and "open" in r.message and r.value.endswith(" ms"), r)
closed = socket.socket(); closed.bind(("127.0.0.1", 0)); cp = closed.getsockname()[1]; closed.close()
r = custom.run_tcp({"name": "T", "kind": "tcp", "port": cp}, dev())
check("closed port is FAIL", r.status == "FAIL" and r.value == "closed", r)
r = custom.run_tcp({"name": "T", "kind": "tcp", "port": TCP, "warn": -1, "fail": 100000, "higher_worse": 1}, dev())
check("latency limit applies", r.status == "WARN", r)

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/ok": body, code = b"<html>Status: HEALTHY</html>", 200
        elif self.path == "/bad": body, code = b"boom", 500
        else: body, code = b"", 404
        self.send_response(code); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
hs = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H); HP = hs.server_address[1]
threading.Thread(target=hs.serve_forever, daemon=True).start()
url = lambda p: f"http://127.0.0.1:{HP}{p}"
mk = lambda **k: {"name": "W", "kind": "http", "expect": "2xx", **k}
r = custom.run_http(mk(target=url("/ok")), dev()); check("200 is OK with timing", r.status == "OK" and "HTTP 200" in r.message and r.numeric is not None, r)
r = custom.run_http(mk(target=url("/bad")), dev()); check("500 is FAIL", r.status == "FAIL" and r.value == "500", r)
r = custom.run_http(mk(target=url("/missing"), expect="404"), dev()); check("expected status can be 404", r.status == "OK")
r = custom.run_http(mk(target=url("/ok"), expect="200,301"), dev()); check("expected list", r.status == "OK")
r = custom.run_http(mk(target=url("/ok"), mode="match", parse="HEALTHY"), dev()); check("body must match: found", r.status == "OK")
r = custom.run_http(mk(target=url("/ok"), mode="match", parse="DEGRADED"), dev()); check("body must match: missing -> FAIL", r.status == "FAIL" and "200" in r.value, r)
r = custom.run_http(mk(target=f"http://{{host}}:{HP}/ok"), dev()); check("{host} is replaced", r.status == "OK")
r = custom.run_http(mk(target=f"http://127.0.0.1:{cp}/"), dev()); check("unreachable site is FAIL", r.status == "FAIL" and r.value == "unreachable", r)

# a real TLS server with a throwaway certificate
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
def make_cert(days, cn="lab.example.test"):
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn), x509.DNSName("alt.example.test")]), False).sign(key, hashes.SHA256()))
def tls_server(days):
    cert = make_cert(days)
    d = tempfile.mkdtemp(); cf, kf = d + r"\c.pem", d + r"\k.pem"
    open(cf, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kf, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cf, kf)
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(5)
    def serve():
        while True:
            try:
                c, _ = s.accept()
                try: ctx.wrap_socket(c, server_side=True).close()
                except Exception: pass
            except Exception: return
    threading.Thread(target=serve, daemon=True).start()
    return s.getsockname()[1], cert
p, cert = tls_server(100)
r = custom.run_tls({"name": "Cert", "kind": "tls", "port": p}, dev())
check("certificate with 100 days left is OK", r.status == "OK" and r.value in ("99 days", "100 days") and "lab.example.test" in r.message, r)
p2, _ = tls_server(20)
check("under 30 days warns", custom.run_tls({"name": "Cert", "kind": "tls", "port": p2}, dev()).status == "WARN")
p3, _ = tls_server(3)
check("under 7 days fails", custom.run_tls({"name": "Cert", "kind": "tls", "port": p3}, dev()).status == "FAIL")
r = custom.run_tls({"name": "Cert", "kind": "tls", "port": p, "warn": 120, "fail": 10}, dev()); check("custom limits (lower is worse)", r.status == "WARN", r)
info = custom.cert_info(cert.public_bytes(serialization.Encoding.DER))
check("certificate details: subject, SANs, validity", info["subject"] == "lab.example.test" and "alt.example.test" in info["sans"] and 98 <= info["days_left"] <= 100, info)
check("no TLS on the port is FAIL", custom.run_tls({"name": "Cert", "kind": "tls", "port": cp}, dev()).status == "FAIL")

r = custom.run_ping({"name": "P", "kind": "ping"}, dev()); check("ping localhost", r.status in ("OK", "WARN") and r.numeric is not None, r)
r = custom.run_ping({"name": "P", "kind": "ping"}, dev(host="192.0.2.1")); check("ping to a black hole fails", r.status == "FAIL", r)

print("== SNMP custom checks")
class FakeClient:
    def __init__(self, *a, **k): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def get(self, *oids):
        from pysnmp.proto.rfc1902 import Integer32, OctetString
        o = oids[0]
        return {o: Integer32(42)} if o.endswith(".9.9") else {o: OctetString("link is up")} if o.endswith(".8.8") else {}
snmp.Client = FakeClient
snmp.credentials_for = lambda d: (snmp.Credentials(community="public"), 161)
s = {"name": "S", "kind": "snmp", "target": "1.3.6.1.4.1.1.9.9", "mode": "number", "warn": 40, "fail": 60, "higher_worse": 1, "unit": " C"}
r = custom.run_snmp(s, dev()); check("numeric OID graded", r.status == "WARN" and r.value == "42 C" and r.numeric == 42.0, r)
r = custom.run_snmp({**s, "target": "1.3.6.1.4.1.1.8.8", "mode": "match", "parse": "up"}, dev()); check("text OID matched", r.status == "OK", r)
r = custom.run_snmp({**s, "target": "1.3.6.1.4.1.1.7.7"}, dev()); check("missing object is an ERROR", r.status == "ERROR", r)
check("device without SNMP settings: not applicable", custom.run_snmp(s, dev(vendor="juniper")) is None)

print("== wired into a run")
db.save_device(dev(name="web1", vendor="snmp", host="127.0.0.1"))
custom.save_check({"name": "Site up", "kind": "http", "target": url("/ok"), "expect": "2xx", "scope": ["Vendor: Generic SNMP"]})
custom.save_check({"name": "Port 22", "kind": "tcp", "port": TCP, "scope": []})
from core.runner import run_one
d = [x for x in db.list_devices() if x["name"] == "web1"][0]
snmp.Client = lambda *a, **k: (_ for _ in ()).throw(snmp.SnmpError("unreachable in test"))
res = run_one(d, db.thresholds_for(d), db.runtime_options())
names = {r.check: r for r in res}
check("a failing built-in driver still reports (one connection ERROR)", names["connection"].status == "ERROR")
check("web and port checks still run when the login fails", names["Site up"].status == "OK" and names["Port 22"].status == "OK", {k: v.status for k, v in names.items()})
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
