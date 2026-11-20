# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# A device certificate whose serial number is zero or negative (RFC 5280 forbids both, devices issue them anyway): the
# certificate sweep still reports its expiry, prints no warning, and keeps working once cryptography refuses to load one.
import datetime, os, socket, ssl, tempfile, threading, time, warnings
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "cs%d.db" % int(time.time()))
from core import db, custom
# a lost packet on loopback can stall a connection for 9 s (TCP retransmit), so waits on local servers are generous
custom.run_tls.__defaults__ = (30,); custom.sweep.__defaults__ = ("443", 30)
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
CN = "lab.example.test"
NOW = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
AFTER = NOW + datetime.timedelta(days=100)

def make(serial, san=True):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CN)])
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(serial)
         .not_valid_before(NOW).not_valid_after(AFTER))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(CN), x509.DNSName("alt.example.test")]), False)
    return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

V3 = bytes.fromhex("a003020102")                      # the version field (v3); the serial number's INTEGER comes right after it

def with_serial(raw, san=True, version=V3):
    """A certificate whose serial number is exactly the bytes `raw`. cryptography's builder refuses a serial below 1, so the
    certificate is built with a placeholder serial of the same length (every byte 0x11) and those bytes are overwritten in the
    DER. That breaks the signature, which nothing here verifies (the sweep reads a certificate whoever signed it)."""
    n = len(raw)
    der = make(int.from_bytes(b"\x11" * n, "big"), san)
    old = V3 + bytes([2, n]) + b"\x11" * n
    assert der.count(old) == 1, "the placeholder serial was not found once"
    return der.replace(old, version + bytes([2, n]) + raw)

def as_v1(der):
    """The same without a version field, as a v1 certificate has it: drop its 5 bytes and shorten the two enclosing lengths."""
    assert der[:2] == b"\x30\x82" and der[4:6] == b"\x30\x82" and der[8:13] == V3
    cut = lambda b: (int.from_bytes(b, "big") - 5).to_bytes(2, "big")
    return der[:2] + cut(der[2:4]) + der[4:6] + cut(der[6:8]) + der[13:]

def quiet(fn):
    """fn's result and every warning it raised."""
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        return fn(), [str(w.message) for w in seen]

def strict(fn):
    """fn's result with every warning turned into an exception: what a cryptography that refuses these certificates does."""
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        try: return fn()
        except Exception as e: return e

def details_ok(info):
    return (isinstance(info, dict) and info["subject"] == CN and CN in info["issuer"] and info["not_before"] == NOW
            and info["not_after"] == AFTER and 98 <= info["days_left"] <= 100)

LONG = b"\x9c" + b"\x5a" * 19                         # 20 octets with the top bit set: the usual way a device ends up negative
CASES = (("zero", b"\x00", "0"), ("negative, one octet", b"\x80", "-80"), ("negative, two octets", b"\x80\x00", "-8000"),
         ("negative, 20 octets", LONG, format(int.from_bytes(LONG, "big", signed=True), "x")))

print("== certificate details")
for label, raw, want in CASES:
    der = with_serial(raw)
    info, said = quiet(lambda: custom.cert_info(der))
    check(f"serial {label}: subject, issuer, validity, days left", details_ok(info) and "alt.example.test" in info["sans"], info)
    check(f"serial {label}: reported as it is", info["serial"] == want, info["serial"])
    check(f"serial {label}: no warning", not said, said)
    check(f"serial {label}: still read when cryptography refuses it", details_ok(strict(lambda: custom.cert_info(der))), strict(lambda: custom.cert_info(der)))
old = as_v1(with_serial(b"\x00", san=False))
info = strict(lambda: custom.cert_info(old))
check("serial zero in a v1 certificate (no version field)", details_ok(info) and info["serial"] == "0" and info["sans"] == [], info)
for label, n in (("small", 5), ("random", x509.random_serial_number()), ("20 octets", int.from_bytes(b"\x7f" + b"\xa5" * 19, "big"))):
    info, said = quiet(lambda: custom.cert_info(make(n)))
    check(f"a positive serial ({label}) is untouched", details_ok(info) and info["serial"] == format(n, "x") and not said, (info, said))
try: custom.cert_info(b"not a certificate"); check("what is not a certificate still raises", False)
except Exception: check("what is not a certificate still raises", True)

print("== the trust prompt (a directory server's certificate)")
import hashlib
from core import certpeek
def described_ok(info, der):                          # the fingerprint is the served certificate's own: it is what gets pinned
    return (isinstance(info, dict) and info["names"] == [CN, "alt.example.test"] and info["issuer"] == CN and not info["expired"]
            and info["valid_from"] == NOW.date().isoformat() and info["valid_to"] == AFTER.date().isoformat()
            and info["sha256"] == ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest()))
for label, raw, _ in CASES[::3]:
    der = with_serial(raw)
    info, said = quiet(lambda: certpeek.describe(der))
    check(f"serial {label}: names, issuer, validity, fingerprint", described_ok(info, der), info)
    check(f"serial {label}: no warning", not said, said)
    check(f"serial {label}: still described when cryptography refuses it", described_ok(strict(lambda: certpeek.describe(der)), der), strict(lambda: certpeek.describe(der)))
info, said = quiet(lambda: certpeek.describe(make(5)))
check("a positive serial is described as before", described_ok(info, make(5)) and not said, (info, said))

print("== over TLS")
def tls_server(der):
    d = tempfile.mkdtemp(); cf, kf = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    open(cf, "w").write(ssl.DER_cert_to_PEM_cert(der))
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
    return s.getsockname()[1]
DEV = {"name": "srv", "vendor": "snmp", "host": "127.0.0.1"}
p = tls_server(with_serial(b"\x00"))
r, said = quiet(lambda: custom.run_tls({"name": "Cert", "kind": "tls", "port": p}, DEV))
check("check: serial zero is graded on its days left", r.status == "OK" and r.value in ("99 days", "100 days") and CN in r.message, r)
check("check: no warning", not said, said)
rows, said = quiet(lambda: custom.sweep(DEV, {}, str(p)))
check("sweep: serial zero gives its row", len(rows) == 1 and rows[0].check == f"certificate :{p}" and rows[0].status == "OK", rows)
check("sweep: no warning", not said, said)
p2 = tls_server(with_serial(LONG))
rows = strict(lambda: custom.sweep(DEV, {}, str(p2)))
check("sweep: a negative serial still gives its row when cryptography refuses it",
      isinstance(rows, list) and len(rows) == 1 and rows[0].status == "OK" and rows[0].value in ("99 days", "100 days"), rows)
# a certificate cryptography cannot read at all (version 7; OpenSSL serves it without looking): a row, not an exception
p3 = tls_server(with_serial(b"\x11", version=bytes.fromhex("a003020107")))
try: rows = custom.sweep(DEV, {}, f"{p3}, {p}")
except Exception as e: rows = e
check("sweep: an unreadable certificate is an ERROR row", isinstance(rows, list) and len(rows) == 2 and rows[0].status == "ERROR"
      and rows[0].check == f"certificate :{p3}" and "version" in rows[0].message, rows)
check("sweep: and the next port is still read", isinstance(rows, list) and len(rows) == 2 and rows[1].status == "OK", rows)

print(f"\n{ok} passed, {bad} failed")
_sys.exit(1 if bad else 0)
