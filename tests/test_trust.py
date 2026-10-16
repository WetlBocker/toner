# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Toner's web requests trust what Windows trusts as well as its own public list, so HTTPS inspection on the network
# (a firewall or antivirus re-signing traffic with a certificate only the Windows store has) does not break updates.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import datetime, http.server, ipaddress, os, ssl, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\trust%d\t.db" % int(time.time())
os.makedirs(os.path.dirname(os.environ["NETCHECK_DB"]), exist_ok=True)
for v in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
    os.environ.pop(v, None)
from core import db, trust, updates
db.init()
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

# ---------------------------------------------------------------- a private CA, like a firewall's inspection certificate
now = datetime.datetime.now(datetime.timezone.utc)
def name(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
ca_key = ec.generate_private_key(ec.SECP256R1())
ca = (x509.CertificateBuilder().subject_name(name("Toner Test Inspection CA")).issuer_name(name("Toner Test Inspection CA"))
      .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
      .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
      .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
      .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                   key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
      .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
      .sign(ca_key, hashes.SHA256()))
srv_key = ec.generate_private_key(ec.SECP256R1())
srv = (x509.CertificateBuilder().subject_name(name("localhost")).issuer_name(ca.subject).public_key(srv_key.public_key())
       .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
       .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]), critical=False)
       .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
       .add_extension(x509.SubjectKeyIdentifier.from_public_key(srv_key.public_key()), critical=False)
       .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
       .sign(ca_key, hashes.SHA256()))
other_key = ec.generate_private_key(ec.SECP256R1())
other = (x509.CertificateBuilder().subject_name(name("Code signing only")).issuer_name(name("Code signing only"))
         .public_key(other_key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(other_key, hashes.SHA256()))
DER = serialization.Encoding.DER
certdir = os.path.join(SP, "certs%d" % int(time.time())); os.makedirs(certdir)
with open(os.path.join(certdir, "srv.pem"), "wb") as f:
    f.write(srv.public_bytes(serialization.Encoding.PEM) + srv_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

class Hello(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length", "5"); self.end_headers(); self.wfile.write(b"hello")
    def log_message(self, *a): pass
web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hello)
sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); sctx.load_cert_chain(os.path.join(certdir, "srv.pem"))
web.socket = sctx.wrap_socket(web.socket, server_side=True)
threading.Thread(target=web.serve_forever, daemon=True).start()
URL = f"https://127.0.0.1:{web.server_address[1]}/"
DIRECT = {"http": "", "https": ""}

# what the Windows store hands back: the inspection CA (all uses), a code-signing-only CA, junk, and a duplicate
STORE = {"ROOT": [(ca.public_bytes(DER), "x509_asn", True), (other.public_bytes(DER), "x509_asn", {"1.3.6.1.5.5.7.3.3"}),
                  (b"not a certificate", "x509_asn", True), (b"\x01\x02", "pkcs_7_asn", True)],
         "CA": [(ca.public_bytes(DER), "x509_asn", {trust.SERVER_AUTH})]}
real_enum = getattr(ssl, "enum_certificates", None)
ssl.enum_certificates = lambda store: STORE.get(store, [])

print("== before: only the public list")
try:
    requests.get(URL, timeout=5, proxies=DIRECT); before = "worked"
except requests.exceptions.SSLError as e:
    before = str(e)
check("a site signed by the inspection certificate is refused, as in the report", "CERTIFICATE_VERIFY_FAILED" in before or "certificate verify failed" in before, before[:120])

print("== what Windows trusts")
pems = trust.windows_pems()
check("the inspection CA is taken once, from either store", len(pems) == 1 and "BEGIN CERTIFICATE" in pems[0], len(pems))
check("a CA trusted only for something else (code signing) is left out", all(x509.load_pem_x509_certificate(p.encode()).subject != other.subject for p in pems))
check("junk in the store is skipped instead of spoiling the file", len(pems) == 1)

print("== after")
path = trust.install()
check("the combined file is written next to Toner's data and used for web requests", path == trust.bundle_path() and os.environ.get("REQUESTS_CA_BUNDLE") == str(path))
text = path.read_text(encoding="utf-8")
import certifi
check("it holds the public list and then what Windows adds", text.startswith(open(certifi.where(), encoding="utf-8").read().rstrip()[:200]) and trust.MARK in text and text.count("BEGIN CERTIFICATE") > 100)
r = requests.get(URL, timeout=5, proxies=DIRECT)
check("the same site now works", r.status_code == 200 and r.text == "hello")
r = requests.get("https://api.github.com/", timeout=10, proxies=DIRECT) if os.environ.get("TONER_TEST_ONLINE") else None
check("public sites still work (online check only when TONER_TEST_ONLINE is set)", r is None or r.status_code in (200, 403))
try:
    requests.get(URL, timeout=5, proxies=DIRECT, verify=False); skipped = True
except Exception:
    skipped = False
check("a connection set not to check certificates is unchanged", skipped)
mtime = path.stat().st_mtime_ns
os.environ.pop("REQUESTS_CA_BUNDLE")
trust.install()
check("starting again with the same certificates leaves the file alone", path.stat().st_mtime_ns == mtime)

print("== when not to touch anything")
os.environ["REQUESTS_CA_BUNDLE"] = r"C:\somewhere\chosen.pem"
check("a file someone chose already is kept", trust.install() is None and os.environ["REQUESTS_CA_BUNDLE"] == r"C:\somewhere\chosen.pem")
os.environ.pop("REQUESTS_CA_BUNDLE")
ssl.enum_certificates = lambda store: []
check("when Windows adds nothing, nothing is set", trust.install() is None and "REQUESTS_CA_BUNDLE" not in os.environ)
def broken(store): raise OSError("access denied")
ssl.enum_certificates = broken
check("a store that cannot be opened is not an error", trust.windows_pems() == [] and trust.install() is None)
if real_enum is not None:
    ssl.enum_certificates = real_enum
    real = trust.windows_pems()
    check("this computer's real store can be read", isinstance(real, list) and all("BEGIN CERTIFICATE" in p for p in real), len(real))

print("== the update messages")
class FakeSSL(requests.exceptions.SSLError): pass
def raise_ssl(*a, **k):
    raise FakeSSL("HTTPSConnectionPool(host='release-assets.githubusercontent.com', port=443): Max retries exceeded "
                  "(Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
                  "self-signed certificate in certificate chain (_ssl.c:1018)')))")
real_get = requests.get
updates.requests.get = raise_ssl
try:
    updates.fetch_latest(); m1 = ""
except updates.UpdateError as e:
    m1 = str(e)
check("a failed check says the certificate was not trusted, and what to do", "not trusted (self-signed certificate in certificate chain)" in m1 and "Windows certificate store" in m1, m1)
rel = updates.Release(version="9.9.9", tag="v9.9.9", name="x", notes="", page_url="", published="")
rel.asset_name, rel.asset_url, rel.sha256 = "Toner-Setup-9.9.9.exe", "https://github.com/WetlBocker/toner/releases/download/v9.9.9/Toner-Setup-9.9.9.exe", "0" * 64
try:
    updates.download(rel, dest_dir=os.path.join(SP, "dl%d" % int(time.time()))); m2 = ""
except updates.UpdateError as e:
    m2 = str(e)
check("a failed download says the same and points to the release page", "failed its security check" in m2 and "SSL inspection" in m2 and "release page" in m2, m2)
updates.requests.get = real_get

print(f"\n{ok} passed, {bad} failed")
web.shutdown()
sys.exit(1 if bad else 0)
