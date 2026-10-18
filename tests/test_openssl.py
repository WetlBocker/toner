# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import base64, hashlib, os, socket, ssl, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\ossl%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roamingssl%d" % int(time.time()))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from core import db, openssl as o
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def raises(fn, text):
    try: fn(); return False
    except ValueError as e: return text.lower() in str(e).lower()

print("== keys")
for kind, cls in (("rsa2048", rsa.RSAPrivateKey), ("p256", ec.EllipticCurvePrivateKey), ("p384", ec.EllipticCurvePrivateKey), ("ed25519", ed25519.Ed25519PrivateKey)):
    pem = o.generate_key(kind)
    check(f"{kind} makes a readable, unencrypted PKCS#8 key", pem.startswith("-----BEGIN PRIVATE KEY-----") and isinstance(o.load_key(pem), cls))
enc = o.generate_key("p256", "s3cret")
check("a passphrase encrypts it", "BEGIN ENCRYPTED PRIVATE KEY" in enc and isinstance(o.load_key(enc, "s3cret"), ec.EllipticCurvePrivateKey))
check("a missing or wrong passphrase is explained", raises(lambda: o.load_key(enc), "enter its passphrase") and raises(lambda: o.load_key(enc, "nope"), "wrong passphrase") and raises(lambda: o.load_key("junk"), "not a readable"))
check("an unknown type is refused", raises(lambda: o.generate_key("dsa"), "unknown key type"))
check("RSA 3072 and 4096 are offered", {"rsa3072", "rsa4096"} <= {k for k, _ in o.KEY_TYPES})

print("== names")
sans = o.parse_sans("a.example.com, 10.0.0.5  IP:10.0.0.6; DNS:b.example.com email:me@x.org uri:https://x.org/ ::1")
check("alternative names: DNS, IPv4, IPv6, prefixed forms, email and URI", [type(s).__name__ for s in sans] == ["DNSName", "IPAddress", "IPAddress", "DNSName", "RFC822Name", "UniformResourceIdentifier", "IPAddress"] and str(sans[1].value) == "10.0.0.5", sans)
check("a bad IP after an IP: prefix is refused", raises(lambda: o.parse_sans("IP:nothing"), "not an ip address"))
check("a country must be two letters", raises(lambda: o.subject_name({"C": "USA"}), "two-letter"))
check("a request needs a name", raises(lambda: o.make_csr({}), "common name"))
check("the subject keeps the order CN, O, OU, C, ST, L, email and upper-cases the country", [a.value for a in o.subject_name({"CN": "x", "O": "Acme", "C": "us", "L": "Chicago", "emailAddress": "a@b.c"})] == ["x", "Acme", "US", "Chicago", "a@b.c"])

print("== certificate requests")
key, csr_pem = o.make_csr({"CN": "www.example.com", "O": "Acme", "C": "US"}, "www.example.com, example.com, 10.0.0.5", "rsa2048", "pw")
csr = x509.load_pem_x509_csr(csr_pem.encode()); csr_key = key
check("a CSR with the subject, the alternative names and a valid signature", csr.is_signature_valid and csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "www.example.com"
      and [str(n.value) for n in csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value] == ["www.example.com", "example.com", "10.0.0.5"])
check("the key that came with it is encrypted and is the CSR's key", "ENCRYPTED" in key and o.load_key(key, "pw").public_key().public_numbers() == csr.public_key().public_numbers())
mine = o.generate_key("p384")
k2, csr2 = o.make_csr({"CN": "re.example.com"}, "", "rsa2048", "", mine)
check("an existing key can be reused: no new key is returned, and the request is for that key", k2 == "" and x509.load_pem_x509_csr(csr2.encode()).public_key().public_numbers() == o.load_key(mine).public_key().public_numbers())
check("Ed25519 requests work too", x509.load_pem_x509_csr(o.make_csr({"CN": "e"}, "", "ed25519")[1].encode()).is_signature_valid)

print("== self-signed certificates")
key, pem = o.make_self_signed({"CN": "lab.test", "O": "Lab"}, "lab.test, 192.168.1.1", "p256", 90)
cert = x509.load_pem_x509_certificate(pem.encode())
cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
check("it is signed by its own key, valid for the days asked (plus a few minutes of clock slack)", days == 90 and cert.subject == cert.issuer)
check("it is a server/client certificate, not a CA, with the names", cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
      and "serverAuth" in str([e._name for e in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]) and len(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value) == 2)
kca, pca = o.make_self_signed({"CN": "Lab Root CA"}, "", "rsa2048", 3650, "", True)
ca = x509.load_pem_x509_certificate(pca.encode())
check("a CA certificate says so and may sign certificates", ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca and ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign)
check("with only a SAN the first name becomes the common name", x509.load_pem_x509_certificate(o.make_self_signed({}, "only.example.com")[1].encode()).subject.rfc4514_string() == "CN=only.example.com")
check("days are range-checked", raises(lambda: o.make_self_signed({"CN": "x"}, days=0), "days") and raises(lambda: o.make_self_signed({"CN": "x"}, days=99999), "days"))
check("Ed25519 self-signed works", x509.load_pem_x509_certificate(o.make_self_signed({"CN": "e"}, "", "ed25519")[1].encode()).signature_algorithm_oid._name == "ed25519")

print("== reading")
text = o.inspect(pem + key)
check("a certificate is described: subject, issuer, self-signed, dates, key, signature, names, fingerprints", all(s in text for s in ("CN=lab.test, O=Lab", "Self-signed:  yes", "days left", "EC, curve secp256r1", "ecdsa-with-SHA256", "DNS:lab.test", "IP:192.168.1.1", "SHA-256:", "SHA-1:")), text)
check("the certificate's fingerprint is the real one", ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256())) in text)
check("a certificate and its key are reported as matching", "They match" in text and "Private key" in text and "not encrypted" in text)
other = o.generate_key("p256")
check("a key that does not belong to the certificate is called out", "NOT the same" in o.inspect(pem + other))
check("a request is described, with its signature checked", "Certificate request" in o.inspect(csr_pem) and "valid" in o.inspect(csr_pem) and "10.0.0.5" in o.inspect(csr_pem))
check("a key and a request for it match", "They match" in o.inspect(csr_pem + csr_key, "pw"))
check("an encrypted key without its passphrase says so, and with it is read", "enter its passphrase" in o.inspect(enc) and "yes (encrypted)" in o.inspect(enc, "s3cret"))
der = x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
check("a DER certificate is recognised", "(DER certificate)" in o.inspect(der) and "CN=lab.test" in o.inspect(der))
check("a chain of several certificates lists each", o.inspect(pem + pca).count("Certificate\n  Subject") == 2)
import datetime as _dt
_nm = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "old")])
_old = x509.CertificateBuilder().subject_name(_nm).issuer_name(_nm).public_key(o.load_key(mine).public_key()).serial_number(5).not_valid_before(_dt.datetime(2020, 1, 1)).not_valid_after(_dt.datetime(2021, 1, 1)).sign(o.load_key(mine), hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
check("an expired certificate is flagged", "EXPIRED" in o.inspect(_old))
check("garbage is refused clearly", raises(lambda: o.inspect(b"hello world"), "not recognised"))
check("a PEM block of a kind it does not know is named, not crashed on", "not described" in o.inspect(b"-----BEGIN DH PARAMETERS-----\nabc\n-----END DH PARAMETERS-----"))

print("== converting")
check("PEM to DER and back gives the same certificate", o.to_der(pem) == der and o.to_pem(der).strip() == pem.strip())
check("a request converts both ways", o.to_pem(o.to_der(csr_pem)).strip() == csr_pem.strip())
check("a key converts to DER (unencrypted PKCS#8)", isinstance(serialization.load_der_private_key(o.to_der(key, "pw"), None), ec.EllipticCurvePrivateKey) or isinstance(serialization.load_der_private_key(o.to_der(key, "pw"), None), rsa.RSAPrivateKey))
check("nothing to convert says so", raises(lambda: o.to_der("hello"), "paste a pem") and raises(lambda: o.to_pem(b"junk"), "not a der"))
rk, rc = o.make_self_signed({"CN": "leaf.test"}, "leaf.test", "rsa2048", 30)
pfx = o.to_pfx(rc + pca + rk, "", "export1", "leaf")
check("certificate + key make a .pfx that opens with its password and not without", isinstance(pfx, bytes) and "PKCS#12" in o.inspect(pfx, "export1") and raises(lambda: o.inspect(pfx), "password"))
back = o.from_pfx(pfx, "export1")
check("a .pfx gives back the certificate, its chain and the key, and the key belongs to the first certificate", back.count("BEGIN CERTIFICATE") == 2 and "BEGIN PRIVATE KEY" in back and "private key" in o.inspect(back).split("Same key pair")[1].split("\n")[0] and "NOT the same" in o.inspect(back))
check("a wrong .pfx password is explained", raises(lambda: o.from_pfx(pfx, "bad"), "wrong password"))
check("the key can leave a .pfx encrypted", "ENCRYPTED PRIVATE KEY" in o.from_pfx(pfx, "export1", "newpass"))
check("a .pfx needs a certificate that matches the key", raises(lambda: o.to_pfx(pca + rk), "matches") and raises(lambda: o.to_pfx(pem), "needs a certificate"))
check("typing a passphrase for a key that has none does no harm", "BEGIN PRIVATE KEY" in o.change_passphrase(rk, "unneeded", "") and "They match" in o.inspect(rc + rk, "unneeded"))
check("a passphrase can be added, changed and removed", "ENCRYPTED" in o.change_passphrase(rk, "", "a") and "ENCRYPTED" not in o.change_passphrase(o.change_passphrase(rk, "", "a"), "a", "")
      and o.load_key(o.change_passphrase(o.change_passphrase(rk, "", "a"), "a", "b"), "b") and raises(lambda: o.change_passphrase("junk"), "paste a pem private key"))

print("== hashes and random")
check("digests are the standard ones", o.digest("abc") == hashlib.sha256(b"abc").hexdigest() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
      and o.digest("abc", "md5") == "900150983cd24fb0d6963f7d28e17f72" and o.digest(b"abc", "sha1") == "a9993e364706816aba3e25717850c26c9cd0d89d" and len(o.digest("x", "sha512")) == 128)
check("an unknown digest is refused", raises(lambda: o.digest("x", "crc32"), "unknown digest"))
check("base64 round-trips, wraps at 64, and rejects junk", o.base64_decode(o.base64_encode(b"x" * 100)) == b"x" * 100 and max(map(len, o.base64_encode(b"x" * 100).split("\n"))) == 64
      and raises(lambda: o.base64_decode("not base64!!"), "not valid base64"))
check("random bytes come in hex or base64, the right length, and differ", len(o.random_bytes(16)) == 32 and len(base64.b64decode(o.random_bytes(16, "base64"))) == 16 and o.random_bytes(16) != o.random_bytes(16)
      and raises(lambda: o.random_bytes(0), "between"))

print("== a server's certificates")
def serve(cert_pem, key_pem):
    d = os.path.join(SP, "srv%d" % int(time.time() * 1000)); os.makedirs(d)
    open(os.path.join(d, "c.pem"), "w").write(cert_pem); open(os.path.join(d, "k.pem"), "w").write(key_pem)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(os.path.join(d, "c.pem"), os.path.join(d, "k.pem"))
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(5); stop = []
    def loop():
        s.settimeout(0.3)
        while not stop:
            try: c, _ = s.accept()
            except OSError: continue
            try:
                t = ctx.wrap_socket(c, server_side=True); t.settimeout(2)
                try: t.recv(100)
                except OSError: pass
                t.close()
            except Exception: pass
    threading.Thread(target=loop, daemon=True).start()
    return s.getsockname()[1], lambda: (stop.append(1), s.close())
srv_key, srv_cert = o.make_self_signed({"CN": "localhost"}, "localhost, 127.0.0.1", "rsa2048", 5)
port, stopper = serve(srv_cert + pca, srv_key)
pem_chain, info = o.fetch_chain("127.0.0.1", port, "localhost")
check("the chain a server sends is fetched (even a self-signed one, which is not validated)", pem_chain.count("BEGIN CERTIFICATE") == 2 and "answered with 2 certificate" in info and "TLSv1" in info, info)
check("it is the server's certificate", "CN=localhost" in o.inspect(pem_chain) and ":".join(f"{b:02X}" for b in x509.load_pem_x509_certificate(srv_cert.encode()).fingerprint(hashes.SHA256())) in o.inspect(pem_chain))
try: o.fetch_chain("127.0.0.1", 1, timeout=2); check("a closed port", False)
except OSError: check("a closed port is a connection error", True)

print("== a real openssl.exe")
fake = os.path.join(SP, "openssl-fake.exe"); open(fake, "wb").close()
check("a chosen file wins", o.find_openssl(fake) == fake)
real = o.find_openssl()
check("otherwise PATH and the usual folders are searched (Git for Windows has one)", real == "" or os.path.isfile(real), real)
import shutil as _sh
_which, _cand = _sh.which, o.CANDIDATES
_sh.which = lambda n: None; o.CANDIDATES = ()
check("nothing found is an empty answer", o.find_openssl("") == "" and o.find_openssl(r"C:\nope\openssl.exe") == "")
_sh.which, o.CANDIDATES = _which, _cand
check("examples exist", len(o.PRESETS) >= 8 and all(a and b for a, b in o.PRESETS))

print("== the tool in the Tools tab")
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox
app = QApplication([])
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import app as A
A.apply_look(app)
from ui.tools import ToolsTab
import ui.opensslui as U
tools = ToolsTab()
check("OpenSSL is in the Tools list under Certificates", "OpenSSL" in [tools.tabs.tabText(i) for i in range(tools.tabs.count())] and isinstance(tools.openssl, U.OpensslTab))
def pump(w, secs=60):
    end = time.time() + secs
    while time.time() < end:
        if not (w.job and w.job.isRunning()): break
        app.processEvents(); time.sleep(0.02)
    app.processEvents()
tab = tools.openssl
check("five pages", [tab.tabs.tabText(i) for i in range(tab.tabs.count())] == ["Create", "Read", "Convert", "Hash and random", "openssl.exe"])

g = tab.generate
g.cn.setText("web.lab"); g.sans.setText("web.lab, 10.1.1.1"); g.org.setText("Lab"); g.country.setText("us"); g.kind.setCurrentIndex(g.kind.findData("p256")); g.pass_.setText("pp")
g.create(); pump(g)
csr_ui = x509.load_pem_x509_csr(g.cert_out.toPlainText().encode())
check("Create makes a key and a CSR from the form", "ENCRYPTED PRIVATE KEY" in g.key_out.toPlainText() and [a.value for a in csr_ui.subject] == ["web.lab", "Lab", "US"], g.status.text())
check("it is ready for another go, and says Toner keeps nothing", g.go.isEnabled() and "does not keep" in g.status.text())
g.mode.setCurrentIndex(g.mode.findData("self")); g.days.setValue(30)
check("self-signed shows the days and CA options and a Certificate heading", g.days.isEnabled() and g.ca.isEnabled() and "Certificate</b>" in g.cert_label.text() and "request" not in g.cert_label.text())
g.pass_.setText(""); g.create(); pump(g)
check("a self-signed certificate is made", "BEGIN CERTIFICATE" in g.cert_out.toPlainText() and "BEGIN PRIVATE KEY" in g.key_out.toPlainText())
g.mode.setCurrentIndex(g.mode.findData("key"))
check("key only hides the certificate box", not g.cert_out.isVisibleTo(g) and not g.days.isEnabled())
g.create(); pump(g)
check("a private key is made", "BEGIN PRIVATE KEY" in g.key_out.toPlainText() and g.cert_out.toPlainText() == "")
g.mode.setCurrentIndex(g.mode.findData("csr")); g.cn.setText(""); g.sans.setText(""); g.org.setText(""); g.country.setText(""); g.create(); pump(g)
check("a missing name is explained in the status line, not a crash", "common name" in g.status.text() and g.go.isEnabled(), g.status.text())
check("the country box takes two letters at most", (g.country.setText("USA"), g.country.text())[1] == "US"); g.cn.setText("web.lab"); g.org.setText("Lab"); g.copy_key.click()
check("Copy puts the key on the clipboard", "PRIVATE KEY" in QApplication.clipboard().text())
outp = os.path.join(SP, "k.key"); QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (outp, ""))
g.save_key.click(); check("Save writes the key", "PRIVATE KEY" in open(outp).read())

r = tab.inspect_
r.source.setPlainText(pem + key); r.read()
check("Read describes what is pasted and checks the match", "CN=lab.test" in r.out.toPlainText() and "They match" in r.out.toPlainText() and r.status.text() == "")
r.source.setPlainText("rubbish"); r.read()
check("rubbish is explained", "not recognised" in r.status.text() and r.out.toPlainText() == "")
r.source.setPlainText(""); r.read(); check("an empty box is explained", "Paste something" in r.status.text())
pf = os.path.join(SP, "b.pfx"); open(pf, "wb").write(pfx)
r.pass_.setText("export1"); r.load_file(pf)
check("a .pfx file is opened, shown as binary, and read with its password", "[binary file: b.pfx" in r.source.toPlainText() and "PKCS#12" in r.out.toPlainText())
r.source.setPlainText("typed over it"); r.read()
check("typing over a loaded file forgets the file", r.blob is None and "not recognised" in r.status.text())
r.pass_.setText(""); r.load_file(pf)
check("a .pfx without its password asks for it", "password" in r.status.text().lower())
pe = os.path.join(SP, "c.pem"); open(pe, "w").write(pem); r.load_file(pe)
check("a PEM file is shown as text", r.source.toPlainText().startswith("-----BEGIN CERTIFICATE") and "CN=lab.test" in r.out.toPlainText())
r.server.setText(f"127.0.0.1:{port}"); r.fetch.click(); pump(r)
check("Get from server fills the box with the chain and reads it", "2 certificate" in r.status.text() and r.source.toPlainText().count("BEGIN CERTIFICATE") == 2 and "CN=localhost" in r.out.toPlainText(), r.status.text())
r.server.setText(""); r.fetch.click(); check("an empty server box is explained", "Enter the server" in r.status.text())
r.server.setText("127.0.0.1:1"); r.fetch.click(); pump(r)
check("a server that cannot be reached is explained and the button comes back", ("refused" in r.status.text().lower() or "10061" in r.status.text() or "timed out" in r.status.text().lower() or "Error" in r.status.text()) and r.fetch.isEnabled(), r.status.text())

c = tab.convert
c.source.setPlainText(pem); c.action.setCurrentIndex(c.action.findData("der")); c.convert()
check("PEM to DER gives binary you can save", c.result and c.result[0] == der and "binary data" in c.out.toPlainText() and c.save.isEnabled())
dp = os.path.join(SP, "out.der"); QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (dp, "")); c.save_result()
check("saving writes the bytes", open(dp, "rb").read() == der)
c.load_file(dp); c.action.setCurrentIndex(c.action.findData("pem")); c.convert()
check("a DER file opened and converted to PEM", c.out.toPlainText().strip() == pem.strip() and c.blob == der)
c.source.setPlainText(rc + rk); c.action.setCurrentIndex(c.action.findData("pfx")); c.new.setText("pw1"); c.convert()
check("certificate + key make a .pfx", c.result and c.result[1] == "bundle.pfx" and "PKCS#12" in o.inspect(c.result[0], "pw1"))
open(pf, "wb").write(c.result[0]); c.load_file(pf); c.action.setCurrentIndex(c.action.findData("unpfx")); c.old.setText("pw1"); c.new.setText(""); c.convert()
check("and the .pfx opens back to PEM", "BEGIN CERTIFICATE" in c.out.toPlainText() and "BEGIN PRIVATE KEY" in c.out.toPlainText())
c.old.setText("wrong"); c.convert()
check("a wrong password clears the result and says why", "wrong password" in c.status.text() and c.out.toPlainText() == "" and not c.save.isEnabled())
c.source.setPlainText(rk); c.action.setCurrentIndex(c.action.findData("pass")); c.old.setText(""); c.new.setText("zz"); c.convert()
check("a passphrase can be put on a key", "ENCRYPTED PRIVATE KEY" in c.out.toPlainText())

h = tab.hash
h.source.setPlainText("abc"); h.hash()
check("Hash shows the digest", "ba7816bf8f01cfea" in h.out.toPlainText() and h.out.toPlainText().startswith("SHA256"))
h.alg.setCurrentIndex(h.alg.findText("md5")); h.hash()
check("another algorithm", "900150983cd24fb0d6963f7d28e17f72" in h.out.toPlainText())
h.b64e.click(); enc64 = h.out.toPlainText().strip()
check("base64 encode", enc64 == "YWJj")
h.source.setPlainText(enc64); h.b64d.click()
check("base64 decode", h.out.toPlainText().strip() == "abc")
h.source.setPlainText("!!"); h.b64d.click(); check("bad base64 is explained", "not valid base64" in h.status.text())
big = os.path.join(SP, "big.bin"); open(big, "wb").write(b"z" * 5000); h.load_file(big); h.alg.setCurrentIndex(h.alg.findText("sha256")); h.hash()
check("a file is hashed whole", hashlib.sha256(b"z" * 5000).hexdigest() in h.out.toPlainText())
h.count.setValue(8); h.rand.click(); check("random bytes", len(h.out.toPlainText().strip()) == 16)

cm = tab.command
check("the command page says whether an openssl.exe was found", ("Using" in cm.where.text()) == bool(cm.exe) and cm.go.isEnabled() == bool(cm.exe))
if cm.exe:
    def wait_run():
        end = time.time() + 40
        while cm.runner.running() and time.time() < end: app.processEvents(); time.sleep(0.02)
        app.processEvents()
    cm.args.setText("version -a"); cm.run(); wait_run()
    check("it runs the real openssl.exe", "OpenSSL" in cm.out.toPlainText() and "[finished, exit code 0]" in cm.out.toPlainText() and cm.go.isEnabled(), cm.out.toPlainText()[-200:])
    cm.out.clear(); cm.args.setText(f"s_client -connect 127.0.0.1:{port} -servername localhost"); cm.run(); wait_run()
    check("s_client does not hang waiting for input (the program's input is closed)", "[finished" in cm.out.toPlainText() and "CN=localhost" in cm.out.toPlainText().replace("CN = ", "CN=").replace(" ", ""), cm.out.toPlainText()[-300:])
    cm.out.clear(); cm.folder.setText(SP); cm.args.setText('x509 -in "' + pe + '" -noout -subject'); cm.run(); wait_run()
    check("quoted paths work and the folder is used", "lab.test" in cm.out.toPlainText(), cm.out.toPlainText()[-200:])
    cm.out.clear(); cm.folder.setText(os.path.join(SP, "nonexistent")); cm.run()
    check("a missing folder is explained, not run", "does not exist" in cm.out.toPlainText())
    cm.folder.setText(SP); cm.out.clear(); cm.args.setText("   "); cm.run()
    check("empty arguments are explained", "Enter the arguments" in cm.out.toPlainText())
    cm.preset.setCurrentIndex(2)
    check("an example fills in the arguments", cm.args.text() == "s_client -connect example.com:443 -servername example.com -showcerts")
else:
    print("  (no openssl.exe on this computer: the command tests were skipped)")
cm.exe = fake; db.set_setting("openssl_path", fake); cm._show_exe()
check("choosing a file is remembered and used", "Using" in cm.where.text() and o.find_openssl(db.get_setting("openssl_path")) == fake)
check("the setting stays with this computer", "openssl_path" in db.NOT_PORTABLE)
tools.shutdown(); stopper()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
