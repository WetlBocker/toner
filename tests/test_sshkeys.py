# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Tools > Crypto > SSH Keys: key pairs in OpenSSH's format and PuTTY's, reading keys and changing their passphrase, and putting a
# public key on a device.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import base64, hashlib, hmac, os, shutil, subprocess, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "sshkeys%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingsshkeys%d" % int(time.time()))
from core import db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from core import sshkeys as K
DIR = os.path.join(SP, "keys%d" % int(time.time())); os.makedirs(DIR)

print("== making keys")
made = {}
for kind, bits in [("ed25519", None), ("rsa", 2048), ("ecdsa", 256), ("ecdsa", 384), ("ecdsa", 521)]:
    k = K.generate(kind, bits)
    made[(kind, bits)] = k
    check(f"{kind} {bits or ''}: the right kind and size", K.kind_of(k) == (kind, bits or 256), K.kind_of(k))
k = made[("ed25519", None)]
line = K.public_line(k, "tech@desk 1")
check("the public key line is 'type base64 comment'", line.startswith("ssh-ed25519 AAAA") and line.endswith(" tech@desk 1"))
check("and loads as an SSH public key", serialization.load_ssh_public_key(" ".join(line.split()[:2]).encode()) is not None)
check("a comment's own spacing and line breaks are flattened", K.public_line(k, " a\n b ").endswith(" a b"))
check("no comment, no trailing space", not K.public_line(k).endswith(" "))
fp = K.fingerprint(k)
check("the fingerprint is SHA256 of the public key, unpadded base64", fp == "SHA256:" + base64.b64encode(hashlib.sha256(K.public_blob(k)).digest()).decode().rstrip("=") and "=" not in fp)
check("RSA defaults to 3072 bits, ECDSA to 256", K.kind_of(K.generate("rsa"))[1] == 3072 and K.kind_of(K.generate("ecdsa"))[1] == 256)
check("the default comment is user@computer", "@" in K.default_comment())

print("== OpenSSH's private key format")
for (kind, bits), key in made.items():
    for pp in ("", "correct horse"):
        text = K.openssh_private(key, "tech@desk 1", pp)
        info = K.read(text, pp)
        check(f"{kind} {bits or ''}{' locked' if pp else ''}: reads back as the same key, with its comment",
              K.public_line(info["key"], info["comment"]) == K.public_line(key, "tech@desk 1") and info["encrypted"] == bool(pp) and info["form"] == "OpenSSH private key")
text = K.openssh_private(k, "c", "pass phrase")
check("the cryptography library reads it too", serialization.load_ssh_private_key(text.encode(), b"pass phrase").public_key().public_bytes(
      serialization.Encoding.Raw, serialization.PublicFormat.Raw) == k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
try: K.read(text); r = None
except K.NeedsPassphrase as e: r = str(e)
check("a locked key without its passphrase asks for it", r and "passphrase" in r, r)
try: K.read(text, "wrong"); r = None
except K.WrongPassphrase as e: r = str(e)
check("a wrong passphrase is said plainly", r == "That passphrase isn't right for this key.", r)
check("lines are 70 characters, as ssh-keygen writes them", max(len(x) for x in text.splitlines()[1:-1]) == 70)

pem = made[("rsa", 2048)].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"pw"))
info = K.read(pem.decode(), "pw")
check("an older PEM key (PKCS#8, locked) reads too", info["form"] == "PEM private key" and info["encrypted"] and info["bits"] == 2048)
info = K.read(line)
check("a public key line reads, with its comment", info["key"] is None and info["comment"] == "tech@desk 1" and info["form"] == "Public key")
blob = base64.b64encode(K.public_blob(k)).decode()
rfc = "---- BEGIN SSH2 PUBLIC KEY ----\nComment: \"from puttygen\"\n" + "\n".join(blob[i:i + 64] for i in range(0, len(blob), 64)) + "\n---- END SSH2 PUBLIC KEY ----"
info = K.read(rfc)
check("and the SSH2 public key format (PuTTYgen's export)", K.fingerprint(info["public"]) == fp and info["comment"] == "from puttygen")
for junk in ("", "hello", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"):
    try: K.read(junk); r = None
    except ValueError as e: r = str(e)
    check(f"not a key ({junk[:12]!r}) is refused with a reason", bool(r), r)

print("== PuTTY's .ppk")
def ppk_check(text, passphrase):
    """Read a .ppk as PuTTY does: the MAC must match and the private part must decrypt."""
    lines = text.splitlines(); f = {}
    i = 0; pub = priv = b""
    while i < len(lines):
        name, _, value = lines[i].partition(": ")
        if name == "Public-Lines": n = int(value); pub = base64.b64decode("".join(lines[i + 1:i + 1 + n])); i += n
        elif name == "Private-Lines": n = int(value); priv = base64.b64decode("".join(lines[i + 1:i + 1 + n])); i += n
        else: f[name] = value
        i += 1
    if f["Encryption"] == "aes256-cbc":
        p = passphrase.encode(); key = (hashlib.sha1(b"\0\0\0\0" + p).digest() + hashlib.sha1(b"\0\0\0\1" + p).digest())[:32]
        d = Cipher(algorithms.AES(key), modes.CBC(b"\0" * 16)).decryptor(); priv = d.update(priv) + d.finalize()
    s = lambda b: len(b).to_bytes(4, "big") + b
    data = s(f["PuTTY-User-Key-File-2"].encode()) + s(f["Encryption"].encode()) + s(f["Comment"].encode()) + s(pub) + s(priv)
    mac = hmac.new(hashlib.sha1(b"putty-private-key-file-mac-key" + passphrase.encode()).digest(), data, hashlib.sha1).hexdigest()
    return mac == f["Private-MAC"], f, pub
for (kind, bits), key in made.items():
    for pp in ("", "pw"):
        text = K.ppk(key, "tech@desk 1", pp)
        good, f, pub = ppk_check(text, pp)
        check(f"{kind} {bits or ''}{' locked' if pp else ''}: a valid .ppk (its MAC checks out)", good and pub == K.public_blob(key) and f["Comment"] == "tech@desk 1"
              and f["Encryption"] == ("aes256-cbc" if pp else "none"))
good, _f, _p = ppk_check(K.ppk(k, "c", "pw"), "not it")
check("with the wrong passphrase the MAC does not match (PuTTY would refuse it)", not good)
info = K.read(K.ppk(k, "putty comment", "pw"))
check("a .ppk reads (its public half), locked or not", info["form"] == "PuTTY private key" and info["encrypted"] and info["comment"] == "putty comment" and K.fingerprint(info["public"]) == fp)

print("== files")
p = os.path.join(DIR, "id_test")
K.write_private(p, K.openssh_private(k, "c"))
K.write_public(p + ".pub", line)
check("the public file is the line and a newline", open(p + ".pub").read() == line + "\n")
if os.name != "nt":
    check("the private file is readable only by its owner", oct(os.stat(p).st_mode & 0o777) == "0o600", oct(os.stat(p).st_mode))
os.chmod(p, 0o644); K.write_private(p, K.openssh_private(k, "c"))
if os.name != "nt":
    check("rewriting one that others could read makes it private again", oct(os.stat(p).st_mode & 0o777) == "0o600")

keygen = shutil.which("ssh-keygen")
if keygen:
    print("== against OpenSSH's ssh-keygen", keygen)
    for (kind, bits), key in made.items():
        q = os.path.join(DIR, f"x_{kind}{bits}")
        K.write_private(q, K.openssh_private(key, "tech@desk 1", "pw"))
        r = subprocess.run([keygen, "-y", "-P", "pw", "-f", q], capture_output=True, text=True, timeout=30)
        check(f"ssh-keygen opens our {kind} {bits or ''} key and finds the same public key and comment",
              r.stdout.strip() in (K.public_line(key, "tech@desk 1"), K.public_line(key)), (r.stdout, r.stderr))
    q = os.path.join(DIR, "made_by_keygen")
    subprocess.run([keygen, "-q", "-t", "ed25519", "-C", "from ssh-keygen", "-N", "pw", "-f", q], capture_output=True, timeout=30)
    if os.path.exists(q):
        info = K.read(open(q).read(), "pw")
        check("and we read ssh-keygen's, comment included", info["comment"] == "from ssh-keygen"
              and K.public_line(info["key"], info["comment"]) == open(q + ".pub").read().strip())

print("== onto a device")
cmd = K.authorized_keys_command(K.public_line(k, "it's me"))
check("the command quotes the key safely (a quote in the comment)", "'\\''" in cmd and K.ADDED in cmd and K.PRESENT in cmd)
for junk in ("", "ssh-ed25519", "ssh-ed25519 notbase64 x", "rm -rf ~"):
    try: K.authorized_keys_command(junk); r = None
    except Exception as e: r = e
    check(f"anything but a key is refused ({junk!r})", r is not None)
if os.name != "nt" and shutil.which("sh"):
    home = os.path.join(DIR, "home"); os.makedirs(home)
    env = dict(os.environ, HOME=home)
    run = lambda l: subprocess.run(["sh", "-c", K.authorized_keys_command(l)], env=env, capture_output=True, text=True).stdout
    ak = os.path.join(home, ".ssh", "authorized_keys")
    check("a new key is added, folder and file made private", K.ADDED in run(K.public_line(k, "it's me")) and oct(os.stat(ak).st_mode & 0o777) == "0o600"
          and oct(os.stat(os.path.dirname(ak)).st_mode & 0o777) == "0o700")
    check("the same key again (another comment) is left alone", K.PRESENT in run(K.public_line(k, "other")) and open(ak).read().count("\n") == 1)
    open(ak, "a").write("ssh-rsa AAAAold without-newline")
    k2 = K.generate("ecdsa", 256)
    check("a file without a final newline gets one before the new key", K.ADDED in run(K.public_line(k2, "two")) and open(ak).read().splitlines()[-1] == K.public_line(k2, "two")
          and open(ak).read().splitlines()[-2] == "ssh-rsa AAAAold without-newline")

class FakeChan:
    def __init__(self, out=b"", err=b""): self.out, self.err, self.cmd = out, err, None
    def settimeout(self, t): pass
    def exec_command(self, c): self.cmd = c
    def recv_ready(self): return bool(self.out)
    def recv(self, n): b, self.out = self.out[:n], self.out[n:]; return b
    def recv_stderr_ready(self): return bool(self.err)
    def recv_stderr(self, n): b, self.err = self.err[:n], self.err[n:]; return b
    def exit_status_ready(self): return True
    def close(self): pass
class FakeClient:
    def __init__(self, chan): self.chan = chan; self.closed = False
    def get_transport(self): return self
    def open_session(self, timeout=None): return self.chan
    def close(self): self.closed = True
check("over a connection: 'added'", K.add_to_device(FakeClient(FakeChan(K.ADDED.encode() + b"\n")), line) == "added")
check("or 'present'", K.add_to_device(FakeClient(FakeChan(K.PRESENT.encode() + b"\n")), line) == "present")
try: K.add_to_device(FakeClient(FakeChan(err=b"% Invalid input detected at '^' marker.")), line); r = None
except ValueError as e: r = str(e)
check("a device without a shell: what it said", r and "Invalid input" in r, r)

print("== the page")
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
from ui.tools import ToolsTab
from ui import sshkeysui as U
tools = ToolsTab()
names = [tools.tabs.list.item(i).text() for i in range(tools.tabs.list.count())]
check("Tools has a CRYPTO group (not Certificates) with TLS Certificates, OpenSSL and SSH Keys",
      "CRYPTO" in names and "CERTIFICATES" not in names and names[names.index("CRYPTO") + 1:names.index("CRYPTO") + 4] == ["TLS Certificates", "OpenSSL", "SSH Keys"], names)
page = tools.sshkeys
check("three tabs", [page.tabs.tabText(i) for i in range(page.tabs.count())] == ["Make a key pair", "Read a key", "Put on a device"])
def pump(w, secs=60):
    end = time.time() + secs
    while time.time() < end and w.job and w.job.isRunning():
        app.processEvents(); time.sleep(0.02)
    app.processEvents(); app.processEvents()

g = page.generate
check("Ed25519 is first, and has no size to choose", g.kind.currentData() == "ed25519" and g.size.isHidden())
g.kind.setCurrentIndex(g.kind.findData("rsa"))
check("RSA offers 2048, 3072 and 4096, 3072 chosen", [g.size.itemData(i) for i in range(g.size.count())] == [2048, 3072, 4096] and g.size.currentData() == 3072 and not g.size.isHidden())
g.kind.setCurrentIndex(g.kind.findData("ecdsa"))
check("ECDSA offers 256, 384 and 521", [g.size.itemData(i) for i in range(g.size.count())] == [256, 384, 521])
g.kind.setCurrentIndex(g.kind.findData("ed25519"))
check("nothing to copy or save before a key is made", not g.copy_pub.isEnabled() and not g.save_pair.isEnabled())
g.pass1.setText("one"); g.pass2.setText("two"); g.go.click(); app.processEvents()
check("passphrases that differ are refused", g.status.text() == "The passphrases don't match." and g.public.text() == "")
g.pass2.setText("one"); g.comment.setText("tech@desk"); g.go.click(); pump(g)
check("Generate key pair shows the public key, fingerprint and private key", g.public.text().startswith("ssh-ed25519 ") and g.public.text().endswith(" tech@desk")
      and g.fp.text().startswith("SHA256:") and "BEGIN OPENSSH PRIVATE KEY" in g.private.toPlainText(), g.status.text())
check("the status says what was made", g.status.text() == "Made an Ed25519 key (256 bits), locked with the passphrase.", g.status.text())
check("the private key is locked with the passphrase", K.read(g.private.toPlainText(), "one")["encrypted"])
check("and 'Put on a device' is offered the new public key", page.deploy.key.text() == g.public.text())
g.copy_pub.click(); check("Copy public key", QApplication.clipboard().text() == g.public.text())
target = os.path.join(DIR, "saved_ed25519")
QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (target, ""))
g.save_pair.click()
check("Save key pair writes the private key and the .pub beside it", K.read(open(target).read(), "one")["comment"] == "tech@desk" and open(target + ".pub").read().strip() == g.public.text())
check("and says where", g.status.text() == f"Saved saved_ed25519 and saved_ed25519.pub to {DIR}.", g.status.text())
QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (target + ".ppk", ""))
g.save_ppk.click()
good, f, _p = ppk_check(open(target + ".ppk").read(), "one")
check("Save for PuTTY writes a .ppk with the same passphrase and comment", good and f["Comment"] == "tech@desk")
QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: ("", ""))
before = g.status.text(); g.save_pair.click()
check("cancelling a save changes nothing", g.status.text() == before)

r = page.reader
check("nothing to act on before a key is read", not r.copy_pub.isEnabled() and not r.change.isEnabled())
QFileDialog.getOpenFileName = staticmethod(lambda *a, **k: (target, ""))
r.open_btn.click()
check("opening a locked key asks for its passphrase", "passphrase" in r.status.text() and r.kind.text() == "", r.status.text())
r.passphrase.setText("one"); r.go.click()
check("with it, the key is described", r.kind.text().startswith("Ed25519") and "locked" in r.kind.text() and r.size.text() == "256 bits"
      and r.comment.text() == "tech@desk" and r.public.text() == g.public.text() and r.fp.text() == g.fp.text(), (r.kind.text(), r.status.text()))
check("its file is named", r.status.text() == "Read saved_ed25519.", r.status.text())
check("change, remove and PuTTY are offered for a private key", r.change.isEnabled() and r.remove.isEnabled() and r.save_ppk.isEnabled())
U.NewPassphrase.exec = lambda self: (self.first.setText("two two"), self.second.setText("two two"), self.accept(), True)[-1]
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
r.change.click()
info = K.read(open(target).read(), "two two")
check("Change passphrase saves the file with the new one, comment kept", info["comment"] == "tech@desk" and K.fingerprint(info["public"]) == g.fp.text())
check("and says so", r.status.text() == "Saved saved_ed25519 with its new passphrase.", r.status.text())
r.remove.click()
info = K.read(open(target).read())
check("Remove passphrase leaves the key unlocked", not info["encrypted"] and info["comment"] == "tech@desk" and r.status.text() == "Removed the passphrase from saved_ed25519.", r.status.text())
check("and Remove is greyed out once there is none", not r.remove.isEnabled())
dlg = U.NewPassphrase(); dlg.first.setText("a"); dlg.second.setText("b"); U.QDialog.accept(dlg) if False else None
U.NewPassphrase.accept(dlg)
check("the new passphrase must be typed the same twice", not dlg.error.isHidden() and dlg.error.text() == "The passphrases don't match." and dlg.result() == 0)
r.text.setPlainText(g.public.text()); r.passphrase.setText(""); r.go.click()
check("a public key: only Copy is offered", r.copy_pub.isEnabled() and not r.change.isEnabled() and not r.save_ppk.isEnabled() and r.status.text() == "")
r.text.setPlainText("not a key"); r.go.click()
check("not a key: the reason, nothing described", "isn't an SSH key" in r.status.text() and r.kind.text() == "")

d = page.deploy
import ui.sshkeysui as SU
sent = []
def fake_connect(host, port, user, password, dev=None, hostkey_mode=None, timeout=15):
    sent.append((host, port, user, password))
    chan = FakeChan((K.PRESENT if len(sent) > 1 else K.ADDED).encode() + b"\n")
    return FakeClient(chan), []
SU.scp.connect = fake_connect
def wait():
    end = time.time() + 20
    while time.time() < end and d.running(): app.processEvents(); time.sleep(0.02)
    app.processEvents(); app.processEvents()
d.key.setText(g.public.text()); d.host.setText("10.0.0.9"); d.user.setText("admin"); d.password.setText("pw")
d.go.click(); wait()
out = d.out.toPlainText()
check("Add to device connects with what was entered", sent and sent[0] == ("10.0.0.9", 22, "admin", "pw"), sent)
check("and says it was added", "Added the key to 10.0.0.9's ~/.ssh/authorized_keys." in out, out)
d.go.click(); wait()
check("a second time: already there, nothing changed", "10.0.0.9 already has this key; nothing changed." in d.out.toPlainText())
import paramiko
def refuse(*a, **k): raise paramiko.AuthenticationException("no")
SU.scp.connect = refuse
d.go.click(); wait()
check("a refused login is said plainly", "Login failed: the device did not accept the user name and password." in d.out.toPlainText())
d.key.setText("not a key"); n = len(sent); d.go.click(); wait()
check("a bad key is refused before connecting", "Error:" in d.out.toPlainText().splitlines()[-1] and len(sent) == n)
d.key.setText(""); d.offer("ssh-ed25519 AAAA offered")
check("a key made or read is offered when the box is empty", d.key.text() == "ssh-ed25519 AAAA offered")
d.offer("ssh-ed25519 BBBB other")
check("but never replaces one already there", d.key.text() == "ssh-ed25519 AAAA offered")
tools.shutdown()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
