# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\vault%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import db, notify, profiles, sessions, vault
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def raises(fn, text):
    try: fn(); return False
    except ValueError as e: return text.lower() in str(e).lower()

print("== what is in the file")
db.save_device(dict(name="core1", vendor="cisco", host="10.0.0.1", port=0, platform="cisco_ios", username="a", site="d", verify_ssl=0, ha_expected=0, enabled=1))
db.save_device(dict(name="snmp1", vendor="snmp", host="10.0.0.2", port=0, platform="", username="", site="d", verify_ssl=0, ha_expected=0, enabled=1))
db.set_secret("core1", "pw-core"); db.set_secret(db.secret_name("core1", "proxy"), "pw-proxy"); db.set_secret(db.secret_name("snmp1", "snmp"), "public-community")
profiles.save({"name": "lab", "username": "u", "snmp": "", "notes": ""}, {"main": "pw-profile"})
sid = sessions.save({"name": "rack", "kind": "ssh", "host": "10.0.0.3", "port": 22, "username": "u", "options": {}}); sessions.set_password(sid, "pw-session")
ch = notify.new_channel("slack"); notify.save_channels([ch]); notify.set_secrets(ch, {"url": "https://hooks.example/secret"})
db.set_secret("service:proxy", "pw-global-proxy"); db.set_secret("service:sftp-server", "pw-sftp"); db.set_secret("service:agent-enroll", "enroll-key")
db.set_secret("unrelated-thing", "not-toner's")
got = vault.collect()
check("device, SNMP, per-device proxy, profile, session, notification and service passwords are found", got.get("core1") == "pw-core" and got.get(db.secret_name("core1", "proxy")) == "pw-proxy"
      and got.get(db.secret_name("snmp1", "snmp")) == "public-community" and got.get(db.secret_name("profile:lab", "main")) == "pw-profile"
      and "pw-session" in got.values() and "https://hooks.example/secret" in got.values() and got["service:proxy"] == "pw-global-proxy" and got["service:sftp-server"] == "pw-sftp"
      and got["service:agent-enroll"] == "enroll-key", sorted(got))
check("things that are not Toner's are not touched", "unrelated-thing" not in got)
check("names with nothing stored are left out", all(v for v in got.values()) and db.secret_name("core1", "snmp") not in got)

print("== the file")
data, n = vault.export_bytes("a long enough password")
check("it is made with a password, and says how many it holds", n == len(got) and data.startswith(vault.MAGIC))
check("none of the passwords can be read in it", not any(v.encode() in data for v in got.values()) and b"core1" not in data)
check("two exports of the same thing differ (new salt and nonce each time)", vault.export_bytes("a long enough password")[0] != data)
check("the right password opens it", vault.read_bytes(data, "a long enough password") == got)
check("a wrong one does not, and says why", raises(lambda: vault.read_bytes(data, "a wrong password!!"), "wrong password"))
check("neither does an empty one", raises(lambda: vault.read_bytes(data, ""), "wrong password"))
bent = bytearray(data); bent[-5] ^= 1
check("a changed file is refused (it is authenticated, not just encrypted)", raises(lambda: vault.read_bytes(bytes(bent), "a long enough password"), "damaged"))
check("something else entirely is not a password file", raises(lambda: vault.read_bytes(b"hello", "x"), "not a toner password file") and raises(lambda: vault.read_bytes(b"", "x"), "not a toner password file"))
check("a short password is refused", raises(lambda: vault.export_bytes("short"), "at least 8"))
check("an empty vault works", vault.read_bytes(vault.export_bytes("a long enough password", {})[0], "a long enough password") == {})

print("== on another computer")
STORE.clear()
check("restoring puts every password back", vault.import_bytes(data, "a long enough password") == (len(got), 0) and vault.collect() == got)
STORE["netcheck", "core1"] = "changed here"; STORE.pop(("netcheck", "service:proxy"))
check("with 'replace' off a password already on this computer is kept, and a missing one is added", vault.import_bytes(data, "a long enough password", replace=False) == (1, len(got) - 1)
      and STORE["netcheck", "core1"] == "changed here" and STORE["netcheck", "service:proxy"] == "pw-global-proxy")
check("with it on, the file wins", vault.import_bytes(data, "a long enough password", replace=True)[1] == 0 and STORE["netcheck", "core1"] == "pw-core")
check("a wrong password stores nothing", (STORE.clear(), raises(lambda: vault.import_bytes(data, "nope nope nope"), "wrong password"), not STORE)[2])

print("== the Settings buttons")
from PySide6.QtWidgets import QApplication, QFileDialog, QInputDialog, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
import ui.settings as S
infos, warns = [], []
QMessageBox.information = staticmethod(lambda *a, **k: infos.append(a[2])); QMessageBox.warning = staticmethod(lambda *a, **k: warns.append(a[2]))
answers = []
QInputDialog.getText = staticmethod(lambda *a, **k: (answers.pop(0), True) if answers and answers[0] is not None else ("", False))
for name, v in got.items(): STORE["netcheck", name] = v
page = S.DataPage(lambda: None)
check("Data and logs has Export and Import saved passwords", {b.text() for b in page.findChildren(S.QPushButton)} >= {"Export saved passwords...", "Import saved passwords..."})
out = os.path.join(SP, "pw" + vault.EXTENSION); QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (out, ""))
answers[:] = ["a long enough password", "different password!"]; page.export_passwords()
check("two passwords that differ export nothing", warns and "not the same" in warns[-1] and not os.path.exists(out))
answers[:] = ["short", "short"]; page.export_passwords()
check("a short one is explained", "at least 8" in warns[-1] and not os.path.exists(out))
answers[:] = [None]; page.export_passwords(); check("cancelling exports nothing", not os.path.exists(out))
answers[:] = ["a long enough password", "a long enough password"]; page.export_passwords()
check("a good export writes the file and says how many", os.path.exists(out) and f"{len(got)} password(s)" in infos[-1] and vault.read_bytes(open(out, "rb").read(), "a long enough password") == got)
STORE.clear(); QFileDialog.getOpenFileName = staticmethod(lambda *a, **k: (out, ""))
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
answers[:] = ["wrong wrong wrong"]; page.import_passwords()
check("a wrong password is explained and nothing is stored", "wrong password" in warns[-1] and not STORE)
answers[:] = ["a long enough password"]; page.import_passwords()
check("the right one restores them", vault.collect() == got and f"{len(got)} password(s) stored" in __import__("ui.toast", fromlist=["x"]).history[-1])

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
