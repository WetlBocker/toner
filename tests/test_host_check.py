# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# A mistyped IP address is said to be one, and is never sent to DNS.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\hostchk%d.db" % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roaminghost%d" % int(time.time()))
from core import db, importer, nettools
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def says(host):
    try:
        nettools.check_host(host)
        return ""
    except ValueError as e:
        return str(e)

print("== what counts as an address")
for good in ("10.0.0.25", "192.168.1.1", "fe80::1", "2001:db8::1", "core-sw1.corp.example.com", "host1", "sw-10", "localhost", "api.ui.com", "my_host.lan", "1.2.3.4."):
    check(f"{good} is fine", says(good) == "", says(good))
for typo in ("10.0.025", "10.0.0", "10.0.0.256", "10.0.0.025", "192.168.1.1.5", "10", "10..0.1", "1.2.3"):
    m = says(typo)
    check(f"{typo} is said to be a bad IP address, not looked up", "not a valid IP address" in m and typo in m and "10.0.0.25" in m, m)
check("a bad IPv6 address is said to be one", "not a valid IPv6" in says("fe80::1::2") or "Host must be" in says("fe80::1::2"), says("fe80::1::2"))
check("other nonsense gets the general message", "Host must be" in says("http://10.0.0.1") and "Host must be" in says("core sw") and "Host must be" in says(""))

print("== nothing is sent to DNS for them")
lookups = []
real = nettools.socket.getaddrinfo
nettools.socket.getaddrinfo = lambda *a, **k: (lookups.append(a[0]), real(*a, **k))[1]
for typo in ("10.0.025", "10.0.0.256"):
    try:
        nettools.resolve_host(nettools.check_host(typo))
    except ValueError:
        pass
check("a mistyped address is stopped before a lookup is tried", lookups == [], lookups)
try:
    importer.normalize({"name": "x", "vendor": "cisco", "host": "10.0.025"}); check("an import row with one is refused with that reason", False)
except ValueError as e:
    check("an import row with one is refused with that reason", "not a valid IP address" in str(e), e)

print("== the Add device dialog")
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
import ui.inventory as I
warned, ran = [], []
QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2]))
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
I.run_one = lambda *a, **k: (ran.append(a), [])[1]
dlg = I.DeviceDialog()
dlg.name.setText("PaloVM"); dlg.host.setText("10.0.025")
check("leaving the field with a bad address marks it and says why", dlg._mark_host() != "" and __import__("ui.status", fromlist=["x"]).ink("FAIL") in dlg.host.styleSheet() and "not a valid IP address" in dlg.host.toolTip())
dlg.host.textEdited.emit("10.0.02")
check("typing again clears the mark until it is left", dlg.host.styleSheet() == "" and dlg.host.toolTip() == "")
dlg.host.setText("10.0.0.25")
check("a good address has no mark", dlg._mark_host() == "" and dlg.host.styleSheet() == "")
dlg.host.setText("10.0.025")
dlg.test()
check("Test says the address is invalid and does not try to connect or resolve", warned and warned[-1].startswith("'10.0.025' is not a valid IP address") and not ran and lookups == [], (warned, ran, lookups))
warned.clear(); dlg.accept()
check("Save refuses it the same way", warned and "not a valid IP address" in warned[-1] and dlg.result() == 0)
dlg.host.setText("")
warned.clear(); dlg.test()
check("an empty address is refused by Test too", warned and "Host must be" in warned[-1] and not ran)
dlg.host.setText("10.0.0.25"); warned.clear(); dlg.test()
check("a good one goes ahead and is tested", ran and not [w for w in warned if "Invalid" in w])
nettools.socket.getaddrinfo = real

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
