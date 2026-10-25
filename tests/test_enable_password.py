# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# A Cisco device's enable password: on the device or its credential profile, used by every connection, shown in both dialogs.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "enable%d.db" % int(time.time())); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import db, profiles
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)


def dev(name, platform="cisco_asa", **kw):
    return dict(name=name, vendor="cisco", host="10.0.0.2", port=0, platform=platform, username="admin", site="default", verify_ssl=0,
                ha_expected=0, enabled=1, location="", details="", folder_id=None, **kw)


print("== where the enable password comes from")
check("'enable' is a secret kind, so renaming and deleting a device carry it along", db.secret_name("asa1", "enable") == "asa1:enable")
pid = profiles.save({"name": "cisco-admins", "username": "admin", "org": 0, "shared": 0, "notes": "", "snmp": ""}, {"main": "Login-pw", "enable": "Prof-en"})
db.save_device(dev("asa1", profile_id=pid))
asa1 = next(d for d in db.list_devices() if d["name"] == "asa1")
check("a device with a profile gets the profile's enable password", profiles.secret(asa1, "enable") == "Prof-en")
check("...and still the profile's login password", profiles.secret(asa1, "main") == "Login-pw")
db.set_secret(db.secret_name("asa1", "enable"), "Own-en")
check("its own enable password wins over the profile's", profiles.secret(asa1, "enable") == "Own-en")
db.save_device(dev("asa2", profile_id=pid))
db.set_secret(db.secret_name("asa2"), "Own-login")
asa2 = next(d for d in db.list_devices() if d["name"] == "asa2")
check("a device with its own login and no enable password of its own still uses the profile's", profiles.secret(asa2, "enable") == "Prof-en")
db.move_device_secrets("asa1", "asa1-renamed")
check("renaming a device moves it", keyring.get_password(db.SERVICE, "asa1-renamed:enable") == "Own-en" and not keyring.get_password(db.SERVICE, "asa1:enable"))
db.move_device_secrets("asa1-renamed", "asa1")

print("== what the connections hand netmiko")
from drivers.cisco import CiscoDriver
from drivers.sshbase import SshDriver
check("the Cisco driver's enable secret is the enable password", CiscoDriver(asa1, {}, {}).enable_secret == "Own-en")
db.save_device(dev("asa3"))
db.set_secret(db.secret_name("asa3"), "Only-login")
asa3 = next(d for d in db.list_devices() if d["name"] == "asa3")
check("with no enable password anywhere, the login password is tried, as before", CiscoDriver(asa3, {}, {}).enable_secret == "Only-login")
import inspect
check("both SSH connect paths pass it (netmiko's 'secret')", "secret=self.enable_secret" in inspect.getsource(CiscoDriver.connect)
      and "secret=self.enable_secret" in inspect.getsource(SshDriver.connect))

print("== the device dialog")
from PySide6.QtWidgets import QApplication
app = QApplication.instance() or QApplication([])
import app as A
A.apply_look(app)
import ui.inventory as I
dlg = I.DeviceDialog(asa1); dlg.show(); dlg.tabs.setCurrentWidget(dlg.page_access); app.processEvents()
check("a Cisco device has an Enable password row, under Password", dlg.access.isRowVisible(dlg.enable_pw)
      and dlg.access.labelForField(dlg.enable_pw).text() == "Enable password")
check("...with the approved tooltip", dlg.enable_pw.toolTip() == "Cisco devices: the password for enable mode, when it differs from the login password.")
check("...and a stored one shows as saved, never its value", dlg.enable_pw.text() == "" and dlg.enable_pw.placeholderText() == "saved; leave blank to keep")
check("nothing typed: no secret is written and the stored one is kept", "enable" not in dlg.ssh_secrets())
dlg.enable_pw.setText("Typed-en")
check("a typed enable password is saved as its own secret, outside the device record", dlg.ssh_secrets() == {"enable": "Typed-en"} and "Typed-en" not in str(dlg.values()))
check("closing would ask about the change", dlg._snapshot() != dlg._start)
dlg.done(0)                                                # not close(): that would ask about the change
api = I.DeviceDialog(); api.vendor.setCurrentIndex(api.vendor.findData("paloalto")); api.show(); api.tabs.setCurrentWidget(api.page_access); app.processEvents()
check("a device reached by API has no enable row", not api.access.isRowVisible(api.enable_pw))
api.done(0)

print("== the credential profile dialog")
from ui.settings_pages.profiles import ProfileDialog
pd = ProfileDialog(); pd.show(); app.processEvents()
pd.name.setText("edge"); pd.username.setText("admin"); pd.secret.setText("L"); pd.enable_pw.setText("E")
prof, secrets = pd.values()
check("a new profile saves its enable password as a secret of its own", secrets["enable"] == "E" and secrets["main"] == "L" and "E" not in str(prof))
pd.done(0)
existing = profiles.of(asa1)
pd2 = ProfileDialog(existing); pd2.show(); app.processEvents()
check("editing a profile with one stored shows it as saved, never its value", pd2.enable_pw.text() == "" and pd2.enable_pw.placeholderText() == "leave blank to keep the stored value")
prof2, secrets2 = pd2.values()
check("...and leaving it blank keeps it", secrets2["enable"] == "" and profiles.secret(asa2, "enable") == "Prof-en")
pd2.done(0)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
