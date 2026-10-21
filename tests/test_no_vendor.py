# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Devices with no vendor yet (imported from a session file): the checks, backups and commands skip them; the inventory says how
# many and filters them; Bulk edit sets a vendor; More > Detect vendors works out what they are, from the inventory.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "nv%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import bulk, db, orgs, service
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def dev(name, vendor="cisco", **kw):
    return dict(dict(name=name, vendor=vendor, host="10.0.0.1", port=0, platform="cisco_ios" if vendor == "cisco" else "", username="admin",
                     site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None), **kw)

print("== the checks skip them")
db.save_device(dev("sw1"))
db.save_device(dev("unknown-1", vendor="", host="10.0.0.2"))
db.save_device(dev("unknown-2", vendor="", host="10.0.0.3", enabled=0))
check("the inventory still lists them", sorted(d["name"] for d in db.list_devices()) == ["sw1", "unknown-1", "unknown-2"])
check("what can be checked leaves them out", [d["name"] for d in db.list_devices(enabled_only=True)] == ["sw1"])
check("so a scheduled run of only such devices does nothing", service.own_devices() == [d for d in db.list_devices(enabled_only=True)]
      and all(d["vendor"] for d in service.own_devices()))

print("== the inventory")
from PySide6.QtWidgets import QApplication, QComboBox
app = QApplication([])
import app as A
A.apply_look(app)
from ui import finder, inventory as INV, vendorassign as VA
sections = {s.key: s for s in finder.device_sections(db.list_devices())}
check("the Vendor filter offers (no vendor), standing for an empty vendor", ("(no vendor)", "") in sections["vendor"].options
      and ("Cisco", "cisco") in sections["vendor"].options, sections["vendor"].options)
w = A.Main(); inv = w.inventory; w.resize(1200, 800); w.show(); app.processEvents()
check("a note says how many the checks skip, in the agreed words", not inv.no_vendor.isHidden() and inv.no_vendor.text()
      == "2 devices have no vendor yet, so the checks skip them. Choose a vendor to start checking them: Bulk edit, or More > Detect vendors.",
      inv.no_vendor.text())
dlg = INV.BulkEditDialog(2)
check("Bulk edit has a Vendor row whose first choice leaves it as it is", "vendor" in dlg.rows and dlg.rows["vendor"][0].text() == "Vendor"
      and dlg.vendor_box.itemText(0) == "(leave as is)" and dlg.vendor_box.itemData(0) is None and dlg.vendor_box.findData("juniper") > 0)
unknowns = [d for d in db.list_devices() if not d["vendor"]]
n = bulk.apply(unknowns, {"vendor": "juniper"})
after = {d["name"]: (d["vendor"], d["platform"]) for d in db.list_devices()}
check("applying a vendor sets it, with its usual platform", n == 2 and after["unknown-1"] == ("juniper", "juniper_junos") and after["unknown-2"] == ("juniper", "juniper_junos"))
check("(leave as is) changes nothing", bulk.apply(db.list_devices(), {"vendor": None}) == 0 and after["sw1"] == ("cisco", "cisco_ios"))
bulk.apply(unknowns, {"vendor": None}); db.save_device({**db.get_device(unknowns[0]["id"]), "vendor": "", "platform": ""})
inv.refresh(); app.processEvents()
check("the note follows the count", inv.no_vendor.text().startswith("1 devices have no vendor yet"), inv.no_vendor.text())
db.save_device({**db.get_device(unknowns[0]["id"]), "vendor": "arista", "platform": "arista_eos"})
inv.refresh(); app.processEvents()
check("and goes away when every device has one", inv.no_vendor.isHidden())

print("== More > Detect vendors for selected")
db.save_device({**db.get_device(unknowns[0]["id"]), "vendor": "", "platform": ""})
db.set_secret(db.secret_name("unknown-1"), "Secr3t!")
w2 = VA.VendorAssignDialog([{"kind": "ssh", "name": "a", "host": "10.0.0.2", "port": 22, "username": "admin", "org": 0, "folder": [], "vendor": "", "platform": ""},
                            {"kind": "ssh", "name": "b", "host": "10.0.0.3", "port": 22, "username": "admin", "org": 0, "folder": [], "vendor": "cisco", "platform": "cisco_xe"}],
                           {}, inventory=True, detect=lambda e, p, on_done=None, cancel=None: [on_done(k, "mikrotik", "mikrotik_routeros") for k in sorted(e)])
buttons = [b.text() for b in w2.findChildren(VA.QPushButton)]
check("from the inventory the buttons are Apply and Cancel", "Apply" in buttons and "Cancel" in buttons and "Add devices" not in buttons and "Sessions only" not in buttons, buttons)
note = next(l.text() for l in w2.findChildren(VA.QLabel) if l.text().startswith("Pick rows"))
check("the note leaves out the import's sentences", "still added" not in note and "Remote Desktop" not in note and "Detect Vendors checks" in note, note)
check("each row starts from the device's own vendor", w2.vendors() == [("", ""), ("cisco", "cisco_xe")])
w2.start_detect()
deadline = time.time() + 5
while not w2.progress.text().startswith("Detected") and time.time() < deadline:
    app.processEvents(); time.sleep(0.01)
check("Detect Vendors fills only the empty ones", w2.vendors() == [("mikrotik", "mikrotik_routeros"), ("cisco", "cisco_xe")], w2.vendors())
seen = {}
def fake_choose(rows, passwords=None, parent=None, inventory=False):
    seen.update(rows=rows, passwords=passwords, inventory=inventory)
    return "devices", [("hpe", "aruba_aoscx") if not r["vendor"] else (r["vendor"], r["platform"]) for r in rows]
VA.choose = fake_choose
inv.refresh(); app.processEvents()
inv.table.selectAll()
devs = inv.selected_devices()
inv.detect_vendors(); app.processEvents()
check("it opens the vendor window for the selected devices, from the inventory", seen["inventory"] is True and len(seen["rows"]) == len(devs) == 3)
row = next(r for r in seen["rows"] if r["name"] == "unknown-1")
check("with each device's address, user name, folder and vendor so far", (row["host"], row["username"], row["vendor"], row["kind"]) == ("10.0.0.2", "admin", "", "ssh"))
check("and its stored password for signing in, never shown", seen["passwords"][seen["rows"].index(row)] == "Secr3t!")
now = {d["name"]: (d["vendor"], d["platform"]) for d in db.list_devices()}
check("Apply sets the vendors chosen and leaves the rest", now["unknown-1"] == ("hpe", "aruba_aoscx") and now["sw1"] == ("cisco", "cisco_ios") and now["unknown-2"] == ("juniper", "juniper_junos"), now)
check("and the note is gone", inv.no_vendor.isHidden())

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
