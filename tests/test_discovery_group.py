# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\dg%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db, discovery, profiles
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
rows = [{"ip": "10.1.2.5", "name": "sw-a", "vendor": "cisco", "platform": "cisco_ios"}, {"ip": "10.1.2.9", "name": "sw-b", "vendor": "cisco", "platform": "cisco_ios"},
        {"ip": "10.1.3.7", "name": "fw-a", "vendor": "fortinet"}, {"ip": "10.1.3.8", "name": "snmp-a", "vendor": "snmp", "snmp": True, "community": "public"},
        {"ip": "10.1.3.9", "name": "pc-a", "vendor": "windows", "platform": "winrm"}]
check("the names of the groupings", [k for k, _ in discovery.GROUPINGS] == ["", "subnet", "type", "both"])
check("the subfolder for each way of grouping", discovery.subfolder_for(rows[0], "subnet") == "10.1.2.0-24" and discovery.subfolder_for(rows[0], "type") == "Cisco"
      and discovery.subfolder_for(rows[0], "both") == "10.1.2.0-24/Cisco" and discovery.subfolder_for(rows[0], "") == "" and discovery.subfolder_for({"ip": "fe80::1", "vendor": "cisco"}, "subnet") == "IPv6")
pid = profiles.save({"name": "ops", "username": "ops", "snmp": "", "notes": ""}, {"main": "pw"})
base = db.create_folder("Chicago", None)
added, skipped = discovery.add_to_inventory(rows, base, pid, "Chicago", "new", group_by="both")
devs = {d["name"]: d for d in db.list_devices()}
paths = db.folder_paths()
check("everything was added", len(added) == 5 and not skipped)
check("each device is in a subfolder of the chosen folder, by network then type", paths[devs["sw-a"]["folder_id"]] == "Chicago/10.1.2.0-24/Cisco" and paths[devs["sw-b"]["folder_id"]] == "Chicago/10.1.2.0-24/Cisco"
      and paths[devs["fw-a"]["folder_id"]] == "Chicago/10.1.3.0-24/Fortinet" and paths[devs["pc-a"]["folder_id"]] == "Chicago/10.1.3.0-24/Windows")
check("devices that share a folder share one folder (not a copy each)", devs["sw-a"]["folder_id"] == devs["sw-b"]["folder_id"] and len([p for p in paths.values() if p.endswith("Cisco")]) == 1)
check("the credential profile goes only to devices that sign in", devs["sw-a"]["profile_id"] == pid and devs["fw-a"]["profile_id"] == pid and devs["pc-a"]["profile_id"] == pid and devs["snmp-a"]["profile_id"] is None)
check("location and tags still apply", devs["sw-a"]["location"] == "Chicago" and devs["sw-a"]["tags"] == "new")
for d in db.list_devices(): db.delete_device(d["id"])
discovery.add_to_inventory([dict(rows[0], name="x1"), dict(rows[2], name="x2")], None, None, group_by="subnet")
paths = db.folder_paths(); devs = {d["name"]: d for d in db.list_devices()}
check("with no folder chosen the subfolders go at the top", paths[devs["x1"]["folder_id"]] == "10.1.2.0-24" and paths[devs["x2"]["folder_id"]] == "10.1.3.0-24")
for d in db.list_devices(): db.delete_device(d["id"])
discovery.add_to_inventory([dict(rows[0], name="y1")], base, None)
check("without grouping, everything goes in the folder as before", db.folder_paths()[[d for d in db.list_devices() if d["name"] == "y1"][0]["folder_id"]] == "Chicago")

from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
QMessageBox.information = staticmethod(lambda *a, **k: None)
from ui import tools2
tab = tools2.DiscoveryTab()
check("the Discovery tool has a 'group into' choice", [tab.group.itemData(i) for i in range(tab.group.count())] == ["", "subnet", "type", "both"])
tab.rows = [dict(r, ports=[], descr="", hint="", cert="", banner="", hostname="", community="") for r in rows[:2]]
tab.table.setRowCount(2)
from PySide6.QtWidgets import QTableWidgetItem
from PySide6.QtCore import Qt
for i, r in enumerate(tab.rows):
    it = QTableWidgetItem(); it.setCheckState(Qt.CheckState.Checked); tab.table.setItem(i, 0, it); tab.table.setItem(i, 2, QTableWidgetItem("ui-" + r["name"]))
    from PySide6.QtWidgets import QComboBox
    cb = QComboBox(); cb.addItem("Cisco", "cisco"); tab.table.setCellWidget(i, 3, cb)
tab.group.setCurrentIndex(tab.group.findData("type")); tab.add()
got = [d for d in db.list_devices() if d["name"].startswith("ui-")]
check("choosing it files what is added", len(got) == 2 and all(db.folder_paths()[d["folder_id"]] == "Cisco" for d in got), [(d["name"], d["folder_id"]) for d in got])

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
