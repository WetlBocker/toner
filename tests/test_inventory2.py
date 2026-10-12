# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import csv, json, os, sys, time
pass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\iv%d.db" % int(time.time())
from core import db, importer, bulk, profiles
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A; A.apply_look(app)
import ui.inventory as I

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
QMessageBox.information = staticmethod(lambda *a, **k: None)
QMessageBox.warning = staticmethod(lambda *a, **k: None)

def dev(name, vendor="cisco", **kw):
    d = dict(name=name, vendor=vendor, host="10.0.0.1", port=0, platform="", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None); d.update(kw)
    db.save_device(d); return [x for x in db.list_devices() if x["name"] == name][0]
a = dev("a", tags="core, wan", location="Chi"); b = dev("b", tags="Core"); c = dev("c", tags="", vendor="juniper")

print("== inventory tab: tags")
w = I.InventoryTab(); w.resize(1100, 500)
check("Tags column", "Tags" in w.COLS and w.table.headerItem().text(w.COLS.index("Tags")) == "Tags")
def shown(): return sorted(w.payload[k]["name"] for k in w.payload if k.startswith("device:"))
check("all devices shown", shown() == ["a", "b", "c"])
w.toggle_filter("tag_sel", "core", True)
check("tag filter is case-insensitive and keeps matching devices", shown() == ["a", "b"], shown())
w.toggle_filter("tag_sel", "wan", True); check("several tags = any of them", shown() == ["a", "b"])
w.toggle_filter("vendor_sel", "juniper", True); check("tags and vendor combine (both must match)", shown() == [])
w.set_filter(None, None); check("clear filter clears tags too", shown() == ["a", "b", "c"] and not w.tag_sel)
w._build_filter_menu(); check("the filter menu offers a Tag submenu", any(x.text() == "Tag" for x in w.filter_menu.actions()))
check("tags are groups for scheduling, reports and thresholds", "Tag: core" in db.group_labels() and db.in_group(a, "Tag: Core") and not db.in_group(c, "Tag: core"))
db.set_setting("threshold_overrides", [{"scope": "Tag: wan", "check": "cpu", "warn": 30, "fail": 40}])
check("a threshold override can target a tag", db.thresholds_for(a)["cpu"]["warn"] == 30 and db.thresholds_for(b)["cpu"]["warn"] == 70)

print("== bulk edit (core)")
fid = db.create_folder("Racks")
devs = [x for x in db.list_devices() if x["name"] in ("a", "b", "c")]
n = bulk.apply(devs, {"folder_id": fid, "add_tags": "audited, PCI", "remove_tags": "core"})
d = {x["name"]: x for x in db.list_devices()}
check("folder moved, tags added and removed (case-insensitively), untouched fields kept", n == 3 and all(d[k]["folder_id"] == fid for k in d) and d["a"]["tags"] == "wan, audited, PCI" and d["b"]["tags"] == "audited, PCI" and d["a"]["location"] == "Chi" and d["c"]["vendor"] == "juniper", {k: v["tags"] for k, v in d.items()})
n = bulk.apply(devs, {"location": "Annex", "enabled": False})
d = {x["name"]: x for x in db.list_devices()}
check("location and enabled", all(d[k]["location"] == "Annex" and d[k]["enabled"] == 0 for k in d))
n = bulk.apply(devs, {"enabled": False}); check("a no-op change counts as zero", n == 0)
pid = profiles.save({"name": "Net team", "username": "ro"}, {"main": "pw"})
bulk.apply(devs, {"profile_id": pid}); d = {x["name"]: x for x in db.list_devices()}
check("credential profile assigned", all(d[k]["profile_id"] == pid for k in d))
bulk.apply(devs, {"profile_id": None}); check("...and detached", all(x["profile_id"] is None for x in db.list_devices()))
bulk.apply(devs[:2], {"jump": "c"}); d = {x["name"]: x for x in db.list_devices()}
check("jump host set", json.loads(d["a"]["jump"]) == {"device": "c"} and d["c"]["jump"] == "")
try: bulk.apply(devs, {"jump": "a"}); check("own jump host refused", False)
except ValueError as e: check("a selected device cannot be the jump host", "own jump host" in str(e))
try: bulk.apply(devs, {"jump": "ghost"}); check("unknown jump host refused", False)
except ValueError: check("unknown jump host refused", True)
bulk.apply(devs[:2], {"jump": ""}); check("jump host cleared", all(not x["jump"] for x in db.list_devices()))

print("== bulk edit dialog")
dlg = I.BulkEditDialog(3)
check("nothing ticked -> nothing to apply", dlg.operations() == {})
dlg.rows["add_tags"][0].setChecked(True); dlg.add_tags.setText("x, y"); dlg.rows["folder_id"][0].setChecked(True); dlg.folder.setCurrentIndex(dlg.folder.findData(fid))
dlg.rows["enabled"][0].setChecked(True); dlg.enabled.setCurrentIndex(0)
check("only ticked rows become operations", dlg.operations() == {"add_tags": "x, y", "folder_id": fid, "enabled": True}, dlg.operations())
check("unticked fields are disabled", not dlg.location.isEnabled() and dlg.add_tags.isEnabled())
w.refresh(); w.select_device(a["id"])
I.BulkEditDialog.exec = lambda self: True
I.BulkEditDialog.operations = lambda self: {"location": "Dock"}
w.table.selectAll(); w.bulk_edit()
check("the tab applies the dialog to the selected devices", all(x["location"] == "Dock" for x in db.list_devices()))

print("== export / import round trip")
for x in db.list_devices(): pass
db.save_device({**[x for x in db.list_devices() if x["name"] == "a"][0], "profile_id": pid, "folder_id": fid, "jump": {"device": "c"}})
db.set_secret("a", "SECRETPW"); db.set_secret("a:snmp", "COMM")
rows = importer.export_rows(db.list_devices())
ra = next(r for r in rows if r["name"] == "a")
check("export carries folder path, tags, profile and jump host by name, never secrets", ra["folder"] == "Racks" and ra["profile"] == "Net team" and ra["jump"] == "c" and "wan" in ra["tags"] and "SECRETPW" not in str(rows) and "COMM" not in str(rows), ra)
for ext in ("csv", "json", "yaml"):
    p = SP + rf"\inv_export.{ext}"
    importer.write_rows(rows, p)
    back = importer.load_rows(p)
    check(f"{ext}: file reads back with every device", sorted(r["name"] for r in back) == ["a", "b", "c"])
try: importer.write_rows(rows, SP + r"\x.txt"); check("unknown extension refused", False)
except ValueError: check("unknown extension refused", True)
# import into a fresh inventory
for x in db.list_devices(): db.delete_device(x["id"])
w2 = I.InventoryTab()
I.QFileDialog.getOpenFileName = staticmethod(lambda *a, **k: (SP + r"\inv_export.csv", ""))
# 'c' is the jump host of 'a' but sorts after it: import order matters, so the first pass reports it and a second import completes it
w2.import_file(); names1 = {x["name"] for x in db.list_devices()}
check("import reports a jump host that is not imported yet, and imports the rest", "b" in names1 and "c" in names1 and "a" not in names1, names1)
w2.import_file(); d = {x["name"]: x for x in db.list_devices()}
check("a second import adds the device that needed it; profile, folder, tags and jump are restored", "a" in d and d["a"]["profile_id"] == pid and json.loads(d["a"]["jump"]) == {"device": "c"} and d["a"]["tags"] == "wan, audited, PCI" and db.folder_paths()[d["a"]["folder_id"]] == "Racks", d.get("a"))
# profile that does not exist
p = SP + r"\inv_bad.csv"
with open(p, "w", newline="", encoding="utf-8") as fh:
    cw = csv.writer(fh); cw.writerow(["name", "vendor", "host", "profile", "tags", "snmp_community"]); cw.writerow(["z1", "snmp", "10.9.9.9", "No such profile", "t1", ""]); cw.writerow(["z2", "snmp", "10.9.9.8", "", "t1; t2", "comm9"])
I.QFileDialog.getOpenFileName = staticmethod(lambda *a, **k: (p, ""))
w2.import_file(); names = {x["name"]: x for x in db.list_devices()}
check("an unknown profile skips just that row", "z1" not in names and "z2" in names)
check("tags with ';' are tidied; SNMP community stored as a secret; vendor snmp gets SNMP settings", names["z2"]["tags"] == "t1, t2" and STORE.get(("netcheck", "z2:snmp")) == "comm9" and json.loads(names["z2"]["snmp"])["version"] == "2c")
print("== export button")
I.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (SP + r"\btn_export.json", ""))
w2.export_file(); check("the Export button writes the visible devices", len(json.load(open(SP + r"\btn_export.json"))["devices"]) == len(db.list_devices()))
w2.table.selectAll(); w2.set_filter("tag_sel", "t1"); w2.table.selectAll()
w2.export_file(); check("a filter limits what is exported", len(json.load(open(SP + r"\btn_export.json"))["devices"]) == 1)

print("== device dialog: profile, tags, fields, SNMP, jump host")
for x in db.list_devices(): db.delete_device(x["id"])
dev("bastion"); pid = profiles.save({"name": "Shared", "username": "ro"}, {"main": "pw"})
dlg = I.DeviceDialog()
check("six tabs, the Windows one only shown for Windows devices", [dlg.tabs.tabText(i) for i in range(dlg.tabs.count())] == ["General", "Access", "SNMP", "Tags and fields", "Windows", "Checks"] and not dlg.tabs.isTabVisible(4) and dlg.tabs.isTabVisible(5))
dlg.name.setText("sw9"); dlg.host.setText("10.9.9.9"); dlg.profile.setCurrentIndex(dlg.profile.findData(pid)); dlg.tags.setText("core, PCI ,core")
dlg.fields.setPlainText("serial=FDO123\nowner = Net team\nnonsense line"); dlg.jump.setCurrentIndex(dlg.jump.findData("bastion"))
dlg.use_snmp.setChecked(True); dlg.snmp.version.setCurrentIndex(dlg.snmp.version.findData("3")); dlg.snmp.user.setText("u3"); dlg.snmp.level.setCurrentText("authPriv"); dlg.snmp.auth_key.setText("authpass123"); dlg.snmp.priv_key.setText("privpass123")
v = dlg.values()
check("values carry the new fields", v["profile_id"] == pid and v["tags"] == "core, PCI ,core" and v["fields"] == {"serial": "FDO123", "owner": "Net team"} and v["jump"] == {"device": "bastion"} and v["snmp"]["version"] == "3" and v["snmp"]["user"] == "u3", v)
check("SNMP secrets are separate from the settings", dlg.snmp_secrets()["snmp_auth"] == "authpass123" and "authpass123" not in json.dumps(v))
w3 = I.InventoryTab(); w3._save(v, "", extra_secrets=dlg.snmp_secrets())
saved = [x for x in db.list_devices() if x["name"] == "sw9"][0]
check("saved tidy; SNMP secrets in the credential store under the device's name", saved["tags"] == "core, PCI" and json.loads(saved["fields"])["serial"] == "FDO123" and STORE.get(("netcheck", "sw9:snmp-auth")) == "authpass123" and STORE.get(("netcheck", "sw9:snmp-priv")) == "privpass123")
again = I.DeviceDialog(saved)
check("editing restores every field; secrets stay hidden with a hint", again.profile.currentData() == pid and again.tags.text() == "core, PCI" and again.fields.toPlainText() == "serial=FDO123\nowner=Net team" and again.jump.currentData() == "bastion" and again.use_snmp.isChecked() and again.snmp.user.text() == "u3" and again.snmp.auth_key.text() == "" and "keep" in again.snmp.auth_key.placeholderText())
again.name.setText("sw9-renamed"); w3._save(again.values(), "", old_name="sw9", extra_secrets=again.snmp_secrets())
check("renaming moves the SNMP secrets with the device", STORE.get(("netcheck", "sw9-renamed:snmp-auth")) == "authpass123" and ("netcheck", "sw9:snmp-auth") not in STORE)
vend = I.DeviceDialog(); vend.vendor.setCurrentIndex(vend.vendor.findData("snmp"))
check("a generic SNMP device needs no password box and always has SNMP settings", not vend.access.isRowVisible(vend.secret) and vend.use_snmp.isChecked() and vend.values()["snmp"] != "" and not vend.use_snmp.isVisibleTo(vend))
cis = I.DeviceDialog(); cis.vendor.setCurrentIndex(cis.vendor.findData("cisco"))
check("an SSH vendor offers a jump host; an API vendor offers SSL checking", cis.access.isRowVisible(cis.jump) and not cis.access.isRowVisible(cis.verify))
api = I.DeviceDialog(); api.vendor.setCurrentIndex(api.vendor.findData("fortinet"))
check("...the other way round for a firewall", not api.access.isRowVisible(api.jump) and api.access.isRowVisible(api.verify) and api.access.isRowVisible(api.ha))
w3._save({**v, "id": None, "name": "sw9-renamed"}, "")
check("a duplicate name is refused", len([x for x in db.list_devices() if x["name"] == "sw9-renamed"]) == 1)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
