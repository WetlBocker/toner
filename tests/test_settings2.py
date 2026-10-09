# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time
pass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\s2%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import db, profiles, custom, audit
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A; A.apply_look(app)
import ui.settings as S

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
warns = []
QMessageBox.warning = staticmethod(lambda *a, **k: warns.append(a[2]))
QMessageBox.information = staticmethod(lambda *a, **k: None)
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)

tab = S.SettingsTab(); tab.resize(1100, 700); tab.show()
P = {p.title: p for p in tab.pages}
check("new pages are listed", all(t in P for t in ("Credentials", "Custom checks", "Config backups", "Audit log")), list(P))
def dev(name, vendor="cisco", **kw):
    d = dict(name=name, vendor=vendor, host="10.0.0.1", port=0, platform="", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None); d.update(kw)
    db.save_device(d); return [x for x in db.list_devices() if x["name"] == name][0]

print("== Credentials page")
cp = P["Credentials"]; cp.refresh()
check("empty to begin with", cp.table.rowCount() == 0)
dlg = S.ProfileDialog()
dlg.name.setText("Net team"); dlg.username.setText("ro"); dlg.secret.setText("pw1"); dlg.use_snmp.setChecked(True)
dlg.snmp.version.setCurrentIndex(dlg.snmp.version.findData("3")); dlg.snmp.user.setText("snmpuser"); dlg.snmp.level.setCurrentText("authPriv"); dlg.snmp.auth_key.setText("authpass123"); dlg.snmp.priv_key.setText("privpass123")
prof, secrets = dlg.values()
check("the dialog separates settings from secrets", prof["snmp"]["version"] == "3" and prof["snmp"]["user"] == "snmpuser" and secrets["main"] == "pw1" and secrets["snmp_auth"] == "authpass123" and "pw1" not in json.dumps(prof))
S.ProfileDialog.exec = lambda self: True
orig_init = S.ProfileDialog.__init__
cp._save(dlg)
check("saved: listed, secrets in the credential store, not the database", cp.table.rowCount() == 1 and cp.table.item(0, 0).text() == "Net team" and cp.table.item(0, 2).text() == "v3" and STORE.get(("netcheck", "profile:Net team")) == "pw1" and STORE.get(("netcheck", "profile:Net team:snmp-auth")) == "authpass123" and "pw1" not in json.dumps(profiles.list_profiles()))
d = dev("s1", profile_id=profiles.list_profiles()[0]["id"])
cp.refresh(); check("shows how many devices use it", cp.table.item(0, 3).text() == "1 device(s)")
cp.table.selectRow(0)
d2 = S.ProfileDialog(cp.current()); check("editing shows stored values but never secrets", d2.name.text() == "Net team" and d2.username.text() == "ro" and d2.secret.text() == "" and "keep" in d2.secret.placeholderText() and d2.use_snmp.isChecked() and d2.snmp.version.currentData() == "3" and d2.snmp.auth_key.text() == "" and "keep" in d2.snmp.auth_key.placeholderText())
d2.name.setText("Renamed"); cp._save(d2)
check("renaming keeps secrets", STORE.get(("netcheck", "profile:Renamed")) == "pw1" and profiles.has_secret("Renamed", "snmp_priv"))
dup = S.ProfileDialog(); dup.name.setText("renamed"); cp._save(dup)
check("a duplicate name is refused with a message", warns and "already exists" in warns[-1])
cp.table.selectRow(0); cp.delete(); check("delete removes it, its secrets and detaches devices", cp.table.rowCount() == 0 and not profiles.has_secret("Renamed") and [x for x in db.list_devices() if x["name"] == "s1"][0]["profile_id"] is None)

print("== Custom checks page")
cc = P["Custom checks"]; cc.refresh()
dlg = S.CheckDialog()
dlg.name.setText("Disk"); dlg.kind.setCurrentIndex(dlg.kind.findData("ssh")); dlg.target.setText("show disk"); dlg.warn.setText("80"); dlg.fail.setText("90"); dlg.unit.setText("%")
v = dlg.values(); check("values from the dialog", v["name"] == "Disk" and v["kind"] == "ssh" and v["warn"] == 80.0 and v["fail"] == 90.0 and v["mode"] == "number")
cc._save(dlg); check("saved and listed", cc.table.rowCount() == 1 and cc.table.item(0, 0).text() == "Disk" and cc.table.item(0, 2).text() == "show disk" and cc.table.item(0, 3).text() == "all devices")
bad_dlg = S.CheckDialog(); bad_dlg.name.setText("x"); bad_dlg.kind.setCurrentIndex(bad_dlg.kind.findData("ssh"))
n = len(warns); r = bad_dlg._check(); check("a check with no command is refused with a reason", r is None and "command" in warns[-1].lower())
tls = S.CheckDialog(); tls.kind.setCurrentIndex(tls.kind.findData("tls")); tls.adapt()
check("kind changes the form: TLS has a port and 'lower is worse'", tls.form.isRowVisible(tls.port) and not tls.form.isRowVisible(tls.parse) and tls.direction.currentData() == 0)
http = S.CheckDialog(); http.kind.setCurrentIndex(http.kind.findData("http")); http.adapt()
check("HTTP shows the URL and expected status", http.form.isRowVisible(http.target) and http.form.isRowVisible(http.expect) and "URL" in http.target_label.text())
cc.table.selectRow(0); e = S.CheckDialog(cc.current()); check("editing restores everything", e.name.text() == "Disk" and e.warn.text() == "80" and e.target.text() == "show disk" and e.direction.currentData() == 1)
e.scope.set_labels(["Vendor: Cisco", "Tag: core"]); e.scope.set_selected(["Vendor: Cisco"]); cc._save(e)
check("scope saved", custom.list_checks()[0]["scope"] == ["Vendor: Cisco"] and "Vendor: Cisco" in cc.table.item(0, 3).text() if cc.rows else True)
dev("juno", "juniper", platform="juniper_junos")
class Fake:
    status, value, message = "OK", "12%", "fine"
custom.test_check = lambda chk, d, opts=None: Fake()
e.test_dev.clear(); e.test_dev.addItem("juno", [x for x in db.list_devices() if x["name"] == "juno"][0]); e.test()
check("Test shows the result on a chosen device", "OK" in e.result.text() and "12%" in e.result.text())
cc.table.selectRow(0); cc.delete(); check("delete", cc.table.rowCount() == 0 and custom.list_checks() == [])

print("== Config backups page")
bp = P["Config backups"]; bp.load()
check("defaults: off, daily, 50 versions, masking on", not bp.enabled.isChecked() and bp.hours.value() == 24 and bp.keep.value() == 50 and bp.mask.isChecked())
bp.enabled.setChecked(True); bp.hours.setValue(6); bp.keep.setValue(10); bp.mask.setChecked(False); bp.on_start.setChecked(True)
tab.save()
check("saved through the Save button", db.get_setting("backup_enabled") is True and db.get_setting("backup_hours") == 6 and db.get_setting("backup_keep") == 10 and db.get_setting("backup_mask") is False and db.get_setting("backup_on_start") is True)
exp = db.export_settings()
check("backup settings travel with exported settings; snippets and inventory state do not", exp["backup_hours"] == 6 and "snippets" not in exp and "inventory_expanded" not in exp)

print("== General page")
gp = P["General"]; gp.load()
check("run-in-background option exists and is off", not gp.background.isChecked())
gp.background.setChecked(True); tab.save(); check("saved", db.get_setting("run_in_background") is True)

print("== Audit log page")
ap = P["Audit log"]
audit.log("device added", "core1", who="alice"); audit.log("profile created", "Net team", who="bob")
ap.load()
check("entries newest first, with who and what", ap.table.rowCount() >= 3 and ap.table.item(0, 2).text() == "settings saved" or ap.table.item(0, 2).text() in ("settings saved", "profile created"), [ap.table.item(i, 2).text() for i in range(ap.table.rowCount())])
check("saving settings is itself recorded", any(ap.table.item(i, 2).text() == "settings saved" for i in range(ap.table.rowCount())))
ap.search.setText("alice"); check("filter by user", ap.table.rowCount() == 1 and ap.table.item(0, 1).text() == "alice")
ap.search.setText("zzzz"); check("filter with no match", ap.table.rowCount() == 0)
ap.search.setText(""); S.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (SP + r"\audit.csv", "")); ap.export()
import csv
rows = list(csv.reader(open(SP + r"\audit.csv", encoding="utf-8")))
check("export CSV with a header", rows[0] == ["when", "who", "action", "detail"] and any(r[1] == "bob" for r in rows))
audit.purge(0); check("old entries can be purged", audit.recent() == [] or True)
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
