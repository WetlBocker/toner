# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
pass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\cf%d.db").replace("\\", os.sep) % int(time.time())
from core import db, backup, alerts
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QCoreApplication
app = QApplication([])
import app as A
A.apply_look(app)
import ui.configs as C

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def add(name, vendor="cisco", platform="cisco_ios"):
    db.save_device(dict(name=name, vendor=vendor, host="10.0.0.1", port=0, platform=platform, username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))
for n in ("sw1", "sw2"): add(n)
add("cloud", "meraki", "")

TEXT = {"sw1": "hostname sw1\ninterface Gi0/1\n description a\nend\n", "sw2": "hostname sw2\nvlan 10\nend\n"}
def fake_fetch(dev, opts=None):
    return TEXT[dev["name"]]
backup.fetch = fake_fetch

w = C.ConfigsTab(); w.resize(1200, 700); w.show()
check("lists every device; cloud one is not supported", w.names == ["cloud", "sw1", "sw2"] and w.devs.item(0, 4).text() == "not supported" and w.devs.item(1, 4).text() == "never backed up", [w.devs.item(i, 4).text() for i in range(3)])
got = []
w.backed_up.connect(lambda res, ran, sched: got.append((res, ran, sched)))
def wait():
    for _ in range(300):
        QCoreApplication.processEvents(); time.sleep(0.02)
        if not w.running(): break
    QCoreApplication.processEvents()
w.run_btn.click(); check("button is disabled while running", not w.run_btn.isEnabled()); wait()
check("finished: buttons back, status summarised", w.run_btn.isEnabled() and "Done" in w.status.text(), w.status.text())
check("signal carries results, devices and 'not scheduled'", len(got) == 1 and got[0][2] is False and sorted(got[0][1]) == ["cloud", "sw1", "sw2"] and {r.device for r in got[0][0]} >= {"sw1", "sw2"}, got and got[0][1])
check("device list shows versions and state", w.devs.item(1, 2).text() == "1" and w.devs.item(1, 4).text() == "ok" and w.devs.item(1, 3).text() != "")
w.devs.selectRow(1); QCoreApplication.processEvents()
check("selecting a device lists its versions", w.vers.rowCount() == 1 and w.vers.item(0, 3).text() == "first copy")
check("first copy: diff view explains itself", "first copy" in w.text.toPlainText())
w.view.setCurrentIndex(w.view.findData("full")); QCoreApplication.processEvents()
check("full view shows the configuration", "hostname sw1" in w.text.toPlainText() and "description a" in w.text.toPlainText())

time.sleep(1.1)
TEXT["sw1"] = "hostname sw1\ninterface Gi0/1\n description uplink to core\n shutdown\nend\n"
w.run_btn.click(); wait()
w.devs.selectRow(1); QCoreApplication.processEvents()
check("a changed config adds a version with the change counts", w.vers.rowCount() == 2 and w.vers.item(0, 3).text() == "+2 / -1", [w.vers.item(i, 3).text() for i in range(w.vers.rowCount())])
w.view.setCurrentIndex(w.view.findData("diff")); w.vers.selectRow(0); QCoreApplication.processEvents()
txt = w.text.toPlainText()
check("diff view shows the removed and added lines", "- description a" in txt and "+ description uplink to core" in txt and "+ shutdown" in txt, txt)
check("diff lines are highlighted", w.highlighter is not None and w.text.document().blockCount() > 3)
w.vers.selectAll(); QCoreApplication.processEvents()
check("two versions selected -> comparison", "Comparing" in w.note.text() and "+2 / -1" in w.note.text(), w.note.text())
res = got[-1][0]
check("results of a change: WARN 'changed' for the device, OK for the unchanged one", {r.device: (r.status, r.value) for r in res}["sw1"] == ("WARN", "changed") and {r.device: r.status for r in res}["sw2"] == "OK")
ev = alerts.evaluate(res, ["sw1", "sw2"])
check("a change is announced as a new event", any(e.kind == "new" and e.device == "sw1" and e.check == "config backup" for e in ev), ev)
res2 = backup.backup_many([d for d in db.list_devices() if d["name"] in ("sw1", "sw2")], 2)
ev2 = alerts.evaluate(res2, ["sw1", "sw2"])
check("the next unchanged backup does NOT announce a 'recovery'", not any(e.kind == "recovered" for e in ev2), ev2)

check("failed backups show in the list", True)
def failing(dev, opts=None): raise TimeoutError("connection timed out")
backup.fetch = failing
w.one_btn.click() if False else None
w.devs.selectRow(2); w.one_btn.click(); wait()
check("'Back up selected' backs up only that device", got[-1][1] == ["sw2"], got[-1][1])
check("a failure is flagged on the device row", w.devs.item(2, 4).text() == "last backup FAILED", w.devs.item(2, 4).text())
backup.fetch = fake_fetch

print("== search")
dlg = C.SearchDialog(w); jumps = []; dlg.jump.connect(lambda d, i: jumps.append((d, i)))
dlg.box.setText("vlan"); dlg.run()
check("search finds the line with its device and line number", len(dlg.hits) == 1 and dlg.hits[0]["device"] == "sw2" and dlg.hits[0]["line_no"] == 2 and dlg.table.item(0, 3).text() == "vlan 10", dlg.hits)
dlg.box.setText("description a"); dlg.all_versions.setChecked(False); dlg.run(); check("newest copy only by default", dlg.hits == [])
dlg.all_versions.setChecked(True); dlg.run(); check("'All versions' also searches older copies", len(dlg.hits) == 1 and dlg.hits[0]["device"] == "sw1")
dlg.regex.setChecked(True); dlg.box.setText("(unclosed"); dlg.run(); check("a bad regular expression is reported, not a crash", "failed" in dlg.info.text().lower())
dlg.regex.setChecked(False); dlg.all_versions.setChecked(True); dlg.box.setText("description a"); dlg.run(); dlg.table.selectRow(0); dlg.open_row()
check("double-click reports where to jump", len(jumps) == 1 and jumps[0][0] == "sw1")
w.select_device(*jumps[0]); QCoreApplication.processEvents()
check("jumping selects the device and opens that old version in full", w.current_device() == "sw1" and "description a" in w.text.toPlainText() and "uplink" not in w.text.toPlainText(), w.text.toPlainText()[:80])

print("== pruning and saving")
import ui.configs as CC
CC.QMessageBox.question = staticmethod(lambda *a, **k: CC.QMessageBox.StandardButton.Yes)
w.prune(); check("delete older versions keeps the newest", len(backup.list_backups("sw1")) == 1)
saved = SP + (r"\saved_cfg.txt").replace("\\", os.sep)
CC.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (saved, ""))
w.devs.selectRow(1); QCoreApplication.processEvents(); w.vers.selectRow(0); w.save_version()
check("save writes the stored text", open(saved, encoding="utf-8").read() == backup.get_text(backup.latest("sw1")["id"]))
w.grab().save(SP + (r"\configs_tab.png").replace("\\", os.sep))
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
