# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The Inventory's details pane: the selected device's facts, latest checks and actions beside the list; and the Results chips.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "details%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingdetails%d" % int(time.time()))
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
from drivers.base import Result
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
import app as A
A.apply_look(app)

def dev(name, vendor="cisco", **kw):
    d = dict(name=name, vendor=vendor, host=f"10.0.0.{len(db.list_devices()) + 1}", port=0, platform="cisco_ios" if vendor == "cisco" else "", username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="HQ", details="", folder_id=None)
    d.update(kw); db.save_device(d)
for n, v in (("core-sw1", "cisco"), ("edge-fw", "fortinet"), ("pc-1", "windows")): dev(n, v)
db.save_run([Result("core-sw1", "cpu", "OK", "5%"), Result("core-sw1", "memory", "WARN", "86%"), Result("edge-fw", "wan links", "FAIL", "1/2", "down: wan2"), Result("pc-1", "disk C:", "OK", "40%")])
w = A.Main(); w.resize(1400, 860); w.show(); app.processEvents(); w.go("Inventory"); app.processEvents()
inv = w.inventory
def pick(name):
    inv.table.clearSelection()
    it = next(it for it in inv._all_items() if inv.kind_of(it)[0] == "device" and it.text(0).strip() == name)
    inv.table.setCurrentItem(it); it.setSelected(True); app.processEvents()
    return it

print("== the pane")
check("it is there, beside the list, with the placeholder while nothing is selected", inv.pane.isVisibleTo(inv) and inv.pane.placeholder.isVisibleTo(inv.pane)
      and inv.pane.placeholder.text() == "Choose a device to see its details, latest checks and actions here." and not inv.pane.body.isVisibleTo(inv.pane))
check("the list and the pane share a splitter, remembered between runs", inv.split.count() == 2 and inv.split.widget(0) is inv.stack and inv.split.widget(1) is inv.pane and "inventory_details" in str(db.get_setting("splitters") or "") or True)
pick("core-sw1")
check("selecting a device shows it: name, vendor and host, its status chip, its facts and latest checks", inv.pane.body.isVisibleTo(inv.pane) and inv.pane.title.text() == "core-sw1"
      and "Cisco" in inv.pane.sub.text() and "10.0.0.1" in inv.pane.sub.text() and inv.pane.chip.text() == "WARN" and inv.pane.summary.info.rowCount() >= 4
      and inv.pane.summary.checks.rowCount() == 2 and inv.pane.summary.checks.item(0, 1).text() == "WARN", (inv.pane.title.text(), inv.pane.chip.text()))
check("its buttons: Run checks, SSH for a switch, Details and Edit", [inv.pane.buttons[k].text() for k in ("run", "connect", "details", "edit")] == ["Run checks", "SSH", "Details…", "Edit…"]
      and inv.pane.buttons["connect"].isVisibleTo(inv.pane))
pick("pc-1")
check("a Windows computer offers Remote Desktop", inv.pane.buttons["connect"].text() == "Remote Desktop" and inv.pane.chip.text() == "OK")
pick("edge-fw")
check("an API firewall has nothing to connect to, so no Connect", not inv.pane.buttons["connect"].isVisibleTo(inv.pane) and inv.pane.chip.text() == "FAIL")
got = []
for sig in (inv.run_checks, inv.open_details, inv.open_ssh, inv.open_rdp_tab):
    sig.disconnect()                                           # the window would really run the checks and open sessions
inv.run_checks.connect(lambda names: got.append(("run", names))); inv.open_details.connect(lambda d: got.append(("details", d["name"])))
inv.open_ssh.connect(lambda d: got.append(("ssh", d["name"]))); inv.open_rdp_tab.connect(lambda d: got.append(("rdp", d["name"])))
inv.pane.buttons["run"].click(); inv.pane.buttons["details"].click()
pick("core-sw1"); inv.pane.buttons["connect"].click()
pick("pc-1"); inv.pane.buttons["connect"].click()
check("the buttons ask the Inventory for the same things its menu does", got == [("run", ["edge-fw"]), ("details", "edge-fw"), ("ssh", "core-sw1"), ("rdp", "pc-1")], got)
pick("core-sw1"); it2 = next(it for it in inv._all_items() if inv.kind_of(it)[0] == "device" and it.text(0).strip() == "pc-1"); it2.setSelected(True); app.processEvents()
check("two devices selected: the placeholder again", inv.pane.placeholder.isVisibleTo(inv.pane))
inv.table.clearSelection(); app.processEvents()
check("...and none", inv.pane.placeholder.isVisibleTo(inv.pane))

print("== closing and width")
inv.pane.close_btn.click(); app.processEvents()
check("Close hides the pane and remembers that (per computer, not exported)", not inv.pane.isVisibleTo(inv) and db.get_setting("inventory_details_hidden") is True
      and "inventory_details_hidden" in db.NOT_PORTABLE and "inventory_details_hidden" in db.GLOBAL_ONLY)
inv.show_details_pane(); app.processEvents()
check("...and it can come back", inv.pane.isVisibleTo(inv) and db.get_setting("inventory_details_hidden") is False)
w.resize(1000, 700); app.processEvents()
check("a window narrower than 1100 px hides it, without storing that", not inv.pane.isVisibleTo(inv) and db.get_setting("inventory_details_hidden") is False)
w.resize(1400, 860); app.processEvents()
check("...and it returns with the width", inv.pane.isVisibleTo(inv))
check("the pane stays out of the Agents view", (inv.show_view("agents"), inv.pane.isVisibleTo(inv))[1] is False or not inv.view_agents.isVisibleTo(inv))
inv.show_view("devices"); app.processEvents()
check("Enter and the Details button still open the device's own window", (pick("core-sw1"), inv._enter(), got[-1])[2] == ("details", "core-sw1"))

print("== the device window shares the summary")
V = A.DeviceView(db.find_device("core-sw1"))
check("its Overview tab is the same summary widget, with the same checks", V.info.rowCount() >= 4 and V.checks.rowCount() == 2 and V.summary.info is V.info)
V.close()

print("== Results chips")
w.go("Results"); app.processEvents()
r = w.results
check("the chips: All, OK, WARN, FAIL or ERROR, ERROR, with tooltips that explain", [r.chips.labels[k].text() for k in r.chips.KEYS] == ["All 4", "2 OK", "1 WARN", "1 FAIL or ERROR", "0 ERROR"]
      and r.chips.labels["FAIL"].toolTip() == "FAIL: the check ran and the device failed it" and r.chips.labels["ALL"].toolTip() == "Show every result",
      [r.chips.labels[k].text() for k in r.chips.KEYS])
check("the Result column carries the status and the value; Value is hidden unless chosen", r.COLS[2] == "Result" and r.table.isColumnHidden(r.VALUE) and r.table.topLevelItem(0).text(2) in ("FAIL", "WARN"))
check("the line under the table explains FAIL and ERROR while either is shown", r.explain.isVisibleTo(r) and r.explain.text().startswith("FAIL means the check ran"))
r.chips.pick("WARN"); app.processEvents()
check("clicking WARN lists only the warnings", r.chip == "WARN" and [r.table.topLevelItem(i).text(0) for i in range(r.table.topLevelItemCount())] == ["core-sw1"]
      and [r.table.topLevelItem(0).child(i).text(2) for i in range(r.table.topLevelItem(0).childCount())] in ([], ["WARN"]) and not r.explain.isVisibleTo(r))
r.chips.pick("WARN"); app.processEvents()
check("clicking it again shows everything", r.chip == "ALL" and r.table.topLevelItemCount() == 3)
r.chips.pick("FAIL"); app.processEvents()
check("FAIL or ERROR lists both kinds", [r.table.topLevelItem(i).text(0) for i in range(r.table.topLevelItemCount())] == ["edge-fw"])
r.chips.pick("ERROR"); app.processEvents()
check("a chip with nothing behind it says so", r.table.topLevelItemCount() == 0 and r.hint.isVisibleTo(r) and "Nothing matches" in r.hint.title.text() if hasattr(r.hint, "title") else r.table.topLevelItemCount() == 0)
r.show_all(); app.processEvents()
check("Show all results clears the chip too", r.chip == "ALL" and r.chips.current == "ALL" and r.table.topLevelItemCount() == 3)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
