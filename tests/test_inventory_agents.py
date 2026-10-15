# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\invag%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import agents, db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
import ui.inventory as I
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def dev(name, vendor="windows", platform="agent"):
    d = dict(name=name, vendor=vendor, host=name, port=0, platform=platform, username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None)
    d["id"] = db.save_device(d); return db.get_device(d["id"])
def report(**kw):
    r = {"v": 1, "at": "2026-01-01T00:00:00Z", "computer": "PC", "domain": "corp", "joined": True, "os": "Microsoft Windows 11 Pro", "reboot": []}
    r.update(kw); return r

dev("sw1", "cisco", "cisco_ios")
tab = I.InventoryTab(); tab.show()
print("== the Agents view in Inventory")
check("with no agents and the receiver off, there is no Devices/Agents switch", not tab.views_w.isVisible() and tab.stack.currentWidget() is tab.table)
tab.show_view("agents")
check("asking for the Agents view then does nothing", tab.stack.currentWidget() is tab.table)
db.set_setting("agent_enabled", True); tab.refresh()
check("with the receiver on the switch appears (so the way to the agents is visible before the first one signs up)", tab.views_w.isVisible() and tab.view_agents.text() == "Agents")
db.set_setting("agent_enabled", False)
dev("pc-1"); agents.token_for("pc-1"); agents.store("pc-1", report(computer="PC1", reboot=["Windows Update"]), "10.0.0.5", 2)
dev("pc-2"); agents.token_for("pc-2"); agents.store("pc-2", report(computer="PC2"), "10.0.0.6", "1.0.0")
tab.refresh()
check("with agents it shows how many", tab.views_w.isVisible() and tab.view_agents.text() == "Agents (2)", tab.view_agents.text())
check("the device tree is what shows first, with its usual buttons", tab.stack.currentWidget() is tab.table and tab.bar_w.isVisible() and tab.view_devices.isChecked())
tab.view_agents.click()
check("the Agents button swaps in the fleet table and hides the device buttons", tab.stack.currentWidget() is tab.fleet and tab.fleet.isVisible() and not tab.bar_w.isVisible() and tab.view_agents.isChecked() and not tab.view_devices.isChecked())
rows = {tab.fleet.table.item(i, 0).text(): [tab.fleet.table.item(i, j).text() for j in range(8)] for i in range(tab.fleet.table.rowCount())}
check("it lists each computer with its system, age, where from, agent version and notes", set(rows) == {"pc-1", "pc-2"} and rows["pc-1"][1] == "PC1" and rows["pc-1"][2].startswith("Windows 11 Pro") and rows["pc-1"][5] == "10.0.0.5"
      and rows["pc-1"][6] == "v2" and "reboot pending" in rows["pc-1"][7] and "agent will update" in rows["pc-1"][7] and rows["pc-2"][6] == "v1.0.0" and "agent will update" in rows["pc-2"][7], rows)
check("the heading counts them", "2 computers" in tab.fleet.info.text())
check("devices that are not agents are not in it", "sw1" not in rows)
opened = []; tab.open_details.connect(opened.append)
tab.fleet.table.cellDoubleClicked.emit(0, 0)
check("double-clicking a computer opens its device window", opened and opened[0]["name"] == "pc-1")
went = []; tab.open_agent_settings.connect(lambda: went.append(1)); tab.fleet.settings_btn.click()
check("'Agent settings...' asks for Settings > Agents", went == [1])
tab.view_devices.click()
check("Devices brings the tree back", tab.stack.currentWidget() is tab.table and tab.bar_w.isVisible())

print("== silent computers")
with db.connect() as c: c.execute("UPDATE agent_reports SET received_at='2020-01-01T00:00:00+00:00' WHERE device='pc-2'")
tab.refresh()
check("silent ones are counted on the button", "1 silent" in tab.view_agents.text(), tab.view_agents.text())
tab.view_agents.click()
silent_row = [i for i in range(tab.fleet.table.rowCount()) if tab.fleet.table.item(i, 0).text() == "pc-2"][0]
check("and marked in the notes, in red", "silent" in tab.fleet.table.item(silent_row, 7).text() and tab.fleet.table.item(silent_row, 7).foreground().color().name() == __import__("ui.status", fromlist=["x"]).ink("FAIL"))
check("the heading says so too", "1 silent" in tab.fleet.info.text())

print("== revoke and remove")
tab.fleet.table.selectRow(silent_row)
check("selecting enables the buttons", tab.fleet.revoke.isEnabled() and tab.fleet.remove.isEnabled())
tab.fleet._revoke()
check("Revoke stops the agent being accepted, says so, and keeps the device", "revoked" in tab.fleet.table.item(silent_row, 7).text() and any(d["name"] == "pc-2" for d in db.list_devices())
      and agents.device_for_token("anything") == "" and ("netcheck", "pc-2:agent") not in STORE)
changed = []; tab.changed.connect(lambda: changed.append(1))
tab.fleet.table.selectRow(silent_row); tab.fleet._remove()
check("Remove deletes the device, its token and its reports, and the inventory knows", not any(d["name"] == "pc-2" for d in db.list_devices()) and "pc-2" not in [r["device"] for r in agents.overview()] and changed)
check("the list, the count and the heading follow", tab.fleet.table.rowCount() == 1 and tab.view_agents.text() == "Agents (1)" and "1 computer reporting" in tab.fleet.info.text())
tab.fleet.table.selectRow(0); tab.fleet._remove()
check("with none left, the switch goes away and the view returns to the devices", not tab.views_w.isVisible() and tab.stack.currentWidget() is tab.table and tab.bar_w.isVisible(), tab.view_agents.text())
check("with none left the heading explains how to start", "No computer reports" in tab.fleet.info.text() and "Settings > Agents" in tab.fleet.info.text())

print("== from the main window")
dev("pc-3"); agents.token_for("pc-3"); agents.store("pc-3", report(), "10.0.0.7", 2)
w = A.Main()
w.inventory.refresh()
check("the Inventory in the main window has the switch", w.inventory.views_w.isVisibleTo(w.inventory))
w.go("Inventory"); w.inventory.show_view("agents"); w.inventory.fleet.settings_btn.click()
titles = [p.title for p in w.settings.pages]
check("'Agent settings...' opens Settings with the Agents page selected", w.tabs.tabText(w.tabs.currentIndex()) == "Settings" and w.settings.current_title() == "Agents", (w.tabs.tabText(w.tabs.currentIndex()), titles))
check("and Settings > Agents keeps the receiver, package, sign-up and certificate", all(hasattr(w.settings.pages[titles.index("Agents")], n) for n in ("enabled", "enroll", "download", "print", "renew", "token_days")))
w.close()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
