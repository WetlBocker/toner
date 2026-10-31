# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The Overview and Inventory brought level with the mockup: the theme's wash shows through every section, the tiles say what a
# click does, Needs attention leads with the status chip and ends under its last row, the Results row counts the problems.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "polish%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingpolish%d" % int(time.time()))
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
from PySide6.QtWidgets import QApplication, QMessageBox, QScrollArea
app = QApplication([])
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
for k, v in dict(theme="Aurora", look="Soft", panels="Raised").items():
    db.set_setting(k, v)
import app as A
from ui import dashboard as D, status as st, theme
A.apply_look(app)

def dev(name, vendor="cisco"):
    db.save_device(dict(name=name, vendor=vendor, host=f"10.0.0.{len(db.list_devices()) + 1}", port=0, platform="cisco_ios" if vendor == "cisco" else "winrm" if vendor == "windows" else "",
                        username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="HQ", details="", folder_id=None))
for n, v in (("core-sw1", "cisco"), ("edge-fw", "fortinet"), ("pc-1", "windows"), ("dist-sw2", "cisco")): dev(n, v)
db.save_run([Result("core-sw1", "cpu", "WARN", "86%"), Result("edge-fw", "wan links", "FAIL", "1/2", "down: wan2"), Result("pc-1", "disk C:", "OK", "40%"),
             Result("dist-sw2", "connection", "ERROR", "", "timeout")])
w = A.Main(); w.resize(1440, 900); w.show(); app.processEvents(); w.go("Overview"); app.processEvents()
d = w.dashboard

print("== the wash shows through")
areas = [a for a in w.tabs.findChildren(QScrollArea)]
check("every section's scroll area lets the backdrop paint (no opaque viewport, no opaque page)", areas
      and all(not a.viewport().autoFillBackground() and (a.widget() is None or not a.widget().autoFillBackground()) for a in areas), len(areas))
check("the backdrop is behind the sections and paints Aurora's wash", w.tabs.backdrop.isVisibleTo(w) and theme.current().get("aurora"))

print("== the tiles")
check("each tile says what a click does", [c.sub.text() for c in d.cards.values()] == ["Open the Inventory", "Show OK results", "Show warnings", "Show FAIL and ERROR", "Open Configs"]
      and all(c.sub.isVisibleTo(d) for c in d.cards.values()))
check("Healthy, Warnings and Failing head in their status colour; Devices and Config changes stay quiet",
      st.ink("OK") in d.cards["ok"].title.styleSheet() and st.ink("WARN") in d.cards["warn"].title.styleSheet() and st.ink("FAIL") in d.cards["fail"].title.styleSheet()
      and not d.cards["devices"].title.styleSheet() and not d.cards["changes"].title.styleSheet())

print("== Needs attention")
t = d.attention
check("the status chip comes first, then the device in bold, and there is no heading row", t.item(0, 0).text() == "ERROR" and t.item(0, 1).text() == "dist-sw2" and t.item(0, 1).font().bold()
      and not t.horizontalHeader().isVisible() and t.itemDelegateForColumn(0) is not None, (t.item(0, 0).text(), t.item(0, 1).text()))
check("the title counts the devices", d.attention_panel.count.text() == "· 3 devices", d.attention_panel.count.text())
check("the list is as tall as its rows, so the panel ends under the last device", t.height() == 3 * D.ATTENTION_ROW + 2 * t.frameWidth() + 2 and t.height() < 160, t.height())
b = d.row_actions(0)
check("the row buttons are bordered, with a ... for acknowledge and snooze", b["open"].property("outline") and b["run"].property("outline") and b["connect"].text() == "SSH"
      and b["more"].text() == "···" and b["more"].toolTip() == "More: acknowledge or snooze" and b["more"].property("ghost"))
check("a firewall reached by API has no Connect; a switch has SSH", d.row_actions(1)["connect"] is None and d.row_actions(2)["connect"].text() == "SSH")
check("the Checked time is quiet", t.item(0, 3).foreground().color().name() == theme.current()["muted"].lower())
w.resize(1900, 1000); app.processEvents(); app.processEvents()
check("the Actions column shows in a wide window", not t.isColumnHidden(4), (t.viewport().width(), t.columnWidth(4)))
w.resize(900, 600); app.processEvents(); app.processEvents()
check("...and goes when the list is too narrow for the buttons and the words", t.isColumnHidden(4), (t.viewport().width(), t.columnWidth(4)))
w.resize(1900, 1000); app.processEvents(); app.processEvents()
check("...and comes back", not t.isColumnHidden(4))
db.save_run([Result("core-sw1", "cpu", "OK", "5%"), Result("edge-fw", "wan links", "OK", "2/2"), Result("pc-1", "disk C:", "OK", "40%"), Result("dist-sw2", "connection", "OK", "")])
d.refresh(); app.processEvents()
check("nothing to show: the hint has room and the count is blank", t.rowCount() == 0 and t.height() == D.ATTENTION_EMPTY + 2 and d.attention_panel.count.text() == "" and d.hint.isVisibleTo(d))

print("== the count on the Results row")
db.save_run([Result("core-sw1", "cpu", "WARN", "86%"), Result("edge-fw", "wan links", "FAIL", "1/2", "down: wan2"), Result("pc-1", "disk C:", "OK", "40%"),
             Result("dist-sw2", "connection", "ERROR", "", "timeout")])
d.refresh(); app.processEvents()
i = w.tabs.indexOf(w.results)
check("the sidebar draws the number of devices needing attention on Results", w.tabs.count_for_row(w.tabs.row_of(i)) == 3 and w.tabs._counts.get(i) == 3)
check("...the dot on About still works as before", (w.tabs.setBadge(w.about, True), w.tabs.item_for(w.about).text().endswith("●"))[1])
w.tabs.setBadge(w.about, False)
from core import acks
acks.put_aside("dist-sw2", db.device_health()["dist-sw2"]["problems"], None); d.refresh(); app.processEvents()
check("a device put aside leaves the count (and the list)", w.tabs._counts.get(i) == 2 and t.rowCount() == 2)
acks.clear("dist-sw2"); d.refresh(); app.processEvents()

print("== Availability figures")
check("the bars still list the devices", d.bars.rows and all(len(r) == 3 for r in d.bars.rows))
check("the data font is monospace", D.data_font(app.font()).families()[0] == "Cascadia Mono")

print("== Inventory")
w.go("Inventory"); app.processEvents()
inv = w.inventory
rows = inv.table.topLevelItemCount()
check("the list ends under its last device (its height is its rows, not the page)", 0 < inv.table.maximumHeight() < 400 and inv.table.height() == inv.table.maximumHeight(), (inv.table.maximumHeight(), inv.table.height(), rows))
check("the details pane hugs its content too", inv.pane.layout().count() == 2 and inv.pane.layout().itemAt(1).spacerItem() is not None)

print("== the Assistant button keeps off the title row")
check("its topmost spot is under the header", A.HEADER_CLEAR == 72)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
