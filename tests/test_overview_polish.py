# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The Overview and Inventory brought level with the mockup: the theme's wash shows through every section, the tiles say what they
# count, Needs attention leads with the status chip and ends under its last row, the Results row counts the problems. Every count
# says what it counts (devices or checks), and "down" and Availability mean a device Toner could not connect to.
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
check("Devices and Config changes say what a click does; the status tiles say what they count", [c.sub.text() for c in d.cards.values()]
      == ["Open the Inventory", "of 4 devices", "of 4 devices", "of 4 devices", "Open Configs"] and all(c.sub.isVisibleTo(d) for c in d.cards.values()), [c.sub.text() for c in d.cards.values()])
check("...and their click is in the tooltip", [d.cards[k].toolTip().split("\n")[0] for k in ("ok", "warn", "fail")]
      == ["Click to show OK results", "Click to show warnings", "Click to show FAIL and ERROR"], [d.cards[k].toolTip() for k in ("ok", "warn", "fail")])
check("Healthy, Warnings and Failing head in their status colour; Devices and Config changes stay quiet",
      st.ink("OK") in d.cards["ok"].title.styleSheet() and st.ink("WARN") in d.cards["warn"].title.styleSheet() and st.ink("FAIL") in d.cards["fail"].title.styleSheet()
      and not d.cards["devices"].title.styleSheet() and not d.cards["changes"].title.styleSheet())

print("== Needs attention")
t = d.attention
check("the status chip comes first, then the device in bold, and there is no heading row", t.item(0, 0).text() == "ERROR" and t.item(0, 1).text() == "dist-sw2" and t.item(0, 1).font().bold()
      and not t.horizontalHeader().isVisible() and t.itemDelegateForColumn(0) is not None, (t.item(0, 0).text(), t.item(0, 1).text()))
check("the title counts the devices", d.attention_panel.count.text() == "3 devices", d.attention_panel.count.text())
check("the list is as tall as its rows, so the panel ends under the last device", t.height() == 3 * D.ATTENTION_ROW + 2 * t.frameWidth() + 2 and t.height() < 160, t.height())
b = d.row_actions(2)
check("the row buttons are bordered, with a ... for acknowledge and snooze", b["open"].property("outline") and b["run"].property("outline") and b["connect"].text() == "SSH"
      and b["more"].text() == "···" and b["more"].toolTip() == "More: open, run checks, connect, ping, acknowledge or snooze" and b["more"].property("ghost"))
check("a firewall reached by API has no Connect; a switch has SSH", d.row_actions(1)["connect"] is None and d.row_actions(2)["connect"].text() == "SSH")
check("the Checked time is quiet", t.item(0, 3).foreground().color().name() == theme.current()["muted"].lower())
down = d.row_actions(0)
check("a device Toner could not reach offers Open and Ping; Run checks and SSH wait in its ... menu", down["open"].text() == "Open" and down["run"] is None
      and down["connect"].text() == "Ping" and down["more"] is not None, {k: (x.text() if x else None) for k, x in down.items()})
check("...and says for how long it has been down, and why", t.item(0, 2).text() == "Down for 1 min: timeout", t.item(0, 2).text())
check("...with the time it started in the tooltip", t.item(0, 2).toolTip().startswith("Toner could not connect to it since 20") and t.item(0, 2).toolTip().endswith("."),
      t.item(0, 2).toolTip())
check("only the device Toner could not reach pulses on the map", d.map.down == {"dist-sw2"} and (d.map._anim is not None or not D.motion.enabled()))
w.resize(1900, 1000); app.processEvents(); app.processEvents()
shown = lambda dash, row: [k for k, x in dash.row_actions(row).items() if x is not None and x.isVisibleTo(dash.attention)]
check("a wide window shows every row button and the Checked time", not t.isColumnHidden(4) and not t.isColumnHidden(3) and shown(d, 2) == ["open", "run", "connect", "more"],
      (t.viewport().width(), shown(d, 2)))
LEVELS = [(True, ("open", "run", "connect", "more")), (False, ("open", "run", "connect", "more")), (False, ("open", "more")), (False, ("more",))]
narrow = D.DashboardTab(); narrow.show(); tn = narrow.attention
seen = []
for wide in (1800, 1100, 900, 760, 640, 560, 420):
    narrow.resize(wide, 700); app.processEvents(); app.processEvents()
    seen.append((tn.viewport().width(), LEVELS.index((not tn.isColumnHidden(3), tuple(shown(narrow, 2))))))
    words = tn.columnWidth(2)
    check(f"at {wide} wide the row keeps a button to act on, and room for what is wrong", not tn.isColumnHidden(4) and "more" in shown(narrow, 2)
          and (words >= D.ATTENTION_WORDS or shown(narrow, 2) == ["more"]), (wide, seen[-1], words))
by_width = [level for _w, level in sorted(seen, reverse=True)]
check("a narrower list never shows more than a wider one", by_width == sorted(by_width), seen)
narrow.resize(2600, 700); app.processEvents(); app.processEvents()      # wide enough for everything, then less and less room
words, levels = D.ATTENTION_WORDS, []
for need in range(0, 2600, 10):                              # less and less room beside "What is wrong", whatever the fonts
    D.ATTENTION_WORDS = need
    narrow._fit_columns()
    levels.append(LEVELS.index((not tn.isColumnHidden(3), tuple(shown(narrow, 2)))))
D.ATTENTION_WORDS = words; narrow._fit_columns()
check("as room runs out, the Checked time goes first, then Run checks and SSH, then Open", [x for i, x in enumerate(levels) if i == 0 or x != levels[i - 1]] == [0, 1, 2, 3], levels)
narrow.resize(1800, 700); app.processEvents(); app.processEvents()
check("...and it all comes back", not tn.isColumnHidden(3) and shown(narrow, 2) == ["open", "run", "connect", "more"], shown(narrow, 2))
narrow.close()
db.save_run([Result("core-sw1", "cpu", "OK", "5%"), Result("edge-fw", "wan links", "OK", "2/2"), Result("pc-1", "disk C:", "OK", "40%"), Result("dist-sw2", "connection", "OK", "")])
d.refresh(); app.processEvents()
check("nothing to show: the hint has room and the count is blank", t.rowCount() == 0 and t.height() == D.ATTENTION_EMPTY + 2 and d.attention_panel.count.text() == "" and d.hint.isVisibleTo(d))
check("with every device reached, nothing pulses", not d.map.down and d.map._anim is None)

print("== the count on the Results row")
db.save_run([Result("core-sw1", "cpu", "WARN", "86%"), Result("edge-fw", "wan links", "FAIL", "1/2", "down: wan2"), Result("pc-1", "disk C:", "OK", "40%"),
             Result("dist-sw2", "connection", "ERROR", "", "timeout")])
d.refresh(); app.processEvents()
i = w.tabs.indexOf(w.results)
check("the sidebar draws the number of devices needing attention on Results", w.tabs.count_for_row(w.tabs.row_of(i)) == 3 and w.tabs._counts.get(i) == 3)
tip = w.tabs.item_for(w.results).toolTip()
check("the badge is red while something fails, and says what it counts", w.tabs.tone_for_row(w.tabs.row_of(i)) == "FAIL"
      and tip.endswith("\n3 devices need attention: 2 failing, 1 with a warning") and "Ctrl+2" in tip, tip)
check("...the dot on About still works as before", (w.tabs.setBadge(w.about, True), w.tabs.item_for(w.about).text().endswith("●"))[1])
w.tabs.setBadge(w.about, False)
from core import acks
acks.put_aside("dist-sw2", db.device_health()["dist-sw2"]["problems"], None); d.refresh(); app.processEvents()
check("a device put aside leaves the count (and the list)", w.tabs._counts.get(i) == 2 and t.rowCount() == 2)
for n in ("edge-fw", "dist-sw2"):
    acks.put_aside(n, db.device_health()[n]["problems"], None)
d.refresh(); app.processEvents()
check("with only a warning left, the badge turns amber", w.tabs._counts.get(i) == 1 and w.tabs.tone_for_row(w.tabs.row_of(i)) == "WARN"
      and w.tabs.item_for(w.results).toolTip().endswith("1 device needs attention: 1 with a warning"), w.tabs.item_for(w.results).toolTip())
for n in ("edge-fw", "dist-sw2"):
    acks.clear(n)
d.refresh(); app.processEvents()

print("== down means Toner could not connect")
check("edge-fw failed a check but answered, so only dist-sw2 is down", d.map.down == {"dist-sw2"} and d.map.summary == "1 of 4 down", (d.map.down, d.map.summary))
check("the summary says what down means", d.map_summary.toolTip() == "Down: Toner could not connect to it in the last run.")
bars = {r[0]: r for r in d.bars.rows}
check("Availability is how often a device was reached: edge-fw's FAIL leaves it at 100 %; dist-sw2 was reached once in three runs",
      bars["edge-fw"][1] == 100 and bars["edge-fw"][2] == "Reached in 3 of 3 runs" and bars["dist-sw2"][2] == "Reached in 1 of 3 runs", bars)

print("== the status bar counts checks")
from ui.statusstrip import StatusStrip
said = StatusStrip._counts(db.last_run())
check("it says how many checks ran, then the problems", said.startswith("4 checks, ") and "1 FAIL" in said and "1 ERROR" in said and "1 WARN" in said, said)
check("...and 'all OK' after the count when nothing is wrong", StatusStrip._counts({"ok": 1, "warn": 0, "fail": 0, "error": 0}).startswith("1 check, ")
      and "all OK" in StatusStrip._counts({"ok": 1}))

print("== FAIL and ERROR are separate chips")
w.go("Results"); app.processEvents()
R = w.results
check("the chips count checks, FAIL apart from ERROR", [R.chips.labels[k].text() for k in R.chips.KEYS] == ["All 4 checks", "1 OK", "1 WARN", "1 FAIL", "1 ERROR"],
      [R.chips.labels[k].text() for k in R.chips.KEYS])
R.chips.pick("FAIL"); app.processEvents()
listed = {R.table.topLevelItem(k).text(0) for k in range(R.table.topLevelItemCount())}
check("FAIL lists only FAIL", listed == {"edge-fw"}, listed)
R.chips.pick("ERROR"); app.processEvents()
listed = {R.table.topLevelItem(k).text(0) for k in range(R.table.topLevelItemCount())}
check("ERROR lists only ERROR", listed == {"dist-sw2"}, listed)
R.chips.pick("ERROR"); app.processEvents()
check("Scanning's All chip has no noun", w.scanning.chips.labels["ALL"].text().startswith("All ") and "checks" not in w.scanning.chips.labels["ALL"].text())
w.go("Overview"); app.processEvents()

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
