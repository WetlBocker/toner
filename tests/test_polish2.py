# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Polish found by looking at every section: layout slips, wording and small helps.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\pol%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roamingpol%d" % int(time.time()))
from core import db, display
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
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)

print("== wording")
check("a check name that ends in a colon does not get a second", display.said("Disk D:", "very high") == "Disk D: very high" and display.said("cpu", "high") == "cpu: high" and display.said("cpu", "") == "cpu")

acme, zeta = db.create_folder("Acme"), db.create_folder("Zeta")
sub = db.create_folder("Branch", parent_id=acme)
def dev(name, folder, vendor="cisco"):
    db.save_device(dict(name=name, vendor=vendor, host="10.0.0.%d" % (len(db.list_devices()) + 1), port=0, platform="", username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=folder, tags="", fields=""))
for n, f in (("a-sw", acme), ("a-fw", sub), ("z-sw", zeta), ("z-ok", zeta)): dev(n, f)
db.save_run([Result("a-sw", "cpu", "OK", "5%"), Result("a-fw", "disk D:", "FAIL", "97% used", "very high"), Result("a-fw", "cpu", "WARN", "80%", "high"), Result("z-sw", "connection", "ERROR", "", "timeout"), Result("z-ok", "cpu", "OK", "3%")])

w = A.Main(); w.resize(1300, 820); w.show(); app.processEvents()

print("== Results: a device with one check is one row")
rt = w.results; rt.results = [Result("a-sw", "cpu", "OK", "5%"), Result("z-sw", "connection", "ERROR", "", "timeout"), Result("a-fw", "disk D:", "FAIL", "97% used", "very high"), Result("a-fw", "cpu", "WARN", "80%", "high")]
rt.last_ran = ["a-sw", "z-sw", "a-fw"]; rt.repopulate()
tops = {rt.table.topLevelItem(i).text(0): rt.table.topLevelItem(i) for i in range(rt.table.topLevelItemCount())}
check("it shows the check, its value and message, and has nothing to open", tops["z-sw"].text(1) == "connection" and tops["z-sw"].text(4) == "timeout" and tops["z-sw"].childCount() == 0 and tops["a-sw"].text(1) == "cpu" and tops["a-sw"].text(3) == "5%")
check("a device with several still opens to list them, and the summary reads 'Disk D: very high'", tops["a-fw"].childCount() == 2 and tops["a-fw"].text(4).startswith("disk D: very high"), tops["a-fw"].text(4))
from ui.results import ROLE
check("the row stands for its check in the right-click menu", tops["z-sw"].data(1, ROLE) == "check" and tops["a-fw"].data(1, ROLE) is None)

print("== Inventory: a closed folder says what is wrong inside it")
inv = w.inventory; inv.refresh()
def folder_rows():
    out = {}
    def walk(it):
        for i in range(it.childCount()):
            c = it.child(i)
            if inv.kind_of(c)[0] == "folder": out[c.text(0).split("  (")[0]] = c
            walk(c)
    for i in range(inv.table.topLevelItemCount()):
        t = inv.table.topLevelItem(i)
        if inv.kind_of(t)[0] == "folder": out[t.text(0).split("  (")[0]] = t
        walk(t)
    return out
fr = folder_rows()
check("Acme (the problem is in its sub-folder) says 1 FAIL", fr["Acme"].text(inv.STATUS) == "1 FAIL", fr["Acme"].text(inv.STATUS))
check("the sub-folder says it too, and a folder with an ERROR says so", fr["Branch"].text(inv.STATUS) == "1 FAIL" and fr["Zeta"].text(inv.STATUS) == "1 ERROR")
check("a healthy folder says nothing", (db.create_folder("Calm") and (inv.refresh() or True)) and folder_rows()["Calm"].text(inv.STATUS) == "")
from ui import status as st
fr2 = folder_rows()
check("it is coloured like the status", fr2["Zeta"].foreground(inv.STATUS).color().name() == st.ink("ERROR") and fr2["Acme"].foreground(inv.STATUS).color().name() == st.ink("FAIL"), fr2["Zeta"].foreground(inv.STATUS).color().name())

print("== the sidebar fits the window")
nav = w.tabs; h42 = {nav.list.item(i).sizeHint().height() for i in range(nav.list.count())}
check("in a tall window every row is the full 42 px", h42 == {42}, h42)
w.resize(900, 560); app.processEvents(); app.processEvents()
rows = [nav.list.item(i).sizeHint().height() for i in range(nav.list.count())]
check("in a short one the rows are squeezed (not below 30) so the last sections stay in view", max(rows) < 42 and min(rows) >= 30 and sum(rows) <= nav.list.height(), (rows, nav.list.height()))
last = nav.list.visualItemRect(nav.list.item(nav.list.count() - 1))
check("About is inside the list", last.bottom() <= nav.list.viewport().height() + 2, (last, nav.list.viewport().height()))
w.resize(1300, 820); app.processEvents(); app.processEvents()
check("and they spread out again", {nav.list.item(i).sizeHint().height() for i in range(nav.list.count())} == {42})

print("== History and Configs")
w.go("History"); app.processEvents(); app.processEvents()
hy = w.history
check("History's header sits at the top of the page", hy.layout().itemAt(0).widget().geometry().top() < 40, hy.layout().itemAt(0).widget().geometry())
w.go("Configs"); app.processEvents(); app.processEvents()
cf = w.configs
fm = cf.devs.fontMetrics()
check("the Configs device list keeps room for every name and its State column", all(cf.devs.columnWidth(0) >= fm.horizontalAdvance(cf.devs.item(r, 0).text()) for r in range(cf.devs.rowCount())) and cf.devs.columnWidth(4) >= 60 and cf.devs.rowCount() >= 4, [cf.devs.columnWidth(i) for i in range(5)])

print("== the rest")
w.go("Overview"); app.processEvents()
check("Overview says when the last run was in words, like the rest of the window", "ago" in w.dashboard.when.text() or "just now" in w.dashboard.when.text(), w.dashboard.when.text())
w.go("Sessions"); app.processEvents()
ss = w.sessions
check("with nothing saved the list says how to start, and the footer does not repeat the header", ss.tree_hint.isVisible() and ss.note.text() == "")
ss.search.setText("zzz"); app.processEvents()
check("a search that finds nothing says so", ss.note.text() == "No session matches.")
ss.search.setText("")
w.go("Settings"); w.settings.select_page("General"); app.processEvents()
gp = next(p for p in w.settings.pages if p.title == "General")
from PySide6.QtWidgets import QLabel
heads = [l.text() for l in gp.findChildren(QLabel) if l.text() in ("STORED DATA", "RUNNING", "DEVICES AND SCANS")]
check("General is grouped under three headings, with the retention note under the retention boxes", heads == ["STORED DATA", "RUNNING", "DEVICES AND SCANS"] and any("older than this are deleted" in l.text() for l in gp.findChildren(QLabel)))
w.open_device_view(db.list_devices()[0]); app.processEvents()
v = next(iter(w.views.values()))
check("the device window has margins like the main window", v.layout().contentsMargins().left() >= 16 and v.layout().contentsMargins().top() >= 12)
v.close()

print("== selection colour")
from ui import theme
t = theme.current()
check("the selected-row colour is one solid colour, not see-through", t["select"].startswith("#") and len(t["select"]) == 7 and t["select"] != t["surface"], t.get("select"))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
