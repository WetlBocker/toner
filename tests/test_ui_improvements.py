# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\uiimp%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
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
from PySide6.QtWidgets import QApplication, QLineEdit, QSpinBox, QCheckBox
from PySide6.QtCore import Qt
app = QApplication([])
import app as A
from drivers.base import Result
from ui import toast as T, settings as ST
A.apply_look(app)

def dev(name, vendor="cisco", **kw):
    d = dict(name=name, vendor=vendor, host=kw.pop("host", "10.0.0.1"), port=0, platform="", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1,
             location=kw.pop("location", ""), details="", tags=kw.pop("tags", ""))
    d.update(kw); db.save_device(d)

print("== getting started on the Overview")
w = A.Main(); w.resize(1180, 680); w.show()
check("a new installation shows the getting-started card", w.dashboard.start.isVisibleTo(w.dashboard))
check("no step is ticked yet", all(m.text() == "•" for m, _ in w.dashboard.steps.values()))
seen = []
w.dashboard.action.disconnect(w.dashboard_action)           # (that one would open the real Add dialog)
w.dashboard.action.connect(seen.append); w.dashboard.run_requested.connect(lambda: seen.append("run"))
for b in w.dashboard.start.findChildren(__import__("PySide6.QtWidgets", fromlist=["x"]).QPushButton):
    if b.text() in ("Add a device", "Scan the network", "Run checks", "Set up notifications"): b.click()
check("its buttons ask for the right things", seen == ["add", "scan", "run", "notify"], seen)
dev("core-sw1", location="HQ", tags="core"); dev("edge-fw", "fortinet", host="10.0.9.9"); dev("sql-01", "windows", host="sql.corp"); dev("old-ap", location="Lab")
w.inventory.refresh(); w.dashboard.refresh()
check("the first step ticks itself once there are devices", w.dashboard.steps["devices"][0].text() == "✓" and w.dashboard.start.isVisibleTo(w.dashboard))
db.save_run([Result("core-sw1", "cpu", "OK", "10%"), Result("edge-fw", "cpu", "FAIL", "99%", "too hot"), Result("sql-01", "disks", "WARN", "90%", "C: 90%"),
             Result("old-ap", "reachability", "ERROR", "", "timeout")])
w.dashboard.refresh()
check("and the second after a run", w.dashboard.steps["run"][0].text() == "✓")
w.dashboard._hide_start()
check("Hide keeps it away, even after a refresh", not w.dashboard.start.isVisibleTo(w.dashboard) and db.get_setting("onboarding_done") is True)
w.dashboard.refresh()
check("(it stays hidden)", not w.dashboard.start.isVisibleTo(w.dashboard))

print("== inventory: search and health dots")
inv = w.inventory
names = lambda: sorted(inv.payload[k]["name"] for k in inv.payload if k.startswith("device:"))
check("all four devices are listed", names() == ["core-sw1", "edge-fw", "old-ap", "sql-01"], names())
inv.search.setText("sw"); inv._search_timer.stop(); inv.refresh()
check("typing narrows the list (name part)", names() == ["core-sw1"], names())
inv.search.setText("10.0.9"); inv._search_timer.stop(); inv.refresh()
check("by address", names() == ["edge-fw"], names())
inv.search.setText("windows"); inv._search_timer.stop(); inv.refresh()
check("by vendor name", names() == ["sql-01"], names())
inv.search.setText("hq core"); inv._search_timer.stop(); inv.refresh()
check("several words must all match (location and tag)", names() == ["core-sw1"], names())
inv.search.setText("cisco lab"); inv._search_timer.stop(); inv.refresh()
check("words may come from different fields", names() == ["old-ap"], names())
inv.search.setText("nothing like this"); inv._search_timer.stop(); inv.refresh()
check("no match shows nothing", names() == [])
check("a search counts as a filter", inv.filtering())
inv.search.setText(""); inv._search_timer.stop(); inv.refresh()
check("clearing it brings everything back", len(names()) == 4 and not inv.filtering())
inv.search.setText("sw"); w.show(); inv._focus_search()
check("Ctrl+F selects what is in the box, ready to type over", inv.search.selectedText() == "sw")
inv.search.setText(""); inv._search_timer.stop(); inv.refresh()
by_name = {it.text(0): it for it in inv._all_items() if inv.kind_of(it)[0] == "device"}
check("every device has a health dot (icon) and a tooltip with the state", all(not it.icon(0).isNull() for it in by_name.values()) and "FAIL" in by_name["edge-fw"].toolTip(0)
      and "too hot" in by_name["edge-fw"].toolTip(0) and by_name["core-sw1"].toolTip(0).startswith("OK"), by_name["edge-fw"].toolTip(0))
check("the worst state decides the dot (the ERROR device says ERROR)", by_name["old-ap"].toolTip(0).startswith("ERROR"))
dev("quiet-one"); inv.refresh()
by_name = {it.text(0): it for it in inv._all_items() if inv.kind_of(it)[0] == "device"}
check("a device never checked has no state text", by_name["quiet-one"].toolTip(0) == "")
check("the less-used buttons are in a More menu so the row fits a narrow window", set(inv.more_actions) == {"Import...", "Import PuTTY sessions on this computer...", "Export...", "Expand all", "Collapse all"})

print("== results: what failed opens by itself")
from ui import results as R
tab = w.results
tab.last_ran = ["a", "b", "c"]; tab.results = [Result("a", "cpu", "FAIL", "1"), Result("b", "cpu", "OK", "1"), Result("c", "cpu", "WARN", "1")]
tab.expanded = set(); tab._active = True
tab.done()
check("the failing and warning devices are open, the healthy one is not", tab.expanded == {"a", "c"}, tab.expanded)
many = [Result(f"d{i:02d}", "cpu", "FAIL", "1") for i in range(30)]
tab.results = many; tab.last_ran = [r.device for r in many]; tab.expanded = set()
tab.done()
check("a long failing list opens only the first few, so the page stays usable", len(tab.expanded) == R.AUTO_OPEN, len(tab.expanded))
db.save_run([])

print("== settings: unsaved changes")
S = w.settings
w.go("Settings"); S.select_page("General"); S.reload()
for _ in range(3): app.processEvents()
check("freshly loaded: nothing is marked", S.dirty_pages() == [] and S.unsaved.text() == "")
gen = S.pages[0]
sp = gen.findChildren(QSpinBox)[0]; was = sp.value(); sp.setValue(was + 1)
S.check_dirty()
check("an edit marks the page and says so beside Save", S.dirty_pages() == [0] and "1 page" in S.unsaved.text(), (S.dirty_pages(), S.unsaved.text()))
row = next(r for r in range(S.nav.count()) if S.nav.item(r).text() == "General")
check("the page's entry in the list carries the mark", S.nav.item(row).data(ST.DIRTY) is True)
sp.setValue(was); S.check_dirty()
check("putting it back clears the mark", S.dirty_pages() == [] and S.unsaved.text() == "")
sp.setValue(was + 2); S.check_dirty(); S.save()
check("saving clears it and keeps the value", S.dirty_pages() == [] and S.unsaved.text() == "" and sp.value() == was + 2 and S.status.text().startswith("Saved"))
sp.setValue(was); S.check_dirty(); S.reload()
check("Revert drops the edit and the mark", sp.value() == was + 2 and S.dirty_pages() == [])
S.refresh_dynamic(); S.check_dirty()
check("a page that refilled its own lists is not an edit", S.dirty_pages() == [])
unstable = []
for i, p in enumerate(S.pages):
    S.stack.setCurrentIndex(i); app.processEvents(); S.check_dirty()
    if S._dirty.get(i): unstable.append(p.title)
check("no page marks itself as changed just by being looked at", not unstable, unstable)

print("== toasts")
n = len(T.history)
t = T.toast(S, "Deleted 3 session log(s).")
check("a toast says its text and is on screen", t.isVisible() and t.text() == "Deleted 3 session log(s)." and T.history[-1] == t.text() and len(T.history) == n + 1)
check("it sits inside the window, near the bottom", 0 <= t.x() and t.x() + t.width() <= w.width() and t.y() + t.height() <= w.height() and t.y() > w.height() // 2)
t2 = T.toast(S, "Another one")
check("a new one replaces the old (one at a time)", t2 is t and t.text() == "Another one")
long = T.toast(S, "word " * 80)
check("long text wraps inside the window", long.width() <= 560 and long.height() > 40)
T.toast(S, "x", problem=True)
check("a problem is red", "#b3261e" in t.styleSheet())
t.timer.stop(); t._start_fade(); t.fade.setCurrentTime(t.fade.duration()); app.processEvents()
check("it fades away by itself", not t.isVisible())
check("with no window to show in, it does nothing", T.toast(None, "x") is None)

print("== the window remembers its place and size")
w.resize(1010, 640); w.remember_layout()
check("the layout is stored (and is not part of an exported settings file)", bool(db.get_setting("window_geometry")) and "window_geometry" not in db.export_settings())
w2 = A.Main(); w2.show()
check("a new window opens at the remembered size, not the default (the test screen is small, so the width is clamped to it)", abs(w2.height() - 640) <= 40 and w2.width() < 1240, (w2.width(), w2.height()))
db.set_setting("window_geometry", "not base64 at all!"); w3 = A.Main()
check("a damaged value is ignored, not fatal", w3.width() > 0)

print("== Ctrl+K is visible")
got = []; w.tabs.search_requested.connect(lambda: got.append(1)); w.tabs.quick.click()
check("the sidebar has a Search button that shows the shortcut (on it, or in its tooltip when the font is too wide)",
      ("Ctrl+K" in w.tabs.quick.text() or "Ctrl+K" in w.tabs.quick.toolTip()) and got == [1], (w.tabs.quick.text(), w.tabs.quick.toolTip()))
check("each section's tooltip names its shortcut", "Ctrl+2" in w.tabs.list.item(1).toolTip() and "Ctrl+1" in w.tabs.list.item(0).toolTip())

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
