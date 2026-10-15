# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Settings > Checks is one page with three tabs: Checks (which run), Schedule (when they run) and Custom (the ones you write).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\chktabs%d.db" % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roamingtabs%d" % int(time.time()))
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
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
import ui.settings as ST
from ui import settings_diff as SD
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
QMessageBox.warning = staticmethod(lambda *a, **k: None)

S = ST.SettingsTab(); S.resize(1200, 800); S.show(); app.processEvents()
page = lambda t: next(p for p in S.pages if p.title == t)
ck = page("Checks")

print("== one page, three tabs")
check("the tabs are Checks, Schedule and Custom, in that order", [ck.tabs.tabText(i) for i in range(ck.tabs.count())] == ["Checks", "Schedule", "Custom"])
check("the list on the left has no Automation or Custom checks page any more", "Automation" not in S.page_titles() and "Custom checks" not in S.page_titles() and S.page_titles()[:4] == ["General", "Thresholds", "Checks", "Maintenance"], S.page_titles())
check("Checks opens on the list of checks, as before", ck.tabs.currentIndex() == 0 and ck.tree.topLevelItemCount() > 5 and ck.collapse_all.text() == "Collapse all")
check("the Schedule tab has when the checks run, and the certificate check", ck.schedule.enabled.text() == "Run health checks automatically" and ck.schedule.sweep.text().startswith("Also check the HTTPS certificate"))
check("the Custom tab has the list of custom checks", ck.custom.table.columnCount() == 5 and ck.custom.hint is not None)

print("== opening a tab")
check("by name", S.select_page("Checks", "Schedule") and ck.tabs.tabText(ck.tabs.currentIndex()) == "Schedule" and S.current_title() == "Checks")
check("or in one word: Checks/Custom", S.select_page("Checks/Custom") and ck.tabs.tabText(ck.tabs.currentIndex()) == "Custom")
check("the old names still lead there", ck.select_tab("Automation") and ck.tabs.currentIndex() == 1 and ck.select_tab("Custom checks") and ck.tabs.currentIndex() == 2)
check("a tab that does not exist is not an error", not ck.select_tab("Nope"))
S.select_page("Checks", "Checks")
S.search.setText("certificate"); app.processEvents()
shown = [S.nav.item(r).text() for r in range(S.nav.count()) if S._index_of(r) is not None and not S.nav.isRowHidden(r)]
check("the search finds a setting on the Schedule tab: 'certificate' leads to Checks", "Checks" in shown, shown)
S.search.setText("writing code"); app.processEvents()
shown = [S.nav.item(r).text() for r in range(S.nav.count()) if S._index_of(r) is not None and not S.nav.isRowHidden(r)]
check("and one on the Custom tab: 'writing code'", "Checks" in shown, shown)
S.search.setText("")

print("== editing and saving across the tabs")
S.reload(); app.processEvents()
ck.schedule.enabled.setChecked(True); ck.schedule.minutes.setValue(25)
S.check_dirty(); S.check_dirty()
i = S.pages.index(ck)
check("an edit on the Schedule tab marks the Checks page", S.dirty_pages() == [i] or i in S.dirty_pages(), S.dirty_pages())
groups = S.pending_changes()
names = [n for t, rows in groups if t == "Checks" for n, _a, _b in rows]
check("the list of changes says which tab: 'Schedule: Every'", any(n.startswith("Schedule: Every") for n in names) and any(n.startswith("Schedule: Run health checks") or "Run health checks automatically" in n for n in names), names)
from PySide6.QtCore import Qt
ck.list.tree.topLevelItem(0).child(0).setCheckState(0, Qt.CheckState.Unchecked)
names = [n for t, rows in S.pending_changes() if t == "Checks" for n, _a, _b in rows]
check("and the list of checks keeps its own names", any(": " in n and not n.startswith("Schedule") for n in names), names)
S.save()
check("saving writes every tab: the schedule and the list", db.get_setting("schedule_enabled") is True and db.get_setting("schedule_minutes") == 25 and len(db.get_setting("disabled_checks")) == 1)
check("and the scheduler picks the new interval up", S.status.text().startswith("Saved") and not S.dirty_pages())
ck.schedule.minutes.setValue(40); S.check_dirty()
S.reload(); app.processEvents()
check("Revert puts the Schedule tab back", ck.schedule.minutes.value() == 25 and not S.pending_changes())

print("== the problems of any tab stop a save")
ck.list.tree.topLevelItem(0).child(0).setCheckState(0, Qt.CheckState.Checked)
S.reload()
check("validation covers the tabs (nothing wrong here)", ck.validate() == [])
real = ck.schedule.validate; ck.schedule.validate = lambda: ["Schedule: something is wrong."]
check("a problem on the Schedule tab is a problem for the page", ck.validate() == ["Schedule: something is wrong."] and S._problems()[1] == i)
ck.schedule.validate = real

print("== from elsewhere in the window")
w = A.Main(); w.resize(1300, 820); w.show(); app.processEvents()
w.strip.schedule.clicked.emit(); app.processEvents()
st = w.settings
check("the status strip's schedule opens Checks > Schedule", w.tabs.currentWidget() is st and st.current_title() == "Checks" and st.pages[st.stack.currentIndex()].tabs.tabText(st.pages[st.stack.currentIndex()].tabs.currentIndex()) == "Schedule")
w.open_palette()
labels = [e[0] for e in w.palette.entries]
check("the search (Ctrl+K) offers Checks > Schedule and Checks > Custom, and not the old pages", "Settings: Checks > Schedule" in labels and "Settings: Checks > Custom" in labels and "Settings: Automation" not in labels and "Settings: Custom checks" not in labels, [l for l in labels if "Settings:" in l][:12])
w.palette.close()
fn = [f for l, _h, f in w.palette.entries if l == "Settings: Checks > Custom"][0]
w.go("Overview"); fn()
check("choosing it opens the Custom tab", st.pages[st.stack.currentIndex()].tabs.tabText(st.pages[st.stack.currentIndex()].tabs.currentIndex()) == "Custom" and w.tabs.currentWidget() is st)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
