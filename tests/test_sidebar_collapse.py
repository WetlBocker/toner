# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself, and the top bar fits its names by their width
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\sidebar%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
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
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence
from PySide6.QtTest import QTest
app = QApplication([])
import app as A
from ui import nav, settings as ST
from ui.settings_pages.general import ChecksPage
A.apply_look(app)

print("== the top bar shows icons only")
w = A.Main(); w.resize(1900, 760); w.show(); app.processEvents()
n = w.tabs
check("it starts with the icons and names", not n.list.item(0).icon().isNull() and not n.collapsed() and n.side.maximumHeight() == nav.BAR_HEIGHT and n.list.item(0).text() == "Overview")
from PySide6.QtCore import QPoint
check("the sections sit in a bar across the top, the page below it", n.side.mapTo(w, QPoint(0, 0)).y() < w.dashboard.mapTo(w, QPoint(0, 0)).y()
      and n.side.width() >= w.width() - 2)
check("the page is centred, no wider than the content width", w.dashboard.width() <= nav.CONTENT_WIDTH)
n.fold.click(); app.processEvents()
check("the button shows icons only", n.collapsed() and n._icons_only())
check("the names are gone from the tabs", all(n.list.item(i).text() == "" for i in range(n.list.count())))
check("every tab still has its icon", all(not n.list.item(i).icon().isNull() for i in range(n.list.count())))
check("the names move to the tooltips, with the shortcuts", n.list.item(0).toolTip().startswith("Overview") and "Ctrl+2" in n.list.item(1).toolTip())
check("Search is just its icon, with the shortcut in the tooltip", n.quick.text() == "" and not n.quick.icon().isNull() and "Ctrl+K" in n.quick.toolTip())
n.setCurrentIndex(2); check("sections can still be switched", n.currentIndex() == 2 and w.inventory.isVisible())
check("the choice is stored", db.get_setting("sidebar_collapsed") is True and "sidebar_collapsed" not in db.export_settings())

print("== a mark on a section shows on its icon while only icons show")
n.setBadge(w.about, True); i = n.indexOf(w.about)
check("the tooltip says something is new", "new" in n.list.item(i).toolTip() and n.list.item(i).text() == "")
n.setCollapsed(False)
check("with the names, the dot is after the name again", n.list.item(i).text().endswith("●") and n.list.item(i).text().startswith("About") and "new" not in n.list.item(i).toolTip())
n.setBadge(w.about, False); check("and it clears", n.list.item(i).text() == "About")
check("the names are back", n.list.item(0).text() == "Overview" and "Jump to a section" in n.quick.toolTip())
check("and the stored choice", db.get_setting("sidebar_collapsed") is False)

print("== a narrow window shows icons only by itself")
w.resize(700, 680); app.processEvents()
check("the names give way to icons", n._icons_only() and n.list.item(0).text() == "" and not n.collapsed())
check("the choice is not stored by that", db.get_setting("sidebar_collapsed") is False)
w.resize(1900, 760); app.processEvents()
check("and the names return when there is room", not n._icons_only() and n.list.item(0).text() == "Overview")

print("== Ctrl+B and the next start")
QTest.keyClick(w, Qt.Key.Key_B, Qt.KeyboardModifier.ControlModifier); app.processEvents()
check("Ctrl+B shows icons only", n.collapsed())
w2 = A.Main(); w2.resize(1900, 760); w2.show(); app.processEvents()
check("a new window opens that way, as it was left", w2.tabs.collapsed() and w2.tabs.list.item(0).text() == "")
QTest.keyClick(w2, Qt.Key.Key_B, Qt.KeyboardModifier.ControlModifier); app.processEvents()
check("Ctrl+B brings the names back", not w2.tabs.collapsed() and w2.tabs.list.item(0).text() == "Overview")
w2.tabs.restyle(); w.tabs.restyle()
check("a theme change keeps it as it is", w.tabs.collapsed() and not w.tabs.list.item(0).icon().isNull())

print("== Settings > Checks: Collapse all and Expand all")
p = ChecksPage(); p.resize(700, 600); p.show(); p.load(); app.processEvents()
t = p.tree
tops = [t.topLevelItem(i) for i in range(t.topLevelItemCount())]
check("the groups start open", len(tops) > 5 and all(x.isExpanded() for x in tops))
check("both buttons are there", p.collapse_all.text() == "Collapse all" and p.expand_all.text() == "Expand all")
p.collapse_all.click(); app.processEvents()
check("Collapse all folds every group", not any(x.isExpanded() for x in tops))
check("the group names are still listed", all(not t.visualItemRect(x).isEmpty() for x in tops[:3]))
before = p.describe_extra()
p.expand_all.click(); app.processEvents()
check("Expand all opens every group", all(x.isExpanded() for x in tops))
tops[0].child(0).setCheckState(0, Qt.CheckState.Unchecked); p.collapse_all.click(); app.processEvents()
saved = []
check("folded groups keep their ticks (saving reads them all)", any(r[1] == "off" for r in p.describe_extra()) and len(p.describe_extra()) == len(before))
p.save(); check("and they are saved", any(k.endswith(tops[0].child(0).data(0, Qt.ItemDataRole.UserRole).split(":", 1)[1]) for k in db.get_setting("disabled_checks")))
p.load(); app.processEvents()
check("reloading the page opens the groups again", all(x.isExpanded() for x in [t.topLevelItem(i) for i in range(t.topLevelItemCount())]))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
