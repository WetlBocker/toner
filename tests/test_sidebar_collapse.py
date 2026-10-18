# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
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

print("== the sidebar folds to icons")
w = A.Main(); w.resize(1180, 680); w.show(); app.processEvents()
n = w.tabs
check("it starts in full", not n.collapsed() and n.side.width() == nav.EXPANDED_WIDTH and n.list.item(0).text() == "Overview")
check("the brand and the Search text show", n.quick.text().startswith("Search") and not n._brand.isHidden())
n.fold.click(); app.processEvents()
check("the button folds it to a narrow strip", n.collapsed() and n.side.width() == nav.COLLAPSED_WIDTH)
check("the names are gone from the rows, and the brand and Search text with them", all(n.list.item(i).text() == "" for i in range(n.list.count())) and n._brand.isHidden() and n.quick.text() == "")
check("every row still has its icon", all(not n.list.item(i).icon().isNull() for i in range(n.list.count())))
check("the names move to the tooltips, with the shortcuts", n.list.item(0).toolTip().startswith("Overview") and "Ctrl+2" in n.list.item(1).toolTip())
check("the buttons are stacked, not side by side", n.bottom.direction() == nav.QBoxLayout.Direction.TopToBottom and not n.quick.icon().isNull() and not n.fold.icon().isNull())
check("the page is given the room", w.dashboard.width() >= 1180 - nav.COLLAPSED_WIDTH - 5, w.dashboard.width())
n.setCurrentIndex(2); check("sections can still be switched", n.currentIndex() == 2 and w.inventory.isVisible())
check("the choice is stored", db.get_setting("sidebar_collapsed") is True and "sidebar_collapsed" not in db.export_settings())

print("== a mark on a section shows on its icon while folded")
n.setBadge(w.about, True); i = n.indexOf(w.about)
check("the tooltip says something is new", "new" in n.list.item(i).toolTip() and n.list.item(i).text() == "")
n.setCollapsed(False)
check("unfolded, the dot is after the name again", n.list.item(i).text().endswith("●") and n.list.item(i).text().startswith("About") and "new" not in n.list.item(i).toolTip())
n.setBadge(w.about, False); check("and it clears", n.list.item(i).text() == "About")
check("unfolding restores the names, brand and Search", n.list.item(0).text() == "Overview" and not n._brand.isHidden() and n.quick.text().startswith("Search") and n.side.width() == nav.EXPANDED_WIDTH)
check("and the stored choice", db.get_setting("sidebar_collapsed") is False)
app.processEvents()
check("Search's words fit beside the collapse button, whatever the font", n.quick.width() >= n.quick.sizeHint().width() and n.fold.width() <= 40,
      (n.quick.text(), n.quick.width(), n.quick.sizeHint().width(), n.fold.width()))
big = n.quick.font(); big.setPointSize(16); n.quick.setFont(big); n._fit_quick(); app.processEvents()
check("with a much wider font it drops the spacing (and then the shortcut) rather than being cut off",
      n.quick.text() in nav.NavStack.QUICK_TEXTS[1:] and n.quick.width() >= n.quick.sizeHint().width() or n.quick.text() == "Search", (n.quick.text(), n.quick.width(), n.quick.sizeHint().width()))
n.quick.setFont(w.font()); n._fit_quick()

print("== Ctrl+B and the next start")
QTest.keyClick(w, Qt.Key.Key_B, Qt.KeyboardModifier.ControlModifier); app.processEvents()
check("Ctrl+B folds it", n.collapsed())
w2 = A.Main(); w2.show(); app.processEvents()
check("a new window opens folded, as it was left", w2.tabs.collapsed() and w2.tabs.side.width() == nav.COLLAPSED_WIDTH and w2.tabs.list.item(0).text() == "")
QTest.keyClick(w2, Qt.Key.Key_B, Qt.KeyboardModifier.ControlModifier); app.processEvents()
check("Ctrl+B opens it again", not w2.tabs.collapsed() and w2.tabs.list.item(0).text() == "Overview")
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
