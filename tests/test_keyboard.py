# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Toner by keyboard: Tab reaches the sidebar and gets out of lists, focus shows, and buttons that are only an icon have names.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "keyboard%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingkeys%d" % int(time.time()))
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
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QFormLayout, QLineEdit, QPushButton, QSpinBox, QWidget
from PySide6.QtTest import QTest
app = QApplication([])
import app as A
A.apply_look(app)
from ui.widgets import KeyboardAccess, RefreshButton
keys = KeyboardAccess(app); app.installEventFilter(keys)
for i, n in enumerate(("core-sw1", "edge-fw", "dist-sw2")):
    db.save_device(dict(name=n, vendor="cisco", host=f"10.0.0.{i + 1}", port=0, platform="cisco_ios", username="u", site="default",
                        verify_ssl=0, ha_expected=0, enabled=1, location="Chicago", details="", folder_id=None))
db.save_run([Result("core-sw1", "memory", "WARN", "86%", numeric=86.0), Result("edge-fw", "ha", "FAIL", "1/2", "Peer unit is not in sync"),
             Result("dist-sw2", "connection", "ERROR", "", "timeout")])
def pump(t=0.3):
    end = time.time() + t
    while time.time() < end:
        app.processEvents(); time.sleep(0.02)

w = A.Main(); w.resize(1440, 900); w.show(); w.activateWindow(); pump(1.0)
n = w.tabs

print("== Tab reaches the sidebar")
check("the sections list, Search and the fold button are reached by Tab, not by a click",
      all(x.focusPolicy() == Qt.FocusPolicy.TabFocus for x in (n.list, n.quick, n.fold)), [x.focusPolicy() for x in (n.list, n.quick, n.fold)])
seen = []
w.dashboard.setFocus(); pump(0.1)
for _ in range(60):
    w.focusNextChild(); seen.append(app.focusWidget())
check("walking with Tab comes to the sections list", n.list in seen, [type(x).__name__ for x in seen[:20]])
n.list.setFocus(); n.setCurrentIndex(0); pump(0.1)
QTest.keyClick(n.list, Qt.Key.Key_Down); pump(0.2)
check("the arrow keys move to the next section (past the group names)", n.currentWidget() is w.results, n.tabText(n.currentIndex()))
n.setCurrentIndex(0); pump(0.3)

print("== Tab gets out of a list")
t = w.dashboard.attention
check("Needs attention has its rows", t.rowCount() == 3, t.rowCount())
check("Tab does not move from cell to cell in a list that cannot be edited", not t.tabKeyNavigation())
t.setFocus(); t.selectRow(0); pump(0.1)
for _ in range(3):
    QTest.keyClick(app.focusWidget(), Qt.Key.Key_Tab); pump(0.05)
check("three presses of Tab leave the list", app.focusWidget() is not t and app.focusWidget() is not None, type(app.focusWidget()).__name__)
opened = []
w.dashboard.open_device.connect(opened.append)
t.setFocus(); t.selectRow(1); pump(0.1)
QTest.keyClick(t, Qt.Key.Key_Return); pump(0.1)
check("Enter opens the chosen row's device, as a double-click does", opened == [w.dashboard.names[1]], (opened, w.dashboard.names))
for top in app.topLevelWidgets():
    if top is not w and top.isVisible():
        top.close()
w.activateWindow(); pump(0.2)

print("== focus shows")
def looks_focused(widget, away=None):
    (away or n.quick).setFocus(Qt.FocusReason.TabFocusReason); pump(0.1); before = widget.grab().toImage()
    widget.setFocus(Qt.FocusReason.TabFocusReason); pump(0.1); after = widget.grab().toImage()
    return before != after
run = next(b for b in w.findChildren(QPushButton) if b.text() == "Run checks" and b.property("primary") and b.isVisible())
check("the accent button (Run checks) changes when it has focus", looks_focused(run))
check("a quiet button (Hide on the getting-started line) does", looks_focused(next(b for b in w.findChildren(QPushButton) if b.text() == "Hide" and b.isVisible())))
check("a list does", looks_focused(t))
check("the sections list does", looks_focused(n.list))
from PySide6.QtWidgets import QCheckBox
holder2 = QWidget(); hl = QFormLayout(holder2); other, box = QLineEdit(), QCheckBox("Tick me"); hl.addRow(other); hl.addRow(box)
holder2.show(); holder2.activateWindow(); pump(0.2)
check("a tick box does", looks_focused(box, other))
box.setChecked(True)
check("and a ticked one", looks_focused(box, other))
holder2.close()

print("== names for screen readers")
r = next(b for b in w.findChildren(RefreshButton) if b.isVisible())
check("Refresh, only an icon, is called by its tooltip", r.accessibleName() and r.accessibleName() == r.toolTip().split("\n")[0].strip(), (r.accessibleName(), r.toolTip()))
check("Refresh can be reached by Tab", r.focusPolicy() == Qt.FocusPolicy.TabFocus)
check("the fold button is called what it does", n.fold.accessibleName().startswith("Fold the sidebar to icons"), n.fold.accessibleName())
n.setCollapsed(True); pump(0.1)
check("...and the other thing once the sidebar is folded", n.fold.accessibleName().startswith("Show the sidebar in full"), n.fold.accessibleName())
n.setCollapsed(False)
check("a name given on purpose is kept", n.quick.accessibleName() == "Search Toner (Ctrl+K)", n.quick.accessibleName())
page = QWidget(); form = QFormLayout(page)
named, loose, spin = QLineEdit(), QLineEdit(), QSpinBox()
loose.setPlaceholderText("Search devices")
form.addRow("Host name:", named); form.addRow("Port", spin)
holder = QWidget(); QFormLayout(holder).addRow(loose)
page.show(); holder.show(); pump(0.1)
check("a box in a form is called by its label, without the colon", named.accessibleName() == "Host name" and spin.accessibleName() == "Port", (named.accessibleName(), spin.accessibleName()))
check("a box with no label is called by its placeholder", loose.accessibleName() == "Search devices", loose.accessibleName())
mine_page = QWidget(); mine = QLineEdit(); mine.setAccessibleName("My own"); QFormLayout(mine_page).addRow("Other", mine); mine_page.show(); pump(0.1)
check("and a box that has a name keeps it", mine.accessibleName() == "My own")

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
