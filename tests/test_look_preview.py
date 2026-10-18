# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Settings > Appearance shows a theme or accent at once and puts the saved one back when the edit is dropped; any colour can be the
# accent; drop-down menus open upward when there is no room below; the import step shows the whole of each name.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "lookprev%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roaminglookprev%d" % int(time.time()))
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
from PySide6.QtCore import QPoint
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QApplication, QColorDialog, QMainWindow, QMenu, QMessageBox, QPushButton, QWidget
app = QApplication([])
import app as A
A.apply_look(app)
from ui import theme

print("== any colour as the accent")
check("a named accent is unchanged", theme.accent_pair("Rose") == theme.ACCENTS["Rose"])
light, dark = theme.accent_pair("#2a9d8f")
check("a chosen colour is used as it is in the light theme", light == "#2a9d8f")
check("and kept readable in the dark one", QColor(dark).lightness() >= 140, dark)
check("a very dark colour is lightened for the dark theme", QColor(theme.accent_pair("#101830")[1]).lightness() >= 140)
check("black still gets a usable colour in the dark theme", QColor(theme.accent_pair("#000000")[1]).lightness() > 0)
check("nonsense falls back to the default accent", theme.accent_pair("not a colour") == theme.ACCENTS[theme.DEFAULT_ACCENT]
      and theme.accent_pair(None) == theme.ACCENTS[theme.DEFAULT_ACCENT])
check("the tokens use the chosen colour", theme.tokens(False, "#2a9d8f")["accent"] == "#2a9d8f")
check("icons are brighter than muted text in the dark theme", QColor(theme.tokens(True)["icon"]).lightness() > QColor(theme.tokens(True)["muted"]).lightness())

print("== Settings > Appearance")
import ui.settings as ST
S = ST.SettingsTab(); S.resize(1200, 800); S.show(); app.processEvents()
page = next(p for p in S.pages if p.title == "Appearance")
shown, reset = [], []
S.look_preview.connect(lambda th, ac: shown.append((th, ac)))
S.look_reset.connect(lambda: reset.append(1))
check("the accent is chosen with a colour picker, showing its colour", isinstance(page.accent, QPushButton) and not page.accent.icon().isNull())
QColorDialog.getColor = staticmethod(lambda *a, **k: QColor("#2a9d8f"))
page.accent.click()
check("choosing a colour shows it at once", shown and shown[-1][1] == "#2a9d8f", shown)
check("it counts as an unsaved change", S.unsaved_count() >= 1, S.unsaved_count())
QColorDialog.getColor = staticmethod(lambda *a, **k: QColor())                  # the picker closed with Cancel
n = len(shown); page.accent.click()
check("cancelling the picker changes nothing", len(shown) == n and page.accent_value == "#2a9d8f")
other = next(t for t in theme.THEMES if t != page.theme.currentText())
page.theme.setCurrentText(other)
check("choosing a theme shows it at once, with the chosen accent", shown[-1] == (other, "#2a9d8f"), shown[-1])
S.cancel()
check("Cancel puts the saved look back", reset and page.accent_value == (db.get_setting("accent") or theme.DEFAULT_ACCENT)
      and page.theme.currentText() == db.get_setting("theme"))
n = len(shown); S.reload()
check("loading the saved values does not count as a preview", len(shown) == n)
QColorDialog.getColor = staticmethod(lambda *a, **k: QColor("#8e44ad"))
page.accent.click()
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
page.save()
check("Save stores the colour", db.get_setting("accent") == "#8e44ad")
S.reload(); page = next(p for p in S.pages if p.title == "Appearance")
check("and it comes back after a reload", page.accent_value == "#8e44ad")
A.apply_look(app)
check("the saved colour is the accent in use", theme.current()["accent"] == theme.tokens(theme.current()["dark"], "#8e44ad")["accent"])

print("== drop-down menus near the bottom")
from ui.widgets import MenuPlacer, place_menu
placer = MenuPlacer(app); app.installEventFilter(placer)
win = QMainWindow(); win.setGeometry(100, 100, 600, 400)
holder = QWidget(); win.setCentralWidget(holder); win.show(); app.processEvents()
low = QPushButton("New session", holder); low.setGeometry(20, 360, 120, 28); low.show()
high = QPushButton("More", holder); high.setGeometry(20, 10, 120, 28); high.show()
app.processEvents()
def menu_for(button):
    m = QMenu(button)
    for i in range(8):
        m.addAction(f"item {i}")
    return m
m = menu_for(low); m.move(low.mapToGlobal(QPoint(0, low.height()))); place_menu(m, low)
check("a menu that would run past the window's bottom opens above its button",
      m.y() + m.sizeHint().height() <= low.mapToGlobal(QPoint(0, 0)).y(), (m.y(), m.sizeHint().height(), low.mapToGlobal(QPoint(0, 0)).y()))
m2 = menu_for(high); below = high.mapToGlobal(QPoint(0, high.height())); m2.move(below); place_menu(m2, high)
check("one with room below stays below", m2.pos() == below, (m2.pos(), below))
m3 = menu_for(low); m3.popup(low.mapToGlobal(QPoint(0, low.height()))); app.processEvents()
check("menus are placed that way as they are shown, without each button doing it", m3.y() < low.mapToGlobal(QPoint(0, 0)).y(), m3.y())
m3.close()

print("== the import step shows each whole name")
from ui import orgassign
long_name = "core-switch-with-a-really-quite-long-name-" + "x" * 40
dlg = orgassign.OrgAssignDialog([(long_name, ["Acme", "Building 7"], "Device"), ("short", [], "Device")])
dlg.show(); dlg.tree.expandAll(); app.processEvents()
need = dlg.tree.fontMetrics().horizontalAdvance("Building 7/" + long_name)
check("the Name column fits the longest name", dlg.tree.columnWidth(0) >= need, (dlg.tree.columnWidth(0), need))
check("the window grew to show it", dlg.width() > 640, dlg.width())
check("but not past the screen", dlg.width() <= dlg.screen().availableGeometry().width())

print(f"\nRESULT: {ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
