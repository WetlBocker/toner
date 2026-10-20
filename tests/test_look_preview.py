# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Settings > Appearance shows a theme at once and puts the saved one back when the edit is dropped (the Toner theme has one accent,
# with no setting for it); drop-down menus open upward when there is no room below; the import step shows the whole of each name.
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

print("== the Toner theme's accent")
check("there is one accent, the Toner theme's, in light and dark", theme.tokens(False)["accent"] == theme.ACCENT[0]
      and theme.tokens(True)["accent"] == theme.ACCENT[1] and theme.ACCENT == ("#0e7490", "#22d3ee"))
check("the Ops console uses it too", theme.tokens(True, theme.OPS)["accent"] == theme.ACCENT[1])
check("icons are brighter than muted text in the dark theme", QColor(theme.tokens(True)["icon"]).lightness() > QColor(theme.tokens(True)["muted"]).lightness())
check("no accent is stored any more", "accent" not in db.DEFAULT_SETTINGS and "accent" not in db.GLOBAL_ONLY)
check("an older settings export with one still imports, the accent left out", db.import_settings({"accent": "#8e44ad", "theme": "Dark"}) == (["theme"], ["accent"]))
db.set_setting("theme", "System")

print("== Settings > Appearance")
import ui.settings as ST
S = ST.SettingsTab(); S.resize(1200, 800); S.show(); app.processEvents()
page = next(p for p in S.pages if p.title == "Appearance")
shown, reset = [], []
S.look_preview.connect(lambda th: shown.append(th))
S.look_reset.connect(lambda: reset.append(1))
labels = [page.form.itemAt(i, page.form.ItemRole.LabelRole).widget().text() for i in range(page.form.rowCount())
          if page.form.itemAt(i, page.form.ItemRole.LabelRole) and page.form.itemAt(i, page.form.ItemRole.LabelRole).widget()]
check("there is no accent colour to choose", "Accent colour" not in labels and not hasattr(page, "accent") and "Theme" in labels, labels)
check("and the note no longer mentions one", not any("accent" in w.text().lower() for w in page.findChildren(ST.QLabel) if hasattr(w, "text")))
other = next(t for t in theme.THEMES if t != page.theme.currentText())
page.theme.setCurrentText(other)
check("choosing a theme shows it at once", shown and shown[-1] == other, shown[-1:])
check("it counts as an unsaved change", S.unsaved_count() >= 1, S.unsaved_count())
S.cancel()
check("Cancel puts the saved look back", reset and page.theme.currentText() == db.get_setting("theme"))
n = len(shown); S.reload()
check("loading the saved values does not count as a preview", len(shown) == n)
page.theme.setCurrentText("Dark")
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
page.save()
check("Save stores the theme", db.get_setting("theme") == "Dark")
S.reload(); page = next(p for p in S.pages if p.title == "Appearance")
check("and it comes back after a reload", page.theme.currentText() == "Dark")
A.apply_look(app)
check("the dark Toner theme is in use", theme.current()["dark"] and theme.current()["accent"] == theme.ACCENT[1])

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
check("but not past the screen (unless the screen is narrower than the window can be)",
      dlg.width() <= max(dlg.screen().availableGeometry().width(), dlg.minimumSizeHint().width()), (dlg.width(), dlg.screen().availableGeometry().width()))

print(f"\nRESULT: {ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
