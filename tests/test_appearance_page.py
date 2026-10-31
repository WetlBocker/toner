# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Settings > Appearance: the theme cards, the knobs, the preview, the unsaved mark and Cancel.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "appear%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingappear%d" % int(time.time()))
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
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
import app as A
from ui import theme, themes
A.apply_look(app)
w = A.Main(); w.resize(1300, 860); w.show(); app.processEvents()
w.go("Settings"); w.settings.select_page("Appearance"); app.processEvents()
page = next(p for p in w.settings.pages if p.title == "Appearance")
shown = []
w.settings.look_preview.connect(lambda look: shown.append(dict(look)))
settle = lambda: (app.processEvents(), time.sleep(0.2), app.processEvents())

print("== the cards")
check("one card per theme, grouped, System first", list(page.grid.cards) == themes.NAMES and page.grid.cards["System"].isChecked())
check("every card says what it is and explains itself on hover", all(c.toolTip() == themes.note(n) and c.accessibleName().startswith(n) for n, c in page.grid.cards.items()))
check("a card is not a setting of its own (the page reports the theme itself)", all(c.property("notSetting") for c in page.grid.cards.values()) and page.describe_extra() == [("Theme", "System")])
card = page.grid.cards["Lagoon"]
QTest.mouseClick(card, Qt.MouseButton.LeftButton); settle()
check("clicking a card previews that theme, once", card.isChecked() and page.grid.current() == "Lagoon" and len(shown) == 1 and shown[-1]["theme"] == "Lagoon"
      and theme.current()["name"] == "Lagoon" and theme.current()["bg"] == themes.FIXED["Lagoon"]["bg"], (len(shown), theme.current().get("name")))
w.settings.check_dirty()
check("the page is marked unsaved, naming the theme", w.settings.unsaved_count() == 1 and ("Theme", "System", "Lagoon") in [r for t, rows in w.settings.pending_changes() if t == "Appearance" for r in rows],
      w.settings.pending_changes())
img = card.grab().toImage()
check("the chosen card wears the accent ring", any(img.pixelColor(x, y).name() == theme.current()["accent"] for y in range(0, 5) for x in range(20, 140)))

print("== the knobs")
n = len(shown)
page.look.setCurrentText("Sharp"); page.panels.setCurrentText("Raised"); page.contrast.setCurrentText("Most"); page.motion.setCurrentText("Off"); settle()
check("a quick run through the boxes restyles the window once, with all of them", len(shown) == n + 1 and shown[-1]["look"] == "Sharp" and shown[-1]["panels"] == "Raised"
      and shown[-1]["contrast"] == "Most" and shown[-1]["motion"] == "Off", (len(shown) - n, shown[-1]))
check("...and the window has them", theme.current()["look"] == "Sharp" and theme.current()["raised"] and theme.current()["contrast"] == "Most" and theme.current()["motion"] == "Off")
w.settings.check_dirty()
names = [r[0] for t, rows in w.settings.pending_changes() if t == "Appearance" for r in rows]
check("each is listed for Save by its label", all(x in names for x in ("Theme", "Look", "Panels", "Contrast", "Motion")), names)

print("== Your colour")
check("its row is hidden while another theme is chosen", not page.custom_row.isVisibleTo(page))
page.grid.set_current("Your colour", emit=True); settle()
check("...and shown when it is", page.custom_row.isVisibleTo(page) and page.accent_btn.isVisibleTo(page) and page.base.isVisibleTo(page) and page.tint.isVisibleTo(page))
page.custom_accent = "#ff00aa"; page.paint_accent(); page._preview(); settle()
check("the accent you pick is previewed, and listed for Save", theme.current()["accent"] == "#ff00aa" and any(r[0] == "Accent" and r[2] == "#ff00aa"
      for t, rows in (w.settings.check_dirty(), w.settings.pending_changes())[1] if t == "Appearance" for r in rows), w.settings.pending_changes())
page.base.setCurrentText("Light"); settle()
check("a light base", not theme.current()["dark"])
page.tint.setChecked(True); settle()
check("a tinted base glows", theme.current()["glow"] and theme.current()["bg"] != themes.FIXED["Daylight"]["bg"])

print("== Cancel and Save")
w.settings.cancel(); settle()
check("Cancel puts everything back", theme.current()["name"] == "System" and theme.current()["look"] == "Standard" and page.grid.current() == "System" and page.look.currentText() == "Standard"
      and not page.custom_row.isVisibleTo(page) and w.settings.unsaved_count() == 0, (theme.current().get("name"), theme.current().get("look")))
page.grid.set_current("Mist", emit=True); page.look.setCurrentText("Soft"); page.motion.setCurrentText("Lively"); settle()
w.settings.save(); settle()
check("Save keeps the theme and the knobs", db.get_setting("theme") == "Mist" and db.get_setting("look") == "Soft" and db.get_setting("motion") == "Lively"
      and theme.current()["name"] == "Mist" and theme.current()["motion"] == "Lively")
w.settings.reload(); settle()
check("...and the page shows them after a reload", page.grid.current() == "Mist" and page.look.currentText() == "Soft" and page.motion.currentText() == "Lively")
check("the grid is not squeezed to a drop-down's width", page.grid.width() > 600, page.grid.width())

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
