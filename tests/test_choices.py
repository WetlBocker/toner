# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_os.environ.setdefault("QT_QPA_FONTDIR", r"C:\Windows\Fonts")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\cho%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtCore import QPoint, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

print("== a number box with common values to pick from")
from ui import settings_base as SB
box = SB.spin(1, 3650, " days", choices=(7, 30, 60, 90, 99999))
box.setValue(90); box.resize(170, 32); box.show(); app.processEvents()
names = [a.text() for a in SB.choices_menu(box).actions()]
check("the list offers the values in the box's own words, and none it cannot hold", names == ["7 days", "30 days", "60 days", "90 days"], names)
SB.choices_menu(box).actions()[1].trigger()
check("picking one sets the box", box.value() == 30 and box.text() == "30 days", box.text())
box.setValue(45)
check("any other number can still be typed", box.value() == 45 and box.text() == "45 days")
opened = []
box.findChild(SB.Choices).open = lambda: opened.append(1)
QTest.mouseClick(box, Qt.MouseButton.LeftButton, pos=QPoint(box.width() - 8, box.height() // 2))
check("the arrow at the right opens the list instead of stepping", opened == [1] and box.value() == 45, (opened, box.value()))
QTest.keyClick(box, Qt.Key.Key_F4); QTest.keyClick(box, Qt.Key.Key_Down, Qt.KeyboardModifier.AltModifier)
check("F4 and Alt+Down open it from the keyboard, as on a drop-down", opened == [1, 1, 1], opened)
QTest.keyClick(box, Qt.Key.Key_Up)
check("the arrow keys still step by one", box.value() == 46, box.value())
never = SB.spin(0, 168, " hours", choices=(0, 4, 24)); never.setSpecialValueText("never")
check("a box's word for its lowest value is used in the list", [a.text() for a in SB.choices_menu(never).actions()] == ["never", "4 hours", "24 hours"])
plain = SB.spin(1, 100)
check("a box without common values is as before", plain.findChild(SB.Choices) is None and not plain.property("choices"))
img = box.grab().toImage(); bg = img.pixelColor(box.width() // 2, 3)
def marks(y0, y1): return sum(1 for x in range(box.width() - 22, box.width() - 8) for y in range(y0, y1) if img.pixelColor(x, y) != bg)
check("one arrow is drawn, in the middle of the right edge, not two small ones", marks(box.height() // 2 - 4, box.height() // 2 + 5) > 0 and marks(3, 9) == 0 and marks(box.height() - 9, box.height() - 3) == 0,
      (marks(3, 9), marks(box.height() // 2 - 4, box.height() // 2 + 5), marks(box.height() - 9, box.height() - 3)))

print("== Settings > General: Keep run history")
from ui.settings_pages.general import GeneralPage
g = GeneralPage(); g.load()
check("Keep run history offers 7, 30, 60 and 90 days", [a.text() for a in SB.choices_menu(g.retention).actions()] == ["7 days", "30 days", "60 days", "90 days"])
g.retention.setValue(45); g.save()
check("and a number typed in is saved as before", db.get_setting("retention_days") == 45, db.get_setting("retention_days"))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
