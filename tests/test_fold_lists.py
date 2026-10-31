# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The page lists of Settings, Tools and Automation fold away to a small button, to give the page the width, and stay
# as they were left.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\fold%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
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
app = QApplication([])
import app as A
A.apply_look(app)
from ui import nav
from ui.settings import SettingsTab
from ui.tools import ToolsTab
from ui.automation import AutomationTab

print("== Settings")
s = SettingsTab(); s.resize(1100, 700); s.show(); app.processEvents()
page_w = s.stack.width()
check("it starts with the page list, the button beside the search box, saying what it does", s.list_shown() and s.search.isVisible() and s.fold.isVisible()
      and s.fold.toolTip() == "Hide the page list" and not s.fold.icon().isNull())
s.fold.click(); app.processEvents()
check("a click folds the list to its button and gives the page the room", not s.list_shown() and not s.search.isVisible() and s.fold.isVisible()
      and s.left.width() == nav.FOLD_WIDTH and s.stack.width() > page_w and s.fold.toolTip() == "Show the page list", (s.left.width(), page_w, s.stack.width()))
check("...and stays at the top of the column", s.fold.mapTo(s, s.fold.rect().topLeft()).y() < 40, s.fold.mapTo(s, s.fold.rect().topLeft()).y())
check("...and is remembered, for this installation only", db.get_setting("settings_list_hidden") is True and "settings_list_hidden" in db.GLOBAL_ONLY and "settings_list_hidden" in db.NOT_PORTABLE)
s2 = SettingsTab(); s2.show(); app.processEvents()
check("a new window opens it as it was left", not s2.list_shown() and s2.left.width() == nav.FOLD_WIDTH)
s2._focus_search(); app.processEvents()
check("Ctrl+F brings the list back to search it", s2.list_shown() and s2.search.isVisible() and db.get_setting("settings_list_hidden") is False)
s.fold.click(); app.processEvents()
check("a second click shows it again", s.list_shown() and s.left.width() == 200 and s.fold.toolTip() == "Hide the page list")

print("== Tools and Automation")
for name, make, attr, key, width in (("Tools", ToolsTab, "tabs", "tools_list_hidden", 228), ("Automation", AutomationTab, "pages", "automation_list_hidden", 200)):
    w = make(); w.resize(1100, 700); w.show(); app.processEvents()
    ps = getattr(w, attr)
    before = ps.stack.width()
    check(f"{name}: the list starts shown, the button above it", ps.list_shown() and ps.fold.isVisible() and ps.fold.toolTip() == "Hide the page list" and ps.side.width() == width)
    ps.fold.click(); app.processEvents()
    check(f"{name}: a click folds it, the page widens, the choice is kept", not ps.list_shown() and ps.side.width() == nav.FOLD_WIDTH and ps.stack.width() > before
          and ps.fold.toolTip() == "Show the page list" and db.get_setting(key) is True and key in db.GLOBAL_ONLY and ps.fold.mapTo(ps, ps.fold.rect().topLeft()).y() < 40,
          (ps.side.width(), before, ps.stack.width(), ps.fold.mapTo(ps, ps.fold.rect().topLeft()).y()))
    w2 = make(); again = getattr(w2, attr)                 # kept alive while it is looked at
    check(f"{name}: a new window opens it folded; pages still switch", not again.list_shown() and (again.setCurrentIndex(1), again.stack.currentIndex())[1] == 1)
    w2.close()
    ps.fold.click(); app.processEvents()
    check(f"{name}: a second click shows it again", ps.list_shown() and ps.side.width() == width and db.get_setting(key) is False)
    w.close()

readme = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "README.md"), encoding="utf-8").read()
check("the README says so", "the page list can be folded away" in readme)
from core.version import VERSION
check("version 1.12.0", VERSION == "1.12.0")

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
