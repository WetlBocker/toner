# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\rf%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db
db.init()
import keyring
keyring.set_password = lambda *a: None
keyring.get_password = lambda *a: None
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)
from ui.widgets import FilterButton

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def dev(name, vendor, loc, tags=""):
    db.save_device(dict(name=name, vendor=vendor, host="10.0.0.1", port=0, platform="", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location=loc, details="", folder_id=None, tags=tags))

print("== the widget on its own")
fb = FilterButton("Pick"); seen = []
fb.changed.connect(lambda: seen.append(1)); fb.set_sections({"A": [("one", 1), ("two", 2)], "B": []})
check("it starts with the tip and no count", fb.toolTip() == "Pick" and fb.text() == "" and not fb.filtering())
fb._build(); b_menu = [a for a in fb.menu.actions() if a.menu()][1]
check("an empty section is greyed out", not b_menu.isEnabled())
fb._toggle("A", 1, True); fb._toggle("A", 2, True); check("it emits when ticked", len(seen) == 2 and fb.describe() == "A: one, two" and fb.text().strip() == "2")
fb.set_sections({"A": [("two", 2)]}); check("set_sections does not emit and drops stale ticks", len(seen) == 2 and fb.selected("A") == {2})
fb.clear(); check("clear empties and emits", len(seen) == 3 and not fb.filtering())

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
