# Run directly (python tests/test_detaillist.py). The Over time tables (ui.detaillist): a column of numbers with blanks in it sorts the
# numbers as numbers and puts the blanks last, whichever way it is sorted.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "dl%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import db
db.init()
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
app = QApplication([])
from ui.detaillist import DetailList

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

t = DetailList()
t.show_rows([{"name": "a", "days": 30}, {"name": "b", "days": None}, {"name": "c", "days": 4}, {"name": "d", "days": 120},
             {"name": "e", "days": None}, {"name": "f", "days": -2}], [("name", "Certificate"), ("days", "Days left")])
names = lambda: [t.model().index(i, 0).data() for i in range(t.model().rowCount())]
t.sortByColumn(1, Qt.SortOrder.AscendingOrder)
check("Days left ascending: the numbers in order, the blanks last", names()[:4] == ["f", "c", "a", "d"] and set(names()[4:]) == {"b", "e"}, names())
t.sortByColumn(1, Qt.SortOrder.DescendingOrder)
check("...descending: the numbers the other way, the blanks still last", names()[:4] == ["d", "a", "c", "f"] and set(names()[4:]) == {"b", "e"}, names())
t.sortByColumn(0, Qt.SortOrder.DescendingOrder)
check("a text column still sorts as text", names() == ["f", "e", "d", "c", "b", "a"], names())
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
