# Run directly (python tests/test_tablefit.py). Every table sizes its columns to fit: as wide as the longest text when there is room,
# sharing the width when there isn't (none under its heading), always draggable, a dragged column keeps its width, full text on hover.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "tf%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import db
db.init()
from PySide6.QtWidgets import QApplication, QHeaderView, QTableWidget, QTableWidgetItem, QTreeWidget, QTreeWidgetItem
app = QApplication([])

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

from ui.tablefit import fit_widths, fit, full_text_at, install_everywhere
check("room for everything: each column is its content width", fit_widths([80, 200, 50], [40, 60, 40], 1000) == [80, 200, 50])
w = fit_widths([80, 600, 300], [40, 60, 40], 500)
check("too narrow: they share the width exactly", sum(w) == 500, w)
check("...the widest gives way first, the small one is untouched", w[0] == 80 and w[1] < 600, w)
check("...none goes under its header", all(a >= h for a, h in zip(fit_widths([80, 600, 300], [70, 300, 200], 400), [70, 300, 200])))
t = QTableWidget(3, 2); t.setHorizontalHeaderLabels(["Name", "Message"])
t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
t.setItem(0, 1, QTableWidgetItem("x" * 120)); t.resize(2000, 300); t.show(); fit(t); app.processEvents()
check("a ResizeToContents header becomes Interactive, so it can be dragged", all(t.horizontalHeader().sectionResizeMode(i) == QHeaderView.ResizeMode.Interactive for i in range(2)))
check("the long column shows all its text", t.columnWidth(1) >= t.fontMetrics().horizontalAdvance("x" * 120))
t.horizontalHeader().resizeSection(0, 300)                      # the person drags it
t.setItem(1, 0, QTableWidgetItem("y")); app.processEvents(); app.processEvents()
check("a dragged column keeps its width after the data changes", t.columnWidth(0) == 300)

n = QTableWidget(2, 2); n.setHorizontalHeaderLabels(["A", "B"]); n.setItem(0, 0, QTableWidgetItem("z" * 200)); n.setItem(0, 1, QTableWidgetItem("short"))
n.resize(300, 200); n.show(); fit(n); app.processEvents()
check("too narrow for the table: the columns share the viewport", n.columnWidth(0) + n.columnWidth(1) == n.viewport().width(), (n.columnWidth(0), n.columnWidth(1), n.viewport().width()))
cell = n.visualRect(n.model().index(0, 0)).center()
check("a cut-off cell shows its full text on hover", full_text_at(n, cell) == "z" * 200)
check("a cell that fits shows no hover text", full_text_at(n, n.visualRect(n.model().index(0, 1)).center()) is None)

tr = QTreeWidget(); tr.setColumnCount(2); tr.setHeaderLabels(["Name", "Note"])
tr.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
tr.addTopLevelItem(QTreeWidgetItem(["a" * 60, "b"])); tr.resize(1500, 200); tr.show(); fit(tr); app.processEvents()
check("a tree's Stretch column is Interactive and fits its text", tr.header().sectionResizeMode(0) == QHeaderView.ResizeMode.Interactive and tr.columnWidth(0) >= tr.fontMetrics().horizontalAdvance("a" * 60))

install_everywhere(app)
p = QTableWidget(1, 1); p.setHorizontalHeaderLabels(["H"]); p.setItem(0, 0, QTableWidgetItem("q" * 80)); p.resize(1500, 200); p.show(); app.processEvents(); app.processEvents()
check("install_everywhere fits a table nobody called fit() on", p.horizontalHeader().sectionResizeMode(0) == QHeaderView.ResizeMode.Interactive and p.columnWidth(0) >= p.fontMetrics().horizontalAdvance("q" * 80))

print(f"\n{ok} passed, {bad} failed"); raise SystemExit(1 if bad else 0)
