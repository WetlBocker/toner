# Run directly (python tests/test_layout_wrappers.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# A layout item read through itemAt keeps its Python wrapper while C++ deletes the item (removeRow, a deleted widget); a new object
# at that address then comes back as the dead item, or crashes. Toner's own readers (the screen-reader names, the Save list) let go.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "laywrap%d.db" % int(time.time())); os.environ["APPDATA"] = SP
from core import db
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
from PySide6.QtWidgets import QApplication, QComboBox, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QVBoxLayout, QWidget
from shiboken6 import Shiboken
app = QApplication([])
from ui import settings_diff as SD
from ui.widgets import FlowLayout, KeyboardAccess, layout_at, widget_at
from ui.settings_base import Page

def items_held():
    """Layout items PySide still holds a wrapper for."""
    return [o for o in Shiboken.getAllValidWrappers() if type(o).__name__ in ("QWidgetItem", "QSpacerItem", "QLayoutItem")]

print("== widget_at and layout_at")
host = QWidget(); form = QFormLayout(host)
bar = QHBoxLayout(); bar.addWidget(QLineEdit()); form.addRow(QLabel("Name"), QLineEdit()); form.addRow("Pair", bar)
check("widget_at gives the widget of a row's role", widget_at(form, 0, QFormLayout.ItemRole.LabelRole).text() == "Name"
      and isinstance(widget_at(form, 0, QFormLayout.ItemRole.FieldRole), QLineEdit))
check("layout_at gives a nested layout, and it stays usable", layout_at(form, 1, QFormLayout.ItemRole.FieldRole) is bar and bar.count() == 1)
check("widget_at by index on a plain layout", isinstance(widget_at(bar, 0), QLineEdit) and widget_at(bar, 5) is None)
check("no item wrappers are kept after reading", items_held() == [], items_held())
while form.rowCount():
    form.removeRow(0)
check("so clearing the form leaves nothing pointing at deleted items", items_held() == [])

print("== the screen-reader names (KeyboardAccess, as main() installs it)")
app._keys = KeyboardAccess(app); app.installEventFilter(app._keys)
page = QWidget(); lay = QVBoxLayout(page)
for k in range(3): lay.addWidget(QLabel(f"row {k}"))
box = QLineEdit(); lay.addWidget(box)                                  # no form label: the namer looks through the layout
rows = QWidget(); rf = QFormLayout(rows); lay.addWidget(rows)
for k in range(3): rf.addRow(QLabel(""), QComboBox())                 # rows whose label is empty: it keeps looking
named = QWidget(); outer = QVBoxLayout(named); nf = QFormLayout(); outer.addLayout(nf); lay.addWidget(named)
field = QLineEdit(); nf.addRow("Server:", field)                     # the form sits inside the page's own layout
page.show(); app.processEvents()
check("a box is still named by its form label, found inside a nested layout", field.accessibleName() == "Server", field.accessibleName())
check("naming the boxes keeps no item wrappers", items_held() == [], len(items_held()))

print("== the Save list (settings_diff.snapshot)")
pg = Page(); pg.form.addRow("Secret", QLineEdit()); two = QHBoxLayout(); two.addWidget(QLineEdit()); two.addWidget(QComboBox()); pg.form.addRow("Both", two)
snap = SD.snapshot(pg)
check("the page reads as before", set(snap) == {"Secret", "Both"}, snap)
check("reading it keeps no item wrappers", items_held() == [], len(items_held()))

print("== a layout written in Python (FlowLayout)")
flow_host = QWidget(); flow = FlowLayout(); flow_host.setLayout(flow)
for t in "abc": flow.addWidget(QLabel(t))
check("it keeps its own items: reading them leaves them usable",
      [widget_at(flow, i).text() for i in range(flow.count())] == ["a", "b", "c"] and all(Shiboken.isValid(flow.itemAt(i)) for i in range(flow.count()))
      and flow.heightForWidth(300) > 0)

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
