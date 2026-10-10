# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Opens every section and every tool at the smallest window size (and a large one) and fails if controls overlap or run
# off the edge of their page.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_os.environ.setdefault("QT_QPA_FONTDIR", r"C:\Windows\Fonts")            # real text widths, as on a user's screen
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\lay%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import db
db.init()
import keyring
keyring.set_password = lambda *a: None
keyring.get_password = lambda *a: None
from PySide6.QtCore import QCoreApplication, QPoint
from PySide6.QtWidgets import (QAbstractItemView, QAbstractSpinBox, QApplication, QCheckBox, QComboBox, QLabel, QLineEdit,
                               QPushButton, QToolButton)
app = QApplication([])
import app as A
A.apply_look(app)

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def dev(name, vendor="cisco", host="10.0.0.1"):
    db.save_device(dict(name=name, vendor=vendor, host=host, port=0, platform="", username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="Chicago", details="", folder_id=None))
dev("core-sw1"); dev("edge-fw", "fortinet", "10.0.0.9")

CONTROLS = (QLineEdit, QPushButton, QComboBox, QAbstractSpinBox, QCheckBox, QToolButton, QLabel)
def inside_view(w):
    p = w.parent()
    while p is not None:
        if isinstance(p, QAbstractItemView): return True
        p = p.parent()
    return False
def is_ancestor(a, b):
    p = b.parent()
    while p is not None:
        if p is a: return True
        p = p.parent()
    return False
def settle():
    for _ in range(8):
        QCoreApplication.processEvents()
def problems(page):
    """Controls on `page` that overlap each other or stick out past its edges."""
    boxes = []
    seen = []
    for kind in CONTROLS:
        seen += [w for w in page.findChildren(kind) if w not in seen]
    for w in seen:
        if not w.isVisibleTo(page) or inside_view(w) or w.width() < 3 or w.height() < 3: continue
        if isinstance(w, QLabel) and not w.text().strip() and w.pixmap() is None: continue
        if w.isWindow() or w.objectName() in ("qt_scrollarea_viewport",): continue
        pos = w.mapTo(page, QPoint(0, 0)); boxes.append((w, pos.x(), pos.y(), pos.x() + w.width(), pos.y() + w.height()))
    out = []
    for i, (a, ax, ay, ax2, ay2) in enumerate(boxes):
        if ax2 > page.width() + 2: out.append(f"{type(a).__name__} '{getattr(a, 'text', lambda: '')()[:20]}' runs off the right edge ({ax2} > {page.width()})")
        for b, bx, by, bx2, by2 in boxes[i + 1:]:
            if is_ancestor(a, b) or is_ancestor(b, a): continue
            w_ = min(ax2, bx2) - max(ax, bx); h_ = min(ay2, by2) - max(ay, by)
            if w_ > 3 and h_ > 3:
                name = lambda x: f"{type(x).__name__} '{getattr(x, 'text', lambda: '')()[:18]}'"
                out.append(f"{name(a)} overlaps {name(b)} by {w_}x{h_}")
    return out

win = A.Main()
for size in ((900, 560), (1240, 760)):
    win.resize(*size); win.show(); settle()
    print(f"== window {size[0]} x {size[1]}")
    for i in range(win.tabs.count()):
        name = win.tabs.tabText(i)
        if name == "Settings": continue                      # forms inside a scrolling area
        win.tabs.setCurrentIndex(i); settle()
        page = win.tabs.currentWidget()
        if name == "Tools":
            for j in range(win.tools.tabs.count()):
                win.tools.tabs.setCurrentIndex(j); settle()
                sub = win.tools.tabs.currentWidget()
                p = problems(sub); check(f"Tools > {win.tools.tabs.tabText(j)}", not p, p[:3])
        else:
            p = problems(page); check(name, not p, p[:3])

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
