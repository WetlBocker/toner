# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Status colours read in every theme and colour preset: a soft chip's word on its own tint, the ink on the panels and the page, and
# ERROR as the one solid chip. How long a device has been down is read from the stored runs. Each status has its own mark.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "marks%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingmarks%d" % int(time.time()))
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
from datetime import datetime
from PySide6.QtCore import QPointF
from PySide6.QtGui import QColor, QImage, QPainter
from PySide6.QtWidgets import QApplication
app = QApplication([])
from core import display, reports
from ui import status as st, theme, themes

print("== every theme, every colour preset")
low = []
for preset in reports.COLOR_PRESETS:
    reports.apply_colors(preset)
    for name in themes.NAMES:
        t = theme.tokens(dict(theme=name))
        theme._current.clear(); theme._current.update(t)
        for s in ("OK", "WARN", "FAIL", "ERROR"):
            ink = QColor(st.ink(s))
            for ground in ("surface", "bg"):
                if st.contrast(ink, QColor(t[ground])) < 4.5:
                    low.append((preset, name, s, "ink on " + ground, round(st.contrast(ink, QColor(t[ground])), 2)))
            bg, word = st.chip(s)
            under = st._over(bg, QColor(t["surface"])) if bg.alpha() < 255 else bg
            if st.contrast(word, under) < 4.5:
                low.append((preset, name, s, "chip", round(st.contrast(word, under), 2)))
check("status words read at 4.5:1 or better on the panels, the page and their own chips", not low, low[:8])
reports.apply_colors("Default")
theme._current.clear(); theme._current.update(theme.tokens(dict(theme="Midnight")))
check("ERROR is the one solid chip", st.chip("ERROR")[0].alpha() == 255 and all(st.chip(s)[0].alpha() < 255 for s in ("OK", "WARN", "FAIL")))
check("a tinted row stays soft even for ERROR", st.chip("ERROR", solid=False)[0].alpha() < 255)

print("== a mark per status")
def drawn(status):
    img = QImage(40, 40, QImage.Format.Format_ARGB32); img.fill(QColor("#000000"))
    p = QPainter(img); st.mark(p, QPointF(20, 20), status, 20, soft=False); p.end()
    return img
shapes = {s: drawn(s) for s in ("OK", "WARN", "FAIL", "ERROR")}
check("the four marks differ in shape, not just colour", len({bytes(QImage(img).convertToFormat(QImage.Format.Format_Grayscale8).bits()) for img in shapes.values()}) == 4)
check("ERROR is a hollow ring: its middle is empty", shapes["ERROR"].pixelColor(20, 20) == QColor("#000000") and shapes["OK"].pixelColor(20, 20) != QColor("#000000"))
check("the names of the shapes", st.SHAPES == {"OK": "round", "WARN": "triangle", "FAIL": "square", "ERROR": "ring"})

print("== how long it has been down")
now = datetime(2026, 11, 3, 15, 17)
check("minutes, hours and minutes, days and hours", [display.span(x, now) for x in ("2026-11-03 15:16:30", "2026-11-03 14:32:00", "2026-11-03 13:02:00",
      "2026-11-03 12:17:00", "2026-10-31 11:00:00")] == ["1 min", "45 min", "2 h 15 min", "3 h", "3 days 4 h"], [display.span(x, now) for x in ("2026-11-03 15:16:30", "2026-11-03 14:32:00", "2026-11-03 13:02:00", "2026-11-03 12:17:00", "2026-10-31 11:00:00")])
check("an unreadable time says nothing", display.span("soon") == "")
from drivers.base import Result
for n in ("sw1", "sw2"):
    db.save_device(dict(name=n, vendor="cisco", host="10.0.0.9", port=0, platform="cisco_ios", username="u", site="default",
                        verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))
def run(at, *results):
    rid = db.save_run(list(results))
    with db.connect() as c:
        c.execute("UPDATE runs SET started_at=? WHERE id=?", (at, rid))
run("2026-11-03 10:00:00", Result("sw1", "cpu", "OK", "5%"), Result("sw2", "cpu", "OK", "5%"))
run("2026-11-03 11:00:00", Result("sw1", "connection", "ERROR", "", "timeout"), Result("sw2", "cpu", "OK", "5%"))
run("2026-11-03 12:00:00", Result("sw1", "connection", "ERROR", "", "timeout"), Result("sw2", "connection", "ERROR", "", "refused"))
check("down since the first run of its current stretch of connection errors", db.down_since("sw1") == "2026-11-03 11:00:00", db.down_since("sw1"))
check("a device that answered later is not down", db.down_since("sw2") == "2026-11-03 12:00:00" and (run("2026-11-03 13:00:00", Result("sw2", "cpu", "OK", "5%")) or True)
      and db.down_since("sw2") is None)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
