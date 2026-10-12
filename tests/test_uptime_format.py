# Run directly (python tests/test_x.py) or all together (python tests/run_all.py).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "uptfmt%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roaminguptfmt%d" % int(time.time()))
from core import db
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
from core import display
from drivers.sshbase import uptime_hours, compact_hours
from drivers import paloalto

print("== Days:Hours:Minutes:Seconds")
check("a few seconds", display.uptime(seconds=9) == "0:00:00:09")
check("a day and a bit", display.uptime(seconds=86400 + 3600 * 2 + 60 * 3 + 4) == "1:02:03:04")
check("from hours", display.uptime(hours=100.0) == "4:04:00:00")
check("fractions of an hour become minutes and seconds", display.uptime(hours=1.5025) == "0:01:30:09", display.uptime(hours=1.5025))
check("a long uptime keeps counting days (no weeks or years)", display.uptime(hours=24 * 400 + 5) == "400:05:00:00")
check("rounding does not give 60 seconds", display.uptime(hours=0.99999) == "0:00:59:59" or display.uptime(hours=0.99999) == "0:01:00:00", display.uptime(hours=0.99999))
check("nothing or a negative number is zero", display.uptime(hours=None) == "0:00:00:00" and display.uptime(seconds=-5) == "0:00:00:00")
check("what vendors print is read, then shown the same way", display.uptime(hours=uptime_hours("1 year, 2 weeks, 3 days, 4 hours, 5 minutes")) == "382:04:05:00"
      and display.uptime(hours=compact_hours("3w2d4h5m6s")) == "23:04:05:06" and display.uptime(hours=compact_hours("13w3d 22:40")) == "94:22:40:00")
check("the Windows collector reports uptime to a fraction of a second", "TotalHours, 5)" in __import__("core.winmon", fromlist=["x"]).COLLECTOR)

print("== the uptime chart (History)")
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)
from ui import history as H
hi, grid = H.uptime_axis(733.0)
check("the axis is in round days (7, 14, 21 ...), not odd numbers of hours", hi == 840 and [g[1] for g in grid] == ["0 d", "7 d", "14 d", "21 d", "28 d", "35 d"], grid)
hi, grid = H.uptime_axis(5.0)
check("a young uptime is shown in hours", [g[1] for g in grid][:3] == ["0 h", "2 h", "4 h"] and hi >= 5, grid)
hi, grid = H.uptime_axis(24 * 800)
check("a very long uptime still gets few lines", len(grid) <= 7 and hi >= 24 * 800, grid)
pts = [("2026-10-01 00:00:00", 10.0), ("2026-10-01 01:00:00", 11.0), ("2026-10-01 02:00:00", 0.5), ("2026-10-01 03:00:00", 1.5), ("2026-10-01 03:30:00", 1.5001)]
check("a fall in uptime is a restart; a rise or a tiny wobble is not", [r[0] for r in H.restarts(pts)] == ["2026-10-01 02:00:00"])
check("the caption says how long, since when and how often", H.uptime_caption(pts) == "Up for 0:01:30:00, since 2026-10-01 02:00.  Restarted 1 time in this period.", H.uptime_caption(pts))
check("no restarts says so", "No restarts" in H.uptime_caption(pts[:2]) and H.uptime_caption([]) == "")
check("uptime gets a chart of its own, away from other numbers", H.scale_key("uptime", pts) == (2, 0) and H.scale_key("uptime (sw1)", pts) == (2, 0) and H.scale_key("temperature", pts) != (2, 0))
check("and its own title", "days:hours:minutes:seconds" in H.scale_title((2, 0)))
cs = H.ChartStack(); cs.resize(900, 500); cs.show()
cs.set_series([("uptime", pts), ("bgp", [("2026-10-01 00:00:00", 2.0), ("2026-10-01 03:30:00", 2.0)])])
check("with other checks ticked, uptime is split out and titled", len(cs.charts) == 2 and any(c.title.startswith("Up for") for c in cs.charts), [c.title for c in cs.charts])
cs.set_series([("uptime", pts)])
check("alone it shows the caption above the line", len(cs.charts) == 1 and cs.charts[0].title.startswith("Up for"))
ch = cs.charts[0]; app.processEvents(); ch.grab()
ch.hover = 2; rows = ch.hover_rows()
check("the point where it restarted says so when hovered", [r[0] for r in rows] == ["Uptime", "Restarted"] and rows[0][1] == "0:00:30:00", rows)
ch.hover = 1
check("other points just show the uptime", [r[0] for r in ch.hover_rows()] == ["Uptime"])

print()
print(f"{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
