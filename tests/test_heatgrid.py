# Run directly (python tests/test_heatgrid.py). The heatmap grid reads by date, the status heatmap and the ring, and the Failures tab on them.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "hg%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from datetime import datetime, timedelta
from core import db, heatgrid
db.init()
from drivers.base import Result
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)
import ui.history as H
from ui import chartspec

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

now = datetime(2026, 11, 8, 14, 30)
g = heatgrid.layout(now - timedelta(hours=8), now)
check("8 hours: 24 hour columns", g.cols == [f"{h:02d}" for h in range(24)])
check("8 hours: one or two date rows, newest first", g.rows == ["Sun 8 Nov"] or g.rows == ["Sun 8 Nov", "Sat 7 Nov"], g.rows)
g = heatgrid.layout(now - timedelta(hours=20), now)
check("two dates, newest first", g.rows == ["Sun 8 Nov", "Sat 7 Nov"], g.rows)
g = heatgrid.layout(now - timedelta(days=30), now)
check("30 days: 31 rows or fewer", len(g.rows) <= 31 and g.cols[0] == "00", len(g.rows))
g90 = heatgrid.layout(now - timedelta(days=90), now)
check("90 days: weekday columns", g90.cols == ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"])
check("90 days: 13 to 14 week rows", 13 <= len(g90.rows) <= 14, len(g90.rows))
check("weeks are labelled with their Monday, newest first", g90.rows[0] == "Mon 2 Nov" and g90.rows[1] == "Mon 26 Oct", g90.rows[:2])
for grid, t in ((g, now - timedelta(days=3, hours=2)), (g90, now - timedelta(days=40, hours=5)), (g, now)):
    xy = grid.cell(t)
    a, b = grid.slot(*xy)
    check(f"round trip {t}", a <= t < b, (xy, a, b))
check("outside the range -> None", g.cell(now + timedelta(hours=1)) is None and g.cell(now - timedelta(days=31)) is None)

p = chartspec.palette()
opt = chartspec.status_heatmap(p, ["a", "b"], ["r"], [(0, 0, "OK"), (1, 0, "FAIL")])
cols = [d["itemStyle"]["color"] for d in opt["series"][0]["data"]]
check("status heatmap: own colours, no visualMap", cols == [chartspec.status_color(p, "OK"), chartspec.status_color(p, "FAIL")] and "visualMap" not in opt, cols)
check("status heatmap: click value is [x, y, ...]", opt["series"][0]["data"][1]["value"][:2] == [1, 0])
opt = chartspec.ring(p, [("OK", 3, "#0a0"), ("FAIL", 1, "#a00")], "75%")
check("ring: centre text in graphic", opt["graphic"][0]["style"]["text"] == "75%" and opt["series"][0]["data"][0]["name"] == "OK")

db.save_device(dict(name="sw0", vendor="cisco", host="10.0.0.1", port=0, platform="", username="u", site="default", verify_ssl=0,
                    ha_expected=0, enabled=1, location="", details="", folder_id=None))
db.save_run([Result("sw0", "link", "FAIL", "down")])
w = H.HistoryTab(); w.resize(1100, 600)
got = {}
w.fail_when.draw = lambda b: got.update(opt=b(p))
w.fail_period.setCurrentIndex(w.fail_period.findData(30))
w.draw_failures()
ys = got["opt"]["yAxis"]["data"]
check("Failures, 30 days: date rows, no weekday row", "Mon" not in ys and "Sun" not in ys and ys[0] == f"{datetime.now():%a} {datetime.now().day} {datetime.now():%b}", ys[:3])
w.fail_period.setCurrentIndex(w.fail_period.findData(90))
w.draw_failures()
check("Failures, 90 days: weekday columns", got["opt"]["xAxis"]["data"][0] == "Mon" and len(got["opt"]["yAxis"]["data"]) >= 13)
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
