# Run directly (python tests/test_timerange.py). The History page's time range: the last 8 hours by default, Last [n] hours or a span of
# dates; the checks table lists every stored row in it (model/view, quick with thousands), and the exports, the Assistant and Over time follow it.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "tr%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from datetime import date, datetime, timedelta
from core import db, display
db.init()
from drivers.base import Result
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

print("== TimeRange")
from ui.timerange import TimeRange
tr = TimeRange()
s, e = tr.span()
check("a new range is the last 8 hours, ending now", abs((datetime.now() - e).total_seconds()) < 5 and abs((e - s) - timedelta(hours=8)) < timedelta(seconds=1), (s, e))
check("and says so", tr.describe() == "Last 8 hours", tr.describe())
fired = []
tr.changed.connect(lambda: fired.append(1))
tr.set_hours(24)
s, e = tr.span()
check("set_hours(24) fires changed once and spans 24 hours", fired == [1] and abs((e - s) - timedelta(hours=24)) < timedelta(seconds=1), (fired, s, e))
check("Last 24 hours", tr.describe() == "Last 24 hours", tr.describe())
tr.set_dates(date(2026, 11, 8), date(2026, 11, 1))
s, e = tr.span()
check("dates given the wrong way round are put in order: the first day's start to the last day's end", s == datetime(2026, 11, 1)
      and e.date() == date(2026, 11, 8) and e >= datetime(2026, 11, 8, 23, 59, 59) and fired == [1, 1], (s, e, fired))
check("From [date] to [date]", tr.describe() == "From 2026-11-01 to 2026-11-08", tr.describe())
tr.set_dates(date(2026, 11, 3), date(2026, 11, 3))
s, e = tr.span()
check("one day is the whole of that day", s == datetime(2026, 11, 3) and e > s + timedelta(hours=23, minutes=59), (s, e))
tr.set_hours(8)
check("and back to hours", tr.describe() == "Last 8 hours" and tr.hours.isVisibleTo(tr) and not tr.dates.isVisibleTo(tr))

print("== History")
for i in range(3):
    db.save_device(dict(name=f"sw{i}", vendor="cisco", host=f"10.0.0.{i}", port=0, platform="", username="u", site="default", verify_ssl=0,
                        ha_expected=0, enabled=1, location="Chicago" if i == 0 else "Denver", details="", folder_id=None))
old = db.save_run([Result(f"sw{i}", "cpu", "OK", "10%", numeric=10.0) for i in range(3)])
with db.connect() as c:
    c.execute("UPDATE runs SET started_at = ? WHERE id = ?", ((datetime.now() - timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S"), old))
time.sleep(1.05)
db.save_run([Result(f"sw{i}", "cpu", "OK", f"{20 + i}%", numeric=20.0 + i) for i in range(3)]
            + [Result(f"sw{i}", "memory", "WARN" if i == 2 else "OK", f"{50 + i}%", numeric=50.0 + i) for i in range(3)])
time.sleep(1.05)
db.save_run([Result(f"sw{i}", "cpu", "FAIL" if i == 1 else "OK", f"{30 + i}%", "high" if i == 1 else "", numeric=30.0 + i) for i in range(3)])

import ui.history as H
w = H.HistoryTab(); w.resize(1100, 600); w.show(); app.processEvents()
check("the runs list is gone", not hasattr(w, "runs") and not hasattr(w, "show_run") and not hasattr(w, "run_ids"))
check("the page has a time range, the last 8 hours", isinstance(w.range, TimeRange) and w.range.describe() == "Last 8 hours")

def table():
    """The checks table as shown: [(time, device, check, status, value, message)]."""
    m = w.detail.model()
    return [tuple(m.index(i, j).data() for j in range(m.columnCount())) for i in range(m.rowCount())]

def wanted(keep=lambda r: True):
    return sorted((r["t"], r["device"], display.check_name(r["check_name"]), r["status"]) for r in db.results_between(*w.range.span()) if keep(r))

shown = lambda: sorted((t, d, c, s) for t, d, c, s, _v, _m in table())
heads = [w.detail.model().headerData(j, H.Qt.Orientation.Horizontal) for j in range(w.detail.model().columnCount())]
check("the checks table: Time, Device, Check, Status, Value, Message", heads == ["Time", "Device", "Check", "Status", "Value", "Message"], heads)
check("it holds exactly the rows of the range (not the run two days ago)", shown() == wanted() and len(table()) == 9, (len(table()), shown()))
check("newest first", [r[0] for r in table()] == sorted((r[0] for r in table()), reverse=True))
check("a model/view table behind a sort proxy, sortable", isinstance(w.detail, H.QTableView) and isinstance(w.detail.model(), H.QSortFilterProxyModel)
      and w.detail.isSortingEnabled())
check("Status is drawn by the StatusDelegate", isinstance(w.detail.itemDelegateForColumn(3), H.StatusDelegate))
w.find.setText("sw1"); app.processEvents()
check("the search box narrows it", shown() == wanted(lambda r: r["device"] == "sw1") and len(table()) == 3, shown())
w.find.setText(""); w.funnel.set("location", {"Chicago"}); app.processEvents()
check("so does the funnel", shown() == wanted(lambda r: r["device"] == "sw0") and len(table()) == 3, shown())
w.funnel.clear(); app.processEvents()
got = {}
real_show = w.panels.show_checks
w.panels.show_checks = lambda dev, vendor, checks, start, end, th: (got.update(start=start, end=end), real_show(dev, vendor, checks, start, end, th))
w.range.set_hours(72); app.processEvents()
check("a longer range brings in the older run", shown() == wanted() and len(table()) == 12, len(table()))
check("Over time follows the same range", got and abs((got["end"] - got["start"]) - timedelta(hours=72)) < timedelta(seconds=2), got)

row = next(i for i, r in enumerate(table()) if r[1] == "sw2" and r[2] == display.check_name("memory"))
w.detail.selectRow(row); app.processEvents()
check("clicking a row ticks that device and check on Over time", w.dev.currentData() == "sw2" and w.chk.selected() == [display.check_name("memory")],
      (w.dev.currentData(), w.chk.selected()))

w.detail.sortByColumn(3, H.Qt.SortOrder.AscendingOrder); app.processEvents()
rep = [(r.device, display.check_name(r.check), r.status, display.value(r.value), r.message) for r in w.report_rows()]
check("report_rows() are the table's rows, in its order", rep == [t[1:] for t in table()], (rep, table()))
check("the report's date is the range", w.report_date() == "Last 72 hours", w.report_date())
sc = w.screen_context()
check("the Assistant is told the range and the rows, and no run", sc.get("time_range") == "Last 72 hours" and len(sc.get("rows", [])) == 12
      and not any("run" in k for k in sc), sc)
check("the export buttons no longer speak of a run", all("run" not in b.toolTip() for b in (w.csv_btn, w.html_btn, w.pdf_btn, w.trend_btn)))

print("== 10,000 rows")
db.save_run([Result(f"bulk{d:03d}", f"check {c:03d}", ("OK", "WARN", "FAIL", "ERROR")[c % 4], f"{c}%", "", numeric=float(c))
             for d in range(100) for c in range(100)])
w.range.set_hours(8); app.processEvents()
t0 = time.perf_counter()
w.show_rows(); app.processEvents()
took = time.perf_counter() - t0
check("10,000 rows fill the table in under 2 s", w.detail.model().rowCount() >= 10000 and took < 2.0, (w.detail.model().rowCount(), round(took, 2)))
print(f"   ({took:.2f} s)")

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
