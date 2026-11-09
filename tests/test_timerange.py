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
from PySide6.QtCore import QCoreApplication, QDate
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def spin(ms):
    end = time.time() + ms / 1000
    while time.time() < end: QCoreApplication.processEvents(); time.sleep(0.005)

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
fired.clear()
tr.hours.setValue(12); spin(400)
check("a person changing the hours fires changed once", fired == [1] and tr.describe() == "Last 12 hours", (fired, tr.describe()))
fired.clear()
tr.mode.setCurrentIndex(1); spin(400)
check("switching to Dates fires it once", fired == [1] and tr.dates.isVisibleTo(tr), fired)
fired.clear()
for day in (1, 2, 3):                                        # typing a date: each valid date along the way, in quick succession
    tr.d1.setDate(QDate(2026, 10, day))
spin(400)
check("editing a date fires it once, after the typing settles", fired == [1] and tr.span()[0] == datetime(2026, 10, 3), (fired, tr.span()))
fired.clear()
tr.hours.setValue(20); tr.set_hours(6); spin(400)
check("a set_hours() right after an edit fires once, not twice", fired == [1] and tr.describe() == "Last 6 hours", fired)

print("== History")
import ui.history as H
w0 = H.HistoryTab(); w0.show(); app.processEvents()
check("with no results at all the table says how to start the history", w0.empty.isVisible()
      and (w0.empty.head.text(), w0.empty.sub.text()) == ("No runs yet", "Press Run checks (Results tab) to start the history"))
w0.hide()
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

w = H.HistoryTab(); w.resize(1100, 600); w.show(); app.processEvents()
check("with results the hint is gone", not w.empty.isVisible() and not w.capped.isVisible())
w.range.set_dates(date(2020, 1, 1), date(2020, 1, 2)); app.processEvents()
check("a range with nothing in it is simply empty, no hint", w.detail.model().rowCount() == 0 and not w.model.cells and not w.empty.isVisible())
w.range.set_hours(8); app.processEvents()
check("the runs list is gone", not hasattr(w, "runs") and not hasattr(w, "show_run") and not hasattr(w, "run_ids"))
check("the page has a time range, the last 8 hours", isinstance(w.range, TimeRange) and w.range.describe() == "Last 8 hours")

def table():
    """Every result the checks table holds, in its order: [(time, device, check, status, value, message)]."""
    return list(w.model.cells)

def tops():
    """The device rows as shown: [(device, checks, newest time, worst status, value, message)]."""
    m = w.model
    return [tuple(m.index(i, j).data() for j in range(m.columnCount())) for i in range(m.rowCount())]

def under(ix):
    m = w.model
    return [tuple(m.index(k, j, ix).data() for j in range(m.columnCount())) for k in range(m.rowCount(ix))]

def at(device, check=None):
    return w.model.find(device if check is None else (device, display.check_name(check)))

def wanted(keep=lambda r: True):
    return sorted((r["t"], r["device"], display.check_name(r["check_name"]), r["status"]) for r in db.results_between(*w.range.span()) if keep(r))

shown = lambda: sorted((t, d, c, s) for t, d, c, s, _v, _m in table())
heads = [w.detail.model().headerData(j, H.Qt.Orientation.Horizontal) for j in range(w.detail.model().columnCount())]
check("the checks table: Device, Check, Time, Status, Value, Message", heads == ["Device", "Check", "Time", "Status", "Value", "Message"], heads)
check("it holds exactly the rows of the range (not the run two days ago)", shown() == wanted() and len(table()) == 9, (len(table()), shown()))
check("a row per device, every one closed", sorted(t[0] for t in tops()) == ["sw0", "sw1", "sw2"]
      and not any(w.detail.isExpanded(at(d)) for d in ("sw0", "sw1", "sw2")), tops())
top = {t[0]: t for t in tops()}
check("a device row counts its checks, shows its worst status and names its first problem", top["sw1"][1] == "2 checks" and top["sw1"][3] == "FAIL"
      and top["sw1"][5] == display.said(display.check_name("cpu"), "high"), top["sw1"])
check("...and says all OK when nothing is wrong", top["sw0"][3:] == ("OK", "", "all OK"), top["sw0"])
kids = {r[1]: r for r in under(at("sw1"))}
cpu = kids[display.check_name("cpu")]
check("under it, a row per check showing its newest result", cpu[0] == "" and cpu[3:5] == ("FAIL", "31%")
      and cpu[2] == max(t[0] for t in table() if t[1] == "sw1"), cpu)
runs = under(at("sw1", "cpu"))
check("...and under the check its earlier results", [r[3:5] for r in runs] == [("OK", "21%")] and runs[0][:2] == ("", ""), runs)
check("newest first: each check's row is newer than every run under it", all(c[2] >= r[2] for d in tops() for c in under(at(d[0]))
                                                                            for r in under(w.model.find((d[0], c[1])))))
check("a tree view, sortable, starting newest first", isinstance(w.detail, H.QTreeView) and w.detail.isSortingEnabled()
      and w.model.key == (2, H.Qt.SortOrder.DescendingOrder))
w.expand_btn.click(); app.processEvents()
check("Expand all opens every device and check", all(w.detail.isExpanded(at(d)) for d in ("sw0", "sw1", "sw2")) and w.detail.isExpanded(at("sw1", "cpu")))
w.collapse_btn.click(); app.processEvents()
check("Collapse all closes them again", not any(w.detail.isExpanded(at(d)) for d in ("sw0", "sw1", "sw2")))
check("the buttons say Expand all and Collapse all", (w.expand_btn.text(), w.collapse_btn.text()) == ("Expand all", "Collapse all"))
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

w.detail.expand(at("sw2")); app.processEvents()
w.detail.setCurrentIndex(at("sw2", "memory")); app.processEvents()
check("clicking a row ticks that device and check on Over time", w.dev.currentData() == "sw2" and w.chk.selected() == [display.check_name("memory")],
      (w.dev.currentData(), w.chk.selected()))

sev = lambda rows: [H.SEVERITY[t[3]] for t in rows]
w.detail.sortByColumn(3, H.Qt.SortOrder.AscendingOrder); app.processEvents()
picked = w.model.ident(w.detail.currentIndex())
check("sorting by Status puts the worst device last, and the chosen row stays chosen with its device open",
      sev(tops()) == sorted(sev(tops())) and picked == ("sw2", display.check_name("memory")) and w.detail.isExpanded(at("sw2")), (tops(), picked))
w.refresh(); app.processEvents()
check("a refresh keeps the sort, the open device and the chosen row", sev(tops()) == sorted(sev(tops())) and w.detail.isExpanded(at("sw2"))
      and w.model.ident(w.detail.currentIndex()) == ("sw2", display.check_name("memory")))
rep =[(r.device, display.check_name(r.check), r.status, display.value(r.value), r.message) for r in w.report_rows()]
check("report_rows() are the table's rows, in its order", rep == [t[1:] for t in table()], (rep, table()))
check("the report's date is the range", w.report_date() == "Last 72 hours", w.report_date())
sc = w.screen_context()
check("the Assistant is told the range and the rows, and no run", sc.get("time_range") == "Last 72 hours" and len(sc.get("rows", [])) == 12
      and not any("run" in k for k in sc), sc)
check("the export buttons no longer speak of a run", all("run" not in b.toolTip() for b in (w.csv_btn, w.html_btn, w.pdf_btn, w.trend_btn)))

reads = []
real_between = db.results_between
db.results_between = lambda *a, **k: (reads.append(a), real_between(*a, **k))[1]
for typed in ("s", "sw", "sw1"):
    w.find.setText(typed); app.processEvents()
check("typing a search filters what was read, without reading the range again", reads == [] and {r[1] for r in table()} == {"sw1"}, (len(reads), table()))
out = os.path.join(SP, "range.html")
H.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (out, ""))
H.QDesktopServices.openUrl = staticmethod(lambda u: True)
w.export_html()
head = open(out, encoding="utf-8").read()
made = [f"Generated {t:%Y-%m-%d %H:%M} \u2014 Last 72 hours, search: sw1" for t in (datetime.now(), datetime.now() - timedelta(minutes=1))]
check("the report says when it was made, then the range and the search", any(m in head for m in made), head[:400])
w.find.setText(""); app.processEvents()
w.range.set_hours(72); app.processEvents()
check("a new range does read again", len(reads) == 1, len(reads))
db.results_between = real_between

print("== 10,000 rows")
db.save_run([Result(f"bulk{d:03d}", f"check {c:03d}", ("OK", "WARN", "FAIL", "ERROR")[c % 4], f"{c}%", "", numeric=float(c))
             for d in range(100) for c in range(100)])
w.range.set_hours(8); app.processEvents()
t0 = time.perf_counter()
w.show_rows(); app.processEvents()
took = time.perf_counter() - t0
check("10,000 rows fill the table in under 2 s", len(table()) >= 10000 and took < 2.0, (len(table()), round(took, 2)))
print(f"   ({took:.2f} s)")
w.find.setText("sw1"); app.processEvents()
t0 = time.perf_counter()
w.find.setText(""); app.processEvents()                     # the search emptied: every row back, from what was read
typed = time.perf_counter() - t0
check("and changing the search over them is quick", len(table()) >= 10000 and typed < 0.3, (len(table()), round(typed, 2)))
print(f"   ({typed:.2f} s)")


print("== The newest rows only")
everything = db.results_between(*w.range.span())
check("results_between(limit=n) is the newest n of the range", db.results_between(*w.range.span(), limit=50) == everything[:50]
      and len(everything) > 50)
check("the shipped cap is 50,000 rows", db.HISTORY_CAP == 50_000)
check("under the cap the line is hidden", not w.capped.isVisible() and len(table()) == len(everything))
db.HISTORY_CAP = len(everything) - 1
row_key = lambda r: (r["t"], r["device"], r["check_name"])
w.show_rows(); app.processEvents()
check("over the cap the table holds the newest rows only", len(table()) == db.HISTORY_CAP
      and sorted(map(row_key, w.model.rows)) == sorted(map(row_key, everything[:db.HISTORY_CAP])), len(table()))
check("...and says so above the checks table", w.capped.isVisible() and w.capped.text() ==
      f"Showing the newest {db.HISTORY_CAP:,} results. Narrow the time range to see older ones.", w.capped.text())
db.HISTORY_CAP = 50_000
w.show_rows(); app.processEvents()
check("...and the line goes when the range fits again", not w.capped.isVisible())

print("== Hidden")
reads = []
db.results_between = lambda *a, **k: (reads.append(a), real_between(*a, **k))[1]
w.hide(); app.processEvents()
w.refresh(); w.refresh(); app.processEvents()
check("a refresh while the page is hidden does not read the range", reads == [], len(reads))
w.show(); app.processEvents()
check("showing the page reads it once", len(reads) == 1, len(reads))
w.hide(); w.show(); app.processEvents()
check("...and only when something asked for it", len(reads) == 1, len(reads))
db.results_between = real_between

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
