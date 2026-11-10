# Run directly (python tests/test_scanning_volume.py). Thousands of Windows CVE rows must keep the Scanning list and its save usable.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "volume%d.db" % int(time.time())); os.environ["APPDATA"] = SP
from core import db
db.init()
from PySide6.QtWidgets import QApplication
app = QApplication([])
from drivers.base import Result
from ui.results import URL_ROLE
from ui.scanning import ScanningTab

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

FILL_LIMIT, SAVE_LIMIT, PER_DEVICE, BATCH = 2.0, 5.0, 5000, 500

FIX = "Windows kernel elevation of privilege. Fixed in build 10.0.20348.%d."
BUILDS = (5761, 5762, 5763)

def rows_for(name):
    """Every tenth CVE states no fix; the rest are fixed in one of three builds."""
    return [Result(name, f"CVE-2025-{i:05d}", "FAIL" if i % 3 else "WARN", f"CVSS {1 + i % 9}.5",
                   "Windows kernel elevation of privilege." if i % 10 == 0 else FIX % BUILDS[i % 3]) for i in range(PER_DEVICE)]

def group_texts():
    rows = rows_for("x")
    out = {f"{sum(1 for r in rows if r.message.endswith('build 10.0.20348.%d.' % b))} CVEs, fixed in build 10.0.20348.{b}" for b in BUILDS}
    return out | {f"{sum(1 for r in rows if 'Fixed' not in r.message)} CVEs, no fix stated"}

def filled(label, n_devices, vendor, rows_of=rows_for):
    names = []
    for k in range(n_devices):
        d = {"name": f"{label}-{k}", "vendor": vendor, "host": f"10.{abs(hash(label)) % 200}.0.{k + 1}", "platform": "", "folder_id": None, "org": None, "enabled": 1}
        db.save_device(d)
        names.append(d["name"])
    tab = ScanningTab(); tab.resize(1000, 600); tab.show(); app.processEvents()
    tab._save = lambda: None                                  # the save is timed on its own
    tab.last_ran, tab._active, tab.results, tab.stored = names, True, [], False
    t = time.perf_counter()
    for name in names:                                        # a worker's batches, as ScanWorker.batch delivers them to add()
        rows = rows_of(name)
        for i in range(0, len(rows), BATCH):
            tab.add(rows[i:i + BATCH])
    tab.done(); tab.show(); app.processEvents()
    return tab, names, time.perf_counter() - t

def measure(label, n_devices):
    tab, names, fill = filled(label, n_devices, "windows")
    t = time.perf_counter()
    db.save_scan(tab.results)
    save = time.perf_counter() - t
    print(f"  {label}: {len(tab.results)} rows, list fill {fill:.2f} s, save_scan {save:.2f} s")
    top = tab.table.topLevelItem(0)
    texts = {top.child(i).text(1) for i in range(top.childCount())}
    check(f"{label}: a device lists one line per fixed build, and one for no fix", texts == group_texts(), f"{texts}")
    groups = [top.child(i) for i in range(top.childCount())]
    check(f"{label}: no CVE is built before its group is opened", all(g.childCount() == 0 for g in groups) and tab.table.topLevelItemCount() == n_devices)
    t = time.perf_counter()
    tab.expand_all(); app.processEvents()
    expand = time.perf_counter() - t
    check(f"{label}: Expand all opens devices but builds no group ({expand:.2f} s)", top.isExpanded() and all(g.childCount() == 0 and not g.isExpanded() for g in groups) and expand < FILL_LIMIT)
    nofix = next(g for g in groups if g.text(1).endswith("no fix stated"))
    nofix.setExpanded(True)
    check(f"{label}: opening the no-fix group lists its CVEs, with their links", nofix.childCount() == PER_DEVICE // 10
          and all(nofix.child(i).data(1, URL_ROLE) == tab.link_for(Result("", nofix.child(i).text(1), "", "", "")) != "" for i in range(nofix.childCount())))
    check(f"{label}: a group shows its worst status", {g.text(2) for g in groups} == {"FAIL", "WARN"})
    check(f"{label}: every row kept", len(tab.results) == n_devices * PER_DEVICE)
    shown = len(tab.shown_rows())
    check(f"{label}: the export still holds every row", shown == n_devices * PER_DEVICE, f"{shown}")
    check(f"{label}: list fills under {FILL_LIMIT} s", fill < FILL_LIMIT, f"{fill:.2f} s")
    check(f"{label}: save_scan under {SAVE_LIMIT} s", save < SAVE_LIMIT, f"{save:.2f} s")
    tab.deleteLater()

measure("one device", 1)
measure("twenty devices", 20)

# a Cisco device's CVE rows are not grouped; a Windows device's single CVE for a build stays a plain row
three = lambda name: [Result(name, f"CVE-2025-0000{i}", "FAIL", "CVSS 7.5", FIX % (5761 if i < 2 else 5762)) for i in range(3)]
tab, _, _ = filled("cisco", 1, "cisco", three)
top = tab.table.topLevelItem(0)
check("a non-Windows device's rows are not grouped", [top.child(i).text(1) for i in range(top.childCount())] == ["CVE-2025-00000", "CVE-2025-00001", "CVE-2025-00002"])
tab, _, _ = filled("win3", 1, "windows", three)
top = tab.table.topLevelItem(0)
check("two CVEs of a build make a group; one alone stays a plain row",
      sorted(top.child(i).text(1) for i in range(top.childCount())) == ["2 CVEs, fixed in build 10.0.20348.5761", "CVE-2025-00002"])

print(f"{chr(10)}{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
