# Run directly (python tests/test_x.py) or all together (python tests/run_all.py).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import sys
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

print()
print(f"{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
