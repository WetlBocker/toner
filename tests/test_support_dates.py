# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Support, warranty and licence end dates kept in a device's custom fields.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time
from datetime import date, timedelta
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "support%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingsupport%d" % int(time.time()))
from core import checks, db, runner, support
from drivers.base import Driver
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

TODAY = date(2026, 10, 12)
TH = db.get_thresholds()

print("== reading a date")
P = support.parse_date
check("a full date", P("2027-06-30") == date(2027, 6, 30) and P("2027/6/3") == date(2027, 6, 3))
check("a month means its last day", P("2027-06") == date(2027, 6, 30) and P("2028-02") == date(2028, 2, 29) and P("2027-02") == date(2027, 2, 28))
check("day first, with dots or slashes", P("30.06.2027") == date(2027, 6, 30) and P("05/11/2027") == date(2027, 11, 5))
check("anything else is not a date", all(P(x) is None for x in ("", "soon", "2027-13", "2027-02-30", "31/02/2027", None)))

print("== the rows")
def dev(**fields): return {"name": "sw1", "fields": json.dumps(fields)}
r = {x.check: x for x in support.rows(dev(support="2027-06", warranty="2026-11-15", eol="2026-10-01", serial="X"), TH, TODAY)}
check("each date is its own row, named for what it is", set(r) == {"support ends", "warranty ends", "end of life"}, set(r))
check("plenty of time is fine, in days", r["support ends"].status == "OK" and r["support ends"].value == "261 days", r["support ends"])
check("under 90 days warns, and says the date", r["warranty ends"].status == "WARN" and r["warranty ends"].value == "34 days" and "2026-11-15" in r["warranty ends"].message)
check("a date that has passed fails, in words", r["end of life"].status == "FAIL" and r["end of life"].value == "ended 11 days ago")
check("the number is kept for the charts", r["warranty ends"].numeric == 34.0)
r = {x.check: x for x in support.rows(dev(Support_End="2026-11-01", **{"licence expires": "2026-10-30", "License": "2028-01-01"}), TH, TODAY)}
check("names are matched loosely (capitals, spaces, dashes, British and American spelling)", r["support ends"].value == "20 days" and r["licence ends"].value == "18 days" and r["support ends"].status == "FAIL")
check("(the first field for the same thing wins)", len([x for x in support.rows(dev(licence="2027-01-01", license="2029-01-01"), TH, TODAY)]) == 1)
r = support.rows(dev(support="next year"), TH, TODAY)
check("a typo is reported, not ignored", r[0].status == "ERROR" and "not a date" in r[0].message and "next year" in r[0].value)
check("a device with no such field has no rows", support.rows(dev(serial="X", owner="NOC"), TH, TODAY) == [] and support.rows({"name": "x", "fields": ""}, TH, TODAY) == [] and support.rows({"name": "x", "fields": "{bad"}, TH, TODAY) == [])

print("== in a real run")
class Probe(Driver):
    def run(self): return [self.result("cpu", "OK", "1%")]
runner.DRIVERS["cisco"] = Probe
d = {"name": "sw-fields", "vendor": "cisco", "host": "127.0.0.1", "port": 0, "platform": "", "username": "", "site": "default", "verify_ssl": 0, "ha_expected": 0, "enabled": 1,
     "fields": {"support": (date.today() + timedelta(days=10)).isoformat()}, "location": "", "details": ""}
d["id"] = db.save_device(d); d = db.get_device(d["id"])
opts = {**db.runtime_options(), "retries": 0, "tls_sweep": False, "custom": []}
own = lambda rows: [x for x in rows if x.check != "reachability"]            # the TCP reachability row is tested in test_reach
res = own(runner.run_one(d, db.thresholds_for(d), opts))
check("a run includes the support row beside the device's own checks", [x.check for x in res] == ["cpu", "support ends"] and res[1].status == "FAIL", [(x.check, x.status) for x in res])
res = own(runner.run_one(d, db.thresholds_for(d), {**opts, "disabled": {"all:support"}}))
check("and it can be switched off for every device in Settings > Checks", [x.check for x in res] == ["cpu"])
check("that switch is listed, under 'Every device'", "all" in checks.CATALOG and ("support", "Support, warranty and licence dates kept in a device's custom fields") in checks.CATALOG["all"])
from core import display
check("with a name people can read", display.type_name("all") == "Every device")
check("and its limits are in Settings > Thresholds, lower being worse", "support_days" in db.DEFAULT_THRESHOLDS and "support_days" in db.LOWER_IS_WORSE)
own = {**d, "checkopts": {"checks": ["cpu"]}}
res = runner.run_one(own, db.thresholds_for(own), opts)
check("a device that picks its own checks still gets its dates checked (they are not one of its vendor's checks)", [x.check for x in res] == ["cpu", "support ends"])

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
