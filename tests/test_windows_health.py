# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Windows checks on the computer's own health: disks, BitLocker, antivirus, firewall, clock, sign-ins, activation, sessions, tasks, AD, Hyper-V, backup.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
from datetime import datetime, timedelta, timezone
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "winhealth%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingwinhealth%d" % int(time.time()))
from core import checks, db, winmon
from drivers import DRIVERS
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def dev(name, platform="agent"):
    d = dict(name=name, vendor="windows", host=name, port=0, platform=platform, username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None, winopts="")
    d["id"] = db.save_device(d); return db.get_device(d["id"])

def iso(dt): return dt.strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
def now(): return datetime.now(timezone.utc)
def report(**kw):
    r = {"v": 1, "at": iso(now()), "now": iso(now()), "computer": "SRV1", "domain": "corp", "joined": True, "os": "Microsoft Windows Server 2022 Standard", "uptime_h": 400.0,
         "mem_total_mb": 16384, "mem_free_mb": 12288, "cpu": 12.0, "disks": [{"drive": "C:", "size": 100 * 2**30, "free": 40 * 2**30}], "reboot": [],
         "service_states": {"Spooler": "R"}, "auto_stopped": [], "events": {"count": 3, "capped": False, "top": []}, "certs": [], "patched": iso(now() - timedelta(days=10))}
    r.update(kw); return r
TH = db.get_thresholds()
def run(d, rep, age=0.0, how="agent", disabled=()):
    drv = DRIVERS["windows"](d, TH, {"disabled": frozenset(disabled)})
    drv.fetch = lambda: (rep, age, how)
    drv._answered = now()                                           # (fetch is replaced, so say when the answer arrived)
    return {r.check: r for r in drv.run()}

print("== the catalog and limits")
want = {"disk health", "bitlocker", "antivirus", "firewall", "clock", "logons", "activation", "sessions", "tasks", "ad replication", "hyper-v", "backup"}
check("the Windows type lists them all", want <= {k for k, _ in checks.CATALOG["windows"]})
check("their limits exist", all(k in db.DEFAULT_THRESHOLDS for k in ("clock_offset", "failed_logons", "lockouts", "av_age", "backup_days", "rdp_disconnected")))
d = dev("srv-h")
r = run(d, report(now=None))
check("a report without any of the new data adds no rows (older agents keep working)", not (want & set(r)), set(r) & want)

print("== disks")
r = run(d, report(physical=[{"name": "Disk A", "health": "Healthy", "op": "OK"}, {"name": "Disk B", "health": "Healthy", "op": "OK"}], volumes=[{"drive": "C:", "health": "Healthy"}]))
check("healthy disks and volumes are counted", r["disk health"].status == "OK" and r["disk health"].value == "3 ok", r["disk health"])
r = run(d, report(physical=[{"name": "Disk A", "health": "Warning", "op": "OK"}, {"name": "Disk B", "health": "Healthy", "op": "OK"}]))
check("a disk with a warning is a warning, named", r["disk health"].status == "WARN" and "Disk A: Warning" in r["disk health"].message)
r = run(d, report(physical=[{"name": "Disk A", "health": "Unhealthy", "op": "Lost Communication"}]))
check("an unhealthy disk fails", r["disk health"].status == "FAIL" and "Lost Communication" in r["disk health"].message)
r = run(d, report(volumes=[{"drive": "D:", "health": "Unhealthy"}]))
check("so does an unhealthy volume", r["disk health"].status == "FAIL" and "volume D:" in r["disk health"].message)

print("== BitLocker, antivirus, firewall")
check("BitLocker: protected is fine", run(d, report(bitlocker=[{"mount": "C:", "protection": "On"}]))["bitlocker"].status == "OK")
r = run(d, report(bitlocker=[{"mount": "C:", "protection": "Off"}, {"mount": "D:", "protection": "On"}]))
check("BitLocker: a volume that is not protected warns, and is named", r["bitlocker"].status == "WARN" and "C:" in r["bitlocker"].message)
check("Defender up to date is fine", run(d, report(defender={"enabled": True, "realtime": True, "sig_days": 0, "mode": "Normal"}, av_products=["Windows Defender"]))["antivirus"].status == "OK")
r = run(d, report(defender={"enabled": True, "realtime": True, "sig_days": 5, "mode": "Normal"}))
check("old signatures warn, very old ones fail", r["antivirus"].status == "WARN" and "5 days" in r["antivirus"].value and run(d, report(defender={"enabled": True, "realtime": True, "sig_days": 12, "mode": "Normal"}))["antivirus"].status == "FAIL")
check("real-time protection off fails", run(d, report(defender={"enabled": True, "realtime": False, "sig_days": 0, "mode": "Normal"}))["antivirus"].status == "FAIL")
r = run(d, report(defender={"enabled": True, "realtime": True, "sig_days": 0, "mode": "Passive"}, av_products=["Windows Defender", "SentinelOne"]))
check("another product with Defender passive is fine, and named", r["antivirus"].status == "OK" and "SentinelOne" in r["antivirus"].value)
r = run(d, report(defender={"enabled": False, "realtime": False, "sig_days": 0, "mode": ""}, av_products=[]))
check("no antivirus at all fails", r["antivirus"].status == "FAIL" and "no antivirus" in r["antivirus"].value)
check("a server with no way to ask is left out", "antivirus" not in run(d, report()))
check("Firewall: all on is fine", run(d, report(firewall=[{"name": "Domain", "on": True}, {"name": "Public", "on": True}]))["firewall"].status == "OK")
r = run(d, report(firewall=[{"name": "Domain", "on": True}, {"name": "Public", "on": False}]))
check("Firewall: a profile that is off warns, named", r["firewall"].status == "WARN" and "Public" in r["firewall"].message)

print("== the clock")
r = run(d, report(**{"now": iso(now() + timedelta(seconds=10))}))
check("a few seconds out is fine", r["clock"].status == "OK" and r["clock"].value.startswith("+"))
r = run(d, report(**{"now": iso(now() - timedelta(seconds=120))}))
check("two minutes behind warns, and says which way", r["clock"].status == "WARN" and "behind" in r["clock"].message and r["clock"].value.startswith("-"), r["clock"])
check("five minutes out fails (Kerberos stops working)", run(d, report(**{"now": iso(now() + timedelta(seconds=400))}))["clock"].status == "FAIL")
check("an old agent that does not send its time has no clock row", "clock" not in run(d, report(now=None)))

print("== sign-ins, lockouts, activation, sessions, tasks")
r = run(d, report(logons={"failed": 3, "capped": False, "top": [{"user": "bob", "count": 3}], "lockouts": 0}))
check("a few failed sign-ins are fine", r["logons"].status == "OK" and r["logons"].value == "3 failed")
r = run(d, report(logons={"failed": 800, "capped": True, "top": [{"user": "administrator", "count": 700}, {"user": "bob", "count": 100}], "lockouts": 0}))
check("hundreds fail, and the busiest names are shown", r["logons"].status == "FAIL" and "administrator x700" in r["logons"].message and r["logons"].value == "800+ failed")
r = run(d, report(logons={"failed": 2, "capped": False, "top": [], "lockouts": 2}))
check("an account lockout warns on its own", r["logons"].status == "WARN" and "2 account lockout" in r["logons"].message)
check("a Security log Toner cannot read gives no row", "logons" not in run(d, report(logons={"failed": None})))
check("Windows activation: licensed is fine", run(d, report(activation={"status": 1, "grace_min": 0}))["activation"].status == "OK")
r = run(d, report(activation={"status": 2, "grace_min": 3 * 1440}))
check("in a grace period fails when it is nearly over", r["activation"].status == "FAIL" and "3 day" in r["activation"].message)
check("unlicensed fails", run(d, report(activation={"status": 0, "grace_min": 0}))["activation"].status == "FAIL")
r = run(d, report(sessions={"active": 2, "disconnected": 9}))
check("disconnected Remote Desktop sessions warn", r["sessions"].status == "WARN" and r["sessions"].value == "2 active, 9 disconnected")
check("and a few do not", run(d, report(sessions={"active": 2, "disconnected": 1}))["sessions"].status == "OK")
r = run(d, report(task_failures=[{"name": "Nightly copy", "result": "0x1"}, {"name": "Cleanup", "result": "0x80070002"}]))
check("failed scheduled tasks are listed", r["tasks"].status == "WARN" and "Nightly copy (0x1)" in r["tasks"].message)
check("none failed is fine", run(d, report(task_failures=[]))["tasks"].status == "OK")

print("== domain controllers, Hyper-V, backup")
check("AD replication fine", run(d, report(ad={"repl_fail": 0, "repl_total": 6}))["ad replication"].status == "OK")
r = run(d, report(ad={"repl_fail": 2, "repl_total": 6}))
check("AD replication failures fail", r["ad replication"].status == "FAIL" and r["ad replication"].value == "2 of 6 failing")
check("Hyper-V: machines running and off are fine", run(d, report(hyperv={"running": 4, "off": 2, "bad": []}))["hyper-v"].value == "4 running, 2 off")
r = run(d, report(hyperv={"running": 3, "off": 0, "bad": ["web1 (Paused-Critical)"]}))
check("Hyper-V: a paused-critical machine fails, named", r["hyper-v"].status == "FAIL" and "web1" in r["hyper-v"].message)
check("backup: yesterday is fine", run(d, report(backup={"last": iso(now() - timedelta(days=1)), "result": 0}))["backup"].status == "OK")
check("backup: four days old warns", run(d, report(backup={"last": iso(now() - timedelta(days=4)), "result": 0}))["backup"].status == "WARN")
r = run(d, report(backup={"last": iso(now() - timedelta(days=1)), "result": -2147024894}))
check("backup: a failed latest run fails whatever the age", r["backup"].status == "FAIL" and "failed" in r["backup"].message)

print("== switching them off")
r = run(d, report(firewall=[{"name": "Public", "on": False}], sessions={"active": 0, "disconnected": 50}), disabled={"windows:firewall", "windows:sessions"})
check("each can be switched off in Settings > Checks", "firewall" not in r and "sessions" not in r)

if sys.platform == "win32":                     # real PowerShell on this computer
    print("== a real run on this computer (real PowerShell)")
    t0 = time.time()
    real = winmon.collect_local(timeout=180)
    check("the collector reports the new facts that this computer has", {"now", "firewall", "defender"} <= set(real) and isinstance(real.get("physical"), list), sorted(real)[:40])
    check("and its own clock at the end of the run, close to now", abs((winmon._when(real["now"]) - now()).total_seconds()) < 30)
    local = dev("this-pc", "local")
    rl = DRIVERS["windows"](local, TH, {"disabled": frozenset()})
    rl.fetch = lambda: (real, None, "local")
    rl._answered = now()
    rows = {r.check: r for r in rl.run()}
    check("every check turns it into a result without an error", rows and not [k for k, v in rows.items() if v.status == "ERROR"], {k: (v.status, v.message) for k, v in rows.items() if v.status == "ERROR"})
    check("and the clock agrees with Toner's (this is the same computer)", "clock" in rows and rows["clock"].status == "OK", rows.get("clock"))
    check("(it took a sensible time)", time.time() - t0 < 120, time.time() - t0)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
