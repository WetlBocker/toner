# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import io, json, os, sys, time, urllib.request
from contextlib import redirect_stdout
from datetime import datetime, timedelta
pass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\sv%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db, service, backup, alerts
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
from drivers.base import Result
import cli

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def dev(name, vendor="cisco", **kw):
    d = dict(name=name, vendor=vendor, host="10.0.0.1", port=0, platform="", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None, tags=""); d.update(kw)
    db.save_device(d)
dev("core1", tags="core"); dev("edge-fw", "fortinet"); dev("off", enabled=0)

calls = {}
def fake_run_all(devices, thresholds, on_results=None, workers=10, opts=None):
    calls["devices"] = sorted(d["name"] for d in devices)
    res = []
    for d in devices:
        res += [Result(d["name"], "cpu", "WARN" if d["name"] == "core1" else "OK", "85%" if d["name"] == "core1" else "5%", numeric=85.0 if d["name"] == "core1" else 5.0), Result(d["name"], "memory", "OK", "40%", numeric=40.0)]
    return res
service.run_all = fake_run_all
sent = []
service.notify.process_run = lambda results, ran, scheduled, desktop=None: sent.append((len(results), sorted(ran), scheduled)) or "ok"

print("== run_checks")
res = service.run_checks([])
check("every enabled device is checked, disabled ones are not", calls["devices"] == ["core1", "edge-fw"] and len(res) == 4)
check("results are sorted worst first and saved as a run", res[0].status == "WARN" and db.last_run()["warn"] == 1 and db.last_run()["ok"] == 3)
check("notifications are sent for scheduled runs", sent == [(4, ["core1", "edge-fw"], True)], sent)
service.run_checks(["Tag: core"], do_notify=False, scheduled=False); check("a group limits the devices; --no-notify sends nothing", calls["devices"] == ["core1"] and len(sent) == 1)
check("no devices in the group -> nothing run, no run saved", service.run_checks(["Tag: nothing"]) == [] and db.last_run()["id"] == 2)

print("== metrics")
db.save_run([Result("core1", "config backup", "WARN", "changed"), Result("ctrl / ap1", "uptime", "OK", "5d", numeric=120.0)]); dev("ctrl", "unifi")
txt = service.metrics_text()
check("check status gauges with labels", 'toner_check_status{device="core1",check="cpu"} 1' in txt and 'toner_check_status{device="edge-fw",check="memory"} 0' in txt, txt[:400])
check("numeric values", 'toner_check_value{device="core1",check="cpu"} 85' in txt and 'toner_check_value{device="core1",check="memory"} 40' in txt)
check("device status is the worst of its checks", 'toner_device_status{device="core1"} 1' in txt and 'toner_device_status{device="edge-fw"} 0' in txt)
check("config-backup rows are not health metrics", 'check="config backup"' not in txt)
check("device and run totals", "toner_devices 4" in txt and "toner_last_run_timestamp_seconds " in txt and "toner_config_changes_24h " in txt)
check("a newer run of one device does not hide the others", 'device="edge-fw",check="cpu"' in txt)
db.save_run([Result('we"ird\\name', "c\nk", "OK", "1", numeric=1.0)])
check("label values are escaped", 'device="we\\"ird\\\\name",check="c\\nk"' in service.metrics_text())
check("every line is valid exposition format", all(l.startswith("#") or l.count(" ") >= 1 for l in service.metrics_text().splitlines() if l))
srv = service.MetricsServer(0, "127.0.0.1"); srv.start()
body = urllib.request.urlopen(f"http://127.0.0.1:{srv.port}/metrics", timeout=5).read().decode()
check("served over HTTP", "toner_check_status" in body and urllib.request.urlopen(f"http://127.0.0.1:{srv.port}/healthz", timeout=5).read() == b"ok\n")
try: urllib.request.urlopen(f"http://127.0.0.1:{srv.port}/nope", timeout=5); check("404 elsewhere", False)
except urllib.error.HTTPError as e: check("404 elsewhere", e.code == 404)
srv.stop()

print("== service (scheduler without a window)")
log = []
bk = []
service.run_backups = lambda groups=None, do_notify=True, scheduled=True, own=False: bk.append(list(groups or [])) or [Result("core1", "config backup", "WARN", "changed")]
chk = []
service.run_checks = lambda groups=None, do_notify=True, scheduled=True, on_result=None, own=False: chk.append(list(groups or [])) or [Result("core1", "cpu", "OK", "1%")]
d = service.Daemon(log=log.append)
db.set_setting("schedule_enabled", True); db.set_setting("schedule_minutes", 30); db.set_setting("backup_enabled", True); db.set_setting("backup_hours", 6)
d._arm(); t0 = datetime.now()
check("nothing is due at first", d.tick(t0) == [] and not chk and not bk)
check("checks run when their time comes, then re-arm", d.tick(t0 + timedelta(minutes=31)) == [("checks", 1)] and chk == [[]] and d.next_checks > t0 + timedelta(minutes=31))
check("...and not again until the next interval", d.tick(t0 + timedelta(minutes=32)) == [])
check("backups run on their own interval", d.tick(t0 + timedelta(hours=6, minutes=1)) == [("checks", 1), ("backup", 1)] or d.tick(t0 + timedelta(hours=6, minutes=1)) == [("backup", 1)], d.next_backup)
check("progress is logged", any("checks:" in l for l in log) and any("backups:" in l and "1 changed" in l for l in log), log)
db.set_setting("schedule_groups", ["Tag: gone"]); d2 = service.Daemon(log=log.append); d2._arm(); n = len(chk)
check("a schedule whose groups were all deleted is skipped, not run on everything", d2.tick(datetime.now() + timedelta(hours=1)) in ([], [("backup", 1)]) and len(chk) == n)
db.set_setting("schedule_enabled", False); db.set_setting("backup_enabled", False)
d3 = service.Daemon(log=log.append); d3._arm(); check("everything off -> nothing scheduled", d3.next_checks is None and d3.next_backup is None and d3.tick(datetime.now() + timedelta(days=9)) == [])

print("== the running service follows Settings")
db.set_setting("schedule_groups", []); db.set_setting("schedule_enabled", True); db.set_setting("schedule_minutes", 30)
d5 = service.Daemon(log=log.append); d5._arm(); t = datetime.now(); n = len(chk)
db.set_setting("schedule_enabled", False)
check("scheduled checks turned off in Settings stop without a restart", d5.tick(t + timedelta(hours=2)) == [] and len(chk) == n and d5.next_checks is None)
db.set_setting("schedule_enabled", True)
d5.tick(t + timedelta(hours=2))
check("turned on again, they run one interval later", d5.next_checks == t + timedelta(hours=2, minutes=30)
      and d5.tick(t + timedelta(hours=2, minutes=29)) == [] and d5.tick(t + timedelta(hours=2, minutes=31)) == [("checks", 1)])
db.set_setting("schedule_minutes", 5)
d5.tick(t + timedelta(hours=2, minutes=32))
check("a shorter interval counts at once, not after the old one", d5.next_checks <= t + timedelta(hours=2, minutes=37), d5.next_checks)
from core import orgs
acme = orgs.create("Acme", "ACME")
d5.tick(t + timedelta(hours=2, minutes=33))
check("an organization added while it runs gets its own schedule", d5.due.get(acme, {}).get("checks") is not None, d5.due)
orgs.set_archived(acme, True)
d5.tick(t + timedelta(hours=2, minutes=34))
check("an archived one is dropped", acme not in d5.due, d5.due)

print("== one Toner process runs the schedule")
from core import platforms
if service._schedule_lock:
    service._schedule_lock.close(); service._schedule_lock = None       # as if this service had only just started
base = db.base_path()
window = platforms.try_lock(base.with_name(base.name + ".schedule.lock"))   # Toner's window started first and runs it
n = len(chk)
check("while the window runs the schedule, the service runs nothing", window is not None and not service.owns_schedule()
      and d5.tick(t + timedelta(days=1)) == [] and len(chk) == n)
window.close()                                                            # the window is closed
check("once the window closes, the service takes over and runs what is due", service.owns_schedule() and d5.tick(t + timedelta(days=1)) == [("checks", 1)] and len(chk) == n + 1)
def boom(*a, **k): raise RuntimeError("disk full")
service.run_checks = boom; db.set_setting("schedule_enabled", True); db.set_setting("schedule_groups", [])
db.set_setting("schedule_on_start", True)
d4 = service.Daemon(log=log.append)
import threading
th = threading.Thread(target=lambda: d4.run(poll=0.05), daemon=True); th.start(); time.sleep(0.4); d4.stop(); th.join(3)
check("an error in one run is logged and the service keeps going", any("disk full" in l for l in log) and not th.is_alive())

print("== command line")
service.run_checks = lambda groups=None, do_notify=True, scheduled=True, on_result=None, own=False: [Result("core1", "cpu", "WARN", "85%", "high", numeric=85.0), Result("edge-fw", "cpu", "OK", "5%")]
def run(*args):
    out = io.StringIO()
    with redirect_stdout(out):
        code = cli.main(list(args))
    return code, out.getvalue()
code, out = run("run"); check("table output with totals; WARN passes the default --fail-on fail", code == 0 and "WARN  core1" in out and "OK 1  WARN 1" in out, out)
code, out = run("run", "--fail-on", "warn"); check("--fail-on warn fails on a warning", code == 1)
code, out = run("run", "--fail-on", "never"); check("--fail-on never always succeeds", code == 0)
code, out = run("run", "--json"); data = json.loads(out); check("--json is machine readable", data[0]["device"] == "core1" and data[0]["numeric"] == 85.0 and len(data) == 2)
service.run_checks = lambda *a, **k: [Result("x", "cpu", "FAIL", "99%")]
check("a failure exits 1", run("run")[0] == 1)
service.run_checks = lambda *a, **k: []
check("nothing to check exits 2", run("run")[0] == 2)
err = io.StringIO()
import contextlib
with contextlib.redirect_stderr(err): code = cli.main(["run", "--group", "Vendor: Nope"])
check("an unknown group is reported with the real ones", code == 2 and "Unknown group" in err.getvalue() and "Vendor: Cisco" in err.getvalue(), err.getvalue())
service.run_backups = lambda *a, **k: [Result("core1", "config backup", "ERROR", "", "boom")]
check("backup: an error exits 1", run("backup")[0] == 1)
service.run_backups = lambda *a, **k: [Result("core1", "config backup", "WARN", "changed")]
check("backup: a change is not an error", run("backup")[0] == 0)
code, out = run("status"); check("status lists devices and their problems; exit 0 without failures", "core1" in out and code == 0, out)
db.save_run([Result("core1", "cpu", "FAIL", "99%", "hot")])
code, out = run("status"); check("a failing device makes status exit 1", code == 1 and "FAIL  cpu  hot" in out.replace("      ", "  ") or code == 1, out)
code, out = run("status", "--json"); check("status --json", json.loads(out)[0]["problems"] is not None)
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
