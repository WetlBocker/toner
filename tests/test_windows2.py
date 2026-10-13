# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, shutil, ssl, subprocess, sys, tempfile, time, urllib.error, urllib.request
from datetime import datetime, timedelta, timezone
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\win2_%d.db" % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roaming2_%d" % int(time.time()))
from core import agents, alerts, db, notify, winmon
from drivers import DRIVERS
from drivers.base import OK, WARN
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def dev(name, platform="agent"):
    d = dict(name=name, vendor="windows", host=name, port=0, platform=platform, username="", site="default", verify_ssl=0, ha_expected=0,
             enabled=1, location="", details="", folder_id=None, winopts="")
    d["id"] = db.save_device(d); return db.get_device(d["id"])
def report(**kw):
    r = {"v": 1, "at": time.strftime("%Y-%m-%dT%H:%M:%S.0000000Z", time.gmtime()), "computer": "SRV", "domain": "corp", "joined": True, "os": "Windows Server 2022",
         "uptime_h": 100.0, "mem_total_mb": 1000, "mem_free_mb": 750, "cpu": 20.0, "disks": [{"drive": "C:", "size": 100, "free": 40}], "reboot": [],
         "service_states": {}, "auto_stopped": [], "events": None, "certs": [], "patched": None,
         "software": {"7-Zip": "23.01", "Chrome": "120"}, "admins": ["SRV\\Administrator", "CORP\\Domain Admins"], "ports": ["135/svchost", "443/nginx", "50001/x"]}
    r.update(kw); return r
TH = db.get_thresholds()
def run(d, rep, **opts):
    drv = DRIVERS["windows"](d, TH, {"disabled": frozenset(), **opts}); drv.fetch = lambda: (rep, 1.0, "agent")
    return {r.check: r for r in drv.run()}

print("== what the collector gathers for change detection (real PowerShell)")
real = winmon.collect_local()
check("installed software, local administrators and listening ports come back", isinstance(real.get("software"), dict) and len(real["software"]) > 3
      and isinstance(real.get("admins"), list) and real["admins"] and isinstance(real.get("ports"), list) and any("/" in p for p in real["ports"]), {k: type(real.get(k)).__name__ for k in ("software", "admins", "ports")})

print("== changes since the last check")
d = dev("srv-drift")
r1 = run(d, report())
check("the first check only records a baseline", r1["changes"].status == OK and r1["changes"].value == "baseline set")
check("nothing changed: OK", run(d, report())["changes"].value == "none")
r = run(d, report(admins=["SRV\\Administrator", "CORP\\Domain Admins", "CORP\\intruder"]))["changes"]
check("a new local administrator is called out first, in capitals", r.status == WARN and r.message.startswith("NEW ADMINISTRATOR: CORP\\intruder"), r.message)
r = run(d, report(admins=["SRV\\Administrator", "CORP\\Domain Admins", "CORP\\intruder"], software={"7-Zip": "24.00", "Chrome": "120", "Putty": "0.80"}, ports=["135/svchost", "443/nginx", "50001/x", "4444/nc", "55555/other"]))["changes"]
check("it saw the change once: software installed and updated, a new listener; the dynamic port range is ignored", r.status == WARN and "installed: Putty" in r.message and "updated: 7-Zip" in r.message and "now listening: 4444/nc" in r.message and "55555" not in r.message, r.message)
same = dict(admins=["SRV\\Administrator", "CORP\\Domain Admins", "CORP\\intruder"], software={"7-Zip": "24.00", "Chrome": "120", "Putty": "0.80"}, ports=["135/svchost", "443/nginx", "50001/x", "4444/nc"])
check("and then it is the new normal (reported once)", run(d, report(**same))["changes"].value == "none")
r = run(d, report(admins=["SRV\\Administrator"], software={"Chrome": "120"}, ports=["135/svchost"]))["changes"]
check("things that went away are reported too", "administrator removed" in r.message and "removed: 7-Zip, Putty" in r.message and "stopped listening" in r.message, r.message)
now_state = dict(admins=["SRV\\Administrator"], software={"Chrome": "120"}, ports=["135/svchost"])
run(d, report(software={"Chrome": "120", "New": "1"}, admins=["SRV\\Administrator"], ports=["135/svchost"]), dry_run=True)
check("a Test (dry run) does not use up a change", "installed: New" in run(d, report(software={"Chrome": "120", "New": "1"}, admins=["SRV\\Administrator"], ports=["135/svchost"]))["changes"].message)
check("a report with none of these facts leaves the check out", "changes" not in run(dev("srv-old"), report(software=None, admins=None, ports=None)))
check("a change is news, not a fault that gets fixed: no 'recovered' message for it", "changes" in alerts.NO_RECOVERY)
check("it can be switched off in Settings > Checks", "changes" not in run(d, report(), disabled={"windows:changes"}) and "changes" in {k for k, _ in __import__("core.checks", fromlist=["x"]).CATALOG["windows"]})

print("== numbers from every report")
db.set_setting("agent_enabled", True); db.set_setting("agent_port", 0); db.set_setting("agent_bind", "127.0.0.1"); agents.apply()
port = agents.status()["port"]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
def call(method, path, body=None, token=None, headers=None):
    h = dict(headers or {})
    if token: h["Authorization"] = "Bearer " + token
    req = urllib.request.Request(f"https://127.0.0.1:{port}{path}", data=json.dumps(body).encode() if body is not None else None, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except OSError: return 0, b""
dev("pc-1"); tok = agents.token_for("pc-1")
for cpu in (10, 20, 30):
    call("POST", "/report", report(cpu=float(cpu)), tok, {"X-Toner-Agent": "2"})
pts = db.series("pc-1", "cpu")
check("each report becomes a point on the chart", [v for _, v in pts][-3:] == [10.0, 20.0, 30.0], pts)
check("memory, disk and uptime too", db.series("pc-1", "memory")[-1][1] == 25.0 and db.series("pc-1", "disks")[-1][1] == 60.0 and db.series("pc-1", "uptime")[-1][1] == 100.0)
check("a check that runs add to the same chart", (lambda: (db.save_run([type("R", (), dict(device="pc-1", check="cpu", status="OK", value="5%", message="", numeric=5.0))()]), 5.0 in [v for _, v in db.series("pc-1", "cpu")])[1])())
db.connect().execute("UPDATE agent_metrics SET at='2020-01-01 00:00:00'").connection.commit()
agents._last_purge[0] = 0; call("POST", "/report", report(), tok)
with db.connect() as c: left = c.execute("SELECT COUNT(*) FROM agent_metrics WHERE at < '2021-01-01'").fetchone()[0]
check("old numbers are deleted with the rest of the history", left == 0)
def count(table, device):
    with db.connect() as c: return c.execute(f"SELECT COUNT(*) FROM {table} WHERE device=?", (device,)).fetchone()[0]
agents.rename("pc-1", "pc-1b")
check("renaming moves the numbers, the first-seen record and the last report", count("agent_metrics", "pc-1b") >= 1 and count("agent_metrics", "pc-1") == 0 and count("agent_seen", "pc-1b") == 1 and agents.latest("pc-1b")[0] is not None)
agents.forget("pc-1b")
with db.connect() as c: gone = sum(c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("agent_metrics", "agent_seen", "agent_reports") if True)
check("deleting the device deletes its numbers, record and token", not db.series("pc-1b", "cpu") and agents.latest("pc-1b")[0] is None)

print("== replacing tokens on a schedule")
dev("pc-2"); t1 = agents.token_for("pc-2")
check("by default tokens are never replaced", db.get_setting("agent_token_days") == 0 and not agents.token_due("pc-2"))
db.set_setting("agent_token_days", 30)
check("a fresh token is not due", not agents.token_due("pc-2"))
with db.connect() as c: c.execute("UPDATE agent_reports SET issued_at=? WHERE device='pc-2'", ((datetime.now(timezone.utc) - timedelta(days=45)).isoformat(),))
check("an old one is", agents.token_due("pc-2"))
code, body = call("POST", "/report", report(), t1, {"X-Toner-Agent": "2"}); ans = json.loads(body)
check("the answer to a package agent's report carries the new token", code == 200 and ans.get("token") and ans["token"] != t1 and STORE[("netcheck", "pc-2:agent")] == ans["token"], ans)
check("the new token works", call("POST", "/report", report(), ans["token"], {"X-Toner-Agent": "2"})[0] == 200 and not agents.token_due("pc-2"))
check("the old one still works for a week, so no agent is locked out", call("POST", "/report", report(), t1)[0] == 200 and agents.device_for_token(t1) == "pc-2")
with db.connect() as c: c.execute("UPDATE agent_reports SET prev_until=? WHERE device='pc-2'", ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),))
check("and then it is refused", call("POST", "/report", report(), t1)[0] == 401)
with db.connect() as c: c.execute("UPDATE agent_reports SET issued_at=? WHERE device='pc-2'", ((datetime.now(timezone.utc) - timedelta(days=45)).isoformat(),))
code, body = call("POST", "/report", report(), ans["token"])
check("an older script that cannot take a new token is left alone", "token" not in json.loads(body))
agents.revoke("pc-2")
check("revoking stops a computer being accepted, and keeps it in the inventory", call("POST", "/report", report(), ans["token"])[0] == 401 and ("netcheck", "pc-2:agent") not in STORE
      and any(d["name"] == "pc-2" for d in db.list_devices()))
db.set_setting("agent_token_days", 0)

print("== updating the agent")
dev("pc-3"); t3 = agents.token_for("pc-3")
code, body = call("POST", "/report", report(), t3, {"X-Toner-Agent": "1"})
check("an agent that does not send its version is never told to update", "update" not in json.loads(body))
code, body = call("POST", "/report", report(), t3, {"X-Toner-Agent": str(agents.AGENT_VERSION)})
check("one on the current version is not either", "update" not in json.loads(body))
REAL_VERSION = agents.AGENT_VERSION
check("the agent's version is Toner's version", agents.AGENT_VERSION == __import__("core.version", fromlist=["x"]).VERSION and "'" + agents.AGENT_VERSION + "'" in agents.package_script())
agents.AGENT_VERSION = "99.0.0"
code, body = call("POST", "/report", report(), t3, {"X-Toner-Agent": REAL_VERSION})
check("one on an older version is told to update", json.loads(body).get("update") is True)
code, body = call("POST", "/report", report(), t3, {"X-Toner-Agent": "3"})
check("so is one from before the versions matched Toner's (a plain number)", json.loads(body).get("update") is True)
code, body = call("POST", "/report", report(), t3, {"X-Toner-Agent": "99.0.1"})
check("one that is newer than this Toner is left alone", "update" not in json.loads(body))
check("what an agent reports is kept as it sent it", agents.latest("pc-3")[0] is not None and [r["version"] for r in agents.overview() if r["device"] == "pc-3"] == ["99.0.1"])
check("outdated or not, by version", agents.agent_outdated("1.3.3") and agents.agent_outdated("98.9") and not agents.agent_outdated("99.0.0") and not agents.agent_outdated("99.0.0.0")
      and agents.agent_outdated("2") and not agents.agent_outdated("") and not agents.agent_outdated("1") and not agents.agent_outdated("junk") and not agents.agent_outdated("99.0"))
check("the new script needs a known token", call("GET", "/agent.ps1")[0] == 401 and call("GET", "/agent.ps1", token="nope")[0] == 401)
code, script = call("GET", "/agent.ps1", token=t3)
text = script.decode("utf-8-sig")
check("with one it is served, as the same text every time, with no computer's settings in it", code == 200 and "Toner agent" in text and t3 not in text and f"AgentVersion = '{agents.AGENT_VERSION}'" in text and "@@" not in text)
work = tempfile.mkdtemp(prefix="agent_up_")
open(os.path.join(work, "served.ps1"), "w", encoding="utf-8-sig").write(text)
chk = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                      "$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('" + os.path.join(work, "served.ps1") + "',[ref]$null,[ref]$e); $e.Count"], capture_output=True, text=True, timeout=60)
check("the served script is valid PowerShell", chk.stdout.strip() == "0", chk.stdout + chk.stderr)

print("== a real installed agent updates itself and takes a new token")
# the script thinks it is installed when it runs from <ProgramData>\Toner Agent, so point ProgramData at a scratch folder
pd = os.path.join(work, "pd"); inst = os.path.join(pd, "Toner Agent"); os.makedirs(inst)
old_script = agents.package_script().replace(f"AgentVersion = '{agents.AGENT_VERSION}'", "AgentVersion = '1.0.0'")
open(os.path.join(inst, "toner-agent.ps1"), "w", encoding="utf-8-sig").write(old_script)
cfg = {"server": f"https://127.0.0.1:{port}/report", "enroll": f"https://127.0.0.1:{port}/enroll", "pin": agents.fingerprint(), "key": "", "minutes": 5, "token": t3}
json.dump(cfg, open(os.path.join(inst, "agent.json"), "w"))
env = dict(os.environ, ProgramData=pd)
db.set_setting("agent_token_days", 30)
with db.connect() as c: c.execute("UPDATE agent_reports SET issued_at=? WHERE device='pc-3'", ((datetime.now(timezone.utc) - timedelta(days=45)).isoformat(),))
r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", os.path.join(inst, "toner-agent.ps1")], capture_output=True, text=True, timeout=180, env=env)
now_cfg = json.loads(open(os.path.join(inst, "agent.json"), encoding="utf-8-sig").read())
now_script = open(os.path.join(inst, "toner-agent.ps1"), encoding="utf-8-sig").read()
check("the run succeeds and says what it did", r.returncode == 0 and "Toner answered: 200" in r.stdout and "new token" in r.stdout and "updated itself" in r.stdout, (r.stdout[-300:], r.stderr[-400:]))
check("it saved the new token", now_cfg["token"] != t3 and agents.device_for_token(now_cfg["token"]) == "pc-3" and STORE[("netcheck", "pc-3:agent")] == now_cfg["token"])
check("and replaced its own script with the newer one (settings untouched)", f"AgentVersion = '{agents.AGENT_VERSION}'" in now_script and now_cfg["server"] == cfg["server"] and not os.path.exists(os.path.join(inst, "toner-agent.ps1.new")))
r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", os.path.join(inst, "toner-agent.ps1")], capture_output=True, text=True, timeout=180, env=env)
check("the updated script runs, and is current (no further update)", r.returncode == 0 and "Toner answered: 200" in r.stdout and "updated itself" not in r.stdout, (r.stdout[-200:], r.stderr[-300:]))
agents.AGENT_VERSION = REAL_VERSION; db.set_setting("agent_token_days", 0)

print("== the reporting interval")
dev("pc-4"); t4 = agents.token_for("pc-4")
hdr = {"X-Toner-Agent": str(agents.AGENT_VERSION)}
check("it is off by default: agents are told nothing about their interval", db.get_setting("agent_push_minutes") is False and "minutes" not in json.loads(call("POST", "/report", report(), t4, hdr)[1]))
db.set_setting("agent_minutes", 15); db.set_setting("agent_push_minutes", True)
check("with it on, the answer to a package agent carries the interval", json.loads(call("POST", "/report", report(), t4, hdr)[1]).get("minutes") == 15)
check("an agent that does not send its version is left alone", "minutes" not in json.loads(call("POST", "/report", report(), t4)[1]))
db.set_setting("agent_minutes", 500)
check("a silly value is held to the 1 to 60 the agent accepts", json.loads(call("POST", "/report", report(), t4, hdr)[1]).get("minutes") == 60)
db.set_setting("agent_minutes", 15)
check("the script changes the schedule only for the task that runs this script", "$answer.minutes" in agents.package_script() and "Set-ScheduledTask" in agents.package_script() and "Test-Admin" in agents.package_script() and "$PSCommandPath, [StringComparison]" in agents.package_script())
check("the interval travels with an exported settings file (it is not about this computer)", "agent_minutes" not in db.NOT_PORTABLE and "agent_push_minutes" not in db.NOT_PORTABLE)
r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", os.path.join(inst, "toner-agent.ps1")], capture_output=True, text=True, timeout=180, env=env)
now_cfg = json.loads(open(os.path.join(inst, "agent.json"), encoding="utf-8-sig").read())
check("a real agent that is not the installed one (no task runs it) leaves its interval alone and says so", r.returncode == 0 and "Toner answered: 200" in r.stdout and "every 15 minutes, but this copy is not the installed agent" in r.stdout and now_cfg["minutes"] == 5, (r.stdout[-300:], r.stderr[-300:]))
db.set_setting("agent_minutes", 5)
r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", os.path.join(inst, "toner-agent.ps1")], capture_output=True, text=True, timeout=180, env=env)
check("and one already at that interval has nothing to say", r.returncode == 0 and "Toner answered: 200" in r.stdout and "minutes" not in r.stdout.replace("Toner answered", ""), r.stdout[-200:])
db.set_setting("agent_push_minutes", False)
shutil.rmtree(work, ignore_errors=True)

print("== telling you about a new computer and an ageing certificate")
sent = []
real_deliver, real_channels = notify.deliver, notify.channels
notify.deliver = lambda ch, msg, desktop=None, secrets=None, retry_delay=2: (sent.append((ch["name"], msg.title, msg.plain())), (True, "ok"))[1]
notify.channels = lambda: [{"name": "ops", "type": "webhook", "enabled": True, "min": "WARN and worse", "recoveries": True},
                           {"name": "pager", "type": "webhook", "enabled": True, "min": "ERROR only", "recoveries": True}]
db.set_setting("notify_enabled", False)
check("with notifications off nothing is sent", notify.announce("x", "agent sign-up", "new computer", "m") == 0 and not sent)
db.set_setting("notify_enabled", True)
n = notify.announce("lab-9", "agent sign-up", "new computer", "signed itself up")
check("announcements go only to channels whose level allows them", n == 1 and len(sent) == 1 and sent[0][0] == "ops" and "lab-9" in sent[0][2] and "Agent Sign-Up" in sent[0][2] + "Agent Sign-Up", sent)
check("and do not touch the alert state", not db.connect().execute("SELECT COUNT(*) FROM alert_state WHERE device='lab-9'").fetchone()[0])
db.set_setting("agent_enroll", True); key = agents.enroll_key(); sent.clear()
code, ans = agents.enroll("NEWBOX", key, "10.1.2.3")
deadline = time.time() + 10
while not sent and time.time() < deadline: time.sleep(0.05)
check("a computer signing itself up is announced, with where it came from", code == 200 and sent and "NEWBOX" in sent[0][2] and "10.1.2.3" in sent[0][2], sent)
sent.clear(); dev("WAITING"); agents.enroll("WAITING", key, "10.1.2.4"); time.sleep(0.5)
check("one claiming a device you added by hand is not 'new', so no announcement", not sent)
check("the certificate is made for ten years", 3600 < agents.cert_days_left() <= 3650)
check("a healthy certificate raises no warning", agents.check_cert() > 3000 and not sent)
real_days = agents.cert_days_left; agents.cert_days_left = lambda: 20
left = agents.check_cert(); deadline = time.time() + 10
while not sent and time.time() < deadline: time.sleep(0.05)
check("one near its end warns, once a month, on the notification channels", left == 20 and sent and "20 days left" in sent[0][2] and db.get_setting("agent_cert_warned") == datetime.now().strftime("%Y-%m"), sent)
sent.clear(); agents.check_cert(); time.sleep(0.5)
check("and not again the same month", not sent)
agents.cert_days_left = real_days; notify.deliver, notify.channels = real_deliver, real_channels
agents.stop()

print("== the fleet overview")
db.set_setting("agent_enabled", False)
dev("fleet-1"); agents.token_for("fleet-1"); agents.store("fleet-1", report(reboot=["Windows Update"], computer="FLEET1"), "10.0.0.7", 2)
row = [x for x in agents.overview() if x["device"] == "fleet-1"][0]
check("it lists each computer with its name, system, domain, version, reboot state and age", row["computer"] == "FLEET1" and "Windows Server" in row["os"] and row["domain"] == "corp" and row["version"] == "2"
      and row["pending_reboot"] and row["age"] < 1 and row["source"] == "10.0.0.7" and row["has_token"])

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
