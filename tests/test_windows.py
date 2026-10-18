# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform != "win32":                       # the Windows agent and real PowerShell (the receiver is also tested in test_orgs_more and test_orgs_round3)
    print("skipped: this test is about Windows itself"); print("\n0 passed, 0 failed"); _sys.exit(0)
import json, os, shutil, ssl, subprocess, sys, tempfile, time, urllib.request, urllib.error
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\win%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roaming%d" % int(time.time()))
from core import agents, checks, db, display, runner, vendors, winmon
from drivers import DRIVERS
from drivers.base import OK, WARN, FAIL, ERROR
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

def dev(name, platform="agent", **kw):
    d = dict(name=name, vendor="windows", host=name, port=0, platform=platform, username="", site="default", verify_ssl=0,
             ha_expected=0, enabled=1, location="", details="", folder_id=None, winopts="")
    d.update(kw)
    d["id"] = db.save_device(d); return db.get_device(d["id"])

NOW = time.time()
def report(**kw):
    r = {"v": 1, "at": time.strftime("%Y-%m-%dT%H:%M:%S.0000000Z", time.gmtime()), "computer": "SRV1", "domain": "corp.example.com", "joined": True, "os": "Microsoft Windows Server 2022 Standard",
         "uptime_h": 400.0, "mem_total_mb": 16384, "mem_free_mb": 12288, "cpu": 12.0,
         "disks": [{"drive": "C:", "size": 100 * 2**30, "free": 40 * 2**30}, {"drive": "D:", "size": 500 * 2**30, "free": 300 * 2**30}],
         "reboot": [], "service_states": {"Spooler": "R", "W32Time": "R", "MSSQLSERVER": "S"}, "auto_stopped": [],
         "events": {"count": 3, "capped": False, "top": [{"source": "Service Control Manager", "count": 3}]},
         "certs": [], "patched": time.strftime("%Y-%m-%dT%H:%M:%S.0000000Z", time.gmtime(NOW - 10 * 86400))}
    r.update(kw); return r

TH = db.get_thresholds()
def run(d, rep, age=1.0, how="agent", disabled=()):
    drv = DRIVERS["windows"](d, TH, {"disabled": frozenset(disabled)})
    drv.fetch = lambda: (rep, age, how)
    return {r.check: r for r in drv.run()}

print("== the vendor")
check("Windows is a vendor with three ways to monitor", vendors.get("windows")["name"] == "Windows" and [k for k, _ in vendors.get("windows")["platforms"]] == ["agent", "winrm", "local"]
      and display.vendor_name("windows") == "Windows" and display.platform_name("winrm") == "WinRM (Toner connects)")
check("it has a driver and a list of checks", "windows" in DRIVERS and {k for k, _ in checks.CATALOG["windows"]} >= {"cpu", "memory", "disks", "services", "events", "certificates", "patches", "pending reboot"})
check("the new thresholds exist, and expiry days are lower-is-worse", {"win_events", "patch_days", "cert_days", "agent_silent"} <= set(db.DEFAULT_THRESHOLDS) and "cert_days" in db.LOWER_IS_WORSE)
check("an agent device is not looked up in DNS (a laptop away from the office would fail), WinRM is", not winmon.needs_dns({"platform": "agent"}) and not winmon.needs_dns({"platform": "local"}) and winmon.needs_dns({"platform": "winrm"}))

print("== the checks, from a report")
d = dev("srv-ok")
r = run(d, report())
check("a healthy server is all OK", {k: v.status for k, v in r.items()} == {"reachability": OK, "cpu": OK, "memory": OK, "disks": OK, "uptime": OK, "pending reboot": OK,
      "services": OK, "events": OK, "certificates": OK, "patches": OK}, {k: v.status for k, v in r.items()})
check("values and numbers for the charts", r["memory"].numeric == 25.0 and r["cpu"].numeric == 12.0 and round(r["disks"].numeric) == 60 and r["uptime"].numeric == 400.0 and round(r["patches"].numeric) == 10 and r["events"].numeric == 3.0)
check("the disks row names the fullest volume and every volume's free space", "fullest C:" in r["disks"].message and "D: 40%" in r["disks"].message and "40.0 GB free" in r["disks"].message, r["disks"].message)
check("the identity row says what the computer is", r["reachability"].value == "SRV1" and "Windows Server 2022" in r["reachability"].message and "corp.example.com" in r["reachability"].message)
check("thresholds apply", run(d, report(cpu=95.0))["cpu"].status == FAIL and run(d, report(cpu=75.0))["cpu"].status == WARN
      and run(d, report(mem_free_mb=1000))["memory"].status == FAIL and run(d, report(disks=[{"drive": "C:", "size": 100, "free": 5}]))["disks"].status == FAIL
      and run(d, report(disks=[{"drive": "C:", "size": 100, "free": 15}]))["disks"].status == WARN)
check("a recent reboot is flagged", run(d, report(uptime_h=0.5))["uptime"].status == WARN)
rb = run(d, report(reboot=["Windows Update", "computer rename"]))["pending reboot"]
check("a pending reboot is a warning, with the reasons", rb.status == WARN and "Windows Update" in rb.message and rb.value == "yes")
ev = run(d, report(events={"count": 300, "capped": False, "top": [{"source": "Disk", "count": 200}]}))["events"]
check("event errors are graded and name the noisiest source", ev.status == FAIL and "Disk x200" in ev.message and run(d, report(events={"count": 30, "capped": False, "top": []}))["events"].status == WARN)
check("an event log that could not be read is left out, not failed", "events" not in run(d, report(events=None)))
ce = run(d, report(certs=[{"subject": "CN=web.corp", "days": 5, "thumb": "x"}, {"subject": "CN=old", "days": 60, "thumb": "y"}]))["certificates"]
check("the nearest certificate expiry is graded (lower is worse)", ce.status == FAIL and ce.numeric == 5.0 and "web.corp" in ce.message
      and run(d, report(certs=[{"subject": "CN=a", "days": 20, "thumb": "x"}]))["certificates"].status == WARN
      and run(d, report(certs=[{"subject": "CN=a", "days": -3, "thumb": "x"}]))["certificates"].value == "expired")
old = time.strftime("%Y-%m-%dT%H:%M:%S.0000000Z", time.gmtime(NOW - 120 * 86400))
check("an old patch level is flagged", run(d, report(patched=old))["patches"].status == FAIL and run(d, report(patched=time.strftime("%Y-%m-%dT%H:%M:%S.0000000Z", time.gmtime(NOW - 60 * 86400))))["patches"].status == WARN)
check("a check can be switched off in Settings", "cpu" not in run(d, report(), disabled={"windows:cpu"}) and "memory" in run(d, report(), disabled={"windows:cpu"}))

print("== services")
auto = [{"name": "Spooler", "display": "Print Spooler", "exit": 1, "delayed": False, "trigger": False},
        {"name": "sppsvc", "display": "Software Protection", "exit": 0, "delayed": True, "trigger": True},
        {"name": "gupdate", "display": "Google Update", "exit": 0, "delayed": True, "trigger": False},
        {"name": "CDPUserSvc_4f3a2", "display": "per-user", "exit": 0, "delayed": False, "trigger": False},
        {"name": "BackupAgent", "display": "Backup", "exit": 0, "delayed": False, "trigger": False}]
sv = run(d, report(auto_stopped=auto))["services"]
check("stopped automatic services are a warning; trigger-start, per-user, delayed-at-boot-time and well-known updaters are skipped",
      sv.status == WARN and sv.value == "2 stopped" and "Spooler" in sv.message and "BackupAgent" in sv.message and "sppsvc" not in sv.message and "gupdate" not in sv.message and "CDPUserSvc" not in sv.message, sv.message)
dl = [{"name": "Late", "display": "x", "exit": 0, "delayed": True, "trigger": False}]
check("a delayed-start service is expected to be down just after boot, not later", run(d, report(auto_stopped=dl, uptime_h=0.1, ))["services"].status == OK and run(d, report(auto_stopped=dl, uptime_h=5))["services"].status == WARN)
dw = dev("srv-watch", winopts={"watch": ["Spooler", "MSSQLSERVER", "Nope"], "ignore": ["BackupAgent"]})
sv = run(dw, report(auto_stopped=auto))["services"]
check("a watched service that is down is a failure; one that does not exist says so", sv.status == FAIL and "MSSQLSERVER" in sv.message and "Nope (not installed)" in sv.message and "Spooler" not in sv.message.split("Nope")[0].replace("MSSQLSERVER", ""), sv.message)
check("an ignored service is not reported", "BackupAgent" not in run(dev("srv-ign", winopts={"ignore": ["BackupAgent", "Spool*"]}), report(auto_stopped=auto))["services"].message)
check("options have safe defaults, and bad JSON is tolerated", winmon.options({"winopts": "not json"}) == {"https": False, "auth": "negotiate", "watch": [], "ignore": []}
      and winmon.options({"winopts": json.dumps({"watch": "A, B;C", "auth": "bogus", "https": 1})}) == {"https": True, "auth": "negotiate", "watch": ["A", "B", "C"], "ignore": []})

print("== a silent agent")
check("a report a few minutes old is fine", run(d, report(), age=3)["reachability"].status == OK)
late = run(d, report(), age=20)
check("a late report warns, and the rest of the checks still show", late["reachability"].status == WARN and "cpu" in late and late["reachability"].numeric == 20.0)
gone = run(d, report(), age=180)
check("a report hours old fails, and only that row is shown (old numbers would mislead)", set(gone) == {"reachability"} and gone["reachability"].status == FAIL and "3.0 h ago" in gone["reachability"].value and "stopped reporting" in gone["reachability"].message)
check("WinRM and this-computer runs are not judged by report age", run(d, report(), age=None, how="winrm")["reachability"].status == OK)
try:
    DRIVERS["windows"](dev("never"), TH, {}).run(); check("no report yet raises a clear error", False)
except RuntimeError as e: check("with no report yet, the runner is told how to set the agent up", "agent script" in str(e) and "Settings" in str(e), e)
res = runner.run_one(dev("never2"), TH, {"retries": 0})
check("and the run shows it as one ERROR row (no DNS lookup was needed for an unresolvable agent name)", len(res) == 1 and res[0].check == "connection" and res[0].status == ERROR and "agent script" in res[0].message, [(x.check, x.message) for x in res])

print("== WinRM, with a stand-in for the remote computer")
class Streams: error = []
class FakeClient:
    seen = {}
    def __init__(self, host, **kw): FakeClient.seen = dict(host=host, **kw)
    def execute_ps(self, script):
        if FakeClient.seen.get("password") == "boom": raise Exception("the specified credentials were rejected by the server (401)")
        FakeClient.script = script
        return json.dumps(report(computer="WINRM1")), Streams(), False
w = dev("srv-winrm", "winrm", host="srv.corp.example.com", username=r"CORP\monitor")
got = winmon.collect_winrm(w, "secret", factory=FakeClient)
check("the collector script is run and its JSON is read", got["computer"] == "WINRM1" and "Win32_OperatingSystem" in FakeClient.script and "ConvertTo-Json" in FakeClient.script)
s = FakeClient.seen
check("by default it uses HTTP on 5985 with the Windows sign-in, as the given user", s["host"] == "srv.corp.example.com" and s["port"] == 5985 and s["ssl"] is False and s["auth"] == "negotiate" and s["username"] == r"CORP\monitor" and s["password"] == "secret", s)
w2 = dev("srv-winrm-tls", "winrm", username="u", winopts={"https": True, "auth": "ntlm"}, verify_ssl=1)
winmon.collect_winrm(w2, "p", factory=FakeClient); s = FakeClient.seen
check("HTTPS uses 5986, the chosen sign-in method, and verifies the certificate when asked", s["port"] == 5986 and s["ssl"] is True and s["auth"] == "ntlm" and s["cert_validation"] is True, s)
winmon.collect_winrm(dev("srv-winrm-port", "winrm", port=5986, username="u"), "p", factory=FakeClient)
check("port 5986 means HTTPS even without the box", FakeClient.seen["ssl"] is True and FakeClient.seen["cert_validation"] is False)
winmon.collect_winrm(dev("srv-sso", "winrm"), "", factory=FakeClient)
check("with no user name it signs in as the Windows user running Toner (single sign-on on a domain)", FakeClient.seen["username"] is None and FakeClient.seen["password"] is None)
try: winmon.collect_winrm(w, "boom", factory=FakeClient); check("a rejected login is reported", False)
except RuntimeError as e: check("a rejected login is explained in plain words", "rejected the sign-in" in str(e) and "Remote Management Users" in str(e), e)
check("other failures are explained too", "WinRM is not enabled" in winmon.explain(TimeoutError("Connection timed out"), False, 5985) and "refused" in winmon.explain(ConnectionError("Connection refused"), True, 5986)
      and "Kerberos" in winmon.explain(Exception("SPNEGO: Server not found in Kerberos database"), False, 5985) and "certificate" in winmon.explain(Exception("SSL: CERTIFICATE_VERIFY_FAILED"), True, 5986))
class FakeNoOut(FakeClient):
    def execute_ps(self, script): return "", Streams(), True
try: winmon.collect_winrm(w, "p", factory=FakeNoOut); check("empty answer", False)
except RuntimeError as e: check("an empty answer is an error", "returned nothing" in str(e))
rr = DRIVERS["windows"](w, TH, {"disabled": frozenset()}); rr.dev = {**w, "password": "secret"}
import core.winmon as _wm; real = _wm.collect_winrm; _wm.collect_winrm = lambda dev, pw, timeout=30, factory=None: real(dev, pw, timeout, FakeClient)
res = {x.check: x for x in rr.run()}
_wm.collect_winrm = real
check("the driver runs the checks on what WinRM returned (using the saved password)", res["reachability"].value == "WINRM1" and res["cpu"].status == OK and FakeClient.seen["password"] == "secret")
t0 = time.time()
try: winmon.collect_winrm(dev("srv-closed", "winrm", host="127.0.0.1", port=5999, username="u"), "p", timeout=5); check("closed port", False)
except RuntimeError as e: check("a real attempt on a closed port gives a readable reason, quickly", ("refused" in str(e) or "no answer" in str(e) or "not listening" in str(e)) and time.time() - t0 < 20, e)

print("== this computer (real PowerShell)")
t0 = time.time()
loc = winmon.collect_local()
check("the collector runs for real and returns this computer's facts", loc["computer"] == os.environ["COMPUTERNAME"] and loc["mem_total_mb"] > 0 and loc["disks"] and loc["service_states"] and "os" in loc, list(loc))
rl = run(dev("this-pc", "local", host="localhost"), loc, age=None, how="local")
check("and every check turns it into a result without an error", rl and not [k for k, v in rl.items() if v.status == ERROR] and {"cpu", "memory", "disks", "uptime"} <= set(rl), {k: (v.status, v.message) for k, v in rl.items()})
check("the real thing is quick enough to run on a schedule", time.time() - t0 < 60, time.time() - t0)

print("== the receiver and the agent script (real HTTPS, real PowerShell)")
db.set_setting("agent_enabled", True); db.set_setting("agent_port", 0); db.set_setting("agent_bind", "127.0.0.1")
check("with the receiver on, it listens", agents.apply() == "" and agents.running() and agents.status()["port"] > 0)
port = agents.status()["port"]
fp = agents.fingerprint()
check("the certificate is made once and keeps its fingerprint", len(fp) == 64 and agents.fingerprint() == fp and os.path.exists(os.path.join(os.environ["APPDATA"], "NetCheck", "agent", "toner-agent.crt")), os.listdir(os.environ["APPDATA"]))
ag = dev("laptop-7", "agent", host="laptop-7.corp.example.com")
tok = agents.token_for("laptop-7")
check("a token is long and random, and only its hash is in the database", len(tok) >= 40 and agents.token_for("laptop-7") == tok and tok not in json.dumps([dict(r) for r in db.connect().execute("SELECT * FROM agent_reports")])
      and agents.device_for_token(tok) == "laptop-7" and agents.device_for_token("wrong") == "" and agents.device_for_token("") == "")
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
def post(body, token=tok, path="/report"):
    req = urllib.request.Request(f"https://127.0.0.1:{port}{path}", data=body if isinstance(body, bytes) else json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r: return r.status
    except urllib.error.HTTPError as e: return e.code
    except OSError: return 0                              # the receiver hung up (it does not read an oversized body)
check("a report with the right token is accepted and stored", post(report(computer="LAPTOP-7")) == 200 and agents.latest("laptop-7")[0]["computer"] == "LAPTOP-7" and agents.latest("laptop-7")[1] < 1)
check("a wrong token is refused and nothing is stored for it", post(report(), token="nope") == 401 and agents.status()["rejected"] >= 1)
check("something that is not a report is refused", post(b"hello") == 400 and post(b'{"x":1}') == 400)
check("an oversized body is refused", post(b"{" + b"a" * (agents.MAX_BODY + 10)) in (413, 0))
check("the other paths do not exist", post(report(), path="/other") == 404)
with urllib.request.urlopen(f"https://127.0.0.1:{port}/ping", context=ctx, timeout=10) as r: ping = r.read().decode()
check("/ping says what it is and nothing more", ping.strip() == "Toner agent receiver")
run_a = run(ag, agents.latest("laptop-7")[0], age=agents.latest("laptop-7")[1])
check("the stored report flows through the checks", run_a["reachability"].value == "LAPTOP-7" and run_a["cpu"].status == OK)
d_agent = DRIVERS["windows"](ag, TH, {"disabled": frozenset()}); real_res = {x.check: x.status for x in d_agent.run()}
check("the driver reads the report from the database on its own", real_res.get("cpu") == OK and real_res.get("reachability") == OK, real_res)

script = agents.script_for("laptop-7", minutes=5, host="127.0.0.1", port=port)
check("the script has the address, the pinned fingerprint and the token, and no placeholder is left", f"https://127.0.0.1:{port}/report" in script and fp in script and tok in script and "@@" not in script and "$Minutes = 5" in script)
check("it can install itself as a SYSTEM task, locked down to administrators, and remove itself", "Register-ScheduledTask" in script and "-Uninstall" in script and "S-1-5-32-544" in script and "S-1-5-18" in script)
check("it takes no commands and opens no listener", "HttpListener" not in script and "TcpListener" not in script and "Invoke-Expression" not in script and "iex " not in script.lower())
work = tempfile.mkdtemp(prefix="agent_t_"); sp = os.path.join(work, "toner-agent.ps1")
open(sp, "w", encoding="utf-8-sig").write(script)
before = agents.latest("laptop-7")[0]["at"]
time.sleep(1.1)
r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", sp], capture_output=True, text=True, timeout=120)
check("the real script runs on this computer and Toner accepts its report", r.returncode == 0 and "Toner answered: 200" in r.stdout, (r.stdout[-300:], r.stderr[-500:]))
after = agents.latest("laptop-7")[0]
check("the report that arrived is this computer's, newer than the one posted by hand", after["computer"] == os.environ["COMPUTERNAME"] and after["at"] > before and after["mem_total_mb"] > 0)
bad_script = script.replace(fp, "0" * 64); bp = os.path.join(work, "bad-pin.ps1"); open(bp, "w", encoding="utf-8-sig").write(bad_script)
r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", bp], capture_output=True, text=True, timeout=120)
check("a script that pins a different certificate refuses to talk to this receiver", r.returncode != 0 and "Toner answered" not in r.stdout, (r.stdout[-200:], r.stderr[-300:]))
stored = agents.latest("laptop-7")[0]["at"]
bt = script.replace(tok, "x" * 43); btp = os.path.join(work, "bad-token.ps1"); open(btp, "w", encoding="utf-8-sig").write(bt)
r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", btp], capture_output=True, text=True, timeout=120)
check("one with a wrong token is turned away, and nothing is stored", r.returncode != 0 and agents.latest("laptop-7")[0]["at"] == stored)
shutil.rmtree(work, ignore_errors=True)

print("== signing computers up with the package")
def post_json(path, obj):
    req = urllib.request.Request(f"https://127.0.0.1:{port}{path}", data=json.dumps(obj).encode(), method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r: return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}")
key = agents.enroll_key()
check("the sign-up key is made once, long, and kept in Credential Manager", len(key) >= 30 and agents.enroll_key() == key and STORE[("netcheck", "service:agent-enroll")] == key)
check("sign-up is off by default, and refused while off", db.get_setting("agent_enroll") is False and post_json("/enroll", {"key": key, "computer": "PC-A"})[0] == 403 and not [d for d in db.list_devices() if d["name"] == "PC-A"])
db.set_setting("agent_enroll", True)
check("a wrong key is refused and adds nothing", post_json("/enroll", {"key": "nope", "computer": "PC-A"})[0] == 401 and not [d for d in db.list_devices() if d["name"] == "PC-A"])
code, ans = post_json("/enroll", {"key": key, "computer": "PC-A"})
dv = [d for d in db.list_devices() if d["name"] == "PC-A"]
check("the right key adds the computer as a Windows device monitored by agent, and returns its token", code == 200 and ans["ok"] and ans["name"] == "PC-A" and dv and dv[0]["vendor"] == "windows" and dv[0]["platform"] == "agent" and dv[0]["enabled"] == 1 and agents.device_for_token(ans["token"]) == "PC-A")
check("that token can send reports", post(report(computer="PC-A"), token=ans["token"]) == 200 and agents.latest("PC-A")[0]["computer"] == "PC-A")
check("signing up again under the same name is refused (nobody can take over a computer's name)", post_json("/enroll", {"key": key, "computer": "pc-a"})[0] == 409 and agents.device_for_token(ans["token"]) == "PC-A")
dev("PC-B", "agent")
code, ans_b = post_json("/enroll", {"key": key, "computer": "PC-B"})
check("a device someone added by hand, waiting for its agent, is claimed rather than duplicated", code == 200 and ans_b["name"] == "PC-B" and len([d for d in db.list_devices() if d["name"] == "PC-B"]) == 1)
dev("PC-C", "winrm", username="u")
check("a device monitored another way is not taken over", post_json("/enroll", {"key": key, "computer": "PC-C"})[0] == 409)
code, ans_d = post_json("/enroll", {"key": key, "computer": "PC 1/../x;"})
check("odd characters in a computer name are cleaned", code == 200 and ans_d["name"] == "PC-1-..-x" and any(d["name"] == "PC-1-..-x" for d in db.list_devices()), ans_d)
check("an empty name, or a request that is not JSON, is refused", post_json("/enroll", {"key": key, "computer": "  "})[0] == 400 and post_json("/enroll", [1, 2])[0] == 400)
check("signing a computer up is in the audit log", any("PC-A" in (a["detail"] or "") for a in db.connect().execute("SELECT * FROM audit WHERE action='agent signed up'").fetchall()))

print("== the package")
import zipfile, io
zdata = agents.package_bytes(minutes=7, host="127.0.0.1", port=port)
zf = zipfile.ZipFile(io.BytesIO(zdata))
names = sorted(zf.namelist())
check("the zip has the script, the settings, both launchers and a read-me", names == ["toner-agent/Install-TonerAgent.cmd", "toner-agent/README.txt", "toner-agent/Uninstall-TonerAgent.cmd", "toner-agent/agent.json", "toner-agent/toner-agent.ps1"], names)
cfg = json.loads(zf.read("toner-agent/agent.json"))
check("agent.json has Toner's address, the pinned fingerprint, the key and the interval, and no token", cfg["server"] == f"https://127.0.0.1:{port}/report" and cfg["enroll"] == f"https://127.0.0.1:{port}/enroll" and cfg["pin"] == agents.fingerprint() and cfg["key"] == key and cfg["minutes"] == 7 and cfg["token"] == "")
ps = zf.read("toner-agent/toner-agent.ps1").decode("utf-8-sig")
check("the script is the same for every computer: no token and no leftover placeholders, and it asks for administrator rights itself", "@@" not in ps and "Bearer" in ps and "-Verb RunAs" in ps and "Register-ScheduledTask" in ps and "-Uninstall" in ps and "S-1-5-32-544" in ps and cfg["key"] not in ps)
check("it takes no commands and opens no listener", "HttpListener" not in ps and "TcpListener" not in ps and "Invoke-Expression" not in ps)
check("the launchers run the script with -Install and -Uninstall", b"-Install" in zf.read("toner-agent/Install-TonerAgent.cmd") and b"-Uninstall" in zf.read("toner-agent/Uninstall-TonerAgent.cmd") and zf.read("toner-agent/toner-agent.ps1").startswith(b"\xef\xbb\xbf"))
work2 = tempfile.mkdtemp(prefix="agent_pkg_"); zf.extractall(work2); folder = os.path.join(work2, "toner-agent")
me = os.environ["COMPUTERNAME"]
r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", os.path.join(folder, "toner-agent.ps1")], capture_output=True, text=True, timeout=180)
check("the real script, run from the unzipped package, signs this computer up and sends its first report", r.returncode == 0 and f"Signed up with Toner as {me}" in r.stdout and "Toner answered: 200" in r.stdout, (r.stdout[-300:], r.stderr[-500:]))
mine = [d for d in db.list_devices() if d["name"] == me]
local_cfg = json.loads(open(os.path.join(folder, "agent.json"), encoding="utf-8-sig").read())
check("Toner now has this computer, with a fresh report from it", mine and mine[0]["platform"] == "agent" and agents.latest(me)[0]["computer"] == me and agents.latest(me)[1] < 2)
check("the installed config keeps the token and no longer holds the sign-up key", local_cfg["token"] and agents.device_for_token(local_cfg["token"]) == me and local_cfg["key"] == "")
r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", os.path.join(folder, "toner-agent.ps1")], capture_output=True, text=True, timeout=180)
check("the next run just reports (no second sign-up)", r.returncode == 0 and "Signed up" not in r.stdout and "Toner answered: 200" in r.stdout, (r.stdout[-200:], r.stderr[-300:]))
cfg2 = dict(cfg, pin="0" * 64, token=""); json.dump(cfg2, open(os.path.join(folder, "agent.json"), "w")); 
db.set_setting("agent_enroll", True); agents.token_for("PC-Z"); 
r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", os.path.join(folder, "toner-agent.ps1")], capture_output=True, text=True, timeout=180)
check("a package pinned to another certificate cannot sign up with this Toner", r.returncode != 0 and "Signed up" not in r.stdout)
db.set_setting("agent_enroll", False)
json.dump(dict(cfg, minutes=7), open(os.path.join(folder, "agent.json"), "w"))
r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", os.path.join(folder, "toner-agent.ps1")], capture_output=True, text=True, timeout=180)
check("a package whose computer is already known and sign-up is off gets a clear refusal", r.returncode != 0 and "notaccepting" in "".join((r.stdout + r.stderr).split()), (r.stdout[-300:], r.stderr[-600:]))      # PowerShell wraps its error text, even mid-word
shutil.rmtree(work2, ignore_errors=True)
db.set_setting("agent_enroll", True); agents._failures.clear()
for i in range(10): post_json("/enroll", {"key": "guess%d" % i, "computer": "PC-G"})
check("guessing the key is slowed down (too many wrong keys from one address)", post_json("/enroll", {"key": key, "computer": "PC-G"})[0] == 429)
agents._failures.clear(); db.set_setting("agent_enroll", False)
check("sign-up settings stay with this computer", "agent_enroll" in db.NOT_PORTABLE)
new_key = agents.enroll_key(rotate=True)
check("a new key replaces the old one, and old packages stop working", new_key != key and (db.set_setting("agent_enroll", True), post_json("/enroll", {"key": key, "computer": "PC-H"})[0])[1] == 401 and post_json("/enroll", {"key": new_key, "computer": "PC-H"})[0] == 200)
db.set_setting("agent_enroll", False)
print("== tokens, renames, the settings")
tok2 = agents.token_for("laptop-7", rotate=True)
check("a new token stops the old one", tok2 != tok and agents.device_for_token(tok) == "" and agents.device_for_token(tok2) == "laptop-7" and post(report(), token=tok) == 401 and post(report(), token=tok2) == 200)
db.move_device_secrets("laptop-7", "laptop-8"); agents.rename("laptop-7", "laptop-8")
check("renaming the device keeps its token and last report", agents.device_for_token(tok2) == "laptop-8" and agents.latest("laptop-8")[0] is not None and agents.latest("laptop-7")[0] is None and STORE[("netcheck", "laptop-8:agent")] == tok2)
db.delete_device_secrets("laptop-8"); agents.forget("laptop-8")
check("deleting the device removes the token and report", agents.device_for_token(tok2) == "" and ("netcheck", "laptop-8:agent") not in STORE and "laptop-8" not in [x["device"] for x in agents.overview()])
check("the overview lists agents with their age", (agents.token_for("a1"), post(report(), token=agents.token_for("a1")))[1] == 200 and agents.overview()[0]["device"] == "a1" and agents.overview()[0]["age"] < 1 and agents.overview()[0]["source"] == "127.0.0.1")
db.set_setting("agent_enabled", False)
agents.apply()
check("turning it off stops listening", not agents.running())
try:
    urllib.request.urlopen(f"https://127.0.0.1:{port}/ping", context=ctx, timeout=3); check("really closed", False)
except Exception: check("nothing answers on the port any more", True)
db.set_setting("agent_enabled", True); db.set_setting("agent_bind", "not-an-ip")
check("a bad listen address is reported, not raised", "not an IP" in agents.apply() and not agents.running() and "not an IP" in agents.status()["error"])
db.set_setting("agent_bind", "127.0.0.1"); check("and fixing it starts it again", agents.apply() == "" and agents.running())
fp2 = agents.renew_cert()
check("a new certificate has a new fingerprint and the receiver is restarted with it", fp2 != fp and agents.running() and fp2 == agents.fingerprint())
agents.stop()
check("settings that are about this computer do not travel in an export", {"agent_enabled", "agent_bind", "agent_address"} <= db.NOT_PORTABLE)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
