# Run directly (python tests/test_x.py) or all together (python tests/run_all.py).
# The binary agent (agent/, Go) against Toner's own receiver: the package's agent.json, enrollment with the sign-up key, a
# report, the stored report through the Windows driver, store-and-forward, the update download. Needs a Go toolchain
# (`go` on PATH); without one the agent is not built and only the receiver's new routes and the package are tested.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import hashlib, io, json, os, shutil, ssl, subprocess, sys, time, urllib.request, zipfile
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "agentgo%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingagentgo%d" % int(time.time()))
from core import db, paths
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

import keyring
STORE = {}                                                   # an in-memory keyring, as the other agent tests use: no desktop vault here
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import agents
from drivers import DRIVERS
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT_SRC = os.path.join(ROOT, "agent")

print("== a stored report's time")
check("a fresh report's numbers are stamped now", agents.metric_time({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})[:13] == time.strftime("%Y-%m-%d %H")[:13])
check("a report kept for a day and sent later keeps its own time", agents.metric_time({"at": "2026-01-01T12:00:00Z"})[:4] == time.strftime("%Y") or agents.metric_time({"at": time.strftime("%Y-%m-%dT00:00:00Z")})[-8:] != time.strftime("%H:%M:%S"))
check("a report from the far past or with no time is stamped now", agents.metric_time({"at": "2001-01-01T00:00:00Z"})[:10] == time.strftime("%Y-%m-%d") and agents.metric_time({})[:10] == time.strftime("%Y-%m-%d"))
check("the kind of agent is read from the report", agents.agent_kind_of({"agent": {"name": "toner-agent", "version": "1.14.0", "os": "linux", "arch": "amd64"}}) == "toner-agent 1.14.0 (linux/amd64)"
      and agents.agent_kind_of({"computer": "PC"}) == "PowerShell")

print("== the receiver: the binary route and the package")
db.set_setting("agent_enabled", True); db.set_setting("agent_enroll", True)
rx = agents.Receiver(0, "127.0.0.1"); rx.start()
port = rx.port
pin = agents.fingerprint()
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

def http(path, method="GET", body=None, headers=None):
    req = urllib.request.Request(f"https://127.0.0.1:{port}{path}", data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)

code, body, _ = http("/agent/linux-amd64")
check("the binary route wants a token", code == 401)
# a device with a token, for the routes that need one
db.save_device({"name": "GOTEST", "vendor": "windows", "host": "GOTEST", "port": 0, "platform": "agent", "username": "", "site": "default",
                "verify_ssl": 0, "ha_expected": 0, "enabled": 1, "location": "", "details": "", "folder_id": None, "tags": "", "fields": "", "profile_id": None})
token = agents.token_for("GOTEST")
code, body, _ = http("/agent/linux-amd64", headers={"Authorization": "Bearer " + token})
check("with a token but no binary in this copy it is a 404, not an error", code == 404 and b"no agent binary" in body, (code, body))
code, body, _ = http("/agent/../../etc/passwd", headers={"Authorization": "Bearer " + token})
check("only the known platforms are served", code == 404)
pkg = zipfile.ZipFile(io.BytesIO(agents.package_bytes(5, host="127.0.0.1", port=port)))
names = pkg.namelist()
check("a copy without the binary makes the PowerShell package, as before", "toner-agent/toner-agent.ps1" in names and "toner-agent/Install-TonerAgent.cmd" in names and not any(n.endswith(".exe") for n in names))
cfg = json.loads(pkg.read("toner-agent/agent.json"))
check("agent.json has the server, the pin and the sign-up key", cfg["server"] == f"https://127.0.0.1:{port}/report" and cfg["pin"] == pin and cfg["key"] and cfg["token"] == "")

print("== the binary agent")
go = shutil.which("go")
binary = os.path.join(SP, "toner-agent")
built = False
if go and os.path.isdir(AGENT_SRC):
    env = dict(os.environ)
    if not env.get("GOWORK"):                                # a fresh checkout has no go.sum entries yet: let the build add them
        env.setdefault("GOFLAGS", "-mod=mod")
    r = subprocess.run([go, "build", "-ldflags", "-X github.com/WetlBocker/toner/agent/internal/agent.Version=" + agents.AGENT_VERSION, "-o", binary, "./cmd/toner-agent"],
                       cwd=AGENT_SRC, capture_output=True, text=True, timeout=600, env=env)
    built = r.returncode == 0 and os.path.exists(binary)
    if not built:
        print("  (the agent did not build here: " + (r.stderr.strip().splitlines() or ["?"])[-1][:200] + ")")
if not built:
    print("  (no Go toolchain or no build: the agent itself is not tested in this run)")
else:
    check("the agent says Toner's version", subprocess.run([binary, "version"], capture_output=True, text=True, timeout=30).stdout.strip() == agents.AGENT_VERSION)
    out = subprocess.run([binary, "collect"], capture_output=True, text=True, timeout=300)
    rep = json.loads(out.stdout) if out.returncode == 0 else {}
    check("collect prints a report with the fields the Windows collector has", out.returncode == 0 and rep.get("v") == 1 and rep.get("computer") and "service_states" in rep and "software" in rep
          and isinstance(rep.get("disks"), list) and rep.get("agent", {}).get("name") == "toner-agent", out.stderr[-300:])
    check("and nothing was sent", agents.latest("GOTEST") == (None, None))

    # the package's agent.json, as a computer would receive it: enrollment with the key
    folder = os.path.join(SP, "agentpkg"); os.makedirs(folder, exist_ok=True)
    cfg_path = os.path.join(folder, "agent.json")
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)
    r = subprocess.run([binary, "once", cfg_path], capture_output=True, text=True, timeout=300)
    check("once: the agent signs up with the key and sends a report", r.returncode == 0, r.stderr[-400:])
    saved = json.load(open(cfg_path))
    check("the token is saved and the key forgotten", saved["token"] and saved["key"] == "")
    hostname = os.uname().nodename.split(".")[0].upper() if hasattr(os, "uname") else ""
    name = agents.device_for_token(saved["token"])
    check("Toner added the computer under its name", name and name.upper() == agents.safe_name(hostname).upper(), (name, hostname))
    report, age = agents.latest(name)
    check("the report is stored", isinstance(report, dict) and report.get("computer") == name.upper() and age is not None and age < 5)
    check("Toner knows which agent sent it", any(r["device"] == name and r["kind"].startswith("toner-agent") for r in agents.overview()))

    # the stored report through the Windows driver: the same checks a PowerShell report gets
    dev = next(d for d in db.list_devices() if d["name"] == name)
    results = {x.check: x for x in DRIVERS["windows"](dev, db.get_thresholds(), {"disabled": frozenset()}).run()}
    check("the driver reads it: reachability, memory, disks, uptime", results["reachability"].status == "OK" and "memory" in results and "disks" in results and "uptime" in results, sorted(results))
    check("a part the computer could not give is N/A rather than wrong", all(r.status in ("OK", "WARN", "FAIL", "N/A") for r in results.values()), {k: v.status for k, v in results.items() if v.status == "ERROR"})

    # a wrong pin is refused by the agent, not just by Toner
    bad_cfg = {**saved, "pin": "0" * 64}
    with open(os.path.join(folder, "bad.json"), "w") as f:
        json.dump(bad_cfg, f)
    r = subprocess.run([binary, "once", os.path.join(folder, "bad.json")], capture_output=True, text=True, timeout=120)
    check("a server with another certificate is refused", r.returncode != 0 and "pinned" in r.stderr, r.stderr[-300:])

    # store-and-forward: Toner is away, the report waits; Toner is back, it is sent
    rx.stop()
    r = subprocess.run([binary, "once", cfg_path], capture_output=True, text=True, timeout=120)
    queued = os.listdir(os.path.join(folder, "queue")) if os.path.isdir(os.path.join(folder, "queue")) else []
    check("with Toner unreachable the report is kept", r.returncode != 0 and len(queued) == 1, (r.stderr[-200:], queued))
    rx = agents.Receiver(port, "127.0.0.1")
    for _ in range(20):
        try:
            rx.start(); break
        except OSError:
            time.sleep(0.5)
    before = db.connect().execute("SELECT COUNT(*) FROM agent_metrics WHERE device=?", (name,)).fetchone()[0]
    r = subprocess.run([binary, "once", cfg_path], capture_output=True, text=True, timeout=300)
    after = db.connect().execute("SELECT COUNT(*) FROM agent_metrics WHERE device=?", (name,)).fetchone()[0]
    check("when Toner is back the kept report goes first, then the new one", r.returncode == 0 and after - before == 2 and not os.listdir(os.path.join(folder, "queue")), (r.stderr[-200:], before, after))

    # the update route serves a binary with its checksum when Toner carries one
    agent_dir = os.path.join(paths.app_dir(), "agent")
    os.makedirs(agent_dir, exist_ok=True)
    fake = os.path.join(agent_dir, "toner-agent-linux-amd64")
    made = not os.path.exists(fake)
    try:
        if made:
            shutil.copy(binary, fake)
        code, body, headers = http("/agent/linux-amd64", headers={"Authorization": "Bearer " + saved["token"]})
        check("the binary route serves the file with its SHA-256", code == 200 and len(body) > 1000 and headers.get("X-Toner-Agent-Sha256") == hashlib.sha256(body).hexdigest())
        pkg2 = zipfile.ZipFile(io.BytesIO(agents.package_bytes(5, host="127.0.0.1", port=port)))
        check("the package then carries it, with install.sh", "toner-agent/toner-agent-linux-amd64" in pkg2.namelist() and "toner-agent/install.sh" in pkg2.namelist())
    finally:
        if made:
            os.remove(fake)
            try:
                os.rmdir(agent_dir)
            except OSError:
                pass
rx.stop()

print()
print(f"{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
