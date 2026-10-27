# Run directly (python tests/test_assistant_commands.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The Assistant's show commands on devices: off by default (the tool is not offered and the instructions say it only reads), the
# Settings > AI switch, the guard (the Command Runner's read-only block plus no output to a file), a real run against a fake
# Cisco switch with the audit line and the ASSISTANT session log, a refused command, the devices that cannot take commands, this PC
# over PowerShell, the panel's step line, and the overview page's "what it can see".
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "aicmd%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import audit, db, orgs, sessionlog
db.init()
from core import assistant as AI
from core.assistant import agent, providers, store, tools as T
from _cisco_fake import CiscoFake
from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)
import ui.settings as S
from ui import assistant as UA

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def settle(n=6):
    for _ in range(n): QCoreApplication.processEvents()
def dev(name, **kw):
    d = dict(name=name, vendor="cisco", host="10.0.0.1", port=0, platform="cisco_ios", username="admin", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None, tags="")
    d.update(kw); db.save_device(d); return [x for x in db.list_devices() if x["name"] == name][0]
def audited(n=10):
    return [e["detail"] for e in audit.recent(n)]

acme = orgs.create("Acme Charter Schools", "acme")
db.set_home(acme)
PW = "Dev-pass-77"
fake = CiscoFake("cisco_ios", "sw1")
fake.password = PW
with db.within(acme):
    sw1 = dev("sw1", host="127.0.0.1", port=fake.port)
    db.set_secret(db.secret_name("sw1"), PW)
    mer = dev("mer1", vendor="meraki", platform="")
    agent_pc = dev("pc-agent", vendor="windows", platform="agent")
    fw = dev("fw1", vendor="fortinet", platform="", username="admin")
    this_pc = dev("this-pc", vendor="windows", platform="local", host="localhost")

print("== off by default")
check("the setting is off and the installation's (Global only)", AI.commands_allowed() is False and "ai_run_commands" in db.GLOBAL_ONLY and db.DEFAULT_SETTINGS["ai_run_commands"] is False)
check("the tool exists but is not offered", "run_commands" in T.BY_NAME and len(T.TOOLS) == 13 and "run_commands" not in [t.name for t in T.offered()] and len(T.offered()) == 12)
check("the instructions say it only reads", "You can only read." in agent.system_prompt(acme) and "run commands that only look" not in agent.system_prompt(acme))
check("what it can see has no show-command line", T.CAN_RUN not in T.what_it_sees())
with db.within(acme):
    r = json.loads(T.run("run_commands", {"device": "sw1", "commands": ["show version"]}))
check("called anyway, it says where the switch is", r["error"] == "Running commands from the Assistant is off: Settings > AI.")

print("== switched on")
db.set_setting("ai_run_commands", True)
check("the tool is offered and the instructions change", "run_commands" in [t.name for t in T.offered()] and "run commands that only look" in agent.system_prompt(acme)
      and "You can only read." not in agent.system_prompt(acme) and "do\nnot try to get around that" in agent.system_prompt(acme))
check("what it can see gains the line", "show commands on devices, when allowed under Settings > AI" in T.what_it_sees())
check("the tool's description, as approved", T.BY_NAME["run_commands"].description.startswith("Run one or more commands that only look (show, display, get, dir, ping, traceroute on network devices and firewalls; Get-… in PowerShell on Windows)")
      and T.BY_NAME["run_commands"].description.endswith("At most 10 commands in one call, 60 seconds each.") and set(T.BY_NAME["run_commands"].schema["required"]) == {"device", "commands"})
check("the step line: one command named, several counted", T.BY_NAME["run_commands"].step({"device": "core-sw1", "commands": ["show interfaces"]}) == "Running show interfaces on core-sw1…"
      and T.BY_NAME["run_commands"].step({"device": "core-sw1", "commands": ["a", "b", "c"]}) == "Running 3 commands on core-sw1…")

print("== the guard")
for c in ("show version", "show ip interface brief", "show logging | include Gi1/0/24", "dir flash:", "ping 10.0.0.1", "traceroute 10.0.0.1", "display version", "get system status"):
    check(f"may send: {c}", T.refused("ssh", c) == "")
for c in ("reload", "configure terminal", "conf t", "copy running-config startup-config", "clear counters", "write memory", "delete flash:x", "request restart system", "execute reboot", "no shutdown"):
    check(f"refused, could change: {c}", T.refused("ssh", c) == "could change the device")
for c in ("show running-config | redirect flash:x", "show tech | append bootflash:t", "show version | tee flash:v", "show configuration | save /var/tmp/c", "show version > flash:v", "show version |redirect x"):
    check(f"refused, writes a file: {c}", T.refused("ssh", c) == "writes its output to a file")
check("PowerShell is judged by its own rules", T.refused("windows", "Get-Service") == "" and T.refused("windows", "Restart-Service Spooler") == "could change the device" and T.refused("windows", "Get-Service > a.txt") == "writes its output to a file")

print("== a real run on a fake switch")
with db.within(acme):
    before = len(sessionlog.list_sessions())
    text = T.run("run_commands", {"device": "sw1", "commands": ["show version", "show nothing-like-this"]})
    r = json.loads(text)
    logs = sessionlog.list_sessions()
check("both commands ran, in order, and the output came back", r["device"] == "sw1" and [o["command"] for o in r["outputs"]] == ["show version", "show nothing-like-this"] and "15.2(7)E9" in r["outputs"][0]["output"]
      and "Invalid input" in r["outputs"][1]["output"] and "error" not in r, text[:300])
check("the password is not in what the model gets", PW not in text)
check("one audit line names every command", audited(3)[0] == "ran on sw1: show version; show nothing-like-this" and not any(d.startswith("Running") for d in audited(3)))
with db.within(acme):
    newest = sorted(logs, key=lambda s: s["id"])[-1]
    body = open(newest["log_path"], encoding="utf-8").read()
check("one session log of type ASSISTANT per run, with its result", len(logs) == before + 1 and newest["kind"] == "assistant" and newest["device"] == "sw1" and newest["host"] == "127.0.0.1" and newest["port"] == fake.port
      and newest["username"] == "admin" and newest["reason"] == "2 commands" and newest["ended_at"])
check("the log holds each command and the answer", "# Toner ASSISTANT session log" in body and "> show version" in body and "15.2(7)E9" in body and "> show nothing-like-this" in body and PW not in body)
with db.within(acme):
    listed = json.loads(T.run("list_session_logs", {}))["sessions"][0]
    read = json.loads(T.run("read_session_log", {"session_id": listed["id"]}))
check("the Assistant's own session-log tools see it", listed["type"] == "ASSISTANT" and listed["device"] == "sw1" and listed["result"] == "2 commands" and "> show version" in read["log"])
with db.within(acme):
    r = json.loads(T.run("run_commands", {"device": "sw1", "commands": ["show version"] * 12}))
check("at most ten commands in one call", len(r["outputs"]) == 10)

print("== refused and failed runs")
with db.within(acme):
    n_logs, n_audit = len(sessionlog.list_sessions()), len(audit.recent(500))
    r = json.loads(T.run("run_commands", {"device": "sw1", "commands": ["show version", "reload"]}))
    logs2 = sessionlog.list_sessions()
check("a command that could change the device stops the whole call before anything is sent", r["error"] == "'reload' could change sw1, so nothing was sent. The Assistant may only run commands that look."
      and len(logs2) == n_logs and audited(1) == ["refused on sw1: reload (could change the device)"] and len(audit.recent(500)) == n_audit + 1)
with db.within(acme):
    r = json.loads(T.run("run_commands", {"device": "sw1", "commands": ["show running-config | redirect flash:x"]}))
check("one that writes a file is refused with its own reason", r["error"] == "'show running-config | redirect flash:x' writes its output to a file, so nothing was sent."
      and audited(1) == ["refused on sw1: show running-config | redirect flash:x (writes its output to a file)"])
with db.within(acme):
    r = json.loads(T.run("run_commands", {"device": "sw1", "commands": []}))
    r2 = json.loads(T.run("run_commands", {"device": "nope", "commands": ["show version"]}))
check("no commands, or no such device", r["error"] == "No command was given." and r2["error"].startswith("No device called 'nope'"))
with db.within(acme):
    rm = json.loads(T.run("run_commands", {"device": "mer1", "commands": ["show version"]}))
    ra = json.loads(T.run("run_commands", {"device": "pc-agent", "commands": ["hostname"]}))
    rf = json.loads(T.run("run_commands", {"device": "fw1", "commands": ["get system status"]}))
check("devices that cannot take commands, each with the reason", rm["error"] == "mer1 cannot take commands: commands cannot be run on this kind of device."
      and ra["error"] == "pc-agent cannot take commands: it reports through an agent, which only sends."
      and rf["error"] == "fw1 cannot take commands: no SSH login is stored for it (Edit device > Access).", (rm, ra, rf))
fake.stop()
with db.within(acme):
    db.save_device({**sw1, "port": fake.port})
    n_logs = len(sessionlog.list_sessions())
    r = json.loads(T.run("run_commands", {"device": "sw1", "commands": ["show version"]}))
    newest = sorted(sessionlog.list_sessions(), key=lambda s: s["id"])[-1]
check("a device that cannot be reached: the error comes back and the session log says failed", r["error"] and r["outputs"] == [] and len(sessionlog.list_sessions()) == n_logs + 1 and newest["reason"].startswith("failed: "), r)

print("== this PC over PowerShell")
with db.within(acme):
    r = json.loads(T.run("run_commands", {"device": "this-pc", "commands": ["hostname"]}))
    rw = json.loads(T.run("run_commands", {"device": "this-pc", "commands": ["Restart-Service Spooler"]}))
check("hostname runs on this PC and the answer comes back", "error" not in r and r["outputs"][0]["command"] == "hostname" and r["outputs"][0]["output"].strip(), r)
check("a PowerShell command that changes something is refused", rw["error"].startswith("'Restart-Service Spooler' could change this-pc"))

print("== the turn loop")
class Scripted(providers.Provider):
    name, label, host, default_model = "claude", "Claude", "api.anthropic.com", "claude-opus-5-5"
    def __init__(self, script):
        super().__init__("k", "claude-opus-5-5", "normal"); self.script = list(script); self.seen = []
    def list_models(self): return [("claude-opus-5-5", "Claude Opus 5.5")]
    def complete(self, system, history, tools, on_text, cancel=None, search=False, on_search=None):
        self.seen.append((system, [dict(m) for m in history], [t.name for t in tools]))
        step = self.script.pop(0)
        r = providers.Reply(); r.model = "claude-opus-5-5"; r.tokens_in, r.tokens_out = 10, 1
        if step[0] == "tool":
            r.calls = [(f"toolu_{i}", n, a) for i, (n, a) in enumerate(step[1])]; r.stop = "tool"
            r.native = [{"role": "assistant", "content": [{"type": "tool_use", "id": c[0], "name": c[1], "input": c[2]} for c in r.calls]}]
        else:
            r.text = step[1]; on_text(step[1]); r.native = [{"role": "assistant", "content": [{"type": "text", "text": r.text}]}]
        return r
    def user_message(self, text): return [{"role": "user", "content": text}]
    def tool_results(self, reply, results): return [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": c[0], "content": t} for c, t in results]}]
events = []
with db.within(acme):
    cid = store.create("claude", "claude-opus-5-5")
prov = Scripted([("tool", [("run_commands", {"device": "this-pc", "commands": ["hostname"]})]), ("text", "Done.")])
done = agent.run_turn(cid, acme, "What is this PC called?", {}, lambda k, p: events.append((k, p)), provider=prov)
check("the panel sees the step line and the model gets the output; run_commands was offered", [p for k, p in events if k == "tool"] == ["Running hostname on this-pc…"] and done["text"] == "Done."
      and "run_commands" in prov.seen[0][2] and "hostname" in prov.seen[1][1][-1]["content"][0]["content"])
db.set_setting("ai_run_commands", False)
prov = Scripted([("text", "Cannot.")])
agent.run_turn(cid, acme, "Run hostname", {}, lambda k, p: None, provider=prov)
check("switched off between questions, the tool is withdrawn and the instructions read only again", "run_commands" not in prov.seen[0][2] and "You can only read." in prov.seen[0][0])

print("== Settings > AI and the overview page")
tab = S.SettingsTab(); tab.resize(1100, 700); tab.show(); settle()
pg = {p.title: p for p in tab.pages}["AI"]
check("the box, unticked, with its note", pg.run_cmds.text() == "Let the Assistant run show commands on devices" and not pg.run_cmds.isChecked() and pg.run_cmds.toolTip().startswith("Off by default.")
      and "Tools > Session logs" in pg.run_cmds.toolTip())
pg.run_cmds.setChecked(True)
AI.check_in_background = lambda done=None: None
tab.save()
check("Save keeps it; load shows it", AI.commands_allowed() is True and (pg.load(), pg.run_cmds.isChecked())[1])
tab.close()
with db.within(acme):
    ov = UA.AssistantOverviewPage(); ov.refresh()
    on = ov.sees.text()
    db.set_setting("ai_run_commands", False); ov.refresh()
    off = ov.sees.text()
check("what it can see: the line and 'It changes nothing.' while on, 'It only reads.' while off", "show commands on devices, when allowed under Settings > AI" in on and on.endswith("It changes nothing.")
      and "show commands" not in off and off.endswith("It only reads."), (on[-120:], off[-120:]))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
