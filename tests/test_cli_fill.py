# Run directly (python tests/test_cli_fill.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database, so nothing on this computer is touched; no device is contacted.
# The Palo Alto and FortiGate command-line parsers, on real output captured 2026-11-21 (trimmed to the lines they read).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "clifill%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingclifill%d" % int(time.time()))
from core import db
db.init()
from drivers import paloalto, fortinet, sshbase
from drivers.base import Driver
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

PA_INFO = """hostname: fw
time: Sat Nov 21 00:29:45 2026
uptime: 31 days, 5:55:14
family: vm
model: PA-VM
sw-version: 11.1.4
"""
PA_TOP = """top - 00:29:54 up 31 days,  5:55,  1 user,  load average: 1.90, 2.04, 1.89
Tasks: 250 total,   1 running, 248 sleeping,   0 stopped,   1 zombie
%Cpu(s): 18.2 us, 12.1 sy,  0.0 ni, 63.6 id,  0.0 wa,  6.1 hi,  0.0 si,  0.0 st
MiB Mem :   5447.1 total,    127.0 free,   2532.7 used,   2787.4 buff/cache
MiB Swap:   4000.0 total,   3560.0 free,    440.0 used.    635.2 avail Mem
"""
FG_CPU = "CPU states: 0% user 0% system 0% nice 100% idle 0% iowait 0% irq 0% softirq"
FG_MEM = "Memory: 2042628k total, 1187340k used (58.1%), 589720k free (28.9%), 265568k freeable (13.0%)"
FG_UP = "Uptime: 31 days,  4 hours,  0 minutes"

print("== Palo Alto")
cpu, mem = paloalto.cpu_memory(PA_TOP)
check("cpu and memory from show system resources", (round(cpu, 1), round(mem, 1)) == (36.4, 46.5), (cpu, mem))
check("uptime with days", round(paloalto.uptime_hours("31 days, 5:55:14"), 2) == 749.92)
check("uptime without days", round(paloalto.uptime_hours("5:55:14"), 2) == 5.92)
check("cli_field reads the values", [paloalto.cli_field(PA_INFO, n) for n in ("sw-version", "model", "uptime", "serial")] == ["11.1.4", "PA-VM", "31 days, 5:55:14", ""])
try:
    paloalto.cpu_memory("Cpu(s):  1.0%us,  0.5%sy\nMem:   4057112k total,  3876544k used"); raised = None
except ValueError as e:
    raised = str(e)
check("an older top layout is refused, with the existing text", raised == "could not read CPU and memory from 'show system resources'", raised)
try:
    paloalto.uptime_hours("soon"); raised = None
except ValueError as e:
    raised = str(e)
check("an unreadable uptime is refused", raised == "unrecognised uptime 'soon'", raised)

print("== FortiGate")
check("cpu is 100 minus idle", fortinet.cli_cpu(FG_CPU) == 0.0, fortinet.cli_cpu(FG_CPU))
check("cpu with load", fortinet.cli_cpu(FG_CPU.replace("100% idle", "40% idle")) == 60.0)
check("memory is the percent after used", fortinet.cli_memory(FG_MEM) == 58.1, fortinet.cli_memory(FG_MEM))
check("uptime through sshbase.uptime_hours", sshbase.uptime_hours(FG_UP) == 748)
check("nothing to read gives None", fortinet.cli_cpu("") is None and fortinet.cli_memory("") is None)
check("a per-core CPU0 line is not read", fortinet.cli_cpu(FG_CPU.replace("CPU states", "CPU0 states")) is None)

print("== uptime_row on Driver")
class Plain(Driver):
    pass
d = Plain({"name": "fw", "vendor": "x", "host": "h", "username": "u", "password": "p"}, db.get_thresholds(), {**db.runtime_options(), "disabled": set()})
r = d.uptime_row(748)
check("a plain Driver has uptime_row; 748 hours is OK", r.check == "uptime" and r.status == "OK" and r.numeric == 748, r)

print("== SSH fills what the API and SNMP did not give")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import cmdrun, netconn, profiles, runner
REAL_RUN_CLI = getattr(cmdrun, "run_cli", None)
import drivers.snmpdev as SD
from drivers.base import AuthRejected, Result as R
TH = db.get_thresholds()
OPTS = {**db.runtime_options(), "disabled": set(), "http_timeout": 5, "retries": 0}
db.set_secret(db.secret_name("fw", "ssh"), "x"); db.set_secret(db.secret_name("pa", "ssh"), "x")
fw = {"name": "fw", "vendor": "fortinet", "host": "h", "username": "u"}
pa = {"name": "pa", "vendor": "paloalto", "host": "h", "username": "u"}
OLD_TOP = "Cpu(s):  1.0%us,  0.5%sy\nMem:   4057112k total,  3876544k used"
CLI = {"calls": [], "raise": None, "top": PA_TOP}
def fake_cli(dev, commands, opts=None, read_timeout=30, device_type=None, before=None):
    CLI["calls"].append((dev["name"], list(commands), device_type))
    if CLI["raise"]: raise CLI["raise"]
    canned = {'get system performance status | grep "CPU states"': FG_CPU, "get system performance status | grep Memory": FG_MEM,
              "get system performance status | grep Uptime": FG_UP, "show system info": PA_INFO, "show system resources": CLI["top"]}
    return [(c, canned[c]) for c in commands]
cmdrun.run_cli = fake_cli
SNMP_ON = [False]
profiles.snmp_configured = lambda d: SNMP_ON[0]
SD.SnmpDriver.run = lambda self: [R(self.name, k, "OK", "v") for k, _fn in self.check_list()]     # (what a live agent would answer)
def reset(): CLI.update({"calls": [], "raise": None, "top": PA_TOP}); SNMP_ON[0] = False
def fill(res, dev=fw, **kw): return runner.fill_gaps(dev, TH, dict(OPTS), res, **kw)
def named(rows, c): return [r for r in rows if r.check == c]
def api(name, *rows): return [R(name, c, s, "1", m) for c, s, m in rows]
def show(rows): return [(r.check, r.status, r.value, r.message) for r in rows]

check("SSH_FILL as given", runner.SSH_FILL == {"fortinet": ("cpu", "memory", "uptime"), "paloalto": ("cpu", "memory", "uptime", "firmware")})
reset(); out = fill(api("fw", ("cpu", "OK", ""), ("memory", "OK", ""), ("firmware", "OK", ""), ("interfaces", "OK", "")))
up = named(out, "uptime")
check("Fortinet, no API uptime, no SNMP: one run_cli call, fortinet_readonly, exactly the Uptime command",
      CLI["calls"] == [("fw", ["get system performance status | grep Uptime"], "fortinet_readonly")], CLI["calls"])
check("...row uptime, 748 hours, 'via SSH'", len(up) == 1 and up[0].numeric == 748 and up[0].message == "via SSH" and up[0].status == "OK", show(out))
reset(); out = fill(api("fw", ("resources", "ERROR", "HTTP 500"), ("uptime", "OK", ""), ("firmware", "OK", ""), ("interfaces", "OK", "")))
check("Fortinet resources ERROR: the CPU and Memory commands only",
      [c[1] for c in CLI["calls"]] == [['get system performance status | grep "CPU states"', "get system performance status | grep Memory"]], CLI["calls"])
check("...cpu 0% and memory 58%, each 'via SSH; the API check failed: HTTP 500'; no resources row",
      [(r.value, r.message) for r in named(out, "cpu") + named(out, "memory")] == [("0%", "via SSH; the API check failed: HTTP 500"), ("58%", "via SSH; the API check failed: HTTP 500")]
      and not named(out, "resources"), show(out))
reset(); out = fill([], dev=pa, signed_in=False)
check("Palo Alto, signed_in=False: both commands", [c[1] for c in CLI["calls"]] == [["show system info", "show system resources"]] and CLI["calls"][0][2] is None, CLI["calls"])
fwr = named(out, "firmware")
check("...cpu 36%, memory 46%, uptime, firmware 11.1.4 'PA-VM, via SSH'",
      [r.value for r in named(out, "cpu") + named(out, "memory")] == ["36%", "46%"] and len(named(out, "uptime")) == 1
      and [(r.value, r.message) for r in fwr] == [("11.1.4", "PA-VM, via SSH")], show(out))
reset(); SNMP_ON[0] = True; out = fill(api("fw", ("cpu", "OK", ""), ("memory", "OK", ""), ("firmware", "OK", ""), ("interfaces", "OK", "")))
check("SNMP fills uptime: run_cli not called", CLI["calls"] == [] and [r.message for r in named(out, "uptime")] == ["via SNMP"], (CLI["calls"], show(out)))
reset(); out = fill(api("fw", ("cpu", "OK", ""), ("memory", "OK", ""), ("uptime", "OK", ""), ("firmware", "OK", ""), ("interfaces", "OK", "")))
check("nothing missing: run_cli not called", CLI["calls"] == [], CLI["calls"])
reset(); CLI["raise"] = AuthRejected("refused"); res = api("fw", ("resources", "ERROR", "HTTP 500"), ("uptime", "OK", ""), ("interfaces", "OK", "")); out = fill(res)
check("review focus 3: a refused SSH login: one ssh ERROR row 'SSH: ...', one attempt, the main rows intact (the resources ERROR too)",
      len(CLI["calls"]) == 1 and out[:3] == res and len(out) == 4 and out[3].check == "ssh" and out[3].status == "ERROR" and out[3].message.startswith("SSH: "), show(out))
reset(); out = fill(api("nokey", ("resources", "ERROR", "HTTP 500")), dev={"name": "nokey", "vendor": "fortinet", "host": "h", "username": "u"})
check("review focus 4: no stored SSH password: run_cli not called, no ssh row", CLI["calls"] == [] and not named(out, "ssh"), show(out))
reset(); out = fill([], dev={**fw, "username": " "}, signed_in=False)
check("...nor with a blank user name", CLI["calls"] == [] and not named(out, "ssh"), show(out))
reset(); CLI["top"] = OLD_TOP; out = fill([], dev=pa, signed_in=False)
check("review focus 5: the older top layout: uptime and firmware, no cpu or memory, no ssh ERROR row",
      named(out, "uptime") and named(out, "firmware") and not named(out, "cpu") and not named(out, "memory") and not named(out, "ssh"), show(out))
reset(); SNMP_ON[0] = True; CLI["top"] = PA_TOP.replace("5447.1 total", "0.0 total"); SD_run = SD.SnmpDriver.run
SD.SnmpDriver.run = lambda self: [R(self.name, "interfaces", "OK", "2/2 up")]
try:
    out = fill([], dev=pa, signed_in=False)
except Exception as e:
    out = [R("pa", "raised", "ERROR", "", repr(e))]
SD.SnmpDriver.run = SD_run
check("a memory total of 0 in top: uptime, firmware and SNMP's interfaces kept, no cpu or memory, no ssh ERROR row",
      named(out, "uptime") and named(out, "firmware") and [r.message for r in named(out, "interfaces")] == ["via SNMP"]
      and not named(out, "cpu") and not named(out, "memory") and not named(out, "ssh") and not named(out, "raised"), show(out))
reset(); seen = []; real_extras = runner.ssh_extras
runner.ssh_extras = lambda d, *a, **k: (seen.append(d["vendor"]), real_extras(d, *a, **k))[1]
db.set_secret(db.secret_name("sw"), "x")
fill([R("sw", "cpu", "ERROR", "", "unexpected output")], dev={"name": "sw", "vendor": "cisco", "host": "h", "username": "u"})
check("a Cisco device is never passed to ssh_extras", seen == [] and CLI["calls"] == [], (seen, CLI["calls"]))
runner.ssh_extras = real_extras
reset(); SNMP_ON[0] = True; SD_run = SD.SnmpDriver.run
SD.SnmpDriver.run = lambda self: [R(self.name, k, "ERROR" if k == "uptime" else "OK", "", "timed out") for k, _fn in self.check_list()]
out = fill(api("fw", ("cpu", "OK", ""), ("memory", "OK", ""), ("firmware", "OK", ""), ("interfaces", "OK", "")))
check("an SNMP ERROR row for a subject SSH then fills is dropped", [(r.status, r.message) for r in named(out, "uptime")] == [("OK", "via SSH")], show(out))
SD.SnmpDriver.run = SD_run
reset(); out = fill(api("fw", ("cpu", "OK", ""), ("memory", "OK", ""), ("uptime", "OK", ""), ("firmware", "ERROR", "HTTP 500"), ("interfaces", "OK", "")))
check("a FortiGate's firmware is not read over SSH", CLI["calls"] == [] and [r.status for r in named(out, "firmware")] == ["ERROR"], (CLI["calls"], show(out)))
reset(); out = fill(api("pa", ("resources", "OK", ""), ("uptime", "OK", ""), ("firmware", "ERROR", "HTTP 403")), dev=pa)
check("a Palo Alto firmware ERROR: show system info only, firmware filled, the ERROR row gone",
      [c[1] for c in CLI["calls"]] == [["show system info"]] and show(named(out, "firmware")) == [("firmware", "OK", "11.1.4", "PA-VM, via SSH; the API check failed: HTTP 403")], (CLI["calls"], show(out)))
reset(); out = fill(api("pa", ("resources", "OK", ""), ("uptime", "OK", "")), dev=pa, signed_in=True)
check("signed in, no firmware row: firmware is not wanted", CLI["calls"] == [], CLI["calls"])
reset(); out = runner.fill_gaps(fw, TH, {**OPTS, "disabled": {"fortinet:uptime"}}, api("fw", ("cpu", "OK", ""), ("memory", "OK", ""), ("firmware", "OK", ""), ("interfaces", "OK", "")))
check("uptime switched off: not read over SSH", CLI["calls"] == [], CLI["calls"])

print("== the joined wording (Task 3)")
check("a filled row with its own message whose main check failed",
      runner.tagged(R("fw", "uptime", "WARN", "0.5 h", "recent reboot"), "SNMP", "HTTP 403").message == "recent reboot, via SNMP; the API check failed: HTTP 403")

print("== ssh_extras on a VDOM FortiGate")
class VdomConn:
    _vdoms = True
befores = []
def vdom_cli(dev, commands, opts=None, read_timeout=30, device_type=None, before=None):
    befores.append(before(VdomConn())); return []
cmdrun.run_cli = vdom_cli
rows = runner.ssh_extras(fw, TH, dict(OPTS), ["cpu", "memory", "uptime"])
check("a FortiGate with VDOMs: the before hook says stop, no rows, no error", befores == [False] and rows == [], (befores, rows))
cmdrun.run_cli = fake_cli

print("== a failure inside the fill costs no results")
class Fake:
    def __init__(self, d, t, o): self.name = d["name"]
    def run(self): return [R(self.name, "cpu", "OK", "1"), R(self.name, "memory", "OK", "1")]
    def flush_baselines(self): pass
real_reach, real_resolve, real_fg = runner.reachability, runner.resolve_host, runner.DRIVERS["fortinet"]
runner.reachability = lambda d, o: []; runner.resolve_host = lambda h: None; runner.DRIVERS["fortinet"] = Fake
real_fill = runner.fill_gaps
def boom(*a, **k): raise RuntimeError("fill broke")
runner.fill_gaps = boom
out = runner.run_one({"name": "fg9", "vendor": "fortinet", "host": "h"}, TH, dict(OPTS))
check("fill_gaps raises: the driver's rows kept, no connection row", [r.check for r in out][:2] == ["cpu", "memory"] and not named(out, "connection"), show(out))
runner.fill_gaps = real_fill; runner.reachability, runner.resolve_host, runner.DRIVERS["fortinet"] = real_reach, real_resolve, real_fg
real_init = SD.SnmpDriver.__init__
def bad_init(self, *a, **k): raise OSError("bad settings")
SD.SnmpDriver.__init__ = bad_init
rows = runner.snmp_extras(fw, TH, dict(OPTS), [], only=["cpu"])
check("the SNMP driver failing to build is the one snmp ERROR row", [(r.check, r.status) for r in rows] == [("snmp", "ERROR")] and rows[0].message.startswith("SNMP: "), show(rows))
SD.SnmpDriver.__init__ = real_init

print("== cmdrun.run_cli")
sent, hooked = [], []
class FakeConn:
    base_prompt = ""
    def __init__(self, **kw): self.kw = kw
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def send_command(self, cmd, **k): sent.append(cmd); return "out " + cmd
real_ch = cmdrun.ConnectHandler; cmdrun.ConnectHandler = FakeConn
cmdrun.run_cli = REAL_RUN_CLI
got = cmdrun.run_cli(fw, ["a", "b"], before=lambda c: hooked.append(c) or False)
check("before returns False: no command sent, [] returned, before called once with the connection",
      got == [] and sent == [] and len(hooked) == 1 and isinstance(hooked[0], FakeConn), (got, sent, hooked))
hooked.clear()
got = cmdrun.run_cli(fw, ["a", "b"], device_type="fortinet_readonly", before=lambda c: hooked.append(c) or True)
check("before returns True: the commands run in order, with the device type given, no session log",
      got == [("a", "out a"), ("b", "out b")] and len(hooked) == 1 and hooked[0].kw["device_type"] == "fortinet_readonly" and "session_log" not in hooked[0].kw, (got, hooked[0].kw))
got = cmdrun.run_cli(fw, ["a"])
check("no device type given: vendors.CLI_TYPES", got == [("a", "out a")], got)
try:
    cmdrun.run_cli({**fw, "username": ""}, ["a"]); raised = None
except ValueError as e:
    raised = str(e)
check("no SSH login: raises as before", raised and "SSH user name and SSH password" in raised, raised)
cmdrun.ConnectHandler = real_ch

print("== netconn.FortinetReadOnly")
from netmiko.base_connection import BaseConnection
def never(*a, **k): raise AssertionError("wrote to the firewall")
ro = netconn.FortinetReadOnly.__new__(netconn.FortinetReadOnly)
ro.write_channel = never; ro.send_multiline = never; ro._output_mode = "more"; ro._original_output_mode = "more"; ro._vdoms = False
check("disable_paging returns '' and writes nothing", ro.disable_paging() == "")
real_cleanup = BaseConnection.cleanup; BaseConnection.cleanup = lambda self, command="": None
try:
    ro.cleanup(); wrote = False
except AssertionError:
    wrote = True
BaseConnection.cleanup = real_cleanup
check("cleanup writes no 'config system console' (send_multiline never called)", not wrote)
check("registered as SPECIAL['fortinet_readonly']", netconn.SPECIAL.get("fortinet_readonly") is netconn.FortinetReadOnly)
ro = netconn.FortinetReadOnly(device_type="fortinet_readonly", host="h", username="u", password="p", auto_connect=False)
check("it reaches netmiko as device_type 'fortinet' (an error text never shows the internal name)", ro.device_type == "fortinet", ro.device_type)
ro.write_channel = never; ro._vdoms = True; ro._os_version = "v7_or_later"
try:
    mode = ro._get_output_mode()
except Exception as e:                     # (a write raises; netmiko turns it into a ValueError)
    mode = repr(e)
check("_get_output_mode is 'more' and sends nothing", mode == "more", mode)

class FortiChan:
    """A FortiGate with VDOMs on FortiOS 7 behind a fake channel: answers the commands netmiko sends while signing in."""
    ANSWERS = {"get system status | grep Virtual": "Virtual domain configuration: multiple",
               "get system status | grep Version": "Version: FortiGate-60F v7.2.5,build1517,230606 (GA.F)", "get system console": "output              : more"}
    def __init__(self): self.pending, self.sent = "FGT # ", []
    def write_channel(self, data):
        for line in data.splitlines(True):
            if line.endswith("\n"):
                cmd = line.strip(); self.sent.append(cmd)
                self.pending += cmd + "\n" + (self.ANSWERS[cmd] + "\n" if cmd in self.ANSWERS else "") + "FGT # "
    def read_channel(self):
        out, self.pending = self.pending, ""; return out
ro = netconn.FortinetReadOnly(device_type="fortinet_readonly", host="h", username="u", password="p", auto_connect=False, fast_cli=True)
ro.channel = FortiChan()
ro.session_preparation(); ro.cleanup()
typed = ro.channel.sent
check("a session (sign-in and clean-up) on a VDOM FortiGate sends no 'config ' or 'set ' line, nor 'get system console'",
      typed and not [c for c in typed if c.startswith(("config ", "set ")) or c == "get system console"], typed)
check("...and it read the VDOM setting the fill's before hook needs", ro._vdoms is True, ro._vdoms)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
