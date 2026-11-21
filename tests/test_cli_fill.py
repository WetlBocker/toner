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

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
