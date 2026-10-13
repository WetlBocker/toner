# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The extra checks on Cisco, Juniper, Arista, HPE and MikroTik: readers tested on samples of real output, and the drivers on a simulated device.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time
from datetime import datetime
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "clichk%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingclichk%d" % int(time.time()))
from core import checks, db
db.init()
from drivers import DRIVERS, clichecks as C
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

print("== fans, power supplies and sensors, from text")
ios = "FAN is OK\nTEMPERATURE is OK\nSW  PID   Serial#   Status   Sys Pwr  PoE Pwr  Watts\n--  ----  --------  -------  -------  -------  -----\n1   Built-in\nRPS is not present\n"
check("IOS: all fine", C.scan_environment(ios) == (2, []), C.scan_environment(ios))
check("IOS: a fan that is not OK fails", C.scan_environment(ios.replace("FAN is OK", "FAN is NOT OK"))[1][0][0] == "FAIL")
xe = "Switch 1 FAN 1 is OK\nSwitch 1 FAN 2 is OK\nSwitch 1: SYSTEM TEMPERATURE is OK\nInlet Temperature Value: 29 Degree Celsius\nTemperature State: GREEN\nFAN PS-1 is OK\n"
check("IOS XE: fans, temperature and the colour state", C.scan_environment(xe)[0] == 5 and C.scan_environment(xe)[1] == [], C.scan_environment(xe))
check("IOS XE: a yellow temperature warns, a red one fails", C.scan_environment(xe.replace("GREEN", "YELLOW"))[1][0][0] == "WARN" and C.scan_environment(xe.replace("GREEN", "RED"))[1][0][0] == "FAIL")
nx = """Fan:
---------------------------------------------------
Fan             Model                Hw     Status
---------------------------------------------------
Chassis-1       N9K-C93180-FAN       --     Ok
PS-1            --                   --     Absent

Power Supply:
Voltage: 12 Volts
PS  Model                Power       Power     Status
                         (Watts)     (Amp)
1   N9K-PAC-650W          650.00     54.16     Ok
2   N9K-PAC-650W            0.00      0.00     Failure

Temperature:
Module   Sensor        MajorThresh   MinorThres   CurTemp     Status
1        Outlet           75             70          38         Ok
"""
r = C.scan_environment(nx)
check("NX-OS: tables under a heading are read row by row; an absent power supply is ignored; a failure is found", r[0] == 4 and [m for _, m in r[1]] == ["2 N9K-PAC-650W 0.00 0.00 Failure"], r)
jn = "Class Item                           Status     Measurement\nPower Power Supply 0                 OK\n      Power Supply 1                 Absent\nTemp  PEM 0                          OK         37 degrees C / 98 degrees F\nFans  Fan Tray 0 Fan 1               OK         Spinning at normal speed\n      Fan Tray 0 Fan 2               Check      Stopped\n"
r = C.scan_environment(jn)
check("Junos: a fan marked Check is a failure, an absent supply is not", r[1][0][0] == "FAIL" and "Fan 2" in r[1][0][1] and len(r[1]) == 1, r)
check("text that is not about fans at all gives None (no row, no guess)", C.scan_environment("% Invalid input detected at '^' marker.") is None and C.scan_environment("") is None and C.scan_environment("hostname sw1\nversion 15") is None)
ar = C.deep_status({"systemStatus": "coolingOk", "fanTraySlots": [{"status": "ok", "fans": [{"status": "ok"}, {"status": "failed"}]}], "powerSupplySlots": [{"status": "absent"}]})
check("Arista JSON: only the status that is not good is listed", ar == [("FAIL", "fanTraySlots/0/fans/1/status: failed")], ar)
check("Arista JSON: a power supply that lost power fails", C.deep_status({"powerSupplies": {"1": {"state": "ok"}, "2": {"state": "powerLoss"}}}) == [("FAIL", "powerSupplies/2/state: powerLoss")])

print("== the clock, saved configuration, flash")
check("NTP: synchronised, not synchronised, and off", C.ntp_state("Clock is synchronized, stratum 3, reference is 10.0.0.1") == "synchronized"
      and C.ntp_state("Clock is unsynchronized, stratum 16, no reference clock") == "unsynchronized" and C.ntp_state("%NTP is not enabled.") is None
      and C.ntp_state("synchronised to NTP server (10.0.0.1) at stratum 3") == "synchronized" and C.ntp_state("unsynchronised") == "unsynchronized")
junos = "     remote           refid      st t when poll reach   delay   offset  jitter\n==============================================================\n*10.0.0.1        .GPS.            1 u   34   64  377    0.512    0.011   0.025\n 10.0.0.2        10.0.0.1         2 u   12   64  377    0.7      0.1     0.1\n"
check("Junos NTP: the line with * is the one the clock follows", C.junos_ntp(junos) == "synchronized" and C.junos_ntp(junos.replace("*10.0.0.1", " 10.0.0.1")) == "unsynchronized" and C.junos_ntp("") is None)
check("an IOS time is read with or without a zone and fractions", C.ios_time("! Last configuration change at 10:21:33 UTC Tue Oct 6 2026 by admin") == datetime(2026, 10, 6, 10, 21, 33)
      and C.ios_time("*10:21:33.123 UTC Tue Oct  6 2026") == datetime(2026, 10, 6, 10, 21, 33) and C.ios_time("nothing") is None)
saved = "! Last configuration change at 10:21:33 UTC Tue Oct 6 2026 by admin\n! NVRAM config last updated at 10:22:01 UTC Tue Oct 6 2026 by admin\n"
check("saved: the startup configuration is newer than the last change", C.unsaved_ios(saved) == (False, ""))
r = C.unsaved_ios(saved.replace("10:21:33", "11:30:00"))
check("not saved: the last change is newer, and says when", r[0] is True and "2026-10-06 11:30" in r[1] and "10:22" in r[1], r)
check("never saved: a change and no save", C.unsaved_ios("! Last configuration change at 10:21:33 UTC Tue Oct 6 2026\n")[0] is True)
check("nothing readable: None", C.unsaved_ios("") is None)
check("flash: used percentage and free bytes", C.flash_usage("Directory of flash:/\n122185728 bytes total (80211968 bytes free)\n")[0] == (122185728 - 80211968) / 122185728 * 100 and C.flash_usage("nope") is None)

print("== Cisco: stacks, redundancy, port-channels, failover")
sw = "Switch/Stack Mac Address : 0011.2233.4455 - Local Mac Address\n                                           H/W   Current\nSwitch#  Role    Mac Address     Priority Version  State \n----------------------------------------------------------\n*1       Active   0011.2233.4455     15     V01     Ready\n 2       Standby  0011.2233.4466     14     V01     Ready\n 3       Member   0011.2233.4477      1     V01     Version Mismatch\n"
check("show switch: members with their state, with or without the hardware-version column", [m[2] for m in C.stack_members(sw)] == ["Ready", "Ready", "Version Mismatch"]
      and C.stack_members("*1 Active 0011.2233.4455 15 Ready\n 2 Member 0011.2233.4466 1 Provisioned")[1][2] == "Provisioned")
hs = "Interface   Grp  Pri P State   Active          Standby         Virtual IP\nVl10        10   110 P Active  local           10.0.10.3       10.0.10.1\nVl20        20   100   Standby 10.0.20.2       local           10.0.20.1\nVl30        30   100   Init    unknown         unknown         10.0.30.1\n"
check("HSRP: groups and their states", C.hsrp_groups(hs) == [("Vl10", "10", "Active"), ("Vl20", "20", "Standby"), ("Vl30", "30", "Init")], C.hsrp_groups(hs))
check("VRRP: the brief table too", C.hsrp_groups("Interface Grp Pri Time Own Pre State Master addr Group addr\nGi0/0 1 100 3609 Y Master 10.0.0.1 10.0.0.254\n") == [("Gi0/0", "1", "Master")])
ec = "Group  Port-channel  Protocol    Ports\n------+-------------+-----------+-----------------------------------------------\n1      Po1(SU)         LACP      Gi0/1(P)    Gi0/2(P)\n2      Po2(SD)         LACP      Gi0/3(D)    Gi0/4(D)\n3      Po3(SU)         LACP      Gi0/5(P)    Gi0/6(s)\n"
check("etherchannel summary: channels, their flags and members", [(n, f, [m for m, _ in mem]) for n, f, mem in C.etherchannels(ec)] == [("Po1", "SU", ["Gi0/1", "Gi0/2"]), ("Po2", "SD", ["Gi0/3", "Gi0/4"]), ("Po3", "SU", ["Gi0/5", "Gi0/6"])])
fo = "Failover On\nFailover unit Primary\nFailover LAN Interface: failover GigabitEthernet0/3 (up)\n        This host: Primary - Active\n                Active time: 12345 (sec)\n        Other host: Secondary - Standby Ready\n"
check("ASA failover: both states, no problems", C.asa_failover(fo) == ("Active", "Standby Ready", []))
check("ASA failover: a failed peer is a problem, and off means no row", C.asa_failover(fo.replace("Standby Ready", "Failed"))[2] == ["the other unit: Failed"] and C.asa_failover("Failover Off\n") is None)

print("== Juniper and Arista")
check("Junos core dumps: files found, or none", C.junos_core_dumps("-rw-r--r--  1 root  wheel  1234567 Oct  6 10:00 /var/crash/core.rpd.1.gz\n") == ["/var/crash/core.rpd.1.gz"]
      and C.junos_core_dumps("ls: /var/crash/core.*: No such file or directory") == [])
bfd = "Address                  State     Interface      Time     Interval  Multiplier\n10.0.0.2                 Up        ge-0/0/1.0     0.900    0.300     3\n10.0.0.3                 Down      ge-0/0/2.0     0.000    0.300     3\n"
check("Junos BFD: the sessions that are down", C.junos_bfd_down(bfd) == ["10.0.0.3"])
mlag = {"state": "active", "negStatus": "connected", "peerLinkStatus": "up", "configSanity": "consistent", "mlagPorts": {"Disabled": 0, "Configured": 0, "Inactive": 0, "Active-partial": 0, "Active-full": 4}}
check("Arista MLAG: healthy, broken, and not configured", C.mlag_problems(mlag) == [] and C.mlag_problems({**mlag, "peerLinkStatus": "down"}) == ["peer link down"]
      and "inactive" in C.mlag_problems({**mlag, "mlagPorts": {"Inactive": 2, "Active-partial": 0}})[0] and C.mlag_problems({"state": "disabled"}) is None)

print("== MikroTik")
check("health: v6 and v7 layouts", C.mikrotik_health("          voltage: 24.1V\n      temperature: 45C\n cpu-temperature: 48C\n") == ({"temperature": 45.0, "cpu-temperature": 48.0}, 24.1)
      and C.mikrotik_health("0 name=temperature value=45 type=C\n1 name=voltage value=24.1 type=V")[0] == {"temperature": 45.0} and C.mikrotik_health("not supported")[0] == {})
check("disk: used percentage of the flash", abs(C.mikrotik_disk({"free-hdd-space": "32.0MiB", "total-hdd-space": "128.0MiB"}) - 75.0) < 0.01 and C.mikrotik_disk({}) is None)
check("RouterBOARD firmware: current and upgrade", C.mikrotik_firmware("routerboard: yes\n current-firmware: 7.1\n upgrade-firmware: 7.5\n") == ("7.1", "7.5") and C.mikrotik_firmware("routerboard: no") is None)
check("NTP client", C.mikrotik_ntp("enabled: yes\n status: synchronized") == "synchronized" and C.mikrotik_ntp("enabled: yes\n status: started") == "unsynchronized" and C.mikrotik_ntp("enabled: no") == "off")

print("== the drivers, on a simulated device")
TH = db.thresholds_for({"name": "x", "vendor": "cisco", "location": ""})
OPTS = {**db.runtime_options(), "disabled": set()}
class Conn:
    def __init__(self, t): self.t = t
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def enable(self): pass
    def send_command(self, cmd, **kw): return self.t.get(cmd, "% Invalid input detected at '^' marker.")
def run(vendor, table, platform="", opts=None, **dev):
    d = {"name": "t", "vendor": vendor, "host": "10.0.0.1", "username": "u", "platform": platform, "password": "p", **dev}
    drv = DRIVERS[vendor](d, TH, {**OPTS, **(opts or {})})
    drv.connect = lambda: Conn(table)
    return {r.check: r for r in drv.run()}
CI = {"show environment all": ios.replace("FAN is OK", "FAN is NOT OK"), "show ntp status": "Clock is unsynchronized, stratum 16, no reference clock",
      "show running-config | include ^! Last configuration change|^! NVRAM config last updated": saved.replace("10:21:33", "11:30:00"), "dir flash:": "100 bytes total (10 bytes free)",
      "show switch": sw, "show standby brief": hs, "show etherchannel summary": ec}
r = run("cisco", CI)
check("Cisco IOS: a failed fan, no NTP sync and an unsaved configuration", r["environment"].status == "FAIL" and r["ntp"].status == "WARN" and r["unsaved config"].status == "WARN" and "11:30" in r["unsaved config"].message)
check("Cisco IOS: flash 90% full, a stack member with a version mismatch, an HSRP group stuck in Init, a port-channel down",
      r["flash"].status == "FAIL" and r["stack"].status == "FAIL" and "Version Mismatch" in r["stack"].message and r["hsrp"].status == "WARN" and "Vl30" in r["hsrp"].message and r["port-channels"].status == "FAIL" and "Po2" in r["port-channels"].message,
      {k: (v.status, v.value, v.message) for k, v in r.items() if k in ("flash", "stack", "hsrp", "port-channels")})
check("Cisco IOS: no failover row (that is the ASA's)", "failover" not in r)
r = run("cisco", {"show failover": fo.replace("Standby Ready", "Failed"), "show environment": ""}, platform="cisco_asa")
check("Cisco ASA: a failed peer fails the failover row", r["failover"].status == "FAIL" and "Failed" in r["failover"].message and "stack" not in r and "unsaved config" not in r)
r = run("cisco", {"show environment": nx}, platform="cisco_nxos")
check("Cisco NX-OS: environment from the tables", r["environment"].status == "FAIL" and "Failure" in r["environment"].message)
r = run("cisco", {})
check("a device that answers none of them adds no rows and no errors", not ({"environment", "ntp", "unsaved config", "flash", "stack", "hsrp", "port-channels", "failover"} & set(r)) and not [k for k, v in r.items() if v.status == "ERROR" and k in ("environment", "ntp")])
JT = {"show chassis environment": jn, "show ntp associations": junos.replace("*10.0.0.1", " 10.0.0.1"), "show | compare": "[edit system]\n-  host-name old;\n+  host-name new;\n",
      "show system core-dumps": "-rw-r--r-- 1 root wheel 1234567 Oct 6 10:00 /var/crash/core.rpd.1.gz", "show bfd session": bfd,
      "show system storage": "Filesystem Size Used Avail Capacity Mounted on\n/dev/gpt/junos 1.2G 740M 380M 66% /.mount\n/dev/gpt/var 4.0G 3.8G 100M 96% /.mount/var\ndevfs 1.0K 1.0K 0B 100% /dev\n",
      "show virtual-chassis status": "Member ID  Status   Serial No    Model          prio  Role\n0 (FPC 0)  Prsnt    AB1234       ex4300-48t      129  Master*\n1 (FPC 1)  NotPrsnt CD5678       ex4300-48t      129  Backup\n"}
r = run("juniper", JT)
check("Junos: failed fan, NTP not following a server, uncommitted changes, a core dump, a BFD session down", r["environment"].status == "FAIL" and r["ntp"].status == "WARN" and r["uncommitted"].status == "WARN" and "2 changed" in r["uncommitted"].value
      and r["core dumps"].status == "WARN" and "core.rpd" in r["core dumps"].message and r["bfd"].status == "FAIL" and "10.0.0.3" in r["bfd"].message, {k: v.status for k, v in r.items()})
check("Junos: the fullest real filesystem decides (96% of /var), devfs is ignored; a missing virtual-chassis member fails", r["storage"].status == "FAIL" and r["storage"].value == "96%" and r["virtual chassis"].status == "FAIL" and "member 1" in r["virtual chassis"].message)
r = run("juniper", {"show | compare": "", "show system core-dumps": "ls: /var/crash/core.*: No such file or directory", "show chassis environment": "Class Item Status\nFans Fan Tray 0 Fan 1 OK Spinning at normal speed\n"})
check("Junos: nothing wrong says so", r["uncommitted"].status == "OK" and r["core dumps"].status == "OK" and r["environment"].status == "OK")
AR = {"show system environment cooling | json": json.dumps({"systemStatus": "coolingOk", "fanTraySlots": [{"status": "ok", "fans": [{"status": "failed"}]}]}),
      "show system environment power | json": json.dumps({"powerSupplies": {"1": {"state": "ok"}}}), "show mlag | json": json.dumps({**mlag, "negStatus": "connecting"}),
      "show ntp status": "unsynchronised", "dir flash:": "4000000000 bytes total (1000000000 bytes free)"}
r = run("arista", AR)
check("Arista: a failed fan, MLAG without its peer, no NTP sync, flash 75% full", r["environment"].status == "FAIL" and r["mlag"].status == "FAIL" and "peer connecting" in r["mlag"].message and r["ntp"].status == "WARN" and r["flash"].status == "OK", {k: v.status for k, v in r.items() if k in ("environment", "mlag", "ntp", "flash")})
check("Arista: MLAG not configured gives no row", "mlag" not in run("arista", {"show mlag | json": json.dumps({"state": "disabled"})}))
HP = {"show environment fan": "Fan Status\n1 fan OK\n2 fan Fault\n", "show environment power-supply": "PS1 power OK\n", "show ntp status": "Status: unsynchronized"}
r = run("hpe", HP, platform="aruba_aoscx")
check("HPE AOS-CX: a fan in fault fails; NTP not synchronised warns", r["environment"].status == "FAIL" and r["ntp"].status == "WARN")
r = run("hpe", {"show system fans": "Fan Status: OK\nFan 2 : Failed\n"}, platform="aruba_osswitch")
check("HPE AOS-S reads its own commands", r["environment"].status == "FAIL")
MT = {"/system resource print": "uptime: 1d2h\ncpu-load: 3%\ntotal-memory: 256.0MiB\nfree-memory: 100.0MiB\ntotal-hdd-space: 128.0MiB\nfree-hdd-space: 8.0MiB\nversion: 7.1\nboard-name: hEX\n",
      "/system health print": "voltage: 24.1V\ntemperature: 90C\n", "/system routerboard print": "routerboard: yes\n current-firmware: 7.1\n upgrade-firmware: 7.5\n", "/system ntp client print": "enabled: yes\n status: synchronized\n"}
r = run("mikrotik", MT)
check("MikroTik: a hot board, a nearly full flash, RouterBOARD firmware to upgrade, NTP fine", r["health"].status == "FAIL" and r["health"].value == "90C" and r["disk"].status == "FAIL" and r["routerboard"].status == "WARN" and "7.5" in r["routerboard"].value and r["ntp"].status == "OK",
      {k: (v.status, v.value) for k, v in r.items() if k in ("health", "disk", "routerboard", "ntp")})
r = run("mikrotik", {**MT, "/system routerboard print": "routerboard: no\n"})
check("MikroTik: a virtual router has no RouterBOARD row", "routerboard" not in r)

print("== switching them off")
r = run("cisco", CI, opts={"disabled": {"cisco:environment", "cisco:ntp", "cisco:unsaved config", "cisco:flash", "cisco:stack", "cisco:hsrp", "cisco:port-channels"}})
check("each can be switched off in Settings > Checks", not ({"environment", "ntp", "unsaved config", "flash", "stack", "hsrp", "port-channels"} & set(r)))
check("the catalog lists them", {"environment", "unsaved config", "stack", "hsrp", "port-channels", "failover"} <= {k for k, _ in checks.CATALOG["cisco"]} and {"uncommitted", "core dumps", "bfd", "virtual chassis"} <= {k for k, _ in checks.CATALOG["juniper"]}
      and {"mlag", "flash"} <= {k for k, _ in checks.CATALOG["arista"]} and {"health", "routerboard", "disk"} <= {k for k, _ in checks.CATALOG["mikrotik"]})

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
