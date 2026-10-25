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
check("flash on an ASA: its free line adds a percentage", C.flash_usage("8238170112 bytes total (7804764160 bytes free/94% free)\n")[1] == 7804764160)

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
ASA_IF = ('Interface Management0/0 "management", is up, line protocol is up\n'
          '  Hardware is net_vmxnet3, BW 10000 Mbps, DLY 10 usec\n'
          '\tAuto-Duplex(Full-duplex), Auto-Speed(10000 Mbps)\n'
          '\tAccelerated networking: enabled\n'                       # a line the ntc-templates reading stops at
          '\tMAC address 000d.3a2b.1c4d, MTU 1500\n\tIP address 10.196.171.197, subnet mask 255.255.255.0\n'
          '\t123456 packets input, 98765432 bytes, 0 no buffer\n\t0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored, 0 abort\n'
          '  Traffic Statistics for "management":\n\t123456 packets input, 98765432 bytes\n'
          'Interface GigabitEthernet0/0 "outside", is up, line protocol is up\n'
          '  Hardware is net_vmxnet3, BW 10000 Mbps, DLY 10 usec\n\t5 input errors, 2 CRC, 0 frame, 0 overrun, 0 ignored, 0 abort\n'
          'Interface GigabitEthernet0/1 "inside", is down, line protocol is down\n\t0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored, 0 abort\n'
          'Interface GigabitEthernet0/2 "", is administratively down, line protocol is down\n  Available but not configured via nameif\n')
ASA = {"show cpu usage": "CPU utilization for 5 seconds = 4%; 1 minute: 6%; 5 minutes: 85%\n",
       "show memory": "Free memory:        5045604352 bytes (59%)\nUsed memory:        3544279040 bytes (41%)\n-------------     ------------------\nTotal memory:       8589883392 bytes (100%)\n",
       "show version": "Cisco Adaptive Security Appliance Software Version 9.18(3)\nDevice Manager Version 7.18(1)\n\n"
                       "Compiled on Thu 19-Jan-23 by builders\nSystem image file is \"disk0:/asa9-18-3-smp-k8.bin\"\n"
                       "Config file at boot was \"startup-config\"\n\nAZ-PROD-NEU-VASA-01 up 2 days 3 hours 14 mins\n"
                       "failover cluster up 2 years 10 days\n",
       "show interface": ASA_IF, "show ntp status": "Clock is synchronized, stratum 3, reference is 10.0.0.1",
       "dir disk0:": "Directory of disk0:/\n\n8571076608 bytes total (6857661286 bytes free)\n",
       "show bgp summary": "BGP router identifier 10.0.0.2, local AS number 65010\nNeighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n"
                           "10.0.0.1        4        65001    1200    1201       42    0    0 2d03h          12\n10.0.0.9        4        65002       0       0        1    0    0 never    Active\n",
       "show ospf neighbor": "Neighbor ID     Pri   State           Dead Time   Address         Interface\n10.1.1.1          1   FULL/DR         0:00:33     10.0.0.5        inside\n",
       "show environment": "ERROR: % Invalid input detected at '^' marker.\n", "show failover": "Failover Off\n"}
check("ASA parsers: CPU over 5 minutes, memory used, its own uptime line (not the failover cluster's)",
      C.asa_cpu(ASA["show cpu usage"]) == 85 and C.asa_memory(ASA["show memory"]) == 41.0 and C.asa_uptime(ASA["show version"]) == "2 days 3 hours 14 mins"
      and C.asa_cpu("") is None and C.asa_memory("nothing") is None and C.asa_uptime("Cisco Adaptive Security Appliance") is None)
check("ASA interfaces: every interface, its state and its error counters, through lines a template would stop at",
      [(i["interface"], i["nameif"], i["link_status"], i["input_errors"], i["crc"]) for i in C.asa_interfaces(ASA_IF)]
      == [("Management0/0", "management", "up", 0, 0), ("GigabitEthernet0/0", "outside", "up", 5, 2), ("GigabitEthernet0/1", "inside", "down", 0, 0),
          ("GigabitEthernet0/2", "", "administratively down", 0, 0)], C.asa_interfaces(ASA_IF))
r = run("cisco", ASA, platform="cisco_asa")
rows = {k: (v.status, v.value) for k, v in r.items()}
check("Cisco ASAv: CPU, memory, uptime, interfaces, interface errors, NTP, disk, BGP and OSPF all have rows", all(k in r for k in
      ("cpu", "memory", "uptime", "interfaces", "interface errors", "ntp", "flash", "bgp", "ospf")) and not [k for k, v in r.items() if v.status == "ERROR"], rows)
check("Cisco ASAv: the values are read right", r["cpu"].status == "WARN" and r["cpu"].value == "85%" and r["memory"].status == "OK" and abs(r["uptime"].numeric - (51 + 14 / 60)) < 0.01
      and r["interfaces"].status == "FAIL" and "GigabitEthernet0/1" in r["interfaces"].message and "GigabitEthernet0/2" not in r["interfaces"].message
      and r["interface errors"].status == "WARN" and "GigabitEthernet0/0" in r["interface errors"].message
      and r["flash"].value == "20%" and r["bgp"].status == "FAIL" and "10.0.0.9" in r["bgp"].message and r["ospf"].status == "OK", rows)
na = lambda k: (r[k].status, r[k].value, r[k].message) if k in r else None
check("Cisco ASAv: N/A rows for the environment (no sensors), failover (off) and EIGRP (not configured)",
      na("environment") == ("N/A", "no sensors", "this device reports no fans, power supplies or temperature") and na("failover") == ("N/A", "off", "failover is not configured")
      and na("eigrp") == ("N/A", "not configured", "EIGRP is not configured on this device"), {k: na(k) for k in ("environment", "failover", "eigrp")})
r = run("cisco", {**ASA, "show cpu usage": "something else", "show interface": "nothing here"}, platform="cisco_asa")
check("Cisco ASA: output that cannot be read is an error row that says which command, not a missing row",
      r["cpu"].status == "ERROR" and "show cpu usage" in r["cpu"].message and r["interfaces"].status == "ERROR" and "show interface" in r["interfaces"].message,
      {k: (v.status, v.message) for k, v in r.items() if v.status == "ERROR"})
drv = DRIVERS["cisco"]({"name": "t", "vendor": "cisco", "host": "10.0.0.1", "username": "u", "platform": "cisco_asa", "password": "p"}, TH, OPTS)
drv.connect = lambda: Conn(ASA)
check("Cisco: the interfaces for Choose interfaces (an ASA's too)", drv.list_interfaces() == [("Management0/0", "up"), ("GigabitEthernet0/0", "up"),
      ("GigabitEthernet0/1", "down"), ("GigabitEthernet0/2", "off")], drv.list_interfaces())
r = run("cisco", {"show environment": nx}, platform="cisco_nxos")
check("Cisco NX-OS: environment from the tables", r["environment"].status == "FAIL" and "Failure" in r["environment"].message)
r = run("cisco", {})
check("a device that answers none of them: N/A for the environment, BGP, OSPF and EIGRP, no other rows, no errors",
      not ({"ntp", "unsaved config", "flash", "stack", "hsrp", "port-channels", "failover"} & set(r)) and all(r[k].status == "N/A" for k in ("environment", "bgp", "ospf", "eigrp"))
      and not [k for k, v in r.items() if v.status == "ERROR" and k in ("environment", "ntp", "bgp", "ospf", "eigrp")], {k: v.status for k, v in r.items()})

print("== BGP, OSPF and EIGRP on Cisco: not configured, running with no neighbors, neighbors")
from drivers.base import NA, is_problem
r = run("cisco", {"show ip bgp summary": "% BGP not active\n", "show ip ospf neighbor": "", "show ip ospf": "", "show ip eigrp neighbors": ""})
check("not configured: N/A rows that say so", [(r[k].status, r[k].value, r[k].message) for k in ("bgp", "ospf", "eigrp")] ==
      [("N/A", "not configured", f"{p} is not configured on this device") for p in ("BGP", "OSPF", "EIGRP")], [(r[k].status, r[k].message) for k in ("bgp", "ospf", "eigrp")])
r = run("cisco", {"show ip bgp summary": "BGP router identifier 10.0.0.1, local AS number 65000\nBGP table version is 1, main routing table version 1\n",
                  "show ip ospf neighbor": "", "show ip ospf": ' Routing Process "ospf 1" with ID 10.0.0.1\n Start time: 00:00:12.345, Time elapsed: 1d02h\n',
                  "show ip eigrp neighbors": "EIGRP-IPv4 Neighbors for AS(100)\n"})
check("running with no neighbors: WARN rows that say so", [(r[k].status, r[k].value, r[k].message) for k in ("bgp", "ospf", "eigrp")] ==
      [("WARN", "no neighbors", f"{p} is running but has no neighbors") for p in ("BGP", "OSPF", "EIGRP")], [(r[k].status, r[k].message) for k in ("bgp", "ospf", "eigrp")])
IOS_EIGRP = ("EIGRP-IPv4 Neighbors for AS(100)\nH   Address                 Interface              Hold Uptime   SRTT   RTO  Q  Seq\n"
             "                                                   (sec)         (ms)       Cnt Num\n"
             "1   10.1.1.3                Gi0/2                    12 01:02:03    4   100  0  9\n"
             "0   10.1.1.2                Gi0/1                    13 00:10:12    1   100  0  5\n"
             "2   10.1.2.2                Vl20                     11 2d03h       2   100  0  7\n")
ASA_EIGRP = ("EIGRP-IPv4 Neighbors for AS(10)\nH   Address                 Interface       Hold Uptime   SRTT   RTO  Q   Seq\n"
             "                                            (sec)         (ms)       Cnt Num\n0   10.0.0.5                inside            12 00:05:31 1      200  0   7\n")
NX_EIGRP = ("IP-EIGRP neighbors for process 100 VRF default\nH   Address                 Interface       Hold  Uptime  SRTT   RTO  Q  Seq\n"
            "                                            (sec)               (ms)       Cnt Num\n0   10.2.0.2                Eth1/1          14   1w2d    3      50   0   12\n")
check("EIGRP neighbors are read from IOS, ASA and NX-OS", C.eigrp_neighbors(IOS_EIGRP) == (True, [("10.1.1.3", "Gi0/2"), ("10.1.1.2", "Gi0/1"), ("10.1.2.2", "Vl20")])
      and C.eigrp_neighbors(ASA_EIGRP) == (True, [("10.0.0.5", "inside")]) and C.eigrp_neighbors(NX_EIGRP) == (True, [("10.2.0.2", "Eth1/1")])
      and C.eigrp_neighbors("") == (False, []) and C.eigrp_neighbors("% Invalid input detected at '^' marker.") == (False, []))
with db.connect() as cx: cx.execute("DELETE FROM counter_baseline WHERE device='eigrp-sw'")      # a first run
def eigrp_run(text, plat=""):
    drv = DRIVERS["cisco"]({"name": "eigrp-sw", "vendor": "cisco", "host": "10.0.0.1", "username": "u", "platform": plat, "password": "p"}, TH, OPTS)
    drv.connect = lambda: Conn({"show ip eigrp neighbors": text, "show eigrp neighbors": text})
    rows = {x.check: x for x in drv.run()}
    drv.flush_baselines()
    return rows["eigrp"]
e = eigrp_run(IOS_EIGRP)
check("EIGRP with 3 neighbors: OK", (e.status, e.value, e.message) == ("OK", "3 neighbors", ""), e)
fewer = IOS_EIGRP.replace("0   10.1.1.2                Gi0/1                    13 00:10:12    1   100  0  5\n", "")
e = eigrp_run(fewer)
check("one gone since the last run: WARN, '2 neighbors', '1 fewer than the last run (3)'", (e.status, e.value, e.message) == ("WARN", "2 neighbors", "1 fewer than the last run (3)"), e)
e = eigrp_run(fewer)
check("the same two on the next run: OK again", (e.status, e.value) == ("OK", "2 neighbors"), e)
e = eigrp_run(ASA_EIGRP, "cisco_asa")
check("an ASA reads 'show eigrp neighbors', and one neighbor is singular", e.value == "1 neighbor", e)
keys = [k for k, _l in checks.CATALOG["cisco"]]
check("EIGRP is in the Cisco list of checks, after OSPF", keys.index("eigrp") == keys.index("ospf") + 1 and ("eigrp", "EIGRP neighbors") in checks.CATALOG["cisco"])

print("== N/A is never a problem")
check("N/A is not a problem; WARN, FAIL and ERROR are", not is_problem(NA) and not is_problem("OK") and all(is_problem(s) for s in ("WARN", "FAIL", "ERROR")))
from core import alerts, reports
from drivers.base import Result
ev = alerts.evaluate([Result("na-dev", "bgp", "N/A", "not configured", "BGP is not configured on this device")], ["na-dev"])
check("an N/A row raises no alert", ev == [], ev)
html = reports.to_html([Result("na-dev", "bgp", "N/A", "not configured", "BGP is not configured on this device"), Result("na-dev", "cpu", "OK", "5%")])
check("a report lists N/A in its counts but not under Needs attention", "N/A: 1" in html and "No problems found." in html)
reports.apply_colors("Color-blind safe"); cb = reports.COLORS.get("N/A"); reports.apply_colors("Default")
check("N/A is grey in every colour preset", cb == reports.NA_COLOR and reports.COLORS["N/A"] == reports.NA_COLOR)
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
