# Run directly (python tests/test_fill_gaps.py) or all together (python tests/run_all.py).
# Which tick box governs each subject (CPU, memory, storage, uptime, interfaces, interface errors) for each vendor.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
from core import checks, vendors
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

print("== governs")
for v, s, want in [("fortinet", "cpu", "resources"), ("fortinet", "memory", "resources"), ("fortinet", "interface errors", "interfaces"),
                   ("fortinet", "storage", "storage"), ("paloalto", "interface errors", "interface errors"), ("cisco", "cpu", "cpu"),
                   ("juniper", "storage", "storage")]:
    check(f"{v} {s} -> {want}", checks.governs(v, s) == want, checks.governs(v, s))

print("== the catalogue gains the SNMP entries")
fg = checks.CATALOG["fortinet"]
check("fortinet gains storage via SNMP", ("storage", "Disk and storage (via SNMP)") in fg)
check("fortinet has no interface errors key", "interface errors" not in [k for k, _ in fg])
check("paloalto gains interface errors via SNMP", ("interface errors", "Interface errors (via SNMP)") in checks.CATALOG["paloalto"])
jun = [e for e in checks.CATALOG["juniper"] if e[0] == "storage"]
check("juniper keeps its own storage label, once", jun == [("storage", "Storage space")], jun)
check("no key twice in a vendor's list (sonicwall's own uptime and interfaces aside)",
      all(len({k for k, _ in l}) == len(l) for v, l in checks.CATALOG.items() if v != "sonicwall"))
check("the six labels say via SNMP", [l for _, l in checks.SNMP_EXTRA] == ["CPU (via SNMP, when set up)", "Memory (via SNMP)", "Disk and storage (via SNMP)",
      "Uptime and recent reboots (via SNMP)", "Interface status (via SNMP)", "Interface errors (via SNMP)"])

print("== fills")
for v in ("fortinet", "paloalto", "cisco", "proxmox"): check(f"fills {v}", vendors.fills(v) is True)
for v in ("sonicwall", "ciscoise", "meraki", "mist", "unifi_cloud", "windows", "snmp", "esxi", "cloud", "wifi", ""): check(f"does not fill {v!r}", vendors.fills(v) is False)

print("== the other lists are unchanged")
SNMP6 = ["cpu", "memory", "storage", "uptime", "interfaces", "interface errors"]
BEFORE = {
    "sonicwall": ["reachability", "uptime", "resources", "interfaces", "ha", "licenses"] + SNMP6 + ["wan usage"],
    "ciscoise": ["reachability", "nodes", "patches", "licensing", "sessions"] + SNMP6,
    "ciscofmc": ["reachability", "devices", "deployment", "ha"] + SNMP6,
    "ciscosdwan": ["reachability", "devices", "control connections", "bfd", "alarms", "resources"] + SNMP6,
    "vmware": ["reachability", "hosts", "vms", "datastores", "health"] + SNMP6,
    "meraki": ["devices", "uplinks", "licenses", "alerts", "config changes", "vpn", "uplink quality"],
    "windows": ["reachability", "cpu", "memory", "disks", "uptime", "pending reboot", "services", "events", "certificates", "patches", "changes", "disk health",
                "bitlocker", "antivirus", "firewall", "clock", "logons", "activation", "sessions", "tasks", "ad replication", "hyper-v", "backup"],
}
for v, keys in BEFORE.items(): check(f"{v} keeps its keys", [k for k, _ in checks.CATALOG[v]] == keys)

print(f"\n{ok} passed, {bad} failed")
