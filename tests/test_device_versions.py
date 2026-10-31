# Run directly (python tests/test_device_versions.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The software version each device runs, read by the ordinary checks and kept on the device record: the one reading shared with the
# Firmware Transfer wizard (core/firmware.read_software), every covered driver on a simulated device, the record (migration, the
# runner writing it, Edit device keeping it, the audit line on a change, a move keeping it), the Inventory's Version column and the
# device page's Version row, and the Assistant reading it from the device rows. The wizard writing it is in test_firmware.py.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time
import xml.etree.ElementTree as ET
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "ver%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import db, display, orgs, runner
from core import firmware as FW
from core.assistant import agent, providers, store, tools as T
from drivers import DRIVERS
from drivers.base import Driver
from PySide6.QtWidgets import QApplication, QFormLayout
db.init()
app = QApplication([])
import app as A
A.apply_look(app)
import ui.inventory as I
import ui.device_view as DV

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def dev(name, vendor="cisco", **kw):
    d = dict(name=name, vendor=vendor, host="10.0.0.1", port=0, platform=kw.pop("platform", "cisco_ios"), username="admin", site="default", verify_ssl=0,
             ha_expected=0, enabled=1, location="", details="", folder_id=None)
    d.update(kw); d["id"] = db.save_device(d); return db.get_device(d["id"])
def audit_lines(word):
    with db.connect() as c:
        return [r["detail"] for r in c.execute("SELECT detail FROM audit WHERE action='version' ORDER BY id") if word in r["detail"]]

# ---------------------------------------------------------------- real show version forms
XE_TABLE = """Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)
core-sw1 uptime is 1 year, 3 weeks, 2 days, 4 hours, 5 minutes
System image file is "flash:packages.conf"

Switch Ports Model              SW Version        SW Image              Mode
------ ----- -----              ----------        ----------            ----
*    1 41    C9300-24P          17.09.04a         CAT9K_IOSXE           INSTALL
     2 41    C9300-24P          17.09.04a         CAT9K_IOSXE           INSTALL

Configuration register is 0x102
"""
XE_LINE = """Cisco IOS XE Software, Version 16.12.04
edge-sw uptime is 12 weeks, 1 day, 2 hours, 3 minutes
System image file is "flash:cat3k_caa-universalk9.16.12.04.SPA.bin"
Installation mode is BUNDLE
"""
XE_BARE = """Cisco IOS XE Software, Version 17.03.04
bare-sw uptime is 3 days, 2 hours, 1 minute
System image file is "{image}"
"""
IOS = """Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E9, RELEASE SOFTWARE (fc1)
acc-sw1 uptime is 2 years, 12 weeks, 3 days, 1 hour, 2 minutes
System image file is "flash:/c2960x-universalk9-mz.152-7.E9/c2960x-universalk9-mz.152-7.E9.bin"
"""
NXOS = """Cisco Nexus Operating System (NX-OS) Software
Software
  BIOS: version 05.47
  NXOS: version 10.2(5)
  NXOS image file is: bootflash:///nxos64-cs.10.2.5.M.bin
Hardware
Kernel uptime is 120 day(s), 3 hour(s), 2 minute(s), 1 second(s)
"""
ASA = """Cisco Adaptive Security Appliance Software Version 9.16(4)
Device Manager Version 7.18(1)
System image file is "disk0:/asa9-16-4-smp-k8.bin"
fw1 up 12 days 3 hours
"""
INSTALL_SUMMARY = """[ R0 ] Installed Package(s) Information:
State (St): I - Inactive, U - Activated & Uncommitted,
            C - Activated & Committed, D - Deactivated & Uncommitted
--------------------------------------------------------------------------------
Type  St   Filename/Version
--------------------------------------------------------------------------------
IMG   C    17.03.04.0.5797
"""

print("== one reading for the checks and the wizard (core/firmware.read_software)")
def reading(platform, table):
    sent = []
    def run(cmd):
        sent.append(cmd); return table.get(cmd, "% Invalid input detected at '^' marker.")
    return FW.read_software(platform, run), sent
r, sent = reading("cisco_xe", {"show version": XE_TABLE})
check("IOS XE, Catalyst 9000: version, the booted file and INSTALL from the table of switches; show version only", r == {"version": "17.09.04a", "image": "packages.conf", "mode": "INSTALL"} and sent == ["show version"], (r, sent))
r, sent = reading("cisco_xe", {"show version": XE_LINE})
check("IOS XE, older release: BUNDLE from the 'Installation mode is' line", r == {"version": "16.12.04", "image": "cat3k_caa-universalk9.16.12.04.SPA.bin", "mode": "BUNDLE"}, r)
r, sent = reading("cisco_xe", {"show version": XE_BARE.format(image="flash:packages.conf")})
check("IOS XE saying neither: packages.conf means INSTALL, without asking install", r["mode"] == "INSTALL" and sent == ["show version"], (r, sent))
r, sent = reading("cisco_xe", {"show version": XE_BARE.format(image="flash:cat9k_iosxe.17.03.04.SPA.bin")})
check("...a .bin means BUNDLE", r["mode"] == "BUNDLE" and r["image"] == "cat9k_iosxe.17.03.04.SPA.bin" and sent == ["show version"], (r, sent))
r, sent = reading("cisco_xe", {"show version": "Cisco IOS XE Software, Version 17.03.04\n", "show install summary": INSTALL_SUMMARY})
check("...and with no image line either, show install summary is asked and read", r == {"version": "17.03.04", "image": "", "mode": "INSTALL"} and sent == ["show version", "show install summary"], (r, sent))
r, sent = reading("cisco_xe", {"show version": "Cisco IOS XE Software, Version 17.03.04\n", "show install summary": "FAILED: install_summary : Device is not in INSTALL mode"})
check("...where a device that is not in INSTALL mode says so: BUNDLE", r["mode"] == "BUNDLE", r)
r, sent = reading("cisco_ios", {"show version": IOS})
check("IOS: version and the image (its folder inside flash kept, as the wizard needs it), no mode (IOS has none)",
      r == {"version": "15.2(7)E9", "image": "c2960x-universalk9-mz.152-7.E9/c2960x-universalk9-mz.152-7.E9.bin", "mode": ""}, r)
r, sent = reading("cisco_nxos", {"show version": NXOS})
check("NX-OS: version and the image", r == {"version": "10.2(5)", "image": "nxos64-cs.10.2.5.M.bin", "mode": ""}, r)
r, sent = reading("cisco_asa", {"show version": ASA})
check("ASA: version and the image", r == {"version": "9.16(4)", "image": "asa9-16-4-smp-k8.bin", "mode": ""}, r)
r, sent = reading("cisco_ios", {})
check("a device that prints nothing readable: no version, nothing else asked", r == {"version": "", "image": "", "mode": ""} and sent == ["show version"], (r, sent))

print("== the drivers read it on a simulated device")
TH = db.thresholds_for({"name": "x", "vendor": "cisco", "location": ""})
OPTS = {**db.runtime_options(), "disabled": set()}
class Conn:
    def __init__(self, t): self.t, self.sent = t, []
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def enable(self): pass
    def send_command(self, cmd, **kw):
        self.sent.append(cmd); return self.t.get(cmd, "% Invalid input detected at '^' marker.")
def run(vendor, table, platform="", opts=None, **extra):
    d = {"name": "t", "vendor": vendor, "host": "10.0.0.1", "username": "u", "platform": platform, "password": "p", **extra}
    drv = DRIVERS[vendor](d, TH, {**OPTS, **(opts or {})})
    conn = Conn(table)
    drv.connect = lambda: conn
    return drv, {r.check: r for r in drv.run()}, conn
drv, rows, conn = run("cisco", {"show version": XE_TABLE}, platform="cisco_xe")
check("Cisco IOS XE: the version, image and mode are facts of the run, and the uptime check still reads", drv.facts.get("software") == {"version": "17.09.04a", "image": "packages.conf", "mode": "INSTALL"}
      and rows["uptime"].status == "OK" and rows["uptime"].numeric > 9000, (drv.facts, rows.get("uptime")))
check("...show version was sent once for both", conn.sent.count("show version") == 1, conn.sent)
drv, rows, conn = run("cisco", {"show version": XE_TABLE}, platform="cisco_xe", opts={"disabled": {"cisco:uptime"}})
check("...with the uptime check switched off it is still read (and sent once)", drv.facts.get("software", {}).get("version") == "17.09.04a" and "uptime" not in rows and conn.sent.count("show version") == 1)
drv, rows, conn = run("cisco", {"show version": ASA, "show environment": ""}, platform="cisco_asa")
check("Cisco ASA: version and image; the ASA uptime read from the same text", drv.facts.get("software") == {"version": "9.16(4)", "image": "asa9-16-4-smp-k8.bin", "mode": ""} and rows["uptime"].status == "OK", (drv.facts, rows.get("uptime")))
drv, rows, conn = run("cisco", {"show version": NXOS}, platform="cisco_nxos")
check("Cisco NX-OS: version and image", drv.facts.get("software") == {"version": "10.2(5)", "image": "nxos64-cs.10.2.5.M.bin", "mode": ""}, drv.facts)
drv, rows, conn = run("cisco", {"dir flash:": "100 bytes total (10 bytes free)"}, platform="cisco_ios")
check("a Cisco device whose show version is unreadable: no fact, the other checks run on", "software" not in drv.facts and "flash" in rows, (drv.facts, list(rows)))
drv, rows, conn = run("arista", {"show version | json": json.dumps({"version": "4.28.3M", "modelName": "DCS-7050SX3-48YC8", "memTotal": 8000000, "memFree": 4000000})}, platform="arista_eos")
check("Arista EOS: from show version's JSON (sent once, the memory check shares it)", drv.facts.get("software") == {"version": "4.28.3M", "image": "", "mode": ""} and conn.sent.count("show version | json") == 1 and rows["memory"].status == "OK", (drv.facts, conn.sent))
CX = "Hostname                   : core-cx\nSystem Description         : FL.10.08.1021\nVendor                     : Aruba\nArubaOS-CX Version         : FL.10.08.1021\nUp Time                    : 6 days, 23 hours, 35 minutes\n"
drv, rows, conn = run("hpe", {"show system": CX}, platform="aruba_aoscx")
check("HPE Aruba AOS-CX: 'ArubaOS-CX Version' on show system (the uptime's screen)", drv.facts.get("software", {}).get("version") == "FL.10.08.1021" and conn.sent.count("show system") == 1 and rows["uptime"].status == "OK", (drv.facts, conn.sent))
AOSS = " Status and Counters - General System Information\n\n  System Name        : HP-2930F\n  Software revision  : WC.16.10.0012\n  ROM Version        : WC.16.01.0006\n  Up Time            : 112 days\n  CPU Util (%)       : 2\n  Memory   - Total   : 196,608,000\n             Free    : 100,000,000\n"
drv, rows, conn = run("hpe", {"show system information": AOSS}, platform="aruba_osswitch")
check("HPE Aruba AOS-S: 'Software revision' on show system information, sent once", drv.facts.get("software", {}).get("version") == "WC.16.10.0012" and conn.sent.count("show system information") == 1 and rows["cpu"].status == "OK", (drv.facts, conn.sent))
MT = "                   uptime: 3w2d4h5m6s\n                  version: 7.12 (stable)\n               build-time: Nov/14/2023 10:52:11\n                 cpu-load: 3%\n              free-memory: 200.0MiB\n             total-memory: 256.0MiB\n               board-name: CCR2004-16G-2S+\n"
drv, rows, conn = run("mikrotik", {"/system resource print": MT}, platform="mikrotik_routeros")
check("MikroTik RouterOS: the version from /system resource print, sent once", drv.facts.get("software", {}).get("version") == "7.12 (stable)" and conn.sent.count("/system resource print") == 1 and rows["firmware"].value == "7.12 (stable)", (drv.facts, conn.sent))
JUNOS = "Hostname: mx1\nModel: mx480\nJunos: 21.4R3-S4.8\nJUNOS OS Kernel 64-bit  [20230608.xxx]\n"
drv, rows, conn = run("juniper", {"show version": JUNOS}, platform="juniper_junos")
check("Juniper: 'Junos:' on show version (the one extra command)", drv.facts.get("software", {}).get("version") == "21.4R3-S4.8" and conn.sent.count("show version") == 1, (drv.facts, conn.sent))
drv, rows, conn = run("juniper", {"show version": "Hostname: old\nModel: ex2200\nJUNOS Base OS boot [12.3R3.4]\nJUNOS Base OS Software Suite [12.3R3.4]\n"}, platform="juniper_junos")
check("...and the older 'JUNOS Base OS boot [...]' form", drv.facts.get("software", {}).get("version") == "12.3R3.4", drv.facts)

def api(vendor, **stubs):
    d = {"name": "t", "vendor": vendor, "host": "10.0.0.1", "username": "u", "platform": "", "password": "p", "site": "default"}
    drv = DRIVERS[vendor](d, TH, OPTS)
    for k, v in stubs.items():
        setattr(drv, k, v)
    try:
        drv.run()
    except Exception:
        pass
    return drv.facts.get("software", {}).get("version")
check("Fortinet: system/status version, beside results", api("fortinet", _get=lambda path, whole=False: ({"version": "v7.4.5", "results": {"hostname": "fw"}} if whole else {"hostname": "fw"})
                                                                   if path == "system/status" else {}) == "v7.4.5")
check("Palo Alto: sw-version from system info", api("paloalto", _op=lambda cmd: ET.fromstring("<result><system><sw-version>11.1.4-h7</sw-version><model>PA-440</model></system></result>")) == "11.1.4-h7")
check("OPNsense: product_version", api("opnsense", get=lambda path, **k: {"product_version": "24.7.9", "status": "none"} if "firmware/status" in path else {}) == "24.7.9")
check("Proxmox VE: /version", api("proxmox", data=lambda path, params=None, optional=False: {"version": "8.2.4", "release": "8.2"} if path == "/version" else []) == "8.2.4")
check("TrueNAS: /system/info version", api("truenas", get=lambda path, **k: {"version": "TrueNAS-SCALE-24.04.2", "hostname": "nas"} if path == "/system/info" else {}) == "TrueNAS-SCALE-24.04.2")
check("UniFi Network API: the application's version", api("unifi_network", get=lambda path, params=None, optional=False: {"applicationVersion": "9.0.114"} if path == "/info" else [],
                                                        offset_pages=lambda *a, **k: [], pick_sites=lambda s: []) == "9.0.114")
check("UniFi Protect API: the application's version", api("unifi_protect", get=lambda path, params=None, optional=False: {"applicationVersion": "5.0.40"} if path == "/meta/info" else []) == "5.0.40")
REPORT = {"v": 1, "computer": "PC1", "os": "Microsoft Windows Server 2022 Standard", "build": "20348", "domain": "corp.local", "joined": True, "cpu": 5, "mem_total_mb": 16000, "mem_free_mb": 8000, "uptime_h": 40}
d = {"name": "pc1", "vendor": "windows", "host": "pc1", "username": "", "platform": "agent", "password": ""}
drv = DRIVERS["windows"](d, db.thresholds_for({**d, "location": ""}), OPTS)
drv.fetch = lambda: (REPORT, 0, "agent")
drv.run()
check("Windows: the OS name and build from the report", drv.facts.get("software", {}).get("version") == "Microsoft Windows Server 2022 Standard (build 20348)", drv.facts)
check("a '?' or blank version is never a fact", (Driver({"name": "n"}, {}).found_software("?") or Driver({"name": "n"}, {}).found_software(" ")) is None and not Driver({"name": "n"}, {}).facts)

print("== the record")
check("the database is at version 12 and the devices table has the four columns", db.schema_version() == 12 and db.SCHEMA_VERSION == 12
      and set(db.SOFTWARE_FIELDS) <= {r[1] for r in db.connect().execute("PRAGMA table_info(devices)")} and not (set(db.SOFTWARE_FIELDS) & set(db.DEVICE_FIELDS)))
sw1 = dev("core-sw1", platform="cisco_xe", location="Chicago", tags="core")
check("a device starts with nothing read", db.software_of(sw1) == {"version": "", "image": "", "mode": "", "read_at": ""} and display.software_line(db.software_of(sw1)) == "")
class Probe(Driver):
    VERSION = "17.09.04a"
    def run(self):
        self.found_software(self.VERSION, "packages.conf", "install")
        return [self.result("cpu", "OK", "5%")]
real = runner.DRIVERS["cisco"]; runner.DRIVERS["cisco"] = Probe
base_opts = {**db.runtime_options(), "retries": 0, "tls_sweep": False, "custom": [], "disabled": set()}
res = runner.run_one(sw1, db.thresholds_for(sw1), base_opts)
row = db.get_device(sw1["id"])
check("a check run keeps what the driver read: version, image, mode (upper case) and when, on the device record", db.software_of(row)["version"] == "17.09.04a" and row["sw_image"] == "packages.conf" and row["sw_mode"] == "INSTALL"
      and row["sw_read_at"][:13] == time.strftime("%Y-%m-%d %H") and [r.check for r in res if r.check != "reachability"] == ["cpu"], db.software_of(row))
check("the first reading writes no audit line", audit_lines("core-sw1") == [])
db.save_device({**row, "location": "Boston"})
row = db.get_device(sw1["id"])
check("Edit device keeps it (save_device never touches the four columns)", row["location"] == "Boston" and row["sw_version"] == "17.09.04a" and row["sw_read_at"], db.software_of(row))
Probe.VERSION = "17.12.03"
runner.run_one(row, db.thresholds_for(row), base_opts)
row = db.get_device(sw1["id"])
check("a different version read later replaces it and writes one audit line", row["sw_version"] == "17.12.03" and audit_lines("core-sw1") == ["core-sw1 now runs 17.12.03 (was 17.09.04a)"], audit_lines("core-sw1"))
runner.run_one(row, db.thresholds_for(row), base_opts)
check("the same version read again writes no second line", audit_lines("core-sw1") == ["core-sw1 now runs 17.12.03 (was 17.09.04a)"])
runner.DRIVERS["cisco"] = real
check("set_software without a version or an id writes nothing", db.set_software(row, {"version": ""}) is None and db.set_software({"name": "x"}, {"version": "1"}) is None and db.get_device(sw1["id"])["sw_version"] == "17.12.03")
check("the texts: the tooltip and the device page's row", display.software_line(db.software_of(row)) == f"17.12.03, INSTALL mode, image packages.conf. Read {display.read_on(row['sw_read_at'])}."
      and display.software_line(db.software_of(row), long=True) == f"17.12.03 (INSTALL mode, packages.conf), read {display.read_on(row['sw_read_at'])}", display.software_line(db.software_of(row)))
check("'26 Oct 2026 at 14:02' from a stored time; no leading zero on the day", display.read_on("2026-10-26 14:02:37") == "26 Oct 2026 at 14:02" and display.read_on("2026-11-06 09:05:00") == "6 Nov 2026 at 09:05" and display.read_on("") == "")
mt = dev("rtr-1", vendor="mikrotik", platform="mikrotik_routeros")
db.set_software(mt, {"version": "7.12 (stable)"})
check("a device with a version alone (MikroTik) reads without mode or image", display.software_line(db.software_of(db.get_device(mt["id"]))).startswith("7.12 (stable). Read ")
      and display.software_line(db.software_of(db.get_device(mt["id"])), long=True).startswith("7.12 (stable), read "))
acme = orgs.create("Acme", "acme")
orgs.move_devices([db.get_device(mt["id"])], acme)
with db.within(acme):
    moved = next(x for x in db.list_devices() if x["name"] == "rtr-1")
check("a device moved to another organization keeps what was last read", moved["org"] == acme and moved["sw_version"] == "7.12 (stable)" and moved["sw_read_at"], db.software_of(moved))

print("== the window")
inv = I.InventoryTab(); inv.resize(1200, 500); inv.refresh()
def items():
    out = {}
    def walk(it):
        for i in range(it.childCount()):
            kid = it.child(i); key = kid.data(0, I.ROLE)
            if key and key.startswith("device:"):
                out[inv.payload[key]["name"]] = kid
            walk(kid)
    for i in range(inv.table.topLevelItemCount()):
        top = inv.table.topLevelItem(i); key = top.data(0, I.ROLE)
        if key and key.startswith("device:"):
            out[inv.payload[key]["name"]] = top
        walk(top)
    return out
it = items()
check("a Version column after Platform; the cell shows the version", inv.COLS[inv.VERSION] == "Version" and inv.COLS[inv.VERSION - 1] == "Platform" and inv.COLS[inv.STATUS] == "Status" and inv.COLS[inv.CHECKED] == "Last checked"
      and inv.COLS[inv.ORG] == "Organization" and it["core-sw1"].text(inv.VERSION) == "17.12.03", [inv.COLS[i] for i in (inv.VERSION, inv.STATUS, inv.CHECKED, inv.ORG)])
check("hovering the cell says the mode, the image and when it was read", it["core-sw1"].toolTip(inv.VERSION) == display.software_line(db.software_of(db.get_device(sw1["id"]))) and "INSTALL mode, image packages.conf. Read " in it["core-sw1"].toolTip(inv.VERSION), it["core-sw1"].toolTip(inv.VERSION))
check("the column is shown while a device has one", not inv.table.isColumnHidden(inv.VERSION))
blank = dev("blank-1"); blank2 = dev("blank-2")
inv.search.setText("blank"); inv.refresh()
check("...and hides itself while every device shown has none (like Platform)", inv.table.isColumnHidden(inv.VERSION) and set(items()) == {"blank-1", "blank-2"} and items()["blank-1"].toolTip(inv.VERSION) == "", (inv.table.isColumnHidden(inv.VERSION), set(items())))
inv.search.setText(""); inv.refresh()
check("...and comes back", not inv.table.isColumnHidden(inv.VERSION))
def page_rows(view):
    out = {}
    for i in range(view.info.rowCount()):
        lab, field = view.info.itemAt(i, QFormLayout.ItemRole.LabelRole), view.info.itemAt(i, QFormLayout.ItemRole.FieldRole)
        if lab and field:
            out[lab.widget().text().replace("<span style='color:gray'>", "").replace("</span>", "")] = field.widget().text()
    return out
view = DV.DeviceView(db.get_device(sw1["id"]))
rows_shown = page_rows(view)
check("the device page has a Version row with the long form", rows_shown.get("Version") == display.software_line(db.software_of(db.get_device(sw1["id"])), long=True) and rows_shown["Version"].startswith("17.12.03 (INSTALL mode, packages.conf), read "), rows_shown.get("Version"))
view.close()
view = DV.DeviceView(db.get_device(blank["id"]))
check("a device with nothing read has no Version row", "Version" not in page_rows(view), page_rows(view))
view.close()

print("== the Assistant")
rows = T.list_devices({})["devices"]
by = {r["name"]: r for r in rows}
check("the device list carries each device's software: version, image, mode and when it was read", by["core-sw1"]["software"] == {"version": "17.12.03", "read_at": db.get_device(sw1["id"])["sw_read_at"], "running_image": "packages.conf", "mode": "INSTALL"}, by["core-sw1"].get("software"))
check("a device with nothing read says so, instead of an empty value", by["blank-1"]["software"]["version"] == "" and by["blank-1"]["software"]["note"] == "Not read yet: the checks read it when they next sign in to the device.", by["blank-1"].get("software"))
det = T.device_details({"device": "core-sw1"})
check("device_details carries it too", det["software"]["version"] == "17.12.03" and det["software"]["mode"] == "INSTALL")
check("the tool descriptions and the panel's line say it", "software version as last read by the checks" in T.BY_NAME["list_devices"].description and "software version (and image and mode where they apply)" in T.BY_NAME["device_details"].description
      and "the device list and each device's details (with its software version as last read by the checks)" in T.WHAT_THEY_READ)
check("the Assistant's instructions say the device list has it", "each device with its software version as last read by the checks" in agent.system_prompt(None))
class Scripted(providers.Provider):
    name, label, host, default_model = "claude", "Claude", "api.anthropic.com", "claude-opus-5-5"
    def __init__(self, script):
        super().__init__("k", "claude-opus-5-5", "normal"); self.script = list(script); self.seen = []
    def list_models(self): return [("claude-opus-5-5", "Claude Opus 5.5")]
    def complete(self, system, history, tools, on_text, cancel=None, search=False, on_search=None):
        self.seen.append((system, [dict(m) for m in history]))
        step = self.script.pop(0)
        r = providers.Reply(); r.model = "claude-opus-5-5"; r.tokens_in, r.tokens_out = 100, 10
        if step[0] == "tool":
            r.calls = [(f"toolu_{i}", n, a) for i, (n, a) in enumerate(step[1])]; r.stop = "tool"
            r.native = [{"role": "assistant", "content": [{"type": "tool_use", "id": c[0], "name": c[1], "input": c[2]} for c in r.calls]}]
        else:
            r.text = step[1]; on_text(step[1])
            r.native = [{"role": "assistant", "content": [{"type": "text", "text": r.text}]}]
        return r
    def user_message(self, text): return [{"role": "user", "content": text}]
    def tool_results(self, reply, results): return [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": c[0], "content": t} for c, t in results]}]
events = []
cid = store.create("claude", "claude-opus-5-5")
prov = Scripted([("tool", [("device_details", {"device": "core-sw1"})]), ("text", "core-sw1 runs IOS XE 17.12.03 in INSTALL mode.")])
done = agent.run_turn(cid, None, "What version is core-sw1 on?", {}, lambda k, p: events.append((k, p)), provider=prov)
handed = json.dumps(prov.seen[1][1][-1]["content"])
check("a question about a version is answered from the record, without the Firmware Transfer wizard", done and done["text"].startswith("core-sw1 runs IOS XE 17.12.03")
      and '\\"version\\": \\"17.12.03\\"' in handed and '\\"mode\\": \\"INSTALL\\"' in handed and [p for k, p in events if k == "tool"] == ["Reading core-sw1's details…"], handed[:300])

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
