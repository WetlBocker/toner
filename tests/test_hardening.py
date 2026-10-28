# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Configuration hardening rules in the Scanning section: each rule on sample configs (IOS, IOS XE, NX-OS, ASA), masked backups,
# the rows a scan adds, the rule toggles under Settings > Scanning, the README and the version.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\hard%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import backup, db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtWidgets import QApplication
app = QApplication([])
from core import hardening as H
from core import advisories as A

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

BAD_IOS = """hostname sw1
enable password cisco
username admin password 7 0822455D0A16
ip http server
ip finger
service tcp-small-servers
snmp-server community public RO
snmp-server community secret99 RW 10
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
 ip directed-broadcast
line con 0
 exec-timeout 0 0
line vty 0 4
 transport input telnet ssh
line vty 5 15
 no login
 transport input all
"""
GOOD_IOS = """hostname sw2
service password-encryption
aaa new-model
enable secret 5 $1$abcd
no ip source-route
no ip http server
ip http secure-server
ip ssh version 2
banner motd ^C Authorised users only ^C
logging host 10.0.0.5
ntp server 10.0.0.6
snmp-server community ReadOnlyStr RO 10
line con 0
 exec-timeout 10 0
line vty 0 4
 exec-timeout 10 0
 login authentication default
 transport input ssh
"""
by = lambda text, plat="cisco_ios", off=(): {k: (s, m) for k, s, m in H.findings(text, plat, off)}

print("== every rule on a bad IOS configuration")
f = by(BAD_IOS)
check("every rule answers, in the list's order", [k for k, _s, _m in H.findings(BAD_IOS, "cisco_ios")] == [k for k, *_ in H.RULES] and len(H.RULES) == 13)
check("telnet: FAIL, naming the lines", f["telnet"][0] == "FAIL" and f["telnet"][1] == "line vty 0 4: transport input telnet ssh; line vty 5 15: transport input all", f["telnet"])
check("http server: FAIL", f["http"] == ("FAIL", "ip http server is on"))
check("snmp: a read-write community fails first", f["snmp community"] == ("FAIL", "read-write community: snmp-server community secret99 RW 10"), f["snmp community"])
check("enable password: FAIL", f["enable password"] == ("FAIL", "enable password is set and enable secret is not"))
check("vty login: FAIL naming the lines and aaa", f["vty login"] == ("FAIL", "no login on line vty 0 4, line vty 5 15; aaa new-model is off"), f["vty login"])
check("type 7: WARN with the line", f["type 7"] == ("WARN", "type 7 (reversible) secrets: username admin password 7 0822455D0A16"), f["type 7"])
check("ssh version: WARN", f["ssh version"] == ("WARN", "ip ssh version 2 is not set"))
check("exec-timeout 0 0: WARN naming the line", f["exec-timeout"] == ("WARN", "line con 0: exec-timeout 0 0 never times out"), f["exec-timeout"])
check("banner, logging, ntp: WARN", f["banner"][0] == f["logging"][0] == f["ntp"][0] == "WARN" and f["logging"][1] == "no logging host")
check("services: every one named", f["services"] == ("WARN", "ip source-route is on (the default); service tcp-small-servers is on; ip finger is on; ip directed-broadcast is on"), f["services"])
check("snmp without an access list: WARN counting them", f["snmp acl"] == ("WARN", "1 of 2 without an access list: snmp-server community public RO"), f["snmp acl"])

print("== a hardened one")
g = by(GOOD_IOS)
check("every rule OK, 'not found'", all(v == ("OK", "not found") for v in g.values()), {k: v for k, v in g.items() if v[0] != "OK"})
check("a vty line with no transport input at all is called out", by(GOOD_IOS.replace(" transport input ssh\n", ""))["telnet"] == ("FAIL", "line vty 0 4 has no transport input (the default allows telnet)"))
check("a well-known community fails without RW", by(GOOD_IOS.replace("ReadOnlyStr", "private"))["snmp community"] == ("FAIL", "well-known community: snmp-server community private RO 10"))
check("login local counts as a login; a line without login fails even with aaa", by(GOOD_IOS.replace("login authentication default", "login local"))["vty login"][0] == "OK"
      and by(GOOD_IOS.replace(" login authentication default\n", ""))["vty login"] == ("FAIL", "no login on line vty 0 4"))
check("no aaa new-model alone is the finding", by(GOOD_IOS.replace("aaa new-model\n", ""))["vty login"] == ("FAIL", "aaa new-model is off"))
check("rules switched off are left out", "telnet" not in by(BAD_IOS, off={"telnet", "http"}) and "http" not in by(BAD_IOS, off={"telnet", "http"}) and len(by(BAD_IOS, off={"telnet"})) == 12)

print("== masked backups say what they cannot tell")
masked = backup.clean(GOOD_IOS.replace("ReadOnlyStr RO 10", "public RO 10") + "username admin password 7 0822455D0A16\n", mask=True)
m = by(masked)
check("the mask hides the community and the type digit", "<masked>" in masked and "public" not in masked and " 7 " not in masked)
check("snmp community: N/A, saying the backup masks it", m["snmp community"][0] == "N/A" and m["snmp community"][1] == "1 community; whether one is public, private or read-write cannot be told, the stored backup masks it (Settings > Config backups)", m["snmp community"])
check("...and so is the access-list rule", m["snmp acl"] == ("N/A", "1 community; whether each has an access list cannot be told, the stored backup masks it (Settings > Config backups)"), m["snmp acl"])
check("type 7: N/A once service password-encryption is on", m["type 7"][0] == "N/A" and m["type 7"][1].startswith("service password-encryption is on; whether type 7 secrets remain cannot be told"), m["type 7"])
check("...but its absence is still a finding", by(backup.clean(BAD_IOS, mask=True))["type 7"] == ("WARN", "service password-encryption is off"))
check("the mask hides RW too: two masked communities are N/A, not a finding", by(backup.clean(BAD_IOS, mask=True))["snmp community"][0] == "N/A" and by(backup.clean(BAD_IOS, mask=True))["snmp community"][1].startswith("2 communities;"))

print("== the other platforms")
nx = by("hostname n9k\nfeature telnet\nfeature ssh\nlogging server 10.0.0.5\nntp server 10.0.0.6\nsnmp-server community ro-str group network-operator\n", "cisco_nxos")
check("NX-OS: feature telnet fails; IOS-only rules do not apply", nx["telnet"] == ("FAIL", "feature telnet is on") and nx["ssh version"] == ("N/A", H.NOT_HERE) and nx["type 7"][0] == "N/A"
      and nx["exec-timeout"][0] == nx["services"][0] == "N/A" and nx["logging"][0] == "OK" and nx["vty login"][0] == "OK", nx)
asa = by("hostname fw\nenable password <masked>\ntelnet 10.0.0.0 255.255.255.0 inside\nssh version 2\nlogging host inside 10.0.0.5\nntp server 10.0.0.6\nbanner motd Keep out\n", "cisco_asa")
check("ASA: telnet lines fail; ssh version 2 and logging host are its own forms; enable password does not apply", asa["telnet"] == ("FAIL", "1 telnet line allow it: telnet 10.0.0.0 255.255.255.0 inside")
      and asa["ssh version"][0] == "OK" and asa["logging"][0] == "OK" and asa["enable password"] == ("N/A", H.NOT_HERE) and asa["banner"][0] == "OK", asa)
check("a Cisco device with no platform is read as IOS", by(BAD_IOS, "")["telnet"][0] == "FAIL" and by(BAD_IOS, "cisco_xe")["http"][0] == "FAIL")

print("== the rows a scan adds")
def dev(name, vendor, platform="", version=""):
    d = {"name": name, "vendor": vendor, "host": "10.0.0.9", "platform": platform, "enabled": 1}
    d["id"] = db.save_device(d)
    if version: db.set_software(d, {"version": version})
    return db.find_device(name)
sw1, sw2, fw = dev("sw1", "cisco", "cisco_ios"), dev("sw2", "cisco", "cisco_xe"), dev("edge-fw", "fortinet")
backup.store("sw1", BAD_IOS, mask=False)
db.set_setting("scan_enabled", False)
rows = A.scan(sw1)
check("lookups off: the version row says so, the rule rows follow", rows[0].check == A.SOFTWARE and rows[0].status == "N/A" and rows[0].message == A.OFF and len(rows) == 1 + len(H.RULES), [(r.check, r.status) for r in rows])
rule_rows = {r.check: r for r in rows[1:]}
check("one row per rule, named 'Hardening: <rule>', with the backup's time on a finding", rule_rows["Hardening: Telnet allowed on VTY lines"].status == "FAIL"
      and rule_rows["Hardening: Telnet allowed on VTY lines"].message.startswith("line vty 0 4: transport input telnet ssh; line vty 5 15: transport input all (backup of 20")
      and all(k.startswith("Hardening: ") for k in rule_rows), list(rule_rows)[:3])
check("no backup yet: one N/A row saying so", [(r.check, r.status, r.message) for r in A.scan(sw2)[1:]] == [("Hardening", "N/A", H.NO_BACKUP)])
check("another vendor: one N/A row, no rules yet", [(r.check, r.status, r.message) for r in A.scan(fw)[1:]] == [("Hardening", "N/A", H.NO_RULES)])
db.set_setting("hardening_off", [k for k, *_ in H.RULES])
check("every rule off: no hardening rows at all", len(A.scan(sw1)) == 1)
db.set_setting("hardening_off", ["telnet"])
check("one rule off: its row is missing", "Hardening: Telnet allowed on VTY lines" not in {r.check for r in A.scan(sw1)} and len(A.scan(sw1)) == len(H.RULES))
db.set_setting("hardening_off", []); db.set_setting("scan_enabled", True)
from core import display
check("exports keep a rule row's name as worded", display.check_name("Hardening: No NTP server") == "Hardening: No NTP server")

print("== Settings > Scanning lists the rules")
from ui.settings_pages.scanning import ScanningPage
pg = ScanningPage(); pg.load()
check("every rule, ticked, with its severity", pg.rules.count() == len(H.RULES) and pg.rules.item(0).text() == "Telnet allowed on VTY lines  (FAIL)" and all(pg.rules.item(i).checkState().name == "Checked" for i in range(pg.rules.count())))
from PySide6.QtCore import Qt
pg.rules.item(1).setCheckState(Qt.CheckState.Unchecked); pg.save()
check("unticking saves the key, installation-wide", db.get_setting("hardening_off") == ["http"] and "hardening_off" in db.GLOBAL_ONLY)
pg.load()
check("...and loads back unticked", pg.rules.item(1).checkState() == Qt.CheckState.Unchecked and pg.rules.item(0).checkState() == Qt.CheckState.Checked)
db.set_setting("hardening_off", [])
readme = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "README.md"), encoding="utf-8").read()
check("the README says so", "**Configuration hardening:**" in readme and "Untick rules under Settings > Scanning" in readme)
from core.version import VERSION
check("version 1.11.2", VERSION == "1.11.2")

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
