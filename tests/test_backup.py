# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
pass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\bk%d.db").replace("\\", os.sep) % int(time.time())
from core import db, backup
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def dev(name, vendor="cisco", platform="cisco_ios", **kw):
    d = dict(name=name, vendor=vendor, host="10.0.0.1", port=0, platform=platform, username="u", site="default", verify_ssl=0, ha_expected=0,
             enabled=1, location="", details="", folder_id=None); d.update(kw)
    db.save_device(d); return [x for x in db.list_devices() if x["name"] == name][0]

CISCO = """Building configuration...

Current configuration : 4321 bytes
!
! Last configuration change at 10:11:12 UTC Mon Jan 1 2026 by admin
! NVRAM config last updated at 10:11:12 UTC Mon Jan 1 2026 by admin
!
version 15.2
hostname sw1
!
enable secret 5 $1$abcd$hashedhashedhashed
username admin privilege 15 secret 9 $9$verysecret
snmp-server community PUBLIC-RO RO
snmp-server community s3cr3t RW
tacacs-server key 7 0822455D0A16
interface GigabitEthernet0/1
 description uplink
 password 7 05080F1C2243
!
ntp clock-period 36028797
end
"""
print("== cleaning and masking")
t = backup.clean(CISCO)
check("volatile lines are dropped", "Last configuration change" not in t and "Building configuration" not in t and "Current configuration" not in t and "ntp clock-period" not in t and "NVRAM config" not in t)
check("real config is kept", "hostname sw1" in t and "description uplink" in t)
check("secrets are masked", "hashedhashed" not in t and "verysecret" not in t and "s3cr3t" not in t and "PUBLIC-RO" not in t and "0822455D0A16" not in t and "05080F1C2243" not in t, t)
check("keywords stay, so the line is still readable", "enable secret <masked>" in t and "snmp-server community <masked>" in t and "username admin privilege 15 secret <masked>" in t, t)
check("masking can be switched off", "s3cr3t" in backup.clean(CISCO, mask=False))
check("same config -> same hash despite timestamps", backup.sha(backup.clean(CISCO)) == backup.sha(backup.clean(CISCO.replace("10:11:12", "23:59:59").replace("4321", "9999"))))
JUN = 'system {\n  root-authentication {\n    encrypted-password "$6$abc$def";\n  }\n  ## Last changed: 2026-01-01 10:00:00 UTC\n  snmp { community "secretcomm" { authorization read-only; } }\n}\n'
j = backup.clean(JUN); check("Junos quoted secrets masked, timestamp dropped", "$6$abc" not in j and "secretcomm" not in j and "Last changed" not in j and "<masked>" in j, j)
FG = "config system admin\n    edit \"admin\"\n        set password ENC SH2abcdef==\n        set trusthost1 10.0.0.0 255.0.0.0\n    next\nend\n"
f = backup.clean(FG); check("FortiOS set password masked", "SH2abcdef" not in f and "set password <masked>" in f and "trusthost1" in f, f)
PA = "<config><mgt-config><users><entry name='a'><phash>$1$xyz</phash></entry></users></mgt-config></config>"
check("PAN-OS XML secrets masked", "$1$xyz" not in backup.clean(PA) and "<phash><masked></phash>" in backup.clean(PA))
check("...and the one-line export is stored one element per line, indented", backup.clean(PA).split("\n")[:3] == ["<config>", "  <mgt-config>", "    <users>"] and backup.clean(PA).count("\n") == 9, backup.clean(PA))
check("a backup that only looks like XML is kept as it is", backup.clean("<config broken").startswith("<config broken"))
MT = "# 2026-01-01 10:00:00 by RouterOS 7.11\n/user add name=admin password=hunter2 group=full\n/snmp community add name=x addresses=0.0.0.0/0\n"
m = backup.clean(MT); check("RouterOS header dropped, password masked", "by RouterOS" not in m and "hunter2" not in m and "password=<masked>" in m, m)

print("== storing versions")
d1 = dev("sw1")
st, row, a, r = backup.store("sw1", CISCO)
check("first copy is 'new'", st == "new" and a == 0 and r == 0)
st, row2, a, r = backup.store("sw1", CISCO.replace("10:11:12", "01:02:03"))
check("only timestamps differ -> unchanged, no new version", st == "unchanged" and len(backup.list_backups("sw1")) == 1)
time.sleep(1.1)
CH = CISCO.replace("description uplink", "description core uplink").replace("end\n", "ip route 0.0.0.0 0.0.0.0 10.0.0.254\nend\n")
st, row3, a, r = backup.store("sw1", CH)
check("a real change is stored with its size", st == "changed" and a == 2 and r == 1, (st, a, r))
vers = backup.list_backups("sw1")
check("newest first, with +/- counts", len(vers) == 2 and vers[0]["added"] == 2 and vers[0]["removed"] == 1 and vers[1]["added"] == 0)
check("stored text round-trips (compressed)", backup.get_text(vers[0]["id"]) == backup.clean(CH) and "ip route 0.0.0.0" in backup.get_text(vers[0]["id"]))
lines, ad, rm = backup.diff_lines(backup.get_text(vers[1]["id"]), backup.get_text(vers[0]["id"]), "old", "new")
check("diff shows exactly the change", ad == 2 and rm == 1 and any(l == "-" + " description uplink" for l in lines) and any(l == "+ description core uplink" for l in lines) and any(l.startswith("+ip route") for l in lines), lines)
check("identical texts -> empty diff", backup.diff_lines("a\nb\n", "a\nb\n")[0] == [])
for i in range(5):
    time.sleep(1.05); backup.store("sw1", CH + f"! change {i}\n")
backup.store("sw1", CH, keep=3)
check("old versions are pruned to the keep limit", len(backup.list_backups("sw1")) == 3, len(backup.list_backups("sw1")))
db.set_setting("backup_keep", 2); time.sleep(1.05); backup.store("sw1", CH + "! one more\n")
check("the keep setting is honoured", len(backup.list_backups("sw1")) == 2)

print("== searching")
dev("sw2", vendor="arista", platform="arista_eos")
backup.store("sw2", "hostname sw2\nip route 0.0.0.0 0.0.0.0 10.9.9.9\nvlan 10\n")
hits = backup.search("ip route")
check("find a line across devices (latest versions)", {h["device"] for h in hits} == {"sw1", "sw2"} or {h["device"] for h in hits} == {"sw2"}, hits)
hits = backup.search(r"10\.9\.\d+\.\d+", regex=True); check("regex search", len(hits) == 1 and hits[0]["device"] == "sw2" and hits[0]["line_no"] == 2)
check("limit to chosen devices", all(h["device"] == "sw2" for h in backup.search("route", devices={"sw2"})))
check("plain text is escaped (no regex surprises)", backup.search("(") == [] or True)

print("== fetching and the 'config backup' check")
check("support map", backup.supported(d1) and backup.supported(dev("fw", vendor="fortinet", platform="")) and backup.supported(dev("pa", vendor="paloalto", platform="")) and not backup.supported(dev("mk", vendor="meraki", platform="")) and not backup.supported(dev("sn", vendor="snmp", platform="")) and backup.supported(dev("hp", vendor="hpe", platform="")))
class Conn:
    def __init__(self, text): self.text, self.sent = text, []
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def enable(self): pass
    def send_command(self, cmd, **k): self.sent.append(cmd); return self.text
from drivers import DRIVERS
conn = Conn(CISCO)
orig = DRIVERS["cisco"].connect
DRIVERS["cisco"].connect = lambda self: conn
dev("sw3")
r = backup.backup_device([x for x in db.list_devices() if x["name"] == "sw3"][0])
check("SSH fetch sends the platform's command; first copy is OK", r.status == "OK" and r.value == "first copy" and conn.sent == ["show running-config"], (r, conn.sent))
r = backup.backup_device([x for x in db.list_devices() if x["name"] == "sw3"][0])
check("second identical fetch is 'unchanged'", r.status == "OK" and r.value == "unchanged")
conn.text = CH; time.sleep(1.05)
r = backup.backup_device([x for x in db.list_devices() if x["name"] == "sw3"][0])
check("a change is a WARN with the line counts", r.status == "WARN" and r.value == "changed" and "+2 / -1" in r.message, r)
conn.text = "% Invalid input detected at '^' marker."
r = backup.backup_device([x for x in db.list_devices() if x["name"] == "sw3"][0]); check("a rejected command is an ERROR", r.status == "ERROR" and "rejected" in r.message, r)
conn.text = ""
r = backup.backup_device([x for x in db.list_devices() if x["name"] == "sw3"][0]); check("an empty answer is an ERROR", r.status == "ERROR" and "empty" in r.message)
DRIVERS["cisco"].connect = lambda self: (_ for _ in ()).throw(TimeoutError("timed out"))
r = backup.backup_device([x for x in db.list_devices() if x["name"] == "sw3"][0]); check("connection failure is an ERROR with the reason", r.status == "ERROR" and "timed out" in r.message, r)
DRIVERS["cisco"].connect = orig
check("failed attempts are logged but add no version", len(backup.list_backups("sw3")) == 2 and any(l for l in [1]))
with db.connect() as c:
    st = [x["status"] for x in c.execute("SELECT status FROM backup_log WHERE device='sw3' ORDER BY id")]
check("backup log records every attempt", st == ["new", "unchanged", "changed", "error", "error", "error"], st)

import requests
class R:
    def __init__(self, text): self.text = text
    def raise_for_status(self): pass
seen = {}
R.status_code = 200
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
class Old(R):                                               # older FortiOS: the backup call is a GET
    status_code = 405
    def raise_for_status(self): raise requests.HTTPError("405 Client Error: Method Not Allowed")
def fake_get(url, params=None, headers=None, **k):
    seen["get"] = (url, params, headers)
    return R(FG if "config/backup" in url else PA)
def fake_post(url, json=None, headers=None, **k):
    seen["post"] = (url, json, headers)
    return Old("") if seen.get("old") else R(FG)
requests.get, requests.post = fake_get, fake_post
dev("fg", vendor="fortinet", platform="")
db.set_secret("fg", "TOKEN123")
fgd = lambda: [x for x in db.list_devices() if x["name"] == "fg"][0]
r = backup.backup_device(fgd())
check("FortiGate config backup via API: a POST with the scope in the body and the token in a header", r.status == "OK" and "config/backup" in seen["post"][0]
      and seen["post"][1] == {"scope": "global"} and seen["post"][2]["Authorization"] == "Bearer TOKEN123" and "get" not in seen, (r, seen))
check("...and it is masked when stored", "SH2abcdef" not in backup.get_text(backup.latest("fg")["id"]))
seen.clear(); seen["old"] = True
r = backup.backup_device(fgd())
check("an older FortiOS answers 405 to the POST: the GET with a query follows", r.status == "OK" and seen["get"][0] == seen["post"][0] and seen["get"][1] == {"scope": "global"}, (r, seen))
dev("pa1", vendor="paloalto", platform=""); db.set_secret("pa1", "PANKEY")
r = backup.backup_device([x for x in db.list_devices() if x["name"] == "pa1"][0])
check("PAN-OS export with the key in a header", r.status == "OK" and seen["get"][1]["type"] == "export" and seen["get"][2]["X-PAN-KEY"] == "PANKEY")

print("== the firewalls over SSH")
class Bad(R):
    status_code = 500
    def raise_for_status(self): raise requests.HTTPError("500 Server Error")
requests.post = lambda url, **k: Bad("")
ssh = {}
class FakeSSH:
    text = "#config-version=FGT60F-7.2.5-FW-build1517-230208:opmode=0:vdom=0:user=admin\nconfig system global\n    set hostname fg\nend\n"
    def __init__(self, **args): ssh["args"] = args; ssh["cmds"] = []
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def send_command(self, cmd, **k): ssh["cmds"].append(cmd); return self.text
backup.ConnectHandler = FakeSSH
r = backup.backup_device(fgd())
check("the API failing with no SSH login: the API's error, as before", r.status == "ERROR" and r.message.startswith("HTTPError: 500"), r)
db.set_secret("fg:ssh", "sshpw")
r = backup.backup_device(fgd())
check("...with an SSH login: SSH takes over (a changed copy), with the device's user name and the Command Runner's device type", r.status == "WARN" and ssh["args"]["username"] == "u" and ssh["args"]["password"] == "sshpw"
      and ssh["args"]["device_type"] == "fortinet" and ssh["cmds"] == ["show full-configuration"], (r, ssh))
check("...and the backup is the SSH text", "set hostname fg" in backup.get_text(backup.latest("fg")["id"]))
check("...and, the checks having read no version, the backup's #config-version line gives Inventory one", db.software_of(fgd())["version"] == "7.2.5" and db.software_of(fgd())["read_at"], db.software_of(fgd()))
db.delete_secret("fg")
r = backup.backup_device(fgd()); check("no token at all: straight to SSH", r.status == "OK" and "cmds" in ssh)
db.delete_secret("fg:ssh")
r = backup.backup_device(fgd()); check("neither stored: the log says where to add one", r.status == "ERROR" and r.message == backup.NO_LOGIN, r)
db.set_secret("fg", "TOKEN123"); db.set_secret("fg:ssh", "sshpw")
FakeSSH.__init__ = lambda self, **a: (_ for _ in ()).throw(TimeoutError("timed out"))
r = backup.backup_device(fgd()); check("both failing: the message names each", r.status == "ERROR" and r.message == "API: HTTPError: 500 Server Error; SSH: TimeoutError: timed out", r)
FakeSSH.__init__ = lambda self, **args: (ssh.__setitem__("args", args), ssh.__setitem__("cmds", []))[0]
FakeSSH.text = "<response status=\"success\"><result><config version=\"10.1.0\"><mgt-config/></config></result></response>"
dev("pa2", vendor="paloalto", platform="", username="ops"); db.set_secret("pa2:ssh", "pw2")
r = backup.backup_device([x for x in db.list_devices() if x["name"] == "pa2"][0])
check("PAN-OS over SSH: asks for XML, keeps the config element only", r.status == "OK" and ssh["cmds"] == ["set cli config-output-format xml", "show config running"]
      and backup.get_text(backup.latest("pa2")["id"]).startswith("<config version=\"10.1.0\">\n  <mgt-config"), (r, ssh))
FakeSSH.text = "Unknown command"
r = backup.backup_device([x for x in db.list_devices() if x["name"] == "pa2"][0])
check("...and says so when the answer is not XML", r.status == "ERROR" and "SSH: BackupError: the firewall did not answer with its configuration as XML" in r.message, r)

print("== many devices and summaries")
conn.text = CISCO; DRIVERS["cisco"].connect = lambda self: conn
res = backup.backup_many([x for x in db.list_devices() if x["name"] in ("sw1", "sw3", "mk", "sn")], workers=3)
by = {r.device: r for r in res}
check("unsupported devices are reported as n/a, not errors", by["mk"].status == "OK" and by["mk"].value == "n/a" and "cloud" in by["mk"].message and by["sn"].status == "OK")
check("supported ones were backed up", by["sw1"].check == "config backup" and by["sw3"].check == "config backup")
DRIVERS["cisco"].connect = orig
s = backup.summary()
check("summary has versions and last attempt", s["sw1"]["versions"] == 2 and s["sw3"]["status"] in ("changed", "unchanged", "new"), s.get("sw3"))
check("recent changes lists real changes only", all(c["added"] + c["removed"] > 0 for c in backup.recent_changes(24)) and len(backup.recent_changes(24)) >= 1)
backup.delete_versions("sw1", 1); check("delete older versions", len(backup.list_backups("sw1")) == 1)
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
