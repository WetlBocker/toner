# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Configuration hardening rules in the Scanning section: each rule on sample configs (IOS, IOS XE, NX-OS, ASA, a Catalyst
# switch, FortiOS, PAN-OS), masked backups, the rows a scan adds, the rule toggles under Settings > Scanning, the README and the version.
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
service timestamps log datetime msec
service password-encryption
aaa new-model
aaa local authentication attempts max-fail 5
aaa accounting exec default start-stop group tacacs+
enable secret 9 $9$abcd
no ip source-route
no ip http server
ip http secure-server
ip ssh version 2
no vstack
banner motd ^C Authorised users only ^C
logging host 10.0.0.5
ntp authenticate
ntp authentication-key 1 md5 secret
ntp trusted-key 1
ntp server 10.0.0.6 key 1
snmp-server community ReadOnlyStr RO 10
line con 0
 exec-timeout 10 0
line vty 0 4
 access-class 10 in
 exec-timeout 10 0
 login authentication default
 transport input ssh
"""
BAD_SWITCH = """hostname sw3
vtp mode server
interface Vlan1
 ip address 10.0.0.2 255.255.255.0
interface Vlan10
 ip address 10.0.10.1 255.255.255.0
 no ip redirects
 no ip proxy-arp
 standby 1 ip 10.0.10.254
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
interface GigabitEthernet1/0/2
 switchport mode access
 switchport port-security
 spanning-tree bpduguard enable
interface GigabitEthernet1/0/47
 switchport mode trunk
 switchport trunk native vlan 999
interface GigabitEthernet1/0/48
 switchport mode trunk
router ospf 1
 network 10.0.0.0 0.0.0.255 area 0
router bgp 65000
 neighbor 10.0.0.9 remote-as 65001
 neighbor 10.0.0.10 remote-as 65002
 neighbor 10.0.0.10 password 7 0822455D0A16
logging trap debugging
"""
NOT_SWITCH = {"dhcp snooping", "arp inspection", "bpdu guard", "port security", "vtp", "vlan 1"}
ASA_ONLY = {"acl any", "threat detection"}
by = lambda text, plat="cisco_ios", off=(), vendor="cisco": {k: (s, m) for k, s, m in H.findings(text, plat, off, vendor)}

print("== every rule on a bad IOS configuration")
f = by(BAD_IOS)
check("every Cisco rule answers, in the list's order", [k for k, _s, _m in H.findings(BAD_IOS, "cisco_ios")] == [k for k, *_ in H.CISCO] and len(H.CISCO) == 32)
check("telnet: FAIL, naming the lines", f["telnet"][0] == "FAIL" and f["telnet"][1] == "line vty 0 4: transport input telnet ssh; line vty 5 15: transport input all", f["telnet"])
check("http server: FAIL", f["http"] == ("FAIL", "ip http server is on"))
check("snmp: a read-write community fails first", f["snmp community"] == ("FAIL", "read-write community: snmp-server community <masked>"), f["snmp community"])
check("enable password: FAIL", f["enable password"] == ("FAIL", "enable password is set and enable secret is not"))
check("vty login: FAIL naming the lines and aaa", f["vty login"] == ("FAIL", "no login on line vty 0 4, line vty 5 15; aaa new-model is off"), f["vty login"])
check("type 7: WARN with the line", f["type 7"] == ("WARN", "type 7 (reversible) secrets: username admin password <masked>"), f["type 7"])
check("ssh version: WARN", f["ssh version"] == ("WARN", "ip ssh version 2 is not set"))
check("exec-timeout 0 0: WARN naming the line", f["exec-timeout"] == ("WARN", "line con 0: exec-timeout 0 0 never times out"), f["exec-timeout"])
check("banner, logging, ntp: WARN", f["banner"][0] == f["logging"][0] == f["ntp"][0] == "WARN" and f["logging"][1] == "no logging host")
check("services: every one named", f["services"] == ("WARN", "ip source-route is on (the default); service tcp-small-servers is on; ip finger is on; ip directed-broadcast is on"), f["services"])
check("snmp without an access list: WARN counting them", f["snmp acl"] == ("WARN", "1 of 2 without an access list: snmp-server community <masked>"), f["snmp acl"])
check("access-class: WARN naming the lines", f["access-class"] == ("WARN", "no access-class on line vty 0 4, line vty 5 15"), f["access-class"])
check("lockout, accounting, timestamps, smart install: WARN", f["lockout"] == ("WARN", "aaa local authentication attempts max-fail is not set") and f["accounting"] == ("WARN", "no aaa accounting")
      and f["log timestamps"] == ("WARN", "service timestamps log datetime is not set") and f["smart install"] == ("WARN", "no vstack is not set (Smart Install is on by default on IOS switches)"))
check("snmp v2c: WARN counting communities and v3 users", f["snmp v2c"] == ("WARN", "2 communities (version 1 or 2c); 0 SNMPv3 users"), f["snmp v2c"])
check("icmp redirects: the routed interface, twice", f["icmp redirects"] == ("WARN", "1 of 1 routed interfaces without no ip redirects: interface GigabitEthernet0/1; "
      "1 of 1 routed interfaces without no ip proxy-arp: interface GigabitEthernet0/1"), f["icmp redirects"])
check("no routing protocols, no ntp, no type 5, no debug logging: OK", f["routing auth"][0] == f["ntp auth"][0] == f["type 5"][0] == f["log debug"][0] == "OK")
check("switch rules on a router config: N/A", all(f[k] == ("N/A", H.NOT_SWITCH) for k in NOT_SWITCH) and all(f[k] == ("N/A", H.NOT_HERE) for k in ASA_ONLY))

print("== a hardened one")
g = by(GOOD_IOS)
check("every rule OK, 'not found', but for SNMP v2c and the rules that do not apply", all(v == ("OK", "not found") for k, v in g.items() if k != "snmp v2c" and v[0] != "N/A")
      and {k for k, v in g.items() if v[0] == "N/A"} == NOT_SWITCH | ASA_ONLY, {k: v for k, v in g.items() if v[0] != "OK"})
check("snmp v2c still warns, counting", g["snmp v2c"] == ("WARN", "1 community (version 1 or 2c); 0 SNMPv3 users"))
check("a vty line with no transport input at all is called out", by(GOOD_IOS.replace(" transport input ssh\n", ""))["telnet"] == ("FAIL", "line vty 0 4 has no transport input (the default allows telnet)"))
check("a well-known community fails without RW", by(GOOD_IOS.replace("ReadOnlyStr", "private"))["snmp community"] == ("FAIL", "well-known community: snmp-server community <masked>"))
check("login local counts as a login; a line without login fails even with aaa", by(GOOD_IOS.replace("login authentication default", "login local"))["vty login"][0] == "OK"
      and by(GOOD_IOS.replace(" login authentication default\n", ""))["vty login"] == ("FAIL", "no login on line vty 0 4"))
check("no aaa new-model alone is the finding", by(GOOD_IOS.replace("aaa new-model\n", ""))["vty login"] == ("FAIL", "aaa new-model is off"))
check("type 5: the line", by(GOOD_IOS.replace("secret 9 $9$", "secret 5 $1$"))["type 5"] == ("WARN", "type 5 (MD5) secrets: enable secret <masked>"))
check("no finding quotes a secret: the lines are masked as a stored backup is (Ruling 17)",
      not any(v in m for _k, _s, m in H.findings(BAD_IOS, "cisco_ios") + H.findings(GOOD_IOS.replace("secret 9 $9$", "secret 5 $1$"), "cisco_ios")
              for v in ("0822455D0A16", "secret99", "$1$abcd")))
check("ntp without trusted-key", by(GOOD_IOS.replace("ntp trusted-key 1\n", ""))["ntp auth"] == ("WARN", "ntp trusted-key not set"))
check("logging trap debugging", by(GOOD_IOS + "logging trap debugging\n")["log debug"] == ("WARN", "logging trap debugging (level 7)"))
check("rules switched off are left out", "telnet" not in by(BAD_IOS, off={"telnet", "http"}) and "http" not in by(BAD_IOS, off={"telnet", "http"}) and len(by(BAD_IOS, off={"telnet"})) == len(H.CISCO) - 1)

print("== a Catalyst switch")
s = by(BAD_SWITCH, "cisco_xe")
check("dhcp snooping and arp inspection off", s["dhcp snooping"] == ("WARN", "ip dhcp snooping is not set") and s["arp inspection"] == ("WARN", "ip arp inspection vlan is not set"))
check("bpdu guard and port security: the access port missing them", s["bpdu guard"] == ("WARN", "1 of 2 access ports without bpduguard: interface GigabitEthernet1/0/1")
      and s["port security"] == ("WARN", "1 of 2 access ports without port security: interface GigabitEthernet1/0/1"), (s["bpdu guard"], s["port security"]))
check("vtp server", s["vtp"] == ("WARN", "vtp mode transparent or off is not set (server is the default)"))
check("vlan 1: the trunk and the SVI", s["vlan 1"] == ("WARN", "1 of 2 trunks with native VLAN 1: interface GigabitEthernet1/0/48; interface Vlan1 has an address"), s["vlan 1"])
check("routing: the BGP neighbor, OSPF and HSRP", s["routing auth"] == ("WARN", "router bgp 65000: 1 neighbor without a password; router ospf 1: no authentication; interface Vlan10: standby 1 without authentication"), s["routing auth"])
check("icmp redirects: Vlan1 only", s["icmp redirects"] == ("WARN", "1 of 2 routed interfaces without no ip redirects: interface Vlan1; 1 of 2 routed interfaces without no ip proxy-arp: interface Vlan1"), s["icmp redirects"])
check("debug logging", s["log debug"] == ("WARN", "logging trap debugging (level 7)"))
hard_sw = BAD_SWITCH.replace("vtp mode server", "vtp mode transparent\nip dhcp snooping\nip arp inspection vlan 10\nspanning-tree portfast bpduguard default").replace(
    "interface GigabitEthernet1/0/48\n switchport mode trunk\n", "interface GigabitEthernet1/0/48\n switchport mode trunk\n switchport trunk native vlan 999\n").replace(
    "interface Vlan1\n ip address 10.0.0.2 255.255.255.0\n", "").replace(" switchport access vlan 10\n", " switchport access vlan 10\n switchport port-security\n").replace(
    " network 10.0.0.0 0.0.0.255 area 0\n", " network 10.0.0.0 0.0.0.255 area 0\n area 0 authentication message-digest\n").replace(
    " neighbor 10.0.0.9 remote-as 65001\n", " neighbor 10.0.0.9 remote-as 65001\n neighbor 10.0.0.9 password 7 0822455D0A16\n").replace(
    " standby 1 ip 10.0.10.254\n", " standby 1 ip 10.0.10.254\n standby 1 authentication md5 key-string x\n")
h = by(hard_sw, "cisco_xe")
check("...and all of them OK once set", all(h[k][0] == "OK" for k in NOT_SWITCH | {"routing auth"}), {k: h[k] for k in NOT_SWITCH | {"routing auth"} if h[k][0] != "OK"})
check("a peer-group password covers its members", by("router bgp 1\n neighbor PG peer-group\n neighbor PG password x\n neighbor 10.0.0.1 remote-as 2\n neighbor 10.0.0.1 peer-group PG\n")["routing auth"][0] == "OK")

print("== masked backups say what they cannot tell")
masked = backup.clean(GOOD_IOS.replace("ReadOnlyStr RO 10", "public RO 10") + "username admin password 7 0822455D0A16\n", mask=True)
m = by(masked)
check("the mask hides the community and the type digit", "<masked>" in masked and "public" not in masked and " 7 " not in masked)
check("snmp community: N/A, saying the backup masks it", m["snmp community"][0] == "N/A" and m["snmp community"][1] == "1 community; whether one is public, private or read-write cannot be told, the stored backup masks it (Settings > Config backups)", m["snmp community"])
check("...and so is the access-list rule", m["snmp acl"] == ("N/A", "1 community; whether each has an access list cannot be told, the stored backup masks it (Settings > Config backups)"), m["snmp acl"])
check("type 7: N/A once service password-encryption is on", m["type 7"][0] == "N/A" and m["type 7"][1].startswith("service password-encryption is on; whether type 7 secrets remain cannot be told"), m["type 7"])
check("type 5: N/A, the type digit is masked", m["type 5"] == ("N/A", f"whether type 5 secrets remain cannot be told, {H.MASKED}"), m["type 5"])
check("...but its absence is still a finding", by(backup.clean(BAD_IOS, mask=True))["type 7"] == ("WARN", "service password-encryption is off"))
check("the mask hides RW too: two masked communities are N/A, not a finding", by(backup.clean(BAD_IOS, mask=True))["snmp community"][0] == "N/A" and by(backup.clean(BAD_IOS, mask=True))["snmp community"][1].startswith("2 communities;"))

print("== the other Cisco platforms")
nx = by("hostname n9k\nfeature telnet\nfeature ssh\nlogging server 10.0.0.5\nntp server 10.0.0.6\nsnmp-server community ro-str group network-operator\n", "cisco_nxos")
check("NX-OS: feature telnet fails; IOS-only rules do not apply", nx["telnet"] == ("FAIL", "feature telnet is on") and nx["ssh version"] == ("N/A", H.NOT_HERE) and nx["type 7"][0] == "N/A"
      and nx["exec-timeout"][0] == nx["services"][0] == nx["lockout"][0] == nx["smart install"][0] == "N/A" and nx["logging"][0] == "OK" and nx["vty login"][0] == "OK"
      and nx["dhcp snooping"] == ("N/A", H.NOT_SWITCH), nx)
ASA_CFG = """hostname fw
enable password <masked>
telnet 10.0.0.0 255.255.255.0 inside
ssh 0.0.0.0 0.0.0.0 outside
ssh version 2
logging host inside 10.0.0.5
logging trap debugging
ntp server 10.0.0.6
banner motd Keep out
access-list outside_in extended permit ip any any
no threat-detection basic-threat
console timeout 0
"""
asa = by(ASA_CFG, "cisco_asa")
check("ASA: telnet lines fail; ssh version 2 and logging host are its own forms; enable password does not apply", asa["telnet"] == ("FAIL", "1 telnet line allow it: telnet 10.0.0.0 255.255.255.0 inside")
      and asa["ssh version"][0] == "OK" and asa["logging"][0] == "OK" and asa["enable password"] == ("N/A", H.NOT_HERE) and asa["banner"][0] == "OK", asa)
check("ASA: permit ip any any fails; management from anywhere, threat detection, console timeout, debug logging, timestamps warn",
      asa["acl any"] == ("FAIL", "1 line permits everything: access-list outside_in extended permit ip any any") and asa["access-class"] == ("WARN", "management from anywhere: ssh 0.0.0.0 0.0.0.0 outside")
      and asa["threat detection"] == ("WARN", "threat-detection basic-threat is off") and asa["exec-timeout"] == ("WARN", "console timeout 0 never times out")
      and asa["log debug"] == ("WARN", "logging trap debugging (level 7)") and asa["log timestamps"] == ("WARN", "logging timestamp is not set") and asa["dhcp snooping"] == ("N/A", H.NOT_HERE), asa)
check("ASA: console timeout 15 and no console line read differently", by(ASA_CFG.replace("console timeout 0", "console timeout 15"), "cisco_asa")["exec-timeout"][0] == "OK"
      and by(ASA_CFG.replace("console timeout 0\n", ""), "cisco_asa")["exec-timeout"] == ("WARN", "console timeout 0 (the default) never times out"))
check("a Cisco device with no platform is read as IOS", by(BAD_IOS, "")["telnet"][0] == "FAIL" and by(BAD_IOS, "cisco_xe")["http"][0] == "FAIL")

print("== FortiGate")
BAD_FG = """#config-version=FGT60F-7.2.5-FW-build1517-230208:opmode=0:vdom=0:user=admin
config system global
    set admintimeout 30
    set admin-telnet enable
    set strong-crypto disable
    set admin-https-ssl-versions tlsv1-1 tlsv1-2
end
config system password-policy
    set minimum-length 8
end
config log eventfilter
    set event disable
    set user disable
end
config user ldap
    edit "corp"
        set server "10.0.0.7"
    next
    edit "corp2"
        set secure starttls
    next
end
config system snmp user
    edit "mon"
    next
end
config system interface
    edit "wan1"
        set allowaccess ping https ssh http
        set role wan
    next
    edit "internal"
        set allowaccess ping https ssh telnet
        set role lan
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
    next
    edit "ops"
        set trusthost1 10.0.0.0 255.255.255.0
    next
end
config system snmp community
    edit 1
        set name <masked>
        config hosts
            edit 1
                set ip 10.0.0.5 255.255.255.255
            next
        end
    next
    edit 2
        set name "public"
    next
end
config log syslogd setting
    set status enable
end
config system ntp
    set ntpsync disable
    set type custom
    config ntpserver
        edit 1
            set server "10.0.0.6"
        next
    end
end
config firewall policy
    edit 1
        set name "allow-all"
        set srcintf "wan1"
        set dstintf "internal"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
    edit 2
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
end
"""
GOOD_FG = """#config-version=FGT60F-7.2.5-FW-build1517-230208:opmode=0:vdom=0:user=admin
config system global
    set ssl-static-key-ciphers disable
    set private-data-encryption enable
    set admin-lockout-duration 900
    set pre-login-banner enable
    set admin-https-ssl-versions tlsv1-2 tlsv1-3
end
config log eventfilter
    set event enable
end
config user ldap
    edit "corp"
        set secure ldaps
    next
end
config system ntp
    set type custom
    config ntpserver
        edit 1
            set server "10.0.0.6"
            set authentication enable
        next
        edit 2
            set server "10.0.0.7"
            set authentication enable
        next
    end
end
config system auto-install
    set auto-install-config disable
    set auto-install-image disable
end
config system interface
    edit "wan1"
        set allowaccess ping
        set role wan
    next
    edit "internal"
        set allowaccess ping https ssh
    next
end
config system admin
    edit "netops"
        set trusthost1 10.0.0.0 255.255.255.0
    next
end
config system snmp user
    edit "mon"
        set security-level auth-priv
    next
end
config log syslogd setting
    set status enable
    set mode reliable
end
config system password-policy
    set status enable
    set minimum-length 15
    set min-upper-case-letter 1
    set min-lower-case-letter 1
    set min-number 1
    set min-non-alphanumeric 1
end
config firewall DoS-policy
    edit 1
        set interface "wan1"
    next
end
config firewall policy
    edit 1
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
end
"""
fg = by(BAD_FG, "", vendor="fortinet")
from core import hardening_fortinet as FG
check("every FortiGate rule answers, in order; all 25 find something", [k for k, *_ in H.findings(BAD_FG, "", vendor="fortinet")] == [k for k, *_ in FG.RULES] and len(FG.RULES) == 25
      and all(v[0] in ("FAIL", "WARN") for v in fg.values()), {k: v for k, v in fg.items() if v[0] not in ("FAIL", "WARN")})
check("admin access on the WAN interface: FAIL with the line", fg["fg wan admin"] == ("FAIL", "wan1: set allowaccess ping https ssh http"), fg["fg wan admin"])
check("telnet or http: every interface and the global switch", fg["fg telnet http"] == ("FAIL", "wan1: set allowaccess ping https ssh http; internal: set allowaccess ping https ssh telnet; set admin-telnet enable"), fg["fg telnet http"])
check("the allow-all policy from wan1, not the one from inside", fg["fg policy any"] == ("FAIL", "policy 1 allow-all: accept all from wan1"), fg["fg policy any"])
check("admins without trusted hosts, the default account, the timeout", fg["fg trusthost"] == ("WARN", "1 of 2 admins without trusted hosts: admin") and fg["fg default admin"] == ("WARN", 'account "admin" exists')
      and fg["fg idle timeout"] == ("WARN", "set admintimeout 30"), (fg["fg trusthost"], fg["fg idle timeout"]))
check("weak TLS: both parts", fg["fg weak tls"] == ("WARN", "set strong-crypto disable; ssl-static-key-ciphers is not disabled (enable is the default)"), fg["fg weak tls"])
check("snmp v2c counted (its name is masked), syslog udp, ntp off", fg["fg snmp v2c"] == ("WARN", "2 SNMP v1/v2c communities enabled; 1 SNMPv3 user") and fg["fg syslog"] == ("WARN", "set mode udp (unencrypted)")
      and fg["fg ntp"] == ("WARN", "set ntpsync disable"), (fg["fg snmp v2c"], fg["fg syslog"]))
check("defaults read as the default: password policy, private data, auto-install, DoS", fg["fg password policy"] == ("WARN", "config system password-policy: status is not enable")
      and fg["fg private data"] == ("WARN", "set private-data-encryption enable is not set") and fg["fg auto install"] == ("WARN", "auto-install-config and auto-install-image not set to disable")
      and fg["fg dos"] == ("WARN", "no DoS policy"), fg["fg auto install"])
M = lambda t: by(t, "", vendor="fortinet")
check("lockout: default duration 60 is short", fg["fg lockout"] == ("WARN", "admin-lockout-threshold 3, admin-lockout-duration 60: set them to 3 and 900 under config system global"), fg["fg lockout"])
check("lockout: threshold 5 with duration 900 is still the finding", M(GOOD_FG.replace("set admin-lockout-duration 900", "set admin-lockout-duration 900\n    set admin-lockout-threshold 5"))["fg lockout"] == ("WARN", "admin-lockout-threshold 5, admin-lockout-duration 900: set them to 3 and 900 under config system global"))
check("password length 8 and the four character rules", fg["fg password length"] == ("WARN", "minimum-length 8: set minimum-length 15 under config system password-policy")
      and fg["fg password complexity"] == ("WARN", "min-upper-case-letter, min-lower-case-letter, min-number, min-non-alphanumeric 0: set min-upper-case-letter, min-lower-case-letter, min-number and min-non-alphanumeric to 1 under config system password-policy"), (fg["fg password length"], fg["fg password complexity"]))
check("one character rule off names only that one", M(GOOD_FG.replace("set min-number 1", "set min-number 0"))["fg password complexity"][1].startswith("min-number 0: set"))
check("banner off by default", fg["fg banner"] == ("WARN", "pre-login-banner is not enabled: set pre-login-banner enable under config system global"), fg["fg banner"])
check("snmp community public is a FAIL", fg["fg snmp public"] == ("FAIL", "community public: rename it under config system snmp community"), fg["fg snmp public"])
check("a masked community name alone answers N/A", M(BAD_FG.replace('set name "public"', "set name <masked>"))["fg snmp public"] == ("N/A", "the community name, the stored backup masks it (Settings > Config backups)"), M(BAD_FG.replace('set name "public"', "set name <masked>"))["fg snmp public"])
check("a disabled private community is not a finding", M(GOOD_FG.replace("config system auto-install", 'config system snmp community\n    edit 1\n        set name "private"\n        set status disable\n    next\nend\nconfig system auto-install'))["fg snmp public"][0] == "OK")
check("snmp v3 user defaults to no auth", fg["fg snmp v3"] == ("WARN", "user mon: security-level no-auth-no-priv: set security-level auth-priv under config system snmp user"), fg["fg snmp v3"])
check("NTP: one custom server, unauthenticated; and only one", fg["fg ntp auth"] == ("WARN", "1 of 1 NTP servers without authentication: set authentication enable under config ntpserver")
      and fg["fg ntp servers"] == ("WARN", "one NTP server: add a second under config system ntp, config ntpserver"), (fg["fg ntp auth"], fg["fg ntp servers"]))
check("FortiGuard NTP (not custom) passes both", M(BAD_FG.replace("set type custom", ""))["fg ntp auth"][0] == "OK" and M(BAD_FG.replace("set type custom", ""))["fg ntp servers"][0] == "OK")
check("event log: the ones off", fg["fg event log"] == ("WARN", "event, user disable: set event, system and user enable under config log eventfilter"), fg["fg event log"])
check("TLS 1.1 on the web UI", fg["fg tls version"] == ("WARN", "admin-https-ssl-versions tlsv1-1 tlsv1-2: set admin-https-ssl-versions tlsv1-2 tlsv1-3 under config system global"), fg["fg tls version"])
check("LDAP: no secure setting is the finding, starttls is not", fg["fg ldap"] == ("WARN", "corp: set secure ldaps under config user ldap"), fg["fg ldap"])
good = by(GOOD_FG, "", vendor="fortinet")
check("a hardened FortiGate: every rule OK", all(v == ("OK", "not found") for v in good.values()), {k: v for k, v in good.items() if v[0] != "OK"})
check("syslog over reliable with encryption off is the finding", by(GOOD_FG.replace("set mode reliable", "set mode reliable\n    set enc-algorithm disable"), "", vendor="fortinet")["fg syslog"] == ("WARN", "set enc-algorithm disable"))
try:
    H.findings(BAD_IOS, "", vendor="fortinet"); check("an IOS text is refused as FortiOS", False)
except ValueError:
    check("an IOS text is refused as FortiOS", True)

print("== Palo Alto")
BAD_PA = """<config version="10.1.0">
 <mgt-config><users><entry name="admin"><phash><masked></phash></entry></users>
  <password-complexity><enabled>yes</enabled><minimum-length>8</minimum-length><minimum-uppercase-letters>1</minimum-uppercase-letters></password-complexity></mgt-config>
 <shared><ssl-tls-service-profile><entry name="mgmt"><protocol-settings><min-version>tls1-1</min-version></protocol-settings></entry></ssl-tls-service-profile>
  <log-settings><system/><config/>
   <snmptrap><entry name="t1"><version><v2c><server><entry name="s"><manager>10.0.0.8</manager></entry></server></v2c></version></entry></snmptrap></log-settings>
  <server-profile><ldap><entry name="dir"><ssl>no</ssl></entry></ldap>
   <syslog><entry name="siem"><server><entry name="s1"><server>10.0.0.9</server><transport>UDP</transport></entry></server></entry></syslog></server-profile></shared>
 <devices><entry name="localhost.localdomain">
  <deviceconfig>
   <system><ntp-servers><primary-ntp-server><ntp-server-address>10.0.0.6</ntp-server-address><authentication-type><none/></authentication-type></primary-ntp-server></ntp-servers>
    <service><disable-telnet>no</disable-telnet><disable-http>yes</disable-http></service>
    <ssl-tls-service-profile>mgmt</ssl-tls-service-profile>
    <snmp-setting><access-setting><version><v2c><snmp-community-string><masked></snmp-community-string></v2c></version></access-setting></snmp-setting>
   </system>
   <setting><management><idle-timeout>30</idle-timeout><admin-lockout><failed-attempts>0</failed-attempts></admin-lockout></management></setting>
  </deviceconfig>
  <network><profiles><interface-management-profile><entry name="allow-mgmt"><https>yes</https><http>yes</http></entry></interface-management-profile></profiles></network>
  <vsys><entry name="vsys1"><rulebase><security><rules>
   <entry name="allow-all"><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application><service><member>any</member></service><action>allow</action></entry>
   <entry name="web"><from><member>trust</member></from><to><member>untrust</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>web-browsing</member></application><service><member>application-default</member></service><action>allow</action></entry>
  </rules></security></rulebase></entry></vsys>
 </entry></devices>
</config>
"""
GOOD_PA = """<config version="10.1.0">
 <mgt-config><users><entry name="netops"><phash><masked></phash></entry></users><password-complexity><enabled>yes</enabled><minimum-length>15</minimum-length><minimum-uppercase-letters>1</minimum-uppercase-letters><minimum-lowercase-letters>1</minimum-lowercase-letters><minimum-numeric-letters>1</minimum-numeric-letters><minimum-special-characters>1</minimum-special-characters></password-complexity></mgt-config>
 <shared><ssl-tls-service-profile><entry name="mgmt"><protocol-settings><min-version>tls1-2</min-version></protocol-settings></entry></ssl-tls-service-profile>
  <log-settings><system><match-list><entry name="all"><send-syslog><member>siem</member></send-syslog></entry></match-list></system>
   <config><match-list><entry name="all"><send-syslog><member>siem</member></send-syslog></entry></match-list></config>
   <snmptrap><entry name="t1"><version><v3><server><entry name="s"><manager>10.0.0.8</manager></entry></server></v3></version></entry></snmptrap></log-settings>
  <server-profile><ldap><entry name="dir"><ssl>yes</ssl></entry></ldap>
   <syslog><entry name="siem"><server><entry name="s1"><server>10.0.0.9</server><transport>SSL</transport></entry></server></entry></syslog></server-profile></shared>
 <devices><entry name="localhost.localdomain"><deviceconfig>
  <system><service><disable-telnet>yes</disable-telnet><disable-http>yes</disable-http></service>
   <permitted-ip><entry name="10.0.0.0/24"/></permitted-ip>
   <ssl-tls-service-profile>mgmt</ssl-tls-service-profile>
   <login-banner>Authorised use only</login-banner>
   <ntp-servers><primary-ntp-server><ntp-server-address>10.0.0.6</ntp-server-address><authentication-type><symmetric-key><key-id>1</key-id></symmetric-key></authentication-type></primary-ntp-server>
    <secondary-ntp-server><ntp-server-address>10.0.0.7</ntp-server-address><authentication-type><autokey/></authentication-type></secondary-ntp-server></ntp-servers>
   <snmp-setting><access-setting><version><v3/></version></access-setting></snmp-setting></system>
  <setting><management><idle-timeout>10</idle-timeout><admin-lockout><failed-attempts>5</failed-attempts><lockout-time>30</lockout-time></admin-lockout></management></setting>
 </deviceconfig></entry></devices>
</config>
"""
pa = by(BAD_PA, "", vendor="paloalto")
from core import hardening_paloalto as PA
check("every Palo Alto rule answers, in order; all find something but the three the older rules read from variants below (the masked hashes do not break the XML)", [k for k, *_ in H.findings(BAD_PA, "", vendor="paloalto")] == [k for k, *_ in PA.RULES]
      and len(PA.RULES) == 21 and {k for k, v in pa.items() if v[0] == "OK"} == {"pa idle timeout", "pa password complexity", "pa ntp"}, {k: v for k, v in pa.items() if v[0] == "OK"})
check("telnet on the MGT port and http in a profile", pa["pa telnet http"] == ("FAIL", "disable-telnet no; interface management profile allow-mgmt: http yes"), pa["pa telnet http"])
check("the any-to-any allow rule, not the web one", pa["pa rule any"] == ("FAIL", "rule allow-all: any to any, allow"), pa["pa rule any"])
check("no permitted IPs, on the MGT port and the profile", pa["pa permitted ip"] == ("WARN", "no permitted-ip on the management interface; interface management profile allow-mgmt allows https or ssh from anywhere"), pa["pa permitted ip"])
check("admin, lockout, idle timeout, password complexity", pa["pa default admin"] == ("WARN", 'account "admin" exists') and pa["pa lockout"] == ("WARN", "admin-lockout failed-attempts is 0 or not set")
      and by(BAD_PA.replace("<idle-timeout>30", "<idle-timeout>0"), "", vendor="paloalto")["pa idle timeout"] == ("WARN", "idle-timeout 0 (never)")
      and by(BAD_PA.replace("<enabled>yes", "<enabled>no"), "", vendor="paloalto")["pa password complexity"] == ("WARN", "password-complexity is not enabled"))
check("TLS 1.1 profile, logs, ntp, snmp v2c", pa["pa tls"] == ("WARN", "profile mgmt: min-version tls1-1") and pa["pa log forwarding"] == ("WARN", "system logs: no syslog server profile and no Panorama server")
      and by(BAD_PA.replace("<ntp-servers>", "<x>").replace("</ntp-servers>", "</x>"), "", vendor="paloalto")["pa ntp"] == ("WARN", "no ntp-servers") and pa["pa snmp v2c"] == ("WARN", "snmp-setting version v2c"), (pa["pa tls"], pa["pa log forwarding"]))
P = lambda t: by(t, "", vendor="paloalto")
check("idle timeout 30; 0 is left to the older rule; absent reads as 60", pa["pa idle long"] == ("WARN", "idle-timeout 30: set Idle Timeout to 10 or fewer (Device > Setup > Management > Authentication Settings)")
      and P(BAD_PA.replace("<idle-timeout>30", "<idle-timeout>0"))["pa idle long"][0] == "OK" and P(BAD_PA.replace("<idle-timeout>30</idle-timeout>", ""))["pa idle long"][1].startswith("idle-timeout 60:"), pa["pa idle long"])
check("password length 8 and the character rules that are 0", pa["pa password length"] == ("WARN", "minimum-length 8: set Minimum Length to 15 (Device > Setup > Management > Minimum Password Complexity)")
      and pa["pa password chars"] == ("WARN", "minimum-lowercase-letters, minimum-numeric-letters, minimum-special-characters 0: set Minimum Uppercase, Lowercase, Numeric and Special to 1 (Device > Setup > Management > Minimum Password Complexity)"), (pa["pa password length"], pa["pa password chars"]))
check("password length is left to the complexity rule while complexity is off", P(BAD_PA.replace("<enabled>yes", "<enabled>no"))["pa password length"][0] == "OK")
check("no login banner", pa["pa banner"] == ("WARN", "no login-banner: set Login Banner (Device > Setup > Management > General Settings)"), pa["pa banner"])
check("NTP: primary with no authentication, no secondary", pa["pa ntp auth"] == ("WARN", "primary-ntp-server authentication-type none: set Symmetric Key or Autokey (Device > Setup > Services)")
      and pa["pa ntp second"] == ("WARN", "no secondary-ntp-server: set Secondary NTP Server (Device > Setup > Services)"), (pa["pa ntp auth"], pa["pa ntp second"]))
check("config logs: none forwarded; a Panorama server passes", pa["pa config log"] == ("WARN", "config logs: no syslog server profile: set one (Device > Log Settings > Configuration)")
      and P(BAD_PA.replace("<system><ntp-servers>", "<system><panorama-server>10.0.0.2</panorama-server><ntp-servers>"))["pa config log"][0] == "OK")
check("SNMP trap v2c, LDAP without SSL, syslog over UDP", pa["pa snmp trap"] == ("WARN", "trap profile t1: version v2c: set Version to V3 (Device > Server Profiles > SNMP Trap)")
      and pa["pa ldap ssl"] == ("WARN", "LDAP profile dir: ssl no: tick Require SSL/TLS (Device > Server Profiles > LDAP)")
      and pa["pa syslog udp"] == ("WARN", "syslog profile siem: transport UDP: set Transport to SSL (Device > Server Profiles > Syslog)"), (pa["pa snmp trap"], pa["pa ldap ssl"], pa["pa syslog udp"]))
check("a syslog server with no transport reads as UDP", P(BAD_PA.replace("<transport>UDP</transport>", ""))["pa syslog udp"][0] == "WARN")
goodpa = by(GOOD_PA, "", vendor="paloalto")
check("a hardened PAN-OS: every rule OK", all(v == ("OK", "not found") for v in goodpa.values()), {k: v for k, v in goodpa.items() if v[0] != "OK"})
check("no TLS profile at all is the finding", by(GOOD_PA.replace("<ssl-tls-service-profile>mgmt</ssl-tls-service-profile>", ""), "", vendor="paloalto")["pa tls"][1].startswith("no SSL/TLS service profile"))
check("lockout time 0 is the finding once attempts are set", by(GOOD_PA.replace("<lockout-time>30</lockout-time>", "<lockout-time>0</lockout-time>"), "", vendor="paloalto")["pa lockout"] == ("WARN", "admin-lockout lockout-time is 0"))

print("== Juniper")
BAD_JN = """## Last commit: 2026-11-01 10:00:00 UTC by admin
version 20.4R3;
groups {
    mgmt {
        system {
            services {
                ftp;
            }
        }
    }
}
apply-groups mgmt;
system {
    host-name srx1;
    login {
        class ops {
            permissions all;
        }
    }
    services {
        telnet;
        web-management {
            http {
                port 80;
            }
        }
        ssh;
    }
    ntp {
        server 10.0.0.1;
    }
}
snmp {
    community public {
        authorization read-write;
    }
}
interfaces {
    lo0 {
        unit 0 {
            family inet {
                address 10.255.0.1/32;
            }
        }
    }
}
"""
GOOD_JN = """version 20.4R3;
system {
    login {
        message "Authorized use only";
        retry-options {
            lockout-period 15;
        }
        password {
            minimum-length 15;
        }
        class ops {
            idle-timeout 10;
        }
    }
    services {
        inactive: telnet;
        ssh {
            root-login deny;
        }
    }
    syslog {
        host 10.0.0.5 {
            any notice;
        }
    }
    ntp {
        authentication-key 1 type md5 value "<masked>";
        trusted-key 1;
        server 10.0.0.1 key 1;
    }
}
snmp {
    v3 {
        usm {
            local-engine {
                user mon {
                    authentication-sha;
                }
            }
        }
    }
}
interfaces {
    lo0 {
        unit 0 {
            family inet {
                filter {
                    input PROTECT-RE;
                }
            }
        }
    }
}
"""
from core import hardening_juniper as JN
jn = by(BAD_JN, "", vendor="juniper")
check("every Junos rule answers, in order; all find something but the NTP server", [k for k, *_ in H.findings(BAD_JN, "", vendor="juniper")] == [k for k, *_ in JN.RULES]
      and len(JN.RULES) == 14 and {k for k, v in jn.items() if v[0] == "OK"} == {"jn ntp"}, {k: v for k, v in jn.items() if v[0] == "OK"})
check("telnet and web-management http, each named", jn["jn telnet http"] == ("FAIL", "telnet: delete system services telnet; web-management http: delete system services web-management http"), jn["jn telnet http"])
check("a service set only by an applied group is found", jn["jn services"] == ("WARN", "ftp: delete system services ftp"), jn["jn services"])
check("without the apply-groups line the group's setting does not count", by(BAD_JN.replace("apply-groups mgmt;", ""), "", vendor="juniper")["jn services"][0] == "OK")
check("ssh root, lockout, password length (default 6) and banner", jn["jn ssh root"] == ("WARN", "root-login deny is not set: set system services ssh root-login deny")
      and jn["jn lockout"] == ("WARN", "retry-options lockout-period is not set: set system login retry-options lockout-period 15")
      and jn["jn password length"] == ("WARN", "minimum-length 6: set system login password minimum-length 15")
      and jn["jn banner"] == ("WARN", "no login message: set system login message"), jn)
check("idle timeout: a class with none, and one over 10", jn["jn idle timeout"] == ("WARN", "class ops: idle-timeout not set: set system login class ops idle-timeout 10")
      and by(BAD_JN.replace("permissions all;", "idle-timeout 30;"), "", vendor="juniper")["jn idle timeout"] == ("WARN", "class ops: idle-timeout 30: set system login class ops idle-timeout 10"))
check("SNMP: a public read-write community, no clients, version 2c", jn["jn snmp community"] == ("FAIL", "community public: name is public or private and authorization read-write: rename it and set authorization read-only under snmp community")
      and jn["jn snmp clients"] == ("WARN", "1 of 1 communities without clients: set snmp community public clients")
      and jn["jn snmp v2c"] == ("WARN", "1 community (version 1 or 2c); 0 SNMPv3 users: move to snmp v3"), jn)
check("syslog, NTP auth and lo0 filter", jn["jn syslog"] == ("WARN", "no syslog host: set system syslog host") and jn["jn ntp auth"] == ("WARN", "authentication-key and trusted-key not set: set system ntp authentication-key and trusted-key")
      and jn["jn lo0 filter"] == ("WARN", "lo0 unit 0: no family inet filter input: set interfaces lo0 unit 0 family inet filter input"), jn)
check("no NTP server: the rule fails and NTP auth has nothing to check", by(BAD_JN.replace("server 10.0.0.1;", ""), "", vendor="juniper")["jn ntp"] == ("WARN", "no ntp server: set system ntp server")
      and by(BAD_JN.replace("server 10.0.0.1;", ""), "", vendor="juniper")["jn ntp auth"][0] == "OK")
goodjn = by(GOOD_JN, "", vendor="juniper")
check("a hardened Junos device: every rule OK (an inactive: telnet does not count)", all(v == ("OK", "not found") for v in goodjn.values()), {k: v for k, v in goodjn.items() if v[0] != "OK"})
check("a masked community name alone answers N/A; an unmasked read-write one still fails", by(BAD_JN.replace("community public", 'community "<masked>"').replace("read-write", "read-only"), "", vendor="juniper")["jn snmp community"]
      == ("N/A", "whether it is public or private cannot be told, the stored backup masks it (Settings > Config backups)")
      and by(BAD_JN.replace("community public", 'community "<masked>"'), "", vendor="juniper")["jn snmp community"][0] == "FAIL")
check("a community with clients passes the clients rule; an applied group's settings count as set", by(BAD_JN.replace("authorization read-write;", "clients {\n 10.0.0.0/8;\n }"), "", vendor="juniper")["jn snmp clients"][0] == "OK"
      and by(GOOD_JN.replace("message \"Authorized use only\";", "").replace("version 20.4R3;", "version 20.4R3;\ngroups {\n b {\n system {\n login {\n message x;\n }\n }\n }\n}\napply-groups b;"), "", vendor="juniper")["jn banner"][0] == "OK")
try:
    H.findings("garbage", "", vendor="juniper"); check("garbage is refused as Junos", False)
except ValueError:
    check("garbage is refused as Junos", True)

print("== Arista")
BAD_AR = """! Command: show running-config
! device: sw1 (DCS-7050SX3-48YC8, EOS-4.28.3M)
hostname sw1
snmp-server community public rw
snmp-server community mon ro
snmp-server user u1 g1 v3
management telnet
   no shutdown
management api http-commands
   protocol http
   no shutdown
management ssh
   idle-timeout 30
ntp server 10.0.0.1
end
"""
GOOD_AR = """! device: sw1 (DCS-7050SX3-48YC8, EOS-4.28.3M)
hostname sw1
snmp-server user mon g1 v3
banner login
Authorized use only
EOF
logging host 10.0.0.5
ntp authenticate
ntp trusted-key 1
ntp server 10.0.0.1 key 1
aaa authentication policy lockout failure 3 window 1 duration 900
aaa accounting commands all default start-stop logging
management telnet
   shutdown
management api http-commands
   protocol https
   no shutdown
management console
   idle-timeout 10
management ssh
   idle-timeout 10
   vrf MGMT
      ip access-group SSH-IN in
management security
   password minimum length 15
"""
from core import hardening_arista as AR
ar = by(BAD_AR, "", vendor="arista")
check("every Arista rule answers, in order; all find something but the NTP server", [k for k, *_ in H.findings(BAD_AR, "", vendor="arista")] == [k for k, *_ in AR.RULES]
      and len(AR.RULES) == 14 and {k for k, v in ar.items() if v[0] == "OK"} == {"ar ntp"}, {k: v for k, v in ar.items() if v[0] == "OK"})
check("telnet and plain-HTTP eAPI", ar["ar telnet"] == ("FAIL", "management telnet is on: set shutdown under management telnet")
      and ar["ar http api"] == ("FAIL", "eAPI over HTTP: remove protocol http under management api http-commands"), ar)
check("a public read-write community is quoted masked, as Cisco's rule does", ar["ar snmp community"] == ("FAIL", "snmp-server community <masked>: change the community and use ro (snmp-server community)"), ar["ar snmp community"])
check("SNMP version 2c and no access list", ar["ar snmp v2c"] == ("WARN", "2 communities (version 1 or 2c); 1 SNMPv3 user: remove snmp-server community and use snmp-server user v3")
      and ar["ar snmp acl"] == ("WARN", "2 of 2 without an access list: add one to snmp-server community"), ar)
check("SSH access list, idle timeouts, lockout, password length", ar["ar ssh acl"] == ("WARN", "no ip access-group under management ssh: add one")
      and ar["ar idle timeout"] == ("WARN", "management console: idle-timeout not set: set idle-timeout 10; management ssh: idle-timeout 30: set idle-timeout 10")
      and ar["ar lockout"] == ("WARN", "aaa authentication policy lockout is not set: set aaa authentication policy lockout failure 3 duration 900")
      and ar["ar password length"] == ("WARN", "password minimum length not set: set password minimum length 15 under management security"), ar)
check("banner, logging, NTP auth and accounting", ar["ar banner"] == ("WARN", "no banner login or banner motd: set one") and ar["ar logging"] == ("WARN", "no logging host: set logging host")
      and ar["ar ntp auth"] == ("WARN", "ntp authenticate is not set: set ntp authenticate servers and ntp trusted-key")
      and ar["ar accounting"] == ("WARN", "no aaa accounting: set aaa accounting commands all default start-stop logging"), ar)
check("no NTP server: the rule fails and NTP auth has nothing to check", by(BAD_AR.replace("ntp server 10.0.0.1", ""), "", vendor="arista")["ar ntp"] == ("WARN", "no ntp server: set ntp server")
      and by(BAD_AR.replace("ntp server 10.0.0.1", ""), "", vendor="arista")["ar ntp auth"][0] == "OK")
goodar = by(GOOD_AR, "", vendor="arista")
check("a hardened Arista switch: every rule OK (shutdown telnet and HTTPS eAPI are fine)", all(v == ("OK", "not found") for v in goodar.values()), {k: v for k, v in goodar.items() if v[0] != "OK"})
mar = by(BAD_AR.replace("community public rw", "community <masked>").replace("community mon ro", "community <masked>"), "", vendor="arista")
check("masked communities answer N/A, with Cisco's wording", mar["ar snmp community"] == ("N/A", "2 communities; whether one is public, private or read-write cannot be told, the stored backup masks it (Settings > Config backups)")
      and mar["ar snmp acl"] == ("N/A", "2 communities; whether each has an access list cannot be told, the stored backup masks it (Settings > Config backups)"), mar)
check("a community with an access list passes the ACL rule", by(GOOD_AR.replace("snmp-server user mon g1 v3", "snmp-server community mon ro MGMT"), "", vendor="arista")["ar snmp acl"][0] == "OK")
check("idle timeout 0 (never) is the finding; eAPI HTTPS alone and a shut telnet are not", by(GOOD_AR.replace("idle-timeout 10\nmanagement ssh", "idle-timeout 0\nmanagement ssh"), "", vendor="arista")["ar idle timeout"]
      == ("WARN", "management console: idle-timeout 0: set idle-timeout 10"))
try:
    H.findings(BAD_IOS, "", vendor="arista"); check("an IOS text is refused as EOS", False)
except ValueError:
    check("an IOS text is refused as EOS", True)

print("== HPE Aruba")
BAD_CX = """!Version ArubaOS-CX FL.10.10.1000
hostname cx1
snmp-server community public
snmp-server community mon
session-timeout 0
aaa authentication minimum-password-length 8
ntp server 10.0.0.1
"""
GOOD_CX = """!Version ArubaOS-CX FL.10.10.1000
hostname cx1
banner motd !
Authorized use only
!
logging 10.0.0.5 vrf mgmt
ntp server 10.0.0.1 vrf mgmt
ntp authentication
ntp authentication-key 1 md5 ciphertext AQBapaAbc123
aaa authentication limit-login-attempts 3 lockout-time 300
aaa authentication minimum-password-length 15
aaa accounting all-mgmt default start-stop local
session-timeout 10
"""
BAD_OS = """; J9774A Configuration Editor; Created on release #YA.16.10.0003
hostname "os1"
snmp-server community "public" operator
snmp-server community "mon" manager
password minimum-length 8
sntp server priority 1 10.0.0.1 3
"""
GOOD_OS = """; J9774A Configuration Editor; Created on release #YA.16.10.0003
hostname "os1"
no telnet-server
no web-management plaintext
web-management ssl
password minimum-length 15
aaa authentication lockout-delay 60
aaa accounting exec start-stop radius
banner motd "Authorized use only"
logging 10.0.0.5
sntp server priority 1 10.0.0.1 3
ip authorized-managers 10.0.0.0 255.255.255.0 access manager
"""
from core import hardening_hpe as HP
CX, OSW = "aruba_aoscx", "aruba_osswitch"
cx, osw = by(BAD_CX, CX, vendor="hpe"), by(BAD_OS, OSW, vendor="hpe")
NOT_HERE = ("N/A", H.NOT_HERE)
check("every HPE rule answers, in order, on both platforms", [k for k, *_ in H.findings(BAD_CX, CX, vendor="hpe")] == [k for k, *_ in HP.RULES] == [k for k, *_ in H.findings(BAD_OS, OSW, vendor="hpe")]
      and len(HP.RULES) == 13 and all(k.startswith("hp ") for k, *_ in HP.RULES))
check("AOS-CX: telnet and HTTP do not apply; the other one-platform rules do", cx["hp telnet"] == NOT_HERE and cx["hp http"] == NOT_HERE and cx["hp mgmt acl"] == NOT_HERE
      and cx["hp lockout"] == ("WARN", "aaa authentication limit-login-attempts is not set: set aaa authentication limit-login-attempts")
      and cx["hp timeout"] == ("WARN", "session-timeout 0: set session-timeout 10")
      and cx["hp ntp auth"] == ("WARN", "ntp authentication and ntp authentication-key not set: set ntp authentication and ntp authentication-key"), cx)
check("AOS-S: timeout and NTP auth do not apply; telnet, HTTP and the manager list do", osw["hp timeout"] == NOT_HERE and osw["hp ntp auth"] == NOT_HERE
      and osw["hp telnet"] == ("FAIL", "no telnet-server is not set: set no telnet-server")
      and osw["hp http"] == ("FAIL", "no web-management plaintext is not set: set web-management ssl and no web-management plaintext")
      and osw["hp mgmt acl"] == ("WARN", "no ip authorized-manager: add ip authorized-manager lines")
      and osw["hp lockout"] == ("WARN", "aaa authentication lockout-delay is not set: set aaa authentication lockout-delay"), osw)
for p, r in ((CX, cx), (OSW, osw)):
    check(f"{p}: SNMP, banner, logging, accounting", r["hp snmp community"] == ("FAIL", "snmp-server community <masked>: change it (snmp-server community)")
          and r["hp snmp v2c"] == ("WARN", "2 communities: remove snmp-server community and use SNMPv3 (snmpv3 only on ArubaOS-Switch)")
          and r["hp banner"] == ("WARN", "no banner motd or banner exec: set one") and r["hp logging"] == ("WARN", "no logging host: set logging {server}")
          and r["hp accounting"] == ("WARN", "no aaa accounting: set aaa accounting") and r["hp ntp"] == ("OK", "not found"), r)
check("password length names the platform's own setting", cx["hp password length"] == ("WARN", "aaa authentication minimum-password-length 8: set aaa authentication minimum-password-length 15")
      and osw["hp password length"] == ("WARN", "password minimum-length 8: set password minimum-length 15")
      and by(GOOD_OS.replace("password minimum-length 15\n", ""), OSW, vendor="hpe")["hp password length"] == ("WARN", "password minimum-length not set: set password minimum-length 15"))
for g, p in ((GOOD_CX, CX), (GOOD_OS, OSW)):
    r = by(g, p, vendor="hpe")
    check(f"a hardened {p} config: every rule OK, but the N/A ones", all(v[0] in ("OK", "N/A") for v in r.values()) and sum(v[0] == "N/A" for v in r.values()) == (3 if p == CX else 2),
          {k: v for k, v in r.items() if v[0] != "OK"})
check("remote AAA: no local lockout can be set, so N/A", by(GOOD_CX.replace("aaa authentication limit-login-attempts 3 lockout-time 300", "aaa authentication login default group radius local"), CX, vendor="hpe")["hp lockout"][0] == "N/A")
check("no platform given: it is read from the header", by(BAD_CX, "", vendor="hpe")["hp telnet"] == NOT_HERE and by(BAD_OS, "", vendor="hpe")["hp timeout"] == NOT_HERE)
check("snmpv3 only ends the SNMP version finding; no web-management at all also passes HTTP", by(BAD_OS.replace("hostname", "snmpv3 only\nhostname"), OSW, vendor="hpe")["hp snmp v2c"][0] == "OK"
      and by(GOOD_OS.replace("no web-management plaintext", "no web-management"), OSW, vendor="hpe")["hp http"][0] == "OK")
check("a masked community name: N/A, whether it is public cannot be told", by(BAD_CX.replace("community public", "community <masked>"), CX, vendor="hpe")["hp snmp community"]
      == ("N/A", "2 communities; whether one is public or private cannot be told, the stored backup masks it (Settings > Config backups)"))
check("no NTP server: NTP fails, NTP auth has nothing to check", by(BAD_CX.replace("ntp server 10.0.0.1", ""), CX, vendor="hpe")["hp ntp"] == ("WARN", "no ntp server: set ntp server")
      and by(BAD_CX.replace("ntp server 10.0.0.1", ""), CX, vendor="hpe")["hp ntp auth"][0] == "OK")
try:
    H.findings(BAD_IOS, CX, vendor="hpe"); check("an IOS text is refused as Aruba", False)
except ValueError:
    check("an IOS text is refused as Aruba", True)

print("== MikroTik")
BAD_MT = """# 2026-11-09 12:00:00 by RouterOS 7.14
/ip service
set www-ssl disabled=no
/ip proxy
set enabled=yes
/ip socks
set enabled=yes
/snmp
set enabled=yes
/snmp community
add name=private write-access=yes
"""
GOOD_MT = """# 2026-11-09 12:00:00 by RouterOS 7.14
# model = RB4011iGS+
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set api disabled=yes
set api-ssl disabled=yes
set ssh address=10.0.0.0/8
set winbox address=10.0.0.0/8
/tool mac-server
set allowed-interface-list=LAN
/tool mac-server mac-winbox
set allowed-interface-list=LAN
/ip neighbor discovery-settings
set discover-interface-list=LAN
/tool bandwidth-server
set enabled=no
/ip ssh
set strong-crypto=yes
/ip firewall filter
add action=accept chain=input connection-state=established,related
add action=drop chain=input comment="drop all not from LAN" \\
    in-interface-list=!LAN
/snmp
set enabled=yes
/snmp community
set [ find default=yes ] addresses=10.0.0.0/8 authentication-protocol=SHA1 name=mon7f3 security=authorized
/system logging action
add name=remote1 remote=10.0.0.5 target=remote
/system logging
add action=remote1 topics=info
/system ntp client
set enabled=yes
"""
from core import hardening_mikrotik as MT
mk = by(BAD_MT, "mikrotik_routeros", vendor="mikrotik")
check("every MikroTik rule answers, in order, and each finds something in a bare export", [k for k, *_ in H.findings(BAD_MT, "", vendor="mikrotik")] == [k for k, *_ in MT.RULES]
      and len(MT.RULES) == 14 and all(k.startswith("mt ") for k, *_ in MT.RULES) and {v[0] for v in mk.values()} == {"FAIL", "WARN"}, mk)
check("services on by default", mk["mt telnet http"] == ("FAIL", "telnet,ftp,www not disabled: /ip service disable telnet,ftp,www")
      and mk["mt api"] == ("WARN", "api not disabled: /ip service disable api")
      and mk["mt service address"] == ("WARN", "ssh, winbox, api-ssl, www-ssl without a source address: set address (available-from on RouterOS 7.25 and later) under /ip service"), mk)
check("MAC server, neighbors, bandwidth, proxy, SSH, firewall", mk["mt mac server"] == ("WARN", "allowed-interface-list all: /tool mac-server set allowed-interface-list=none and /tool mac-server mac-winbox set allowed-interface-list=none")
      and mk["mt neighbor"] == ("WARN", "discover-interface-list all: /ip neighbor discovery-settings set discover-interface-list=none")
      and mk["mt bandwidth"] == ("WARN", "bandwidth-server is on: /tool bandwidth-server set enabled=no")
      and mk["mt proxy"] == ("WARN", "proxy, socks on: set enabled=no under /ip proxy, /ip socks")
      and mk["mt ssh"] == ("WARN", "strong-crypto is off: /ip ssh set strong-crypto=yes")
      and mk["mt firewall"] == ("WARN", "no drop rule in chain=input: add one under /ip firewall filter"), mk)
check("SNMP: the default community left as public, a private one with write access, both open", mk["mt snmp public"] == ("FAIL", "community public: name is public or private; community private: name is public or private and write-access=yes: rename the community and set write-access=no under /snmp community")
      and mk["mt snmp addresses"] == ("WARN", "2 of 2 communities on 0.0.0.0/0: set addresses= under /snmp community")
      and mk["mt snmp v2c"] == ("WARN", "2 communities without security=authorized or private: set security= and authentication-protocol= under /snmp community"), mk)
check("logging and NTP", mk["mt syslog"] == ("WARN", "no remote logging action: add target=remote under /system logging action and use it in /system logging")
      and mk["mt ntp"] == ("WARN", "NTP client not enabled: /system ntp client set enabled=yes"), mk)
goodmt = by(GOOD_MT, "mikrotik_routeros", vendor="mikrotik")
check("a hardened router (a wrapped drop rule, a renamed default community): every rule OK", all(v == ("OK", "not found") for v in goodmt.values()), {k: v for k, v in goodmt.items() if v[0] != "OK"})
mt2 = lambda s: by(s, "mikrotik_routeros", vendor="mikrotik")
check("SNMP off: its rules pass; one-line forms and [ find name= ] are read", mt2(GOOD_MT.replace("/snmp\nset enabled=yes", "/snmp\nset enabled=no").replace("name=mon7f3", "name=public"))["mt snmp public"][0] == "OK"
      and mt2(GOOD_MT.replace("/ip service\nset telnet disabled=yes", "/ip service set [ find name=telnet ] disabled=no"))["mt telnet http"] == ("FAIL", "telnet not disabled: /ip service disable telnet")
      and mt2(GOOD_MT.replace("set ssh address=10.0.0.0/8", "set ssh"))["mt service address"][0] == "WARN")
check("www-ssl is off until enabled; a source limit written as available-from counts", mt2(GOOD_MT)["mt service address"][0] == "OK"
      and mt2(GOOD_MT.replace("set ssh address=10.0.0.0/8", "set ssh available-from=10.0.0.0/8"))["mt service address"][0] == "OK"
      and mt2(GOOD_MT + "/ip service\nset www-ssl disabled=no\n")["mt service address"] == ("WARN", "www-ssl without a source address: set address (available-from on RouterOS 7.25 and later) under /ip service"))
check("a disabled drop rule does not count; neither does a drop in another chain", mt2(GOOD_MT.replace("add action=drop chain=input", "add action=drop chain=input disabled=yes"))["mt firewall"][0] == "WARN"
      and mt2(GOOD_MT.replace("chain=input comment", "chain=forward comment"))["mt firewall"][0] == "WARN")
try:
    H.findings(BAD_IOS, "", vendor="mikrotik"); check("an IOS text is refused as RouterOS", False)
except ValueError:
    check("an IOS text is refused as RouterOS", True)

print("== the masked backups a scan reads")
check("a hardened Junos config through the masker: every rule still OK", all(v == ("OK", "not found") for v in by(backup.mask_secrets(GOOD_JN), "", vendor="juniper").values()), {k: v for k, v in by(backup.mask_secrets(GOOD_JN), "", vendor="juniper").items() if v[0] != "OK"})
check("a hardened Arista config through the masker: every rule still OK", all(v == ("OK", "not found") for v in by(backup.mask_secrets(GOOD_AR), "", vendor="arista").values()), {k: v for k, v in by(backup.mask_secrets(GOOD_AR), "", vendor="arista").items() if v[0] != "OK"})
for name, text, plat, vendor in (("HPE AOS-CX", GOOD_CX, CX, "hpe"), ("HPE AOS-S", GOOD_OS, OSW, "hpe"), ("MikroTik", GOOD_MT, "mikrotik_routeros", "mikrotik")):
    now, was = by(backup.mask_secrets(text), plat, vendor=vendor), by(text, plat, vendor=vendor)
    check(f"a hardened {name} config through the masker: every rule answers as it did before", now == was, {k: v for k, v in now.items() if v != was[k]})
check("the masker leaves a length setting and a block opener alone, and still masks a password",
      backup.mask_secrets("   password minimum length 15") == "   password minimum length 15" and backup.mask_secrets("    password {") == "    password {"
      and backup.mask_secrets("username a password 7 0822455D0A16") == "username a password <masked>" and backup.mask_secrets("password cisco") == "password <masked>")
OLD_JN = GOOD_JN.replace("        password {\n            minimum-length 15;\n        }\n", "        password <masked>\n            minimum-length 15;\n        }\n")
oj = by(OLD_JN, "", vendor="juniper")
check("an old Junos backup that lost the password block's brace: later system rules still right", oj["jn idle timeout"][0] == "OK" and oj["jn ssh root"][0] == "OK" and oj["jn password length"][0] == "OK"
      and oj["jn syslog"][0] == "OK" and oj["jn ntp auth"][0] == "OK", {k: v for k, v in oj.items() if v[0] != "OK"})
check("an old Arista backup with the length line masked: N/A, not 'not set'", by(GOOD_AR.replace("password minimum length 15", "password <masked>"), "", vendor="arista")["ar password length"]
      == ("N/A", "the minimum length, the stored backup masks it (Settings > Config backups)"))

print("== the rows a scan adds")
def dev(name, vendor, platform="", version=""):
    d = {"name": name, "vendor": vendor, "host": "10.0.0.9", "platform": platform, "enabled": 1}
    d["id"] = db.save_device(d)
    if version: db.set_software(d, {"version": version})
    return db.find_device(name)
sw1, sw2, fw, pan, mt = dev("sw1", "cisco", "cisco_ios"), dev("sw2", "cisco", "cisco_xe"), dev("edge-fw", "fortinet"), dev("pan", "paloalto"), dev("mt", "meraki")
backup.store("sw1", BAD_IOS, mask=False)
db.set_setting("scan_enabled", False)
rows = A.scan(sw1)
check("lookups off: the version row says so, the rule rows follow", rows[0].check == A.SOFTWARE and rows[0].status == "N/A" and rows[0].message == A.OFF and len(rows) == 1 + len(H.CISCO), [(r.check, r.status) for r in rows])
rule_rows = {r.check: r for r in rows[1:]}
check("one row per rule, named 'Hardening: <rule>', with the backup's time on a finding", rule_rows["Hardening: Telnet allowed on VTY lines"].status == "FAIL"
      and rule_rows["Hardening: Telnet allowed on VTY lines"].message.startswith("line vty 0 4: transport input telnet ssh; line vty 5 15: transport input all (backup of 20")
      and all(k.startswith("Hardening: ") for k in rule_rows), list(rule_rows)[:3])
check("no backup yet: one N/A row saying so, Cisco or FortiGate", [(r.check, r.status, r.message) for r in A.scan(sw2)[1:]] == [("Hardening", "N/A", H.NO_BACKUP)]
      and [(r.check, r.status, r.message) for r in A.scan(fw)[1:]] == [("Hardening", "N/A", H.NO_BACKUP)])
check("a vendor without rules: one N/A row saying so", [(r.check, r.status, r.message) for r in A.scan(mt)[1:]] == [("Hardening", "N/A", H.NO_RULES)])
backup.store("edge-fw", BAD_FG, mask=True)
fg_rows = A.scan(fw)[1:]
check("a FortiGate backup: one row per FortiGate rule", len(fg_rows) == len(FG.RULES) and fg_rows[0].check == "Hardening: Admin access on a WAN interface" and fg_rows[0].status == "FAIL", [(r.check, r.status) for r in fg_rows[:2]])
jn1, ar1 = dev("jn1", "juniper"), dev("ar1", "arista")
backup.store("jn1", BAD_JN, mask=True); backup.store("ar1", BAD_AR, mask=True)
jn_rows, ar_rows = A.scan(jn1)[1:], A.scan(ar1)[1:]
check("a Junos backup: one row per Junos rule, named 'Hardening: <rule>'", len(jn_rows) == len(JN.RULES) and jn_rows[0].check == "Hardening: Telnet or HTTP management on" and jn_rows[0].status == "FAIL", [(r.check, r.status) for r in jn_rows[:2]])
check("an Arista backup: one row per Arista rule", len(ar_rows) == len(AR.RULES) and ar_rows[0].check == "Hardening: Telnet on" and ar_rows[0].status == "FAIL", [(r.check, r.status) for r in ar_rows[:2]])
backup.store("pan", BAD_IOS, mask=True)
check("a backup that is not the vendor's format: one N/A row saying so", [(r.check, r.status, r.message) for r in A.scan(pan)[1:]] == [("Hardening", "N/A", "The backup could not be read as a PAN-OS configuration.")])
db.set_setting("hardening_off", [k for k, *_ in H.RULES])
check("every rule off: no hardening rows at all", len(A.scan(sw1)) == 1 and len(A.scan(fw)) == 1)
db.set_setting("hardening_off", ["telnet"])
check("one rule off: its row is missing", "Hardening: Telnet allowed on VTY lines" not in {r.check for r in A.scan(sw1)} and len(A.scan(sw1)) == len(H.CISCO))
db.set_setting("hardening_off", []); db.set_setting("scan_enabled", True)
from core import display
check("exports keep a rule row's name as worded", display.check_name("Hardening: No NTP server") == "Hardening: No NTP server")

print("== Windows")
import copy, json
from core import hardening_windows as WIN
GU = lambda h: "{0CCE" + h + "-69AE-11D9-BED3-505054503030}"
GOOD_WIN = {"v": 1, "build": "20348.5760", "dc": False, "joined": True,
    "reg": {"Smb1Server": 0, "Smb1ClientStart": 4, "SmbServerSigning": 1, "SmbClientSigning": 1, "LlmnrMulticast": 0, "LmCompatibilityLevel": 5, "RunAsPPL": 1,
            "WDigestLogonCredential": 0, "CredGuardPolicy": 1, "CredGuardLsa": None, "RdpNlaPolicy": 1, "RdpNlaTcp": 1, "RdpDenyConnections": 0, "EnableLUA": 1,
            "Tls10Server": 0, "Tls11Server": 0},
    "policy": {"MinimumPasswordLength": 14, "PasswordComplexity": 1, "PasswordHistorySize": 24, "ClearTextPassword": 0, "LockoutBadCount": 3,
               "LockoutDuration": 15, "ResetLockoutCount": 15, "EnableGuestAccount": 0},
    "audit": {GU(h): "Success and Failure" for h in ("923F", "9215", "9217", "9235", "922F", "9228", "9212")} | {GU(h): "Success" for h in ("9216", "921B", "9237", "922B", "9210", "9211")},
    "firewall": [{"name": "Domain", "on": True}, {"name": "Private", "on": True}, {"name": "Public", "on": True}],
    "defender": {"enabled": True, "realtime": True, "mode": "Normal"}}
def W(**edits):
    """The Windows rule answers for GOOD_WIN with edits: a dict edits a part ("gone" deletes a key), anything else replaces it."""
    o = copy.deepcopy(GOOD_WIN)
    for k, v in edits.items():
        if isinstance(v, dict) and isinstance(o.get(k), dict):
            for kk, vv in v.items():
                (o[k].pop(kk, None) if vv == "gone" else o[k].__setitem__(kk, vv))
        elif v == "gone": o.pop(k, None)
        else: o[k] = v
    return {k: (st, m) for k, st, m in H.findings(json.dumps(o), "", vendor="windows")}
UNREAD = ("N/A", H.UNREAD_SETTING)
good = W()
check("a hardened Windows snapshot: every rule OK", len(good) == len(WIN.RULES) == 18 and all(v == ("OK", "not found") for v in good.values()), {k: v for k, v in good.items() if v[0] != "OK"})
check("keys start win and the groups list Windows last", all(k.startswith("win ") for k, *_ in WIN.RULES) and H.GROUPS[-1][:3] == ("windows", "Windows", "Windows settings"))
check("approved constants", H.NO_SETTINGS == "No Windows settings read yet. Run the health checks; an older agent needs updating." and H.UNREAD_SETTING == "Toner could not read this setting on this computer.")
check("SMBv1: Start 3 fails with the approved message, mrxsmb10 absent (null) passes, Start unread is N/A", W(reg={"Smb1ClientStart": 3})["win smb1"] == ("FAIL", "SMBv1 is on: remove the FS-SMB1 feature, or set LanmanServer\\Parameters\\SMB1 to 0 and mrxsmb10\\Start to 4")
      and W(reg={"Smb1ClientStart": None})["win smb1"][0] == "OK" and W(reg={"Smb1ClientStart": "gone"})["win smb1"] == UNREAD)
check("SMBv1: Start 4 with SMB1 set 1 fails; SMB1 null is on; SMB1 unread is N/A", W(reg={"Smb1Server": 1})["win smb1"][0] == "FAIL" and W(reg={"Smb1Server": None})["win smb1"][0] == "FAIL"
      and W(reg={"Smb1Server": "gone"})["win smb1"] == UNREAD)
check("SMB signing: server off named, client on", W(reg={"SmbServerSigning": 0})["win smb signing"] == ("WARN", "RequireSecuritySignature is off on server: set Microsoft network server: Digitally sign communications (always) to Enabled"), W(reg={"SmbServerSigning": 0})["win smb signing"])
check("SMB signing: absent is off below build 26100 and on from 26100; no build is N/A; unread is N/A", W(reg={"SmbClientSigning": None})["win smb signing"][0] == "WARN"
      and W(reg={"SmbClientSigning": None}, build="26100.1")["win smb signing"][0] == "OK" and W(reg={"SmbClientSigning": None}, build="gone")["win smb signing"] == UNREAD
      and W(reg={"SmbClientSigning": None}, build="x")["win smb signing"] == UNREAD and W(reg={"SmbClientSigning": "gone"})["win smb signing"] == UNREAD
      and W(reg={"SmbClientSigning": "gone", "SmbServerSigning": 0})["win smb signing"][0] == "WARN")
check("LLMNR: absent is on, unread N/A", W(reg={"LlmnrMulticast": None})["win llmnr"] == ("WARN", "EnableMulticast is not 0: set Turn off multicast name resolution to Enabled (DNS Client policy)")
      and W(reg={"LlmnrMulticast": "gone"})["win llmnr"] == UNREAD)
check("NTLM: absent reads 3", W(reg={"LmCompatibilityLevel": None})["win ntlm"][1].startswith("LmCompatibilityLevel 3:") and W(reg={"LmCompatibilityLevel": 5})["win ntlm"][0] == "OK"
      and W(reg={"LmCompatibilityLevel": "gone"})["win ntlm"] == UNREAD and W(reg={"LmCompatibilityLevel": 2})["win ntlm"][0] == "FAIL")
check("LSA protection: 2 passes, absent and 0 do not", W(reg={"RunAsPPL": 2})["win lsa protection"][0] == "OK" and W(reg={"RunAsPPL": 0})["win lsa protection"] == ("WARN", "RunAsPPL is 0: set it to 1 under Lsa")
      and W(reg={"RunAsPPL": None})["win lsa protection"][0] == "WARN" and W(reg={"RunAsPPL": "gone"})["win lsa protection"] == UNREAD)
check("WDigest: 1 fails, absent passes", W(reg={"WDigestLogonCredential": 1})["win wdigest"] == ("FAIL", "UseLogonCredential is 1: set it to 0 (SecurityProviders\\WDigest)") and W(reg={"WDigestLogonCredential": None})["win wdigest"][0] == "OK"
      and W(reg={"WDigestLogonCredential": "gone"})["win wdigest"] == UNREAD)
check("Credential Guard: off fails, the Lsa value passes, N/A on a DC or when not joined or facts missing", W(reg={"CredGuardPolicy": None})["win credential guard"] == ("WARN", "LsaCfgFlags is not set: turn on Credential Guard Configuration (Device Guard policy)")
      and W(reg={"CredGuardPolicy": None, "CredGuardLsa": 2})["win credential guard"][0] == "OK" and W(reg={"CredGuardPolicy": 0})["win credential guard"][1].startswith("LsaCfgFlags is 0:")
      and W(reg={"CredGuardPolicy": None}, dc=True)["win credential guard"] == ("N/A", H.NOT_HERE) and W(reg={"CredGuardPolicy": None}, joined=False)["win credential guard"] == ("N/A", H.NOT_HERE)
      and W(dc="gone")["win credential guard"] == UNREAD and W(joined="gone")["win credential guard"] == UNREAD and W(reg={"CredGuardPolicy": "gone"})["win credential guard"] == UNREAD)
check("Firewall: profiles that are off, none listed is N/A", W(firewall=[{"name": "Domain", "on": True}, {"name": "Public", "on": False}])["win firewall"] == ("FAIL", "Public off: turn on Windows Defender Firewall for those profiles")
      and W(firewall="gone")["win firewall"] == UNREAD and W(firewall=[])["win firewall"] == UNREAD)
check("RDP NLA: policy off fails, passes when RDP is off, falls back to RDP-Tcp", W(reg={"RdpNlaPolicy": 0})["win rdp nla"][0] == "WARN" and W(reg={"RdpNlaPolicy": 0, "RdpDenyConnections": 1})["win rdp nla"][0] == "OK"
      and W(reg={"RdpNlaPolicy": None, "RdpNlaTcp": 0})["win rdp nla"][0] == "WARN" and W(reg={"RdpNlaPolicy": None, "RdpNlaTcp": 1})["win rdp nla"][0] == "OK"
      and W(reg={"RdpNlaPolicy": 0, "RdpDenyConnections": "gone"})["win rdp nla"] == UNREAD and W(reg={"RdpNlaPolicy": "gone"})["win rdp nla"] == UNREAD)
check("UAC: 0 fails, absent passes", W(reg={"EnableLUA": 0})["win uac"][0] == "FAIL" and W(reg={"EnableLUA": None})["win uac"][0] == "OK" and W(reg={"EnableLUA": "gone"})["win uac"] == UNREAD)
check("guest and reversible encryption", W(policy={"EnableGuestAccount": 1})["win guest"] == ("FAIL", "Guest is enabled: set Accounts: Guest account status to Disabled")
      and W(policy={"ClearTextPassword": 1})["win reversible"][0] == "FAIL" and W(policy={"EnableGuestAccount": "gone"})["win guest"] == UNREAD and W(policy={"ClearTextPassword": "gone"})["win reversible"] == UNREAD)
check("password policy: each weak value named; unread alone is N/A", W(policy={"MinimumPasswordLength": 8, "PasswordComplexity": 0, "PasswordHistorySize": 5})["win password"]
      == ("WARN", "MinimumPasswordLength 8, PasswordComplexity 0, PasswordHistorySize 5: set Account Policies > Password Policy to length 14, complexity on and history 24")
      and W(policy={"PasswordHistorySize": "gone"})["win password"] == UNREAD and W(policy={"PasswordHistorySize": "gone", "MinimumPasswordLength": 8})["win password"][0] == "WARN")
check("lockout: 0 attempts, 4 attempts, short duration and reset; -1 duration is fine", W(policy={"LockoutBadCount": 0})["win lockout"][1].startswith("LockoutBadCount 0:") and W(policy={"LockoutBadCount": 4})["win lockout"][0] == "WARN"
      and W(policy={"LockoutDuration": 10, "ResetLockoutCount": 5})["win lockout"][1].startswith("LockoutDuration 10, ResetLockoutCount 5:") and W(policy={"LockoutDuration": -1})["win lockout"][0] == "OK"
      and W(policy={"LockoutBadCount": "gone"})["win lockout"] == UNREAD)
check("logon auditing: Logon on Success only; a missing GUID is N/A", W(audit={GU("9215"): "Success"})["win audit logon"] == ("WARN", "Logon: set Advanced Audit Policy for Logon/Logoff and Account Logon to the needed Success or Failure")
      and W(audit={GU("9215"): "No Auditing", GU("9216"): "Failure"})["win audit logon"][1].startswith("Logon, Logoff:") and W(audit={GU("9215"): "gone"})["win audit logon"] == UNREAD
      and W(audit={GU("9215"): "gone", GU("9216"): "No Auditing"})["win audit logon"][0] == "WARN")
check("change auditing: Process Creation off; Success and Failure also satisfies a Success need", W(audit={GU("922B"): "No Auditing"})["win audit changes"][1].startswith("Process Creation:")
      and W(audit={GU("922B"): "Success and Failure"})["win audit changes"][0] == "OK")
check("audit text on another language is N/A, not a finding", W(audit={GU("9215"): "Erfolg und Fehler"})["win audit logon"] == UNREAD and W(audit={GU("9215"): "Erfolg und Fehler", GU("9216"): "Success"})["win audit logon"] == UNREAD)
check("Defender: off fails, passive mode passes, unread is N/A", W(defender={"realtime": False})["win defender"] == ("FAIL", "Real-time protection off: turn on Microsoft Defender real-time protection")
      and W(defender={"realtime": False, "mode": "Passive Mode"})["win defender"][0] == "OK" and W(defender="gone")["win defender"] == UNREAD
      and W(defender={"realtime": "gone"})["win defender"] == UNREAD)
check("TLS: an SCHANNEL value of 0xFFFFFFFF counts as on, and so does a negative one; absent follows the build", W(reg={"Tls10Server": 4294967295})["win tls"] == ("WARN", "TLS 1.0 on: set Enabled to 0 under SCHANNEL\\Protocols\\TLS 1.0\\Server")
      and W(reg={"Tls10Server": -1, "Tls11Server": 1})["win tls"][1].startswith("TLS 1.0, TLS 1.1 on:") and W(reg={"Tls10Server": None})["win tls"][0] == "WARN"
      and W(reg={"Tls10Server": None, "Tls11Server": None}, build="26100.1")["win tls"][0] == "OK" and W(reg={"Tls10Server": None}, build="gone")["win tls"] == UNREAD
      and W(reg={"Tls10Server": "gone"})["win tls"] == UNREAD)
check("an empty snapshot answers N/A for every rule, never OK", all(st == "N/A" for _k, st, _m in H.findings(json.dumps({"v": 1}), "", vendor="windows")))
try:
    H.findings("hostname sw1", "", vendor="windows"); check("text that is not JSON is refused", False)
except ValueError:
    check("text that is not JSON is refused", True)
wd, wl = dev("win1", "windows", version="Windows Server 2022 Datacenter 10.0.20348 (20348.5760)"), dev("lin1", "windows", version="Ubuntu 24.04")
check("no snapshot yet: one N/A row saying so", [(r.check, r.status, r.message) for r in A.scan(wd)[1:]] == [("Hardening", "N/A", H.NO_SETTINGS)])
check("a Linux agent device gets no rules", [(r.check, r.status, r.message) for r in A.scan(wl)[1:]] == [("Hardening", "N/A", H.NO_RULES)])
db.set_device_settings(wd, {**GOOD_WIN, "reg": {**GOOD_WIN["reg"], "EnableLUA": 0}}, when=__import__("datetime").datetime(2026, 11, 9, 10, 5, 59))
wrows = {r.check: r for r in A.scan(wd)[1:]}
check("a snapshot: one row per Windows rule, a finding ends (read date time)", len(wrows) == len(WIN.RULES) and wrows["Hardening: UAC off"].status == "FAIL"
      and wrows["Hardening: UAC off"].message == "EnableLUA is 0: set User Account Control: Run all administrators in Admin Approval Mode to Enabled (read 2026-11-09 10:05)"
      and wrows["Hardening: SMBv1 on"].message == "not found", [(r.check, r.message) for r in wrows.values()][:2])
db.set_setting("hardening_off", ["win uac"])
check("a rule switched off has no row", "Hardening: UAC off" not in {r.check for r in A.scan(wd)}); db.set_setting("hardening_off", [])

print("== Settings > Scanning lists the rules under vendor headings")
from ui.settings_pages.scanning import ScanningPage
from PySide6.QtCore import Qt
pg = ScanningPage(); pg.load()
check("every rule, ticked, with its severity, under eight headings", pg.rules.count() == len(H.RULES) + 8 and pg.rules.item(0).text() == "Cisco (IOS, IOS XE, NX-OS, ASA)"
      and pg.rules.item(0).flags() == Qt.ItemFlag.NoItemFlags and pg.rules.item(1).text() == "Telnet allowed on VTY lines  (FAIL)"
      and pg.rules.item(len(H.CISCO) + 1).text() == "FortiGate" and all(it.checkState().name == "Checked" for it in pg._rule_items()) and len(pg._rule_items()) == len(H.RULES))
pg.rules.item(2).setCheckState(Qt.CheckState.Unchecked); pg.save()
check("unticking saves the key, installation-wide", db.get_setting("hardening_off") == ["http"] and "hardening_off" in db.GLOBAL_ONLY)
pg.load()
check("...and loads back unticked", pg.rules.item(2).checkState() == Qt.CheckState.Unchecked and pg.rules.item(1).checkState() == Qt.CheckState.Checked)
db.set_setting("hardening_off", [])
readme = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "README.md"), encoding="utf-8").read()
check("the README says so", "**Configuration hardening:**" in readme and "FortiGate:" in readme and "Palo Alto:" in readme and "Untick rules under Settings > Scanning" in readme)
from core.version import VERSION
check("version 1.14.1", VERSION == "1.14.1")

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
