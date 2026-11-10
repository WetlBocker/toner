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

print("== the rows a scan adds")
def dev(name, vendor, platform="", version=""):
    d = {"name": name, "vendor": vendor, "host": "10.0.0.9", "platform": platform, "enabled": 1}
    d["id"] = db.save_device(d)
    if version: db.set_software(d, {"version": version})
    return db.find_device(name)
sw1, sw2, fw, pan, mt = dev("sw1", "cisco", "cisco_ios"), dev("sw2", "cisco", "cisco_xe"), dev("edge-fw", "fortinet"), dev("pan", "paloalto"), dev("mt", "mikrotik")
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
backup.store("pan", BAD_IOS, mask=True)
check("a backup that is not the vendor's format: one N/A row saying so", [(r.check, r.status, r.message) for r in A.scan(pan)[1:]] == [("Hardening", "N/A", "The backup could not be read as a PAN-OS configuration.")])
db.set_setting("hardening_off", [k for k, *_ in H.RULES])
check("every rule off: no hardening rows at all", len(A.scan(sw1)) == 1 and len(A.scan(fw)) == 1)
db.set_setting("hardening_off", ["telnet"])
check("one rule off: its row is missing", "Hardening: Telnet allowed on VTY lines" not in {r.check for r in A.scan(sw1)} and len(A.scan(sw1)) == len(H.CISCO))
db.set_setting("hardening_off", []); db.set_setting("scan_enabled", True)
from core import display
check("exports keep a rule row's name as worded", display.check_name("Hardening: No NTP server") == "Hardening: No NTP server")

print("== Settings > Scanning lists the rules under vendor headings")
from ui.settings_pages.scanning import ScanningPage
from PySide6.QtCore import Qt
pg = ScanningPage(); pg.load()
check("every rule, ticked, with its severity, under three headings", pg.rules.count() == len(H.RULES) + 3 and pg.rules.item(0).text() == "Cisco (IOS, IOS XE, NX-OS, ASA)"
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
