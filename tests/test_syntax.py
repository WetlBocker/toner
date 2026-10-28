# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Syntax colours in the terminal: the vendor rule sets, the paint path (device-sent colours win), the Settings box, the README.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\syn%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db, syntax
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtWidgets import QApplication
app = QApplication([])

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def kinds(fam, line):
    return [(line[a:b], k) for a, b, k in syntax.spans(fam, line)]

print("== the rule sets")
check("vendors map to a rule set, Cisco-style for the rest and for no device", syntax.family_of("cisco") == "cisco" and syntax.family_of("arista") == "cisco"
      and syntax.family_of("hpe") == "cisco" and syntax.family_of("juniper") == "juniper" and syntax.family_of("paloalto") == "juniper"
      and syntax.family_of("mikrotik") == "mikrotik" and syntax.family_of("fortinet") == "fortinet" and syntax.family_of("windows") == "cisco"
      and syntax.family_of("") == "cisco" and syntax.family_of(None) == "cisco")
k = kinds("cisco", "access-list outside_access_in extended permit ip host AWS_ENDPOINT_1 host YOUR_UPLINK_ADDRESS")
check("Cisco: keywords, permit in green, names left plain", k == [("access-list", "keyword"), ("extended", "keyword"), ("permit", "good"), ("ip", "keyword"), ("host", "keyword"), ("host", "keyword")], k)
k = kinds("cisco", "access-list cryacl extended deny ip 192.168.0.0 255.255.255.0 172.16.4.0 255.255.255.0")
check("...deny in red, addresses and masks as addresses", ("deny", "bad") in k and k.count(("255.255.255.0", "address")) == 2 and ("192.168.0.0", "address") in k, k)
check("...a comment line is one comment", kinds("cisco", "! Access lists are configured to permit creation of tunnels") == [("! Access lists are configured to permit creation of tunnels", "comment")])
check("...a policy number is a number", kinds("cisco", "crypto isakmp policy 201")[-1] == ("201", "number"))
check("...an interface name is one piece, long or short", kinds("cisco", "interface FastEthernet0") == [("interface", "keyword"), ("FastEthernet0", "interface")]
      and kinds("cisco", "Gi1/0/24   notconnect  1   auto")[:2] == [("Gi1/0/24", "interface"), ("notconnect", "bad")])
check("...'no' has its own colour", kinds("cisco", "no ip directed-broadcast (default)")[0] == ("no", "no"))
check("...a device's % error line is red", kinds("cisco", "% Invalid input detected at '^' marker.") == [("% Invalid input detected at '^' marker.", "bad")])
plain = lambda fam, s: all(k == "plain" for _a, _b, k in syntax.spans(fam, s))
check("...a prompt is left alone, whatever its host name holds", plain("cisco", "Switch(config-if)#") and plain("cisco", "router#") and plain("juniper", "user@host> ")
      and plain("mikrotik", "[admin@MikroTik] /ip firewall> ") and plain("fortinet", "FGT (port1) # ") and kinds("cisco", "router# show ip route")[1:] == [("show", "keyword"), ("ip", "keyword"), ("route", "keyword")])
check("...IPv6 and MAC addresses are addresses, a time of day is not", [x for x in kinds("cisco", "2001:db8::1/64 00:11:22:33:44:55 0011.2233.4455 at 10:30:45") if x[1] == "address"]
      == [("2001:db8::1/64", "address"), ("00:11:22:33:44:55", "address"), ("0011.2233.4455", "address")] and ("10:30:45", "address") not in kinds("cisco", "at 10:30:45"))
k = kinds("juniper", "set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24")
check("Juniper: set-style keywords, ge-0/0/0 as an interface, a prefix as an address", ("ge-0/0/0", "interface") in k and ("10.0.0.1/24", "address") in k and k[0] == ("set", "keyword"), k)
check("...braces and semicolons are muted, permit is green", kinds("juniper", "    then { permit; }") == [("then", "keyword"), ("{", "comment"), ("permit", "good"), (";", "comment"), ("}", "comment")])
k = kinds("mikrotik", '/ip firewall filter add chain=input action=drop in-interface=ether1 comment="wan"')
check("MikroTik: the path and the keys before = are keywords, drop is red, ether1 an interface", k[0] == ("/ip firewall filter", "keyword") and ("chain", "keyword") in k and ("drop", "bad") in k and ("ether1", "interface") in k, k)
check("Fortinet: config words, port1 as an interface, accept in green", kinds("fortinet", '    set srcintf "port1"') == [("set", "keyword"), ("srcintf", "keyword"), ("port1", "interface")]
      and kinds("fortinet", "    set action accept")[-1] == ("accept", "good"))
check("a blank line and a plain line mark nothing", syntax.spans("cisco", "   ") == [] and syntax.spans("cisco", "Building configuration...") == [])
t0 = time.perf_counter()
for _ in range(2000):
    syntax.marks("cisco", "access-list cryacl extended deny ip 192.168.0.0 255.255.255.0 172.16.4.0 255.255.255.0")
check("two thousand lines are marked in well under a second", time.perf_counter() - t0 < 1.0, time.perf_counter() - t0)

print("== the terminal paints with them")
from ui.terminal import TerminalView, SCHEMES
t = TerminalView(); t.configure(scheme="Dark"); t.set_syntax("cisco"); t.resize(800, 400); t.show()
t.feed(b"interface FastEthernet0\r\n\x1b[31mdeny\x1b[0m permit\r\n")
app.processEvents(); pm = t.grab()
check("it paints", pm.width() > 0)
line = t.screen.buffer[0]; text = "".join(line[i].data or " " for i in range(t.cols)); m = t._marks(text)
check("a default-coloured keyword gets the scheme's syntax colour", t._fg_for(line[0], m[0]).name() == SCHEMES["Dark"]["syntax"]["keyword"] and t._fg_for(line[10], m[10]).name() == SCHEMES["Dark"]["syntax"]["interface"])
l2 = t.screen.buffer[1]; m2 = t._marks("".join(l2[i].data or " " for i in range(t.cols)))
check("a colour the device sent itself is kept, the rest is coloured", t._fg_for(l2[0], m2[0]).name() == SCHEMES["Dark"]["colors"]["red"] and t._fg_for(l2[5], m2[5]).name() == SCHEMES["Dark"]["syntax"]["good"])
check("the marks are remembered per line of text", t._marks(text) is m)
t.configure(scheme="Light")
check("the Light scheme has its own syntax colours", t._fg_for(line[0], m[0]).name() == SCHEMES["Light"]["syntax"]["keyword"] and set(SCHEMES["Light"]["syntax"]) == set(syntax.KINDS))
t.set_syntax(None)
check("switched off, the scheme's text colour is used", t._fg_for(line[0], None) == t.fg and t.syntax is None)

print("== a session pane follows its device and the setting")
import ui.sessions as S
pane = S.SessionPane({"name": "sw", "kind": "ssh", "host": "10.0.0.1", "port": 22, "username": "u", "password": "", "dev": {"vendor": "mikrotik"}, "options": {}, "saved_id": None})
check("a pane for a MikroTik device uses the MikroTik rules", pane.term.syntax == "mikrotik")
pane2 = S.SessionPane({"name": "x", "kind": "serial", "host": "loop://", "port": 0, "username": "", "password": "", "dev": None, "options": {}, "saved_id": None})
check("a serial session with no device uses the Cisco-style rules", pane2.term.syntax == "cisco")
db.set_setting("term_syntax", False); pane.apply_settings(); pane2.apply_settings()
check("Settings > Terminal switches it off for open sessions", pane.term.syntax is None and pane2.term.syntax is None)
db.set_setting("term_syntax", True); pane.apply_settings()
check("...and back on", pane.term.syntax == "mikrotik")

print("== Settings > Terminal")
from ui.settings_pages.appearance import TerminalPage
pg = TerminalPage(); pg.load()
check("the box is ticked by default, with the approved wording", pg.syntax.isChecked() and pg.syntax.text() == "Colour command output by vendor")
pg.syntax.setChecked(False); pg.save()
check("saving keeps the choice, installation-wide", db.get_setting("term_syntax") is False and "term_syntax" in db.GLOBAL_ONLY)
pg.syntax.setChecked(True); pg.save()
readme = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "README.md"), encoding="utf-8").read()
check("the README says so", "Command output is coloured by vendor" in readme and "Settings > Terminal switches it off" in readme)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
