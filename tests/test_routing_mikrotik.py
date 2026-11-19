# Run directly (python tests/test_routing_mikrotik.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database, so nothing on this computer is touched; the router is a stand-in (no network, no SSH).
# MikroTik BGP neighbours: RouterOS v7 (/routing bgp session and connection) and v6 (/routing bgp peer). The v7 samples are MikroTik's own
# documentation; the v6 manual (wiki.mikrotik.com) now redirects to the v7 one, so the v6 sample is that manual's layout from memory.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "rtmt%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingrtmt%d" % int(time.time()))
from core import db
db.init()
import drivers.mikrotik as MK
from drivers import DRIVERS
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

TH = db.thresholds_for({"name": "x", "vendor": "mikrotik", "location": ""})
OPTS = {**db.runtime_options()}

# v7, "/routing/bgp/session print": https://help.mikrotik.com/docs/spaces/ROS/pages/328220/BGP (the same text is at
# https://manual.mikrotik.com/docs/user-guides/routing-and-networking-protocols/unicast/bgp/peering-sessions/)
SESSION = """Flags: E - established
 0 E name="toR2"
     remote.address=192.168.1.2 .as=65532 .id=192.168.1.1 .refused-cap-opt=no
     .capabilities=mp,rr,as4 .afi=ip,ipv6 .messages=43346 .bytes=3635916 .eor=""
     local.address=192.168.1.1 .as=65531 .id=192.168.44.2 .capabilities=mp,rr,gr,as4 .messages=2
     .bytes=71 .eor=""
     output.procid=97 .keep-sent-attributes=no
     .last-notification=ffffffffffffffffffffffffffffffff0015030601
     input.procid=97 .limit-process-routes=500000 ebgp limit-exceeded
     hold-time=3m keepalive-time=1m uptime=4s70ms
"""
# The same page, "BGP unnumbered": a session and the connection it came from (the session is named after the connection, "-1" added)
SESSION_UNNUMBERED = """Flags: E - ESTABLISHED
 0 E name="unnumbered_2-1" instance=v6_test
     remote.address=fe80::de2c:6eff:fec5:a7ff%sfp-sfpplus1 .as=333 .id=203.0.113.2 .capabilities=mp,rr,enhe,gr,as4 .afi=ipv6
     .messages=5181 .bytes=98439 .eor=""
     local.role=ibgp .address=fe80::de2c:6eff:fea4:b42f%sfp-sfpplus1 .as=333 .id=203.0.113.1 .cluster-id=203.0.113.1
     .capabilities=mp,rr,enhe,gr,as4 .afi=ipv6 .messages=5181 .bytes=98439 .eor=""
     output.procid=20 input.procid=20 ibgp multihop=yes hold-time=3m keepalive-time=1m uptime=3d14h20m55s640ms
     last-started=2026-02-12 18:26:59 prefix-count=0
"""
CONN_UNNUMBERED = """Flags: D - DYNAMIC, X - DISABLED, I - INACTIVE
 0   name="unnumbered_2" instance=v6_test
     local.address=sfp-sfpplus1 .default-address=fe80::de2c:6eff:fea4:b42f%sfp-sfpplus1 .role=ibgp
     routing-table=main as=333
"""
# A second session whose cache is kept after it stopped (the page: "Even if the BGP session is not active anymore, the cache can still be
# stored for some time"): the documented layout without the E flag. Not a sample from the page.
SESSION_ONE_DOWN = SESSION + ' 1   name="toR3"\n     remote.address=192.168.1.3 .as=65533 .id=192.168.1.3\n     local.address=192.168.1.1 .as=65531\n     hold-time=3m keepalive-time=1m\n'
# Connections in the layout of the page's "connection print", with the values of its own "add" examples
# (add name=toR2 remote.address=192.168.1.2 ... local.role=ebgp); a range to listen on is from
# https://help.mikrotik.com/docs/spaces/ROS/pages/30474256/Moving+from+ROSv6+to+v7+with+examples (add remote.address=10.155.101.0/24 listen=yes)
def conns(*rows):
    return "Flags: D - DYNAMIC, X - DISABLED, I - INACTIVE\n" + "".join(f' {n} {f:1} name="{name}" instance=i1\n     remote.address={addr} local.role=ebgp\n     routing-table=main as=65531\n'
                                                                       for n, (f, name, addr) in enumerate(rows))
CONN = conns(("", "toR2", "192.168.1.2"))
CONN_TWO = conns(("", "toR2", "192.168.1.2"), ("", "toR3", "192.168.1.3/32"))
CONN_LISTEN = conns(("", "dyn", "10.155.101.0/24 listen=yes"))
# v6, "/routing bgp peer print status": the layout of the retired https://wiki.mikrotik.com/wiki/Manual:Routing/BGP (it redirects to the v7 manual
# now, so this could not be read again: flags "X - disabled, E - established", remote-address=, state= are as that manual had them)
PEERS_V6 = """Flags: X - disabled, E - established
 0 E name="peer1" instance=default remote-address=10.0.0.2 remote-as=65002 tcp-md5-key="" nexthop-choice=default multihop=no route-reflect=no hold-time=3m ttl=default in-filter="" out-filter=""
     address-families=ip default-originate=never remove-private-as=no as-override=no passive=no use-bfd=no remote-id=10.0.0.2 local-address=10.0.0.1 uptime=1d2h3m4s prefix-count=3
     updates-sent=1 updates-received=3 withdrawn-sent=0 withdrawn-received=0 remote-hold-time=3m used-hold-time=3m used-keepalive-time=1m refresh-capability=yes as4-capability=yes state=established
 1   name="peer2" instance=default remote-address=10.0.0.3 remote-as=65003 tcp-md5-key="" nexthop-choice=default multihop=no route-reflect=no hold-time=3m ttl=default in-filter="" out-filter=""
     address-families=ip default-originate=never remove-private-as=no as-override=no passive=no use-bfd=no state=active
 2 X name="old" instance=default remote-address=10.0.0.9 remote-as=65009 tcp-md5-key="" nexthop-choice=default multihop=no route-reflect=no hold-time=3m ttl=default in-filter="" out-filter=""
     address-families=ip default-originate=never remove-private-as=no as-override=no passive=no use-bfd=no state=idle
"""
V6_ONLY = "bad command name session (line 1 column 14)"

print("== the reader, on what the router prints")
check("v7: the documented session is one neighbor, established", MK.bgp_neighbors(SESSION, CONN) == (1, []), MK.bgp_neighbors(SESSION, CONN))
check("v7: an unnumbered session counts by its link-local address; its connection names no address and adds nothing", MK.bgp_neighbors(SESSION_UNNUMBERED, CONN_UNNUMBERED) == (1, []), MK.bgp_neighbors(SESSION_UNNUMBERED, CONN_UNNUMBERED))
check("v7: a session without the E flag is down, named by its address", MK.bgp_neighbors(SESSION_ONE_DOWN, CONN_TWO) == (2, ["192.168.1.3"]), MK.bgp_neighbors(SESSION_ONE_DOWN, CONN_TWO))
check("v7: a connection whose peer never came up has no session at all: it is down all the same", MK.bgp_neighbors(SESSION, CONN_TWO) == (2, ["192.168.1.3"]) and MK.bgp_neighbors("", CONN) == (1, ["192.168.1.2"]), MK.bgp_neighbors(SESSION, CONN_TWO))
check("v7: a range to listen on, and a connection switched off, are no neighbor", MK.bgp_neighbors("", CONN_LISTEN) == (0, []) and MK.bgp_neighbors(SESSION, conns(("", "toR2", "192.168.1.2"), ("X", "off", "192.168.1.9"))) == (1, []))
check("v7: an old cached session beside the live one for the same address is not a neighbor down", MK.bgp_neighbors(SESSION_ONE_DOWN.replace("192.168.1.3", "192.168.1.2"), CONN) == (1, []))
check("an item with a comment (RouterOS prints it first, after ;;;) is still read", MK.bgp_neighbors(SESSION.replace(' 0 E name="toR2"', ' 0 E ;;; uplink to R2, as=65532\n     name="toR2"'), CONN.replace(' 0   name="toR2"', ' 0   ;;; uplink\n     name="toR2"')) == (1, [])
      and MK.bgp_neighbors("", CONN.replace(' 0   name="toR2"', ' 0   ;;; uplink\n     name="toR2"')) == (1, ["192.168.1.2"]))
check("v6: established by flag and state; the peer that is not is named; the disabled one is left out", MK.bgp_neighbors(PEERS_V6) == (2, ["10.0.0.3"]), MK.bgp_neighbors(PEERS_V6))
check("nothing to read gives nothing", MK.bgp_neighbors("") == (0, []) and MK.bgp_neighbors(V6_ONLY, "bad command name connection") == (0, []))

print("== a whole run")
class Conn:
    def __init__(self, table): self.t = table; self.sent = []
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def send_command(self, cmd, **kw):
        self.sent.append(cmd)
        return self.t.get(cmd, "bad command name")
MT = {"/system resource print": "                   uptime: 3w2d4h5m6s\n                  version: 7.11.2 (stable)\n               free-memory: 256.0MiB\n              total-memory: 1024.0MiB\n                 cpu-load: 35%\n               board-name: RB5009UG+S+\n",
      "/interface print terse": " 0  R  name=ether1 default-name=ether1 type=ether mtu=1500\n"}
S7, C7, P6 = "/routing bgp session print", "/routing bgp connection print", "/routing bgp peer print status"
def run(table):
    d = {"name": "t", "vendor": "mikrotik", "host": "10.0.0.1", "username": "u", "platform": "", "password": "p"}
    drv = DRIVERS["mikrotik"](d, TH, OPTS)
    conn = Conn({**MT, **table})
    drv.connect = lambda: conn
    return {r.check: r for r in drv.run()}, conn.sent
row = lambda r: (r["bgp"].status, r["bgp"].value, r["bgp"].message) if "bgp" in r else None

r, sent = run({S7: SESSION, C7: CONN})
check("v7, all up: OK, 1/1 established", row(r) == ("OK", "1/1 established", ""), row(r))
check("v7 is not asked the v6 command", P6 not in sent and S7 in sent and C7 in sent, sent)
r, _ = run({S7: SESSION_ONE_DOWN, C7: CONN_TWO})
check("v7, one down: FAIL naming it", row(r) == ("FAIL", "1/2 established", "down: 192.168.1.3"), row(r))
r, _ = run({S7: SESSION, C7: CONN_TWO})
check("v7, a peer that never came up: FAIL naming it", row(r) == ("FAIL", "1/2 established", "down: 192.168.1.3"), row(r))
r, _ = run({S7: "", C7: CONN_LISTEN})
check("v7, BGP set up with no neighbors warns", row(r) == ("WARN", "no neighbors", "BGP is running but has no neighbors"), row(r))
r, _ = run({S7: "", C7: ""})
check("v7, nothing set up: an N/A row that says so", row(r) == ("N/A", "not configured", "BGP is not configured on this device"), row(r))
r, sent = run({S7: V6_ONLY, P6: PEERS_V6})
check("v6: the peer menu is read instead; one of two down", row(r) == ("FAIL", "1/2 established", "down: 10.0.0.3") and C7 not in sent, (row(r), sent))
r, _ = run({S7: V6_ONLY, P6: PEERS_V6.replace(' 1   name="peer2"', ' 1 E name="peer2"').replace("state=active", "state=established")})
check("v6, all up: OK", row(r) == ("OK", "2/2 established", ""), row(r))
r, _ = run({S7: V6_ONLY, P6: "Flags: X - disabled, E - established\n"})
check("v6, no peers: N/A", row(r) == ("N/A", "not configured", "BGP is not configured on this device"), row(r))
r, _ = run({})
check("a router without the routing package (bad command name): N/A", row(r) == ("N/A", "not configured", "BGP is not configured on this device"), row(r))
check("the other rows are still there", {"cpu", "memory", "uptime", "firmware", "interfaces", "ospf"} <= set(r), sorted(r))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
