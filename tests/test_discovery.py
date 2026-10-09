# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import asyncio, os, socket, sys, threading, time
pass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\dc%d.db" % int(time.time())
from core import db, discovery, snmp, vendors
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

print("== target parsing")
check("single, cidr, range, list", discovery.targets("127.0.0.1") == ["127.0.0.1"] and len(discovery.targets("10.0.0.0/30")) == 2 and discovery.targets("10.0.0.5-7") == ["10.0.0.5", "10.0.0.6", "10.0.0.7"] and discovery.targets("10.0.0.1, 10.0.0.1 10.0.0.2") == ["10.0.0.1", "10.0.0.2"], discovery.targets("10.0.0.0/30"))
for bad_t in ("", "10.0.0.9-3", "10.0.0.0/8", "not a host!"):
    try: discovery.targets(bad_t); check(f"rejects '{bad_t}'", False)
    except ValueError: check(f"rejects '{bad_t}'", True)
try: discovery.targets("10.0.0.0/19"); check("limits the size of one scan", False)
except ValueError as e: check("limits the size of one scan", "at most" in str(e) or "too large" in str(e), e)

print("== hints")
check("banner keywords", discovery.hint_from_text("SSH-2.0-Cisco-1.25") == "cisco" and discovery.hint_from_text("SSH-2.0-ROSSSH") == "mikrotik" and discovery.hint_from_text("FortiGate-60F") == "fortinet" and discovery.hint_from_text("nothing known") == "")
check("enterprise numbers", snmp.vendor_from_oid("1.3.6.1.4.1.9.1.1745") == "cisco" and snmp.vendor_from_oid("1.3.6.1.4.1.2636.1.1.1.2.21") == "juniper" and snmp.vendor_from_oid("1.3.6.1.4.1.14988.1") == "mikrotik" and snmp.vendor_from_oid("1.3.6.1.4.1.99999") == "")
check("supported vendor kept, others become generic SNMP only when SNMP answered", discovery.netcheck_vendor("cisco", False) == "cisco" and discovery.netcheck_vendor("dell", True) == "snmp" and discovery.netcheck_vendor("dell", False) == "" and discovery.netcheck_vendor("", False) == "")
check("platform guesses", discovery.guess_platform("cisco", "Cisco IOS XE Software") == "cisco_xe" and discovery.guess_platform("cisco", "Cisco NX-OS(tm) n9000") == "cisco_nxos" and discovery.guess_platform("cisco", "Cisco IOS Software, C2960") == "cisco_ios" and discovery.guess_platform("hpe", "ArubaOS-CX 10.08") == "aruba_aoscx" and discovery.guess_platform("hpe", "ProCurve J9") == "aruba_osswitch" and discovery.guess_platform("juniper", "x") == "juniper_junos")

print("== probing local fake devices")
def banner_server(text):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(10)
    def go():
        while True:
            try:
                c, _ = s.accept(); c.sendall(text.encode()); time.sleep(0.05); c.close()
            except OSError: return
    threading.Thread(target=go, daemon=True).start(); return s.getsockname()[1]
ssh_port = banner_server("SSH-2.0-Cisco-1.25\r\n")
r = discovery.probe("127.0.0.1", (), ports=(ssh_port,), ssh_ports=(ssh_port,), tls_ports=())
check("open port + SSH banner -> vendor hint", r and r["ports"] == [ssh_port] and r["banner"] == "SSH-2.0-Cisco-1.25" and r["vendor"] == "cisco" and r["platform"] == "cisco_ios", r)
dead = socket.socket(); dead.bind(("127.0.0.1", 0)); dp = dead.getsockname()[1]; dead.close()
check("nothing answering -> None", discovery.probe("127.0.0.1", (), ports=(dp,), timeout=0.3) is None)
r = discovery.probe("127.0.0.1", (), ports=(dp, ssh_port), ssh_ports=(ssh_port,), tls_ports=())
check("only open ports are listed", r["ports"] == [ssh_port])

# SNMP agent
PORT = 17100 + os.getpid() % 500
def agent():
    from pysnmp.entity import engine, config
    from pysnmp.entity.rfc3413 import cmdrsp, context
    from pysnmp.carrier.asyncio.dgram import udp
    async def main():
        eng = engine.SnmpEngine()
        config.add_transport(eng, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode(("127.0.0.1", PORT)))
        config.add_v1_system(eng, "area", "secretcomm")
        config.add_vacm_user(eng, 2, "area", "noAuthNoPriv", (1, 3, 6, 1, 2, 1), (1, 3, 6, 1, 2, 1))
        ctx = context.SnmpContext(eng)
        cmdrsp.GetCommandResponder(eng, ctx); cmdrsp.NextCommandResponder(eng, ctx); cmdrsp.BulkCommandResponder(eng, ctx)
        eng.transport_dispatcher.job_started(1); ready.set()
        while not stop.is_set(): await asyncio.sleep(0.1)
        eng.close_dispatcher()
    asyncio.run(main())
ready, stop = threading.Event(), threading.Event()
threading.Thread(target=agent, daemon=True).start(); ready.wait(10); time.sleep(0.4)
real_client = snmp.Client
snmp.Client = lambda host, port, creds, **k: real_client(host, PORT, creds, **k)      # the agent is not on 161
r = discovery.probe("127.0.0.1", ("public", "wrong", "secretcomm"), ports=(dp,), timeout=0.3)
check("SNMP community found among several, identity read", r and r["snmp"] and r["community"] == "secretcomm" and r["descr"] and r["vendor"] == "snmp", r)
check("SNMP-only host is found even with no open TCP port", r["ports"] == [])
snmp.Client = real_client

print("== scanning a list in parallel")
found = []
res = discovery.scan(["127.0.0.1", "127.0.0.2"], (), ports=(ssh_port,), ssh_ports=(ssh_port,), tls_ports=(), on_found=found.append)
check("scan returns the live addresses sorted", [r["ip"] for r in res] == ["127.0.0.1"] and found, res)
cancel = threading.Event(); cancel.set()
res = discovery.scan(["127.0.0.1"] * 3, (), ports=(ssh_port,), ssh_ports=(ssh_port,), tls_ports=(), cancel=cancel)
check("cancel stops early", len(res) <= 1)

print("== adding to the inventory")
db.save_device(dict(name="existing", vendor="cisco", host="127.0.0.9", port=0, platform="cisco_ios", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))
check("known addresses are recognised", "127.0.0.9" in discovery.known_hosts())
fid = db.create_folder("Discovered")
rows = [{"ip": "10.1.0.1", "name": "sw-a", "vendor": "cisco", "platform": "cisco_xe", "snmp": True, "community": "comm1", "descr": "Cisco IOS XE"},
        {"ip": "10.1.0.2", "name": "existing", "vendor": "juniper", "platform": "juniper_junos", "snmp": False},
        {"ip": "10.1.0.3", "name": "mystery", "vendor": "", "snmp": False},
        {"ip": "10.1.0.4", "name": "box", "vendor": "snmp", "snmp": True, "community": "comm2"}]
added, skipped = discovery.add_to_inventory(rows, folder_id=fid, location="Lab", tags="new, discovered")
check("devices created; name clashes get a suffix; unknown vendors are skipped with a reason", added == ["sw-a", "existing-2", "box"] and len(skipped) == 1 and "10.1.0.3" in skipped[0], (added, skipped))
d = {x["name"]: x for x in db.list_devices()}
check("folder, location, tags, platform and notes applied", d["sw-a"]["folder_id"] == fid and d["sw-a"]["location"] == "Lab" and d["sw-a"]["tags"] == "new, discovered" and d["sw-a"]["platform"] == "cisco_xe" and d["sw-a"]["details"] == "Cisco IOS XE")
check("the SNMP community found is kept as the device's secret, not in the database", STORE.get(("netcheck", "sw-a:snmp")) == "comm1" and "comm1" not in str(d["sw-a"]) and d["sw-a"]["snmp"])
check("generic SNMP devices get SNMP settings", d["box"]["snmp"] and STORE.get(("netcheck", "box:snmp")) == "comm2")
stop.set()
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
