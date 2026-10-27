# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Sessions imported from MobaXterm, PuTTY or SecureCRT are linked to the inventory device with the same name (capitals aside):
# exactly one device and one new session with that name, a session that already has a device keeps it, and the rest is
# listed with its reason. The samples are made up.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "il%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import db, orgs, sessionimport as SI, sessions
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def device(name, host, **kw):
    return db.save_device({**dict(name=name, vendor="cisco", host=host, port=0, platform="cisco_ios", username="netadmin", site="default",
                                  verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None), **kw})
def entry(name, host, kind="ssh", folder=(), **kw):
    return {"kind": kind, "name": name, "folder": list(folder), "host": host, "port": sessions.DEFAULT_PORT[kind], "username": "netadmin",
            "options": {}, **kw}
def by_name():
    return {(s["name"], sessions.path_of(s)): s for s in sessions._sessions_here()}

acero = orgs.create("Acero Charter", "ACERO")
with db.within(acero):
    device("core-sw1", "10.1.1.1")
    device("FW1", "10.1.1.2")
    device("plain", "10.1.1.3")
    with db.connect() as c:                                   # two devices differing only in capitals cannot be saved; an old database may hold them
        c.execute("INSERT INTO devices(name, vendor, host, port, platform, username) VALUES('Twin', 'cisco', '10.1.1.4', 0, 'cisco_ios', '')")
        c.execute("INSERT INTO devices(name, vendor, host, port, platform, username) VALUES('twin', 'cisco', '10.1.1.5', 0, 'cisco_ios', '')")
    device("dc01", "10.1.1.10", vendor="windows", platform="winrm")
    device("console-box", "10.1.1.11")
    device("kiosk", "10.1.1.12")

print("== after an import")
found = SI.Found("MobaXterm", [entry("core-sw1", "10.1.1.1"),                                 # the same name: linked
                               entry("fw1", "10.1.1.2"),                                      # capitals differ: linked to FW1
                               entry("nobody", "10.1.1.99"),                                  # no device with the name
                               entry("Twin", "10.1.1.4"),                                     # two devices have the name
                               entry("dup", "10.2.1.1", folder=["East"]),                     # two imported sessions have the name
                               entry("dup", "10.3.1.1", folder=["West"]),
                               entry("dc01", "10.1.1.10", kind="rdp"),                        # Remote Desktop links too
                               entry("kiosk", "10.1.1.12", kind="vnc"),                       # so does VNC
                               {"kind": "serial", "name": "console-box", "folder": [], "host": "COM3", "port": 0, "username": "", "options": {"baud": 9600}}])
with db.within(acero):
    device("dup", "10.2.1.1")
    r = SI.save(found)
    check("save() says which sessions it added", r["added"] == 9 and len(r["ids"]) == 9 and all(isinstance(i, int) for i in r["ids"]), r)
    link = SI.link_devices(r["ids"])
    s = by_name()
check("the session with a device's name is linked to it", s[("core-sw1", "")]["device"] == "core-sw1")
check("capitals are ignored, and the link holds the device's real name", s[("fw1", "")]["device"] == "FW1")
check("a session with no device of its name is left alone", s[("nobody", "")]["device"] == "")
check("Remote Desktop and VNC sessions link too", s[("dc01", "")]["device"] == "dc01" and s[("kiosk", "")]["device"] == "kiosk")
check("a serial session never does (its editor offers no device)", s[("console-box", "")]["device"] == "")
check("two devices with the name: not linked, with the reason", s[("Twin", "")]["device"] == "" and "Twin: two inventory devices have this name." in link["unlinked"])
check("two imported sessions with the name: neither is linked, said once", s[("dup", "East")]["device"] == "" and s[("dup", "West")]["device"] == ""
      and link["unlinked"].count("dup: two imported sessions have this name.") == 1, link["unlinked"])
check("the counts: 4 linked, 2 reasons", link["linked"] == 4 and len(link["unlinked"]) == 2, link)

print("== what is left alone")
with db.within(acero):
    sid = sessions.save({"kind": "ssh", "name": "plain", "folder_id": None, "host": "10.9.9.9", "port": 22, "username": "x", "device": "core-sw1", "options": {}})
    before = sessions.get(sid)["device"]
    link2 = SI.link_devices([sid])
    check("a session that already points at a device keeps it", before == "core-sw1" and sessions.get(sid)["device"] == "core-sw1" and link2 == {"linked": 0, "unlinked": []}, link2)
    other = sessions.save({"kind": "ssh", "name": "plain", "folder_id": sessions.ensure_folder_path("Old"), "host": "10.9.9.8", "port": 22, "username": "x", "options": {}})
    link3 = SI.link_devices([other])
    check("one not in this import is never touched, even with a matching name", link3["linked"] == 1 and sessions.get(other)["device"] == "plain"
          and sessions.get(s[("nobody", "")]["id"])["device"] == "", link3)
    again = SI.save(found)
    check("importing the same file again adds no sessions, so there is nothing to link", again["added"] == 0 and again["ids"] == []
          and SI.link_devices(again["ids"]) == {"linked": 0, "unlinked": []}, again)
check("nothing with no ids at all", SI.link_devices([]) == {"linked": 0, "unlinked": []} and SI.link_devices(None) == {"linked": 0, "unlinked": []})

print("== a Shared device from Global")
with db.within(None):
    device("shared-sw", "10.8.0.1", shared=1)
    device("global-only", "10.8.0.2")
beta = orgs.create("Beta Labs", "BETA")
with db.within(beta):
    r = SI.save(SI.Found("PuTTY", [entry("shared-sw", "10.8.0.1"), entry("global-only", "10.8.0.2")]))
    link = SI.link_devices(r["ids"])
    s = by_name()
check("an organization's session links to Global's Shared device of that name, not to one Global keeps to itself",
      s[("shared-sw", "")]["device"] == "shared-sw" and s[("global-only", "")]["device"] == "" and link["linked"] == 1, (link, {k: v["device"] for k, v in s.items()}))
with db.within(beta):
    r = SI.save(SI.Found("PuTTY", [entry("core-sw1", "10.1.1.1")]))
    link = SI.link_devices(r["ids"])
    s = by_name()
check("another organization's device is not seen: names are matched in the session's own organization", s[("core-sw1", "")]["device"] == "" and link["linked"] == 0, link)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
