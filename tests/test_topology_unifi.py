# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The topology's UniFi source: a console's device list as neighbour rows, with the login or the API key, and the status line of a
# discovery that found nothing.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "topounifi%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingtopounifi%d" % int(time.time()))
from core import db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
import requests
from core import topology

GW, SW, AP = "aa:00:00:00:00:01", "aa:00:00:00:00:02", "aa:00:00:00:00:03"
DEVICES = [
    {"name": "Gateway", "mac": GW, "ip": "10.0.0.1", "type": "udm", "model": "UDMPRO",
     "port_table": [{"port_idx": 9, "up": True, "speed": 10000}],
     "lldp_table": [{"chassis_id": SW, "port_id": "Port 24", "local_port_idx": 9, "local_port_name": "Port 9"}]},
    {"name": "Closet switch", "mac": SW.upper(), "ip": "10.0.0.2", "type": "usw", "model": "US24P250",
     "port_table": [{"port_idx": 24, "up": True, "speed": 10000}, {"port_idx": 3, "up": True, "speed": 1000}, {"port_idx": 5, "up": True, "speed": 100},
                    {"port_idx": 7, "up": False, "speed": 0}],
     "lldp_table": [{"chassis_id": GW, "port_id": "eth8", "local_port_idx": 24, "local_port_name": "Port 24"},
                    {"chassis_id": AP, "port_id": AP, "local_port_idx": 3},                                     # no port name: 'Port 3'
                    {"chassis_id": "00:11:22:33:44:55", "port_id": "Gi1/0/5", "chassis_descr": "Cisco IOS Software", "local_port_idx": 5, "local_port_name": "Port 5"},
                    {"chassis_id": "", "port_id": "", "local_port_idx": 7}]},                                    # nothing known of the far end: left out
    {"name": "Lobby AP", "mac": AP, "ip": "10.0.0.3", "type": "uap", "model": "U7PG2",
     "lldp_table": [{"chassis_id": SW, "port_id": "Port 3", "local_port_idx": 0, "local_port_name": "eth0"}]},
    "junk",
]

print("== a console's device list as neighbour rows")
rows = topology.parse_unifi(DEVICES, "udm", "10.0.0.1")
by = {(r["device"], r["local_port"]): r for r in rows}
check("one row per neighbour with something known of it", len(rows) == 5, str(len(rows)))
check("the device at the entry's address is the entry", by[("udm", "Port 9")]["remote_name"] == "Closet switch" and by[("Closet switch", "Port 24")]["remote_name"] == "udm")
check("a UniFi neighbour's port is the one it lists itself, not what it announced",
      by[("udm", "Port 9")]["remote_port"] == "Port 24" and by[("Closet switch", "Port 24")]["remote_port"] == "Port 9" and by[("Closet switch", "Port 3")]["remote_port"] == "eth0")
check("a port with no name is named by its number", ("Closet switch", "Port 3") in by)
check("a neighbour the console does not manage: its MAC, its announced port and description",
      (by[("Closet switch", "Port 5")]["remote_name"], by[("Closet switch", "Port 5")]["remote_port"], by[("Closet switch", "Port 5")]["remote_desc"]) == ("00:11:22:33:44:55", "Gi1/0/5", "Cisco IOS Software"))
check("the port's state and speed ride along", (by[("udm", "Port 9")]["local_up"], by[("udm", "Port 9")]["local_speed"]) == (True, "10 Gbps")
      and by[("Closet switch", "Port 5")]["local_speed"] == "100 Mbps" and by[("Lobby AP", "eth0")]["local_up"] is None)
check("the neighbour's address is the console's", by[("Closet switch", "Port 3")]["remote_addr"] == "10.0.0.3")
check("no address match: the only gateway is the entry", {r["device"] for r in topology.parse_unifi(DEVICES, "udm", "10.9.9.9")} == {"udm", "Closet switch", "Lobby AP"})
two = [dict(DEVICES[0]), dict(DEVICES[0], mac="aa:00:00:00:00:09", name="Second gateway", lldp_table=[])]
check("two gateways and no address match: none is the entry", "udm" not in {r["device"] for r in topology.parse_unifi(two, "udm", "10.9.9.9")})
check("nothing listed: no rows", topology.parse_unifi(None, "udm") == [] and topology.parse_unifi([{"name": "x"}], "udm") == [])

lag = [{"name": "A", "mac": GW, "type": "usw", "lldp_table": [{"chassis_id": SW, "port_id": "Port 7", "local_port_idx": 1, "local_port_name": "Port 1"},
                                                              {"chassis_id": SW, "port_id": "Port 8", "local_port_idx": 2, "local_port_name": "Port 2"}]},
       {"name": "B", "mac": SW, "type": "usw", "lldp_table": [{"chassis_id": GW, "port_id": "Port 1", "local_port_idx": 7, "local_port_name": "Port 7"},
                                                              {"chassis_id": GW, "port_id": "Port 2", "local_port_idx": 8, "local_port_name": "Port 8"}]}]
_n, links = topology.build_graph(topology.parse_unifi(lag, "console"))
check("two cables between two switches are two links, each seen from both ends",
      sorted((l["a_port"], l["b_port"]) for l in links) == [("Port 1", "Port 7"), ("Port 2", "Port 8")] and all(l["both"] for l in links), str(links))

print("== the map")
db.save_device(dict(name="udm", vendor="unifi_network", host="10.0.0.1", port=0, platform="", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))
nodes, links = topology.build_graph(rows)
check("one link per cable, the UniFi ones seen from both ends", len(links) == 3 and sum(l["both"] for l in links) == 2, str(links))
check("the entry is the inventory's tile; the devices it manages are their own", nodes["udm"]["inventory"] and not nodes["Closet switch"]["inventory"])
roles = topology.roles_for(nodes, rows)
check("each tile is what the console says it is", (roles["udm"], roles["Closet switch"], roles["Lobby AP"]) == ("router", "switch", "ap"), str(roles))
check("a neighbour that says it is a WLAN access point is one", topology.role_of("x", "", "WLAN Access Point, Bridge") == "ap")
check("a UniFi console is asked for neighbours", [d["name"] for d in topology.devices()] == ["udm"])

print("== asking the console")
class Resp:
    def __init__(self, data, code=200): self.data, self.status_code = data, code
    def json(self): return {"data": self.data}
    def raise_for_status(self):
        if self.status_code >= 400: raise requests.HTTPError(f"{self.status_code} error")
class Session:
    made, refuse = [], False
    def __init__(self): self.headers, self.proxies, self.verify, self.calls, self.verifies = {}, {}, True, [], []; Session.made.append(self)
    def post(self, url, **k): self.verifies.append(k.get("verify")); self.calls.append(("POST", url, k.get("json"))); return Resp([])
    def get(self, url, **k):
        self.verifies.append(k.get("verify")); self.calls.append(("GET", url, None))
        if Session.refuse: return Resp([], 401)
        return Resp([{"name": "default", "desc": "Main office"}, {"name": "abc123", "desc": "Branch"}] if url.endswith("self/sites") else DEVICES)
requests.Session = Session
STORE.clear()
dev = db.list_devices()[0]
from core import profiles
profiles.secret = lambda d, kind="main": "the-secret"
l2, l3 = topology.discover(dev)
s = Session.made[-1]
check("the API key goes in its header, with no login", s.headers.get("X-API-KEY") == "the-secret" and not [c for c in s.calls if c[0] == "POST"])
check("the default site's device list is read", [c[1] for c in s.calls] == ["https://10.0.0.1/proxy/network/api/self/sites", "https://10.0.0.1/proxy/network/api/s/default/stat/device"])
check("its rows come back as API rows of their own devices", len(l2) == 5 and l3 == [] and {r["via"] for r in l2} == {"API"} and {r["device"] for r in l2} == {"udm", "Closet switch", "Lobby AP"})
l2, _ = topology.discover({**dev, "site": "Branch"})
check("a site is picked by its name", Session.made[-1].calls[-1][1].endswith("/s/abc123/stat/device"))
l2, _ = topology.discover({**dev, "site": "*"})
check("* reads every site", len([c for c in Session.made[-1].calls if "stat/device" in c[1]]) == 2 and len(l2) == 10)
try:
    topology.discover({**dev, "site": "nowhere"}); said = ""
except ValueError as e:
    said = str(e)
check("an unknown site says which exist", said == "site 'nowhere' not found; this key can see: Main office (default), Branch (abc123)", said)
Session.refuse = True
rows_, _l3, errors = topology.collect([dev])
check("a console that refuses the key says so, without the key", rows_ == [] and errors == {"udm": "this API key may not read self/sites (HTTP 401)"}, str(errors))
Session.refuse = False
l2, _ = topology.discover({**dev, "vendor": "unifi", "username": "admin", "port": 8443})
s = Session.made[-1]
check("the console login signs in first and out after", s.calls[0] == ("POST", "https://10.0.0.1:8443/api/auth/login", {"username": "admin", "password": "the-secret"})
      and s.calls[-1][:2] == ("POST", "https://10.0.0.1:8443/api/auth/logout") and "X-API-KEY" not in s.headers and len(l2) == 5)

check("every call says whether to verify the certificate (a session-wide setting loses to REQUESTS_CA_BUNDLE)", s.verifies == [False] * 4, s.verifies)
print("== the status line of a discovery that found nothing")
from PySide6.QtWidgets import QApplication
app = QApplication([])
from ui import topology as TU
tab = TU.TopologyTab()
tab.n, tab.total = 2, 2
tab._step("udm")
check("while asking: how many answered", tab.status.text() == "3 of 2 answered...")
tab._done([], [], {"udm": "this API key may not read self/sites (HTTP 401)"})
check("nothing found: the line says so and names what failed", "0 link(s) between 0 device(s)." in tab.status.text()
      and "1 device(s) failed: udm: this API key may not read self/sites (HTTP 401)" in tab.status.text(), tab.status.text())
tab._done(l2, [], {})
check("a discovery with neighbours draws them", "3 link(s) between 4 device(s)." in tab.status.text() and len(tab.l2.boxes) == 4, tab.status.text())

print("== the card of a clicked device")
from PySide6.QtWidgets import QLabel
tab.resize(1400, 900); tab.show(); app.processEvents()
tab.endpoints.set("each"); app.processEvents()
card = tab.l2.card
def fits(card):
    grid = [card.grid.itemAt(i).widget() for i in range(card.grid.count())]
    return (card.height() == card.layout().totalHeightForWidth(card.width()) and all(b.width() >= b.sizeHint().width() for b in card._buttons)
            and all(b.geometry().right() <= card.width() for b in card._buttons) and all(w.isVisibleTo(card) for w in grid)
            and len([w for w in card.findChildren(QLabel) if w.isVisibleTo(card)]) == len(grid) + 4)      # the title, the role, the links' heading and list
tab.select("udm", "l2"); app.processEvents()
check("an inventory device: five buttons with their words whole, on a card as tall as its contents",
      [b.text() for b in card._buttons] == ["Details", "SSH", "Run checks", "Ping", "Put on the top tier"] and fits(card), (card.size(), [(b.text(), b.width(), b.sizeHint().width()) for b in card._buttons]))
card.setFixedWidth(290); card._fit(); app.processEvents()       # too narrow for one row, wide enough for the longest button
check("buttons that do not fit one row wrap onto more lines instead of being cut", len({b.geometry().top() for b in card._buttons}) >= 2
      and all(b.width() >= b.sizeHint().width() and b.geometry().right() <= card.width() for b in card._buttons),
      [(b.text(), b.width(), b.sizeHint().width(), b.geometry().right(), card.width()) for b in card._buttons])
card.setFixedWidth(340); card._fit()
tab.select("Lobby AP", "l2")                                 # no events run: the card is rebuilt while it is open
check("another device on the open card: its own rows only, and the card fits again", card.title.text() == "Lobby AP" and fits(card)
      and [b.text() for b in card._buttons] == ["Add to inventory...", "Put on the top tier"], (card.size(), card.layout().totalHeightForWidth(card.width())))
tab.select("udm", "l2")
check("...and back", fits(card) and len(card._buttons) == 5, card.size())

print("== grabbing the canvas")
from PySide6.QtCore import QPoint, Qt
from PySide6.QtTest import QTest
view = tab.l2
view.card.hide(); app.processEvents()
vp = view.viewport()
empty = next(QPoint(x, y) for y in range(20, vp.height() - 20, 15) for x in range(60, vp.width() - 20, 15) if view.itemAt(QPoint(x, y)) is None)
box = view.boxes["udm"]
where = lambda: view.mapFromScene(box.scenePos())
before, at = where(), box.pos()
check("the whole map shows, so there would be nothing to scroll without room of its own", view.sceneRect().contains(view.scene().sceneRect())
      and view.sceneRect().width() > view.scene().sceneRect().width() + 2000)
QTest.mousePress(vp, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, empty)
QTest.mouseMove(vp, empty + QPoint(60, 40)); QTest.mouseMove(vp, empty + QPoint(120, 80))
QTest.mouseRelease(vp, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, empty + QPoint(120, 80)); app.processEvents()
moved = where() - before
check("dragging empty canvas moves the map with the mouse", abs(moved.x() - 120) <= 3 and abs(moved.y() - 80) <= 3, (moved.x(), moved.y()))
check("...and the devices stay where they were on it", box.pos() == at)
check("no scroll bars: the canvas is moved by hand", view.horizontalScrollBarPolicy() == Qt.ScrollBarPolicy.ScrollBarAlwaysOff and view.verticalScrollBarPolicy() == Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
view.fit(); app.processEvents()
check("Fit brings the whole map back", vp.rect().contains(where()) and all(vp.rect().contains(view.mapFromScene(b.scenePos())) for b in view.boxes.values()))
check("Save as... still draws the map alone, not the room round it", view.scene().sceneRect().width() < 3000)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
