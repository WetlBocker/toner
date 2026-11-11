# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The eleven adjustments of 2026-11-01 (the second list): the topology saved as draw.io and Visio, the MTR header's rule the whole
# width, Panel opacity, the Subnet Calculator (IPv4 / IPv6, the Split tree, a public address looked up at ipstack), the maker's mark
# beside a device's name and the pane's status line, the shorter SCP text, Find Devices' headings and drop-downs, the API Tester's
# cells, Reset buttons, and the TLS audit's rows choosing what is shown above them.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import io, json, os, sys, time, zipfile
import xml.dom.minidom as minidom
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "adjust2_%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingadjust2_%d" % int(time.time()))
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
from datetime import datetime
from drivers.base import Result
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QLineEdit, QMessageBox, QStyleOptionViewItem
app = QApplication([])
from ui.widgets import layout_at, widget_at       # not lay.itemAt(i).widget(): see ui/widgets.py _let_go
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
for i, (n, v) in enumerate((("PaloVM", "paloalto"), ("core-sw1", "cisco"), ("edge-fw", "fortinet"))):
    db.save_device(dict(name=n, vendor=v, host=f"10.0.0.{i + 1}", port=0, platform="cisco_ios" if v == "cisco" else "", username="u", site="",
                        verify_ssl=0, ha_expected=0, enabled=1, location="Chicago", details="", folder_id=None))
db.save_run([Result("PaloVM", "cpu", "OK", "36%", numeric=36.0), Result("PaloVM", "disk", "OK", "43%", numeric=43.0), Result("core-sw1", "cpu", "WARN", "88%", numeric=88.0)])
for k, v in dict(theme="Aurora", look="Soft", panels="Raised").items():
    db.set_setting(k, v)
import app as A
A.apply_look(app)
from core import iplookup, subnets, topoexport, topology
from ui import theme, themes

print("== the Subnet Calculator's sums")
f = dict(subnets.facts(subnets.parse("192.168.1.10/24")))
check("IPv4 facts: network, mask, wildcard, broadcast, range, hosts, private", f["Network"] == "192.168.1.0/24" and f["Wildcard"] == "0.0.0.255" and f["Broadcast"] == "192.168.1.255"
      and f["Host range"] == "192.168.1.1 - 192.168.1.254" and f["Usable hosts"] == "254" and f["Private"] == "yes" and f["Public"] == "no", f)
f6 = dict(subnets.facts(subnets.parse("2001:db8::1/64")))
check("IPv6 facts: addresses, range, the kind of address", f6["Addresses"] == f"{2 ** 64:,}" and f6["Range"].startswith("2001:db8::") and "Kind" in f6, f6)
check("a public address is told from a private one", subnets.is_public(subnets.parse("8.8.8.8/32").ip) and not subnets.is_public(subnets.parse("10.1.1.1/8").ip)
      and not subnets.is_public(subnets.parse("fe80::1/64").ip) and subnets.is_public(subnets.parse("2606:4700::1111/128").ip))
check("version() says 4, 6 or None", subnets.version("1.2.3.4") == 4 and subnets.version("::1") == 6 and subnets.version("nope") is None)
kids = subnets.children(subnets.parse("10.0.0.0/24").network, 26)
check("a /24 splits into four /26s", [str(k) for k in kids] == ["10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26"])
check("the Split tree's row: network, first, last, hosts", subnets.row(kids[1])[:4] == ("10.0.0.64/26", "10.0.0.65", "10.0.0.126", "62"), subnets.row(kids[1]))
check("a /31 keeps both addresses; a /32 one", subnets.row(subnets.parse("10.0.0.0/31").network)[3] == "2" and subnets.row(subnets.parse("10.0.0.7/32").network)[:4] == ("10.0.0.7/32", "10.0.0.7", "10.0.0.7", "1"))
for text, prefix, why in (("10.0.0.0/24", 24, "not longer"), ("10.0.0.0/24", 33, "past /32"), ("10.0.0.0/8", 24, "too many at once")):
    try:
        subnets.children(subnets.parse(text).network, prefix); bad_split = False
    except ValueError:
        bad_split = True
    check(f"a split that is {why} is refused", bad_split)

print("== where a public address is (ipstack)")
check("the key lives in the vault", not iplookup.has_key() and (iplookup.set_key("abc123") or iplookup.get_key() == "abc123") and ("ipstack" in [u for _s, u in STORE]))
check("the default URL carries the address and the key, https first", iplookup.build(iplookup.get_url(), "8.8.8.8", "abc123") == "https://api.ipstack.com/8.8.8.8?access_key=abc123")
RECORD = {"ip": "8.8.8.8", "type": "ipv4", "city": "Mountain View", "region_name": "California", "country_name": "United States", "latitude": 37.4, "longitude": -122.0,
          "connection": {"asn": 15169, "isp": "Google LLC"}, "time_zone": {"id": "America/Los_Angeles", "gmt_offset": -28800}}
calls = []
class FakeReply(io.BytesIO):
    pass
def opener(req, timeout=0):
    calls.append(req.full_url)
    if req.full_url.startswith("https://"):
        return FakeReply(json.dumps({"success": False, "error": {"code": 105, "type": "https_access_restricted", "info": "Access Restricted - Your current Subscription Plan does not support HTTPS Encryption."}}).encode())
    return FakeReply(json.dumps(RECORD).encode())
rec = iplookup.lookup("8.8.8.8", opener=opener)
check("a free key: ipstack refuses https (code 105), so the same question goes over http", rec == RECORD and [u[:5] for u in calls] == ["https", "http:"], calls)
rows = dict(iplookup.fields(rec))
check("the answer as fields: nested keys joined with dots", rows["city"] == "Mountain View" and rows["connection.isp"] == "Google LLC"
      and rows["time_zone.id"] == "America/Los_Angeles", rows)
def refuse(req, timeout=0):
    return FakeReply(json.dumps({"success": False, "error": {"code": 101, "type": "invalid_access_key", "info": "You have not supplied a valid API Access Key."}}).encode())
try:
    iplookup.lookup("8.8.8.8", opener=refuse); said = ""
except iplookup.LookupError_ as e:
    said = str(e)
check("a bad key: ipstack's own words come back", "valid API Access Key" in said and "101" in said, said)
iplookup.set_key("")
try:
    iplookup.lookup("8.8.8.8", opener=opener); nokey = ""
except ValueError as e:
    nokey = str(e)
check("without a key the calculator says where to put one", not iplookup.has_key() and "Settings > Connections" in nokey, nokey)

print("== the topology as draw.io and Visio files")
tiles = [{"id": "sw1", "label": "core-sw1", "sub": "10.0.0.2", "x": 0, "y": 0, "w": 120, "h": 56, "colour": "#237356"},
         {"id": "fw", "label": "edge-fw", "sub": "10.0.0.3", "x": 300, "y": 0, "w": 120, "h": 56, "colour": "#B5452E"},
         {"id": "ap1", "label": "ap1 & co", "sub": "", "x": 150, "y": 200, "w": 110, "h": 56, "colour": "#8857AE"}]
links = [{"a": "sw1", "b": "fw", "label_a": "Gi1/0/1", "label_b": "port1", "colour": "#8d9ea8", "dashed": False, "width": 2},
         {"a": "sw1", "b": "ap1", "label_a": "Gi1/0/5", "label_b": "", "colour": "#E79B4B", "dashed": True, "width": 2}]
x = topoexport.drawio_xml("Layer 2", tiles, links)
doc = minidom.parseString(x)
cells = doc.getElementsByTagName("mxCell")
vert = [c for c in cells if c.getAttribute("vertex") == "1" and c.getAttribute("parent") == "1"]
edges = [c for c in cells if c.getAttribute("edge") == "1"]
labels = [c for c in cells if c.getAttribute("connectable") == "0"]
check("draw.io: a box per device in its role colour, a line per link, a label at each named end", len(vert) == 3 and len(edges) == 2 and len(labels) == 3
      and "fillColor=#237356" in vert[0].getAttribute("style") and "dashed=1" in edges[1].getAttribute("style") and "ap1 &amp; co" in x, (len(vert), len(edges), len(labels)))
check("draw.io: the lines join the boxes by id", edges[0].getAttribute("source") == vert[0].getAttribute("id") and edges[0].getAttribute("target") == vert[1].getAttribute("id"))
v = topoexport.vsdx_bytes("Layer 2", tiles, links)
z = zipfile.ZipFile(io.BytesIO(v))
parts = z.namelist()
check("Visio: the package holds the content types, the document, the pages list and the page", all(p in parts for p in ("[Content_Types].xml", "_rels/.rels", "visio/document.xml", "visio/pages/pages.xml", "visio/pages/page1.xml", "visio/pages/_rels/pages.xml.rels")), parts)
parsed = {p: minidom.parseString(z.read(p)) for p in parts if p.endswith((".xml", ".rels"))}
page = parsed["visio/pages/page1.xml"]
shapes = page.getElementsByTagName("Shape")
connects = page.getElementsByTagName("Connect")
check("Visio: every part is well-formed XML; five shapes (3 boxes, 2 lines) and a Connect at each end of each line", len(parsed) == len(parts) and len(shapes) == 5 and len(connects) == 4)
texts = [t.firstChild.data for t in page.getElementsByTagName("Text") if t.firstChild]
check("Visio: the boxes carry name and address, the lines their ports", "core-sw1\n10.0.0.2" in texts and "Gi1/0/1  —  port1" in texts and "ap1 & co" in texts, texts)
cells1 = {c.getAttribute("N"): c.getAttribute("V") for c in shapes[0].getElementsByTagName("Cell")}
check("Visio: inches, measured up from the bottom of the page", cells1["Width"] == "1.2500" and float(cells1["PinY"]) > float(cells1["Height"]), cells1)
ct = z.read("[Content_Types].xml").decode()
check("Visio: the parts are declared as Visio's own content types", "application/vnd.ms-visio.drawing.main+xml" in ct and "application/vnd.ms-visio.page+xml" in ct)

print("== Panel opacity")
check("the setting defaults to solid and is this computer's own", db.get_setting("panel_opacity") == 100 and "panel_opacity" in db.GLOBAL_ONLY and themes.DEFAULT_LOOK["panel_opacity"] == 100)
t = theme.tokens(dict(theme="Aurora", panel_opacity=70))
check("at 70 the panels, lists and boxes are painted see-through", t["surface_a"].startswith("rgba(") and t["surface_a"].endswith(",0.7)") and t["input_a"].endswith(",0.7)") and t["panel_opacity"] == 70, t["surface_a"])
t100 = theme.tokens(dict(theme="Aurora", panel_opacity=100))
check("at 100 they are the plain colours", t100["surface_a"] == t100["surface"] and t100["input_a"] == t100["input"])
check("a value off the scale is held in it", theme.tokens(dict(theme="Aurora", panel_opacity=5))["panel_opacity"] == 50 and theme.tokens(dict(theme="Aurora", panel_opacity="x"))["panel_opacity"] == 100)
css = theme.stylesheet(t)
check("the stylesheet paints cards, lists and inputs with the see-through colour", css.count("rgba(") >= 3 and 'QFrame[card="true"] { background: rgba(' in css)

print("== the window")
w = A.Main(); w.resize(1400, 820); w.show(); app.processEvents()
ap = next(p for p in w.settings.pages if p.title == "Appearance")
check("Appearance has a Panel opacity slider and box, 50 to 100 %, previewed like the other knobs", ap.opacity.minimum() == 50 and ap.opacity.maximum() == 100 and ap.opacity_slider.maximum() == 100
      and ap.look_dict()["panel_opacity"] == 100)
ap.opacity_slider.setValue(80)
check("the slider and the box move together", ap.opacity.value() == 80)
ap.opacity.setValue(100)
cp = next(p for p in w.settings.pages if p.title == "Connections")
check("Connections has the ipstack key box, hidden as it is typed, with no key saved yet", cp.ipstack.echoMode() == QLineEdit.EchoMode.Password and cp.ipstack.placeholderText() == "")
cp.ipstack.setText("k3y"); cp.save()
check("Save puts the key in the vault and clears the box", iplookup.get_key() == "k3y" and cp.ipstack.text() == "" and "saved" in cp.ipstack.placeholderText())
cp._forget_ipstack()
check("Forget key empties the vault", not iplookup.has_key() and cp.ipstack.placeholderText() == "")

w.go("Tools"); T = w.tools
print("== Reset buttons")
from ui.tools import RESET_TIP
for name, tab in (("Path Monitor", T.mtr), ("TLS Certificates", T.tls), ("Find Devices", T.discovery), ("Subnet Calculator", T.subnet), ("Port Scanner", T.scan), ("Throughput", T.iperf), ("SCP", T.scp)):
    check(f"{name} has a Reset button with the tooltip", tab.reset.text() == "Reset" and tab.reset.toolTip() == RESET_TIP)
check("Live Ping keeps the Reset it had", T.liveping.clear.text() == "Reset")

print("== the Subnet Calculator")
S = T.subnet
T.tabs.setCurrentWidget(S); app.processEvents()
S.inp.setText("8.8.8.8/24"); app.processEvents()
check("typing an address fills the facts and puts the network at the top of the Split tree", "8.8.8.0/24" in S.facts.text() and S.tree.topLevelItemCount() == 1 and S.tree.topLevelItem(0).text(0) == "8.8.8.0/24")
check("a public address offers Look up", S.lookup_box.isVisible() and S.lookup_btn.isEnabled())
S.split(1); app.processEvents()
root = S.tree.topLevelItem(0)
check("Split in two halves the chosen network", root.childCount() == 2 and root.child(0).text(0) == "8.8.8.0/25" and root.child(1).text(0) == "8.8.8.128/25" and root.isExpanded())
S.tree.setCurrentItem(root.child(0)); S.split_to(root.child(0), 27); app.processEvents()
check("Split into... a longer prefix makes the subnets under it", root.child(0).childCount() == 4 and root.child(0).child(3).text(0) == "8.8.8.96/27" and root.child(0).child(3).text(3) == "30")
check("the tree ends under its rows", S.tree.maximumHeight() < 16777215 and S.tree.maximumHeight() < 400, S.tree.maximumHeight())
S.tree.clearSelection()
for _i in range(4): root.child(0).child(_i).setSelected(True)
S.join_up(); app.processEvents()
check("Join on all of a network's subnets puts them back together",root.child(0).childCount() == 0 and S.tree.currentItem() is root.child(0))
S.inp.setText("2001:db8::1/48"); app.processEvents()
check("an IPv6 address switches the IPv4 | IPv6 segment by itself, and is not looked up", S.mode.value() == "v6" and "Addresses" in S.facts.text() and not S.lookup_box.isVisible())
S.inp.setText("192.168.1.10/24"); app.processEvents()
check("a private IPv4 address switches back and offers no look-up", S.mode.value() == "v4" and not S.lookup_box.isVisible())
S.mode.set("v6"); app.processEvents()
check("choosing the other family by hand clears the box and changes the hint", S.inp.text() == "" and "2001:db8" in S.inp.placeholderText())
S.inp.setText("not an address"); app.processEvents()
check("nonsense says so and empties the tree", "Not a valid address" in S.facts.text() and S.tree.topLevelItemCount() == 0)
S.inp.setText("8.8.8.8/24"); S.reset.click(); app.processEvents()
check("Reset clears the address, facts and tree", S.inp.text() == "" and S.facts.text() == "" and S.tree.topLevelItemCount() == 0)
S.inp.setText("8.8.8.8"); S.lookup(); app.processEvents()
check("Look up without a key points at Settings > Connections", "Settings > Connections" in S.lookup_out.text())

print("== Find Devices")
D = T.discovery
T.tabs.setCurrentWidget(D); app.processEvents()
fm = D.table.horizontalHeader().fontMetrics()
check("each heading fits before the first scan (What it looks like was cut short)", all(D.table.columnWidth(c) >= fm.horizontalAdvance(D.table.horizontalHeaderItem(c).text()) for c in range(6)),
      [D.table.columnWidth(c) for c in range(7)])
D.known = set()
for i in range(3):
    D._found({"ip": f"10.0.2.{i}", "name": f"cam{i}", "vendor": "unifi", "platform": "", "descr": "", "banner": "SSH-2.0-dropbear", "cert": "", "hint": "", "ports": [22], "snmp": False})
D._done([1, 2, 3]); app.processEvents()
check("the vendor drop-down fits its row", all(D.table.rowHeight(i) >= D.table.cellWidget(i, 3).sizeHint().height() for i in range(3)), [D.table.rowHeight(0), D.table.cellWidget(0, 3).sizeHint().height()])
check("the list ends under its rows", D.table.maximumHeight() < 400 and D.table.height() == D.table.maximumHeight(), (D.table.maximumHeight(), D.table.height()))
D.reset.click(); app.processEvents()
check("Reset empties the list and the progress", D.table.rowCount() == 0 and D.rows == [] and D.status.text() == "")

print("== TLS Certificates")
L = T.tls
T.tabs.setCurrentWidget(L); app.processEvents()
info = dict(subject="FortiGate", issuer="CN=FGVM", not_before=datetime(2026, 10, 21), not_after=datetime(2029, 1, 23), days_left=813, sans=["vpn.example.com"], protocol="TLSv1.2", cipher="ECDHE", serial="4597")
devs = db.list_devices()
L._audited([(devs[0], dict(info, subject="dbc2df22", days_left=188), ""), (devs[1], None, "timed out"), (devs[2], info, "")]); app.processEvents()
check("the audit's list ends under its rows", L.table.rowCount() == 3 and L.table.maximumHeight() < 400, L.table.maximumHeight())
L.table.selectRow(1); app.processEvents()
check("choosing a row shows that device's certificate above the list", "FortiGate" in L.details.text() and "vpn.example.com" in L.details.text() and L.host.text() == devs[2]["host"], L.details.text()[:80])
L.table.selectRow(2); app.processEvents()
check("a device without one says why", L.status.text() == "No certificate: timed out" and L.details.text() == "")
L.reset.click(); app.processEvents()
check("Reset clears the certificate and the audit", L.table.rowCount() == 0 and L.audited == [] and L.details.text() == "" and L.status.text() == "")

print("== MTR, SCP, the API Tester")
check("the MTR table's last column takes the rest of the row, so the header's rule runs the whole width", T.mtr.table.horizontalHeader().stretchLastSection())
T.mtr.reset.click()
check("MTR's Reset leaves the table empty", T.mtr.table.rowCount() == 0)
from PySide6.QtWidgets import QLabel
scp_text = next(l.text() for l in T.scp.findChildren(QLabel) if l.text().startswith("Copy files"))
check("the SCP text is the short one", scp_text == "Copy files to or from a device over SSH (SCP), using the device's saved login, jump host and proxy. Cisco IOS needs 'ip scp server enable' "
      "and a privilege 15 user; Juniper, Arista, MikroTik and Linux have it ready.", scp_text)
from ui.apitool import CellEditDelegate
P = T.apitest.params
d = P.itemDelegate()
check("the Params table edits through the fitted delegate, with name / value hints on the empty row", isinstance(d, CellEditDelegate) and d.hints == {1: "name", 2: "value"})
opt = QStyleOptionViewItem()
opt.rect = P.visualRect(P.model().index(0, 1))
ed = d.createEditor(P.viewport(), opt, P.model().index(0, 1))
d.updateEditorGeometry(ed, opt, P.model().index(0, 1))
check("the editor is a frameless box the size of its cell", isinstance(ed, QLineEdit) and not ed.hasFrame() and ed.geometry() == opt.rect, (ed.geometry(), opt.rect))
check("the Variables table edits the same way", isinstance(T.apitest.variables.table.itemDelegate(), CellEditDelegate))

print("== the maker's mark and the pane's status line")
from ui import brandicons
check("nine makers have their own mark (Simple Icons), the rest two letters on a tile", all(v in brandicons.VENDOR_PATHS for v in ("cisco", "fortinet", "paloalto", "juniper", "mikrotik", "unifi", "proxmox", "truenas", "opnsense"))
      and all(v not in brandicons.VENDOR_PATHS and v in brandicons.VENDOR_TILES for v in ("arista", "hpe", "windows", "meraki")))
check("a mark is drawn in white on the maker's tile; a letter tile has text instead", '<path fill="#ffffff"' in brandicons.vendor_tile_svg("cisco") and "<text" in brandicons.vendor_tile_svg("hpe")
      and brandicons.vendor_tile_svg("").count("?") == 1)
ic = brandicons.vendor_icon("unifi_network")
check("vendor_icon gives an icon (the UniFi family shares one)", not ic.isNull() and ic is brandicons.vendor_icon("unifi"))
folder = os.path.join(SP, "Vendor Icons"); os.makedirs(folder, exist_ok=True)
from PySide6.QtGui import QImage, QColor as _QC
for name, colour in (("PALO ALTO.png", "#fa582d"), ("PRXMOX.png", "#e57000"), ("MIKROTIK.png", "#ffffff"), ("HP.png", "#000000")):
    im = QImage(64, 64, QImage.Format.Format_ARGB32); im.fill(Qt.GlobalColor.transparent)
    for y in range(16, 48):
        for x in range(8, 56):
            im.setPixelColor(x, y, _QC(colour))
    im.save(os.path.join(folder, name))
db.set_setting("vendor_icons_folder", folder); brandicons.forget_vendor_icons()
check("a file named after the vendor is found, spaces and case ignored, and a near miss such as PRXMOX too",
      brandicons.vendor_file("paloalto") and brandicons.vendor_file("paloalto").endswith("PALO ALTO.png") and brandicons.vendor_file("proxmox") and brandicons.vendor_file("proxmox").endswith("PRXMOX.png")
      and brandicons.vendor_file("hpe") and brandicons.vendor_file("hpe").endswith("HP.png") and brandicons.vendor_file("cisco") is None, (brandicons.vendor_file("proxmox"), brandicons.vendor_file("cisco")))
check("the folder comes first, then the built-in mark, then letters", brandicons.vendor_source("paloalto") == "file" and brandicons.vendor_source("cisco") == "mark" and brandicons.vendor_source("arista") == "letters")
pm_pa = brandicons.vendor_icon("paloalto").pixmap(64, 64).toImage()
check("the file is drawn as it is: no tile behind it, its own pixels in the middle", pm_pa.pixelColor(2, 2).alpha() == 0 and pm_pa.pixelColor(32, 32).name() == "#fa582d", (pm_pa.pixelColor(2, 2).alpha(), pm_pa.pixelColor(32, 32).name()))
db.set_setting("vendor_icons_folder", ""); brandicons.forget_vendor_icons()
check("with no folder chosen, the built-in marks are back (unless Documents\\Vendor Icons exists on this PC)", brandicons.vendor_source("paloalto") in ("mark", "file"))
w.go("Inventory"); app.processEvents()
pane = w.inventory.pane
pane.set_device(devs[0]); app.processEvents()
labels = [x.text() for x in (widget_at(pane.summary.info, i) for i in range(pane.summary.info.count())) if x]
check("the pane shows the mark, the chip and 'checked ...' on one line, and no Status row to wrap", not pane.mark.pixmap().isNull() and pane.chip.text() == "OK"
      and pane.checked.text().startswith("checked ") and not any("Status" in t for t in labels), (pane.checked.text(), labels))
pane.set_device(next(d for d in devs if d["name"] == "edge-fw")); app.processEvents()
check("a device never checked says so", pane.checked.text() == "no results yet" and not pane.chip.isVisible(), pane.checked.text())
from ui.device_view import DeviceView
dv = DeviceView(devs[0], w); dv.show(); app.processEvents()
check("the device window shows the mark beside the name and keeps its Status row", not dv.mark.pixmap().isNull() and dv.mark.toolTip() == "Palo Alto"
      and any("Status" in x.text() for x in (widget_at(dv.info, i) for i in range(dv.info.count())) if x))
dv.close()

print("== the topology's Save as...")
tp = T.topology
check("Save as... offers PNG, SVG, draw.io and Visio", tp.save_btn.text() == "Save as..." and [a.text() for a in tp.save_btn.menu().actions()] == ["PNG image", "SVG drawing", "Draw.io diagram (.drawio)", "Visio drawing (.vsdx)"])
nodes = {"core-sw1": {"inventory": True, "addr": "10.0.0.2"}, "edge-fw": {"inventory": True, "addr": "10.0.0.3"}, "ap1": {"inventory": False, "addr": "10.0.0.9"}}
glinks = [{"a": "core-sw1", "b": "edge-fw", "a_port": "Gi1/0/1", "b_port": "port1", "protocols": {"LLDP"}, "both": True, "down": False, "change": "", "speed": "1G", "rows": []},
          {"a": "core-sw1", "b": "ap1", "a_port": "Gi1/0/5", "b_port": "eth0", "protocols": {"CDP"}, "both": False, "down": False, "change": "new", "rows": []}]
tp.l2.draw(nodes, glinks, {"core-sw1": (0, 0), "edge-fw": (300, 0), "ap1": (150, 200)}, {"core-sw1": "l3switch", "edge-fw": "firewall", "ap1": "ap"}, {"core-sw1": "WARN"}, {})
tiles2, links2 = tp.diagram(tp.l2)
by = {t["id"]: t for t in tiles2}
check("the drawn map becomes tiles and links for the writers: positions, role colours, ports", len(tiles2) == 3 and len(links2) == 2 and by["core-sw1"]["colour"] == topology.ROLE_COLORS["l3switch"]
      and by["edge-fw"]["x"] > by["core-sw1"]["x"] and by["ap1"]["y"] > by["core-sw1"]["y"] and links2[0]["label_a"] == "Gi1/0/1" and links2[1]["dashed"] and not links2[0]["dashed"], (tiles2, links2))
check("the drawing starts at the page's corner", min(t["x"] for t in tiles2) == 0 and min(t["y"] for t in tiles2) == 0)
tmp = os.path.join(SP, "map.vsdx")
from PySide6.QtWidgets import QFileDialog
QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (tmp, ""))
tp.tab_l2.setChecked(True); tp.save_picture("vsdx"); app.processEvents()
check("Save as Visio writes the file", os.path.exists(tmp) and zipfile.is_zipfile(tmp))
tmp2 = os.path.join(SP, "map.drawio")
QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (tmp2, ""))
tp.save_picture("drawio"); app.processEvents()
check("Save as draw.io writes the file", os.path.exists(tmp2) and open(tmp2, encoding="utf-8").read().startswith("<?xml") and "mxfile" in open(tmp2, encoding="utf-8").read())

w.close()
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
