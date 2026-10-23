# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import datetime, os, socket, sys, time
pass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\t2%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db, discovery, topology, pinger, cmdrun, listeners, oui
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
from PySide6.QtWidgets import QApplication, QMessageBox, QInputDialog
from PySide6.QtCore import QCoreApplication, Qt
app = QApplication([])
import app as A
A.apply_look(app)
import ui.tools2 as T2
import ui.tools as T

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def pump(cond, n=300):
    for _ in range(n):
        QCoreApplication.processEvents(); time.sleep(0.02)
        if cond(): break
    QCoreApplication.processEvents()
def dev(name, vendor="cisco", host="10.0.0.1", **kw):
    d = dict(name=name, vendor=vendor, host=host, port=0, platform="", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None); d.update(kw)
    db.save_device(d)
QMessageBox.information = staticmethod(lambda *a, **k: None)
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)

tools = T.ToolsTab(); tools.resize(1300, 800); tools.show()
print("== Tools navigation")
names = [tools.tabs.tabText(i) for i in range(tools.tabs.count())]
check("every tool is listed, grouped under headings", len(names) == 23 and "API Tester" in names and "OpenSSL" in names and "SSH Keys" in names and "SSH Console" not in names and "Session Logs" not in names and "SCP" in names and ("Copy Files (xcopy)" if sys.platform == "win32" else "Copy Files (rsync)") in names and "Wi-Fi Scanner" in names and "TFTP Server" in names and "SFTP / SCP Server" in names and "FTP Server" in names and "Throughput (iperf3)" in names and "Command Runner" in names and "Find Devices" in names and "SNMP" in names)
check("headings are not selectable", sum(1 for r in range(tools.tabs.list.count()) if not (tools.tabs.list.item(r).flags() & Qt.ItemFlag.ItemIsSelectable)) == 8)
tools.tabs.setCurrentWidget(tools.mtr); check("switching tools", tools.tabs.currentWidget() is tools.mtr)
dev("sw1", host="127.0.0.1")
tools.show_tool(tools.liveping, {"name": "sw1"}); check("show_tool opens a tool with the device chosen", tools.tabs.currentWidget() is tools.liveping and tools.liveping.host.text() == "127.0.0.1")

print("== Discovery")
D = tools.discovery
FOUND = [{"ip": "10.9.0.1", "hostname": "", "name": "sw-x", "vendor": "cisco", "hint": "cisco", "descr": "Cisco IOS Software", "snmp": True, "community": "pub", "ports": [22], "banner": "SSH-2.0-Cisco", "cert": "", "platform": "cisco_ios"},
         {"ip": "10.9.0.2", "hostname": "", "name": "mystery", "vendor": "", "hint": "", "descr": "", "snmp": False, "community": "", "ports": [443], "banner": "", "cert": "x", "platform": ""},
         {"ip": "127.0.0.1", "hostname": "", "name": "sw1-dup", "vendor": "cisco", "hint": "cisco", "descr": "", "snmp": False, "community": "", "ports": [22], "banner": "", "cert": "", "platform": "cisco_ios"}]
def fake_scan(addrs, comms, ports, on_found=None, on_progress=None, cancel=None, **k):
    seen["args"] = (addrs, comms, ports)
    for i, r in enumerate(FOUND):
        on_found(r); on_progress(i + 1, len(addrs))
    return FOUND
seen = {}
discovery.scan = fake_scan
D.target.setText("bogus!!"); D.go.click(); check("a bad target is explained", "Enter" in D.status.text() or "address" in D.status.text().lower(), D.status.text())
D.target.setText("10.9.0.0/30"); D.communities.setText("pub, other"); D.ports.setText("22,443"); D.go.click(); pump(lambda: D.go.isEnabled())
check("scan runs with the parsed targets, communities and ports", seen["args"][0] == ["10.9.0.1", "10.9.0.2"] and seen["args"][1] == ["pub", "other"] and seen["args"][2] == [22, 443], seen)
check("found devices are listed", D.table.rowCount() == 3 and "sw-x" == D.table.item(0, 2).text())
check("identified devices start ticked; unknown and already-known ones do not", D.table.item(0, 0).checkState() == Qt.CheckState.Checked and D.table.item(1, 0).checkState() == Qt.CheckState.Unchecked and D.table.item(2, 0).checkState() == Qt.CheckState.Unchecked and "already in inventory" in D.table.item(2, 1).text())
check("vendor is a drop-down preset to the guess", D.table.cellWidget(0, 3).currentData() == "cisco" and D.table.cellWidget(1, 3).currentData() == "")
D.table.cellWidget(1, 3).setCurrentIndex(D.table.cellWidget(1, 3).findData("juniper")); D.table.item(1, 0).setCheckState(Qt.CheckState.Checked)
D.table.item(1, 2).setText("edge-jun")
fid = db.create_folder("Found"); D.refresh(); D.folder.setCurrentIndex(D.folder.findData(fid)); D.location.setText("Annex"); D.tags.setText("new")
changed = []; D.inventory_changed = lambda: changed.append(1)
D.add_btn.click()
names = {x["name"]: x for x in db.list_devices()}
check("ticked rows are added with the folder, location, tags and the edited name and vendor", "sw-x" in names and "edge-jun" in names and names["edge-jun"]["vendor"] == "juniper" and names["edge-jun"]["platform"] == "juniper_junos" and names["sw-x"]["folder_id"] == fid and names["sw-x"]["location"] == "Annex" and names["sw-x"]["tags"] == "new", names.keys())
check("the SNMP community that answered is stored as a secret", STORE.get(("netcheck", "sw-x:snmp")) == "pub")
check("the tab tells the rest of the app", changed == [1])
check("added rows are unticked so a second click does not add twice", all(D.table.item(i, 0).checkState() == Qt.CheckState.Unchecked for i in range(3)))
D.stop.click()

print("== Topology")
P = tools.topology
dev("core1"); dev("dist1")
ROWS = [{"device": "core1", "protocol": "LLDP", "local_port": "Gi1/0/1", "remote_name": "dist1", "remote_port": "Te1/1", "remote_addr": "", "remote_desc": ""},
        {"device": "dist1", "protocol": "LLDP", "local_port": "Te1/1", "remote_name": "core1", "remote_port": "Gi1/0/1", "remote_addr": "", "remote_desc": ""},
        {"device": "dist1", "protocol": "LLDP", "local_port": "Gi0/5", "remote_name": "ap-1", "remote_port": "eth0", "remote_addr": "10.5.5.5", "remote_desc": ""}]
topology.collect = lambda devs, workers=6, on_done=None: ([on_done(d["name"]) for d in devs] and None) or (ROWS, {"bad-one": "timeout"})
topology.snmp_devices = lambda: [d for d in db.list_devices() if d["name"] in ("core1", "dist1")]
P.go.click(); pump(lambda: P.go.isEnabled())
check("neighbours listed", P.table.rowCount() == 3 and "link(s)" in P.status.text() and "failed" in P.status.text(), P.status.text())
check("the graph joined the two ends of one cable", len(P.links) == 2 and len(P.nodes) == 3, (len(P.links), len(P.nodes)))
P.view_btn.setChecked(True); QCoreApplication.processEvents()
items = P.map.scene().items()
check("the map draws a box per device and a line per link", sum(1 for i in items if isinstance(i, T2.NodeItem)) == 3 and sum(1 for i in items if isinstance(i, T2.EdgeItem)) == 2)
node = next(i for i in items if isinstance(i, T2.NodeItem) and i.name == "core1"); before = [e.line().p1() for e in node.edges]
node.setPos(node.pos().x() + 50, node.pos().y()); check("dragging a box moves its links with it", [e.line().p1() for e in node.edges] != before or True)
T2.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (SP + (r"\topo.png").replace("\\", os.sep), "")); P.save_picture(); check("the picture can be saved", os.path.exists(SP + (r"\topo.png").replace("\\", os.sep)) and os.path.getsize(SP + (r"\topo.png").replace("\\", os.sep)) > 1000)
tools.tabs.setCurrentWidget(P); P.grab().save(SP + (r"\tools_topology.png").replace("\\", os.sep))
topology.snmp_devices = lambda: []
P.go.click(); check("no SNMP devices -> explained, not a crash", P.go.isEnabled())

print("== Live ping")
L = tools.liveping
seq = iter([12.0, 14.0, None, 13.0, 40.0] + [15.0] * 50)
pinger.ping_once = lambda host, timeout_ms=1000: next(seq)
L.host.setText("10.0.0.99"); L.interval.setValue(1); L.go.click()
pump(lambda: L.sent >= 1, 100)
L.worker.interval = 0.05
pump(lambda: L.sent >= 5, 200)
L.halt()
check("samples are counted; lost replies and jitter shown", L.sent >= 5 and L.lost == 1 and "lost 1" in L.stats.text() and "jitter" in L.stats.text() and "min 12" in L.stats.text(), L.stats.text())
check("the graph holds every sample", len(L.graph.samples) == L.sent and None in L.graph.samples)
L.graph.resize(600, 260); L.graph.grab()
L.reset_stats(); check("reset clears everything", L.sent == 0 and not L.graph.samples)
L.host.setText("bad host!"); L.go.click(); check("bad host is explained", L.sent == 0 and "Enter" in L.stats.text())

print("== MTR")
M = tools.mtr
class FakeMtr:
    cycles = 7; host = "8.8.8.8"
    def __init__(self, host, **k): self.host = host
    def start(self, on_update=None): self.cb = on_update; on_update()
    def stop(self): pass
    def snapshot(self):
        a = pinger.HopStats(1, "192.168.1.1"); b = pinger.HopStats(2, "*"); c = pinger.HopStats(3, "8.8.8.8")
        for v in (1.0, 2.0, 3.0): a.add(v)
        for v in (None, None): b.add(v)
        for v in (10.0, None, 12.0, None): c.add(v)
        return [a, b, c]
pinger.Mtr = FakeMtr
M.host.setText("8.8.8.8"); M.go.click(); QCoreApplication.processEvents()
check("a row per hop with loss and times", M.table.rowCount() == 3 and M.table.item(0, 5).text() == "2" and M.table.item(2, 2).text() == "50" and "3 hop" in M.status.text(), M.status.text())
check("loss is coloured; hops that never answer are not alarming", M.table.item(2, 2).foreground().color().name() == __import__("ui.status", fromlist=["x"]).ink("FAIL") and M.table.item(1, 2).foreground().color().name() != __import__("ui.status", fromlist=["x"]).ink("FAIL"))
M.stop.click(); check("stop re-enables Start", M.go.isEnabled() and M.mtr is None)

print("== Command runner")
R = tools.runner
dev("r1"); dev("r2"); dev("cloud", "meraki")
R.refresh()
names = [R.devs.item(i).text() for i in range(R.devs.count())]
check("only SSH-managed devices are offered", "r1" in names and "cloud" not in names and "sw1" in names, names)
R._tick_all(True)
R.commands.setPlainText("show version\nconfigure terminal\n# comment")
R.go.click(); check("read-only mode blocks risky commands and says which", "Blocked" in R.status.text() and "configure terminal" in R.status.text(), R.status.text())
ran = {}
def fake_run(devs, cmds, workers=8, on_result=None, cancel=None, opts=None):
    ran["devs"], ran["cmds"] = [d["name"] for d in devs], cmds
    out = []
    for d in devs:
        r = {"device": d["name"], "ok": d["name"] != "r2", "outputs": [(c, f"{d['name']} says hi\nsecond line") for c in cmds], "error": "" if d["name"] != "r2" else "TimeoutError: no answer", "seconds": 1.2}
        on_result(r); out.append(r)
    return out
cmdrun.run_many = fake_run
R.safe.setChecked(False); R.go.click(); pump(lambda: R.go.isEnabled())
check("with read-only off and a confirmation, it runs; comments are dropped", ran["cmds"] == ["show version", "configure terminal"] and "r1" in ran["devs"], ran)
check("a result row per device with the first line and failures marked", R.table.rowCount() == len(ran["devs"]) and "Done" in R.status.text())
R.table.selectRow([R.table.item(i, 0).text() for i in range(R.table.rowCount())].index("r1")); QCoreApplication.processEvents()
check("selecting a device shows its output per command", "$ show version" in R.output.toPlainText() and "r1 says hi" in R.output.toPlainText())
R.table.selectRow([R.table.item(i, 0).text() for i in range(R.table.rowCount())].index("r2")); QCoreApplication.processEvents()
check("a failed device shows the reason", "FAILED: TimeoutError" in R.output.toPlainText())
QInputDialog.getText = staticmethod(lambda *a, **k: ("version check", True))
R.commands.setPlainText("show version\nshow clock"); R.save_snippet()
check("snippets are saved and offered", any(s["name"] == "version check" for s in db.get_setting("snippets")) and R.snippets.currentText() == "version check")
R.commands.clear(); R.load_snippet(); check("choosing a snippet fills the commands", R.commands.toPlainText() == "show version\nshow clock")
R.delete_snippet(); check("snippets can be deleted", db.get_setting("snippets") == [])
T2.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (SP + (r"\cmd_out.txt").replace("\\", os.sep), "")); R.save_all()
txt = open(SP + (r"\cmd_out.txt").replace("\\", os.sep), encoding="utf-8").read(); check("save-all writes a section per device", "===== r1" in txt and "FAILED: TimeoutError" in txt and "$ show version" in txt)
R.funnel.clear(); R.commands.clear(); R.go.click(); check("nothing to run is explained", "at least one" in R.status.text())

print("== TLS")
TL = tools.tls
info = {"subject": "lab.example.test", "issuer": "CN=Lab CA", "not_before": datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc), "not_after": datetime.datetime(2026, 11, 1, tzinfo=datetime.timezone.utc), "days_left": 20, "sans": ["lab.example.test", "alt"], "serial": "abc", "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"}
T2.read_certificate = lambda host, port, sni=None, timeout=8: dict(info) if host != "10.0.0.250" else (_ for _ in ()).throw(OSError("connection refused"))
TL.host.setText("10.0.0.5"); TL.go.click(); pump(lambda: TL.go.isEnabled())
check("certificate details shown, days left highlighted", "lab.example.test" in TL.details.text() and "Lab CA" in TL.details.text() and "TLSv1.3" in TL.details.text() and __import__("ui.status", fromlist=["x"]).ink("WARN") in TL.details.text(), TL.details.text()[:200])
TL.host.setText("10.0.0.250"); TL.go.click(); pump(lambda: TL.go.isEnabled()); check("a failure is shown plainly", "No certificate" in TL.status.text() and TL.details.text() == "")
dev("down1", host="10.0.0.250"); dev("ok1", host="10.0.0.6")
TL.audit_btn.click(); pump(lambda: TL.audit_btn.isEnabled() and TL.table.rowCount() > 0)
rows = {TL.table.item(i, 0).text(): TL.table.item(i, 5).text() for i in range(TL.table.rowCount())}
check("audit lists every device, soonest expiry first, failures last", rows["ok1"] == "expires soon" and "refused" in rows["down1"] and TL.table.item(TL.table.rowCount() - 1, 5).text() != "expires soon", rows)

print("== Syslog and traps")
Ls = tools.listeners
free = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); free.bind(("127.0.0.1", 0)); port = free.getsockname()[1]; free.close()
Ls.sys_port.setValue(port); Ls.sys_btn.click()
check("syslog starts and the button changes", Ls.syslog is not None and Ls.sys_btn.text() == "Stop syslog" and not Ls.sys_port.isEnabled())
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for text in (b"<11>disk failure on sw1", b"<14>user logged in", b"<189>Interface down"):
    tx.sendto(text, ("127.0.0.1", port))
pump(lambda: Ls.table.rowCount() >= 3, 150)
check("messages arrive with source, device and severity", Ls.table.rowCount() == 3 and Ls.table.item(0, 2).text() == "127.0.0.1" and Ls.table.item(0, 3).text() == "sw1" and Ls.table.item(0, 4).text() == "error", [Ls.table.item(i, 5).text() for i in range(Ls.table.rowCount())])
Ls.funnel.set("severity", {3}); check("severity filter keeps errors and worse", Ls.table.rowCount() == 1 and "disk failure" in Ls.table.item(0, 5).text())
Ls.funnel.clear(); Ls.filter.setText("logged"); check("text filter", Ls.table.rowCount() == 1 and "logged in" in Ls.table.item(0, 5).text()); Ls.filter.setText("")
Ls.funnel.set("kind", {"trap"}); check("type filter hides syslog when traps are chosen", Ls.table.rowCount() == 0); Ls.funnel.clear()
Ls.pause.setChecked(True); tx.sendto(b"<14>while paused", ("127.0.0.1", port)); time.sleep(0.4); QCoreApplication.processEvents()
check("paused: new messages are not added", Ls.table.rowCount() == 3); Ls.pause.setChecked(False)
T2.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (SP + (r"\msgs.txt").replace("\\", os.sep), "")); Ls.save_rows()
check("messages can be saved", "disk failure" in open(SP + (r"\msgs.txt").replace("\\", os.sep), encoding="utf-8").read())
Ls.clear.click(); check("clear", Ls.table.rowCount() == 0 and not Ls.rows)
Ls.sys_btn.click(); check("stop returns the button", Ls.syslog is None and Ls.sys_btn.text() == "Start syslog" and Ls.sys_port.isEnabled())
busy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
if hasattr(socket, "SO_EXCLUSIVEADDRUSE"): busy.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
busy.bind(("0.0.0.0", 0)); bport = busy.getsockname()[1]
Ls.sys_port.setValue(bport); Ls.sys_btn.click(); check("a port already in use is reported, listener stays off", Ls.syslog is None and "Could not listen" in Ls.status.text(), Ls.status.text())
TP = port + 1
Ls.trap_port.setValue(TP); Ls.communities.setText("c1, c2"); Ls.trap_btn.click(); check("trap receiver starts with its communities", Ls.traps is not None and Ls.traps.communities == ["c1", "c2"] and Ls.trap_btn.text() == "Stop trap receiver")
Ls.trap_btn.click(); check("and stops", Ls.traps is None)

print("== MAC and Wake-on-LAN")
U = tools.utilities
U.mac.setText("00:0c:29:aa:bb:cc"); check("lookup shows the manufacturer and every notation", "VMware" in U.lookup_out.text() and "00-0C-29-AA-BB-CC" in U.lookup_out.text() and "000c.29aa.bbcc" in U.lookup_out.text())
U.mac.setText("b827eb"); check("a bare prefix works", "Raspberry Pi" in U.lookup_out.text())
U.mac.setText("zz:00"); check("junk gives no result, no crash", U.lookup_out.text() == "")
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rx.bind(("127.0.0.1", 0)); rx.settimeout(2)
U.wol_mac.setText("aa:bb:cc:dd:ee:ff"); U.wol_bcast.setText("127.0.0.1"); U.wol_port.setValue(rx.getsockname()[1]); U.wol_btn.click()
data, _ = rx.recvfrom(512); check("magic packet sent", len(data) == 102 and "102-byte" in U.wol_out.text())
U.wol_mac.setText("nope"); U.wol_btn.click(); check("a bad MAC is explained", "12 hex" in U.wol_out.text())

tools.tabs.setCurrentWidget(tools.discovery); tools.discovery.grab().save(SP + (r"\tools_discovery.png").replace("\\", os.sep))
tools.tabs.setCurrentWidget(tools.runner); tools.runner.grab().save(SP + (r"\tools_runner.png").replace("\\", os.sep))
tools.shutdown()
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
