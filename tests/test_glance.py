# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Network at a glance on the Overview: dots for the devices, links from Tools > Topology, rings on what is down or being checked.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "glance%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingglance%d" % int(time.time()))
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
from drivers.base import Result
from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
import app as A
A.apply_look(app)
from core import topology
from ui import motion
from ui.glance import GlanceMap, NO_MAP

def dev(name, vendor="cisco"):
    db.save_device(dict(name=name, vendor=vendor, host=f"10.0.0.{len(db.list_devices()) + 1}", port=0, platform="cisco_ios", username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))

print("== nothing yet")
m = GlanceMap(); m.resize(400, 200); m.show(); app.processEvents()
m.refresh()
check("no devices: an empty map that still draws", not m.nodes and m.summary == "" and (m.grab() or True))

print("== devices, no scan")
for n in ("core-sw1", "edge-fw", "dist-sw2", "udm-pro"): dev(n)
db.save_run([Result("core-sw1", "cpu", "OK", "5%"), Result("edge-fw", "wan", "OK", "2/2"), Result("dist-sw2", "connection", "ERROR", "", "timeout")])
m.refresh()
check("every device is a dot, in a grid, with no links", set(m.nodes) == {"core-sw1", "edge-fw", "dist-sw2", "udm-pro"} and not m.links and not m.scanned)
check("the statuses are known (a device never checked has none)", m.status == {"core-sw1": "OK", "edge-fw": "OK", "dist-sw2": "ERROR"} and "udm-pro" not in m.status)
check("the heading says how many are down", m.summary == "1 of 4 down")
check("the hint says to scan", NO_MAP.startswith("No map yet") and m.grab().width() == 400)
check("it reads aloud for a screen reader", "dist-sw2 ERROR" in m.accessibleName() and "udm-pro not checked" in m.accessibleName())
check("with motion off, nothing pulses", m._anim is None and m.pulse == 0.0)

print("== after a topology scan")
rows = [dict(device="core-sw1", local_port="Gi1/0/1", remote_name="edge-fw", remote_port="port1", remote_desc="", remote_addr="", protocol="LLDP"),
        dict(device="core-sw1", local_port="Gi1/0/2", remote_name="dist-sw2", remote_port="Gi1/0/24", remote_desc="", remote_addr="", protocol="CDP"),
        dict(device="dist-sw2", local_port="Gi1/0/5", remote_name="udm-pro", remote_port="eth0", remote_desc="", remote_addr="", protocol="LLDP"),
        dict(device="core-sw1", local_port="Gi1/0/9", remote_name="outsider", remote_port="1", remote_desc="", remote_addr="", protocol="LLDP")]
topology.remember(rows, [])
m.refresh()
check("the links Topology found join the dots (an outside neighbour is left out)", m.scanned and sorted(m.links) == [("core-sw1", "dist-sw2"), ("core-sw1", "edge-fw"), ("dist-sw2", "udm-pro")], m.links)
check("the dots are laid out, inside the map", all(0 <= x <= 1 and 0 <= y <= 1 for x, y in m.nodes.values()) and len({tuple(p) for p in m.nodes.values()}) == 4)
sig = m._sig; m.refresh()
check("the same devices and links are not laid out again", m._sig is sig or m._sig == sig)

print("== rings and clicks")
motion.force("Subtle")
m.set_checking(["udm-pro"])
check("a device being checked, or down, pulses while motion is on", m._anim is not None and m.checking == {"udm-pro"})
m.set_checking([])
check("...and the down device keeps it going", m._anim is not None)
motion.force("Off"); m.hide(); m.show(); m.set_checking([])
check("motion off stops it", m._anim is None)
motion.force(None)
got = []
m.open_device.connect(got.append)
p = m._pt("edge-fw")
m.mousePressEvent(QMouseEvent(QMouseEvent.Type.MouseButtonPress, QPointF(p), Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier))
check("clicking a dot opens the device", got == ["edge-fw"], got)
m.mouseMoveEvent(QMouseEvent(QMouseEvent.Type.MouseMove, QPointF(p), Qt.MouseButton.NoButton, Qt.MouseButton.NoButton, Qt.KeyboardModifier.NoModifier))
check("hovering names it", m._hover == "edge-fw" and "edge-fw: OK" in m.toolTip())
for i in range(40): dev(f"ap-{i:02d}")
m.refresh()
check("many devices still draw (the names go to the hover)", len(m.nodes) == 44 and (m.grab() or True))

print("== on the Overview")
w = A.Main(); w.resize(1300, 820); w.show(); app.processEvents(); w.go("Overview"); app.processEvents()
d = w.dashboard
check("the Overview has the map with its summary", d.map.nodes and d.map_summary.text().startswith("· ") and "down" in d.map_summary.text(), d.map_summary.text())
d.run_started(["core-sw1", "edge-fw"]); d.set_progress(0, 2); app.processEvents()
check("a run rings the devices it is on, and the button says so", d.map.checking == {"core-sw1", "edge-fw"} and d.run_btn.text() == "Checking…" and d.progress.isVisibleTo(d))
d.device_done("core-sw1"); d.set_progress(1, 2)
check("each device drops its ring as its results come in", d.map.checking == {"edge-fw"})
d.set_progress(2, 2); app.processEvents()
check("when the run ends, the rings and the line go and the button is itself again", not d.map.checking and d.run_btn.text() == "Run checks" and not d.progress.isVisibleTo(d))
got = []
d.open_device.connect(got.append)
d.map.open_device.emit("edge-fw")
check("a click on the map opens the device through the Overview", got == ["edge-fw"])

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
