"""More Tools: discovery, topology, live ping and MTR, command runner, TLS certificates, listeners, MAC utilities."""
import ipaddress
import socket
import threading
import time
from collections import deque
from datetime import datetime

from PySide6.QtCore import QPointF, QRectF, QThread, QTimer, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QFontDatabase, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout,
                               QGraphicsItem, QGraphicsLineItem, QGraphicsRectItem, QGraphicsScene,
                               QGraphicsSimpleTextItem, QGraphicsView, QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSpinBox,
                               QSplitter, QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)
from core import audit, cmdrun, custom, db, discovery, listeners, nettools, oui, pinger, profiles, reports, snmp
from core import proxy, topology, vendors
from ui import theme
from ui.tools import DevicePicker, OutputBox, _row
from ui.widgets import GroupPicker


def _table(cols, stretch_last=True):
    t = QTableWidget(0, len(cols))
    t.setHorizontalHeaderLabels(cols)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.verticalHeader().setVisible(False)
    t.setShowGrid(False)
    t.horizontalHeader().setStretchLastSection(stretch_last)
    return t


def _muted(text=""):
    lab = QLabel(text)
    lab.setProperty("muted", True)
    lab.setWordWrap(True)
    return lab


def _primary(text):
    b = QPushButton(text)
    b.setProperty("primary", True)
    return b


# =============================================================================== Discovery
class DiscoveryWorker(QThread):
    found = Signal(dict)
    progress = Signal(int, int)
    done = Signal(list)

    def __init__(self, addresses, communities, ports):
        super().__init__()
        self.addresses, self.communities, self.ports = addresses, communities, ports
        self.cancel = threading.Event()

    def run(self):
        res = discovery.scan(self.addresses, self.communities, self.ports, on_found=self.found.emit,
                             on_progress=self.progress.emit, cancel=self.cancel)
        self.done.emit(res)


class DiscoveryTab(QWidget):
    VENDOR_CHOICES = [("(skip)", "")] + [(v["name"], k) for k, v in vendors.VENDORS.items()]

    def __init__(self):
        super().__init__()
        self.worker = None
        self.rows = []
        self.target = QLineEdit()
        self.target.setPlaceholderText("10.0.0.0/24   or   10.0.0.1-50   or   192.168.1.10, 192.168.1.20")
        self.communities = QLineEdit("public")
        self.communities.setPlaceholderText("SNMP communities to try, comma separated")
        self.ports = QLineEdit("22,443")
        self.go, self.stop = _primary("Scan"), QPushButton("Stop")
        self.stop.setEnabled(False)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(6)
        self.status = _muted("")
        self.table = _table(["Add", "Address", "Name", "Vendor", "Platform", "What it looks like", "Open ports"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.DoubleClicked)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.folder, self.profile = QComboBox(), QComboBox()
        self.folder.addItem("(top level)", None)
        self.profile.addItem("(none)", None)
        self.location, self.tags = QLineEdit(), QLineEdit()
        self.location.setPlaceholderText("location")
        self.tags.setPlaceholderText("tags, comma separated")
        self.group = QComboBox()
        for key, label in discovery.GROUPINGS:
            self.group.addItem(label, key)
        self.group.setToolTip("File the devices in subfolders of the folder chosen, made as needed, so a scan of a whole site comes out tidy.")
        self.add_btn = _primary("Add checked to inventory")
        self.all_btn, self.none_btn = QPushButton("Check all"), QPushButton("Check none")
        top = _row("Scan", self.target, "Communities", self.communities, "Ports", self.ports, self.go, self.stop)
        bottom = QHBoxLayout()
        for w in (QLabel("Folder"), self.folder, self.group, QLabel("Profile"), self.profile, self.location, self.tags):
            bottom.addWidget(w, 1 if isinstance(w, (QLineEdit, QComboBox)) else 0)
        bottom.addWidget(self.all_btn)
        bottom.addWidget(self.none_btn)
        bottom.addWidget(self.add_btn)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(_muted("Finds devices by trying a few ports and SNMP, then guesses what each one is. Check the ones you "
                             "want, correct the name or vendor if the guess is wrong, and add them. Scan only networks you "
                             "are responsible for."))
        lay.addWidget(self.bar)
        lay.addWidget(self.status)
        lay.addWidget(self.table, 1)
        lay.addLayout(bottom)
        self.go.clicked.connect(self.start)
        self.stop.clicked.connect(self.halt)
        self.add_btn.clicked.connect(self.add)
        self.all_btn.clicked.connect(lambda: self._check_all(True))
        self.none_btn.clicked.connect(lambda: self._check_all(False))
        self.target.returnPressed.connect(self.start)
        self.refresh()

    def refresh(self):
        keep_f, keep_p = self.folder.currentData(), self.profile.currentData()
        self.folder.clear()
        self.folder.addItem("(top level)", None)
        for fid, path in sorted(db.folder_paths().items(), key=lambda kv: kv[1].lower()):
            self.folder.addItem(path, fid)
        self.profile.clear()
        self.profile.addItem("(none)", None)
        for p in profiles.list_profiles():
            self.profile.addItem(p["name"], p["id"])
        self.folder.setCurrentIndex(max(0, self.folder.findData(keep_f)))
        self.profile.setCurrentIndex(max(0, self.profile.findData(keep_p)))

    def running(self):
        return bool(self.worker and self.worker.isRunning())

    def start(self):
        if self.running():
            return
        try:
            addrs = discovery.targets(self.target.text())
            ports = nettools.parse_ports(self.ports.text()) if self.ports.text().strip() else [22, 443]
        except ValueError as e:
            self.status.setText(str(e))
            return
        limit = int(db.get_setting("scan_confirm_over"))
        if limit and len(addrs) > limit and QMessageBox.question(
                self, "Large scan", f"This covers {len(addrs):,} addresses, more than the {limit:,} you asked to be "
                "warned about (Settings > General).\n\nScan anyway?") != QMessageBox.StandardButton.Yes:
            return
        comms = [c.strip() for c in self.communities.text().split(",") if c.strip()]
        self.known = discovery.known_hosts()
        self.table.setRowCount(0)
        self.rows = []
        self.go.setEnabled(False)
        self.stop.setEnabled(True)
        self.bar.setRange(0, len(addrs))
        self.bar.setValue(0)
        self.status.setText(f"Scanning {len(addrs):,} address(es)...")
        audit.log("discovery scan", f"{self.target.text().strip()} ({len(addrs)} addresses)")
        self.worker = DiscoveryWorker(addrs, comms, ports)
        self.worker.found.connect(self._found)
        self.worker.progress.connect(lambda d, n: self.bar.setValue(d))
        self.worker.done.connect(self._done)
        self.worker.start()

    def halt(self):
        if self.running():
            self.worker.cancel.set()
            self.status.setText("Stopping...")

    def _found(self, r):
        i = len(self.rows)
        self.rows.append(r)
        self.table.insertRow(i)
        known = r["ip"] in self.known
        check = QTableWidgetItem("")
        check.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
        check.setCheckState(Qt.CheckState.Unchecked if known or not r["vendor"] else Qt.CheckState.Checked)
        self.table.setItem(i, 0, check)
        name = QTableWidgetItem(r["name"])
        self.table.setItem(i, 2, name)
        combo = QComboBox()
        for label, key in self.VENDOR_CHOICES:
            combo.addItem(label, key)
        combo.setCurrentIndex(max(0, combo.findData(r["vendor"])))
        self.table.setCellWidget(i, 3, combo)
        desc = r["descr"] or r["banner"] or r["cert"] or r["hint"]
        for col, text in ((1, r["ip"] + ("   (already in inventory)" if known else "")), (4, r["platform"]),
                          (5, desc), (6, ", ".join(map(str, r["ports"])) + (", SNMP" if r["snmp"] else ""))):
            it = QTableWidgetItem(text)
            it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(i, col, it)
        self.table.resizeColumnsToContents()

    def _done(self, found):
        self.go.setEnabled(True)
        self.stop.setEnabled(False)
        self.status.setText(f"Found {len(found)} device(s).  Unticked rows are already in the inventory or could not be identified.")

    def _check_all(self, on):
        for i in range(self.table.rowCount()):
            self.table.item(i, 0).setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)

    def checked_rows(self):
        out = []
        for i, r in enumerate(self.rows):
            if i < self.table.rowCount() and self.table.item(i, 0).checkState() == Qt.CheckState.Checked:
                row = dict(r)
                row["name"] = self.table.item(i, 2).text().strip() or r["ip"]
                row["vendor"] = self.table.cellWidget(i, 3).currentData()
                row["platform"] = r["platform"] if row["vendor"] == r["vendor"] else vendors.default_platform(row["vendor"])
                out.append(row)
        return out

    def add(self):
        rows = self.checked_rows()
        if not rows:
            QMessageBox.information(self, "Discovery", "Tick the devices to add first.")
            return
        added, skipped = discovery.add_to_inventory(rows, self.folder.currentData(), self.profile.currentData(),
                                                    self.location.text().strip(), self.tags.text().strip(), self.group.currentData())
        audit.log("devices added by discovery", ", ".join(added))
        msg = f"Added {len(added)} device(s)."
        if skipped:
            msg += "\n\nNot added:\n" + "\n".join(skipped)
        msg += ("\n\nThe SNMP community that answered was stored for each device. Add SSH or API credentials with a "
                "credential profile (Settings > Credentials) or in each device.") if added else ""
        QMessageBox.information(self, "Discovery", msg)
        self.known = discovery.known_hosts()
        for i in range(self.table.rowCount()):
            if self.table.item(i, 0).checkState() == Qt.CheckState.Checked and self.rows[i]["name"] is not None:
                self.table.item(i, 0).setCheckState(Qt.CheckState.Unchecked)
        self.inventory_changed()

    def inventory_changed(self):
        """Overridden by the Tools tab so other parts of the app notice new devices."""

    def shutdown(self):
        self.halt()
        if self.worker:
            self.worker.wait(3000)


# =============================================================================== Topology
class NodeItem(QGraphicsRectItem):
    def __init__(self, name, status, inventory, w=120, h=34):
        super().__init__(-w / 2, -h / 2, w, h)
        self.name, self.edges = name, []
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)
        self.setZValue(2)
        tk = theme.current() or {}
        bg = {"OK": reports.COLORS.get("OK"), "WARN": reports.COLORS.get("WARN"), "FAIL": reports.COLORS.get("FAIL"),
              "ERROR": reports.COLORS.get("ERROR")}.get(status) if inventory else None
        self.setBrush(QBrush(QColor(bg or tk.get("surface2", "#eeeeee"))))
        pen = QPen(QColor(tk.get("muted", "#888888")), 1.4)
        if not inventory:
            pen.setStyle(Qt.PenStyle.DashLine)
        self.setPen(pen)
        label = QGraphicsSimpleTextItem(name if len(name) <= 17 else name[:16] + "…", self)
        label.setBrush(QBrush(QColor(reports.fg_for(bg) if bg else tk.get("text", "#222222"))))
        r = label.boundingRect()
        label.setPos(-r.width() / 2, -r.height() / 2)

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for e in self.edges:
                e.update_line()
        return super().itemChange(change, value)


class EdgeItem(QGraphicsLineItem):
    def __init__(self, a, b, a_port, b_port, tip):
        super().__init__()
        self.a, self.b = a, b
        tk = theme.current() or {}
        self.setPen(QPen(QColor(tk.get("muted", "#888888")), 1.6))
        self.setZValue(1)
        self.setToolTip(tip)
        self.la, self.lb = QGraphicsSimpleTextItem(a_port, self), QGraphicsSimpleTextItem(b_port, self)
        for lab in (self.la, self.lb):
            f = lab.font()
            f.setPointSizeF(max(6.5, f.pointSizeF() - 2))
            lab.setFont(f)
            lab.setBrush(QBrush(QColor(tk.get("muted", "#888888"))))
        a.edges.append(self)
        b.edges.append(self)
        self.update_line()

    def update_line(self):
        p1, p2 = self.a.pos(), self.b.pos()
        self.setLine(p1.x(), p1.y(), p2.x(), p2.y())
        for lab, p, q in ((self.la, p1, p2), (self.lb, p2, p1)):
            d = q - p
            n = (d.x() ** 2 + d.y() ** 2) ** 0.5 or 1
            lab.setPos(p.x() + d.x() / n * 92 - lab.boundingRect().width() / 2, p.y() + d.y() / n * 48 - lab.boundingRect().height() / 2)


class TopologyView(QGraphicsView):
    def __init__(self):
        super().__init__()
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)

    def wheelEvent(self, e):
        f = 1.15 if e.angleDelta().y() > 0 else 1 / 1.15
        self.scale(f, f)

    def draw(self, nodes, links, positions, status):
        sc = self.scene()
        sc.clear()
        items = {}
        for name, info in nodes.items():
            x, y = positions.get(name, (0, 0))
            n = NodeItem(name, status.get(name, ""), info["inventory"])
            n.setPos(x, y)
            n.setToolTip(name + (f"\n{info['addr']}" if info["addr"] else "") + ("" if info["inventory"] else "\n(not in the inventory)"))
            sc.addItem(n)
            items[name] = n
        for l in links:
            e = EdgeItem(items[l["a"]], items[l["b"]], l["a_port"], l["b_port"],
                         f"{l['a']} {l['a_port']}  <->  {l['b']} {l['b_port']}\n{', '.join(sorted(l['protocols']))}")
            sc.addItem(e)
        sc.setSceneRect(sc.itemsBoundingRect().adjusted(-60, -60, 60, 60))
        self.resetTransform()
        self.fitInView(sc.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)


class TopologyWorker(QThread):
    done = Signal(list, dict)
    step = Signal(str)

    def __init__(self, devices):
        super().__init__()
        self.devices = devices

    def run(self):
        rows, errors = topology.collect(self.devices, on_done=self.step.emit)
        self.done.emit(rows, errors)


class TopologyTab(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.rows, self.nodes, self.links = [], {}, []
        self.group = GroupPicker()
        self.group.set_labels(db.group_labels()[1:])
        self.go = _primary("Discover neighbours")
        self.view_btn = QPushButton("Show map")
        self.view_btn.setCheckable(True)
        self.save_btn = QPushButton("Save picture...")
        self.status = _muted("")
        self.table = _table(["Device", "Local port", "Neighbour", "Neighbour port", "Protocol", "Address"])
        self.map = TopologyView()
        self.stack = QStackedWidget()
        self.stack.addWidget(self.table)
        self.stack.addWidget(self.map)
        top = QHBoxLayout()
        for w in (self.group, self.go, self.view_btn, self.save_btn):
            top.addWidget(w)
        top.addWidget(self.status, 1)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(_muted("Asks every device that has SNMP settings for its LLDP and CDP neighbours, then joins the answers "
                             "into one picture. Devices turn up as boxes coloured by their last health result; neighbours "
                             "that are not in the inventory are dashed. Drag boxes to tidy up, scroll to zoom."))
        lay.addWidget(self.stack, 1)
        self.go.clicked.connect(self.start)
        self.view_btn.toggled.connect(self._toggle)
        self.save_btn.clicked.connect(self.save_picture)
        self.refresh()

    def refresh(self):
        self.group.set_labels(db.group_labels()[1:])

    def _toggle(self, on):
        self.stack.setCurrentIndex(1 if on else 0)
        self.view_btn.setText("Show table" if on else "Show map")
        if on and self.nodes:
            self.draw_map()

    def running(self):
        return bool(self.worker and self.worker.isRunning())

    def start(self):
        if self.running():
            return
        devs = [d for d in topology.snmp_devices() if db.in_groups(d, self.group.selected())]
        if not devs:
            QMessageBox.information(self, "Topology", "No devices with SNMP settings. Set SNMP on a device (its SNMP tab) "
                                    "or use a credential profile that includes SNMP.")
            return
        self.go.setEnabled(False)
        self.total, self.n = len(devs), 0
        self.status.setText(f"Asking {len(devs)} device(s)...")
        self.worker = TopologyWorker(devs)
        self.worker.step.connect(self._step)
        self.worker.done.connect(self._done)
        self.worker.start()

    def _step(self, name):
        self.n += 1
        self.status.setText(f"{self.n} of {self.total} answered...")

    def _done(self, rows, errors):
        self.go.setEnabled(True)
        self.rows = rows
        self.nodes, self.links = topology.build_graph(rows)
        self.table.setRowCount(len(rows))
        for i, r in enumerate(sorted(rows, key=lambda r: (r["device"].lower(), r["local_port"]))):
            for j, v in enumerate([r["device"], r["local_port"], r["remote_name"], r["remote_port"], r["protocol"], r["remote_addr"]]):
                self.table.setItem(i, j, QTableWidgetItem(v))
        self.table.resizeColumnsToContents()
        msg = f"{len(self.links)} link(s) between {len(self.nodes)} device(s)."
        if errors:
            msg += f"  {len(errors)} device(s) failed: " + "; ".join(f"{k}: {v[:60]}" for k, v in list(errors.items())[:3])
        self.status.setText(msg)
        if self.view_btn.isChecked():
            self.draw_map()

    def draw_map(self):
        pos = topology.layout(self.nodes, self.links, 900, 600)
        self.map.draw(self.nodes, self.links, pos, topology.latest_status())

    def save_picture(self):
        if not self.nodes:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save picture", "topology.png", "PNG image (*.png)")
        if path:
            sc = self.map.scene()
            from PySide6.QtGui import QImage
            img = QImage(int(sc.sceneRect().width() * 2), int(sc.sceneRect().height() * 2), QImage.Format.Format_ARGB32)
            img.fill(QColor((theme.current() or {}).get("surface", "#ffffff")))
            p = QPainter(img)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            sc.render(p)
            p.end()
            img.save(path)

    def shutdown(self):
        if self.worker:
            self.worker.wait(5000)


# =============================================================================== Live ping / MTR
class PingWorker(QThread):
    sample = Signal(object)                       # milliseconds, or None for a lost reply

    def __init__(self, host, interval, timeout_ms):
        super().__init__()
        self.host, self.interval, self.timeout_ms = host, interval, timeout_ms
        self.stop_event = threading.Event()

    def run(self):
        while not self.stop_event.is_set():
            t0 = time.time()
            self.sample.emit(pinger.ping_once(self.host, self.timeout_ms))
            self.stop_event.wait(max(0.0, self.interval - (time.time() - t0)))


class LatencyGraph(QWidget):
    def __init__(self):
        super().__init__()
        self.samples = deque(maxlen=300)
        self.setMinimumHeight(220)

    def add(self, ms):
        self.samples.append(ms)
        self.update()

    def clear(self):
        self.samples.clear()
        self.update()

    def paintEvent(self, _):
        tk = theme.current() or {}
        col = lambda k, d: QColor(tk.get(k, d))
        surface, border, muted, accent = col("surface", "#fff"), col("border", "#ddd"), col("muted", "#777"), col("accent", "#2563eb")
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(QPen(border, 1))
        p.setBrush(surface)
        p.drawRoundedRect(QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5), 10, 10)
        r = QRectF(self.rect().adjusted(50, 16, -16, -26))
        vals = [s for s in self.samples if s is not None]
        if not self.samples:
            p.setPen(muted)
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "Press Start")
            return
        hi = max(10.0, (max(vals) if vals else 10.0) * 1.2)
        y = lambda v: r.bottom() - v / hi * r.height()
        n = self.samples.maxlen
        x = lambda i: r.right() - (len(self.samples) - 1 - i) * r.width() / (n - 1)
        for frac in (0, 0.5, 1):
            p.setPen(QPen(border, 1))
            p.drawLine(QPointF(r.left(), y(hi * frac)), QPointF(r.right(), y(hi * frac)))
            p.setPen(muted)
            p.drawText(QRectF(0, y(hi * frac) - 9, 44, 18), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, f"{hi * frac:.0f} ms")
        path = None
        for i, s in enumerate(self.samples):
            if s is None:                                       # a lost reply: a red tick on the floor
                p.setPen(QPen(QColor("#d32f2f"), 2))
                p.drawLine(QPointF(x(i), r.bottom()), QPointF(x(i), r.bottom() - 14))
                path = None
                continue
            pt = QPointF(x(i), y(s))
            if path is None:
                path = QPainterPath(pt)
            else:
                path.lineTo(pt)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(accent, 2))
        # draw the connected runs of replies as lines
        run = []
        for i, s in enumerate(list(self.samples) + [None]):
            if s is not None:
                run.append(QPointF(x(i), y(s)))
            else:
                if len(run) > 1:
                    pp = QPainterPath(run[0])
                    for q in run[1:]:
                        pp.lineTo(q)
                    p.drawPath(pp)
                elif len(run) == 1:
                    p.drawEllipse(run[0], 2, 2)
                run = []


class LivePingTab(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.picker = DevicePicker()
        self.host = QLineEdit()
        self.host.setPlaceholderText("hostname or IP address")
        self.interval, self.timeout = QSpinBox(), QSpinBox()
        self.interval.setRange(1, 60)
        self.interval.setValue(1)
        self.interval.setSuffix(" s")
        self.timeout.setRange(100, 10000)
        self.timeout.setValue(1000)
        self.timeout.setSuffix(" ms")
        self.go, self.stop, self.clear = _primary("Start"), QPushButton("Stop"), QPushButton("Reset")
        self.stop.setEnabled(False)
        self.graph = LatencyGraph()
        self.stats = QLabel("")
        self.stats.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.reset_stats()
        top = _row("Device", self.picker, "Host", self.host, "Every", self.interval, "Timeout", self.timeout, self.go, self.stop, self.clear)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.graph, 1)
        lay.addWidget(self.stats)
        self.go.clicked.connect(self.start)
        self.stop.clicked.connect(self.halt)
        self.clear.clicked.connect(self.reset_stats)
        self.host.returnPressed.connect(self.start)
        self.picker.currentIndexChanged.connect(lambda: self.picker.currentData() and self.host.setText(self.picker.currentData()["host"]))

    def reset_stats(self):
        self.sent = self.lost = 0
        self.vals = []
        self.graph.clear()
        self.show_stats()

    def show_stats(self):
        if not self.sent:
            self.stats.setText("")
            return
        v = self.vals
        jitter = sum(abs(a - b) for a, b in zip(v, v[1:])) / (len(v) - 1) if len(v) > 1 else 0.0
        self.stats.setText(f"sent {self.sent}   lost {self.lost} ({self.lost / self.sent * 100:.1f}%)   "
                           + (f"min {min(v):.0f}   avg {sum(v) / len(v):.1f}   max {max(v):.0f}   jitter {jitter:.1f} ms" if v else "no replies yet"))

    def running(self):
        return bool(self.worker and self.worker.isRunning())

    def start(self):
        if self.running():
            return
        try:
            host = nettools.check_target(self.host.text())
        except ValueError as e:
            self.stats.setText(str(e))
            return
        self.reset_stats()
        self.go.setEnabled(False)
        self.stop.setEnabled(True)
        self.worker = PingWorker(host, self.interval.value(), self.timeout.value())
        self.worker.sample.connect(self._sample)
        self.worker.start()

    def _sample(self, ms):
        self.sent += 1
        if ms is None:
            self.lost += 1
        else:
            self.vals.append(ms)
            del self.vals[:-3000]
        self.graph.add(ms)
        self.show_stats()

    def halt(self):
        if self.running():
            self.worker.stop_event.set()
            self.worker.wait(4000)
        self.go.setEnabled(True)
        self.stop.setEnabled(False)

    def shutdown(self):
        self.halt()


class MtrTab(QWidget):
    COLS = ["Hop", "Address", "Loss %", "Sent", "Last", "Avg", "Best", "Worst"]
    updated = Signal()

    def __init__(self):
        super().__init__()
        self.mtr = None
        self.picker = DevicePicker()
        self.host = QLineEdit()
        self.host.setPlaceholderText("hostname or IP address")
        self.go, self.stop = _primary("Start"), QPushButton("Stop")
        self.stop.setEnabled(False)
        self.status = _muted("")
        self.table = _table(self.COLS, stretch_last=False)
        top = _row("Device", self.picker, "Target", self.host, self.go, self.stop)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(_muted("Finds the route with a traceroute, then pings every router on it once a second and shows loss "
                             "and delay per hop. Loss that starts at one hop and continues to the end is real; loss at a single "
                             "hop only usually means that router ignores pings."))
        lay.addWidget(self.status)
        lay.addWidget(self.table, 1)
        self.go.clicked.connect(self.start)
        self.stop.clicked.connect(self.halt)
        self.host.returnPressed.connect(self.start)
        self.updated.connect(self.show_hops)
        self.picker.currentIndexChanged.connect(lambda: self.picker.currentData() and self.host.setText(self.picker.currentData()["host"]))

    def start(self):
        if self.mtr:
            return
        try:
            host = nettools.check_target(self.host.text())
        except ValueError as e:
            self.status.setText(str(e))
            return
        self.table.setRowCount(0)
        self.status.setText(f"Tracing the route to {host}...")
        self.go.setEnabled(False)
        self.stop.setEnabled(True)
        self.mtr = pinger.Mtr(host)
        self.mtr.start(on_update=self.updated.emit)

    def show_hops(self):
        if not self.mtr:
            return
        hops = self.mtr.snapshot()
        self.status.setText(f"{self.mtr.host}: {len(hops)} hop(s), {self.mtr.cycles} round(s)")
        self.table.setRowCount(len(hops))
        fmt = lambda v: "" if v is None else f"{v:.0f}"
        for i, h in enumerate(hops):
            cells = [str(h.number), h.address, f"{h.loss:.0f}", str(h.sent), fmt(h.last), fmt(h.avg), fmt(h.best), fmt(h.worst)]
            for j, v in enumerate(cells):
                it = QTableWidgetItem(v)
                if j == 2 and h.loss >= 50 and h.address != "*":
                    it.setForeground(QColor("#d32f2f"))
                elif j == 2 and h.loss > 0 and h.address != "*":
                    it.setForeground(QColor("#e6b800"))
                self.table.setItem(i, j, it)
        self.table.resizeColumnsToContents()

    def halt(self):
        if self.mtr:
            self.mtr.stop()
            self.mtr = None
        self.go.setEnabled(True)
        self.stop.setEnabled(False)

    def shutdown(self):
        self.halt()


# =============================================================================== Command runner
class CommandWorker(QThread):
    one = Signal(dict)
    done = Signal(list)

    def __init__(self, devices, commands, workers):
        super().__init__()
        self.devices, self.commands, self.workers = devices, commands, workers
        self.cancel = threading.Event()

    def run(self):
        res = cmdrun.run_many(self.devices, self.commands, self.workers, on_result=self.one.emit, cancel=self.cancel)
        self.done.emit(res)


class CommandRunnerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.results = {}
        self.group = GroupPicker()
        self.group.changed.connect(self.fill_devices)
        self.devs = QListWidget()
        self.devs.setMaximumWidth(280)
        self.all_btn, self.none_btn = QPushButton("All"), QPushButton("None")
        self.commands = QPlainTextEdit()
        self.commands.setPlaceholderText("one command per line, e.g.\nshow version\nshow ip interface brief")
        self.commands.setFixedHeight(110)
        self.commands.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.snippets = QComboBox()
        self.snippets.setMinimumWidth(140)
        self.snip_save, self.snip_del = QPushButton("Save snippet..."), QPushButton("Delete snippet")
        self.safe = QCheckBox("Read-only mode")
        self.safe.setChecked(True)
        self.safe.setToolTip("Blocks commands that could change a device (reload, configure, clear, copy ...)")
        self.go, self.stop = _primary("Run"), QPushButton("Stop")
        self.stop.setEnabled(False)
        self.status = _muted("")
        self.table = _table(["Device", "Result", "Seconds", "First line of output"])
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.output.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.save_btn, self.copy_btn = QPushButton("Save all output..."), QPushButton("Copy")
        left = QVBoxLayout()
        left.addWidget(QLabel("Devices"))
        left.addWidget(self.group)
        left.addWidget(self.devs, 1)
        lb = QHBoxLayout()
        lb.addWidget(self.all_btn)
        lb.addWidget(self.none_btn)
        left.addLayout(lb)
        right = QVBoxLayout()
        right.addLayout(_row("Snippets", self.snippets, self.snip_save, self.snip_del, self.safe, self.go, self.stop))   # wraps in a narrow window
        right.addWidget(self.commands)
        right.addWidget(self.status)
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.table)
        box = QWidget()
        bl = QVBoxLayout(box)
        bl.setContentsMargins(0, 0, 0, 0)
        bb = QHBoxLayout()
        bb.addStretch()
        bb.addWidget(self.copy_btn)
        bb.addWidget(self.save_btn)
        bl.addLayout(bb)
        bl.addWidget(self.output, 1)
        split.addWidget(box)
        split.setSizes([200, 320])
        right.addWidget(split, 1)
        lay = QHBoxLayout(self)
        lay.addLayout(left)
        lay.addLayout(right, 1)
        self.go.clicked.connect(self.start)
        self.stop.clicked.connect(self.halt)
        self.all_btn.clicked.connect(lambda: self._tick_all(True))
        self.none_btn.clicked.connect(lambda: self._tick_all(False))
        self.table.itemSelectionChanged.connect(self.show_output)
        self.snippets.activated.connect(self.load_snippet)
        self.snip_save.clicked.connect(self.save_snippet)
        self.snip_del.clicked.connect(self.delete_snippet)
        self.copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.output.toPlainText()))
        self.save_btn.clicked.connect(self.save_all)
        self.refresh()

    def refresh(self):
        self.group.set_labels(db.group_labels()[1:])
        self.fill_devices()
        self.fill_snippets()

    def ssh_devices(self):
        return [d for d in db.list_devices(enabled_only=True) if vendors.get(d["vendor"]).get("kind") == "ssh"
                and db.in_groups(d, self.group.selected())]

    def fill_devices(self):
        ticked = {self.devs.item(i).text() for i in range(self.devs.count()) if self.devs.item(i).checkState() == Qt.CheckState.Checked}
        self.devs.clear()
        for d in self.ssh_devices():
            it = QListWidgetItem(d["name"])
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(Qt.CheckState.Checked if d["name"] in ticked else Qt.CheckState.Unchecked)
            self.devs.addItem(it)

    def _tick_all(self, on):
        for i in range(self.devs.count()):
            self.devs.item(i).setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)

    def checked_devices(self):
        names = {self.devs.item(i).text() for i in range(self.devs.count()) if self.devs.item(i).checkState() == Qt.CheckState.Checked}
        return [d for d in self.ssh_devices() if d["name"] in names]

    # ---- snippets
    def fill_snippets(self):
        self.snippets.clear()
        self.snippets.addItem("(choose)", None)
        for s in db.get_setting("snippets"):
            self.snippets.addItem(s["name"], s["commands"])

    def load_snippet(self, _=None):
        c = self.snippets.currentData()
        if c is not None:
            self.commands.setPlainText(c)

    def save_snippet(self):
        from PySide6.QtWidgets import QInputDialog
        text = self.commands.toPlainText().strip()
        if not text:
            return
        name, ok = QInputDialog.getText(self, "Save snippet", "Name:")
        if ok and name.strip():
            snips = [s for s in db.get_setting("snippets") if s["name"].lower() != name.strip().lower()]
            snips.append({"name": name.strip(), "commands": text})
            db.set_setting("snippets", sorted(snips, key=lambda s: s["name"].lower()))
            self.fill_snippets()
            self.snippets.setCurrentIndex(self.snippets.findText(name.strip()))

    def delete_snippet(self):
        name = self.snippets.currentText()
        if self.snippets.currentData() is not None:
            db.set_setting("snippets", [s for s in db.get_setting("snippets") if s["name"] != name])
            self.fill_snippets()

    # ---- running
    def running(self):
        return bool(self.worker and self.worker.isRunning())

    def start(self):
        if self.running():
            return
        cmds = cmdrun.split_commands(self.commands.toPlainText())
        devs = self.checked_devices()
        if not cmds or not devs:
            self.status.setText("Tick at least one device and enter at least one command.")
            return
        risky = [c for c in cmds if not cmdrun.read_only(c)]
        if risky and self.safe.isChecked():
            self.status.setText("Blocked (read-only mode): " + "; ".join(risky[:3]) + ". Untick 'Read-only commands only' to allow them.")
            return
        if risky and QMessageBox.question(
                self, "Commands that may change devices",
                f"These commands could change the {len(devs)} selected device(s):\n\n" + "\n".join(risky[:8]) +
                "\n\nRun them anyway?") != QMessageBox.StandardButton.Yes:
            return
        audit.log("command run", f"{len(devs)} device(s): {'; '.join(cmds)[:300]}")
        self.results = {}
        self.table.setRowCount(0)
        self.output.clear()
        self.go.setEnabled(False)
        self.stop.setEnabled(True)
        self.total = len(devs)
        self.status.setText(f"Running on {len(devs)} device(s)...")
        self.worker = CommandWorker(devs, cmds, min(8, int(db.get_setting("workers"))))
        self.worker.one.connect(self._one)
        self.worker.done.connect(self._done)
        self.worker.start()

    def halt(self):
        if self.running():
            self.worker.cancel.set()
            self.status.setText("Stopping after the devices already running...")

    def _one(self, r):
        self.results[r["device"]] = r
        self.status.setText(f"{len(self.results)} of {self.total} finished...")

    def _done(self, results):
        self.go.setEnabled(True)
        self.stop.setEnabled(False)
        self.table.setRowCount(len(results))
        for i, r in enumerate(results):
            first = r["error"] or next((l for _, out in r["outputs"] for l in out.splitlines() if l.strip()), "")
            for j, v in enumerate([r["device"], "ok" if r["ok"] else "FAILED", f"{r['seconds']:.1f}", first]):
                it = QTableWidgetItem(v)
                if j == 1 and not r["ok"]:
                    it.setForeground(QColor("#d32f2f"))
                self.table.setItem(i, j, it)
        self.table.resizeColumnsToContents()
        bad = sum(1 for r in results if not r["ok"])
        self.status.setText(f"Done: {len(results) - bad} succeeded, {bad} failed.")
        if results:
            self.table.selectRow(0)

    def show_output(self):
        rows = {i.row() for i in self.table.selectedItems()}
        if len(rows) != 1:
            return
        r = self.results.get(self.table.item(next(iter(rows)), 0).text())
        if not r:
            return
        if r["error"]:
            self.output.setPlainText(f"FAILED: {r['error']}")
        else:
            self.output.setPlainText("\n\n".join(f"$ {c}\n{o}" for c, o in r["outputs"]))

    def save_all(self):
        if not self.results:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save output", f"command-output-{datetime.now():%Y%m%d-%H%M}.txt", "Text files (*.txt)")
        if path:
            parts = []
            for name in sorted(self.results, key=str.lower):
                r = self.results[name]
                parts.append(f"===== {name} " + ("=" * 40) + "\n" + (f"FAILED: {r['error']}" if r["error"] else "\n\n".join(f"$ {c}\n{o}" for c, o in r["outputs"])))
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n\n".join(parts))

    def shutdown(self):
        self.halt()
        if self.worker:
            self.worker.wait(5000)


# =============================================================================== TLS certificates
class TlsWorker(QThread):
    done = Signal(object)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            self.done.emit(self.fn())
        except Exception as e:
            self.done.emit(e)


def read_certificate(host, port, sni=None, timeout=8):
    """Everything about the certificate a server presents (the chain is not validated)."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with proxy.create_connection(None, (host, port), timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni or host) as s:
            der = s.getpeercert(binary_form=True)
            info = custom.cert_info(der)
            info["protocol"] = s.version() or ""
            info["cipher"] = (s.cipher() or ("", "", 0))[0]
    return info


class TlsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.picker = DevicePicker()
        self.host = QLineEdit()
        self.host.setPlaceholderText("hostname or IP address")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(443)
        self.sni = QLineEdit()
        self.sni.setPlaceholderText("server name (optional)")
        self.go = _primary("Check")
        self.audit_btn = QPushButton("Check every inventory device")
        self.status = _muted("")
        self.details = QLabel("")
        self.details.setTextFormat(Qt.TextFormat.RichText)
        self.details.setWordWrap(True)
        self.details.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.table = _table(["Device", "Address", "Subject", "Expires", "Days left", "Result"])
        top = _row("Device", self.picker, "Host", self.host, "Port", self.port, self.sni, self.go)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.status)
        lay.addWidget(self.details)
        row = QHBoxLayout()
        row.addWidget(QLabel("Audit"))
        row.addWidget(self.audit_btn)
        row.addStretch()
        lay.addLayout(row)
        lay.addWidget(self.table, 1)
        self.go.clicked.connect(self.check)
        self.host.returnPressed.connect(self.check)
        self.audit_btn.clicked.connect(self.audit)
        self.picker.currentIndexChanged.connect(lambda: self.picker.currentData() and self.host.setText(self.picker.currentData()["host"]))

    def check(self):
        if self.worker and self.worker.isRunning():
            return
        try:
            host = nettools.check_target(self.host.text())
        except ValueError as e:
            self.status.setText(str(e))
            return
        port, sni = self.port.value(), self.sni.text().strip() or None
        self.status.setText(f"Connecting to {host}:{port}...")
        self.go.setEnabled(False)
        self.worker = TlsWorker(lambda: read_certificate(host, port, sni))
        self.worker.done.connect(self._shown)
        self.worker.start()

    def _shown(self, res):
        self.go.setEnabled(True)
        if isinstance(res, Exception):
            self.status.setText(f"No certificate: {res}")
            self.details.setText("")
            return
        d = res["days_left"]
        color = "#d32f2f" if d < 7 else "#e6b800" if d < 30 else "#16a34a"
        esc = lambda s: str(s).replace("&", "&amp;").replace("<", "&lt;")
        self.status.setText("")
        self.details.setText(
            f"<table cellpadding='3'>"
            f"<tr><td><b>Subject</b></td><td>{esc(res['subject'])}</td></tr>"
            f"<tr><td><b>Issuer</b></td><td>{esc(res['issuer'])}</td></tr>"
            f"<tr><td><b>Valid</b></td><td>{res['not_before']:%Y-%m-%d} to {res['not_after']:%Y-%m-%d}</td></tr>"
            f"<tr><td><b>Days left</b></td><td><span style='color:{color}; font-weight:600'>{d}</span>"
            f"{'  (EXPIRED)' if d < 0 else ''}</td></tr>"
            f"<tr><td><b>Names</b></td><td>{esc(', '.join(res['sans']) or '(none)')}</td></tr>"
            f"<tr><td><b>Connection</b></td><td>{esc(res['protocol'])}  {esc(res['cipher'])}</td></tr>"
            f"<tr><td><b>Serial</b></td><td>{esc(res['serial'])}</td></tr></table>")

    def audit(self):
        if self.worker and self.worker.isRunning():
            return
        devs = db.list_devices(enabled_only=True)
        port = self.port.value()
        if not devs:
            return
        self.table.setRowCount(0)
        self.status.setText(f"Checking {len(devs)} device(s) on port {port}...")
        self.audit_btn.setEnabled(False)

        def run():
            from concurrent.futures import ThreadPoolExecutor
            def one(d):
                try:
                    return d, read_certificate(d["host"], port, None, 4), ""
                except Exception as e:
                    return d, None, str(e)[:80]
            with ThreadPoolExecutor(max_workers=16) as pool:
                return list(pool.map(one, devs))
        self.worker = TlsWorker(run)
        self.worker.done.connect(self._audited)
        self.worker.start()

    def _audited(self, res):
        self.audit_btn.setEnabled(True)
        if isinstance(res, Exception):
            self.status.setText(f"Failed: {res}")
            return
        res.sort(key=lambda r: (r[1] is None, r[1]["days_left"] if r[1] else 0))
        self.table.setRowCount(len(res))
        for i, (d, info, err) in enumerate(res):
            if info:
                dl = info["days_left"]
                cells = [d["name"], d["host"], info["subject"], f"{info['not_after']:%Y-%m-%d}", str(dl),
                         "EXPIRED" if dl < 0 else "expires soon" if dl < 30 else "ok"]
            else:
                cells = [d["name"], d["host"], "", "", "", err or "no certificate"]
            for j, v in enumerate(cells):
                it = QTableWidgetItem(v)
                if info and j in (4, 5):
                    it.setForeground(QColor("#d32f2f" if info["days_left"] < 7 else "#e6b800" if info["days_left"] < 30 else "#16a34a"))
                self.table.setItem(i, j, it)
        self.table.resizeColumnsToContents()
        self.status.setText(f"{sum(1 for r in res if r[1])} of {len(res)} device(s) presented a certificate.")

    def shutdown(self):
        if self.worker:
            self.worker.wait(8000)


# =============================================================================== Listeners (syslog + traps)
class ListenersTab(QWidget):
    message = Signal(dict)
    MAX_ROWS = 5000

    def __init__(self):
        super().__init__()
        self.syslog = self.traps = None
        self.paused = False
        self.rows = []
        self.sys_port, self.trap_port = QSpinBox(), QSpinBox()
        for s, v in ((self.sys_port, 514), (self.trap_port, 162)):
            s.setRange(1, 65535)
            s.setValue(v)
        self.communities = QLineEdit("public")
        self.communities.setPlaceholderText("trap communities, comma separated")
        self.sys_btn, self.trap_btn = QPushButton("Start syslog"), QPushButton("Start trap receiver")
        self.pause, self.clear, self.save = QPushButton("Pause"), QPushButton("Clear"), QPushButton("Save...")
        self.pause.setCheckable(True)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("filter the list")
        self.kind = QComboBox()
        self.kind.addItems(["Everything", "Syslog only", "Traps only"])
        self.sev = QComboBox()
        self.sev.addItem("Any severity", 7)
        for n, name in enumerate(listeners.SEVERITIES):
            self.sev.addItem(f"{name} and worse", n)
        self.status = _muted("Not listening. Port 514 and 162 are the standard ones; point devices at this computer's address.")
        self.table = _table(["Time", "Type", "From", "Device", "Severity", "Message"])
        top = _row("Syslog UDP", self.sys_port, self.sys_btn, "Traps UDP", self.trap_port, self.communities, self.trap_btn)
        bar = _row(self.kind, self.sev, self.filter, self.pause, self.clear, self.save)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addLayout(bar)
        lay.addWidget(self.status)
        lay.addWidget(self.table, 1)
        self.sys_btn.clicked.connect(self.toggle_syslog)
        self.trap_btn.clicked.connect(self.toggle_traps)
        self.message.connect(self.on_message)
        self.pause.toggled.connect(lambda on: setattr(self, "paused", on))
        self.clear.clicked.connect(self.clear_rows)
        self.save.clicked.connect(self.save_rows)
        for w in (self.kind, self.sev):
            w.currentIndexChanged.connect(self.repaint_rows)
        self.filter.textChanged.connect(self.repaint_rows)

    # ---- start / stop
    def toggle_syslog(self):
        if self.syslog:
            self.syslog.stop()
            self.syslog = None
        else:
            try:
                self.syslog = listeners.SyslogListener(self.sys_port.value(), on_message=lambda m: self.message.emit({**m, "type": "syslog"}))
                self.syslog.start()
            except OSError as e:
                self.syslog = None
                self.status.setText(f"Could not listen on UDP {self.sys_port.value()}: {e}")
        self._buttons()

    def toggle_traps(self):
        if self.traps:
            self.traps.stop()
            self.traps = None
        else:
            comms = [c.strip() for c in self.communities.text().split(",") if c.strip()]
            try:
                self.traps = listeners.TrapListener(self.trap_port.value(), comms, on_trap=lambda m: self.message.emit({**m, "type": "trap", "severity": "", "severity_no": 6}))
                self.traps.start()
            except OSError as e:
                self.traps = None
                self.status.setText(f"Could not listen on UDP {self.trap_port.value()}: {e}")
        self._buttons()

    def _buttons(self):
        self.sys_btn.setText("Stop syslog" if self.syslog else "Start syslog")
        self.trap_btn.setText("Stop trap receiver" if self.traps else "Start trap receiver")
        for w in (self.sys_port,):
            w.setEnabled(not self.syslog)
        for w in (self.trap_port, self.communities):
            w.setEnabled(not self.traps)
        on = [n for n, o in (("syslog", self.syslog), ("traps", self.traps)) if o]
        if on:
            ips = ", ".join(sorted({i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)}))
            self.status.setText(f"Listening for {' and '.join(on)}. Send to: {ips}")
        elif not self.status.text().startswith("Could not"):
            self.status.setText("Not listening.")

    # ---- rows
    def wanted(self, m):
        if self.kind.currentIndex() == 1 and m["type"] != "syslog":
            return False
        if self.kind.currentIndex() == 2 and m["type"] != "trap":
            return False
        if m["type"] == "syslog" and m["severity_no"] > self.sev.currentData():
            return False
        f = self.filter.text().strip().lower()
        return not f or f in (m["text"] + " " + m["source"] + " " + m.get("device", "")).lower()

    def _add_row(self, m):
        i = self.table.rowCount()
        self.table.insertRow(i)
        for j, v in enumerate([m["time"], m["type"], m["source"], m.get("device", ""), m.get("severity", ""), m["text"] if m["type"] == "syslog" else (m.get("trap", "") + "  " + m["text"]).strip()]):
            it = QTableWidgetItem(v)
            if j == 4 and m.get("severity_no", 7) <= 3:
                it.setForeground(QColor("#d32f2f"))
            elif j == 4 and m.get("severity_no", 7) == 4:
                it.setForeground(QColor("#e6b800"))
            self.table.setItem(i, j, it)

    def on_message(self, m):
        if self.paused:
            return
        self.rows.append(m)
        del self.rows[:-self.MAX_ROWS]
        if self.wanted(m):
            self._add_row(m)
            if self.table.rowCount() > self.MAX_ROWS:
                self.table.removeRow(0)
            self.table.scrollToBottom()

    def repaint_rows(self, *_):
        self.table.setRowCount(0)
        for m in self.rows:
            if self.wanted(m):
                self._add_row(m)
        self.table.resizeColumnsToContents()

    def clear_rows(self):
        self.rows.clear()
        self.table.setRowCount(0)

    def save_rows(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save messages", f"messages-{datetime.now():%Y%m%d-%H%M}.txt", "Text files (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                for m in self.rows:
                    if self.wanted(m):
                        fh.write(f"{m['time']}\t{m['type']}\t{m['source']}\t{m.get('device', '')}\t{m.get('severity', '')}\t{m['text']}\n")

    def shutdown(self):
        for o in (self.syslog, self.traps):
            if o:
                o.stop()
        self.syslog = self.traps = None


# =============================================================================== MAC utilities
class UtilitiesTab(QWidget):
    def __init__(self):
        super().__init__()
        self.mac = QLineEdit()
        self.mac.setPlaceholderText("AA:BB:CC:DD:EE:FF   (any common format; the first six digits are enough for a lookup)")
        self.lookup_out = QLabel("")
        self.lookup_out.setTextFormat(Qt.TextFormat.RichText)
        self.lookup_out.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.update_btn = QPushButton("Update OUI database...")
        self.oui_info = _muted("")
        self.wol_mac, self.wol_bcast = QLineEdit(), QLineEdit("255.255.255.255")
        self.wol_mac.setPlaceholderText("MAC address of the computer to wake")
        self.wol_port = QSpinBox()
        self.wol_port.setRange(1, 65535)
        self.wol_port.setValue(9)
        self.wol_btn = _primary("Send magic packet")
        self.wol_out = _muted("")
        look = QFormLayout()
        look.addRow("MAC address", self.mac)
        look.addRow("", self.lookup_out)
        wol = QFormLayout()
        wol.addRow("MAC address", self.wol_mac)
        wol.addRow("Broadcast address", self.wol_bcast)
        wol.addRow("UDP port", self.wol_port)
        wol.addRow("", self.wol_btn)
        wol.addRow("", self.wol_out)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("<b>MAC address lookup</b>"))
        lay.addLayout(look)
        row = QHBoxLayout()
        row.addWidget(self.update_btn)
        row.addWidget(self.oui_info, 1)
        lay.addLayout(row)
        lay.addSpacing(18)
        lay.addWidget(QLabel("<b>Wake-on-LAN</b>"))
        lay.addWidget(_muted("Sends a magic packet to the broadcast address of the computer's network. The target must be "
                             "on the same network segment and have Wake-on-LAN switched on in its firmware."))
        lay.addLayout(wol)
        lay.addStretch()
        self.mac.textChanged.connect(self.show_lookup)
        self.update_btn.clicked.connect(self.update_db)
        self.wol_btn.clicked.connect(self.send)
        self.show_info()

    def show_info(self):
        p = oui.cache_path()
        self.oui_info.setText(f"Full IEEE list installed ({p.stat().st_size // 1024:,} KB)." if p.exists() else
                              "Using the short built-in list. Update to look up any manufacturer.")

    def show_lookup(self, text):
        text = text.strip()
        if not text:
            self.lookup_out.setText("")
            return
        digits = "".join(c for c in text if c in "0123456789abcdefABCDEF")
        try:
            if len(digits) == 12:
                full = oui.normalize(text)
                vendor = oui.lookup(full) or "unknown manufacturer"
                self.lookup_out.setText(
                    f"<b>{vendor}</b><br><span style='font-family:Consolas'>{oui.pretty(full)}<br>{oui.pretty(full, '-')}<br>"
                    f"{full[:4].lower()}.{full[4:8].lower()}.{full[8:].lower()}<br>{full.lower()}</span>")
            elif len(digits) >= 6:
                vendor = oui.lookup((digits + "000000")[:12]) or "unknown manufacturer"
                self.lookup_out.setText(f"<b>{vendor}</b>")
            else:
                self.lookup_out.setText("")
        except ValueError as e:
            self.lookup_out.setText(str(e))

    def update_db(self):
        if QMessageBox.question(self, "Update OUI database", "This downloads the manufacturer list (about 6 MB) from "
                                "standards-oui.ieee.org.\n\nDownload now?") != QMessageBox.StandardButton.Yes:
            return
        QApplication.setOverrideCursor(self.cursor())
        try:
            n = oui.update_from_ieee()
            self.oui_info.setText(f"Updated: {n:,} manufacturers.")
        except Exception as e:
            self.oui_info.setText(f"Update failed: {e}")
        finally:
            QApplication.restoreOverrideCursor()
        self.show_lookup(self.mac.text())

    def send(self):
        try:
            n = oui.send_wol(self.wol_mac.text(), self.wol_bcast.text().strip(), self.wol_port.value())
        except (ValueError, OSError) as e:
            self.wol_out.setText(str(e))
            return
        audit.log("wake-on-lan", self.wol_mac.text())
        self.wol_out.setText(f"Sent a {n}-byte magic packet to {self.wol_bcast.text().strip()}:{self.wol_port.value()}.")

    def shutdown(self):
        pass
