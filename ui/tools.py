import csv
import threading
from datetime import datetime

import keyring
from PySide6.QtCore import QObject, QProcess, QThread, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFontDatabase
from PySide6.QtWidgets import (QAbstractItemView, QApplication as _QApp, QCheckBox, QComboBox, QCompleter, QFileDialog, QGroupBox, QHBoxLayout, QLabel,
                               QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QSplitter,
                               QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget)
from core import db, jump, nettools, profiles, reach, sessionlog, snmp, vendors


class OutputBox(QPlainTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setMaximumBlockCount(20000)
        self.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

    def add(self, text):
        sb = self.verticalScrollBar()
        follow = sb.value() >= sb.maximum() - 4         # only auto-scroll if already at the bottom
        self.moveCursor(self.textCursor().MoveOperation.End)
        self.insertPlainText(text)
        if follow:
            sb.setValue(sb.maximum())

    def line(self, text):
        self.add(text.rstrip("\n") + "\n")


class DevicePicker(QComboBox):
    """Inventory device chooser; item data is the device dict (None = type it in by hand)."""
    def __init__(self):
        super().__init__()
        self.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.setMinimumContentsLength(20)
        self.refresh()

    def refresh(self):
        cur = self.currentText()
        self.blockSignals(True)
        self.clear()
        self.addItem("(enter manually)", None)
        several = db.several()
        for d in db.list_devices():
            place = " / ".join(x for x in ((db.org_name(d["org"]) if several else ""), db.path_of(d)) if x)    # Global: whose it is
            where = f"   [{place}]" if place else ""
            self.addItem(f"{d['name']}  —  {d['host']}{where}", d)
        i = self.findText(cur)
        self.setCurrentIndex(max(0, i))
        self.blockSignals(False)


class Runner(QObject):
    """Runs one external program and streams its output. Arguments are a list; no shell is used."""
    output = Signal(str)
    finished = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.proc = QProcess(self)
        self.proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.proc.readyReadStandardOutput.connect(self._read)
        self.proc.finished.connect(self._done)
        self.proc.errorOccurred.connect(self._error)

    def running(self):
        return self.proc.state() != QProcess.ProcessState.NotRunning

    def start(self, program, args):
        self.proc.start(program, args)

    def stop(self):
        if self.running():
            self.proc.kill()
            self.proc.waitForFinished(1000)

    def _read(self):
        from core.platforms import WINDOWS                         # Windows' console programs write in its OEM code page
        self.output.emit(bytes(self.proc.readAllStandardOutput()).decode("oem" if WINDOWS else "utf-8", "replace").replace("\r\n", "\n"))

    def _done(self, code, _status):
        self._read()
        self.output.emit(f"\n[finished, exit code {code}]\n")
        self.finished.emit()

    def _error(self, err):
        if err == QProcess.ProcessError.FailedToStart:
            self.output.emit(f"Could not start the program: {self.proc.errorString()}\n")
            self.finished.emit()


def _row(*widgets):
    """A row of captioned boxes and buttons that wraps onto a second line when the window is narrow."""
    from ui.widgets import flow
    return flow(*widgets)


# ---------------------------------------------------------------- session logs
class LogsTab(QWidget):
    COLS = ["Started", "Ended", "Duration", "Type", "Device", "Host", "User", "Result"]
    MAX_VIEW = 2_000_000

    def __init__(self):
        super().__init__()
        self.sessions = []
        self.table = QTableWidget(0, len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.itemSelectionChanged.connect(self.show_log)
        self.view = OutputBox()
        refresh, folder = QPushButton("Refresh"), QPushButton("Open log folder")
        refresh.clicked.connect(self.refresh)
        folder.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(sessionlog.log_dir()))))
        self.note = QLabel("")
        bar = QHBoxLayout()
        bar.addWidget(refresh)
        bar.addWidget(folder)
        bar.addWidget(self.note, 1)
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.table)
        split.addWidget(self.view)
        split.setSizes([220, 380])
        lay = QVBoxLayout(self)
        lay.addLayout(bar)
        lay.addWidget(split, 1)
        self.refresh()

    @staticmethod
    def _duration(s):
        if not s["ended_at"]:
            return ""
        a = datetime.strptime(s["started_at"], "%Y-%m-%d %H:%M:%S")
        b = datetime.strptime(s["ended_at"], "%Y-%m-%d %H:%M:%S")
        secs = int((b - a).total_seconds())
        return f"{secs // 3600}h {secs % 3600 // 60}m {secs % 60}s"

    def refresh(self):
        keep = self.current_id()
        self.sessions = sessionlog.list_sessions()
        self.table.blockSignals(True)
        self.table.setRowCount(len(self.sessions))
        for i, s in enumerate(self.sessions):
            vals = [s["started_at"], s["ended_at"] or "(open, or not closed cleanly)", self._duration(s),
                    (s.get("kind") or "ssh").upper(), s["device"], f"{s['host']}:{s['port']}", s["username"], s["reason"] or ""]
            for j, v in enumerate(vals):
                self.table.setItem(i, j, QTableWidgetItem(str(v)))
            if s["id"] == keep:
                self.table.selectRow(i)
        self.table.resizeColumnsToContents()
        self.table.blockSignals(False)
        self.note.setText(f"{len(self.sessions)} session(s) logged in {sessionlog.log_dir()}")
        self.show_log()

    def current_id(self):
        rows = {i.row() for i in self.table.selectedIndexes()}
        return self.sessions[rows.pop()]["id"] if len(rows) == 1 and self.sessions else None

    def show_log(self):
        sid = self.current_id()
        s = next((x for x in self.sessions if x["id"] == sid), None)
        self.view.clear()
        if not s:
            return
        try:
            with open(s["log_path"], "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - self.MAX_VIEW))
                text = f.read().decode("utf-8", "replace")
            if size > self.MAX_VIEW:
                text = f"[showing the last {self.MAX_VIEW // 1000} KB of {size // 1000} KB - open the file for all of it]\n" + text
            self.view.setPlainText(text)
        except OSError as e:
            self.view.setPlainText(f"The log file could not be opened: {e}\n{s['log_path']}")


# ---------------------------------------------------------------- ping / traceroute / DNS
class DiagnosticsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.picker = DevicePicker()
        self.target = QLineEdit()
        self.target.setPlaceholderText("hostname or IP address")
        self.out = OutputBox()
        self.runner = Runner(self)
        self.runner.output.connect(self.out.add)
        self.buttons = {}
        row = QHBoxLayout()
        for text, fn in (("Ping", self.ping), ("Traceroute", self.trace), ("DNS lookup", self.dns)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            row.addWidget(b)
            self.buttons[text] = b
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop)
        clear = QPushButton("Clear")
        clear.clicked.connect(self.out.clear)
        row.addWidget(self.stop_btn)
        row.addWidget(clear)
        self.via_proxy = QCheckBox("Through the proxy (TCP)")
        self.via_proxy.toggled.connect(lambda _on: self._busy(self.busy()))
        row.addWidget(self.via_proxy)
        row.addStretch()
        self.tcp = None
        lay = QVBoxLayout(self)
        lay.addLayout(_row("Device", self.picker, "Target", self.target))
        lay.addLayout(row)
        lay.addWidget(self.out, 1)
        self.picker.currentIndexChanged.connect(
            lambda: self.picker.currentData() and self.target.setText(self.picker.currentData()["host"]))
        self.runner.finished.connect(lambda: self._busy(False))

    def busy(self):
        return self.runner.running() or bool(self.tcp and self.tcp.isRunning())

    def _busy(self, on):
        for b in self.buttons.values():
            b.setEnabled(not on)
        tcp = self.via_proxy.isChecked()
        self.buttons["Traceroute"].setEnabled(not on and not tcp)        # a route cannot be traced through a proxy
        self.buttons["Traceroute"].setToolTip(reach.TRACE_NEEDS_ICMP if tcp else "")
        self.stop_btn.setEnabled(on)

    def stop(self):
        self.runner.stop()
        if self.tcp:
            self.tcp.stop_event.set()

    def _run(self, program, args, title):
        try:
            target = nettools.check_target(self.target.text())
        except ValueError as e:
            self.out.line(str(e))
            return
        self.out.line(f"\n> {title} {target}")
        self._busy(True)
        self.runner.start(program, args + [target])

    def ping(self):
        if not self.via_proxy.isChecked():
            from core.platforms import WINDOWS
            self._run("ping", ["-n", "4"] if WINDOWS else ["-c", "4"], "ping")       # four echoes (-c elsewhere)
            return
        try:
            target = nettools.check_target(self.target.text())
        except ValueError as e:
            self.out.line(str(e))
            return
        d = self.picker.currentData()
        dev = d if isinstance(d, dict) and d.get("host") == target else {}       # the chosen device's own proxy, else the global one
        self.out.line(f"\n> TCP ping {target}")
        self._busy(True)
        self.tcp = TcpPing(dev, target)
        self.tcp.line.connect(self.out.line)
        self.tcp.finished.connect(lambda: self._busy(False))
        self.tcp.start()

    def trace(self):
        from core.platforms import WINDOWS
        if WINDOWS:
            self._run("tracert", ["-d", "-h", "30"], "tracert")
        else:
            self._run("traceroute", ["-n", "-m", "30"], "traceroute")

    def dns(self):
        self._run("nslookup", [], "nslookup")

    def shutdown(self):
        self.stop()
        if self.tcp:
            self.tcp.wait(6000)


class TcpPing(QThread):
    """Ping with Through the proxy (TCP) ticked: four TCP connections to the management port, a second apart."""
    line = Signal(str)

    def __init__(self, dev, host, count=4):
        super().__init__()
        self.dev, self.host, self.count = dev, host, count
        self.stop_event = threading.Event()

    def run(self):
        for i in range(self.count):
            if self.stop_event.is_set():
                break
            self.line.emit(reach.line(reach.probe(self.dev, host=self.host), self.host))
            if i < self.count - 1:
                self.stop_event.wait(1.0)


# ---------------------------------------------------------------- port scanner
class ScanTab(QWidget):
    def __init__(self):
        super().__init__()
        self.nmap = nettools.find_nmap()
        self.scan = None
        self.picker = DevicePicker()
        self.target = QLineEdit()
        self.target.setPlaceholderText("host, 10.0.0.0/24, or 10.0.0.1-50 (ranges need nmap)")
        self.profile = QComboBox()
        self.profile.addItems(nettools.NMAP_PROFILES)
        self.ports = QLineEdit()
        self.ports.setPlaceholderText("e.g. 22,80,443 or 1-1024")
        self.go = QPushButton("Scan")
        self.go.setProperty("primary", True)
        self.stop = QPushButton("Stop")
        self.stop.setEnabled(False)
        self.out = OutputBox()
        self.runner = Runner(self)
        self.runner.output.connect(self.out.add)
        self.runner.finished.connect(lambda: self._busy(False))

        from core.platforms import WINDOWS
        from ui import installdlg
        self.engine = QLabel(
            f"Engine: nmap ({self.nmap})" if self.nmap else
            "nmap is not installed, so the built-in TCP scanner is used (single host or up to a /24; "
            "blank ports = 30 common ports). " + ("For full nmap scans run: winget install Insecure.Nmap" if WINDOWS else
                                                  "For full nmap scans install nmap (for example: sudo apt install nmap)."))
        self.engine.setWordWrap(True)
        self.install_nmap = installdlg.button("nmap", self, done=self._nmap_installed)
        self.install_nmap.setVisible(not self.nmap and installdlg.offered("nmap"))
        lay = QVBoxLayout(self)
        lay.addWidget(self.engine)
        lay.addWidget(self.install_nmap, 0, Qt.AlignmentFlag.AlignLeft)
        lay.addLayout(_row("Device", self.picker, "Target", self.target))
        lay.addLayout(_row("Profile", self.profile, "Ports", self.ports, self.go, self.stop))
        lay.addWidget(self.out, 1)
        self.profile.setEnabled(bool(self.nmap))
        self.go.clicked.connect(self.start)
        self.stop.clicked.connect(self.halt)
        self.picker.currentIndexChanged.connect(
            lambda: self.picker.currentData() and self.target.setText(self.picker.currentData()["host"]))

    def _nmap_installed(self):
        self.nmap = nettools.find_nmap()
        if self.nmap:
            self.engine.setText(f"Engine: nmap ({self.nmap})")
            self.install_nmap.hide()

    def _busy(self, on):
        self.go.setEnabled(not on)
        self.stop.setEnabled(on)

    def start(self):
        try:
            target = nettools.check_target(self.target.text())
            if self.nmap:
                args = nettools.nmap_args(self.profile.currentText(), target, self.ports.text())
            else:
                ports = nettools.parse_ports(self.ports.text()) if self.ports.text().strip() \
                    else nettools.COMMON_PORTS
        except ValueError as e:
            self.out.line(f"Error: {e}")
            return
        limit = int(db.get_setting("scan_confirm_over"))
        n = nettools.count_addresses(target)
        if limit and n > limit and QMessageBox.question(
                self, "Large scan", f"{target} covers {n:,} addresses, more than the {limit:,} you asked "
                "to be warned about (Settings > Security).\n\nScan anyway?") != QMessageBox.StandardButton.Yes:
            return
        self.out.line(f"\n> scan {target}")
        self._busy(True)
        if self.nmap:
            self.runner.start(self.nmap, args)
        else:
            self.scan = nettools.TcpScan(target, ports)
            self.scan.line.connect(self.out.line)
            self.scan.finished.connect(lambda: self._busy(False))
            self.scan.start()

    def halt(self):
        self.runner.stop()
        if self.scan and self.scan.isRunning():
            self.scan.stop()

    def shutdown(self):
        self.halt()
        if self.scan:
            self.scan.wait(3000)


# ---------------------------------------------------------------- subnet calculator
class SubnetTab(QWidget):
    def __init__(self):
        super().__init__()
        self.inp = QLineEdit()
        self.inp.setPlaceholderText("192.168.1.10/24   or   10.0.0.0/255.255.255.0   or   2001:db8::/64")
        self.out = OutputBox()
        lay = QVBoxLayout(self)
        lay.addLayout(_row("Address / prefix", self.inp))
        lay.addWidget(self.out, 1)
        self.inp.textChanged.connect(self.calc)

    def calc(self, text):
        try:
            self.out.setPlainText(nettools.subnet_info(text) if text.strip() else "")
        except ValueError as e:
            self.out.setPlainText(f"Not a valid address: {e}")


# ---------------------------------------------------------------- SNMP
class SnmpWorker(QThread):
    rows = Signal(list)
    done = Signal(object)

    def __init__(self, args, parent=None):
        super().__init__(parent)
        self.args, self.cancel = args, threading.Event()

    def run(self):
        host, port, creds, op, oid, timeout, retries, max_rows = self.args
        stream = None if op in ("interfaces", "rates", "neighbors") else self.rows.emit        # interfaces are pivoted at the end
        self.done.emit(snmp.query(host, port, creds, op, oid, timeout, retries, max_rows, self.cancel, stream))


class SnmpTab(QWidget):
    """Read-only SNMP: Get, Get next, Walk, Bulk walk, plus ready-made System info and Interfaces."""
    RAW_COLS = ["OID", "Name", "Type", "Value"]

    def __init__(self):
        super().__init__()
        self.worker = None
        self.picker = DevicePicker()
        self.host = QLineEdit()
        self.host.setPlaceholderText("hostname or IP address")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(161)
        self.version = QComboBox()
        for label, v in snmp.VERSIONS:
            self.version.addItem(label, v)
        self.community = QLineEdit()
        self.community.setEchoMode(QLineEdit.EchoMode.Password)
        self.community.setPlaceholderText("community string")
        self.show_secrets = QCheckBox("Show")
        self.show_secrets.setToolTip("Show the community string and passwords. They are never saved.")

        self.v3 = QGroupBox("SNMPv3")
        self.user = QLineEdit()
        self.level = QComboBox()
        self.level.addItems(snmp.LEVELS)
        self.auth_proto, self.priv_proto = QComboBox(), QComboBox()
        self.auth_proto.addItems(snmp.AUTH_PROTOCOLS)
        self.priv_proto.addItems(snmp.PRIV_PROTOCOLS)
        self.auth_key, self.priv_key = QLineEdit(), QLineEdit()
        for e in (self.auth_key, self.priv_key):
            e.setEchoMode(QLineEdit.EchoMode.Password)
        v3 = QVBoxLayout(self.v3)
        v3.addLayout(_row("User", self.user, "Security level", self.level))
        v3.addLayout(_row("Authentication", self.auth_proto, self.auth_key))
        v3.addLayout(_row("Privacy", self.priv_proto, self.priv_key))

        self.op = QComboBox()
        for label, v in snmp.OPERATIONS:
            self.op.addItem(label, v)
        self.oid = QLineEdit("sysDescr.0")
        self.oid.setPlaceholderText("OID or name, e.g. sysDescr.0, ifTable, 1.3.6.1.2.1.1")
        self.oid.setCompleter(QCompleter(sorted(snmp.NAMES), self.oid))
        self.oid.completer().setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.timeout, self.retries, self.max_rows = QSpinBox(), QSpinBox(), QSpinBox()
        self.timeout.setRange(1, 60)
        self.timeout.setValue(3)
        self.timeout.setSuffix(" s")
        self.retries.setRange(0, 5)
        self.retries.setValue(1)
        self.max_rows.setRange(1, snmp.MAX_ROWS)
        self.max_rows.setValue(2000)
        self.max_rows.setToolTip("A walk stops after this many rows")
        self.go, self.stop = QPushButton("Run"), QPushButton("Stop")
        self.go.setProperty("primary", True)
        self.stop.setEnabled(False)
        self.copy_btn, self.clear_btn = QPushButton("Copy results"), QPushButton("Clear")
        self.save_btn = QPushButton("Save...")
        self.save_btn.setToolTip("Save the results as a CSV file")
        self.status = QLabel("")
        self.table = QTableWidget(0, len(self.RAW_COLS))
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self._columns(self.RAW_COLS)

        lay = QVBoxLayout(self)
        lay.addLayout(_row("Device", self.picker, "Host", self.host, "Port", self.port))
        lay.addLayout(_row("Version", self.version, "Community", self.community, self.show_secrets))
        lay.addWidget(self.v3)
        lay.addLayout(_row("Operation", self.op, "OID", self.oid))
        lay.addLayout(_row("Timeout", self.timeout, "Retries", self.retries, "Max rows", self.max_rows,
                           self.go, self.stop, self.copy_btn, self.save_btn, self.clear_btn))
        lay.addWidget(self.status)
        lay.addWidget(self.table, 1)

        self.version.currentIndexChanged.connect(self._adapt)
        self.level.currentIndexChanged.connect(self._adapt)
        self.op.currentIndexChanged.connect(self._adapt)
        self.show_secrets.toggled.connect(self._reveal)
        self.picker.currentIndexChanged.connect(self._picked)
        self.go.clicked.connect(self.start)
        self.stop.clicked.connect(self.halt)
        self.copy_btn.clicked.connect(self.copy)
        self.save_btn.clicked.connect(self.save)
        self.clear_btn.clicked.connect(self.clear)
        self.oid.returnPressed.connect(self.start)
        self._adapt()

    # ---------- form
    def _adapt(self, *_):
        v3 = self.version.currentData() == "3"
        self.v3.setVisible(v3)
        self.community.setEnabled(not v3)
        lvl = self.level.currentText()
        for w in (self.auth_proto, self.auth_key):
            w.setEnabled(lvl != "noAuthNoPriv")
        for w in (self.priv_proto, self.priv_key):
            w.setEnabled(lvl == "authPriv")
        self.oid.setEnabled(self.op.currentData() in ("get", "getnext", "walk", "bulkwalk"))
        self.status_hint = None

    def _picked(self, *_):
        """Choosing an inventory device fills in its host and, when it has them, its stored SNMP settings."""
        d = self.picker.currentData()
        if not d:
            return
        self.host.setText(d["host"])
        if profiles.snmp_configured(d) or vendors.is_snmp(d["vendor"]):
            s = profiles.snmp_settings(d)
            self.version.setCurrentIndex(max(0, self.version.findData(str(s["version"]))))
            self.port.setValue(int(s["port"] or 161))
            self.user.setText(s["user"])
            self.level.setCurrentText(s["level"])
            self.auth_proto.setCurrentText(s["auth_protocol"])
            self.priv_proto.setCurrentText(s["priv_protocol"])
            self.community.setText(profiles.secret(d, "snmp") or "")
            self.auth_key.setText(profiles.secret(d, "snmp_auth") or "")
            self.priv_key.setText(profiles.secret(d, "snmp_priv") or "")
            self.status.setText(f"Using the stored SNMP settings of {d['name']}.")

    def _reveal(self, on):
        mode = QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password
        for e in (self.community, self.auth_key, self.priv_key):
            e.setEchoMode(mode)

    def credentials(self):
        return snmp.Credentials(version=self.version.currentData(), community=self.community.text(),
                                user=self.user.text().strip(), level=self.level.currentText(),
                                auth_protocol=self.auth_proto.currentText(), auth_key=self.auth_key.text(),
                                priv_protocol=self.priv_proto.currentText(), priv_key=self.priv_key.text())

    # ---------- results table
    def _columns(self, names):
        self.table.setColumnCount(len(names))
        self.table.setHorizontalHeaderLabels(names)

    def _append(self, cells):
        r = self.table.rowCount()
        self.table.insertRow(r)
        for i, v in enumerate(cells):
            self.table.setItem(r, i, QTableWidgetItem(v))

    def clear(self):
        self.table.setRowCount(0)
        self._columns(self.RAW_COLS)
        self.status.setText("")

    def copy(self):
        sel = sorted({i.row() for i in self.table.selectedItems()}) or range(self.table.rowCount())
        cols = range(self.table.columnCount())
        head = "\t".join(self.table.horizontalHeaderItem(c).text() for c in cols)
        body = ["\t".join(self.table.item(r, c).text() if self.table.item(r, c) else "" for c in cols) for r in sel]
        _QApp.clipboard().setText("\n".join([head] + body))

    def save(self):
        """Every row in the table (whatever the operation showed: OIDs, System info, Interfaces...) to a CSV file."""
        host = "".join(ch if ch.isalnum() or ch in ".-_" else "-" for ch in self.host.text().strip()) or "snmp"
        path, _ = QFileDialog.getSaveFileName(self, "Save SNMP results", f"snmp-{host}-{datetime.now():%Y%m%d-%H%M}.csv",
                                              "CSV files (*.csv);;Text files (*.txt)")
        if not path:
            return
        cols = range(self.table.columnCount())
        with open(path, "w", encoding="utf-8-sig", newline="") as f:          # (a BOM, so Excel reads it as UTF-8)
            out = csv.writer(f)
            out.writerow([self.table.horizontalHeaderItem(c).text() for c in cols])
            for r in range(self.table.rowCount()):
                out.writerow([self.table.item(r, c).text() if self.table.item(r, c) else "" for c in cols])

    # ---------- running
    def running(self):
        return bool(self.worker and self.worker.isRunning())

    def start(self):
        if self.running():
            return
        host, op = self.host.text().strip(), self.op.currentData()
        if not host:
            self.status.setText("Enter a host first.")
            return
        self.table.setRowCount(0)
        self._columns(self.RAW_COLS)
        self.status.setText(f"Querying {host}...")
        self.go.setEnabled(False)
        self.stop.setEnabled(True)
        args = (host, self.port.value(), self.credentials(), op, self.oid.text(), self.timeout.value(),
                self.retries.value(), self.max_rows.value())
        self.worker = SnmpWorker(args, self)
        self.worker.rows.connect(self._rows)
        self.worker.done.connect(self._finished)
        self.worker.start()

    def halt(self):
        if self.running():
            self.worker.cancel.set()
            self.status.setText("Stopping...")

    def _rows(self, rows):
        for r in rows:
            self._append([r.oid, r.name if r.name != r.oid else "", r.type, r.value])
        self.table.resizeColumnsToContents()

    def _finished(self, out):
        op = self.op.currentData()
        if out.table is not None:
            self._columns(out.columns)
            for row in out.table:
                self._append([str(x) for x in row])
            self.table.resizeColumnsToContents()
            n = len(out.table)
        elif op == "interfaces" and out.rows:
            names = ["Index"] + [label for _, label in snmp.IF_COLUMNS]
            self._columns(names)
            for d in snmp.interface_table(out.rows):
                self._append([d["index"]] + [d.get(k, "") for k, _ in snmp.IF_COLUMNS])
            self.table.resizeColumnsToContents()
            n = self.table.rowCount()
        else:
            n = len(out.rows)
        parts = [f"{n} row{'s' if n != 1 else ''}", f"{out.seconds:.1f} s"]
        if out.truncated:
            parts.append(f"stopped at the {self.max_rows.value():,}-row limit")
        if out.cancelled:
            parts.append("stopped")
        if out.table is not None and not out.table and not out.error:
            parts.append("nothing returned (the device may not support this, or has none)")
        if op == "interfaces" and not out.rows and not out.error:
            parts.append("no interface table returned (the device may not expose IF-MIB to this community)")
        self.status.setText(("Error: " + out.error + "   |   " if out.error else "") + "  |  ".join(parts))
        self.go.setEnabled(True)
        self.stop.setEnabled(False)

    def shutdown(self):
        if self.running():
            self.worker.cancel.set()
            self.worker.wait(5000)


# ---------------------------------------------------------------- the tab
class ToolsTab(QWidget):
    inventory_changed = Signal()                  # discovery added devices

    def __init__(self):
        super().__init__()
        from ui import tools2, tools3
        from ui.nav import PageStack
        from ui.settings_base import tidy
        self.diag, self.scan, self.subnet = DiagnosticsTab(), ScanTab(), SubnetTab()
        self.snmp = SnmpTab()
        self.runner = tools2.CommandRunnerTab()
        self.liveping, self.mtr = tools2.LivePingTab(), tools2.MtrTab()
        self.tls = tools2.TlsTab()
        self.discovery, self.topology = tools2.DiscoveryTab(), tools2.TopologyTab()
        self.listeners = tools2.ListenersTab()
        self.tftp, self.sftp, self.iperf = tools3.FileServerTab("tftp"), tools3.FileServerTab("sftp"), tools3.IperfTab()
        self.wifi = tools3.WifiTab()
        self.scp, self.xcopy = tools3.ScpTab(), tools3.XcopyTab()
        self.utilities = tools2.UtilitiesTab()
        from ui import opensslui, playbookeditor
        self.openssl = opensslui.OpensslTab()
        self.playbooks = playbookeditor.PlaybookEditorTab()
        self.discovery.inventory_changed = self.inventory_changed.emit
        self.tabs = PageStack(width=228)          # wide enough for 'Ping / Traceroute / DNS' without cutting it short
        for title, pages in (("Connect", ((self.runner, "Command Runner"),)),
                             ("Diagnose", ((self.diag, "Ping / Traceroute / DNS"), (self.liveping, "Live Ping"),
                                           (self.mtr, "Path Monitor (MTR)"), (self.scan, "Port Scanner"),
                                           (self.iperf, "Throughput (iperf3)"), (self.wifi, "Wi-Fi Scanner"),
                                           (self.subnet, "Subnet Calculator"))),
                             ("Discover", ((self.discovery, "Find Devices"), (self.topology, "Topology"))),
                             ("SNMP and logs", ((self.snmp, "SNMP"), (self.listeners, "Syslog and Traps"))),
                             ("File transfer", ((self.tftp, "TFTP Server"), (self.sftp, "SFTP Server"), (self.scp, "SCP"),
                                               (self.xcopy, f"Copy Files ({self.xcopy.name})"))),
                             ("Certificates", ((self.tls, "TLS Certificates"), (self.openssl, "OpenSSL"))),
                             ("Automation", ((self.playbooks, "Playbook Editor"),)),
                             ("Utilities", ((self.utilities, "MAC and Wake-on-LAN"),))):
            self.tabs.addSection(title)
            for w, label in pages:
                tidy(w, combo_min=460)                          # a button or drop-down is only as wide as what it says, even in a wide window
                self.tabs.addTab(w, label)
        lay = QVBoxLayout(self)
        lay.addWidget(self.tabs)
        self._pickers = (self.diag, self.scan, self.snmp, self.liveping, self.mtr, self.tls, self.iperf, self.scp)
        self._others = (self.runner, self.discovery, self.topology)

    def refresh(self):
        for t in self._pickers:
            t.picker.refresh()
        for t in self._others:
            t.refresh()

    def show_tool(self, widget, dev=None):
        """Open another tool (live ping, SNMP, ...) with a device's address filled in."""
        self.refresh()
        self.tabs.setCurrentWidget(widget)
        if dev is not None and hasattr(widget, "picker"):
            for i in range(widget.picker.count()):
                d = widget.picker.itemData(i)
                if d and d["name"] == dev["name"]:
                    widget.picker.setCurrentIndex(i)
                    break

    def edit_playbook(self, name):
        """Open a playbook in the editor (Automation > Playbooks > Edit)."""
        self.tabs.setCurrentWidget(self.playbooks)
        self.playbooks.refresh()
        self.playbooks.open_playbook(name)

    def shutdown(self):
        for t in (self.diag, self.scan, self.snmp, self.liveping, self.mtr, self.tls, self.runner,
                  self.discovery, self.topology, self.listeners, self.utilities, self.tftp, self.sftp, self.iperf, self.wifi, self.scp, self.xcopy, self.openssl, self.playbooks):
            t.shutdown()
