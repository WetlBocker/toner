import csv
import os
import threading
from datetime import datetime
from pathlib import Path

import keyring
from PySide6.QtCore import QObject, QProcess, QStandardPaths, QThread, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFontDatabase
from PySide6.QtWidgets import (QAbstractItemView, QApplication as _QApp, QCheckBox, QComboBox, QCompleter, QFileDialog, QGroupBox, QHBoxLayout, QLabel,
                               QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QSplitter,
                               QTableWidget, QTableWidgetItem, QTabWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)
from core import db, jump, nettools, perms, profiles, reach, sealedfile, sessionlog, snmp, vendors


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
        self.refresh([])                         # filled by its tool's refresh (Tools fills every picker at once, from one read)

    @staticmethod
    def entries():
        """(label, device) for every device listed: read once by Tools and handed to each of its pickers."""
        several = db.several()
        out = []
        for d in db.list_devices():
            place = " / ".join(x for x in ((db.org_name(d["org"]) if several else ""), db.path_of(d)) if x)    # Global: whose it is
            out.append((f"{d['name']}  —  {d['host']}" + (f"   [{place}]" if place else ""), d))
        return out

    def refresh(self, entries=None):
        cur = self.currentText()
        self.blockSignals(True)
        self.clear()
        self.addItem("(enter manually)", None)
        for label, d in (self.entries() if entries is None else entries):
            self.addItem(label, d)
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


RESET_TIP = "Clear the results and start afresh"


def reset_button():
    """The Reset button a tool with results carries (Live Ping had one first): the results go, what was typed stays."""
    b = QPushButton("Reset")
    b.setToolTip(RESET_TIP)
    return b


def _row(*widgets):
    """A row of captioned boxes and buttons that wraps onto a second line when the window is narrow."""
    from ui.widgets import flow
    return flow(*widgets)


# ---------------------------------------------------------------- session logs
class LogsTab(QWidget):
    COLS = ["Started", "Ended", "Duration", "Type", "Device", "Host", "User", "Result"]
    MAX_VIEW = 2_000_000
    OTHER_LOGS = ("backup", "command-runner", "firmware")      # <kind>-<device>.log beside the session logs, one per device

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
        save = QPushButton("Save a readable copy...")      # the files in the folder are sealed: this is how to read one elsewhere
        refresh.clicked.connect(self.refresh)
        folder.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(sessionlog.log_dir()))))
        save.clicked.connect(self.save_copy)
        self.note = QLabel("")
        bar = QHBoxLayout()
        bar.addWidget(refresh)
        bar.addWidget(folder)
        bar.addWidget(save)
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

    def _other_logs(self):
        """The backup, Command Runner and firmware logs, newest first, shaped like sessions (no host, user or end)."""
        out = []
        for p in sessionlog.log_dir().iterdir():
            kind = next((k for k in self.OTHER_LOGS if p.name.startswith(k + "-") and p.suffix == ".log"), None)
            if kind:
                try:
                    at = datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                except OSError:
                    continue
                out.append({"id": "file:" + p.name, "log_path": str(p), "started_at": at, "kind": kind,
                            "device": p.stem[len(kind) + 1:], "file": True})
        return sorted(out, key=lambda s: s["started_at"], reverse=True)

    def refresh(self):
        keep = self.current_id()
        self.sessions = sessionlog.list_sessions() + self._other_logs()
        self.table.blockSignals(True)
        self.table.setRowCount(len(self.sessions))
        for i, s in enumerate(self.sessions):
            vals = ([s["started_at"], "", "", s["kind"].replace("-", " ").capitalize(), s["device"], "", "", ""] if s.get("file") else
                    [s["started_at"], s["ended_at"] or "(open, or not closed cleanly)", self._duration(s),
                     (s.get("kind") or "ssh").upper(), s["device"], f"{s['host']}:{s['port']}", s["username"], s["reason"] or ""])
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
            raw = sealedfile.read_bytes(s["log_path"])
            size = len(raw)
            text = raw[-self.MAX_VIEW:].decode("utf-8", "replace")
            if size > self.MAX_VIEW:
                text = f"[showing the last {self.MAX_VIEW // 1000} KB of {size // 1000} KB. Save a readable copy for all of it.]\n" + text
            self.view.setPlainText(text)
        except (OSError, ValueError, sealedfile.Locked) as e:
            self.view.setPlainText(f"The log file could not be opened: {e}\n{s['log_path']}")

    def save_copy(self):
        """The selected log, decrypted, to a file the person picks (Documents by default)."""
        sid = self.current_id()
        s = next((x for x in self.sessions if x["id"] == sid), None)
        if not s:
            return
        docs = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DocumentsLocation)
        path, _ = QFileDialog.getSaveFileName(self, "Save a readable copy", os.path.join(docs, Path(s["log_path"]).name))
        if not path:
            return
        try:
            data = sealedfile.read_bytes(s["log_path"])
            with open(path, "wb") as f:
                f.write(data)
        except (OSError, ValueError, sealedfile.Locked) as e:
            QMessageBox.warning(self, "Save a readable copy", f"The log file could not be opened: {e}")


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
        self.reset = reset_button()
        self.out = OutputBox()
        self.runner = Runner(self)
        self.runner.output.connect(self.out.add)
        self.runner.finished.connect(lambda: self._busy(False))
        self.reset.clicked.connect(self.out.clear)

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
        lay.addLayout(_row("Profile", self.profile, "Ports", self.ports, self.go, self.stop, self.reset))
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
class Call(QThread):
    """Runs one function off the window thread and hands back what it returned, or the exception."""
    done = Signal(object)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            self.done.emit(self.fn())
        except Exception as e:
            self.done.emit(e)


class SubnetTab(QWidget):
    """IPv4 or IPv6: the facts about an address and its network, a public address looked up at ipstack, and a Split tree that breaks
    the network into smaller subnets (core/subnets.py does the sums)."""
    NET = Qt.ItemDataRole.UserRole
    PLACEHOLDER = {"v4": "192.168.1.10/24   or   10.0.0.0/255.255.255.0", "v6": "2001:db8::1/64   or   2001:db8::/48"}
    COLS = ["Network", "First address", "Last address", "Hosts"]

    def __init__(self):
        super().__init__()
        from core import iplookup, subnets
        from ui.panels import fit_rows
        from ui.topology import Segment
        self.subnets, self.iplookup, self.fit_rows = subnets, iplookup, fit_rows
        self.worker = None
        self.iface = None
        self.mode = Segment((("v4", "IPv4"), ("v6", "IPv6")))
        self.inp = QLineEdit()
        self.inp.setPlaceholderText(self.PLACEHOLDER["v4"])
        self.reset = reset_button()
        self.facts = QLabel("")
        self.facts.setTextFormat(Qt.TextFormat.RichText)
        self.facts.setWordWrap(True)
        self.facts.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.facts.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        # a public address: where it is, by ipstack
        self.lookup_btn = QPushButton("Look up")
        self.lookup_btn.setToolTip("Ask ipstack.com where this public address is (your access key is under Settings > Connections)")
        self.lookup_note = QLabel("Public address: looked up at ipstack.com with the key under Settings > Connections.")
        self.lookup_note.setProperty("muted", True)
        self.lookup_note.setWordWrap(True)
        self.lookup_out = QLabel("")
        self.lookup_out.setTextFormat(Qt.TextFormat.RichText)
        self.lookup_out.setWordWrap(True)
        self.lookup_out.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.lookup_box = QWidget()
        lb = QVBoxLayout(self.lookup_box)
        lb.setContentsMargins(0, 0, 0, 0)
        lrow = QHBoxLayout()
        lrow.addWidget(self.lookup_btn)
        lrow.addWidget(self.lookup_note, 1)
        lb.addLayout(lrow)
        lb.addWidget(self.lookup_out)
        self.lookup_box.hide()
        # the Split tree
        self.split_title = QLabel("<b>Split</b>")
        self.split_note = QLabel("Choose a network in the tree, then split it into smaller subnets; Join puts them back together.")
        self.split_note.setProperty("muted", True)
        self.split_note.setWordWrap(True)
        self.split2, self.splitn, self.join = QPushButton("Split in two"), QPushButton("Split into..."), QPushButton("Join")
        self.split2.setToolTip("Halve the chosen network (one bit longer)")
        self.splitn.setToolTip("Split the chosen network into subnets of a prefix length you pick")
        self.join.setToolTip("Put the chosen network's subnets back together")
        self.tree = QTreeWidget()
        self.tree.setColumnCount(len(self.COLS))
        self.tree.setHeaderLabels(self.COLS)
        self.tree.setRootIsDecorated(True)
        self.tree.setAlternatingRowColors(False)
        self.tree.header().setStretchLastSection(True)
        lay = QVBoxLayout(self)
        lay.addLayout(_row(self.mode, "Address / prefix", self.inp, self.reset))
        lay.addWidget(self.facts)
        lay.addWidget(self.lookup_box)
        lay.addWidget(self.split_title)
        lay.addWidget(self.split_note)
        srow = QHBoxLayout()
        for b in (self.split2, self.splitn, self.join):
            srow.addWidget(b)
        srow.addStretch(1)
        lay.addLayout(srow)
        lay.addWidget(self.tree, 1)
        lay.addStretch(0)                                  # the tree ends under its rows (fit_rows)
        self._switching = False
        self.mode.changed.connect(self._mode)
        self.inp.textChanged.connect(self.calc)
        self.reset.clicked.connect(self.clear)
        self.lookup_btn.clicked.connect(self.lookup)
        self.split2.clicked.connect(lambda: self.split(1))
        self.splitn.clicked.connect(self.split_into)
        self.join.clicked.connect(self.join_up)
        self.tree.itemSelectionChanged.connect(self._buttons)
        self.calc("")

    # ---- the address
    def _mode(self, key):
        self.inp.setPlaceholderText(self.PLACEHOLDER.get(key, ""))
        if not self._switching:
            v = self.subnets.version(self.inp.text())
            if v and (v == 4) != (key == "v4"):
                self.inp.clear()                           # the other family: start afresh in it

    def calc(self, text):
        self.lookup_out.setText("")
        if not text.strip():
            self.iface = None
            self.facts.setText("")
            self.lookup_box.hide()
            self.tree.clear()
            self._buttons()
            self.fit_rows(self.tree)
            return
        try:
            iface = self.subnets.parse(text)
        except ValueError as e:
            self.iface = None
            self.facts.setText(f"<span style='color:gray'>Not a valid address: {self._esc(e)}</span>")
            self.lookup_box.hide()
            self.tree.clear()
            self._buttons()
            self.fit_rows(self.tree)
            return
        self.iface = iface
        want = "v4" if iface.version == 4 else "v6"
        if self.mode.value() != want:                      # typed the other family: the switch follows
            self._switching = True
            self.mode.set(want)
            self._switching = False
        self.facts.setText(self._table(self.subnets.facts(iface)))
        self.lookup_box.setVisible(self.subnets.is_public(iface.ip))
        self.tree.clear()
        self._item(None, iface.network)
        self.tree.setCurrentItem(self.tree.topLevelItem(0))
        self._sized()

    @staticmethod
    def _esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;")

    def _table(self, rows):
        return "<table cellpadding='3'>" + "".join(f"<tr><td><b>{self._esc(k)}</b></td><td>{self._esc(v)}</td></tr>" for k, v in rows) + "</table>"

    def clear(self):
        """Reset: the address, facts, look-up and tree go."""
        self.inp.clear()

    # ---- where a public address is
    def lookup(self):
        if not self.iface or (self.worker and self.worker.isRunning()):
            return
        if not self.iplookup.has_key():
            self.lookup_out.setText("<span style='color:gray'>Add your ipstack access key under Settings > Connections first.</span>")
            return
        ip = self.iface.ip
        self.lookup_btn.setEnabled(False)
        self.lookup_out.setText(f"<span style='color:gray'>Asking ipstack about {ip}...</span>")
        self.worker = Call(lambda: self.iplookup.lookup(ip))
        self.worker.done.connect(self._looked_up)
        self.worker.start()

    def _looked_up(self, res):
        self.lookup_btn.setEnabled(True)
        if isinstance(res, Exception):
            self.lookup_out.setText(f"<span style='color:gray'>ipstack: {self._esc(res)}</span>")
            return
        self.lookup_out.setText(self._table(self.iplookup.summary(res)))

    # ---- the Split tree
    def _item(self, parent, net):
        it = QTreeWidgetItem(list(self.subnets.row(net)))
        it.setData(0, self.NET, str(net))
        if parent is None:
            self.tree.addTopLevelItem(it)
        else:
            parent.addChild(it)
        return it

    def _net(self, item):
        import ipaddress
        return ipaddress.ip_network(item.data(0, self.NET)) if item is not None else None

    def _chosen(self):
        it = self.tree.currentItem()
        return it if it is not None else self.tree.topLevelItem(0)

    def _buttons(self):
        it = self._chosen()
        net = self._net(it)
        top = 32 if net is not None and net.version == 4 else 128
        can_split = net is not None and net.prefixlen < top
        self.split2.setEnabled(can_split)
        self.splitn.setEnabled(can_split)
        self.join.setEnabled(it is not None and (it.childCount() > 0 or it.parent() is not None))

    def split(self, more):
        it = self._chosen()
        net = self._net(it)
        if net is None:
            return
        self.split_to(it, net.prefixlen + more)

    def split_into(self):
        it = self._chosen()
        net = self._net(it)
        if net is None:
            return
        top = 32 if net.version == 4 else 128
        from PySide6.QtWidgets import QInputDialog
        new, ok = QInputDialog.getInt(self, "Split into", f"New prefix length for {net} (/{net.prefixlen + 1} to /{top})", net.prefixlen + 1, net.prefixlen + 1, top)
        if ok:
            self.split_to(it, new)

    def split_to(self, item, new_prefix):
        net = self._net(item)
        try:
            parts = self.subnets.children(net, new_prefix)
        except ValueError as e:
            from ui.toast import toast
            toast(self, str(e))
            return
        item.takeChildren()
        for p in parts:
            self._item(item, p)
        item.setExpanded(True)
        self.tree.setCurrentItem(item)
        self._sized()

    def join_up(self):
        it = self._chosen()
        if it is None:
            return
        target = it if it.childCount() else it.parent()
        if target is None:
            return
        target.takeChildren()
        self.tree.setCurrentItem(target)
        self._sized()

    def _sized(self):
        for c in range(len(self.COLS) - 1):
            self.tree.resizeColumnToContents(c)
        self.fit_rows(self.tree)
        self._buttons()

    def shutdown(self):
        if self.worker:
            self.worker.wait(3000)


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
        self.tftp, self.sftp, self.ftp = tools3.FileServerTab("tftp"), tools3.FileServerTab("sftp"), tools3.FileServerTab("ftp")
        self.iperf = tools3.IperfTab()
        self.wifi = tools3.WifiTab()
        self.scp, self.xcopy = tools3.ScpTab(), tools3.XcopyTab()
        from ui import firmware
        self.firmware = firmware.FirmwareTab(servers=lambda: {"ftp": self.ftp.server, "sftp": self.sftp.server, "tftp": self.tftp.server})
        self.maclookup, self.wol = tools2.MacLookupTab(), tools2.WolTab()
        from ui import opensslui, playbookeditor
        self.openssl = opensslui.OpensslTab()
        from ui import sshkeysui
        self.sshkeys = sshkeysui.SshKeysTab()
        self.playbooks = playbookeditor.PlaybookEditorTab()
        from ui import apitool
        self.apitest = apitool.ApiTesterTab()
        self.discovery.inventory_changed = self.inventory_changed.emit
        self.tabs = PageStack(width=228, key="tools_list_hidden")          # wide enough for 'Ping / Traceroute / DNS' without cutting it short
        for title, pages in (("Connect", ((self.runner, "Command Runner"), (self.apitest, "API Tester"))),
                             ("Diagnose", ((self.diag, "Ping / Traceroute / DNS"), (self.liveping, "Live Ping"),
                                           (self.mtr, "Path Monitor (MTR)"), (self.scan, "Port Scanner"),
                                           (self.iperf, "Throughput (iperf3)"))),
                             ("Discover", ((self.discovery, "Find Devices"), (self.topology, "Topology"), (self.wifi, "Wi-Fi Scanner"))),
                             ("SNMP and logs", ((self.snmp, "SNMP"), (self.listeners, "Syslog and Traps"))),
                             ("File transfer", ((self.firmware, "Firmware Transfer"), (self.tftp, "TFTP Server"), (self.sftp, "SFTP / SCP Server"), (self.ftp, "FTP Server"),
                                               (self.scp, "SCP"), (self.xcopy, f"Copy Files ({self.xcopy.name})"))),
                             ("Crypto", ((self.tls, "TLS Certificates"), (self.openssl, "OpenSSL"), (self.sshkeys, "SSH Keys"))),
                             ("Automation", ((self.playbooks, "Playbook Editor"),)),
                             ("Utilities", ((self.maclookup, "MAC OUI Lookup"), (self.wol, "Wake-on-LAN"), (self.subnet, "Subnet Calculator")))):
            self.tabs.addSection(title)
            for w, label in pages:
                tidy(w, combo_min=460)                          # a button or drop-down is only as wide as what it says, even in a wide window
                self.tabs.addTab(w, label)
        lay = QVBoxLayout(self)
        lay.addWidget(self.tabs)
        self._pickers = (self.diag, self.scan, self.snmp, self.liveping, self.mtr, self.tls, self.iperf, self.scp, self.sshkeys)
        self._others = (self.runner, self.discovery, self.topology, self.apitest, self.firmware)
        self._keys = {self.runner: "command-runner", self.apitest: "api-tester", self.diag: "ping", self.liveping: "live-ping",
                      self.mtr: "path-monitor", self.scan: "port-scanner", self.iperf: "iperf", self.discovery: "find-devices",
                      self.topology: "topology", self.wifi: "wifi", self.snmp: "snmp", self.listeners: "syslog", self.firmware: "firmware",
                      self.tftp: "tftp", self.sftp: "sftp", self.ftp: "ftp", self.scp: "scp", self.xcopy: "copy-files", self.tls: "tls",
                      self.openssl: "openssl", self.sshkeys: "ssh-keys", self.playbooks: "playbook-editor", self.maclookup: "mac-lookup",
                      self.wol: "wol", self.subnet: "subnet"}
        self.apply_permissions()

    def tool_allowed(self, widget):
        return perms.allowed("tool:" + self._keys[widget])

    def apply_permissions(self):
        """Each tool is in the list while the signed-in role allows it (safe to call again)."""
        for w in self._keys:
            self.tabs.setTabVisible(w, self.tool_allowed(w))

    def any_allowed(self):
        return any(self.tool_allowed(w) for w in self._keys)

    def refresh(self):
        entries = DevicePicker.entries()                  # once, not once per tool (each lists every device)
        for t in self._pickers:
            t.picker.refresh(entries)
        for t in self._others:
            t.refresh()

    def show_tool(self, widget, dev=None):
        """Open another tool (live ping, SNMP, ...) with a device's address filled in."""
        if widget in self._keys and not self.tool_allowed(widget):
            return
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
        if not self.tool_allowed(self.playbooks):
            return
        self.tabs.setCurrentWidget(self.playbooks)
        self.playbooks.refresh()
        self.playbooks.open_playbook(name)

    def shutdown(self):
        for t in (self.diag, self.scan, self.snmp, self.liveping, self.mtr, self.tls, self.runner, self.subnet,
                  self.discovery, self.topology, self.listeners, self.maclookup, self.wol, self.tftp, self.sftp, self.ftp, self.iperf, self.wifi, self.scp, self.xcopy, self.openssl, self.sshkeys, self.playbooks, self.apitest, self.firmware):
            t.shutdown()
