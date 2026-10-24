"""File servers (TFTP, SFTP with SCP, FTP) and the iperf3 throughput test."""
import os
import re
import subprocess
import threading
from datetime import datetime

import pyqtgraph as pg
from PySide6.QtCore import QThread, QTimer, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                               QProgressBar, QPushButton, QSpinBox, QStackedWidget, QTableWidgetItem, QVBoxLayout, QWidget, QFrame)
import paramiko
from core import audit, db, fileserver, iperf, nettools, oui, profiles, proxy, scp, vendors, wifi, xcopy
from ui import plots, theme
from ui.tools import DevicePicker, OutputBox, Runner, _row
from ui.tools2 import _muted, _primary, _table
from ui import status as st

SECRETS = {"sftp": "service:sftp-server", "ftp": "service:ftp-server"}       # the servers' passwords, in the vault
AUDITED = {"write", "delete", "mkdir", "rename", "login"}              # plain reads stay out of the audit log


def _size(n):
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024


# =============================================================================== TFTP / SFTP
class FileServerTab(QWidget):
    event = Signal(dict)
    MAX_ROWS = 5000
    PROTOS = {"tftp": ("TFTP", 69), "sftp": ("SFTP", 22), "ftp": ("FTP", 21)}      # the usual ports: devices' copy URLs need none

    def __init__(self, proto):
        super().__init__()
        self.proto = proto
        self.label, default_port = self.PROTOS[proto]
        self.server = None
        self.rows = []
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(lambda: self.stop(f"Stopped automatically after {self.minutes.value()} minutes."))

        self.folder = QLineEdit()
        self.folder.setPlaceholderText("a dedicated folder, for example C:\\TFTP")
        self.browse, self.open_btn = QPushButton("Browse..."), QPushButton("Open")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(default_port)
        self.user = QLineEdit("toner")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.show_pw = QCheckBox("Show")
        self.gen = QPushButton("Generate")
        self.fingerprint = _muted("")
        self.fingerprint.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.pasv_lo, self.pasv_hi = QSpinBox(), QSpinBox()                   # FTP: the ports for passive data connections
        for box, value in ((self.pasv_lo, 50000), (self.pasv_hi, 50100)):
            box.setRange(1, 65535)
            box.setValue(value)
        self.write = QCheckBox("Allow uploads (devices can send files to this folder)")
        self.replace = QCheckBox("Also allow replacing and deleting existing files")
        self.replace.setEnabled(False)
        self.allowed = QLineEdit()
        self.allowed.setPlaceholderText("only these clients, e.g. 10.0.0.0/24, 192.168.1.5   (blank = any)")
        self.minutes = QSpinBox()
        self.minutes.setRange(0, 1440)
        self.minutes.setValue(60)
        self.minutes.setSpecialValueText("never")
        self.minutes.setSuffix(" minutes")
        self.go = _primary(f"Start {self.label} server")
        self.status = _muted("")
        self.clear, self.save = QPushButton("Clear"), QPushButton("Save...")
        self.table = _table(["Time", "From", "Action", "File", "Size", "Result", "Note"])

        lay = QVBoxLayout(self)
        lay.addWidget(_muted(self._intro()))
        lay.addLayout(_row("Folder", self.folder, self.browse, self.open_btn, "Port", self.port))
        if proto in ("sftp", "ftp"):
            lay.addLayout(_row("User name", self.user, "Password", self.password, self.show_pw, self.gen))
        if proto == "sftp":
            lay.addWidget(self.fingerprint)
        if proto == "ftp":
            lay.addLayout(_row("Passive ports", self.pasv_lo, "to", self.pasv_hi))
        lay.addWidget(self.write)
        lay.addWidget(self.replace)
        lay.addLayout(_row("Allowed clients", self.allowed))
        lay.addLayout(_row("Stop automatically after", self.minutes, self.go))
        lay.addWidget(self.status)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Transfers"))
        bar.addStretch(1)
        bar.addWidget(self.clear)
        bar.addWidget(self.save)
        lay.addLayout(bar)
        lay.addWidget(self.table, 1)

        self.browse.clicked.connect(self.choose_folder)
        self.open_btn.clicked.connect(self.open_folder)
        self.go.clicked.connect(self.toggle)
        self.event.connect(self.on_event)
        self.clear.clicked.connect(self.clear_rows)
        self.save.clicked.connect(self.save_rows)
        self.write.toggled.connect(self.replace.setEnabled)
        self.write.toggled.connect(lambda on: not on and self.replace.setChecked(False))
        self.show_pw.toggled.connect(lambda on: self.password.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
        self.gen.clicked.connect(self.generate)
        self.load()

    def _intro(self):
        if self.proto == "tftp":
            return ("A TFTP server for sending firmware and configuration files to switches and routers, and receiving "
                    "backups from them. TFTP has no passwords, so this one serves only the folder below, is read-only until "
                    "you allow uploads, and can be limited to the devices you name. Stop it when you are finished.")
        if self.proto == "ftp":
            return ("An FTP server for the same jobs. Every Cisco platform has an FTP client, and FTP is much faster than TFTP "
                    "for large images. It serves only the folder below, is read-only until you allow uploads, needs a user name "
                    "and password, and sends them in clear text, so use it on a management network. Data connections use the "
                    "passive ports below when the device asks for passive mode; if Windows asks about the firewall, allow "
                    "private networks.")
        return ("An SFTP server (file transfer over SSH, with a user name and password) for the same jobs. It serves only "
                "the folder below, is read-only until you allow uploads, gives no shell, and locks out an address after "
                "five wrong passwords. Devices with an SCP client but no SFTP client (IOS, ASA) can use it too.")

    # ---- saved choices (never the password: that goes to the vault)
    def load(self):
        saved = (db.get_setting("fileserver") or {}).get(self.proto, {})
        self.folder.setText(saved.get("folder", ""))
        self.port.setValue(saved.get("port", self.port.value()))
        self.write.setChecked(bool(saved.get("write")))
        self.replace.setChecked(bool(saved.get("replace")) and self.write.isChecked())
        self.allowed.setText(saved.get("allowed", ""))
        self.minutes.setValue(saved.get("minutes", 60))
        if self.proto in ("sftp", "ftp"):
            self.user.setText(saved.get("user", "toner"))
            try:
                import keyring
                self.password.setText(keyring.get_password(db.SERVICE, SECRETS[self.proto]) or "")
            except Exception:
                pass
        if self.proto == "sftp":
            self._show_fingerprint()
        if self.proto == "ftp":
            self.pasv_lo.setValue(int(saved.get("pasv_lo", 50000)))
            self.pasv_hi.setValue(int(saved.get("pasv_hi", 50100)))

    def save_choices(self):
        data = dict(db.get_setting("fileserver") or {})
        entry = {"folder": self.folder.text().strip(), "port": self.port.value(), "write": self.write.isChecked(),
                 "replace": self.replace.isChecked(), "allowed": self.allowed.text().strip(), "minutes": self.minutes.value()}
        if self.proto in ("sftp", "ftp"):
            entry["user"] = self.user.text().strip()
        if self.proto == "ftp":
            entry["pasv_lo"], entry["pasv_hi"] = self.pasv_lo.value(), self.pasv_hi.value()
        data[self.proto] = entry
        db.set_setting("fileserver", data)

    def _key_path(self):
        return str(db.db_path().parent / "sftp_host_key")

    def _show_fingerprint(self):
        path = self._key_path()
        try:
            fp = fileserver.fingerprint(fileserver.load_host_key(path)) if os.path.exists(path) else ""
        except Exception:
            fp = ""
        self.fingerprint.setText(f"Server fingerprint: {fp}   (check it matches when a client connects for the first time)"
                                 if fp else "A server identity is created the first time it starts; its fingerprint is shown here.")

    # ---- inputs
    def choose_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Folder to share", self.folder.text() or os.path.expanduser("~"))
        if path:
            self.folder.setText(os.path.normpath(path))

    def open_folder(self):
        if os.path.isdir(self.folder.text().strip()):
            QDesktopServices.openUrl(QUrl.fromLocalFile(self.folder.text().strip()))

    def generate(self):
        self.password.setText(fileserver.new_password())
        self.show_pw.setChecked(True)

    # ---- start and stop
    def toggle(self):
        self.stop() if self.server else self.start()

    def start(self):
        folder = self.folder.text().strip()
        problem = fileserver.risky_root(folder)
        if problem:
            self.status.setText(problem)
            return
        try:
            allowed = fileserver.parse_allowed(self.allowed.text())
        except ValueError as e:
            self.status.setText(str(e))
            return
        if self.write.isChecked() and not allowed and self.proto == "tftp" and QMessageBox.question(
                self, "Allow uploads from anyone?",
                "TFTP has no passwords. With no client list, any computer that can reach this one can put files in "
                f"{folder}.\n\nStart anyway? (Naming the devices in 'Allowed clients' avoids this.)") != QMessageBox.StandardButton.Yes:
            return
        emit = lambda e: self.event.emit(e)
        try:
            if self.proto == "tftp":
                srv = fileserver.TftpServer(folder, self.port.value(), allow_write=self.write.isChecked(),
                                            allow_overwrite=self.replace.isChecked(), allowed=allowed, on_event=emit)
            elif self.proto == "ftp":
                if not self.password.text():
                    self.generate()
                srv = fileserver.FtpServer(folder, self.user.text(), self.password.text(), self.port.value(),
                                           passive_ports=(self.pasv_lo.value(), self.pasv_hi.value()), allow_write=self.write.isChecked(),
                                           allow_overwrite=self.replace.isChecked(), allowed=allowed, on_event=emit)
            else:
                if not self.password.text():
                    self.generate()
                srv = fileserver.SftpServer(folder, self.user.text(), self.password.text(), self.port.value(),
                                            host_key_path=self._key_path(), allow_write=self.write.isChecked(),
                                            allow_overwrite=self.replace.isChecked(), allowed=allowed, on_event=emit)
            srv.start()
        except (OSError, ValueError) as e:
            self.status.setText(f"Could not start: {e}")
            return
        self.server = srv
        if self.proto in ("sftp", "ftp"):
            try:
                db.set_secret(SECRETS[self.proto], self.password.text())
            except Exception:
                pass
        if self.proto == "sftp":
            self._show_fingerprint()
        self.save_choices()
        audit.log(f"{self.proto} server started", f"folder {folder}, port {srv.port}, uploads {'on' if srv.allow_write else 'off'}"
                  f"{', replacing on' if srv.allow_overwrite else ''}, clients {self.allowed.text().strip() or 'any'}")
        if self.minutes.value():
            self.timer.start(self.minutes.value() * 60000)
        self._sync()

    def stop(self, reason=""):
        self.timer.stop()
        if self.server:
            self.server.stop()
            audit.log(f"{self.proto} server stopped", f"{self.server.count} events")
            self.server = None
        self._sync()
        if reason:
            self.status.setText(reason)

    def _sync(self):
        on = self.server is not None
        self.go.setText(f"Stop {self.label} server" if on else f"Start {self.label} server")
        for w in (self.folder, self.browse, self.port, self.write, self.allowed, self.minutes, self.user, self.password,
                  self.gen, self.show_pw, self.pasv_lo, self.pasv_hi):
            w.setEnabled(not on)
        self.replace.setEnabled(not on and self.write.isChecked())
        if not on:
            self.status.setText("Stopped.")
            return
        s = self.server
        ips = fileserver.local_addresses() or ["this-computer"]
        shown = ", ".join(ips[:4])
        if self.proto == "tftp":
            how = f"Devices can use  tftp://{ips[0]}/<file>   (for example: copy tftp://{ips[0]}/image.bin flash:)"
        elif self.proto == "ftp":
            how = (f"Devices can use  ftp://{s.username}:<password>@{ips[0]}/<file>   "
                   f"(for example: copy ftp://{s.username}:<password>@{ips[0]}/image.bin flash:)")
        else:
            how = (f"Connect with any SFTP or SCP client to {shown} port {s.port} as {s.username}   "
                   f"(for example on a Cisco device: copy scp://{s.username}:<password>@{ips[0]}/image.bin flash:)")
        mode = ("read and upload" + (", replace and delete" if s.allow_overwrite else "")) if s.allow_write else "read-only"
        self.status.setText(f"Running on {shown}, port {s.port}, {mode}.  {how}  "
                            "If Windows asks about the firewall, allow private networks.")

    # ---- transfer list
    def on_event(self, e):
        self.rows.append(e)
        del self.rows[:-self.MAX_ROWS]
        self._add_row(e)
        if self.table.rowCount() > self.MAX_ROWS:
            self.table.removeRow(0)
        self.table.scrollToBottom()
        if e["status"] != "ok" or e["op"] in AUDITED:
            audit.log(f"{self.proto} {e['op']} {e['status']}", f"{e['client']} {e['path']} {_size(e['bytes']) if e['bytes'] else ''} {e['note']}".strip())

    def _add_row(self, e):
        i = self.table.rowCount()
        self.table.insertRow(i)
        values = [e["time"], e["client"], e["op"], e["path"], _size(e["bytes"]) if e["bytes"] else "", e["status"], e["note"]]
        for j, v in enumerate(values):
            it = QTableWidgetItem(v)
            if j == 5 and e["status"] == "denied":
                it.setForeground(st.qink("FAIL"))
            elif j == 5 and e["status"] == "failed":
                it.setForeground(st.qink("WARN"))
            self.table.setItem(i, j, it)

    def clear_rows(self):
        self.rows.clear()
        self.table.setRowCount(0)

    def save_rows(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save transfer log", f"{self.proto}-transfers-{datetime.now():%Y%m%d-%H%M}.txt", "Text files (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                for e in self.rows:
                    fh.write("\t".join(str(e[k]) for k in ("time", "client", "op", "path", "bytes", "status", "note")) + "\n")

    def shutdown(self):
        self.stop()


# =============================================================================== iperf3
class SecondsAxis(pg.AxisItem):
    """The time axis of a test: '2 s', '4 s' ..."""

    def __init__(self):
        super().__init__("bottom")

    def tickStrings(self, values, scale, spacing):
        return [f"{v:g} s" for v in values]


class ThroughputGraph(QFrame):
    """Speed over the course of a test, drawn with pyqtgraph: one point per interval, as it arrives."""

    def __init__(self):
        super().__init__()
        self.points = []                                    # [(seconds, Mbit/s)]
        self.setMinimumHeight(150)
        self.empty = QLabel("The speed appears here during a test")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty.setProperty("muted", True)
        self.summary = QLabel()
        self.summary.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.plot = plots.plot_widget(axisItems={"bottom": SecondsAxis()})
        self.plot.setMouseEnabled(x=True, y=False)
        self.plot.getViewBox().setMouseMode(pg.ViewBox.RectMode)
        self.plot.scene().sigMouseClicked.connect(lambda ev: ev.double() and self.plot.autoRange())
        self.plot.getAxis("left").setLabel("Mbit/s")
        self.curve = self.plot.plot()
        self.last = pg.ScatterPlotItem(size=8)
        self.plot.addItem(self.last)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 6, 10, 6)
        lay.setSpacing(2)
        for w in (self.summary, self.empty, self.plot):
            lay.addWidget(w)
        lay.setStretch(2, 1)
        self.set_points([])

    def set_points(self, points):
        self.points = list(points)
        plots.card_style(self, "throughputGraph")
        surface, _border, _muted = plots.restyle(self.plot)
        accent = plots.colours()[4]
        has = bool(self.points)
        self.empty.setVisible(not has)
        self.plot.setVisible(has)
        self.summary.setVisible(has)
        if not has:
            return
        xs, ys = [t for t, _ in self.points], [v for _, v in self.points]
        shade = QColor(accent)
        shade.setAlpha(45)
        self.curve.setData(xs, ys, pen=pg.mkPen(accent, width=2), fillLevel=0, brush=pg.mkBrush(shade))
        self.last.setData([xs[-1]], [ys[-1]], brush=pg.mkBrush(accent), pen=pg.mkPen(surface, width=1.2))
        peak = max(ys) or 1.0
        self.plot.setYRange(0, peak * 1.15, padding=0)
        self.plot.setXRange(0, max(xs) or 1.0, padding=0.01)
        self.summary.setText(f"now {ys[-1]:.1f}   peak {peak:.1f}   average {sum(ys) / len(ys):.1f} Mbit/s")


class IperfTab(QWidget):
    def __init__(self):
        super().__init__()
        self.exe = iperf.find_iperf3(db.get_setting("iperf_path"))
        self.buffer = ""
        self.mode = QComboBox()
        self.mode.addItems(["Client (run a test against another iperf3 server)", "Server (wait for another computer to test against this one)"])
        self.picker = DevicePicker()
        self.target = QLineEdit()
        self.target.setPlaceholderText("address of the iperf3 server")
        self.port, self.server_port = QSpinBox(), QSpinBox()
        for s in (self.port, self.server_port):
            s.setRange(1, 65535)
            s.setValue(5201)
        self.seconds, self.streams = QSpinBox(), QSpinBox()
        self.seconds.setRange(1, 3600)
        self.seconds.setValue(10)
        self.seconds.setSuffix(" s")
        self.streams.setRange(1, 128)
        self.reverse = QCheckBox("Download (the server sends)")
        self.udp = QCheckBox("UDP")
        self.bandwidth = QLineEdit()
        self.bandwidth.setPlaceholderText("UDP rate, e.g. 100M")
        self.bandwidth.setMaximumWidth(150)
        self.bind = QLineEdit()
        self.bind.setPlaceholderText("listen on one address (optional)")
        self.one_off = QCheckBox("Stop after one test")
        from core.platforms import exe as _exe
        from ui import installdlg
        self.where = _muted("")
        self.choose = QPushButton(f"Choose {_exe('iperf3')}...")
        self.install_iperf = installdlg.button("iperf3", self, done=self._iperf_installed)
        self.go = _primary("Start test")
        self.stop = QPushButton("Stop")
        self.stop.setEnabled(False)
        self.graph = ThroughputGraph()
        self.result = QLabel("")
        f = self.result.font()
        f.setBold(True)
        self.result.setFont(f)
        self.out = OutputBox()
        self.runner = Runner(self)
        self.runner.output.connect(self.on_output)
        self.runner.finished.connect(self._finished)

        self.client_box, self.server_box = QWidget(), QWidget()
        cl = QVBoxLayout(self.client_box)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.addLayout(_row("Device", self.picker, "Address", self.target, "Port", self.port))
        cl.addLayout(_row("Duration", self.seconds, "Streams", self.streams, self.reverse, self.udp, self.bandwidth))
        sl = QVBoxLayout(self.server_box)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.addLayout(_row("Port", self.server_port, self.bind, self.one_off))
        sl.addWidget(_muted("Other computers connect to this one on this port. Windows may ask about the firewall; allow private "
                            "networks only for as long as you need it, and stop the server when you are done."))

        lay = QVBoxLayout(self)
        lay.addWidget(self.where)
        lay.addLayout(self._left(self.choose, self.install_iperf))
        lay.addWidget(self.mode)
        lay.addWidget(self.client_box)
        lay.addWidget(self.server_box)
        lay.addLayout(self._left(self.go, self.stop))
        lay.addWidget(self.result)
        lay.addWidget(self.graph)
        lay.addWidget(self.out, 1)

        self.mode.currentIndexChanged.connect(self._mode)
        self.go.clicked.connect(self.start)
        self.stop.clicked.connect(self.halt)
        self.choose.clicked.connect(self.pick_exe)
        self.udp.toggled.connect(self.bandwidth.setEnabled)
        self.bandwidth.setEnabled(False)
        self.picker.currentIndexChanged.connect(
            lambda: self.picker.currentData() and self.target.setText(self.picker.currentData()["host"]))
        self._mode()
        self._where()

    @staticmethod
    def _left(*widgets):
        h = _row(*widgets)
        h.addStretch(1)
        return h

    def _where(self):
        from core.platforms import WINDOWS
        self.where.setText(
            f"Using iperf3: {self.exe}" if self.exe else
            "iperf3 was not found. Toner runs the free iperf3 program (it is not bundled): download iperf3 for Windows "
            "from iperf.fr, then choose iperf3.exe below, or put it in a folder on your PATH." if WINDOWS else
            "iperf3 was not found. Install iperf3 (for example: sudo apt install iperf3), or choose the iperf3 program below.")
        if hasattr(self, "install_iperf"):
            from ui import installdlg
            self.install_iperf.setVisible(not self.exe and installdlg.offered("iperf3"))

    def _iperf_installed(self):
        self.exe = iperf.find_iperf3(db.get_setting("iperf_path"))
        self._where()

    def _mode(self):
        self.client_box.setVisible(self.mode.currentIndex() == 0)
        self.server_box.setVisible(self.mode.currentIndex() == 1)
        self.go.setText("Start test" if self.mode.currentIndex() == 0 else "Start server")

    def pick_exe(self):
        path, _ = QFileDialog.getOpenFileName(self, "iperf3", os.path.dirname(self.exe or ""), "iperf3 (iperf3.exe);;All files (*)")
        if path:
            self.exe = path
            db.set_setting("iperf_path", path)
            self._where()

    def _busy(self, on):
        self.go.setEnabled(not on)
        self.stop.setEnabled(on)
        self.mode.setEnabled(not on)
        self.client_box.setEnabled(not on)
        self.server_box.setEnabled(not on)

    _server_running = False

    def _finished(self):
        self._busy(False)
        if self._server_running:
            audit.log("iperf3 server stopped")
            self._server_running = False

    def start(self):
        if not self.exe:
            self.out.line("iperf3 was not found. See the note at the top.")
            return
        server = self.mode.currentIndex() == 1
        try:
            args = iperf.server_args(self.server_port.value(), self.one_off.isChecked(), self.bind.text()) if server else \
                iperf.client_args(self.target.text(), self.port.value(), self.seconds.value(), self.streams.value(),
                                  self.reverse.isChecked(), self.udp.isChecked(), self.bandwidth.text())
        except ValueError as e:
            self.out.line(f"Error: {e}")
            return
        self.buffer = ""
        self.result.setText("")
        self.graph.set_points([])
        self.out.line(f"\n> iperf3 {' '.join(args)}")
        self._busy(True)
        self._server_running = server
        if server:
            audit.log("iperf3 server started", f"port {self.server_port.value()}")
        self.runner.start(self.exe, args)

    def halt(self):
        self.runner.stop()

    def on_output(self, text):
        self.out.add(text)
        self.buffer += text
        sm = iperf.Summary().feed(self.buffer)
        self.graph.set_points((r["end"], r["mbps"]) for r in sm.intervals)
        if sm.sender or sm.receiver:
            self.result.setText(sm.text())
        elif sm.intervals:
            self.result.setText(f"{sm.intervals[-1]['mbps']:.1f} Mbit/s   (running...)")

    def refresh(self):
        pass

    def shutdown(self):
        self.runner.stop()


# =============================================================================== Wi-Fi scanner
class WifiWorker(QThread):
    done = Signal(list, str, object)

    def run(self):
        nets, err = wifi.scan()
        adapters, _ = wifi.interfaces()
        self.done.emit(nets, err, wifi.current(adapters))


class WifiTab(QWidget):
    COLS = ["Network", "Signal", "Channel", "Band", "Radio", "Security", "BSSID", "Made by"]

    def __init__(self):
        super().__init__()
        self.nets, self.worker = [], None
        self.scan_btn = _primary("Scan now")
        self.auto = QCheckBox("Rescan every 5 seconds")
        self.band = QComboBox()
        self.band.addItems(["All bands", "2.4 GHz", "5 GHz", "6 GHz"])
        from ui.finder import SearchBox
        self.filter = SearchBox("Search networks", "Type part of a network name or an access point's maker. Several words must all match.",
                                page=self)
        self.me = _muted("")
        self.summary = _muted("")
        self.table = _table(self.COLS)
        self.timer = QTimer(self)
        self.timer.setInterval(5000)
        bar = QHBoxLayout()
        for w in (self.scan_btn, self.auto, self.band):
            bar.addWidget(w)
        bar.addStretch(1)
        bar.addWidget(self.filter, 1)                     # on the right, as on Inventory
        from core.platforms import WINDOWS
        from ui import installdlg
        self.install_nm = installdlg.button("nmcli", self, done=self.scan)
        self.install_nm.hide()                                     # shown when NetworkManager is missing (Linux)
        lay = QVBoxLayout(self)
        lay.addWidget(_muted("The Wi-Fi networks this computer can hear, strongest first, with the channel each one uses. "
                             "Use it to find a crowded channel, a weak spot, or an access point that is not yours."
                             + (" Windows needs Location access switched on to list networks." if WINDOWS else "")))
        lay.addLayout(bar)
        lay.addWidget(self.me)
        lay.addWidget(self.summary)
        lay.addWidget(self.install_nm, 0, Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(self.table, 1)
        self.scan_btn.clicked.connect(self.scan)
        self.auto.toggled.connect(lambda on: (self.timer.start() if on else self.timer.stop(), on and self.scan()))
        self.timer.timeout.connect(self.scan)
        self.band.currentIndexChanged.connect(self.show_rows)
        self.filter.textChanged.connect(self.show_rows)

    def scan(self):
        if self.worker and self.worker.isRunning():
            return
        self.scan_btn.setEnabled(False)
        self.summary.setText("Scanning...")
        self.worker = WifiWorker()
        self.worker.done.connect(self.on_done)
        self.worker.start()

    def on_done(self, nets, err, mine):
        self.scan_btn.setEnabled(True)
        self.nets = sorted(nets, key=lambda n: -(n["signal"] or 0))
        for n in self.nets:
            n["maker"] = oui.lookup(n["bssid"]) if n["bssid"] else ""
        if mine and mine.get("connected"):
            self.me.setText(f"This computer is connected to {mine.get('ssid', '?')} ({mine.get('band_text', '')}, "
                            f"channel {mine.get('channel_no') or '?'}, signal {mine.get('signal_pct', '?')}%).")
        else:
            self.me.setText("This computer is not connected to Wi-Fi." if mine else "")
        self.summary.setText(err if err else self._summary())
        from ui import installdlg
        self.install_nm.setVisible(err == wifi.NM_MISSING and installdlg.offered("nmcli"))
        self.show_rows()

    def _summary(self):
        ssids = {n["ssid"] for n in self.nets}
        text = f"{len(self.nets)} access points in {len(ssids)} networks."
        if any(n["band"] == "2.4 GHz" for n in self.nets):
            best, load = wifi.best_channels(self.nets)
            text += (f"  Quietest 2.4 GHz channel: {best}  (access points sharing channel 1: {load[1]}, 6: {load[6]}, "
                     f"11: {load[11]}).")
        return text

    def show_rows(self, *_):
        band = self.band.currentText()
        rows = [n for n in self.nets if (band == "All bands" or n["band"] == band) and self.filter.matches(n["ssid"], n.get("maker", ""))]
        self.table.setRowCount(len(rows))
        for i, n in enumerate(rows):
            sig = n["signal"]
            vals = [n["ssid"], "" if sig is None else f"{sig}%", n["channel"] or "", n["band"], n["radio"],
                    f"{n['auth']} {n['encryption']}".strip(), n["bssid"], n.get("maker", "")]
            for j, v in enumerate(vals):
                it = QTableWidgetItem(str(v))
                if j == 1 and sig is not None:
                    it.setForeground(st.qink(st.level(sig, 65, 40, lower_is_worse=True)))
                self.table.setItem(i, j, it)
        self.table.resizeColumnsToContents()

    def refresh(self):
        pass

    def shutdown(self):
        self.timer.stop()
        if self.worker:
            self.worker.wait(5000)


# =============================================================================== SCP (to and from a device)
class ScpWorker(QThread):
    line = Signal(str)
    progress = Signal(int, int)
    finished_ok = Signal(bool)

    def __init__(self, job):
        super().__init__()
        self.job = job
        self.cancel = threading.Event()

    def _progress(self, kind, name, done, total):
        if kind == "file":
            self.line.emit(f"  {name}  ({_size(total)})")
            self.progress.emit(0, total)
        elif kind == "dir":
            self.line.emit(f"  {name}/")
        else:
            self.progress.emit(done, total)

    def run(self):
        j, ok, client, extra = self.job, False, None, []
        try:
            self.line.emit(f"Connecting to {j['host']}:{j['port']} as {j['user']}...")
            client, extra = scp.connect(j["host"], j["port"], j["user"], j["password"], j["dev"], j["hostkey_mode"], j["timeout"])
            s = scp.Scp(client, progress=self._progress, cancel=self.cancel, timeout=j["timeout"])
            if j["upload"]:
                files, nbytes = s.upload(j["local"], j["remote"], j["recursive"], j["preserve"])
            else:
                files, nbytes = s.download(j["remote"], j["local"], j["recursive"], j["preserve"], j["overwrite"])
            for path in s.skipped:
                self.line.emit(f"  kept your existing file, not replaced: {path}")
            self.line.emit(f"Done: {files} file(s), {_size(nbytes)}.")
            ok = True
            self.summary = (files, nbytes)
        except scp.Cancelled:
            self.line.emit("Stopped.")
        except paramiko.BadHostKeyException:
            self.line.emit(f"HOST KEY CHANGED for {j['host']}. It does not match the key saved earlier: the device may "
                           "have been replaced or reset, or something is impersonating it. Nothing was copied. If the "
                           "change is expected, forget the saved key under Settings > Security.")
        except paramiko.AuthenticationException:
            self.line.emit("Login failed: the device did not accept the user name and password.")
        except Exception as e:
            text = str(e)
            if "not found in known_hosts" in text:
                text = (f"{j['host']} is not a known host and the policy is 'Reject unknown hosts'. Connect once with "
                        "'Trust on first use' to save its key.")
            self.line.emit(f"Failed: {text if isinstance(e, (scp.ScpError, proxy.ProxyError)) or 'known host' in text else type(e).__name__ + ': ' + text}")
        finally:
            if client:
                client.close()
            for c in extra:
                try:
                    c.close()
                except Exception:
                    pass
            self.finished_ok.emit(ok)


class ScpTab(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.picker = DevicePicker()
        self.host, self.user, self.password = QLineEdit(), QLineEdit(), QLineEdit()
        self.host.setPlaceholderText("host or IP")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(int(db.get_setting("default_ssh_port")))
        self.direction = QComboBox()
        self.direction.addItem("Send to the device (upload)", True)
        self.direction.addItem("Get from the device (download)", False)
        self.local, self.remote = QLineEdit(), QLineEdit()
        self.remote.setPlaceholderText("e.g. flash:/image.bin  or  /config/backup.cfg")
        self.file_btn, self.folder_btn = QPushButton("File..."), QPushButton("Folder...")
        self.recursive = QCheckBox("Include sub-folders")
        self.preserve = QCheckBox("Keep file dates")
        self.overwrite = QCheckBox("Replace files that already exist here")
        self.go = _primary("Start")
        self.stop = QPushButton("Stop")
        self.stop.setEnabled(False)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setMaximumHeight(8)
        self.out = OutputBox()
        self.local_label = QLabel("From (this computer)")
        self.remote_label = QLabel("To (on the device)")

        lay = QVBoxLayout(self)
        lay.addWidget(_muted("Copy files to or from a device over SSH (SCP). Uses the device's saved login, jump host and "
                             "proxy. The device must allow it: on Cisco IOS turn it on with 'ip scp server enable' and use a "
                             "user with privilege 15; Juniper, Arista, MikroTik and most Linux systems have it ready."))
        lay.addLayout(_row("Device", self.picker, "Host", self.host, "Port", self.port, "User", self.user, "Password", self.password))
        lay.addLayout(_row("Direction", self.direction))
        lay.addLayout(_row(self.local_label, self.local, self.file_btn, self.folder_btn))
        lay.addLayout(_row(self.remote_label, self.remote))
        lay.addLayout(_row(self.recursive, self.preserve, self.overwrite))
        lay.addLayout(_row(self.go, self.stop))
        lay.addWidget(self.bar)
        lay.addWidget(self.out, 1)

        self.picker.currentIndexChanged.connect(self.picked)
        self.direction.currentIndexChanged.connect(self._direction)
        self.file_btn.clicked.connect(self.pick_file)
        self.folder_btn.clicked.connect(self.pick_folder)
        self.go.clicked.connect(self.start)
        self.stop.clicked.connect(self.halt)
        self.password.returnPressed.connect(self.start)
        self.picked()
        self._direction()

    def picked(self, *_):
        d = self.picker.currentData()
        if d:
            self.host.setText(d["host"])
            if d.get("port"):
                self.port.setValue(int(d["port"]))
            self.user.setText(profiles.username(d))
            self.password.setPlaceholderText("blank = use the stored password" if vendors.uses_ssh_login(d["vendor"]) else "")
        else:
            self.password.setPlaceholderText("")

    def stored_password(self):
        d = self.picker.currentData()
        return (profiles.secret(d) or "") if d and vendors.uses_ssh_login(d["vendor"]) else ""

    def _direction(self, *_):
        up = bool(self.direction.currentData())
        self.local_label.setText("From (this computer)" if up else "To (this computer)")
        self.remote_label.setText("To (on the device)" if up else "From (on the device)")
        self.file_btn.setVisible(up)
        self.overwrite.setVisible(not up)

    def pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "File to send", self.local.text() or os.path.expanduser("~"))
        if path:
            self.local.setText(os.path.normpath(path))

    def pick_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Folder", self.local.text() or os.path.expanduser("~"))
        if path:
            self.local.setText(os.path.normpath(path))
            if self.direction.currentData():
                self.recursive.setChecked(True)

    def running(self):
        return bool(self.worker and self.worker.isRunning())

    def _busy(self, on):
        self.go.setEnabled(not on)
        self.stop.setEnabled(on)
        for w in (self.picker, self.host, self.port, self.user, self.password, self.direction, self.local, self.remote,
                  self.recursive, self.preserve, self.overwrite, self.file_btn, self.folder_btn):
            w.setEnabled(not on)

    def start(self):
        if self.running():
            return
        try:
            host = nettools.check_host(self.host.text())
        except ValueError as e:
            self.out.line(f"Error: {e}")
            return
        user, remote, local = self.user.text().strip(), self.remote.text().strip(), self.local.text().strip().strip('"')
        up = bool(self.direction.currentData())
        problem = ("Enter a user name." if not user else "Enter the path on the device (for example flash:/image.bin)." if not remote
                   else "Choose the file or folder on this computer." if not local
                   else f"{local} does not exist." if up and not os.path.exists(local) else "")
        if problem:
            self.out.line(f"Error: {problem}")
            return
        dev = self.picker.currentData()
        job = {"host": host, "port": self.port.value(), "user": user, "password": self.password.text() or self.stored_password(),
               "dev": profiles.resolve(dev) if dev else None, "upload": up, "local": local, "remote": remote,
               "recursive": self.recursive.isChecked(), "preserve": self.preserve.isChecked(),
               "overwrite": self.overwrite.isChecked(), "hostkey_mode": db.get_setting("hostkey_mode"),
               "timeout": int(db.get_setting("ssh_timeout"))}
        self.out.line(f"\n> {'send' if up else 'get'} {local} {'to' if up else 'from'} {user}@{host}:{remote}")
        self.bar.setValue(0)
        self._busy(True)
        self.worker = ScpWorker(job)
        self.worker.line.connect(self.out.line)
        self.worker.progress.connect(lambda done, total: (self.bar.setMaximum(max(1, total)), self.bar.setValue(done)))
        self.worker.finished_ok.connect(lambda ok, job=job: self._done(ok, job))
        self.worker.start()

    def _done(self, ok, job):
        self._busy(False)
        self.bar.setValue(self.bar.maximum() if ok else self.bar.value())
        audit.log("scp " + ("upload" if job["upload"] else "download") + ("" if ok else " failed"),
                  f"{(self.picker.currentData() or {}).get('name') or job['host']}: {job['local']} "
                  f"{'->' if job['upload'] else '<-'} {job['remote']}")

    def halt(self):
        if self.running():
            self.worker.cancel.set()

    def refresh(self):
        pass

    def shutdown(self):
        if self.running():
            self.worker.cancel.set()
            self.worker.wait(5000)


# =============================================================================== xcopy (copy folders on this computer or a share)
class XcopyTab(QWidget):
    """Copy Files: Windows' xcopy, or rsync on Linux and macOS (core/rsync.py: the same options and calls)."""

    def __init__(self):
        super().__init__()
        from core import rsync
        from core.platforms import WINDOWS
        self.windows = WINDOWS
        self.tool = xcopy if WINDOWS else rsync
        self.name = "xcopy" if WINDOWS else "rsync"
        self.exe = xcopy.find_xcopy() if WINDOWS else rsync.find()
        self.buffer = ""
        self.source, self.dest = QLineEdit(), QLineEdit()
        if WINDOWS:
            self.source.setPlaceholderText(r"C:\TFTP   or   \\fileserver\share\configs   or   C:\TFTP\*.cfg")
            self.dest.setPlaceholderText(r"D:\Backups\network   or   \\fileserver\backup")
        else:
            self.source.setPlaceholderText("/srv/tftp   or   /mnt/fileserver/configs   or   /srv/tftp/*.cfg")
            self.dest.setPlaceholderText("/mnt/backup/network")
        self.src_file, self.src_folder, self.dst_folder = QPushButton("File..."), QPushButton("Folder..."), QPushButton("Folder...")
        self.subfolders = QCheckBox("Include sub-folders, even empty ones")
        self.subfolders.setChecked(True)
        self.existing = QComboBox()
        self.existing.addItem("Replace files that already exist", xcopy.REPLACE)
        self.existing.addItem("Replace only if the source is newer", xcopy.NEWER)
        self.hidden = QCheckBox("Include hidden and system files" if WINDOWS else "Include hidden files (names starting with a dot)")
        self.readonly = QCheckBox("Keep the read-only attribute" if WINDOWS else "Keep permissions")
        self.keep_going = QCheckBox("Keep going after an error")
        self.keep_going.setChecked(True)
        self.verify = QCheckBox("Verify each file after writing")
        self.preview = QPushButton("Preview")
        self.go = _primary("Copy")
        self.stop = QPushButton("Stop")
        self.stop.setEnabled(False)
        self.result = QLabel("")
        f = self.result.font()
        f.setBold(True)
        self.result.setFont(f)
        self.out = OutputBox()
        self.runner = Runner(self)
        self.runner.output.connect(self.on_output)
        self.runner.finished.connect(self._finished)
        self._preview = False

        from ui import installdlg
        self.install = installdlg.button("rsync", self, done=self._rsync_installed)
        self.install.setVisible(not WINDOWS and not self.exe and installdlg.offered("rsync"))
        lay = QVBoxLayout(self)
        self.intro = _muted(
            "Copy a folder, or files matching a pattern, on this computer or to and from a network share, using Windows "
            "xcopy. The contents of the source folder are copied into the destination folder. Use Preview first to see "
            "what would be copied without copying anything." + ("" if self.exe else "  xcopy.exe was not found on this computer.")
            if WINDOWS else
            "Copy a folder, or files matching a pattern, on this computer or to and from a mounted network share, using rsync. "
            "The contents of the source folder are copied into the destination folder. Use Preview first to see what would "
            "be copied without copying anything." + ("" if self.exe else "  rsync was not found on this computer."))
        lay.addWidget(self.intro)
        lay.addWidget(self.install, 0, Qt.AlignmentFlag.AlignLeft)
        lay.addLayout(_row("Copy from", self.source, self.src_file, self.src_folder))
        lay.addLayout(_row("Copy to", self.dest, self.dst_folder))
        lay.addLayout(_row("If a file already exists", self.existing, self.subfolders))
        lay.addLayout(_row(self.hidden, self.readonly, self.keep_going, self.verify))
        self.keep_going.setVisible(WINDOWS)                     # rsync always carries on, and checks what it writes
        self.verify.setVisible(WINDOWS)
        lay.addLayout(_row(self.preview, self.go, self.stop))
        lay.addWidget(self.result)
        lay.addWidget(self.out, 1)
        self.src_file.clicked.connect(lambda: self._pick(self.source, True))
        self.src_folder.clicked.connect(lambda: self._pick(self.source, False))
        self.dst_folder.clicked.connect(lambda: self._pick(self.dest, False))
        self.preview.clicked.connect(lambda: self.start(True))
        self.go.clicked.connect(lambda: self.start(False))
        self.stop.clicked.connect(self.runner.stop)

    def _pick(self, box, file):
        if file:
            path, _ = QFileDialog.getOpenFileName(self, "File to copy", box.text() or os.path.expanduser("~"))
        else:
            path = QFileDialog.getExistingDirectory(self, "Folder", box.text() or os.path.expanduser("~"))
        if path:
            box.setText(os.path.normpath(path))

    def _busy(self, on):
        for w in (self.go, self.preview):
            w.setEnabled(not on)
        self.stop.setEnabled(on)

    def start(self, preview):
        if self.runner.running():
            return
        if not self.exe:
            self.out.line("Error: xcopy.exe was not found on this computer." if self.windows else "Error: rsync was not found on this computer.")
            return
        try:
            args = self.tool.build_args(self.source.text(), self.dest.text(), self.subfolders.isChecked(),
                                    self.existing.currentData(), self.hidden.isChecked(), self.readonly.isChecked(),
                                    self.keep_going.isChecked(), self.verify.isChecked(), preview)
        except ValueError as e:
            self.out.line(f"Error: {e}")
            return
        dest = args[1] if self.windows else args[-1].rstrip("/")
        if (not preview and self.existing.currentData() == xcopy.REPLACE and os.path.isdir(dest) and os.listdir(dest)
                and QMessageBox.question(self, "Replace files?", f"Files in {dest} with the same names as the ones being "
                                         "copied will be replaced.\n\nCopy anyway? (Preview shows what would be copied.)")
                != QMessageBox.StandardButton.Yes):
            return
        self._preview, self.buffer = preview, ""
        self.result.setText("")
        self.out.line(f"\n> {self.name} {' '.join(args)}")
        if not preview:
            audit.log(self.name, f"{self.source.text().strip()} -> {dest} ({self.existing.currentText().lower()})")
        self._busy(True)
        self.runner.start(self.exe, args)

    def on_output(self, text):
        self.out.add(text)
        self.buffer += text

    def _finished(self):
        self._busy(False)
        m = re.findall(r"\[finished, exit code (-?\d+)\]", self.buffer)
        code = int(m[-1]) if m else -1
        text = self.tool.describe_exit(code, self.buffer)
        if self._preview and code == 0 and self.tool.count_copied(self.buffer):
            text = f"Preview: {self.tool.count_copied(self.buffer)} file(s) would be copied. Nothing was copied."
        self.result.setText(text)

    def _rsync_installed(self):
        from core import rsync
        self.exe = rsync.find()
        if self.exe:
            self.install.hide()
            self.intro.setText(self.intro.text().replace("  rsync was not found on this computer.", ""))

    def refresh(self):
        pass

    def shutdown(self):
        self.runner.stop()
