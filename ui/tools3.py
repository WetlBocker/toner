"""File servers (TFTP, SFTP) and the iperf3 throughput test."""
import os
import subprocess
from datetime import datetime

from PySide6.QtCore import QTimer, Qt, Signal
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                               QPushButton, QSpinBox, QStackedWidget, QTableWidgetItem, QVBoxLayout, QWidget)
from core import audit, db, fileserver, iperf
from ui.tools import DevicePicker, OutputBox, Runner, _row
from ui.tools2 import _muted, _primary, _table

SECRET = "service:sftp-server"
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
    PROTOS = {"tftp": ("TFTP", 69), "sftp": ("SFTP", 2222)}

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
        if proto == "sftp":
            lay.addLayout(_row("User name", self.user, "Password", self.password, self.show_pw, self.gen))
            lay.addWidget(self.fingerprint)
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
        return ("An SFTP server (file transfer over SSH, with a user name and password) for the same jobs. It serves only "
                "the folder below, is read-only until you allow uploads, gives no shell, and locks out an address after "
                "five wrong passwords.")

    # ---- saved choices (never the password: that goes to Credential Manager)
    def load(self):
        saved = (db.get_setting("fileserver") or {}).get(self.proto, {})
        self.folder.setText(saved.get("folder", ""))
        self.port.setValue(saved.get("port", self.port.value()))
        self.write.setChecked(bool(saved.get("write")))
        self.replace.setChecked(bool(saved.get("replace")) and self.write.isChecked())
        self.allowed.setText(saved.get("allowed", ""))
        self.minutes.setValue(saved.get("minutes", 60))
        if self.proto == "sftp":
            self.user.setText(saved.get("user", "toner"))
            try:
                import keyring
                self.password.setText(keyring.get_password(db.SERVICE, SECRET) or "")
            except Exception:
                pass
            self._show_fingerprint()

    def save_choices(self):
        data = dict(db.get_setting("fileserver") or {})
        entry = {"folder": self.folder.text().strip(), "port": self.port.value(), "write": self.write.isChecked(),
                 "replace": self.replace.isChecked(), "allowed": self.allowed.text().strip(), "minutes": self.minutes.value()}
        if self.proto == "sftp":
            entry["user"] = self.user.text().strip()
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
        if self.proto == "sftp":
            try:
                db.set_secret(SECRET, self.password.text())
            except Exception:
                pass
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
                  self.gen, self.show_pw):
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
        else:
            how = f"Connect with any SFTP client to {shown} port {s.port} as {s.username}."
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
                it.setForeground(QColor("#d32f2f"))
            elif j == 5 and e["status"] == "failed":
                it.setForeground(QColor("#e6b800"))
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
        self.where = _muted("")
        self.choose = QPushButton("Choose iperf3.exe...")
        self.go = _primary("Start test")
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
        self.pages = QStackedWidget()
        self.pages.addWidget(self.client_box)
        self.pages.addWidget(self.server_box)

        lay = QVBoxLayout(self)
        lay.addWidget(self.where)
        lay.addLayout(self._left(self.choose))
        lay.addWidget(self.mode)
        lay.addWidget(self.pages)
        lay.addLayout(self._left(self.go, self.stop))
        lay.addWidget(self.result)
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
        self.where.setText(
            f"Using iperf3: {self.exe}" if self.exe else
            "iperf3 was not found. Toner runs the free iperf3 program (it is not bundled): download iperf3 for Windows "
            "from iperf.fr, then choose iperf3.exe below, or put it in a folder on your PATH.")

    def _mode(self):
        self.pages.setCurrentIndex(self.mode.currentIndex())
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
        self.pages.setEnabled(not on)

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
        if sm.sender or sm.receiver:
            self.result.setText(sm.text())
        elif sm.intervals:
            self.result.setText(f"{sm.intervals[-1]['mbps']:.1f} Mbit/s   (running...)")

    def refresh(self):
        pass

    def shutdown(self):
        self.runner.stop()
