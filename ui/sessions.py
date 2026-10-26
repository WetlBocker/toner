"""Sessions: saved connections (SSH, Telnet, Remote Desktop, Serial) on the left, open terminals in tabs on the right."""
import math

from PySide6.QtCore import QPoint, Qt, QTimer, Signal
from PySide6.QtGui import QFont, QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QGridLayout, QHBoxLayout,
                               QInputDialog, QLabel, QLineEdit, QMenu, QMessageBox, QPushButton, QSpinBox, QSplitter,
                               QStackedWidget, QTabWidget, QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)
from core import audit, db, nettools, profiles, serialconn, sessionlog, sessions, vendors
from core.telnet import TelnetSession
from ui.terminal import TerminalView
from ui.widgets import flow, remember_sizes

KIND_TEXT = {k: label for k, label, _, _ in sessions.KINDS}
ROLE = Qt.ItemDataRole.UserRole


def _muted(text=""):
    lab = QLabel(text)
    lab.setProperty("muted", True)
    lab.setWordWrap(True)
    return lab


def _device(name, org=None):
    """The inventory device a session points at, looked up in the session's own organization."""
    if not name:
        return None
    with db.within(org):
        return next((d for d in db.list_devices() if d["name"] == name), None)


# =============================================================================== the new / edit dialog
class SessionDialog(QDialog):
    def __init__(self, session=None, kind="ssh", parent=None, folder_id=None, org=None):
        """org: for a new session, the organization picked in Global's list (its folders and devices are offered)."""
        from ui.orgfield import choice_file
        start = (session or {}).get("org") if session and session.get("id") else choice_file(org)
        with db.within(start):
            self._build(session, kind, parent, folder_id, org)

    def _build(self, session, kind, parent, folder_id, org):
        from ui.orgfield import org_choices, choice_file
        super().__init__(parent)
        self.session = session or {}
        self.folder_id = (session or {}).get("folder_id", folder_id)
        self.action = None
        self.setWindowTitle("Edit session" if session else "New session")
        self.setMinimumWidth(520)
        self.kind = QComboBox()
        for k, label, _, _ in sessions.KINDS:
            self.kind.addItem(label, k)
        self.about_kind = _muted("")
        self.name, self.folder = QLineEdit(), QComboBox()
        self.name.setPlaceholderText("e.g. Core switch, Rack 4 console")
        self.new_folder_btn = QPushButton("New folder...")
        self.new_folder_btn.setToolTip("Make a folder to keep sessions in (inside the one chosen here, if any)")
        self._fill_folders(self.folder_id)
        folder_row = QWidget()
        fl = QHBoxLayout(folder_row)
        fl.setContentsMargins(0, 0, 0, 0)
        fl.addWidget(self.folder, 1)
        fl.addWidget(self.new_folder_btn)
        self.device = QComboBox()
        self.device.addItem("(none: enter the details here)", "")
        for d in db.list_devices():
            self.device.addItem(f"{d['name']}  -  {d['host']}", d["name"])
        self.device.setToolTip("Use an inventory device's address, user name, saved password, jump host and proxy.")
        self.org_pick = QComboBox()
        org_choices(self.org_pick, self.session if self.session.get("id") else None, org)
        self.org_pick.setToolTip("Which organization the session belongs to. Shared sessions are seen by every organization.")
        if self.session.get("id") and not db.everything():
            self.org_pick.setEnabled(False)
        self._org_was = choice_file(self.org_pick.currentData())
        self.org_pick.currentIndexChanged.connect(self._org_changed)
        self.host, self.user, self.password = QLineEdit(), QLineEdit(), QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.host.setPlaceholderText("host name or IP address")
        self.port = QSpinBox()
        self.port.setRange(0, 65535)
        self.port.setSpecialValueText("default")
        self.remember = QCheckBox("Remember the password (kept in Toner's vault)")
        from ui.linkitem import LinkRow
        self.link_row = LinkRow()                                    # Link... to a password manager item (when one is chosen)
        self.paging = QCheckBox("Turn off paging after login")
        # remote desktop
        self.fullscreen = QCheckBox("Fill the window (full screen in Windows' own client)")
        self.width_, self.height_ = QSpinBox(), QSpinBox()
        for s, v in ((self.width_, 1280), (self.height_, 800)):
            s.setRange(320, 8192)
            s.setValue(v)
        self.clipboard = QCheckBox("Share the clipboard")
        self.drives = QCheckBox("Make my drives available in the session")
        self.printers = QCheckBox("Make my printers available in the session")
        self.admin = QCheckBox("Connect to the console (administrative) session")
        self.gateway = QLineEdit()
        self.gateway.setPlaceholderText("optional Remote Desktop gateway")
        self.client = QComboBox()                                    # Windows: its own Remote Desktop, or FreeRDP (xrdp on Linux)
        self.client.addItem("Windows Remote Desktop", "windows")
        self.client.addItem("FreeRDP", "freerdp")
        # vnc
        self.vnc_full, self.vnc_viewonly = QCheckBox("Full screen"), QCheckBox("View only")
        # serial
        self.serial_port = QComboBox()
        self.serial_port.setEditable(True)
        self.refresh_ports = QPushButton("Refresh")
        self.baud = QComboBox()
        self.baud.setEditable(True)
        for b in sessions.BAUDS:
            self.baud.addItem(str(b), b)
        self.baud.setCurrentText("9600")
        self.bits, self.parity, self.stop, self.flow = QComboBox(), QComboBox(), QComboBox(), QComboBox()
        for b in (8, 7, 6, 5):
            self.bits.addItem(str(b), b)
        for label, v in sessions.PARITY:
            self.parity.addItem(label, v)
        for label, v in (("1", 1), ("1.5", 1.5), ("2", 2)):
            self.stop.addItem(label, v)
        for label, v in sessions.FLOW:
            self.flow.addItem(label, v)
        self.save_box = QCheckBox("Save this session so it can be opened again")
        self.save_box.setChecked(True)

        self.form = QFormLayout()
        port_row = QWidget()
        pl = QHBoxLayout(port_row)
        pl.setContentsMargins(0, 0, 0, 0)
        pl.addWidget(self.serial_port, 1)
        pl.addWidget(self.refresh_ports)
        self.rows = {}
        for key, label, widget, kinds in (
                ("org", "Organization", self.org_pick, "all"),
                ("kind", "Type", self.kind, "all"), ("about", "", self.about_kind, "all"), ("name", "Name", self.name, "all"),
                ("folder", "Folder", folder_row, "all"),
                ("device", "Inventory device", self.device, ("ssh", "telnet", "rdp", "vnc")),
                ("host", "Host", self.host, ("ssh", "telnet", "rdp", "vnc")), ("port", "Port", self.port, ("ssh", "telnet", "rdp", "vnc")),
                ("user", "User name", self.user, ("ssh", "rdp")), ("password", "Password", self.password, ("ssh",)),
                ("remember", "", self.remember, ("ssh",)), ("link", "", self.link_row, ("ssh",)), ("paging", "", self.paging, ("ssh",)),
                ("client", "Client", self.client, ("rdp",)), ("vnc_full", "", self.vnc_full, ("vnc",)),
                ("vnc_viewonly", "", self.vnc_viewonly, ("vnc",)),
                ("fullscreen", "", self.fullscreen, ("rdp",)), ("width", "Window width", self.width_, ("rdp",)),
                ("height", "Window height", self.height_, ("rdp",)), ("clipboard", "", self.clipboard, ("rdp",)),
                ("drives", "", self.drives, ("rdp",)), ("printers", "", self.printers, ("rdp",)), ("admin", "", self.admin, ("rdp",)),
                ("gateway", "Gateway", self.gateway, ("rdp",)),
                ("serial_port", "Port", port_row, ("serial",)), ("baud", "Baud rate", self.baud, ("serial",)),
                ("bits", "Data bits", self.bits, ("serial",)), ("parity", "Parity", self.parity, ("serial",)),
                ("stop", "Stop bits", self.stop, ("serial",)), ("flow", "Flow control", self.flow, ("serial",)),
                ("save", "", self.save_box, "all")):
            self.form.addRow(label, widget)
            self.rows[key] = (widget, kinds)
        self.note = _muted("")
        self.buttons = QDialogButtonBox()
        self.connect_btn = self.buttons.addButton("Connect", QDialogButtonBox.ButtonRole.AcceptRole)
        self.save_btn = self.buttons.addButton("Save", QDialogButtonBox.ButtonRole.ActionRole)
        self.buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        self.connect_btn.setDefault(True)
        lay = QVBoxLayout(self)
        lay.addLayout(self.form)
        lay.addWidget(self.note)
        lay.addWidget(self.buttons)

        self.kind.setCurrentIndex(max(0, self.kind.findData(self.session.get("kind") or kind)))
        self._load()
        self.kind.currentIndexChanged.connect(self._adapt)
        self.client.currentIndexChanged.connect(self._adapt)              # (the note says where it opens)
        self.device.currentIndexChanged.connect(self._from_device)
        self.refresh_ports.clicked.connect(self._fill_ports)
        self.new_folder_btn.clicked.connect(self._new_folder)
        self.connect_btn.clicked.connect(lambda: self._done("connect"))
        self.save_btn.clicked.connect(lambda: self._done("save"))
        self.buttons.rejected.connect(self.reject)
        self._fill_ports(keep=self.session.get("host") if self.session.get("kind") == "serial" else "")
        self._adapt()

    # ---- what is shown
    def current_kind(self):
        return self.kind.currentData()

    def _adapt(self, *_):
        k = self.current_kind()
        from core import orgs
        from ui.linkitem import wanted
        from core.platforms import WINDOWS
        for key, (widget, kinds) in self.rows.items():
            self.form.setRowVisible(widget, (kinds == "all" or k in kinds) and (key != "org" or bool(orgs.list_orgs()))
                                    and (key != "link" or wanted()) and (key != "client" or WINDOWS))
        info = next(t for kk, _, _, t in sessions.KINDS if kk == k)
        self.about_kind.setText(info)
        self.connect_btn.setText("Connect")
        self.note.setText({"ssh": "A password left empty is asked for when you connect, or taken from the inventory device.",
                           "telnet": "Telnet sends everything, passwords included, without encryption.",
                           "rdp": self._rdp_note(),
                           "vnc": "Opens in the VNC viewer, which asks for the password. Toner never stores it.",
                           "serial": "Enter sends a carriage return, as consoles expect. Use Send break from the session tab for ROMMON."}[k])
        self.adjustSize()

    def _rdp_note(self):
        """Where a Remote Desktop session opens: Windows' tab, or FreeRDP in its own window (Toner asks for the password on Linux)."""
        s = {"options": {"client": self.client.currentData()}}
        if sessions.rdp_client(s) == "windows":
            return "Opens in a tab inside Toner. Windows asks for the password when the connection starts; Toner never stores it."
        if sessions.asks_for_password(s):
            return "Opens in FreeRDP, in its own window. Toner asks for the password and never stores it."
        return "Opens in FreeRDP, in its own window. Toner never stores the password."

    def _fill_folders(self, select=None):
        self.folder.clear()
        self.folder.addItem("(top level)", None)
        for fid, path in sorted(sessions.folder_paths().items(), key=lambda kv: kv[1].lower()):
            self.folder.addItem(path, fid)
        self.folder.setCurrentIndex(max(0, self.folder.findData(select)))

    def _new_folder(self):
        name, ok = QInputDialog.getText(self, "New folder", "Folder name:")
        if not ok or not name.strip():
            return
        parent = self.folder.currentData()
        from ui.orgfield import choice_file
        try:
            with db.within(choice_file(self.org_pick.currentData())):
                fid = sessions.create_folder(name, parent)
        except ValueError as e:
            QMessageBox.warning(self, "New folder", str(e))
            return
        with db.within(choice_file(self.org_pick.currentData())):
            self._fill_folders(fid)

    def _org_changed(self, *_):
        """Another organization: its folders and inventory devices."""
        from ui.orgfield import choice_file
        new = choice_file(self.org_pick.currentData())
        if new is None or new == self._org_was:
            return
        self._org_was = new
        with db.within(new):
            self._fill_folders(None)
            self.device.blockSignals(True)
            self.device.clear()
            self.device.addItem("(none: enter the details here)", "")
            for d in db.list_devices():
                self.device.addItem(f"{d['name']}  -  {d['host']}", d["name"])
            self.device.blockSignals(False)

    def _fill_ports(self, keep=""):
        cur = keep if isinstance(keep, str) and keep else self.serial_port.currentText()
        self.serial_port.clear()
        for dev, desc in serialconn.ports():
            self.serial_port.addItem(desc if desc.startswith(dev) else f"{dev}  -  {desc}", dev)
        if cur:
            self.serial_port.setCurrentText(cur)
        elif self.serial_port.count():
            self.serial_port.setCurrentIndex(0)

    def _from_device(self, *_):
        from ui.orgfield import choice_file
        d = _device(self.device.currentData(), choice_file(self.org_pick.currentData()))
        if d:
            self.host.setText(d["host"])
            if d.get("port"):
                self.port.setValue(int(d["port"]))
            self.user.setText(profiles.username(d))
            if not self.name.text().strip():
                self.name.setText(d["name"])

    def _load(self):
        s = self.session
        if not s:                                          # a new session starts from the usual defaults
            self.paging.setChecked(sessions.DEFAULTS["ssh"]["paging"])
            self.clipboard.setChecked(sessions.DEFAULTS["rdp"]["clipboard"])
            return
        o = s.get("options") or {}
        self.name.setText(s.get("name") or "")
        self.device.setCurrentIndex(max(0, self.device.findData(s.get("device") or "")))
        self.host.setText(s.get("host") if s["kind"] != "serial" else "")
        self.port.setValue(int(s.get("port") or 0))
        self.user.setText(s.get("username") or "")
        self.remember.setChecked(bool(o.get("remember")))
        self.paging.setChecked(bool(o.get("paging", True)))
        if s.get("id") and sessions.password(s["id"], s.get("org")):
            self.password.setPlaceholderText("saved; leave blank to keep")
        if s.get("id"):
            with db.within(s.get("org")):
                self.link_row.load(sessions.secret_name(s["id"]))
        self.fullscreen.setChecked(bool(o.get("fullscreen")))
        self.width_.setValue(int(o.get("width", 1280)))
        self.height_.setValue(int(o.get("height", 800)))
        self.clipboard.setChecked(bool(o.get("clipboard", True)))
        self.drives.setChecked(bool(o.get("drives")))
        self.printers.setChecked(bool(o.get("printers")))
        self.admin.setChecked(bool(o.get("admin")))
        self.gateway.setText(o.get("gateway") or "")
        self.client.setCurrentIndex(max(0, self.client.findData(o.get("client") or "windows")))
        self.vnc_full.setChecked(bool(o.get("fullscreen")) if s.get("kind") == "vnc" else False)
        self.vnc_viewonly.setChecked(bool(o.get("viewonly")))
        self.baud.setCurrentText(str(o.get("baud", 9600)))
        self.bits.setCurrentIndex(max(0, self.bits.findData(int(o.get("bytesize", 8)))))
        self.parity.setCurrentIndex(max(0, self.parity.findData(o.get("parity", "N"))))
        self.stop.setCurrentIndex(max(0, self.stop.findData(o.get("stopbits", 1))))
        self.flow.setCurrentIndex(max(0, self.flow.findData(o.get("flow", "none"))))
        self.save_box.setChecked(True)

    # ---- what it produces
    def values(self):
        k = self.current_kind()
        from ui.orgfield import choice_file, SHARED_CHOICE
        v = {"id": self.session.get("id"), "kind": k, "name": self.name.text().strip(),
             "org": choice_file(self.org_pick.currentData()), "shared": int(self.org_pick.currentData() == SHARED_CHOICE),
             "folder_id": self.folder.currentData(), "device": self.device.currentData() if k in ("ssh", "telnet", "rdp", "vnc") else "",
             "host": self.host.text().strip(), "port": self.port.value(), "username": self.user.text().strip() if k in ("ssh", "rdp") else "",
             "options": {}}
        if k == "ssh":
            v["options"] = {"paging": self.paging.isChecked(), "remember": self.remember.isChecked()}
        elif k == "rdp":
            v["options"] = {"fullscreen": self.fullscreen.isChecked(), "width": self.width_.value(), "height": self.height_.value(),
                            "clipboard": self.clipboard.isChecked(), "drives": self.drives.isChecked(),
                            "printers": self.printers.isChecked(), "admin": self.admin.isChecked(), "gateway": self.gateway.text().strip(),
                            "client": self.client.currentData()}
        elif k == "vnc":
            v["options"] = {"fullscreen": self.vnc_full.isChecked(), "viewonly": self.vnc_viewonly.isChecked()}
        elif k == "serial":
            port = self._serial_port()
            try:
                baud = int(self.baud.currentText().strip())
            except ValueError:
                baud = 0
            v.update(host=port, port=0)
            v["options"] = {"baud": baud, "bytesize": self.bits.currentData(), "parity": self.parity.currentData(),
                            "stopbits": self.stop.currentData(), "flow": self.flow.currentData()}
        return v

    def _serial_port(self):
        """The port chosen from the list (its description is shown, its name is kept) or typed in by hand."""
        text = self.serial_port.currentText().strip()
        i = self.serial_port.findText(text)
        if i >= 0 and self.serial_port.itemData(i):
            return self.serial_port.itemData(i)
        return text.split()[0] if text.upper().startswith("COM") and " " in text else text

    def typed_password(self):
        return self.password.text()

    def wants_save(self):
        return self.action == "save" or self.save_box.isChecked()

    def _done(self, action):
        v = self.values()
        if self.org_pick.currentData() is None and (action == "save" or self.save_box.isChecked()):
            QMessageBox.warning(self, "Organization", "Choose the organization this session belongs to.")
            return
        check = {**v, "name": v["name"] or v["host"] or "session"}
        try:
            if action == "save" or self.save_box.isChecked():
                sessions.validate(v)
            else:
                sessions.validate(check)
        except ValueError as e:
            QMessageBox.warning(self, "Session", str(e))
            return
        self.action = action
        self.accept()


# =============================================================================== one open terminal
class SessionPane(QWidget):
    state_changed = Signal(object)
    logs_changed = Signal()

    def __init__(self, spec):
        super().__init__()
        self.spec = spec
        self.session = self.log = None
        self.up = False                                   # true from the moment we start connecting until the session reports it ended
        self._override = None
        self._used = False
        self.owner = None                                 # the SessionsTab, which routes typing while Type in all sessions is on
        self.term = TerminalView()
        self.apply_settings()
        self.status = QLabel("Not connected.")
        self.reconnect_btn, self.disconnect_btn = QPushButton("Reconnect"), QPushButton("Disconnect")
        self.break_btn = QPushButton("Send break")
        self.break_btn.setToolTip("Sends a serial break, which routers read as 'interrupt the boot' (ROMMON)")
        self.break_btn.setVisible(spec["kind"] == "serial")
        self.leave_out = QCheckBox("Leave out")                # shown only while Type in all sessions is on
        self.leave_out.setToolTip("Keep this session out of Type in all sessions: what you type here stays here, "
                                  "and nothing typed elsewhere is sent here.")
        self.leave_out.setVisible(False)
        self.pop_btn = QPushButton("Pop out")
        self.pop_btn.setToolTip("Move this session into its own window, which can be moved, resized or made full screen.")
        self.files_btn = QPushButton("Files")                  # SSH only: the Files panel under the terminal
        self.files_btn.setCheckable(True)
        self.files_btn.setToolTip("Browse this computer and the device side by side, and move files between them (SFTP on this session).")
        self.files_btn.setVisible(spec["kind"] == "ssh")
        self.browser = None
        for b in (self.reconnect_btn, self.disconnect_btn, self.break_btn, self.pop_btn, self.files_btn):
            b.setAutoDefault(False)
        bar = QHBoxLayout()
        bar.addWidget(self.status, 1)
        for b in (self.leave_out, self.break_btn, self.files_btn, self.reconnect_btn, self.disconnect_btn, self.pop_btn):
            bar.addWidget(b)
        self.bar = bar
        self.vsplit = QSplitter(Qt.Orientation.Vertical)      # the terminal, and under it the Files panel when it is open
        self.vsplit.addWidget(self.term)
        self.vsplit.setChildrenCollapsible(False)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 6, 0, 0)
        lay.addLayout(bar)
        lay.addWidget(self.vsplit, 1)
        self.term.data_out.connect(self._to_session)
        self.term.resized.connect(self._resize_session)
        self.reconnect_btn.clicked.connect(self.connect_now)
        self.disconnect_btn.clicked.connect(self.disconnect_now)
        self.break_btn.clicked.connect(lambda: self.session and hasattr(self.session, "send_break") and self.session.send_break())
        self.pop_btn.clicked.connect(lambda: self.owner and self.owner.pop_out(self))
        self.files_btn.toggled.connect(self._files_toggled)
        self._set_connected(False)

    def _files_toggled(self, on):
        """Files: the two-sided file browser under the terminal, made on first use and kept (hidden) after."""
        if on and self.browser is None:
            from ui.filebrowser import FileBrowser
            self.browser = FileBrowser(self)
            self.vsplit.addWidget(self.browser)
            self.vsplit.setStretchFactor(0, 3)
            self.vsplit.setStretchFactor(1, 2)
            total = max(self.vsplit.height(), 400)
            self.vsplit.setSizes([int(total * 0.55), int(total * 0.45)])     # the lists need room: a bit under half to begin with
            self.browser.session_changed()
        if self.browser is not None:
            self.browser.setVisible(on)

    @property
    def kind(self):
        return self.spec["kind"]

    def takes_part(self):
        """Does typing in other sessions reach this one while Type in all sessions is on? Only a connected terminal that is not left out."""
        return self.connected() and not self.leave_out.isChecked()

    def send_raw(self, data):
        """Bytes straight to the device (what Type in all sessions sends from another pane)."""
        if self.connected():
            self.session.send(data)

    def apply_settings(self):
        """Pick up font, colours and scrollback from Settings > Terminal."""
        self.term.configure(db.get_setting("term_font"), int(db.get_setting("term_font_size")),
                            db.get_setting("term_scheme"), int(db.get_setting("term_scrollback")))

    def connected(self):
        return self.up

    def _set_connected(self, on):
        self.up = on
        self.reconnect_btn.setEnabled(not on)
        self.disconnect_btn.setEnabled(on)
        self.break_btn.setEnabled(on)
        if self.browser is not None:
            self.browser.session_changed()
        self.state_changed.emit(self)

    def _say(self, text):
        self.term.feed(text.replace("\n", "\r\n").encode())

    def _to_session(self, data):
        if self.owner is not None and self.owner.typing_everywhere() and self.takes_part():
            self.owner.send_everywhere(data)              # to every session that takes part, this one included
        elif self.connected():
            self.session.send(data)

    def _resize_session(self, cols, rows):
        if self.connected():
            self.session.resize(cols, rows)
        elif not self._used:
            self._intro()

    def _intro(self):
        self.term.reset()
        self._say(f"{self.spec['name']}  -  {KIND_TEXT[self.kind]}\nPress Reconnect to connect.\n")

    # ---- connecting
    def _password(self):
        sp = self.spec
        pw = sp.get("password") or ""
        dev = sp.get("dev")
        if not pw and dev and vendors.uses_ssh_login(dev["vendor"]):
            pw = profiles.secret(dev) or ""
        if pw:
            return pw
        text, ok = QInputDialog.getText(self, "Password", f"Password for {sp['username']}@{sp['host']}:", QLineEdit.EchoMode.Password)
        return text if ok else None

    def connect_now(self):
        if self.connected():
            return
        sp, kind = self.spec, self.spec["kind"]
        dev = sp.get("dev")
        password = ""
        if kind == "ssh":
            if not sp.get("username"):                         # imported or saved without one: ask, as for the password
                user, ok = QInputDialog.getText(self, "User name", f"User name for {sp['host']}:")
                if not ok or not user.strip():
                    return
                sp["username"] = user.strip()
            password = self._password()
            if password is None:
                self.status.setText("Not connected: no password was entered.")
                return
        opts = sp.get("options") or {}
        try:
            log = sessionlog.SessionLog(sp["name"], sp["host"], sp["port"], sp.get("username") or "", kind)
        except OSError as e:
            self._say(f"\nNot connecting: the session log could not be created ({e}).\n")
            return
        timeout = int(db.get_setting("ssh_timeout"))
        self._used = True
        self.term.reset()
        if kind == "ssh":
            paging = (vendors.paging_command(dev["vendor"], db.get_setting("paging_cmd")) if dev
                      else db.get_setting("paging_cmd")) if opts.get("paging", True) else ""
            session = nettools.SshSession(sp["host"], sp["port"], sp["username"], password, paging, self.term.cols, self.term.rows,
                                          hostkey_mode=db.get_setting("hostkey_mode"), timeout=timeout,
                                          jump_dev=profiles.resolve(dev) if dev else None)
            self._say(f"Connecting to {sp['host']}:{sp['port']} as {sp['username']}...\n")
        elif kind == "telnet":
            session = TelnetSession(sp["host"], sp["port"], self.term.cols, self.term.rows, timeout, profiles.resolve(dev) if dev else None)
            self._say(f"Connecting to {sp['host']}:{sp['port']} (Telnet is not encrypted)...\n")
        else:
            session = serialconn.SerialSession(sp["host"], opts.get("baud", 9600), opts.get("bytesize", 8), opts.get("parity", "N"),
                                               opts.get("stopbits", 1), opts.get("flow", "none"))
            self._say(f"Opening {sp['host']} at {opts.get('baud', 9600)} baud...\n")
        self.session, self.log, self._override = session, log, None
        self.up = True
        session.data.connect(lambda b, s=session, lg=log: self._on_data(b, s, lg))     # bound to this session: a late
        session.closed.connect(lambda r, s=session, lg=log: self._ended(s, lg, r))     # signal from an old one is ignored
        session.start()
        self._set_connected(True)
        self.status.setText(f"Connecting to {sp['host']}  -  logging to {log.path.name}")
        self.logs_changed.emit()
        audit.log("session opened", f"{kind} {sp['name']} ({sp['host']})")
        self.term.setFocus()

    def disconnect_now(self):
        if self.connected():
            self.disconnect_btn.setEnabled(False)
            self.status.setText("Disconnecting...")
            self.session.stop()

    def _on_data(self, data, session, log):
        if not log.write(data) and session is self.session and not self._override:
            self._override = "Disconnected: the session log could not be written."
            self._say("\n[Logging failed, so the session is being closed.]\n")
            session.stop()
        if session is self.session:
            self.term.feed(data)
            if self.status.text().startswith("Connecting"):
                self.status.setText(f"Connected to {self.spec['host']}  -  logging to {log.path.name}")

    def _ended(self, session, log, reason):
        if session is self.session and self._override:
            reason = self._override
        log.close(reason)
        if session is self.session:
            self._say(f"\n[{reason}]\n")
            self._set_connected(False)
            self.status.setText(f"Not connected.  Last session logged to {log.path.name}")
        self.logs_changed.emit()

    def shutdown(self):
        if self.browser is not None:
            self.browser.shutdown()
        if self.session is not None and self.session.isRunning():
            self.session.stop()
            self.session.wait(3000)
        if self.log and not self.log.closed:                  # the closed signal may never be delivered
            self.log.close("Application closed.")


# =============================================================================== the Sessions section
class SessionTree(QTreeWidget):
    """The saved sessions. Dropping on a folder moves what was dragged into it; dropping on empty space, to the top level."""
    moved = Signal(list, object)           # [("session"|"folder", id), ...], target folder id (None = top level)

    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def mousePressEvent(self, e):
        if not self.indexAt(e.position().toPoint()).isValid():           # a click on empty space deselects
            self.clearSelection()
            self.setCurrentItem(None)
        super().mousePressEvent(e)

    def dropEvent(self, e):
        target = self.itemAt(e.position().toPoint())
        tid, where = None, db.target()
        if target is not None:
            kind, ident = self.owner.kind_of(target)
            where = self.owner.org_of(target)
            tid = ident if kind == "folder" else (None if kind == "org" else self.owner.payload[target.data(0, ROLE)].get("folder_id"))
        items = [i for i in self.selectedItems() if self.owner.kind_of(i)[0] in ("session", "folder")]
        e.setDropAction(Qt.DropAction.IgnoreAction)                       # we move the data and rebuild; Qt must not move items
        e.accept()
        if any(self.owner.org_of(i) != where for i in items) or not self.owner.editable(where):
            return                                                        # sessions stay in their own organization
        moves = [self.owner.kind_of(i) for i in items]
        if moves:
            self.moved.emit(moves, (where, tid))


TERMINAL_KINDS = ("ssh", "telnet", "serial")       # panes with a terminal: Type in all sessions reaches these, never Remote Desktop


def grid_shape(n):
    """(rows, columns) that share the screen as equally as possible: 1 = full, 2 = side by side, 3-4 = 2x2, 5-6 = 2x3, 7-9 = 3x3..."""
    if n <= 1:
        return (1, 1)
    cols = math.ceil(math.sqrt(n))
    return (math.ceil(n / cols), cols)


class GridCell(QWidget):
    """One session in Split view: a header line with the connection dot, the session's name and a Close button, then the pane."""

    def __init__(self, pane, owner):
        super().__init__()
        self.pane = pane
        self.title = QLabel()
        self.title.setStyleSheet("font-weight: 600;")
        self.close_btn = QPushButton("Close")
        self.close_btn.setAutoDefault(False)
        self.close_btn.setToolTip("Close this session (asks first while it is connected)")
        self.close_btn.clicked.connect(lambda: owner.close_pane(pane))
        head = QHBoxLayout()
        head.setContentsMargins(4, 0, 4, 0)
        head.addWidget(self.title, 1)
        head.addWidget(self.close_btn)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addLayout(head)
        lay.addWidget(pane, 1)
        pane.show()                                       # (a page taken out of the tabs is left hidden)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet("GridCell { border: 1px solid palette(mid); }")
        self.retitle()

    def retitle(self):
        self.title.setText(("● " if self.pane.connected() else "") + self.pane.spec["name"])

    def release(self):
        """Take the pane out, so it can go back to a tab; the cell is then thrown away."""
        self.layout().removeWidget(self.pane)
        self.pane.setParent(None)
        self.hide()
        self.deleteLater()
        return self.pane


class PoppedWindow(QWidget):
    """A session in its own top-level window: it can be moved, resized or made full screen, and put back in a tab."""

    def __init__(self, pane, owner):
        super().__init__(None, Qt.WindowType.Window)
        self.pane, self.owner = pane, owner
        self._closing_quietly = False
        self.setWindowTitle(f"{pane.spec['name']} - Toner")
        self.back_btn = QPushButton("Put back in a tab")
        self.back_btn.setToolTip("Return this session to the Sessions tabs")
        self.full_btn = QPushButton("Full screen")
        self.full_btn.setCheckable(True)
        self.full_btn.setToolTip("Fill the screen   (F11)")
        for b in (self.back_btn, self.full_btn):
            b.setAutoDefault(False)
        bar = QHBoxLayout()
        bar.addStretch(1)
        bar.addWidget(self.full_btn)
        bar.addWidget(self.back_btn)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 4, 8, 8)
        lay.addLayout(bar)
        lay.addWidget(pane, 1)
        pane.show()
        if hasattr(pane, "pop_btn"):
            pane.pop_btn.setVisible(False)                # (it is already out)
        self.back_btn.clicked.connect(lambda: owner.put_back(pane))
        self.full_btn.toggled.connect(self.set_full)
        QShortcut(QKeySequence("F11"), self, activated=lambda: self.full_btn.setChecked(not self.full_btn.isChecked()))
        self.resize(900, 560)

    def set_full(self, on):
        self.showFullScreen() if on else self.showNormal()
        self.full_btn.setText("Leave full screen" if on else "Full screen")

    def release(self):
        """Take the pane out and close the window without a question (the pane is going back to a tab)."""
        self.layout().removeWidget(self.pane)
        self.pane.setParent(None)
        if hasattr(self.pane, "pop_btn"):
            self.pane.pop_btn.setVisible(True)
        self._closing_quietly = True
        self.close()
        self.deleteLater()
        return self.pane

    def closeEvent(self, e):
        if self._closing_quietly:
            return super().closeEvent(e)
        e.ignore()                                        # closing the window ends the session, with the same question as closing a tab
        QTimer.singleShot(0, lambda: self.owner.close_pane(self.pane) if self.pane in self.owner.popped else None)


class SessionsTab(QWidget):
    logs_changed = Signal()

    def __init__(self):
        super().__init__()
        self.logs_dialog = None
        self.popped = {}                                           # pane -> its PoppedWindow
        self.cells = {}                                            # pane -> its GridCell, while Split view is on
        self.grid_order = []                                       # the panes in the grid, in tab order
        self._wired = set()                                        # panes whose signals are connected here (once each)
        from ui.finder import FilterButton, SearchBox
        self.search = SearchBox("Search sessions", "Type part of a name, address, folder or type. Several words must all match.", page=self)
        self.search.setMaximumWidth(16777215)                     # the box fills the column above the list
        self.funnel = FilterButton(self._sections, tip="Filter by type or device")
        self.funnel.changed.connect(self.refresh)
        self.payload = {}                                  # item key -> session / folder
        self._building = False
        self.expanded = set(db.get_setting("sessions_expanded"))
        self.tree = SessionTree(self)
        self.tree.setHeaderLabels(["Name", "Type", "Host"])
        self.tree.setRootIsDecorated(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.tree.setDragEnabled(True)
        self.tree.setAcceptDrops(True)
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.tree.header().setStretchLastSection(True)                  # the host column takes what is left
        self.tree.setTextElideMode(Qt.TextElideMode.ElideRight)
        from ui.widgets import EmptyHint
        self.tree_hint = EmptyHint(self.tree, "No saved sessions", "A saved session reopens with one double-click", wrap=True,
                                   actions=[("New SSH session", lambda: self.new_session("ssh"))])
        self.new_btn = QToolButton()
        self.new_btn.setText("New session")
        self.new_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.new_btn.setProperty("primary", True)
        self.new_menu = QMenu(self.new_btn)
        for k, label, _, _ in sessions.KINDS:
            self.new_menu.addAction(label, lambda k=k: self.new_session(k))
        self.new_btn.setMenu(self.new_menu)
        self.folder_btn = QPushButton("New folder")
        self.connect_btn, self.edit_btn = QPushButton("Connect"), QPushButton("Edit")
        self.copy_btn, self.delete_btn, self.logs_btn = QPushButton("Duplicate"), QPushButton("Delete"), QPushButton("Session logs")
        self.expand_btn, self.collapse_btn = QPushButton("Expand all"), QPushButton("Collapse all")
        self.note = _muted("")

        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True)
        self.welcome = QWidget()                                          # nothing open: say so, and offer the usual first steps
        wl = QVBoxLayout(self.welcome)
        wl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        head = QLabel("No session is open")
        head.setAlignment(Qt.AlignmentFlag.AlignCenter)
        head.setStyleSheet("font-size: 13pt; font-weight: 600;")
        sub = QLabel("Double-click a saved session on the left, or start a new one.")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setProperty("muted", True)
        sub.setWordWrap(True)
        wl.addWidget(head)
        wl.addWidget(sub)
        wl.addSpacing(8)
        starts = QHBoxLayout()
        starts.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.welcome_buttons = {}
        for kind, text in (("ssh", "New SSH session"), ("rdp", "New Remote Desktop"), ("serial", "New serial console")):
            b = QPushButton(text)
            b.setProperty("primary", kind == "ssh")
            b.setAutoDefault(False)
            b.clicked.connect(lambda _=False, k=kind: self.new_session(k))
            starts.addWidget(b)
            self.welcome_buttons[kind] = b
        wl.addLayout(starts)
        self.grid = QWidget()                                             # Split view: every open session at once
        self.grid_lay = QGridLayout(self.grid)
        self.grid_lay.setContentsMargins(0, 0, 0, 0)
        self.grid_lay.setSpacing(4)
        self.stack = QStackedWidget()
        self.stack.addWidget(self.welcome)
        self.stack.addWidget(self.tabs)
        self.stack.addWidget(self.grid)
        self.tabs.tabBar().setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tabs.tabBar().customContextMenuRequested.connect(self._tab_menu)
        # the bar above the sessions: hide the list, Split view, Type in all sessions
        self.list_btn = QPushButton()
        self.list_btn.setProperty("ghost", True)
        self.list_btn.setFixedWidth(36)
        self.list_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.split_btn = QPushButton("Split view")
        self.split_btn.setCheckable(True)
        self.split_btn.setToolTip("Show every open session at once, in an equal grid, instead of in tabs.")
        self.multi_btn = QPushButton("Type in all sessions")
        self.multi_btn.setCheckable(True)
        self.multi_btn.setToolTip("What you type in one connected session is sent to every connected session. "
                                  "Tick Leave out on a session to keep it out.")
        for b in (self.list_btn, self.split_btn, self.multi_btn):
            b.setAutoDefault(False)
        self.multi_banner = QLabel("Type in all sessions is on: keys and pastes go to every connected session except those marked Leave out.")
        self.multi_banner.setWordWrap(True)
        self.multi_banner.setVisible(False)
        self.multi_banner.setStyleSheet("QLabel { background: #b8860b; color: #ffffff; padding: 4px 8px; border-radius: 4px; }")
        bar = QHBoxLayout()
        bar.setContentsMargins(0, 0, 0, 0)
        bar.addWidget(self.list_btn)
        bar.addStretch(1)
        bar.addWidget(self.split_btn)
        bar.addWidget(self.multi_btn)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.addLayout(bar)
        rl.addWidget(self.multi_banner)
        rl.addWidget(self.stack, 1)

        left = self.left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 8, 0)
        finder = QHBoxLayout()
        finder.addWidget(self.search, 1)
        finder.addWidget(self.funnel)
        ll.addLayout(finder)
        ll.addWidget(self.tree, 1)
        self.more_btn = QPushButton("More")                         # the occasional buttons live in a menu, so the row stays one line
        self.more_menu = QMenu(self.more_btn)
        self.more_menu.aboutToShow.connect(self._fill_more)
        self.more_btn.setMenu(self.more_menu)
        ll.addLayout(flow(self.new_btn, self.connect_btn, self.edit_btn, self.more_btn))      # Delete: the More menu, the Delete key or a right-click
        ll.addWidget(self.note)
        split = QSplitter()
        split.addWidget(left)
        split.addWidget(right)
        split.setStretchFactor(1, 1)
        split.setSizes([360, 700])
        remember_sizes(split, "sessions")
        split.setChildrenCollapsible(False)
        left.setMinimumWidth(240)
        lay = QVBoxLayout(self)
        lay.addWidget(split, 1)
        self.list_btn.clicked.connect(lambda: self.show_list(not self.left.isVisibleTo(self)))
        self.split_btn.toggled.connect(self._split_toggled)
        self.multi_btn.toggled.connect(self._multi_toggled)
        self.show_list(not db.get_setting("sessions_list_hidden"), remember=False)
        self._show_what_is_open()

        self.search.textChanged.connect(self.refresh)
        self.tree.itemDoubleClicked.connect(self._double_clicked)
        self.tree.itemSelectionChanged.connect(self._buttons)
        self.tree.itemExpanded.connect(lambda it: self.remember(it, True))
        self.tree.itemCollapsed.connect(lambda it: self.remember(it, False))
        self.tree.itemExpanded.connect(self._autosize_soon)
        self.tree.itemCollapsed.connect(self._autosize_soon)
        self.tree.moved.connect(self.handle_moves)
        self.tree.customContextMenuRequested.connect(self._menu)
        # only while the list has the focus: an open session's terminal needs Enter, Delete and F2 for the device
        here = Qt.ShortcutContext.WidgetWithChildrenShortcut
        QShortcut(QKeySequence("F2"), self.tree, activated=self.rename_folder, context=here)
        QShortcut(QKeySequence("Delete"), self.tree, activated=self.delete_selected, context=here)
        for key in ("Return", "Enter"):
            QShortcut(QKeySequence(key), self.tree, activated=self.connect_selected, context=here)
        self.folder_btn.clicked.connect(lambda: self.new_folder())
        self.expand_btn.clicked.connect(self.expand_all)
        self.collapse_btn.clicked.connect(self.collapse_all)
        self.connect_btn.clicked.connect(self.connect_selected)
        self.edit_btn.clicked.connect(self.edit_selected)
        self.copy_btn.clicked.connect(self.duplicate_selected)
        self.delete_btn.clicked.connect(self.delete_selected)
        self.logs_btn.clicked.connect(self.open_logs)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.refresh()

    # ---------------------------------------------------------------- the saved list
    @staticmethod
    def kind_of(item):
        """('session', id), ('folder', id), ('org', organization) or ('', None). Items of another organization's file than the one
        being written to carry it in their key: 'session:3:12' (see org_of)."""
        key = item.data(0, ROLE) or ""
        kind, _, ident = key.partition(":")
        last = ident.rpartition(":")[2]
        return (kind, int(last)) if last.isdigit() else ("", None)

    @staticmethod
    def org_of(item):
        key = item.data(0, ROLE) or ""
        kind, _, ident = key.partition(":")
        if kind == "org":
            return int(ident)
        return int(ident.partition(":")[0]) if ":" in ident else db.target()

    @staticmethod
    def _key(kind, org, ident):
        return f"{kind}:{ident}" if org == db.target() else f"{kind}:{org}:{ident}"

    @staticmethod
    def _ek(org, fid):
        return fid if org == db.target() else f"{org}:{fid}"

    def _keep_open(self):
        db.set_setting("sessions_expanded", sorted(self.expanded, key=str))

    def editable(self, org):
        """Sessions of the organization being looked at can be changed here; Shared ones (from an organization) and archived ones cannot."""
        if org in db.archived_ids():
            return False
        return db.everything() or org == db.home()

    def selected_org(self):
        found = {self.org_of(i) for i in self.tree.selectedItems()}
        if len(found) > 1:
            return None
        return found.pop() if found else db.target()

    @staticmethod
    def device_of(s, by_host):
        """The inventory device a session belongs to: the one it is linked to, else the one at its address."""
        return s.get("device") or by_host.get((s.get("host") or "").lower(), "")

    def _sections(self):
        from ui.finder import Section
        all_sessions = sessions.list_sessions()
        by_host = {d["host"].lower(): d["name"] for d in db.list_devices() if d.get("host")}
        kinds = {s["kind"] for s in all_sessions}
        from ui.finder import org_section
        devs = sorted({self.device_of(s, by_host) for s in all_sessions} - {""}, key=str.lower)
        return org_section() + [x for x in (Section("type", "Type", [(KIND_TEXT.get(k, k), k) for k, *_ in sessions.KINDS if k in kinds]),
                                            Section("device", "Device", [(d, d) for d in devs])) if x.options]

    def refresh(self, *_):
        want = bool(self.search.words()) or self.funnel.active()
        kinds, devices, picked = self.funnel.selected("type"), self.funnel.selected("device"), self.funnel.selected("org")
        by_host = {d["host"].lower(): d["name"] for d in db.list_devices() if d.get("host")} if devices else {}
        keep = [(self.kind_of(i), self.org_of(i)) for i in self.tree.selectedItems()]
        me = db.target()
        all_sessions = sessions.list_sessions()
        self._building = True
        self.tree.blockSignals(True)
        self.tree.clear()
        self.payload = {}
        bold = QFont()
        bold.setBold(True)
        shown = [0]

        def chosen(s, paths):
            if picked and s["org"] not in picked:
                return False
            if kinds and s["kind"] not in kinds or devices and self.device_of(s, by_host) not in devices:
                return False
            return self.search.matches(s["name"], s["host"], paths.get(s["folder_id"], ""), KIND_TEXT.get(s["kind"], ""),
                                       db.org_name(s["org"]) if db.several() else "")

        def branch(title, key, org, tip=""):
            node = QTreeWidgetItem([title, "", ""])
            node.setData(0, ROLE, key)
            self.payload[key] = {"org": org}
            node.setFont(0, bold)
            node.setIcon(0, self._folder_icon())
            node.setToolTip(0, tip)
            node.setFlags((node.flags() | Qt.ItemFlag.ItemIsDropEnabled) & ~Qt.ItemFlag.ItemIsDragEnabled)
            self.tree.addTopLevelItem(node)
            return node

        if db.several():                                   # Global: a branch per organization
            from core import orgs
            files = [db.GLOBAL] + [o["id"] for o in orgs.list_orgs(archived=False)]
            for org in files:
                if picked and org not in picked:
                    continue
                with db.within(org):
                    folders, paths = sessions.list_folders(), sessions.folder_paths()
                mine = [x for x in all_sessions if x["org"] == org and chosen(x, paths)]
                if want and not mine:
                    continue
                node = branch(f"{db.org_name(org)}  ({len(mine)})", f"org:{org}", org)
                self._fill_tree(node, folders, mine, org, want, bold, shown)
                node.setExpanded(f"org:{org}" in self.expanded or bool(want))
        else:
            paths = sessions.folder_paths()
            own = [x for x in all_sessions if x["org"] == me and chosen(x, paths)]
            self._fill_tree(None, sessions.list_folders(), own, me, want, bold, shown)
            with db.within(db.GLOBAL):
                gpaths = sessions.folder_paths()
            shared = [x for x in all_sessions if x["org"] != me and chosen(x, gpaths)]
            if shared:
                node = branch(f"Shared  ({len(shared)})", f"org:{db.GLOBAL}", db.GLOBAL, "Sessions Global shares with every organization. They are changed from Global.")
                for x in sorted(shared, key=lambda x: x["name"].lower()):
                    node.addChild(self._session_item(x, db.GLOBAL))
                    shown[0] += 1
                node.setExpanded(f"org:{db.GLOBAL}" in self.expanded or bool(want))
        for it in self._all_items():
            if (self.kind_of(it), self.org_of(it)) in keep:
                it.setSelected(True)
        self._building = False
        self.tree.blockSignals(False)
        for i in range(2):
            self.tree.resizeColumnToContents(i)
        total = len(all_sessions)
        self.note.setText((f"{shown[0]} of {total} session(s)" if shown[0] else "No session matches.") if want else "")      # the header already says how many are saved
        self.tree_hint.setVisible(total == 0)
        self._buttons()

    def _session_item(self, s, org):
        host = s["host"] if s["kind"] not in ("rdp", "vnc") or s["port"] == sessions.DEFAULT_PORT[s["kind"]] else f"{s['host']}:{s['port']}"
        item = QTreeWidgetItem([s["name"], KIND_TEXT.get(s["kind"], s["kind"]), host])
        key = self._key("session", org, s["id"])
        item.setData(0, ROLE, key)
        self.payload[key] = s
        item.setFlags((item.flags() | Qt.ItemFlag.ItemIsDragEnabled) & ~Qt.ItemFlag.ItemIsDropEnabled)
        return item

    def _fill_tree(self, top, folders, found, org, want, bold, shown):
        """One organization's session folders and sessions, under `top` (None: at the top of the list)."""
        known = {f["id"] for f in folders}
        kids, by_folder = {}, {}
        for f in folders:
            kids.setdefault(f["parent_id"] if f["parent_id"] in known else None, []).append(f)
        for x in found:
            by_folder.setdefault(x["folder_id"] if x["folder_id"] in known else None, []).append(x)

        def count(fid):
            return len(by_folder.get(fid, [])) + sum(count(c["id"]) for c in kids.get(fid, []))

        def fill(parent_item, fid):
            def add(item):
                (parent_item.addChild if parent_item else self.tree.addTopLevelItem)(item)
            for f in sorted(kids.get(fid, []), key=lambda f: f["name"].lower()):
                if want and not count(f["id"]):
                    continue                                   # while searching, hide folders with nothing to show
                item = QTreeWidgetItem([f"{f['name']}  ({count(f['id'])})", "", ""])
                key = self._key("folder", org, f["id"])
                item.setData(0, ROLE, key)
                self.payload[key] = {**f, "org": org}
                item.setFont(0, bold)
                item.setIcon(0, self._folder_icon())
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsDragEnabled | Qt.ItemFlag.ItemIsDropEnabled)
                add(item)
                fill(item, f["id"])
                item.setExpanded(self._ek(org, f["id"]) in self.expanded or bool(want))
            for x in sorted(by_folder.get(fid, []), key=lambda x: x["name"].lower()):
                add(self._session_item(x, org))
                shown[0] += 1

        fill(top, None)

    def _folder_icon(self):
        from ui import icons, theme
        t = theme.current()
        return icons.icon("folder", t["accent"]) if t else QIcon()

    def _all_items(self):
        out, todo = [], [self.tree.topLevelItem(i) for i in range(self.tree.topLevelItemCount())]
        while todo:
            it = todo.pop()
            out.append(it)
            todo.extend(it.child(i) for i in range(it.childCount()))
        return out

    def remember(self, item, open_):
        """Keep which folders are open, across restarts."""
        if self._building:
            return
        kind, ident = self.kind_of(item)
        if kind in ("folder", "org"):
            key = self._ek(self.org_of(item), ident) if kind == "folder" else f"org:{ident}"
            (self.expanded.add if open_ else self.expanded.discard)(key)
            self._keep_open()

    def _autosize(self):
        """Keep names readable as folders open and close. Done after the tree has finished changing, not during."""
        self._sizing = False
        for i in range(2):
            self.tree.resizeColumnToContents(i)

    def _autosize_soon(self, *_):
        if not self._building and not getattr(self, '_sizing', False):
            self._sizing = True
            QTimer.singleShot(0, self._autosize)

    def expand_all(self):
        self.tree.expandAll()

    def collapse_all(self):
        self.tree.collapseAll()

    def selected_sessions(self):
        return [self.payload[i.data(0, ROLE)] for i in self.tree.selectedItems() if self.kind_of(i)[0] == "session" and i.data(0, ROLE) in self.payload]

    def selected_folders(self):
        return [self.kind_of(i)[1] for i in self.tree.selectedItems() if self.kind_of(i)[0] == "folder"]

    def selected_id(self):
        """The id of the one session that is selected, or None (its organization: selected_org)."""
        s = self.selected_sessions()
        return s[0]["id"] if len(s) == 1 and not self.selected_folders() else None

    def current_folder(self):
        """Where something new should go: the selected folder, or the folder of the selected session."""
        folders, found = self.selected_folders(), self.selected_sessions()
        if len(folders) == 1 and not found:
            return folders[0]
        if len(found) == 1 and not folders:
            return found[0].get("folder_id")
        return None

    def _fill_more(self):
        """The rarely used actions, each acting through its button (so they follow the same enabled state)."""
        self.more_menu.clear()
        for b in (self.folder_btn, self.copy_btn, self.delete_btn, self.expand_btn, self.collapse_btn, self.logs_btn):
            act = self.more_menu.addAction(b.text())
            act.setEnabled(b.isEnabled())
            act.triggered.connect(lambda _=False, b=b: b.click())

    def _buttons(self):
        one = self.selected_id() is not None
        folders, found = self.selected_folders(), self.selected_sessions()
        org = self.selected_org()
        can = org is not None and self.editable(org)
        self.connect_btn.setEnabled(one)
        self.copy_btn.setEnabled(one and can)
        self.edit_btn.setEnabled(can and (one or (len(folders) == 1 and not found)))
        self.edit_btn.setText("Rename" if len(folders) == 1 and not found else "Edit")
        self.delete_btn.setEnabled(can and bool(found or folders))
        self.folder_btn.setEnabled(can)

    def _double_clicked(self, item, *_):
        if self.kind_of(item)[0] == "session":
            self.connect_selected()

    def _menu(self, pos):
        item = self.tree.itemAt(pos)
        if item is not None and not item.isSelected():
            self.tree.clearSelection()
            item.setSelected(True)
        found, folders = self.selected_sessions(), self.selected_folders()
        org = self.selected_org()
        can = org is not None and self.editable(org)
        m = QMenu(self)
        if found or folders:
            if len(found) == 1 and not folders:
                m.addAction("Connect", self.connect_selected)
                if can:
                    m.addAction("Edit...", self.edit_selected)
                    m.addAction("Duplicate", self.duplicate_selected)
            if len(folders) == 1 and not found and can:
                add = m.addMenu("New session here")
                for k, label, _, _ in sessions.KINDS:
                    add.addAction(label, lambda k=k: self.new_session(k))
                m.addAction("New subfolder...", lambda: self.new_folder(folders[0]))
                m.addAction("Rename...", self.rename_folder)
            if can:
                move = m.addMenu("Move to folder")
                with db.within(org):
                    banned = set().union(*(sessions.folder_descendants(f) for f in folders)) if folders else set()
                    paths = sessions.folder_paths()
                move.addAction("(top level)", lambda: self.move_selected_to(None))
                for fid, path in sorted(paths.items(), key=lambda kv: kv[1].lower()):
                    if fid not in banned:
                        move.addAction(path, lambda fid=fid: self.move_selected_to(fid))
                m.addSeparator()
                m.addAction("Delete folder..." if folders and not found else "Delete...", self.delete_selected)
        else:
            m.addAction("New folder...", lambda: self.new_folder(None, use_selection=False))
            add = m.addMenu("New session")
            for k, label, _, _ in sessions.KINDS:
                add.addAction(label, lambda k=k: self.new_session(k))
        m.addSeparator()
        m.addAction("Expand all", self.expand_all)
        m.addAction("Collapse all", self.collapse_all)
        m.exec(self.tree.viewport().mapToGlobal(pos) if isinstance(pos, QPoint) else self.cursor().pos())

    # ---------------------------------------------------------------- folders
    def _ask_name(self, title, label, text=""):
        name, ok = QInputDialog.getText(self, title, label, text=text)
        return name.strip() if ok else None

    def new_folder(self, parent_id=None, use_selection=True):
        parent = self.current_folder() if use_selection and parent_id is None else parent_id
        org = self.selected_org() if self.tree.selectedItems() and use_selection or parent_id is not None else db.target()
        if org is None or not self.editable(org):
            return None
        name = self._ask_name("New folder", "Folder name:")
        if not name:
            return None
        try:
            with db.within(org):
                fid = sessions.create_folder(name, parent)
        except ValueError as e:
            QMessageBox.warning(self, "New folder", str(e))
            return None
        self.expanded.update({self._ek(org, fid)} | ({self._ek(org, parent)} if parent else set()) | ({f"org:{org}"} if db.several() else set()))
        self._keep_open()
        with db.within(org):
            audit.log("session folder created", sessions.folder_paths().get(fid, name))
        self.refresh()
        return fid

    def rename_folder(self):
        folders = self.selected_folders()
        if len(folders) != 1 or self.selected_sessions():
            return
        org = self.selected_org()
        if org is None or not self.editable(org):
            return
        name = self._ask_name("Rename folder", "New name:", self.payload[self._key("folder", org, folders[0])]["name"])
        if not name:
            return
        try:
            with db.within(org):
                sessions.rename_folder(folders[0], name)
        except ValueError as e:
            QMessageBox.warning(self, "Rename folder", str(e))
            return
        self.refresh()

    def delete_folder(self):
        folders = self.selected_folders()
        if len(folders) != 1:
            return
        fid, org = folders[0], self.selected_org()
        if org is None or not self.editable(org):
            return
        f = self.payload[self._key("folder", org, fid)]
        with db.within(org):
            kids = sum(1 for x in sessions.list_folders() if x["parent_id"] == fid)
            inside = sum(1 for s in sessions.list_sessions() if s["folder_id"] == fid and s["org"] == org)
            where = sessions.folder_paths().get(f["parent_id"], "") or "the top level"
        if QMessageBox.question(self, "Delete folder", f"Delete the folder '{f['name']}'?\n\nIts {inside} session(s) and "
                                f"{kids} subfolder(s) move up to {where}. No session is deleted.") != QMessageBox.StandardButton.Yes:
            return
        try:
            with db.within(org):
                sessions.delete_folder(fid)
        except ValueError as e:
            QMessageBox.warning(self, "Delete folder", str(e))
            return
        with db.within(org):
            audit.log("session folder deleted", f["name"])
        self.expanded.discard(self._ek(org, fid))
        self.refresh()

    def move_selected_to(self, target_id):
        moves = [("session", s["id"]) for s in self.selected_sessions()] + [("folder", i) for i in self.selected_folders()]
        self.handle_moves(moves, target_id)

    def handle_moves(self, moves, target_id):
        """Move sessions and folders into a folder (None = top level) of their own organization, reporting anything that cannot
        move. target_id can be (organization, folder id), from a drop."""
        org, target_id = target_id if isinstance(target_id, tuple) else (self.selected_org(), target_id)
        if org is None or not self.editable(org):
            return
        problems, ids = [], []
        with db.within(org):
            for kind, ident in moves:
                if kind == "session":
                    ids.append(ident)
                else:
                    try:
                        sessions.move_folder(ident, target_id)
                    except ValueError as e:
                        problems.append(str(e))
            here = sessions._sessions_here()
            clash = {s["name"].lower() for s in here if s["folder_id"] == target_id and s["id"] not in ids}
            moving = [s for s in here if s["id"] in ids]
            ok_ids = []
            for s in moving:
                if s["name"].lower() in clash and s["folder_id"] != target_id:
                    problems.append(f"'{s['name']}' was not moved: the folder already has a session with that name.")
                else:
                    ok_ids.append(s["id"])
                    clash.add(s["name"].lower())
            sessions.move_sessions(ok_ids, target_id)
        if target_id is not None:
            self.expanded.add(self._ek(org, target_id))
            self._keep_open()
        self.refresh()
        if problems:
            QMessageBox.warning(self, "Move", "\n".join(sorted(set(problems))))

    # ---------------------------------------------------------------- creating, changing, removing
    def new_session(self, kind="ssh", prefill=None):
        from ui.orgfield import GLOBAL_ONLY_CHOICE
        org = self.selected_org() if db.several() and self.tree.selectedItems() else None
        pre = None if org is None else (GLOBAL_ONLY_CHOICE if org == db.GLOBAL else org)
        dlg = SessionDialog(prefill, kind, self, folder_id=self.current_folder() if org is None or org == db.target() or db.several() else None, org=pre)
        dlg.exec()
        if dlg.action:
            self._after_dialog(dlg)
        else:
            self.refresh()                      # a folder may have been made in the dialog

    def edit_selected(self):
        folders = self.selected_folders()
        if len(folders) == 1 and not self.selected_sessions():
            self.rename_folder()
            return
        org = self.selected_org()
        if org is None or not self.editable(org):
            return
        s = sessions.get(self.selected_id(), org)
        if s:
            dlg = SessionDialog(s, parent=self)
            dlg.exec()
            if dlg.action:
                self._after_dialog(dlg)
            else:
                self.refresh()

    def _after_dialog(self, dlg):
        v = dlg.values()
        pw = dlg.typed_password()
        saved_id = None
        org = v.get("org")
        old = dlg.session.get("org") if dlg.session.get("id") else None
        if v["kind"] == "ssh" and dlg.link_row.linked():
            v["options"]["remember"] = True                    # a linked password is always the one used
        if dlg.wants_save():
            if old is not None and org is not None and org != old:      # Global: moved to another organization's file
                pw = pw or sessions.password(dlg.session["id"], old)
                v = {**v, "id": None}
            try:
                saved_id = sessions.save(v)
            except ValueError as e:
                QMessageBox.warning(self, "Session", str(e))
                return
            if v.get("id") is None and old is not None and org != old:
                sessions.delete(dlg.session["id"], old)
            if v["kind"] == "ssh":
                if v["options"]["remember"] and pw:
                    sessions.set_password(saved_id, pw, org)
                elif not v["options"]["remember"]:
                    sessions.forget_password(saved_id, org)
                with db.within(org):
                    dlg.link_row.apply(sessions.secret_name(saved_id))
            if v["folder_id"] is not None:
                self.expanded.add(self._ek(org if org is not None else db.target(), v["folder_id"]))
                self._keep_open()
            with db.within(org):
                audit.log("session saved", f"{v['kind']} {v['name']}")
        self.refresh()
        if dlg.action == "connect":
            spec = self._spec(v, pw, saved_id)
            if saved_id:
                sessions.touch(saved_id, org)
            self.open_spec(spec)

    def duplicate_selected(self):
        new = sessions.duplicate(self.selected_id(), self.selected_org())
        if new:
            audit.log("session saved", f"copy of session {self.selected_id()}")
            self.refresh()

    def delete_selected(self):
        folders, found = self.selected_folders(), self.selected_sessions()
        if len(folders) == 1 and not found:
            self.delete_folder()
            return
        if not found or folders:
            return
        what = f"the session '{found[0]['name']}'" if len(found) == 1 else f"these {len(found)} sessions"
        if QMessageBox.question(self, "Delete session", f"Delete {what}?\n\nA saved password is removed too.") != QMessageBox.StandardButton.Yes:
            return
        if any(not self.editable(s.get("org", db.target())) for s in found):
            return
        for s in found:
            sessions.delete(s["id"], s.get("org"))
            with db.within(s.get("org")):
                audit.log("session deleted", f"{s['kind']} {s['name']}")
        self.refresh()

    # ---------------------------------------------------------------- opening
    def _spec(self, s, password="", saved_id=None):
        """Everything a pane needs to connect: the saved session plus the inventory device it points at."""
        dev = _device(s.get("device"), s.get("org"))
        kind = s["kind"]
        spec = {"name": s.get("name") or s.get("host") or "session", "kind": kind, "host": s.get("host") or (dev["host"] if dev else ""),
                "port": int(s.get("port") or (dev.get("port") if dev else 0) or sessions.DEFAULT_PORT[kind]),
                "username": s.get("username") or (profiles.username(dev) if dev else ""), "password": password,
                "dev": dev, "options": {**sessions.DEFAULTS[kind], **(s.get("options") or {})}, "saved_id": saved_id}
        if kind == "ssh" and not password and saved_id:
            spec["password"] = sessions.password(saved_id, s.get("org"))
        return spec

    def _open_rdp_tab(self, spec):
        """Remote Desktop inside Toner. Returns the pane, or None when this computer cannot host the control (the caller then uses Windows' own client)."""
        from ui.rdppane import RdpPane, RdpUnavailable
        try:
            pane = RdpPane(spec)
        except RdpUnavailable as e:
            self.note.setText(f"Remote Desktop cannot run inside Toner here ({e}). Using Windows' own client.")
            return None
        self._place(pane)
        QTimer.singleShot(0, lambda: pane.connect_now() if pane in self.panes() else None)      # once the tab has its real size
        return pane

    def open_rdp_device(self, dev):
        """Inventory > Open Remote Desktop, the device window and the command palette: a Remote Desktop tab for a Windows computer."""
        for p in self.panes():
            if p.kind == "rdp" and p.spec.get("dev") and p.spec["dev"]["name"] == dev["name"] and p.spec["dev"].get("org") == dev.get("org"):
                self.show_pane(p)
                if not p.connected():
                    p.connect_now()
                return p
        base = sessions.rdp_for_device(dev)
        spec = self._spec({"name": dev["name"], "kind": "rdp", "host": dev["host"], "port": 3389, "device": dev["name"], "org": dev.get("org"),
                           "username": base["username"], "options": {"fullscreen": True}})
        self.open_spec(spec)
        return self.current_pane()

    def open_spec(self, spec):
        if spec["kind"] == "vnc":
            from ui import rdpprompt
            if rdpprompt.start_vnc(self, {"name": spec["name"], "host": spec["host"], "port": spec["port"], "options": spec["options"]}):
                audit.log("session opened", f"vnc {spec['name']} ({spec['host']})")
                self.note.setText(f"Started VNC to {spec['host']}.")
            return
        if spec["kind"] == "rdp":
            if sessions.use_embedded(spec) and self._open_rdp_tab(spec) is not None:
                return
            from ui import rdpprompt
            path = rdpprompt.start(self, {"name": spec["name"], "host": spec["host"], "port": spec["port"],
                                          "username": spec["username"], "options": spec["options"]})
            if path is False:
                return
            audit.log("session opened", f"rdp {spec['name']} ({spec['host']})")
            self.note.setText(f"Started Remote Desktop to {spec['host']} (settings in {path.name})." if path else
                              f"Started Remote Desktop to {spec['host']}.")
            return
        pane = SessionPane(spec)
        pane.owner = self
        self._place(pane)
        # connect once the tab has its real size, or the first lines are cropped when the terminal settles
        QTimer.singleShot(0, lambda: pane.connect_now() if pane in self.panes() else None)

    def connect_selected(self):
        sid, org = self.selected_id(), self.selected_org()
        s = sessions.get(sid, org)
        if s:
            sessions.touch(sid, org)
            self.open_spec(self._spec(s, "", sid))

    def open_session(self, session_id, org=None):
        s = sessions.get(session_id, org)
        if s:
            sessions.touch(session_id, org)
            self.open_spec(self._spec(s, "", session_id))

    def open_device(self, dev):
        """An inventory device's SSH session (Inventory > Open SSH session, the device window, the command palette)."""
        for p in self.panes():
            if p.spec.get("dev") and p.spec["dev"]["name"] == dev["name"] and p.spec["dev"].get("org") == dev.get("org") and p.kind == "ssh":
                self.show_pane(p)
                if not p.connected():
                    p.connect_now()
                return p
        spec = self._spec({"name": dev["name"], "kind": "ssh", "host": dev["host"], "port": dev.get("port") or int(db.get_setting("default_ssh_port")),
                           "device": dev["name"], "org": dev.get("org"), "options": {"paging": True}})
        self.open_spec(spec)
        return self.current_pane()

    # ---------------------------------------------------------------- the open sessions: tabs, the grid and popped-out windows
    def attached(self):
        """The panes shown here, in order: the tabs, or the grid while Split view is on."""
        return list(self.grid_order) if self.split_btn.isChecked() else [self.tabs.widget(i) for i in range(self.tabs.count())]

    def panes(self):
        """Every open session: the ones shown here and the ones in their own window."""
        return self.attached() + list(self.popped)

    def current_pane(self):
        if self.split_btn.isChecked():
            return self.grid_order[-1] if self.grid_order else None
        return self.tabs.currentWidget() if self.tabs.count() else None

    def _place(self, pane):
        """A new or returning pane: into a tab, or into the grid while Split view is on."""
        if getattr(pane, "owner", None) is None and hasattr(pane, "owner"):
            pane.owner = self
        if pane not in self._wired:
            self._wired.add(pane)
            pane.state_changed.connect(self._retitle)
            pane.logs_changed.connect(self._logs_changed)
        if self.split_btn.isChecked():
            self.grid_order.append(pane)
            self._lay_grid()
        else:
            i = self.tabs.addTab(pane, pane.spec["name"])
            self.tabs.setCurrentIndex(i)
            self._retitle(pane)
        if isinstance(pane, SessionPane):
            pane.leave_out.setVisible(self.multi_btn.isChecked())
        self._show_what_is_open()

    def _take(self, pane):
        """Remove a pane from wherever it is shown (a tab, the grid or its own window) without closing it."""
        i = self.tabs.indexOf(pane)
        if i >= 0:
            self.tabs.removeTab(i)
        if pane in self.cells:
            self.cells.pop(pane).release()
            self.grid_order.remove(pane)
            self._lay_grid()
        elif pane in self.grid_order:
            self.grid_order.remove(pane)
        if pane in self.popped:
            self.popped.pop(pane).release()
        pane.setParent(None)

    def _show_what_is_open(self):
        here = self.attached()
        self.stack.setCurrentWidget(self.welcome if not here else self.grid if self.split_btn.isChecked() else self.tabs)
        for b in (self.split_btn, self.multi_btn):
            b.setEnabled(bool(self.panes()))

    def show_pane(self, pane):
        """Bring a pane to the front: its tab, or its window."""
        i = self.tabs.indexOf(pane)
        if i >= 0:
            self.tabs.setCurrentIndex(i)
        elif pane in self.popped:
            self.popped[pane].raise_()
            self.popped[pane].activateWindow()

    def _retitle(self, pane):
        i = self.tabs.indexOf(pane)
        if i >= 0:
            self.tabs.setTabText(i, ("● " if pane.connected() else "") + pane.spec["name"])
        if pane in self.cells:
            self.cells[pane].retitle()

    def _tab_menu(self, pos):
        i = self.tabs.tabBar().tabAt(pos)
        if i < 0:
            return
        pane = self.tabs.widget(i)
        m = QMenu(self)
        m.addAction("Pop out", lambda: self.pop_out(pane))
        m.addAction("Close", lambda: self.close_pane(pane))
        m.exec(self.tabs.tabBar().mapToGlobal(pos))

    def close_tab(self, i):
        self.close_pane(self.tabs.widget(i))

    def close_pane(self, pane):
        """End a session and remove it, wherever it is shown. Asks first while it is connected."""
        if pane.connected() and QMessageBox.question(self, "End session", f"'{pane.spec['name']}' is still connected. End the session?") \
                != QMessageBox.StandardButton.Yes:
            return False
        pane.shutdown()
        self._take(pane)
        self._wired.discard(pane)
        pane.deleteLater()
        self._logs_changed()
        self._show_what_is_open()
        return True

    # ---- Split view
    def _split_toggled(self, on):
        if on:
            self.grid_order = [self.tabs.widget(i) for i in range(self.tabs.count())]
            while self.tabs.count():
                self.tabs.removeTab(0)
            self._lay_grid()
        else:
            for pane in list(self.grid_order):
                self.cells.pop(pane).release()
            while self.grid_lay.count():
                self.grid_lay.takeAt(0)
            order, self.grid_order = self.grid_order, []
            for pane in order:
                self.tabs.addTab(pane, pane.spec["name"])
                self._retitle(pane)
            if order:
                self.tabs.setCurrentIndex(0)
        self._show_what_is_open()

    def _lay_grid(self):
        """Share the screen equally between the panes in the grid (see grid_shape). Called whenever the set of panes changes."""
        while self.grid_lay.count():
            self.grid_lay.takeAt(0)
        for pane in list(self.cells):
            if pane not in self.grid_order:
                self.cells.pop(pane).release()
        for pane in self.grid_order:
            if pane not in self.cells:
                self.cells[pane] = GridCell(pane, self)
        for c in range(max(1, self.grid_lay.columnCount())):
            self.grid_lay.setColumnStretch(c, 0)
        for r in range(max(1, self.grid_lay.rowCount())):
            self.grid_lay.setRowStretch(r, 0)
        rows, cols = grid_shape(len(self.grid_order))
        for n, pane in enumerate(self.grid_order):
            self.grid_lay.addWidget(self.cells[pane], n // cols, n % cols)
            self.cells[pane].show()
        for c in range(cols):
            self.grid_lay.setColumnStretch(c, 1)
        for r in range(rows):
            self.grid_lay.setRowStretch(r, 1)

    def grid_positions(self):
        """{pane: (row, column)} of the grid as laid out now (for the tests)."""
        out = {}
        for i in range(self.grid_lay.count()):
            item = self.grid_lay.itemAt(i)
            r, c, _, _ = self.grid_lay.getItemPosition(i)
            out[item.widget().pane] = (r, c)
        return out

    # ---- a session in its own window
    def pop_out(self, pane):
        if pane in self.popped or pane not in self.panes():
            return None
        self._take(pane)
        win = PoppedWindow(pane, self)
        self.popped[pane] = win
        win.show()
        self._show_what_is_open()
        return win

    def put_back(self, pane):
        if pane not in self.popped:
            return
        self._take(pane)
        self._place(pane)

    # ---- Type in all sessions
    def typing_everywhere(self):
        return self.multi_btn.isChecked()

    def _multi_toggled(self, on):
        self.multi_banner.setVisible(on)
        for p in self.panes():
            if isinstance(p, SessionPane):
                p.leave_out.setVisible(on)

    def send_everywhere(self, data):
        """What was typed in one session, to every connected terminal session that is not left out (never a Remote Desktop pane)."""
        for p in self.panes():
            if isinstance(p, SessionPane) and p.kind in TERMINAL_KINDS and p.takes_part():
                p.send_raw(data)

    # ---- the session list
    def show_list(self, on, remember=True):
        self.left.setVisible(on)
        self.list_btn.setToolTip("Hide the session list" if on else "Show the session list")
        from ui import icons, theme
        t = theme.current()
        if t:
            self.list_btn.setIcon(icons.icon("panel", t.get("icon", t["muted"]), t["text"]))
        else:
            self.list_btn.setText("List")
        if remember:
            db.set_setting("sessions_list_hidden", not on)

    def _logs_changed(self):
        self.logs_changed.emit()
        if self.logs_dialog is not None:
            self.logs_dialog.logs.refresh()

    def open_logs(self):
        from ui.tools import LogsTab
        if self.logs_dialog is None:
            d = QDialog(self)
            d.setWindowTitle("Session logs")
            d.resize(1000, 640)
            d.logs = LogsTab()
            QVBoxLayout(d).addWidget(d.logs)
            self.logs_dialog = d
        self.logs_dialog.logs.refresh()
        self.logs_dialog.show()
        self.logs_dialog.raise_()

    # ---------------------------------------------------------------- housekeeping
    def apply_settings(self):
        for p in self.panes():
            p.apply_settings()

    def count_open(self):
        return sum(1 for p in self.panes() if p.connected())

    def shutdown(self):
        for p in self.panes():
            p.shutdown()
        for win in list(self.popped.values()):                # the popped-out windows go with the application, without a question
            win._closing_quietly = True
            win.close()


    def screen_context(self):
        """What the Assistant is told about this page: the selected saved session(s), and the open session's log so far."""
        out = {"page": "Sessions", "selected_sessions": [{"name": s.get("name", ""), "type": s.get("kind", ""), "host": s.get("host", ""), "port": s.get("port", 0),
                                                           "username": s.get("username", ""), "device": s.get("device", "")} for s in self.selected_sessions()]}
        pane = self.current_pane()
        spec = getattr(pane, "spec", None) or {}
        if pane is not None:
            out["open_session"] = {"name": spec.get("name", ""), "host": spec.get("host", ""), "type": spec.get("kind", ""),
                                   "connected": bool(pane.connected()) if hasattr(pane, "connected") else None}
        path = getattr(getattr(pane, "log", None), "path", None)
        if path:
            try:
                from core import sessionlog
                with open(path, "rb") as f:
                    f.seek(0, 2)
                    size = f.tell()
                    f.seek(max(0, size - 20000))
                    out["log"] = sessionlog.clean(f.read().decode("utf-8", "replace"))
            except OSError:
                pass
        return out
