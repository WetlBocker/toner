"""Sessions: saved connections (SSH, Telnet, Remote Desktop, Serial) on the left, open terminals in tabs on the right."""
from PySide6.QtCore import QPoint, Qt, QTimer, Signal
from PySide6.QtGui import QFont, QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout,
                               QInputDialog, QLabel, QLineEdit, QMenu, QMessageBox, QPushButton, QSpinBox, QSplitter,
                               QStackedWidget, QTabWidget, QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)
from core import audit, db, nettools, profiles, serialconn, sessionlog, sessions, vendors
from core.telnet import TelnetSession
from ui.terminal import TerminalView
from ui.widgets import flow

KIND_TEXT = {k: label for k, label, _, _ in sessions.KINDS}
ROLE = Qt.ItemDataRole.UserRole


def _muted(text=""):
    lab = QLabel(text)
    lab.setProperty("muted", True)
    lab.setWordWrap(True)
    return lab


def _device(name):
    return next((d for d in db.list_devices() if d["name"] == name), None) if name else None


# =============================================================================== the new / edit dialog
class SessionDialog(QDialog):
    def __init__(self, session=None, kind="ssh", parent=None, folder_id=None):
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
        self.host, self.user, self.password = QLineEdit(), QLineEdit(), QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.host.setPlaceholderText("host name or IP address")
        self.port = QSpinBox()
        self.port.setRange(0, 65535)
        self.port.setSpecialValueText("default")
        self.remember = QCheckBox("Remember the password (kept in Windows Credential Manager)")
        self.paging = QCheckBox("Turn off paging after login")
        # remote desktop
        self.fullscreen = QCheckBox("Full screen")
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
                ("kind", "Type", self.kind, "all"), ("about", "", self.about_kind, "all"), ("name", "Name", self.name, "all"),
                ("folder", "Folder", folder_row, "all"),
                ("device", "Inventory device", self.device, ("ssh", "telnet", "rdp")),
                ("host", "Host", self.host, ("ssh", "telnet", "rdp")), ("port", "Port", self.port, ("ssh", "telnet", "rdp")),
                ("user", "User name", self.user, ("ssh", "rdp")), ("password", "Password", self.password, ("ssh",)),
                ("remember", "", self.remember, ("ssh",)), ("paging", "", self.paging, ("ssh",)),
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
        for key, (widget, kinds) in self.rows.items():
            self.form.setRowVisible(widget, kinds == "all" or k in kinds)
        info = next(t for kk, _, _, t in sessions.KINDS if kk == k)
        self.about_kind.setText(info)
        self.connect_btn.setText("Connect" if k != "rdp" else "Open Remote Desktop")
        self.note.setText({"ssh": "A password left empty is asked for when you connect, or taken from the inventory device.",
                           "telnet": "Telnet sends everything, passwords included, without encryption.",
                           "rdp": "Windows asks for the password when the connection starts; it is never stored in the file.",
                           "serial": "Enter sends a carriage return, as consoles expect. Use Send break from the session tab for ROMMON."}[k])
        self.adjustSize()

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
        try:
            fid = sessions.create_folder(name, parent)
        except ValueError as e:
            QMessageBox.warning(self, "New folder", str(e))
            return
        self._fill_folders(fid)

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
        d = _device(self.device.currentData())
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
        if s.get("id") and sessions.password(s["id"]):
            self.password.setPlaceholderText("saved; leave blank to keep")
        self.fullscreen.setChecked(bool(o.get("fullscreen")))
        self.width_.setValue(int(o.get("width", 1280)))
        self.height_.setValue(int(o.get("height", 800)))
        self.clipboard.setChecked(bool(o.get("clipboard", True)))
        self.drives.setChecked(bool(o.get("drives")))
        self.printers.setChecked(bool(o.get("printers")))
        self.admin.setChecked(bool(o.get("admin")))
        self.gateway.setText(o.get("gateway") or "")
        self.baud.setCurrentText(str(o.get("baud", 9600)))
        self.bits.setCurrentIndex(max(0, self.bits.findData(int(o.get("bytesize", 8)))))
        self.parity.setCurrentIndex(max(0, self.parity.findData(o.get("parity", "N"))))
        self.stop.setCurrentIndex(max(0, self.stop.findData(o.get("stopbits", 1))))
        self.flow.setCurrentIndex(max(0, self.flow.findData(o.get("flow", "none"))))
        self.save_box.setChecked(True)

    # ---- what it produces
    def values(self):
        k = self.current_kind()
        v = {"id": self.session.get("id"), "kind": k, "name": self.name.text().strip(),
             "folder_id": self.folder.currentData(), "device": self.device.currentData() if k in ("ssh", "telnet", "rdp") else "",
             "host": self.host.text().strip(), "port": self.port.value(), "username": self.user.text().strip() if k in ("ssh", "rdp") else "",
             "options": {}}
        if k == "ssh":
            v["options"] = {"paging": self.paging.isChecked(), "remember": self.remember.isChecked()}
        elif k == "rdp":
            v["options"] = {"fullscreen": self.fullscreen.isChecked(), "width": self.width_.value(), "height": self.height_.value(),
                            "clipboard": self.clipboard.isChecked(), "drives": self.drives.isChecked(),
                            "printers": self.printers.isChecked(), "admin": self.admin.isChecked(), "gateway": self.gateway.text().strip()}
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
        self.term = TerminalView()
        self.apply_settings()
        self.status = QLabel("Not connected.")
        self.reconnect_btn, self.disconnect_btn = QPushButton("Reconnect"), QPushButton("Disconnect")
        self.break_btn = QPushButton("Send break")
        self.break_btn.setToolTip("Sends a serial break, which routers read as 'interrupt the boot' (ROMMON)")
        self.break_btn.setVisible(spec["kind"] == "serial")
        bar = QHBoxLayout()
        bar.addWidget(self.status, 1)
        for b in (self.break_btn, self.reconnect_btn, self.disconnect_btn):
            bar.addWidget(b)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 6, 0, 0)
        lay.addLayout(bar)
        lay.addWidget(self.term, 1)
        self.term.data_out.connect(self._to_session)
        self.term.resized.connect(self._resize_session)
        self.reconnect_btn.clicked.connect(self.connect_now)
        self.disconnect_btn.clicked.connect(self.disconnect_now)
        self.break_btn.clicked.connect(lambda: self.session and hasattr(self.session, "send_break") and self.session.send_break())
        self._set_connected(False)

    @property
    def kind(self):
        return self.spec["kind"]

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
        self.state_changed.emit(self)

    def _say(self, text):
        self.term.feed(text.replace("\n", "\r\n").encode())

    def _to_session(self, data):
        if self.connected():
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
            if not sp.get("username"):
                self._say("\nThis session has no user name. Edit it and add one.\n")
                return
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
        tid = None
        if target is not None:
            kind, ident = self.owner.kind_of(target)
            tid = ident if kind == "folder" else self.owner.payload[target.data(0, ROLE)].get("folder_id")
        moves = [k for k in (self.owner.kind_of(i) for i in self.selectedItems()) if k[0] in ("session", "folder")]
        e.setDropAction(Qt.DropAction.IgnoreAction)                       # we move the data and rebuild; Qt must not move items
        e.accept()
        if moves:
            self.moved.emit(moves, tid)


class SessionsTab(QWidget):
    logs_changed = Signal()

    def __init__(self):
        super().__init__()
        self.logs_dialog = None
        self.search = QLineEdit()
        self.search.setPlaceholderText("search sessions")
        self.search.setClearButtonEnabled(True)
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
        self.welcome = QLabel("No session is open.\n\nDouble-click a saved session, or choose New session to connect to a "
                              "device by SSH, Telnet, Remote Desktop or a serial cable.")
        self.welcome.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.welcome.setWordWrap(True)
        self.welcome.setProperty("muted", True)
        self.stack = QStackedWidget()
        self.stack.addWidget(self.welcome)
        self.stack.addWidget(self.tabs)

        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 8, 0)
        ll.addWidget(self.search)
        ll.addWidget(self.tree, 1)
        self.more_btn = QPushButton("More")                         # the occasional buttons live in a menu, so the row stays one line
        self.more_menu = QMenu(self.more_btn)
        self.more_menu.aboutToShow.connect(self._fill_more)
        self.more_btn.setMenu(self.more_menu)
        ll.addLayout(flow(self.new_btn, self.connect_btn, self.edit_btn, self.delete_btn, self.more_btn))
        ll.addWidget(self.note)
        split = QSplitter()
        split.addWidget(left)
        split.addWidget(self.stack)
        split.setStretchFactor(1, 1)
        split.setSizes([360, 700])
        split.setChildrenCollapsible(False)
        left.setMinimumWidth(240)
        lay = QVBoxLayout(self)
        lay.addWidget(split, 1)

        self.search.textChanged.connect(self.refresh)
        self.tree.itemDoubleClicked.connect(self._double_clicked)
        self.tree.itemSelectionChanged.connect(self._buttons)
        self.tree.itemExpanded.connect(lambda it: self.remember(it, True))
        self.tree.itemCollapsed.connect(lambda it: self.remember(it, False))
        self.tree.itemExpanded.connect(self._autosize_soon)
        self.tree.itemCollapsed.connect(self._autosize_soon)
        self.tree.moved.connect(self.handle_moves)
        self.tree.customContextMenuRequested.connect(self._menu)
        QShortcut(QKeySequence("F2"), self.tree, activated=self.rename_folder)
        QShortcut(QKeySequence("Delete"), self.tree, activated=self.delete_selected)
        QShortcut(QKeySequence("Return"), self.tree, activated=self.connect_selected)
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
        key = item.data(0, ROLE) or ""
        kind, _, ident = key.partition(":")
        return (kind, int(ident)) if ident.isdigit() else ("", None)

    def refresh(self, *_):
        want = self.search.text().strip().lower()
        keep = [self.kind_of(i) for i in self.tree.selectedItems()]
        paths = sessions.folder_paths()
        folders, all_sessions = sessions.list_folders(), sessions.list_sessions()
        known = {f["id"] for f in folders}
        kids, by_folder = {}, {}
        for f in folders:
            kids.setdefault(f["parent_id"] if f["parent_id"] in known else None, []).append(f)
        for s in all_sessions:
            if want and want not in f"{s['name']} {s['host']} {paths.get(s['folder_id'], '')} {KIND_TEXT.get(s['kind'], '')}".lower():
                continue
            by_folder.setdefault(s["folder_id"] if s["folder_id"] in known else None, []).append(s)

        def count(fid):
            return len(by_folder.get(fid, [])) + sum(count(c["id"]) for c in kids.get(fid, []))

        self._building = True
        self.tree.blockSignals(True)
        self.tree.clear()
        self.payload = {}
        bold = QFont()
        bold.setBold(True)
        shown = [0]

        def fill(parent_item, fid):
            def add(item):
                (parent_item.addChild if parent_item else self.tree.addTopLevelItem)(item)
            for f in sorted(kids.get(fid, []), key=lambda f: f["name"].lower()):
                if want and not count(f["id"]):
                    continue                                   # while searching, hide folders with nothing to show
                item = QTreeWidgetItem([f"{f['name']}  ({count(f['id'])})", "", ""])
                key = f"folder:{f['id']}"
                item.setData(0, ROLE, key)
                self.payload[key] = f
                item.setFont(0, bold)
                item.setIcon(0, self._folder_icon())
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsDragEnabled | Qt.ItemFlag.ItemIsDropEnabled)
                add(item)
                fill(item, f["id"])
                item.setExpanded(f["id"] in self.expanded or bool(want))
            for s in sorted(by_folder.get(fid, []), key=lambda s: s["name"].lower()):
                host = s["host"] if s["kind"] != "rdp" or s["port"] == 3389 else f"{s['host']}:{s['port']}"
                item = QTreeWidgetItem([s["name"], KIND_TEXT.get(s["kind"], s["kind"]), host])
                key = f"session:{s['id']}"
                item.setData(0, ROLE, key)
                self.payload[key] = s
                item.setFlags((item.flags() | Qt.ItemFlag.ItemIsDragEnabled) & ~Qt.ItemFlag.ItemIsDropEnabled)
                add(item)
                shown[0] += 1

        fill(None, None)
        for it in self._all_items():
            if self.kind_of(it) in keep:
                it.setSelected(True)
        self._building = False
        self.tree.blockSignals(False)
        for i in range(2):
            self.tree.resizeColumnToContents(i)
        total = len(all_sessions)
        self.note.setText((f"{shown[0]} of {total} session(s)" if want else f"{total} saved session(s), {len(folders)} folder(s)")
                          if shown[0] or not want else "No session matches.")
        self._buttons()

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
        if kind == "folder":
            (self.expanded.add if open_ else self.expanded.discard)(ident)
            db.set_setting("sessions_expanded", sorted(self.expanded))

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
        """The id of the one session that is selected, or None."""
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
        for b in (self.folder_btn, self.copy_btn, self.expand_btn, self.collapse_btn, self.logs_btn):
            act = self.more_menu.addAction(b.text())
            act.setEnabled(b.isEnabled())
            act.triggered.connect(lambda _=False, b=b: b.click())

    def _buttons(self):
        one = self.selected_id() is not None
        folders, found = self.selected_folders(), self.selected_sessions()
        self.connect_btn.setEnabled(one)
        self.copy_btn.setEnabled(one)
        self.edit_btn.setEnabled(one or (len(folders) == 1 and not found))
        self.edit_btn.setText("Rename" if len(folders) == 1 and not found else "Edit")
        self.delete_btn.setEnabled(bool(found or folders))

    def _double_clicked(self, item, *_):
        if self.kind_of(item)[0] == "session":
            self.connect_selected()

    def _menu(self, pos):
        item = self.tree.itemAt(pos)
        if item is not None and not item.isSelected():
            self.tree.clearSelection()
            item.setSelected(True)
        found, folders = self.selected_sessions(), self.selected_folders()
        m = QMenu(self)
        if found or folders:
            if len(found) == 1 and not folders:
                m.addAction("Connect", self.connect_selected)
                m.addAction("Edit...", self.edit_selected)
                m.addAction("Duplicate", self.duplicate_selected)
            if len(folders) == 1 and not found:
                add = m.addMenu("New session here")
                for k, label, _, _ in sessions.KINDS:
                    add.addAction(label, lambda k=k: self.new_session(k))
                m.addAction("New subfolder...", lambda: self.new_folder(folders[0]))
                m.addAction("Rename...", self.rename_folder)
            move = m.addMenu("Move to folder")
            banned = set().union(*(sessions.folder_descendants(f) for f in folders)) if folders else set()
            move.addAction("(top level)", lambda: self.move_selected_to(None))
            for fid, path in sorted(sessions.folder_paths().items(), key=lambda kv: kv[1].lower()):
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
        name = self._ask_name("New folder", "Folder name:")
        if not name:
            return None
        try:
            fid = sessions.create_folder(name, parent)
        except ValueError as e:
            QMessageBox.warning(self, "New folder", str(e))
            return None
        self.expanded.update({fid} | ({parent} if parent else set()))
        db.set_setting("sessions_expanded", sorted(self.expanded))
        audit.log("session folder created", sessions.folder_paths().get(fid, name))
        self.refresh()
        return fid

    def rename_folder(self):
        folders = self.selected_folders()
        if len(folders) != 1 or self.selected_sessions():
            return
        name = self._ask_name("Rename folder", "New name:", self.payload[f"folder:{folders[0]}"]["name"])
        if not name:
            return
        try:
            sessions.rename_folder(folders[0], name)
        except ValueError as e:
            QMessageBox.warning(self, "Rename folder", str(e))
            return
        self.refresh()

    def delete_folder(self):
        folders = self.selected_folders()
        if len(folders) != 1:
            return
        fid = folders[0]
        f = self.payload[f"folder:{fid}"]
        kids = sum(1 for x in sessions.list_folders() if x["parent_id"] == fid)
        inside = sum(1 for s in sessions.list_sessions() if s["folder_id"] == fid)
        where = sessions.folder_paths().get(f["parent_id"], "") or "the top level"
        if QMessageBox.question(self, "Delete folder", f"Delete the folder '{f['name']}'?\n\nIts {inside} session(s) and "
                                f"{kids} subfolder(s) move up to {where}. No session is deleted.") != QMessageBox.StandardButton.Yes:
            return
        try:
            sessions.delete_folder(fid)
        except ValueError as e:
            QMessageBox.warning(self, "Delete folder", str(e))
            return
        audit.log("session folder deleted", f["name"])
        self.expanded.discard(fid)
        self.refresh()

    def move_selected_to(self, target_id):
        moves = [("session", s["id"]) for s in self.selected_sessions()] + [("folder", i) for i in self.selected_folders()]
        self.handle_moves(moves, target_id)

    def handle_moves(self, moves, target_id):
        """Move sessions and folders into a folder (None = top level), reporting anything that cannot move."""
        problems, ids = [], []
        for kind, ident in moves:
            if kind == "session":
                ids.append(ident)
            else:
                try:
                    sessions.move_folder(ident, target_id)
                except ValueError as e:
                    problems.append(str(e))
        clash = {s["name"].lower() for s in sessions.list_sessions() if s["folder_id"] == target_id and s["id"] not in ids}
        moving = [s for s in sessions.list_sessions() if s["id"] in ids]
        ok_ids = []
        for s in moving:
            if s["name"].lower() in clash and s["folder_id"] != target_id:
                problems.append(f"'{s['name']}' was not moved: the folder already has a session with that name.")
            else:
                ok_ids.append(s["id"])
                clash.add(s["name"].lower())
        sessions.move_sessions(ok_ids, target_id)
        if target_id is not None:
            self.expanded.add(target_id)
            db.set_setting("sessions_expanded", sorted(self.expanded))
        self.refresh()
        if problems:
            QMessageBox.warning(self, "Move", "\n".join(sorted(set(problems))))

    # ---------------------------------------------------------------- creating, changing, removing
    def new_session(self, kind="ssh", prefill=None):
        dlg = SessionDialog(prefill, kind, self, folder_id=self.current_folder())
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
        s = sessions.get(self.selected_id())
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
        if dlg.wants_save():
            try:
                saved_id = sessions.save(v)
            except ValueError as e:
                QMessageBox.warning(self, "Session", str(e))
                return
            if v["kind"] == "ssh":
                if v["options"]["remember"] and pw:
                    sessions.set_password(saved_id, pw)
                elif not v["options"]["remember"]:
                    sessions.forget_password(saved_id)
            if v["folder_id"] is not None:
                self.expanded.add(v["folder_id"])
                db.set_setting("sessions_expanded", sorted(self.expanded))
            audit.log("session saved", f"{v['kind']} {v['name']}")
        self.refresh()
        if dlg.action == "connect":
            spec = self._spec(v, pw, saved_id)
            if saved_id:
                sessions.touch(saved_id)
            self.open_spec(spec)

    def duplicate_selected(self):
        new = sessions.duplicate(self.selected_id())
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
        for s in found:
            sessions.delete(s["id"])
            audit.log("session deleted", f"{s['kind']} {s['name']}")
        self.refresh()

    # ---------------------------------------------------------------- opening
    def _spec(self, s, password="", saved_id=None):
        """Everything a pane needs to connect: the saved session plus the inventory device it points at."""
        dev = _device(s.get("device"))
        kind = s["kind"]
        spec = {"name": s.get("name") or s.get("host") or "session", "kind": kind, "host": s.get("host") or (dev["host"] if dev else ""),
                "port": int(s.get("port") or (dev.get("port") if dev else 0) or sessions.DEFAULT_PORT[kind]),
                "username": s.get("username") or (profiles.username(dev) if dev else ""), "password": password,
                "dev": dev, "options": {**sessions.DEFAULTS[kind], **(s.get("options") or {})}, "saved_id": saved_id}
        if kind == "ssh" and not password and saved_id:
            spec["password"] = sessions.password(saved_id)
        return spec

    def open_spec(self, spec):
        if spec["kind"] == "rdp":
            try:
                path = sessions.launch_rdp({"name": spec["name"], "host": spec["host"], "port": spec["port"],
                                            "username": spec["username"], "options": spec["options"]})
            except OSError as e:
                QMessageBox.warning(self, "Remote Desktop", str(e))
                return
            audit.log("session opened", f"rdp {spec['name']} ({spec['host']})")
            self.note.setText(f"Started Remote Desktop to {spec['host']} (settings in {path.name}).")
            return
        pane = SessionPane(spec)
        pane.state_changed.connect(self._retitle)
        pane.logs_changed.connect(self._logs_changed)
        i = self.tabs.addTab(pane, spec["name"])
        self.tabs.setCurrentIndex(i)
        self.stack.setCurrentWidget(self.tabs)
        # connect once the tab has its real size, or the first lines are cropped when the terminal settles
        QTimer.singleShot(0, lambda: pane.connect_now() if pane in self.panes() else None)

    def connect_selected(self):
        sid = self.selected_id()
        s = sessions.get(sid)
        if s:
            sessions.touch(sid)
            self.open_spec(self._spec(s, "", sid))

    def open_session(self, session_id):
        s = sessions.get(session_id)
        if s:
            sessions.touch(session_id)
            self.open_spec(self._spec(s, "", session_id))

    def open_device(self, dev):
        """An inventory device's SSH session (Inventory > Open SSH session, the device window, the command palette)."""
        for i in range(self.tabs.count()):
            p = self.tabs.widget(i)
            if p.spec.get("dev") and p.spec["dev"]["name"] == dev["name"] and p.kind == "ssh":
                self.tabs.setCurrentIndex(i)
                if not p.connected():
                    p.connect_now()
                return p
        spec = self._spec({"name": dev["name"], "kind": "ssh", "host": dev["host"], "port": dev.get("port") or int(db.get_setting("default_ssh_port")),
                           "device": dev["name"], "options": {"paging": True}})
        self.open_spec(spec)
        return self.tabs.currentWidget()

    # ---------------------------------------------------------------- the tabs
    def panes(self):
        return [self.tabs.widget(i) for i in range(self.tabs.count())]

    def _retitle(self, pane):
        i = self.tabs.indexOf(pane)
        if i >= 0:
            self.tabs.setTabText(i, ("● " if pane.connected() else "") + pane.spec["name"])

    def close_tab(self, i):
        pane = self.tabs.widget(i)
        if pane.connected() and QMessageBox.question(self, "End session", f"'{pane.spec['name']}' is still connected. End the session?") \
                != QMessageBox.StandardButton.Yes:
            return
        pane.shutdown()
        self.tabs.removeTab(i)
        pane.deleteLater()
        self._logs_changed()
        if not self.tabs.count():
            self.stack.setCurrentWidget(self.welcome)

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
