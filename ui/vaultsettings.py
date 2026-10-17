"""Settings > Security > Vault: where Toner keeps its passwords (Toner's vault, or Bitwarden, Vaultwarden, Keeper, 1Password),
how it signs in to that manager, and which collection each organization's passwords go to.

Everything here acts through its own buttons (Test connection, Use this vault), not through Save changes, so its boxes are marked
notSetting. Secret fields are never shown: they read 'saved in the vault - leave blank to keep it' when one is kept."""
from PySide6.QtCore import QThread, QTimer, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from core import audit, db, extstore, extvault, orgs, passvault
from ui.brandicons import vault_icon

KEPT = "saved in the vault - leave blank to keep it"


def _quiet(w):
    w.setProperty("notSetting", True)
    return w


class _Tester(QThread):
    done = Signal(bool, str, object)

    def __init__(self, kind, cfg, secrets, parent=None):
        super().__init__(parent)
        self.args = (kind, cfg, secrets)

    def run(self):
        ok, text, conn = extstore.test(*self.args)
        self.done.emit(ok, text, conn)


class _Fields(QWidget):
    """The sign-in boxes of one manager."""

    def __init__(self, kind):
        super().__init__()
        self.kind = kind
        self.form = QFormLayout(self)
        self.form.setContentsMargins(0, 0, 0, 0)
        self.boxes, self.secret_boxes = {}, {}
        if kind == "bitwarden":
            self._combo("region", "Region", extvault.BITWARDEN_REGIONS)
        if kind == "vaultwarden":
            self._line("server", "Server address", "https://vault.example.com")
        if kind in ("bitwarden", "vaultwarden"):
            self._line("client_id", "Client ID", "user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
            self._secret("client_secret", "Client secret")
            self._secret("master_password", "Master password")
            self._line("organization", "Organization", "the Bitwarden organization that holds the collections")
            self._cli("Bitwarden CLI", "bw.exe")
        if kind == "onepassword":
            self._secret("token", "Service account token")
            self._cli("1Password CLI", "op.exe")
        if kind == "keeper":
            self._combo("region", "Region", extvault.KEEPER_REGIONS)
            self._secret("token", "One-time access token")
            self.connected = QLabel("Connected")
            self.form.addRow("", self.connected)

    def _line(self, key, label, hint=""):
        box = _quiet(QLineEdit())
        box.setPlaceholderText(hint)
        self.boxes[key] = box
        self.form.addRow(label, box)

    def _secret(self, key, label):
        box = _quiet(QLineEdit())
        box.setEchoMode(QLineEdit.EchoMode.Password)
        self.secret_boxes[key] = box
        self.form.addRow(label, box)

    def _combo(self, key, label, choices):
        box = _quiet(QComboBox())
        for text, value in choices:
            box.addItem(text, value)
        self.boxes[key] = box
        self.form.addRow(label, box)

    def _cli(self, label, exe):
        box = _quiet(QLineEdit())
        box.setPlaceholderText(f"{exe} (found automatically when it is on the PATH)")
        browse, get = QPushButton("Browse..."), QLabel(f"<a href='{extvault.DOWNLOADS[self.kind]}'>Download</a>")
        browse.clicked.connect(lambda: self._browse(box, exe))
        get.setTextFormat(Qt.TextFormat.RichText)
        get.linkActivated.connect(lambda url: QDesktopServices.openUrl(QUrl(url)))
        row = QWidget()
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        h.addWidget(box, 1)
        h.addWidget(browse)
        h.addWidget(get)
        self.boxes["cli"] = box
        self.form.addRow(label, row)
        self.where = QLabel("")                                          # which bw.exe / op.exe will be used, like iperf3's line
        self.where.setWordWrap(True)
        self.where.setProperty("muted", True)
        self.form.addRow("", self.where)
        box.textChanged.connect(self.show_where)

    def show_where(self, *_):
        if not hasattr(self, "where"):
            return
        exe = extvault.CLI_NAMES[self.kind]
        box = self.boxes["cli"]
        found = extvault.find_cli(self.kind, box.text())
        # found on PATH: said inside the empty box; a chosen path shows itself; nothing found: the line below says how to get it
        box.setPlaceholderText(f"Using {exe}: {found}" if found and not box.text().strip() else
                               f"{exe}.exe (found automatically when it is on the PATH)")
        self.where.setText("" if found else
                           f"{exe}.exe was not found. Download the {extvault.CLI_LABELS[self.kind]}, then choose {exe}.exe with "
                           "Browse..., or put it in a folder on your PATH.")
        self.where.setVisible(not found)

    def _browse(self, box, exe):
        path, _ = QFileDialog.getOpenFileName(self, "Choose " + exe, "", f"{exe} ({exe});;Programs (*.exe)")
        if path:
            box.setText(path)

    def load(self):
        cfg = extstore.config(self.kind)
        for key, box in self.boxes.items():
            if isinstance(box, QComboBox):
                box.setCurrentIndex(max(0, box.findData(cfg.get(key))))
            else:
                box.setText(cfg.get(key) or "")
        for key, box in self.secret_boxes.items():
            box.clear()
            box.setPlaceholderText(KEPT if extstore.secret(self.kind, key) else "")
        self.show_where()
        if self.kind == "keeper":
            bound = bool(extstore.secret("keeper", "config"))
            self.connected.setVisible(bound)
            self.secret_boxes["token"].setPlaceholderText("")

    def values(self):
        """(settings, secrets): what is typed, with a kept secret standing in for an empty box."""
        cfg = dict(extstore.config(self.kind))
        for key, box in self.boxes.items():
            cfg[key] = box.currentData() if isinstance(box, QComboBox) else box.text().strip()
        secrets = extstore.secrets(self.kind)
        for key, box in self.secret_boxes.items():
            if box.text():
                secrets[key] = box.text()
                if self.kind == "keeper" and key == "token":
                    secrets["config"] = None                 # a new token: bind again
        return cfg, secrets


class VaultSection(QWidget):
    """Store passwords in: the drop-down, the chosen manager's boxes, the collections, Test connection and Use this vault."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.kind = _quiet(QComboBox())
        for kind, label in extvault.KINDS:
            self.kind.addItem(vault_icon(kind), label, kind)
        self.kind.currentIndexChanged.connect(self._show)
        self.fields = {k: _Fields(k) for k in extvault.CONNECTORS}
        self.stack = QStackedWidget()
        self.stack.addWidget(QWidget())                                 # Toner's vault: nothing to fill in
        for f in self.fields.values():
            self.stack.addWidget(f)
        self.where = QLabel("<b>Where each organization's passwords go</b>")
        self.table = QTableWidget(0, 2)
        self.table.setProperty("notSetting", True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.DoubleClicked | QAbstractItemView.EditTrigger.SelectedClicked
                                   | QAbstractItemView.EditTrigger.EditKeyPressed)
        self.table.setMinimumHeight(110)
        self.test_btn, self.use_btn = QPushButton("Test connection"), QPushButton("Use this vault")
        self.test_btn.clicked.connect(self.test)
        self.use_btn.clicked.connect(self.use)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.direct = _quiet(QCheckBox("Connect directly to the password manager (ignore the proxy settings)"))
        self.direct.toggled.connect(self._direct)
        self.copies = _quiet(QCheckBox("Keep a copy of each password in Toner's vault"))
        self.copies.toggled.connect(self._copies)
        self.copies_note = QLabel("Checks keep working when the password manager can't be reached. Without copies, Toner reads "
                                  "passwords from the password manager each time it starts and keeps them only in memory.")
        self.copies_note.setWordWrap(True)
        self.copies_note.setProperty("muted", True)
        self.copies_note.setContentsMargins(26, 0, 0, 0)
        top = QFormLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.addRow("Store passwords in", self.kind)
        buttons = QHBoxLayout()
        buttons.addWidget(self.test_btn)
        buttons.addWidget(self.use_btn)
        buttons.addStretch(1)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addLayout(top)
        lay.addWidget(self.stack)
        lay.addWidget(self.where)
        lay.addWidget(self.table)
        lay.addWidget(self.copies)
        lay.addWidget(self.copies_note)
        lay.addWidget(self.direct)
        lay.addLayout(buttons)
        lay.addWidget(self.status)
        self.tester = None
        self.watch = QTimer(self)                                       # the status line follows the background sync
        self.watch.setInterval(2000)
        self.watch.timeout.connect(self.show_status)
        self.watch.start()

    # ---------- showing
    def load(self):
        for f in self.fields.values():
            f.load()
        self.direct.blockSignals(True)
        self.direct.setChecked(bool(db.get_setting("vault_direct")))
        self.direct.blockSignals(False)
        self.kind.blockSignals(True)
        self.kind.setCurrentIndex(max(0, self.kind.findData(extstore.active())))
        self.kind.blockSignals(False)
        self._show()

    def chosen(self):
        return self.kind.currentData()

    def _show(self, *_):
        kind = self.chosen()
        manager = kind in extvault.CONNECTORS
        self.stack.setCurrentIndex(0 if not manager else 1 + list(extvault.CONNECTORS).index(kind))
        self.stack.setVisible(manager)
        for w in (self.where, self.table, self.test_btn, self.direct):
            w.setVisible(manager)
        for w in (self.copies, self.copies_note):                    # (it is about the manager in use)
            w.setVisible(manager and kind == extstore.active())
        self.copies.blockSignals(True)
        self.copies.setChecked(extstore.keep_copies())
        self.copies.blockSignals(False)
        self.use_btn.setEnabled(kind != extstore.active())
        if manager:
            self._fill_table(kind)
        self.show_status()

    def _fill_table(self, kind):
        self.table.setHorizontalHeaderLabels(["Organization", extvault.CONTAINER_WORD[kind]])
        chosen = extstore.config(kind).get("containers") or {}
        rows = [(db.GLOBAL, "Global")] + [(o["id"], o["name"]) for o in orgs.list_orgs()]
        self.table.setRowCount(len(rows))
        for i, (oid, name) in enumerate(rows):
            org = QTableWidgetItem(name)
            org.setFlags(org.flags() & ~Qt.ItemFlag.ItemIsEditable)
            org.setData(Qt.ItemDataRole.UserRole, oid)
            self.table.setItem(i, 0, org)
            self.table.setItem(i, 1, QTableWidgetItem(chosen.get(str(oid)) or f"Toner - {name}"))
        self.table.resizeColumnToContents(0)

    def show_status(self):
        if self.tester is not None:
            return
        self.status.setText(extstore.status_text() if self.chosen() == extstore.active() else "")

    # ---------- what is typed
    def _values(self):
        kind = self.chosen()
        cfg, secrets = self.fields[kind].values()
        cfg["containers"] = {str(self.table.item(i, 0).data(Qt.ItemDataRole.UserRole)): self.table.item(i, 1).text().strip()
                             for i in range(self.table.rowCount())}
        return kind, cfg, secrets

    def _keep(self, kind, cfg, secrets):
        extstore.set_config(kind, cfg)
        for key, value in secrets.items():
            if key in extvault.SECRET_FIELDS[kind]:
                extstore.set_secret(kind, key, value)
        self.fields[kind].load()

    def _copies(self, on):
        """Keep a copy on or off. Off asks first, and only once every password is in the password manager."""
        label = extvault.LABELS[extstore.active()]
        try:
            if not on:
                n = len(extstore.local_names())
                if QMessageBox.question(self, "Store passwords in", f"Remove Toner's copies of {n:,} passwords? Toner will read them "
                                        f"from {label} each time it starts. While {label} can't be reached, checks that need a "
                                        "password will fail.") != QMessageBox.StandardButton.Yes:
                    raise extstore.CannotSwitch("")
            extstore.set_keep_copies(on)
            audit.log("password copies " + ("kept in Toner's vault" if on else "removed from Toner's vault"), label)
        except extstore.CannotSwitch as e:
            if str(e):
                QMessageBox.information(self, "Store passwords in", str(e))
            self.copies.blockSignals(True)
            self.copies.setChecked(extstore.keep_copies())
            self.copies.blockSignals(False)
        self.show_status()

    def _direct(self, on):
        db.set_setting("vault_direct", on)
        audit.log("password manager " + ("connects directly" if on else "follows the proxy settings"))
        extstore.kick()

    # ---------- buttons
    def test(self):
        if self.tester is not None:
            return
        kind, cfg, secrets = self._values()
        self.status.setText(f"Connecting to {extvault.LABELS[kind]}...")
        self.test_btn.setEnabled(False)
        self.tester = _Tester(kind, cfg, secrets, self)
        self.tester.done.connect(lambda ok, text, conn, k=kind, c=cfg, s=secrets: self._tested(ok, text, conn, k, c, s))
        self.tester.start()

    def _tested(self, ok, text, conn, kind, cfg, secrets):
        self.tester = None
        self.test_btn.setEnabled(True)
        if ok:
            self._keep(kind, cfg, {**secrets, **(conn.new_secrets or {})})       # Keeper: its configuration replaces the token
        self.status.setText(text)

    def use(self):
        kind = self.chosen()
        label = extvault.LABELS[kind]
        if kind == "toner":
            was = extvault.LABELS[extstore.active()]
            if extstore.keep_copies() and QMessageBox.question(
                    self, "Store passwords in", f"Stop using {was}? Toner's vault already has a copy of every password, "
                    "so nothing is lost.") != QMessageBox.StandardButton.Yes:
                return
            try:
                extstore.use("toner")                             # (without copies: copied back from the manager first)
            except extstore.CannotSwitch as e:
                QMessageBox.information(self, "Store passwords in", str(e))
                return
            audit.log("passwords kept in Toner's vault", f"no longer {was}")
        else:
            n = len(extstore.local_names()) if passvault.is_open() else 0
            if QMessageBox.question(self, "Store passwords in", f"Move Toner's {n:,} saved passwords to {label}? Toner keeps an encrypted copy "
                                    f"of each in its own vault, for when {label} can't be reached.") != QMessageBox.StandardButton.Yes:
                return
            k, cfg, secrets = self._values()
            try:
                self._keep(k, cfg, secrets)
                extstore.use(kind)                                # (without copies: they come back into Toner's vault first)
            except extstore.CannotSwitch as e:
                QMessageBox.information(self, "Store passwords in", str(e))
                return
            audit.log("passwords kept in " + label, f"{n} password(s) sent")
        self._show()
