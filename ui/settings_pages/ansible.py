"""Settings page: where Ansible runs (WSL on this PC, or a Linux server over SSH), where the playbooks are kept, and how a run starts."""

import os

import keyring
from PySide6.QtCore import QThread, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QCheckBox, QComboBox, QFileDialog, QLabel, QLineEdit, QPushButton

from core import ansible as AN, audit, db
from ui.settings_base import Page, compact_row, note, row_of, spin


class _Worker(QThread):
    """Runs one slow call (listing WSL distributions, testing a login) away from the window."""
    done = Signal(object)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            self.done.emit(self.fn())
        except Exception as e:                               # shown to the person, never raised into the event loop
            self.done.emit(e)


class AnsiblePage(Page):
    title = "Ansible"

    def __init__(self):
        super().__init__()
        self._forget = False
        self._have_password = False
        self._jobs = []                                       # running workers (kept so none is dropped while running)
        self.where = QComboBox()
        self.where.addItem("This PC, through WSL (Windows Subsystem for Linux)", "wsl")
        self.where.addItem("A Linux server, over SSH", "server")
        self.where.setToolTip("Ansible does not run on Windows itself, so it runs in a Linux that does: one on this PC (WSL) or one you already have")
        self.command = QLineEdit()
        self.command.setPlaceholderText(AN.DEFAULT_COMMAND)
        self.command.setToolTip("The command that runs a playbook, if it is not on the path as ansible-playbook (for example /home/me/venv/bin/ansible-playbook)")
        # WSL
        self.distro = QComboBox()
        self.distro.setToolTip("Which Linux installed in WSL runs Ansible")
        self.find_distro = QPushButton("Find installed")
        # a server
        self.login = QComboBox()
        self.login.addItem("An Inventory device", "device")
        self.login.addItem("Type the address and login here", "typed")
        self.device = QComboBox()
        self.host, self.user, self.key_file = QLineEdit(), QLineEdit(), QLineEdit()
        self.host.setPlaceholderText("ansible.example.com")
        self.user.setPlaceholderText("a user who can run ansible-playbook")
        self.key_file.setPlaceholderText("optional: a private key file, instead of a password")
        self.port = spin(1, 65535)
        self.port.setValue(22)
        self.browse_key = QPushButton("Browse...")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.forget = QPushButton("Remove saved password")
        self.pw_note = note("")
        self.device_note = note("The device's address, SSH port, user name and saved password are used. Add the server to the Inventory as an SSH device (a Linux or "
                                "'Other SSH' device) and its login is kept with your other credentials.")
        # playbooks and runs
        self.folder = QLineEdit()
        self.folder.setPlaceholderText(str(AN.default_dir()))
        self.browse_folder, self.open_folder = QPushButton("Browse..."), QPushButton("Open folder")
        self.check_default = QCheckBox("Start every run as a check (nothing is changed)")
        self.check_default.setToolTip("A check runs the playbook with --check --diff: it shows what would change. You can switch it off for a single run.")
        self.keep = spin(10, 5000)
        self.test_btn = QPushButton("Test")
        self.test_out = QLabel("")
        self.test_out.setWordWrap(True)
        self.test_out.setTextInteractionFlags(self.test_out.textInteractionFlags() | self.test_out.textInteractionFlags().TextSelectableByMouse)

        self.form.addRow("Run Ansible on", self.where)
        self.form.addRow("Distribution", compact_row(self.distro, self.find_distro))
        self.form.addRow("Sign in with", self.login)
        self.form.addRow("Server", self.device)
        self.form.addRow("", self.device_note)
        self.form.addRow("Address", self.host)
        self.form.addRow("Port", self.port)
        self.form.addRow("User name", self.user)
        self.form.addRow("Key file", row_of(self.key_file, self.browse_key))
        self.form.addRow("Password", self.password)
        self.form.addRow("", compact_row(self.forget))
        self.form.addRow("", self.pw_note)
        self.form.addRow("Command", self.command)
        self.form.addRow("Try it", compact_row(self.test_btn))
        self.form.addRow("", self.test_out)
        self.form.addRow("Playbook folder", row_of(self.folder, self.browse_folder, self.open_folder))
        self.form.addRow("", self.check_default)
        self.form.addRow("Keep the last", row_of(self.keep, QLabel("runs in the history")))
        self.lay.insertWidget(0, note(
            "Toner writes, checks and runs Ansible playbooks. Ansible itself needs Linux, so a run happens in WSL on this PC or on a Linux server you "
            "already have. Toner makes the inventory from the Inventory (every device with its login), uses it for the run and removes it afterwards: "
            "no password is written into a playbook or kept on the server."))
        self.where.currentIndexChanged.connect(self.adapt)
        self.login.currentIndexChanged.connect(self.adapt)
        self.find_distro.clicked.connect(self.list_distros)
        self.browse_key.clicked.connect(self._pick_key)
        self.browse_folder.clicked.connect(self._pick_folder)
        self.open_folder.clicked.connect(self._open_folder)
        self.forget.clicked.connect(self._clear_password)
        self.test_btn.clicked.connect(self.test)

    # ---- showing the right boxes
    def adapt(self, *_):
        wsl = self.where.currentData() == "wsl"
        device = self.login.currentData() == "device"
        self.form.setRowVisible(self.distro.parentWidget(), wsl)
        self.form.setRowVisible(self.login, not wsl)
        for w in (self.device, self.device_note):
            self.form.setRowVisible(w, not wsl and device)
        for w in (self.host, self.port, self.user, self.key_file.parentWidget(), self.password, self.pw_note):
            self.form.setRowVisible(w, not wsl and not device)
        self.form.setRowVisible(self.forget.parentWidget(), not wsl and not device and self._have_password)

    # ---- values
    def _fill_devices(self, keep=""):
        self.device.clear()
        for d in db.list_devices():
            self.device.addItem(d["name"], d["name"])
        i = self.device.findData(keep)
        if keep and i < 0:
            self.device.addItem(f"{keep} (not in the Inventory)", keep)
            i = self.device.count() - 1
        self.device.setCurrentIndex(max(0, i))

    def _set_distros(self, names, keep=""):
        self.distro.clear()
        self.distro.addItem("(the default one)", "")
        for n in names:
            self.distro.addItem(n, n)
        if keep and self.distro.findData(keep) < 0:
            self.distro.addItem(keep, keep)
        self.distro.setCurrentIndex(max(0, self.distro.findData(keep)))

    def load(self):
        self.where.setCurrentIndex(max(0, self.where.findData(db.get_setting("ansible_backend") or "wsl")))
        self._set_distros([], db.get_setting("ansible_distro") or "")
        self.command.setText(db.get_setting("ansible_command") if db.get_setting("ansible_command") != AN.DEFAULT_COMMAND else "")
        dev = (db.get_setting("ansible_server_device") or "").strip()
        self.login.setCurrentIndex(max(0, self.login.findData("device" if dev else "typed")))
        self._fill_devices(dev)
        s = db.get_setting("ansible_server") or {}
        self.host.setText(s.get("host", ""))
        self.port.setValue(int(s.get("port") or 22))
        self.user.setText(s.get("user", ""))
        self.key_file.setText(s.get("key_file", ""))
        self.password.clear()
        self._forget = False
        have = bool(keyring.get_password(db.SERVICE, AN.SERVER_SECRET))
        self.pw_note.setText("A password is saved in the vault. Leave the box empty to keep it. With a key file, this is the key's passphrase." if have
                             else "Stored in Toner's vault, not in its database. With a key file, this is the key's passphrase.")
        self._have_password = have
        self.folder.setText(db.get_setting("ansible_playbooks") or "")
        self.check_default.setChecked(bool(db.get_setting("ansible_check_default")))
        self.keep.setValue(int(db.get_setting("ansible_keep_runs") or 200))
        self.test_out.setText("")
        self.adapt()

    def refresh(self):
        keep = self.device.currentData() or ""
        self._fill_devices(keep)

    def validate(self):
        out = []
        if self.where.currentData() == "server":
            if self.login.currentData() == "device":
                if not self.device.currentData():
                    out.append("Ansible: choose the server in the list, or choose 'Type the address and login here'.")
            else:
                if not self.host.text().strip():
                    out.append("Ansible: enter the server's address.")
                if not self.user.text().strip():
                    out.append("Ansible: enter the server's user name.")
        f = self.folder.text().strip()
        if f and os.path.exists(f) and not os.path.isdir(f):
            out.append("Ansible: the playbook folder is a file. Choose a folder.")
        return out

    def save(self):
        db.set_setting("ansible_backend", self.where.currentData())
        db.set_setting("ansible_distro", self.distro.currentData() or "")
        db.set_setting("ansible_command", self.command.text().strip() or AN.DEFAULT_COMMAND)
        db.set_setting("ansible_server_device", (self.device.currentData() or "") if self.login.currentData() == "device" else "")
        db.set_setting("ansible_server", {"host": self.host.text().strip(), "port": self.port.value(), "user": self.user.text().strip(), "key_file": self.key_file.text().strip()})
        if self.password.text():
            db.set_secret(AN.SERVER_SECRET, self.password.text())
        elif self._forget:
            db.delete_secret(AN.SERVER_SECRET)
        db.set_setting("ansible_playbooks", self.folder.text().strip())
        db.set_setting("ansible_check_default", self.check_default.isChecked())
        db.set_setting("ansible_keep_runs", self.keep.value())
        where = self.where.currentData()
        audit.log("ansible settings changed", where + (f" {self.host.text().strip()}" if where == "server" and self.login.currentData() == "typed" else ""))
        self.load()

    # ---- buttons
    def _pick_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Private key file", self.key_file.text() or os.path.expanduser("~"))
        if path:
            self.key_file.setText(path)

    def _pick_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Playbook folder", self.folder.text().strip() or str(AN.playbook_dir()))
        if path:
            self.folder.setText(os.path.normpath(path))

    def _open_folder(self):
        f = self.folder.text().strip()
        path = f if f and os.path.isdir(f) else str(AN.playbook_dir())     # the saved folder is made on first use; the shown one may not be saved yet
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def _clear_password(self):
        self._forget = True
        self.password.clear()
        self.pw_note.setText("The saved password will be removed when you save.")

    def _job(self, fn, then):
        w = _Worker(fn)
        self._jobs.append(w)

        def finished(res, w=w):
            then(res)
            if w in self._jobs:
                self._jobs.remove(w)
        w.done.connect(finished)
        w.start()

    def list_distros(self):
        keep = self.distro.currentData() or ""
        self.find_distro.setEnabled(False)

        def then(names):
            self.find_distro.setEnabled(True)
            if isinstance(names, Exception) or not names:
                self.test_out.setText("WSL has no Linux installed, or WSL is not installed. In an administrator PowerShell run  wsl --install -d Ubuntu , restart, "
                                      "and open Ubuntu once to finish setting it up.")
                return
            self._set_distros(names, keep)
            self.test_out.setText(f"Found: {', '.join(names)}.")
        self._job(AN.WslBackend.distros, then)

    def current_backend(self):
        """The backend as the boxes show it now (before saving), for the test."""
        cmd = self.command.text().strip() or AN.DEFAULT_COMMAND
        if self.where.currentData() == "wsl":
            return AN.WslBackend(self.distro.currentData() or "", cmd)
        if self.login.currentData() == "device":
            login = AN.device_login(self.device.currentData() or "")
        else:
            pw = self.password.text() or ("" if self._forget else (keyring.get_password(db.SERVICE, AN.SERVER_SECRET) or ""))
            login = {"host": self.host.text().strip(), "port": self.port.value(), "user": self.user.text().strip(), "key_file": self.key_file.text().strip(), "password": pw}
        return AN.ServerBackend(login, cmd)

    def test(self):
        try:
            back = self.current_backend()
        except AN.BackendError as e:
            self.test_out.setText("Failed: " + str(e))
            return
        self.test_btn.setEnabled(False)
        self.test_out.setText("Trying...")

        def then(res):
            self.test_btn.setEnabled(True)
            if isinstance(res, Exception):
                self.test_out.setText(f"Failed: {res}")
            else:
                ok, msg = res
                self.test_out.setText(("OK: " if ok else "Failed: ") + (msg or ("Ansible is ready." if ok else "")))
        self._job(back.check, then)
