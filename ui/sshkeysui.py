"""Tools > SSH Keys: make a key pair, read a key (and change its passphrase), and put a public key on a device."""
import os

import paramiko
from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (QApplication, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QSizePolicy, QSpinBox, QTabWidget, QVBoxLayout, QWidget)

from core import audit, db, profiles, scp, sshkeys, vendors
from ui.opensslui import _Base, _secret, _text
from ui.tools import DevicePicker, OutputBox, _row
from ui.tools2 import _muted, _primary

MISMATCH = "The passphrases don't match."


def _line_box():
    """The one-line public key, selectable and copyable."""
    box = QLineEdit()
    box.setReadOnly(True)
    box.setFont(_text().font())
    return box


def _fixed(box, width=220):
    """A box that keeps its width rather than taking the spare room in its row (which pushed the buttons after it away)."""
    box.setFixedWidth(width)
    box.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
    return box


def _button(text):
    b = QPushButton(text)
    b.setAutoDefault(False)
    return b


def _save_pair(parent, kind, private_text, line):
    """Save key pair...: the private key where the person chooses (only they can read it) and the public key beside it (.pub).
    Returns the private key's path, or '' when cancelled."""
    path, _ = QFileDialog.getSaveFileName(parent, "Save key pair", os.path.join(sshkeys.ssh_folder(), sshkeys.FILE_NAMES.get(kind, "id_key")))
    if not path:
        return ""
    sshkeys.write_private(path, private_text)
    sshkeys.write_public(path + ".pub", line)
    return path


def _save_ppk(parent, key, comment, passphrase, name):
    path, _ = QFileDialog.getSaveFileName(parent, "Save for PuTTY", os.path.join(sshkeys.ssh_folder(), name + ".ppk"),
                                          "PuTTY private key (*.ppk)")
    if path:
        sshkeys.write_private(path, sshkeys.ppk(key, comment, passphrase))
    return path


# =============================================================================== make a key pair
class GenerateKeys(_Base):
    made = Signal(str)                      # the new public key line (Put on a device offers it)

    def __init__(self):
        super().__init__()
        self.key = None
        self.kind = QComboBox()
        for k, label, _sizes in sshkeys.TYPES:
            self.kind.addItem(label, k)
        self.size = QComboBox()
        self.size_label = QLabel("Size")
        self.comment = QLineEdit(sshkeys.default_comment())
        self.comment.setToolTip("Shown at the end of the public key, to tell keys apart")
        _fixed(self.comment, 300)
        self.pass1, self.pass2 = _fixed(_secret("")), _fixed(_secret(""))
        self.go = _primary("Generate key pair")
        self.status = _muted("")
        self.public = _line_box()
        self.fp = QLabel("")
        self.fp.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.private = _text("The private key appears here. Keep it secret.", 150)
        self.private.setReadOnly(True)
        self.copy_pub, self.save_pair, self.save_pub, self.save_ppk = (_button("Copy public key"), _button("Save key pair..."),
                                                                       _button("Save public key..."), _button("Save for PuTTY (.ppk)..."))
        lay = QVBoxLayout(self)
        lay.addWidget(_muted("Make a key pair for signing in over SSH without a password. Put the public key on the device (in "
                             "~/.ssh/authorized_keys, or the device's admin page) and keep the private key on this computer."))
        lay.addLayout(_row("Key type", self.kind, self.size_label, self.size))
        hint = _muted("Shown at the end of the public key, to tell keys apart")
        hint.setWordWrap(False)
        lay.addLayout(_row("Comment", self.comment, hint))
        lay.addLayout(_row("Passphrase", self.pass1, "Confirm passphrase", self.pass2))
        lay.addWidget(_muted("Optional. Locks the private key file; you're asked for it when the key is used."))
        lay.addLayout(_row(self.go))
        lay.addWidget(self.status)
        lay.addWidget(QLabel("<b>Public key</b>"))
        lay.addWidget(self.public)
        lay.addLayout(_row("Fingerprint", self.fp))
        lay.addWidget(QLabel("<b>Private key</b>"))
        lay.addWidget(self.private, 1)
        lay.addLayout(_row(self.copy_pub, self.save_pair, self.save_pub, self.save_ppk))
        self.kind.currentIndexChanged.connect(self._sizes)
        self.go.clicked.connect(self.generate)
        self.copy_pub.clicked.connect(lambda: QApplication.clipboard().setText(self.public.text()))
        self.save_pair.clicked.connect(self.save)
        self.save_pub.clicked.connect(self.save_public)
        self.save_ppk.clicked.connect(self.save_putty)
        self._sizes()
        self._ready(False)

    def _sizes(self, *_):
        kind = self.kind.currentData()
        sizes = next(s for k, _l, s in sshkeys.TYPES if k == kind)
        self.size.clear()
        for b in sizes:
            self.size.addItem(f"{b} bits", b)
        if sizes:
            self.size.setCurrentIndex(sizes.index(sshkeys.DEFAULT_BITS[kind]))
        self.size.setVisible(bool(sizes))
        self.size_label.setVisible(bool(sizes))

    def _ready(self, on):
        for b in (self.copy_pub, self.save_pair, self.save_pub, self.save_ppk):
            b.setEnabled(on)

    def generate(self):
        if self.pass1.text() != self.pass2.text():
            self.status.setText(MISMATCH)
            return
        kind, bits, comment, pp = self.kind.currentData(), self.size.currentData(), self.comment.text().strip(), self.pass1.text()
        self.go.setEnabled(False)
        self.status.setText("Making the key...")

        def work():
            key = sshkeys.generate(kind, bits)
            return key, sshkeys.openssh_private(key, comment, pp)

        def done(result):
            self.go.setEnabled(True)
            self.key, text = result
            self.made_kind, self.made_comment, self.made_pass = kind, comment, pp
            self.public.setText(sshkeys.public_line(self.key, comment))
            self.public.setCursorPosition(0)
            self.fp.setText(sshkeys.fingerprint(self.key))
            self.private.setPlainText(text)
            k, b = sshkeys.kind_of(self.key)
            self.status.setText(f"Made an {sshkeys.label_of(k)} key ({b} bits){', locked with the passphrase' if pp else ''}.")
            self._ready(True)
            audit.log("ssh key made", f"{sshkeys.label_of(k)} {b} {self.fp.text()}")
            self.made.emit(self.public.text())
        self._run(work, done)
        if self.job is not None:
            self.job.finished.connect(lambda: self.go.setEnabled(True))

    def save(self):
        path = _save_pair(self, self.made_kind, self.private.toPlainText(), self.public.text())
        if path:
            folder, name = os.path.split(path)
            self.status.setText(f"Saved {name} and {name}.pub to {folder}.")

    def save_public(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save public key",
                                              os.path.join(sshkeys.ssh_folder(), sshkeys.FILE_NAMES.get(self.made_kind, "id_key") + ".pub"))
        if path:
            sshkeys.write_public(path, self.public.text())
            self.status.setText(f"Saved {os.path.basename(path)} to {os.path.dirname(path)}.")

    def save_putty(self):
        path = _save_ppk(self, self.key, self.made_comment, self.made_pass, sshkeys.FILE_NAMES.get(self.made_kind, "id_key"))
        if path:
            self.status.setText(f"Saved {os.path.basename(path)} to {os.path.dirname(path)}.")


# =============================================================================== read a key
class NewPassphrase(QDialog):
    """Change passphrase...: the new one, twice."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Change passphrase")
        self.first, self.second = QLineEdit(), QLineEdit()
        for w in (self.first, self.second):
            w.setEchoMode(QLineEdit.EchoMode.Password)
            w.textChanged.connect(lambda _t: self.error.hide())
        self.error = QLabel(MISMATCH)
        self.error.setStyleSheet("color:#d32f2f;")
        self.error.hide()
        form = QFormLayout()
        form.addRow("New passphrase", self.first)
        form.addRow("Confirm new passphrase", self.second)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        ok = buttons.addButton("Change", QDialogButtonBox.ButtonRole.AcceptRole)
        ok.setProperty("primary", True)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(self.error)
        lay.addWidget(buttons)

    def accept(self):
        if not self.first.text() or self.first.text() != self.second.text():
            self.error.setText(MISMATCH if self.first.text() else "Enter the new passphrase.")
            self.error.show()
            return
        super().accept()

    def passphrase(self):
        return self.first.text()


class ReadKey(_Base):
    read_line = Signal(str)                 # the public key line of the key just read (Put on a device offers it)

    def __init__(self):
        super().__init__()
        self.info, self.path = None, ""
        self._loading = False                # True while Toner itself fills the box (an opened file keeps its path)
        self.text = _text("Paste a private key, a .ppk file or a public key line, or open a key file.", 120)
        self.open_btn = _button("Open...")
        self.passphrase = _fixed(_secret("its passphrase, if it has one"))
        self.go = _primary("Read")
        self.status = _muted("")
        self.kind, self.size, self.fp, self.comment = QLabel(), QLabel(), QLabel(), QLabel()
        self.public = _line_box()
        self.copy_pub, self.change, self.remove, self.save_ppk = (_button("Copy public key"), _button("Change passphrase..."),
                                                                  _button("Remove passphrase"), _button("Save for PuTTY (.ppk)..."))
        form = QFormLayout()
        for label, w in (("Type", self.kind), ("Size", self.size), ("Fingerprint", self.fp), ("Comment", self.comment), ("Public key", self.public)):
            form.addRow(label, w)
        lay = QVBoxLayout(self)
        lay.addWidget(_muted("Open or paste a key, private or public, to see its type, size, fingerprint and public-key line."))
        lay.addWidget(self.text, 1)
        lay.addLayout(_row(self.open_btn, self.passphrase, self.go))
        lay.addWidget(self.status)
        lay.addLayout(form)
        lay.addLayout(_row(self.copy_pub, self.change, self.remove, self.save_ppk))
        self.open_btn.clicked.connect(self.open_file)
        self.go.clicked.connect(self.read)
        self.passphrase.returnPressed.connect(self.read)
        self.text.textChanged.connect(lambda: setattr(self, "path", "") if not self._loading else None)
        self.copy_pub.clicked.connect(lambda: QApplication.clipboard().setText(self.public.text()))
        self.change.clicked.connect(self.change_passphrase)
        self.remove.clicked.connect(self.remove_passphrase)
        self.save_ppk.clicked.connect(self.save_putty)
        self._show(None)

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open a key", sshkeys.ssh_folder())
        if not path:
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read(200_000)
        except OSError as e:
            self.status.setText(f"Couldn't open {os.path.basename(path)}: {e.strerror or e}")
            return
        self._loading = True
        self.text.setPlainText(text)
        self._loading = False
        self.path = path
        self.read()

    def _show(self, info):
        self.info = info
        has = info is not None
        self.kind.setText(f"{sshkeys.label_of(info['kind'])}  ({info['form']}{', locked with a passphrase' if info['encrypted'] else ''})" if has else "")
        self.size.setText(f"{info['bits']} bits" if has else "")
        self.fp.setText(sshkeys.fingerprint(info["public"]) if has else "")
        self.comment.setText(info["comment"] if has else "")
        self.public.setText(sshkeys.public_line(info["public"], info["comment"]) if has else "")
        self.public.setCursorPosition(0)
        private = has and info["key"] is not None
        self.copy_pub.setEnabled(has)
        self.change.setEnabled(private)
        self.remove.setEnabled(private and info["encrypted"])
        self.save_ppk.setEnabled(private)

    def read(self):
        try:
            info = sshkeys.read(self.text.toPlainText(), self.passphrase.text())
        except ValueError as e:
            self._show(None)
            self.status.setText(str(e))
            return
        self._show(info)
        self.status.setText(f"Read {os.path.basename(self.path)}." if self.path else "")
        self.read_line.emit(self.public.text())

    def _rewrite(self, passphrase, done_text):
        """The key in OpenSSH's format with its new passphrase (or none): back into its file when it came from one."""
        text = sshkeys.openssh_private(self.info["key"], self.info["comment"], passphrase)
        if self.path:
            if QMessageBox.question(self, "Save the key", f"Save {os.path.basename(self.path)} with this change?") != QMessageBox.StandardButton.Yes:
                return
            sshkeys.write_private(self.path, text)
        self._loading = True
        self.text.setPlainText(text)
        self._loading = False
        self.passphrase.setText(passphrase)
        self.read()
        self.status.setText(done_text.format(name=os.path.basename(self.path)) if self.path else
                            "The key above has the change; copy it or save it.")
        audit.log("ssh key passphrase changed", sshkeys.fingerprint(self.info["public"]))

    def change_passphrase(self):
        dlg = NewPassphrase(self)
        if dlg.exec():
            self._rewrite(dlg.passphrase(), "Saved {name} with its new passphrase.")

    def remove_passphrase(self):
        self._rewrite("", "Removed the passphrase from {name}.")

    def save_putty(self):
        name = os.path.splitext(os.path.basename(self.path))[0] if self.path else sshkeys.FILE_NAMES.get(self.info["kind"], "id_key")
        path = _save_ppk(self, self.info["key"], self.info["comment"], self.passphrase.text() if self.info["encrypted"] else "", name)
        if path:
            self.status.setText(f"Saved {os.path.basename(path)} to {os.path.dirname(path)}.")


# =============================================================================== put a public key on a device
class DeployWorker(QThread):
    line = Signal(str)
    finished_ok = Signal(bool)

    def __init__(self, job):
        super().__init__()
        self.job = job

    def run(self):
        j, ok, client, extra = self.job, False, None, []
        try:
            self.line.emit(f"Connecting to {j['host']}:{j['port']} as {j['user']}...")
            client, extra = scp.connect(j["host"], j["port"], j["user"], j["password"], j["dev"], j["hostkey_mode"], j["timeout"])
            result = sshkeys.add_to_device(client, j["line"], j["timeout"])
            self.line.emit(f"Added the key to {j['name']}'s ~/.ssh/authorized_keys." if result == "added"
                           else f"{j['name']} already has this key; nothing changed.")
            ok = True
        except paramiko.BadHostKeyException:
            self.line.emit(f"HOST KEY CHANGED for {j['host']}. It does not match the key saved earlier: the device may have been "
                           "replaced or reset, or something is impersonating it. Nothing was changed. If the change is expected, "
                           "forget the saved key under Settings > Security.")
        except paramiko.AuthenticationException:
            self.line.emit("Login failed: the device did not accept the user name and password.")
        except Exception as e:
            self.line.emit(f"Failed: {e}" if isinstance(e, ValueError) else f"Failed: {type(e).__name__}: {e}")
        finally:
            if client:
                client.close()
            for c in extra:
                try:
                    c.close()
                except Exception:
                    pass
            self.finished_ok.emit(ok)


class DeployKey(QWidget):
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
        self.key = QLineEdit()
        self.key.setPlaceholderText("ssh-ed25519 AAAA... comment")
        self.key.setFont(_text().font())
        self.open_btn = _button("Open .pub...")
        self.go = _primary("Add to device")
        self.out = OutputBox()
        lay = QVBoxLayout(self)
        lay.addWidget(_muted("Adds the public key to the device's ~/.ssh/authorized_keys over SSH, like ssh-copy-id, using the "
                             "device's saved login, jump host and proxy. For Linux, macOS and other Unix-like systems; most network "
                             "devices take keys on their own admin page instead."))
        _fixed(self.user, 200)
        _fixed(self.password, 200)
        lay.addLayout(_row("Device", self.picker))
        lay.addLayout(_row("Host", self.host, "Port", self.port, "User", self.user, "Password", self.password))
        lay.addLayout(_row("Public key", self.key, self.open_btn))
        lay.addLayout(_row(self.go))
        lay.addWidget(self.out, 1)
        self.picker.currentIndexChanged.connect(self.picked)
        self.open_btn.clicked.connect(self.open_pub)
        self.go.clicked.connect(self.start)
        self.password.returnPressed.connect(self.start)
        self.picked()

    def offer(self, line):
        """A key just made or read: offered here unless one is already typed in."""
        if line and not self.key.text().strip():
            self.key.setText(line)
            self.key.setCursorPosition(0)

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

    def open_pub(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open a public key", sshkeys.ssh_folder(), "Public keys (*.pub);;All files (*)")
        if not path:
            return
        try:
            info = sshkeys.read(open(path, encoding="utf-8", errors="replace").read(200_000))
        except (OSError, ValueError) as e:
            self.out.line(f"Error: {e}")
            return
        self.key.setText(sshkeys.public_line(info["public"], info["comment"]))
        self.key.setCursorPosition(0)

    def running(self):
        return bool(self.worker and self.worker.isRunning())

    def start(self):
        if self.running():
            return
        from core import nettools
        try:
            host = nettools.check_host(self.host.text())
            sshkeys.authorized_keys_command(self.key.text())
        except ValueError as e:
            self.out.line(f"Error: {e}")
            return
        user = self.user.text().strip()
        if not user:
            self.out.line("Error: Enter a user name.")
            return
        dev = self.picker.currentData()
        job = {"host": host, "port": self.port.value(), "user": user, "password": self.password.text() or self.stored_password(),
               "dev": profiles.resolve(dev) if dev else None, "line": " ".join(self.key.text().split()),
               "name": dev["name"] if dev else host, "hostkey_mode": db.get_setting("hostkey_mode"),
               "timeout": int(db.get_setting("ssh_timeout"))}
        self.go.setEnabled(False)
        self.worker = DeployWorker(job)
        self.worker.line.connect(self.out.line)
        self.worker.finished_ok.connect(lambda ok, job=job: self._done(ok, job))
        self.worker.start()

    def _done(self, ok, job):
        self.go.setEnabled(True)
        audit.log("ssh key added to device" + ("" if ok else " failed"), f"{job['name']}: {sshkeys.fingerprint(sshkeys.read(job['line'])['public'])}")

    def refresh(self):
        self.picker.refresh()

    def shutdown(self):
        if self.running():
            self.worker.wait(5000)


# =============================================================================== the page
class SshKeysTab(QWidget):
    def __init__(self):
        super().__init__()
        self.generate, self.reader, self.deploy = GenerateKeys(), ReadKey(), DeployKey()
        self.picker = self.deploy.picker
        self.tabs = QTabWidget()
        for w, label in ((self.generate, "Make a key pair"), (self.reader, "Read a key"), (self.deploy, "Put on a device")):
            self.tabs.addTab(w, label)
        self.generate.made.connect(self.deploy.offer)
        self.reader.read_line.connect(self.deploy.offer)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.tabs)

    def shutdown(self):
        self.generate.shutdown()
        self.reader.shutdown()
        self.deploy.shutdown()
