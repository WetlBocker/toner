"""The Directory dialog (Settings > Accounts and sign-in > Directories): one directory's settings. Test connection and Save talk
to the directory on a Job thread. Save turns the group names into the DNs the server writes (only those are stored), then signs
the list with roles.set_directories. The service password goes to the vault and Duo's secret key to the OS protected store;
neither is ever in netcheck.keys, a log, the audit or a message. An empty password box on Edit keeps the stored password."""
import hashlib
import secrets

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QDialog, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit,
                               QPushButton, QScrollArea, QSpinBox, QVBoxLayout, QWidget)

from core import datakey, directory, dirpin, osstore, passvault, perms, roles
from ui import status
from ui.settings_base import note
from ui.signinwindow import Job, primary, say

CONNECTED = "Connected. Found {n} groups."
FAILED = "Toner couldn't connect: {reason}"
NO_STORE = "This computer has no protected store, so Duo can't be turned on here."
NO_GROUP = "Toner couldn't find a group named {name}."
TWO_GROUPS = "More than one group is named {name}. Type its full DN instead."
TAKEN = "Another directory already uses {value}."
CA_UNREADABLE = "Toner can't read that CA file."
CA_CHANGED = "The directory's CA file changed. An admin needs to save the directory again."
KINDS = (("Active Directory", "ad"), ("LDAP", "ldap"))
SECURITY = (("LDAPS", "ldaps", 636), ("StartTLS", "starttls", 389))
ROLES = directory.ROLE_ORDER


class Said(Exception):
    """Already in the approved words."""


def service_key(directory_id):
    return f"service:directory-{directory_id}"


def words(e):
    """What to show for a failed Test connection or Save. Never a secret: directory's messages hold none."""
    if isinstance(e, Said):
        return str(e)
    if isinstance(e, directory.CaChanged):
        return CA_CHANGED
    if isinstance(e, directory.NotFound):
        return NO_GROUP.format(name=e.args[0])
    if isinstance(e, directory.Ambiguous):
        return TWO_GROUPS.format(name=e.args[0])
    known = (directory.InsecureConfig, directory.Unreachable, directory.BadCredentials)
    return FAILED.format(reason=str(e) if isinstance(e, known) else type(e).__name__)


def with_ca(cfg, signed=None):
    """`cfg` ready to connect (on the Job's thread: a CA path may be slow to open). A CA file is read here, and its SHA-256 is
    `signed` (the hash in the signed list, so a changed file is caught) or else the file's own (one just chosen, or a Save)."""
    if cfg.get("ca_file"):
        try:
            with open(cfg["ca_file"], "rb") as f:
                data = f.read()
        except OSError:
            raise Said(CA_UNREADABLE) from None
        cfg["ca_sha256"] = signed or hashlib.sha256(data).hexdigest()
    return cfg


def _split(text):
    """Comma-separated values, trimmed, each once (case aside)."""
    out = {}
    for v in (x.strip() for x in text.split(",")):
        if v:
            out.setdefault(v.casefold(), v)
    return list(out.values())


class DirectoryDialog(QDialog):
    """Add a directory (cfg None) or edit `cfg`, one of `dirs` (the verified list). Saving writes the whole list and accepts."""

    def __init__(self, dirs, cfg=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Directory")
        self.setMinimumSize(560, 600)
        self.dirs, self.orig = list(dirs), cfg
        self.id = cfg["id"] if cfg else secrets.token_hex(8)
        self.ca_path = ""
        self._jobs = set()
        self._closed = False
        self.store = None                                    # the protected store: unknown until asked off this thread

        body = QWidget()
        self.form = QFormLayout(body)
        self.name = self._row("Name", QLineEdit())
        self.kind = self._row("Kind", QComboBox())
        self.kind.addItems([t for t, _ in KINDS])
        self.servers = self._row("Servers", QLineEdit())
        self.servers.setPlaceholderText("One or more, separated by commas")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(636)
        self._row("Port", self.port)
        self.security = self._row("Security", QComboBox())
        self.security.addItems([t for t, _, _ in SECURITY])
        self.security.currentIndexChanged.connect(self._security)
        self.cert, self.ca_label = QComboBox(), note("")
        self.cert.addItems(["System trust store", "CA file..."])
        self.cert.currentIndexChanged.connect(self._cert)
        self._row("Certificate", self.cert, self.ca_label)
        self.base_dn = self._row("Base DN", QLineEdit())
        self.netbios = self._row("Domain (NetBIOS)", QLineEdit())
        self.suffixes = self._row("Email and UPN suffixes", QLineEdit())
        self.suffixes.setPlaceholderText("Separated by commas")
        self.service_dn = self._row("Service account", QLineEdit())
        self.service_pw = self._row("Service account password", QLineEdit())
        self.service_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.groups = {}
        for role in ROLES:
            box = QPlainTextEdit()
            box.setPlaceholderText("Group names, one per line")
            box.setTabChangesFocus(True)
            box.setFixedHeight(64)
            self.groups[role] = self._row(f"{role} groups", box)
        self.second, self.duo_note = QComboBox(), note(NO_STORE)
        self.second.addItems(["Off", "Duo"])
        self.second.model().item(1).setEnabled(False)
        self.duo_note.hide()
        self._row("Second step", self.second, self.duo_note)
        self.duo_host = self._row("Duo API hostname", QLineEdit())
        self.duo_ikey = self._row("Integration key", QLineEdit())
        self.duo_skey = self._row("Secret key", QLineEdit())
        self.duo_skey.setEchoMode(QLineEdit.EchoMode.Password)
        self.second.currentIndexChanged.connect(self._duo_fields)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(body)
        self.message = QLabel()
        self.message.setWordWrap(True)
        self.message.hide()
        self.test_btn, self.save_btn = QPushButton("Test connection"), primary("Save")
        self.test_btn.setAutoDefault(False)
        self.test_btn.clicked.connect(self._test)
        self.save_btn.clicked.connect(self._save)
        buttons = QHBoxLayout()
        buttons.addWidget(self.test_btn)
        buttons.addStretch(1)
        buttons.addWidget(self.save_btn)
        lay = QVBoxLayout(self)
        lay.addWidget(scroll)
        lay.addWidget(self.message)
        lay.addLayout(buttons)

        if cfg:
            self._show(cfg)
        self._duo_fields()
        if dirpin._avail is None:                            # a Secret Service nobody unlocks takes 3 seconds to say no
            self._run(dirpin._store, lambda r, e: self._store_known(e is None and bool(r)), block=False)
        else:
            self._store_known(dirpin._avail)

    def _row(self, text, widget, under=None):
        widget.setAccessibleName(text)
        field = widget
        if under is not None:
            field = QWidget()
            v = QVBoxLayout(field)
            v.setContentsMargins(0, 0, 0, 0)
            v.addWidget(widget)
            v.addWidget(under)
        lab = QLabel(text)
        lab.setBuddy(widget)
        self.form.addRow(lab, field)
        return widget

    def _show(self, cfg):
        self.name.setText(cfg.get("name", ""))
        self.kind.setCurrentIndex(1 if cfg.get("kind") == "ldap" else 0)
        self.servers.setText(", ".join(cfg.get("servers") or []))
        self.security.setCurrentIndex(1 if cfg.get("security") == "starttls" else 0)
        self.port.setValue(int(cfg.get("port") or 636))
        if cfg.get("ca_file"):
            self.cert.blockSignals(True)
            self.cert.setCurrentIndex(1)
            self.cert.blockSignals(False)
            self.ca_path = cfg["ca_file"]
            self.ca_label.setText(self.ca_path)
        self.base_dn.setText(cfg.get("base_dn", ""))
        self.netbios.setText(cfg.get("netbios") or "")
        self.suffixes.setText(", ".join(cfg.get("suffixes") or []))
        self.service_dn.setText(cfg.get("service_dn") or "")
        for role, box in self.groups.items():
            box.setPlainText("\n".join((cfg.get("groups") or {}).get(role) or []))
        duo = cfg.get("duo") or {}
        self.second.setCurrentIndex(1 if duo.get("on") else 0)
        self.duo_host.setText(duo.get("host") or "")
        self.duo_ikey.setText(duo.get("ikey") or "")

    # ---------------------------------------------------------------- what the boxes do
    def _security(self, i):
        """The other mode's usual port follows the switch; any other port is left as typed."""
        if self.port.value() == SECURITY[1 - i][2]:
            self.port.setValue(SECURITY[i][2])

    def _cert(self, i):
        if i == 1:
            path, _ = QFileDialog.getOpenFileName(self, "")
            if not path and not self.ca_path:
                self.cert.blockSignals(True)
                self.cert.setCurrentIndex(0)
                self.cert.blockSignals(False)
            self.ca_path = path or self.ca_path
        else:
            self.ca_path = ""
        self.ca_label.setText(self.ca_path)

    def _store_known(self, available):
        self.store = available
        self.second.model().item(1).setEnabled(available)
        self.duo_note.setVisible(not available)
        self._duo_fields()

    def _duo_fields(self):
        on = self.second.currentIndex() == 1
        for box in (self.duo_host, self.duo_ikey):
            box.setEnabled(on)
        self.duo_skey.setEnabled(on and bool(self.store))

    # ---------------------------------------------------------------- the settings as typed
    def _cfg(self):
        cfg = {"id": self.id, "name": self.name.text().strip(), "kind": KINDS[self.kind.currentIndex()][1],
               "servers": _split(self.servers.text()), "port": self.port.value(), "security": SECURITY[self.security.currentIndex()][1],
               "ca_file": self.ca_path, "base_dn": self.base_dn.text().strip(), "netbios": self.netbios.text().strip(),
               "suffixes": _split(self.suffixes.text()), "service_dn": self.service_dn.text().strip(),
               "groups": dict((self.orig or {}).get("groups") or {}),
               "duo": {"on": self.second.currentIndex() == 1, "host": self.duo_host.text().strip(), "ikey": self.duo_ikey.text().strip()}}
        return cfg

    def _names(self):
        return {role: [n.strip() for n in box.toPlainText().splitlines() if n.strip()] for role, box in self.groups.items()}

    def _password(self):
        """The one typed, or (editing) the one in the vault."""
        if self.service_pw.text() or not self.orig:
            return self.service_pw.text()
        try:
            return passvault.get(service_key(self.id)) or ""
        except passvault.Locked:
            return ""

    def _taken(self, cfg):
        """A NetBIOS name or suffix another directory already has (as typed), else None."""
        others = [d for d in self.dirs if d.get("id") != self.id]
        for field in ("netbios", "suffixes"):
            vals = lambda d: [d.get(field)] if field == "netbios" else list(d.get(field) or [])
            used = {str(v).casefold() for d in others for v in vals(d) if v}
            hit = next((v for v in vals(cfg) if v and v.casefold() in used), None)
            if hit:
                return hit
        return None

    # ---------------------------------------------------------------- Test connection and Save
    def _run(self, fn, landed, block=True):
        job = Job(fn)
        job.landed, job.block = landed, block
        if block:
            self.test_btn.setEnabled(False)
            self.save_btn.setEnabled(False)
        job.done.connect(self._landed, Qt.ConnectionType.QueuedConnection)
        self._jobs.add(job)
        job.start()

    def _landed(self, job, result, error):
        job.wait()
        job.fn = None                                        # (its closure holds the service password)
        self._jobs.discard(job)
        if job.block:
            self.test_btn.setEnabled(True)
            self.save_btn.setEnabled(True)
        if not self._closed:                                 # (a Save landing after Close writes nothing)
            job.landed(result, error)

    def _say(self, text, good=False):
        self.message.setStyleSheet("" if good else f"color: {status.ink('FAIL')};")
        say(self.message, text)

    def _test(self):
        cfg, pw = self._cfg(), self._password()
        same = self.orig and self.orig.get("ca_file") and self.orig.get("ca_file") == cfg["ca_file"]
        signed = self.orig.get("ca_sha256") if same else None
        self._say("")
        self._run(lambda: directory.test(with_ca(cfg, signed), pw),
                  lambda n, e: self._say(words(e)) if e is not None else self._say(CONNECTED.format(n=n), good=True))

    def _save(self):
        cfg, pw, names = self._cfg(), self._password(), self._names()
        taken = self._taken(cfg)
        if taken:
            self._say(TAKEN.format(value=taken))
            return
        self._say("")
        wanted = list(dict.fromkeys(n for role in ROLES for n in names[role]))
        found = {}                                           # (a dict sent through the Job's signal aborts PySide6)
        self._run(lambda: found.update(directory.resolve_groups(with_ca(dict(cfg)), wanted, pw)),
                  lambda _r, e: self._saved(cfg, names, found, e))

    def _saved(self, cfg, names, found, error):
        if error is not None:
            self._say(words(error))
            return
        cfg["groups"] = {role: list(dict.fromkeys(found[n] for n in names[role])) for role in ROLES}
        new = [cfg if d.get("id") == self.id else d for d in self.dirs] + ([] if self.orig else [cfg])
        try:
            roles.set_directories(new)                       # signs the CA file's hash in, and writes the audit row
        except (ValueError, datakey.Locked, perms.Denied) as e:
            self._say(CA_UNREADABLE if str(e) == "the CA file can't be read" else str(e))
            return
        if self.service_pw.text():
            passvault.put(service_key(self.id), self.service_pw.text())
        if cfg["duo"]["on"] and self.duo_skey.text():
            osstore.put("duo:" + self.id, self.duo_skey.text().encode("utf-8"))
        self.service_pw.clear()
        self.duo_skey.clear()
        self.accept()

    def done(self, r):
        """A Job must not outlive its dialog."""
        self._closed = True
        for job in list(self._jobs):
            job.wait()
        self._jobs.clear()
        self.service_pw.clear()
        self.duo_skey.clear()
        super().done(r)
