"""The External Identities flow (Settings > Accounts > Add; Edit opens it filled in, the type fixed): five steps on one stack.
Step 3's Next connects on a Job and reads the base DN, the NetBIOS name, the DNS domain and the OUs and groups the service
account can see; step 4 ticks who can sign in; step 5 gives each a role, and Save signs the list (roles.set_directories). Only
DNs the server wrote are stored. The service password is taken from its box when Next or Save is clicked, goes to the vault
only, and the box is cleared on Save and on close. Duo isn't here: Set up 2FA owns cfg["duo"], which Edit keeps as it is."""
import secrets

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (QComboBox, QDialog, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QPushButton, QRadioButton, QScrollArea, QSpinBox, QStackedWidget, QVBoxLayout,
                               QWidget)

from core import datakey, directory, passvault, perms, roles
from ui import status
from ui.directorydlg import CA_UNREADABLE, KINDS, SECURITY, TAKEN, _netbios, _split, _taken, service_key, with_ca, words
from ui.settings_base import note
from ui.signinwindow import Job, heading, primary, say

TITLES = ("Choose a type", "Server and service account", "Connection", "Who can sign in", "Roles")
CONNECTED = "Connected. Choose who can sign in."
NONE_TICKED = "Choose at least one OU or group."
LISTS = (("ous", "OUs"), ("groups", "Groups"))
ROLES = directory.ROLE_ORDER
CAP = 5000                  # OUs and groups loaded at step 3; past it a filter box also searches the directory
PAUSE_MS = 400              # typing pauses this long before that search
CHECKED, UNCHECKED = Qt.CheckState.Checked, Qt.CheckState.Unchecked


def _row(form, text, widget, under=None):
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
    form.addRow(lab, field)
    return widget


def _plain(text):
    lab = QLabel(text)
    lab.setTextFormat(Qt.TextFormat.PlainText)         # a DN is the server's text, never markup
    return lab


class IdentityWizard(QDialog):
    """Add an identity (cfg None) or edit `cfg`, one of `dirs` (the verified list). exec() is truthy after a Save."""

    def __init__(self, dirs, cfg=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("External Identities")
        self.setMinimumSize(640, 560)
        self.dirs, self.orig = list(dirs), cfg
        saved = cfg or {}
        self.id = saved.get("id") or secrets.token_hex(8)
        self.ca_path, self.ca_picked = saved.get("ca_file") or "", False
        self._jobs, self._closed = set(), False
        self._live, self.more, self._loaded = None, False, False     # step 3's (cfg, service password) for the searches
        self._target = None                                          # (servers, base DN) step 3 last connected to
        self._asked = {k: 0 for k, _ in LISTS}                       # a search's answer counts only while this is unchanged
        self._role = {}                                              # DN key -> role chosen (Edit: as saved; the highest wins)
        self._saved_ticks = {}
        for kind, _ in LISTS:
            m = saved.get(kind) or {}
            self._saved_ticks[kind] = [dn for r in ROLES for dn in m.get(r) or []]
            for r in reversed(ROLES):
                self._role.update((directory._key(dn), r) for dn in m.get(r) or [])
        self.stack = QStackedWidget()

        page = QWidget()                                             # 1: the type
        lay = QVBoxLayout(page)
        self.kinds = [QRadioButton(t) for t, _ in KINDS]
        for r in self.kinds:
            r.setEnabled(cfg is None)
            lay.addWidget(r)
        self.kinds[1 if saved.get("kind") == "ldap" else 0].setChecked(True)
        lay.addStretch(1)
        self.stack.addWidget(page)

        form = self._form()                                          # 2: the server and service account
        self.servers = _row(form, "Host name, IP address or FQDN", QLineEdit(", ".join(saved.get("servers") or [])))
        self.service_dn = _row(form, "Service account", QLineEdit(saved.get("service_dn") or ""))
        self.service_pw = _row(form, "Password", QLineEdit())
        self.service_pw.setEchoMode(QLineEdit.EchoMode.Password)

        form = self._form()                                          # 3: the connection
        self.security = _row(form, "Security", QComboBox())
        self.security.addItems([t for t, _, _ in SECURITY])
        self.security.setCurrentIndex(1 if saved.get("security") == "starttls" else 0)
        self.security.currentIndexChanged.connect(self._security)
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(int(saved.get("port") or 636))
        _row(form, "Port", self.port)
        self.cert, self.ca_label = QComboBox(), note(self.ca_path)
        self.cert.addItems(["System trust store", "CA file..."])
        self.cert.setCurrentIndex(1 if self.ca_path else 0)
        self.cert.activated.connect(self._cert)           # (not currentIndexChanged: choosing CA file... again re-opens the picker)
        _row(form, "Certificate", self.cert, self.ca_label)

        page = QWidget()                                             # 4: who can sign in
        cols = QHBoxLayout(page)
        self.headings, self.filters, self.lists, self._timers = [], {}, {}, {}
        for kind, text in LISTS:
            col = QVBoxLayout()
            h, box, lst = QLabel(text), QLineEdit(), QListWidget()
            h.setStyleSheet("font-weight: 600;")
            h.setBuddy(box)
            box.setAccessibleName(text)
            box.setClearButtonEnabled(True)
            lst.setAccessibleName(text)
            lst.setUniformItemSizes(True)
            timer = QTimer(self)
            timer.setSingleShot(True)
            timer.setInterval(PAUSE_MS)
            timer.timeout.connect(lambda k=kind: self._search(k))
            box.textChanged.connect(lambda _t, k=kind: self._filter(k))
            for wgt in (h, box, lst):
                col.addWidget(wgt)
            cols.addLayout(col)
            self.headings.append(h)
            self.filters[kind], self.lists[kind], self._timers[kind] = box, lst, timer
        self.stack.addWidget(page)

        page = QWidget()                                             # 5: roles, then the settings read at step 3
        lay = QVBoxLayout(page)
        host = QWidget()
        self.role_form = QFormLayout(host)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(host)
        lay.addWidget(scroll, 1)
        form = QFormLayout()
        lay.addLayout(form)
        self.name = _row(form, "Name", QLineEdit(saved.get("name") or ""))
        self.base_dn = _row(form, "Base DN", QLineEdit(saved.get("base_dn") or ""))
        self.netbios = _row(form, "Domain (NetBIOS)", QLineEdit(saved.get("netbios") or ""))
        self.suffixes = _row(form, "Email and UPN suffixes", QLineEdit(", ".join(saved.get("suffixes") or [])))
        self.role_boxes, self.role_labels = {}, {}
        self.stack.addWidget(page)

        self.title = heading()
        self.message = QLabel()
        self.message.setWordWrap(True)
        self.message.hide()
        self.back_btn, self.next_btn, self.save_btn = QPushButton("Back"), primary("Next"), primary("Save")
        self.back_btn.setAutoDefault(False)
        self.back_btn.clicked.connect(lambda: self._go(self.stack.currentIndex() - 1))
        self.next_btn.clicked.connect(self._next)
        self.save_btn.clicked.connect(self._save)
        buttons = QHBoxLayout()
        buttons.addWidget(self.back_btn)
        buttons.addStretch(1)
        buttons.addWidget(self.next_btn)
        buttons.addWidget(self.save_btn)
        outer = QVBoxLayout(self)
        outer.addWidget(self.title)
        outer.addWidget(self.stack, 1)
        outer.addWidget(self.message)
        outer.addLayout(buttons)
        self._go(0)

    def _form(self):
        page = QWidget()
        form = QFormLayout(page)
        self.stack.addWidget(page)
        return form

    # ---------------------------------------------------------------- moving between the steps
    def _go(self, i):
        self.stack.setCurrentIndex(i)
        self.title.setText(TITLES[i])
        self.back_btn.setVisible(i > 0)
        self.next_btn.setVisible(i < len(TITLES) - 1)
        self.save_btn.setVisible(i == len(TITLES) - 1)
        self._say("")

    def _next(self):
        i = self.stack.currentIndex()
        if i == 2:
            return self._connect()
        if i == 3:
            if not any(self._ticked(k) for k, _ in LISTS):
                return self._say(NONE_TICKED)
            self._fill_roles()
        self._go(i + 1)

    def _say(self, text, good=False):
        self.message.setStyleSheet("" if good else f"color: {status.ink('FAIL')};")
        say(self.message, text)

    # ---------------------------------------------------------------- step 3
    def _security(self, i):
        """The other mode's usual port follows the switch; any other port is left as typed."""
        if self.port.value() == SECURITY[1 - i][2]:
            self.port.setValue(SECURITY[i][2])

    def _cert(self, i):
        if i == 1:
            self._pick()
            if not self.ca_path:
                self.cert.setCurrentIndex(0)
        else:
            self.ca_path = ""
            self.ca_label.setText("")

    def _pick(self):
        """The file picker, starting at the CA file there is. A file chosen here is trusted: step 3 hashes it anew. True if chosen."""
        path, _ = QFileDialog.getOpenFileName(self, "", self.ca_path)
        if path:
            self.ca_picked, self.ca_path = True, path
            self.ca_label.setText(path)
        return bool(path)

    def _connect(self):
        cfg, pw = self._cfg(), self._password()
        refill = self._loaded and self._target is not None and self._servers(cfg) != self._target[0]   # another server: read anew
        # Edit, with the CA file not chosen again here: it must still be the one signed (else CA_CHANGED); choosing it is trusting it
        signed = self.orig.get("ca_sha256") if self.orig and not self.ca_picked else None
        got = {}                                             # (a dict sent through the Job's signal aborts PySide6)

        def run():
            directory.check_config(cfg)
            c = with_ca(cfg, signed)
            info = directory.discover(c, pw)
            c["base_dn"] = (not refill and c["base_dn"]) or info["base_dn"]
            got.update(info=info, tree=directory.tree(c, pw, cap=CAP), cfg=c)
        self._run(run, lambda _r, e: self._connected(got, pw, refill, e))

    @staticmethod
    def _servers(cfg):
        return tuple(directory._key(s) for s in cfg["servers"])

    def _connected(self, got, pw, refill, error):
        if error is not None:
            self._say(words(error))
            if isinstance(error, directory.CaChanged) and self._pick():     # the file chosen again is the one to trust
                self._connect()
            return
        info, found, c = got["info"], got["tree"], got["cfg"]
        target = (self._servers(c), directory._key(c["base_dn"]))
        moved = self._loaded and target != self._target
        self._live, self.more, self._target = (c, pw), found["more"], target
        for k in self._asked:                                # a search sent before this connection is stale
            self._asked[k] += 1
        for box, value in ((self.name, (info["suffixes"] or [""])[0]), (self.base_dn, c["base_dn"]),
                           (self.netbios, info["netbios"]), (self.suffixes, ", ".join(info["suffixes"]))):
            if refill or not box.text().strip():
                box.setText(value)
        for kind, _ in LISTS:
            keep = self._ticked(kind) if self._loaded else self._saved_ticks[kind]
            if moved:                                        # another server or base: only what it has (and, on Edit, what was saved)
                there = {directory._key(dn) for dn in found[kind]}
                keep = [dn for dn in keep if directory._key(dn) in there] + self._saved_ticks[kind]
            self.lists[kind].clear()
            self._add(kind, found[kind] + keep, {directory._key(dn) for dn in keep})
        self._loaded = True
        self._go(3)
        self._say(CONNECTED, good=True)

    # ---------------------------------------------------------------- step 4
    def _ticked(self, kind):
        lst = self.lists[kind]
        return [lst.item(i).text() for i in range(lst.count()) if lst.item(i).checkState() == CHECKED]

    def _add(self, kind, dns, tick=frozenset()):
        """Rows for the DNs not listed yet (ticked when their key is in `tick`); rows already there keep their ticks."""
        lst = self.lists[kind]
        have = {directory._key(lst.item(i).text()) for i in range(lst.count())}
        lst.setUpdatesEnabled(False)
        for dn in dns:
            key = directory._key(dn)
            if key in have:
                continue
            have.add(key)
            item = QListWidgetItem(dn)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(CHECKED if key in tick else UNCHECKED)
            lst.addItem(item)
        lst.setUpdatesEnabled(True)
        self._narrow(kind)

    def _narrow(self, kind):
        lst, low = self.lists[kind], self.filters[kind].text().strip().casefold()
        lst.setUpdatesEnabled(False)
        for i in range(lst.count()):
            lst.item(i).setHidden(bool(low) and low not in lst.item(i).text().casefold())
        lst.setUpdatesEnabled(True)

    def _filter(self, kind):
        """Narrows at once; a list that didn't load whole is also searched once typing pauses."""
        self._narrow(kind)
        self._asked[kind] += 1
        if self.more and self._live and self.filters[kind].text().strip():
            self._timers[kind].start()
        else:
            self._timers[kind].stop()

    def _search(self, kind):
        if self._closed or not self._live:
            return
        text, n, (cfg, pw) = self.filters[kind].text().strip(), self._asked[kind], self._live
        got = {}
        self._run(lambda: got.update(directory.tree(cfg, pw, cap=CAP, text=text)), lambda _r, e: self._found(kind, n, got, e), block=False)

    def _found(self, kind, n, got, error):
        if n != self._asked[kind]:                           # typed again since: a newer search answers
            return
        if error is not None:
            if self.stack.currentIndex() == 3:               # an error landing after step 4 was left is no longer about anything
                self._say(words(error))
            return
        self._add(kind, got[kind])

    # ---------------------------------------------------------------- step 5
    def _fill_roles(self):
        while self.role_form.rowCount():
            self.role_form.removeRow(0)
        self.role_boxes, self.role_labels = {}, {}
        for kind, _ in LISTS:
            for dn in self._ticked(kind):
                key, lab, box = directory._key(dn), _plain(dn), QComboBox()
                box.addItems(ROLES)
                box.setCurrentText(self._role.get(key, "Tech"))
                box.setAccessibleName(dn)
                box.currentTextChanged.connect(lambda r, k=key: self._role.__setitem__(k, r))
                lab.setBuddy(box)
                self.role_form.addRow(lab, box)
                self.role_boxes[dn], self.role_labels[dn] = box, lab

    # ---------------------------------------------------------------- the settings as typed, and Save
    def _cfg(self):
        kind = next(v for r, (_, v) in zip(self.kinds, KINDS) if r.isChecked())
        cfg = {"id": self.id, "name": self.name.text().strip(), "kind": kind, "servers": _split(self.servers.text()),
               "port": self.port.value(), "security": SECURITY[self.security.currentIndex()][1], "ca_file": self.ca_path,
               "base_dn": self.base_dn.text().strip(), "netbios": self.netbios.text().strip(), "suffixes": _split(self.suffixes.text()),
               "service_dn": self.service_dn.text().strip(),
               "duo": dict((self.orig or {}).get("duo") or {"on": False, "host": "", "ikey": ""})}     # Ruling R1
        for k, _ in LISTS:
            cfg[k] = {r: [dn for dn in self._ticked(k) if dn in self.role_boxes and self.role_boxes[dn].currentText() == r] for r in ROLES}
        return cfg

    def _password(self):
        """The one typed, or (editing) the one in the vault."""
        if self.service_pw.text() or not self.orig:
            return self.service_pw.text()
        try:
            return passvault.get(service_key(self.id)) or ""
        except passvault.Locked:
            return ""

    def _save(self):
        cfg, pw, typed = self._cfg(), self._password(), self.service_pw.text()   # as they are at the click, not when it lands
        taken = _taken(self.dirs, self.id, cfg)
        if taken:
            return self._say(TAKEN.format(value=taken))
        self._say("")
        got = []
        moved = directory._key(cfg["base_dn"]) != directory._key(self._live[0]["base_dn"])

        def look():
            c = with_ca(dict(cfg))
            if moved and not directory.has_entry(c, c["base_dn"], pw):     # a Base DN typed after step 3 must be there
                raise directory.Unreachable("no base DN found")
            got.extend(_netbios(c, pw))                      # a blank AD NetBIOS name is read; a failed read refuses (Ruling R4)
        self._run(look, lambda _r, e: self._saved(cfg, got, typed, e))

    def _saved(self, cfg, got, typed, error):
        if error is not None:
            return self._say(words(error))
        if got:
            cfg["netbios"] = got[0]
            self.netbios.setText(got[0])
            taken = _taken(self.dirs, self.id, cfg)
            if taken:
                return self._say(TAKEN.format(value=taken))
        new = [cfg if d.get("id") == self.id else d for d in self.dirs] + ([] if self.orig else [cfg])
        try:
            roles.set_directories(new, edited=self.id)       # hashes this one's CA file only; writes the audit row
        except (ValueError, datakey.Locked, perms.Denied) as e:
            return self._say(CA_UNREADABLE if str(e) == "the CA file can't be read" else str(e))
        if typed:
            passvault.put(service_key(self.id), typed)
        self.service_pw.setText("")
        self.accept()

    # ---------------------------------------------------------------- Jobs
    def _run(self, fn, landed, block=True):
        job = Job(fn)
        job.landed, job.block = landed, block
        if block:
            self._enable(False)
        job.done.connect(self._landed, Qt.ConnectionType.QueuedConnection)
        self._jobs.add(job)
        job.start()

    def _enable(self, on):
        for w in (self.stack, self.back_btn, self.next_btn, self.save_btn):
            w.setEnabled(on)

    def _landed(self, job, result, error):
        job.wait()
        landed, job.fn, job.landed = job.landed, None, None  # (their closures hold the service password)
        self._jobs.discard(job)
        if job.block and not self._closed:
            self._enable(True)
        if not self._closed:                                 # (a Save landing after Close writes nothing)
            landed(result, error)

    def done(self, r):
        """A Job must not outlive its dialog, nor the password its box."""
        self._closed = True
        for t in self._timers.values():
            t.stop()
        for job in list(self._jobs):
            job.wait()
        self._jobs.clear()
        self._live = None
        self.service_pw.setText("")
        super().done(r)
