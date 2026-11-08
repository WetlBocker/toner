"""The External Identities flow (Settings > Accounts > Add; Edit opens it filled in, the type fixed): five steps on one stack.
Step 3's Next connects on a Job and reads the base DN, the NetBIOS name, the DNS domain and the OUs and groups the service
account can see; step 4 ticks who can sign in; step 5 gives each a role, and Save signs the list (roles.set_directories). Only
DNs the server wrote are stored. The service password is taken from its box when Next or Save is clicked, goes to the vault
only, and the box is cleared on Save and on close. Duo isn't here: Set up 2FA owns cfg["duo"], which Edit keeps as it is.

An SSO connection (kind "oidc") has its own steps 2 to 4 (Provider, Connection, Who can sign in) and shares step 5. Its Next on
Connection reads the provider's discovery document. Entra lists and searches groups with an Entra admin's sign-in, whose access token
stays on this window only; other providers' groups are typed; no groups claim means one role for everyone. A client secret goes to
the protected store on Save, only when typed (Edit with the box empty keeps the stored one)."""
import secrets
import threading
import webbrowser

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (QComboBox, QDialog, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QPlainTextEdit, QPushButton, QRadioButton, QScrollArea, QSpinBox, QStackedWidget,
                               QVBoxLayout, QWidget)

from core import datakey, directory, oidc, osstore, passvault, perms, roles, ssopresets
from core.dirsignin import UNREACHABLE, sso_said
from ui import status
from ui.directorydlg import CA_UNREADABLE, KINDS, SECURITY, TAKEN, Said, _netbios, _split, _taken, service_key, with_ca, words
from ui.settings_base import note
from ui.signinwindow import Job, heading, primary, say

TITLES = ("Choose a type", "Server and service account", "Connection", "Who can sign in", "Roles")
SSO_TITLES = ("Choose a type", "Provider", "Connection", "Who can sign in", "Roles")
SECRET = "Client secret (only if the provider requires one)"
FOUND = "Toner found {provider}'s sign-in settings."
NOT_FOUND = "Toner couldn't read sign-in settings from {url}."
LIST_GROUPS = "Sign in to list groups"
LIST_GROUPS_TEXT = ("Sign in with an Entra admin account. Toner uses it only to list and search groups, and keeps nothing but the "
                    "groups you choose.")
TYPE_GROUPS_TEXT = "Type each group exactly as {provider} sends it, one per line."
EVERYONE = "Role for everyone who signs in"
GRAPH_SCOPES = "openid profile GroupMember.Read.All"
GROUP_ID = Qt.ItemDataRole.UserRole                 # an Entra group row's id (its text is the group's name)
CONNECTED = "Connected. Choose who can sign in."
NONE_TICKED = "Choose at least one OU or group."
NONE_SSO = "Choose at least one group."
NO_DOMAIN = "Type at least one email domain."
BAD_ADDRESS = "The address must start with https:// and name a server."
GRAPH_DENIED = ("Entra didn't let Toner list groups. Grant GroupMember.Read.All with admin consent for Toner's app, then try "
                "again.")
NO_STORE = ("This computer has no protected store, so the client secret can't be kept. Use a public client, as the provider's note "
            "describes.")
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
        self.step, self._token, self._cancel = 0, None, None         # SSO: the Entra admin's access token (memory only)
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
        self.kinds[next((i for i, (_, v) in enumerate(KINDS) if v == saved.get("kind")), 0)].setChecked(True)
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

        page = QWidget()                                             # 4: who can sign in (also SSO's, for Entra)
        lay = QVBoxLayout(page)
        self.list_text, self.list_btn = note(LIST_GROUPS_TEXT), QPushButton(LIST_GROUPS)    # Entra only
        self.list_btn.setAutoDefault(False)
        self.list_btn.clicked.connect(self._list_groups)
        lay.addWidget(self.list_text)
        lay.addWidget(self.list_btn, 0, Qt.AlignmentFlag.AlignLeft)
        cols = QHBoxLayout()
        lay.addLayout(cols, 1)
        self.headings, self.filters, self.lists, self._timers, self._columns = [], {}, {}, {}, {}
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
            self.filters[kind], self.lists[kind], self._timers[kind], self._columns[kind] = box, lst, timer, (h, box, lst)
        self.stack.addWidget(page)

        page = QWidget()                                             # 5: roles, then the settings read at step 3
        lay = QVBoxLayout(page)
        host = QWidget()
        self.role_form = QFormLayout(host)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(host)
        lay.addWidget(scroll, 1)
        form = self.read_form = QFormLayout()
        lay.addLayout(form)
        self.name = _row(form, "Name", QLineEdit(saved.get("name") or ""))
        self.base_dn = _row(form, "Base DN", QLineEdit(saved.get("base_dn") or ""))
        self.netbios = _row(form, "Domain (NetBIOS)", QLineEdit(saved.get("netbios") or ""))
        self.suffixes = _row(form, "Email and UPN suffixes", QLineEdit(", ".join(saved.get("suffixes") or [])))
        self.role_boxes, self.role_labels = {}, {}
        self.stack.addWidget(page)

        page = QWidget()                                             # SSO 2: the provider
        lay = QVBoxLayout(page)
        self.providers = {}
        for key, p in ssopresets.PRESETS.items():
            r = self.providers[key] = QRadioButton(p["label"])
            r.setEnabled(cfg is None)                                # (its claims name the accounts already made)
            r.toggled.connect(lambda on, k=key: on and self._provider_picked(k))
            lay.addWidget(r)
        self.provider_note = note("")
        self.provider_note.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(self.provider_note)
        lay.addStretch(1)
        self.stack.addWidget(page)

        form = self._form()                                          # SSO 3: the connection
        sso = saved.get("kind") == "oidc"
        value = saved.get("issuer") or ""
        if sso and saved.get("provider") == "entra":                 # https://login.microsoftonline.com/<tenant>/v2.0
            value = value.split("/")[3] if value.count("/") >= 4 else ""
        self.issuer = _row(form, "Issuer URL", QLineEdit(value))
        self.client_id = _row(form, "App (client) ID", QLineEdit(saved.get("client_id") or ""))
        self.secret = _row(form, SECRET, QLineEdit())
        self.secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.domains = _row(form, "Email domains", QLineEdit(", ".join(saved.get("suffixes") or []) if sso else ""))
        self.claim = _row(form, "Groups claim", QLineEdit())
        self.sso_form = form

        page = QWidget()                                             # SSO 4, other than Entra: typed groups, or a role for everyone
        lay = QVBoxLayout(page)
        self.typed_text, self.typed = note(""), QPlainTextEdit()
        self.typed_text.setTextFormat(Qt.TextFormat.PlainText)
        self.typed.setAccessibleName(TYPE_GROUPS_TEXT)
        self.everyone_label, self.everyone = QLabel(EVERYONE), QComboBox()
        self.everyone.addItems(ROLES)
        self.everyone.setCurrentText(saved.get("everyone") or "Tech")
        self.everyone.setAccessibleName(EVERYONE)
        self.everyone_label.setBuddy(self.everyone)
        for wgt in (self.typed_text, self.typed, self.everyone_label, self.everyone):
            lay.addWidget(wgt)
        lay.addStretch(1)
        self.stack.addWidget(page)

        self.providers[saved.get("provider") if saved.get("provider") in self.providers else "entra"].setChecked(True)
        if sso:                                                      # Edit: the saved values, not the preset's
            self.claim.setText(saved.get("groups_claim") or "")
            chosen = [g for r in ROLES for g in (saved.get("groups") or {}).get(r) or []]
            if saved.get("provider") == "entra":
                names = saved.get("group_names") or {}
                self._add_groups([(g, names.get(g, g)) for g in chosen], set(chosen))
            else:
                self.typed.setPlainText("\n".join(chosen))

        self.title = heading()
        self.message = QLabel()
        self.message.setWordWrap(True)
        self.message.setTextFormat(Qt.TextFormat.PlainText)         # NOT_FOUND carries the URL as typed
        self.message.hide()
        self.back_btn, self.next_btn, self.save_btn = QPushButton("Back"), primary("Next"), primary("Save")
        self.back_btn.setAutoDefault(False)
        self.back_btn.clicked.connect(lambda: self._go(self.step - 1))
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
    def _sso(self):
        return self.kinds[[v for _, v in KINDS].index("oidc")].isChecked()

    def _provider(self):
        return next(k for k, r in self.providers.items() if r.isChecked())

    def _pages(self):
        """The stack's page for each of the five steps."""
        if not self._sso():
            return (0, 1, 2, 3, 4)
        lists = self._provider() == "entra" and self.claim.text().strip()
        return (0, 5, 6, 3 if lists else 7, 4)

    def _go(self, i):
        sso = self._sso()
        self.step = i
        self.stack.setCurrentIndex(self._pages()[i])
        self.title.setText((SSO_TITLES if sso else TITLES)[i])
        self.back_btn.setVisible(i > 0)
        self.next_btn.setVisible(i < len(TITLES) - 1)
        self.save_btn.setVisible(i == len(TITLES) - 1)
        for wgt in (self.list_text, self.list_btn):                 # step 4: Entra's sign-in, and Groups only
            wgt.setVisible(sso)
        for wgt in self._columns["ous"]:
            wgt.setVisible(not sso)
        for wgt in (self.base_dn, self.netbios, self.suffixes):    # step 5: what step 3 read from a directory
            self.read_form.setRowVisible(wgt, not sso)
        named = self.name.text().strip() or ssopresets.PRESETS[self._provider()]["label"]
        self.typed_text.setText(TYPE_GROUPS_TEXT.format(provider=named))
        self.typed.setAccessibleName(TYPE_GROUPS_TEXT.format(provider=named))
        claim = bool(self.claim.text().strip())
        for wgt in (self.typed_text, self.typed):
            wgt.setVisible(claim)
        for wgt in (self.everyone_label, self.everyone):
            wgt.setVisible(not claim)
        self._say("")

    def _next(self):
        i = self.step
        if i == 2:
            return self._discover() if self._sso() else self._connect()
        if i == 3:
            if not self._choices() and not (self._sso() and not self.claim.text().strip()):
                return self._say(NONE_SSO if self._sso() else NONE_TICKED)
            self._fill_roles()
        self._go(i + 1)

    def _provider_picked(self, key):
        p = ssopresets.PRESETS[key]
        self.provider_note.setText(p["note"])
        self.sso_form.labelForField(self.issuer).setText(p["field"])
        self.issuer.setAccessibleName(p["field"])
        self.claim.setText(p["groups_claim"] or "")

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

    def _discover(self):
        """SSO step 3: the provider's sign-in settings read, and the connection's values checked, on a Job."""
        cfg = self._sso_cfg()

        def run():
            try:
                directory.check_config(cfg)                 # (the two the admin can put right here first, in the approved words)
            except directory.BadIssuer:
                raise Said(BAD_ADDRESS) from None
            except directory.NoDomain:
                raise Said(NO_DOMAIN) from None
            try:
                oidc.discover(cfg["issuer"])
            except oidc.OidcError:
                raise Said(NOT_FOUND.format(url=cfg["issuer"])) from None
        self._run(run, lambda _r, e: self._discovered(cfg, e))

    def _discovered(self, cfg, error):
        if error is not None:
            return self._say(words(error))
        if not self.name.text().strip():
            self.name.setText(ssopresets.PRESETS[cfg["provider"]]["label"])
        self._go(3)
        self._say(FOUND.format(provider=self.name.text().strip()), good=True)

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
        """Narrows at once; a list that didn't load whole (or Entra's, once listed) is also searched once typing pauses."""
        self._narrow(kind)
        self._asked[kind] += 1
        searchable = self._token if self._sso() else self.more and self._live
        if searchable and self.filters[kind].text().strip():
            self._timers[kind].start()
        else:
            self._timers[kind].stop()

    def _search(self, kind):
        if self._closed or not (self._token if self._sso() else self._live):
            return
        text, n, got = self.filters[kind].text().strip(), self._asked[kind], {}
        if self._sso():
            token = self._token
            fn = lambda: got.update(groups=oidc.search_groups(token, text))
        else:
            cfg, pw = self._live
            fn = lambda: got.update(directory.tree(cfg, pw, cap=CAP, text=text))
        self._run(fn, lambda _r, e: self._found(kind, n, got, e), block=False)

    def _found(self, kind, n, got, error):
        if n != self._asked[kind]:                           # typed again since: a newer search answers
            return
        if error is not None:
            if self.stack.currentIndex() == 3:               # an error landing after step 4 was left is no longer about anything
                self._say(self._sso_words(error) if self._sso() else words(error))
            return
        if self._sso():
            return self._add_groups(got["groups"])
        self._add(kind, got[kind])

    def _add_groups(self, found, tick=frozenset()):
        """Entra's (id, name) rows not listed yet, by id (two groups may share a name); rows already there keep their ticks."""
        lst = self.lists["groups"]
        have = {lst.item(i).data(GROUP_ID) for i in range(lst.count())}
        for gid, name in found:
            if gid in have:
                continue
            have.add(gid)
            item = QListWidgetItem(name)
            item.setData(GROUP_ID, gid)
            item.setToolTip(gid)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(CHECKED if gid in tick else UNCHECKED)
            lst.addItem(item)
        self._narrow("groups")

    def _list_groups(self):
        """Entra: an admin's browser sign-in (fresh, nonce checked), then the first page of groups. The access token stays here."""
        cfg, cancel, got = self._sso_cfg(), threading.Event(), {}
        self._cancel = cancel

        def run():
            b = oidc.BrowserSignIn(cfg, open_url=webbrowser.open, scopes=GRAPH_SCOPES)
            try:
                b.open()
                got["token"] = b.run(cancel).access_token
            finally:
                b.close()
            got["groups"] = oidc.search_groups(got["token"], "")
        self.list_btn.setEnabled(False)
        self._run(run, lambda _r, e: self._listed(got, e), block=False)

    def _listed(self, got, error):
        self.list_btn.setEnabled(True)
        self._token = got.get("token") or self._token
        if error is not None:
            return self._say(self._sso_words(error))
        self._say("")
        self._add_groups(got["groups"])

    def _sso_words(self, e):
        """An SSO failure in the approved words: an oidc error's own text names the provider's host, so is never shown."""
        if isinstance(e, oidc.Unreachable):
            return UNREACHABLE
        if isinstance(e, oidc.Forbidden):                   # Graph: no admin consent for GroupMember.Read.All
            return GRAPH_DENIED
        if not isinstance(e, oidc.OidcError):
            return words(e)
        return sso_said({"name": self.name.text().strip()}, e)

    # ---------------------------------------------------------------- step 5
    def _fill_roles(self):
        while self.role_form.rowCount():
            self.role_form.removeRow(0)
        self.role_boxes, self.role_labels = {}, {}
        for value, shown in self._choices():
            key, lab, box = directory._key(value), _plain(shown), QComboBox()
            box.addItems(ROLES)
            box.setCurrentText(self._role.get(key, "Tech"))
            box.setAccessibleName(shown)
            box.currentTextChanged.connect(lambda r, k=key: self._role.__setitem__(k, r))
            lab.setBuddy(box)
            self.role_form.addRow(lab, box)
            self.role_boxes[value], self.role_labels[value] = box, lab

    def _choices(self):
        """(value stored, text shown) for each OU or group chosen at step 4: a DN; an Entra group's id and name; a typed group."""
        if not self._sso():
            return [(dn, dn) for kind, _ in LISTS for dn in self._ticked(kind)]
        if not self.claim.text().strip():
            return []
        if self._provider() == "entra":
            lst = self.lists["groups"]
            return [(it.data(GROUP_ID), it.text()) for it in map(lst.item, range(lst.count()))
                    if it.checkState() == CHECKED and it.data(GROUP_ID)]
        return [(g, g) for g in dict.fromkeys(line.strip() for line in self.typed.toPlainText().splitlines()) if g]

    # ---------------------------------------------------------------- the settings as typed, and Save
    def _sso_cfg(self):
        p, claim = self._provider(), self.claim.text().strip() or None
        chosen = self._choices()
        role_of = lambda v: self.role_boxes[v].currentText() if v in self.role_boxes else None
        return {"id": self.id, "name": self.name.text().strip(), "kind": "oidc", "provider": p,
                "issuer": ssopresets.issuer_for(p, self.issuer.text()), "client_id": self.client_id.text().strip(),
                "groups_claim": claim, "id_claim": ssopresets.PRESETS[p]["id_claim"], "suffixes": _split(self.domains.text()),
                "groups": {r: [v for v, _ in chosen if role_of(v) == r] for r in ROLES},
                "group_names": {v: shown for v, shown in chosen if role_of(v)} if p == "entra" else {},
                "everyone": None if claim else self.everyone.currentText()}

    def _cfg(self):
        if self._sso():
            return self._sso_cfg()
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
        if self._sso():                                      # nothing to read from a server: saved at once
            if self.secret.text() and not osstore.available():     # (before anything is saved: the secret couldn't be kept)
                return self._say(NO_STORE)
            cfg = self._cfg()
            taken = _taken(self.dirs, self.id, cfg)
            return self._say(TAKEN.format(value=taken)) if taken else self._saved(cfg, [], self.secret.text(), None)
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
        if typed and cfg["kind"] == "oidc":
            osstore.put(f"oidc:{self.id}", typed.encode())
        elif typed:
            passvault.put(service_key(self.id), typed)
        self.service_pw.setText("")
        self.secret.setText("")
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
        if self._cancel is not None:                         # an Entra admin's browser sign-in stops waiting within a second
            self._cancel.set()
        for job in list(self._jobs):
            job.wait()
        self._jobs.clear()
        self._live = self._token = None
        self.service_pw.setText("")
        self.secret.setText("")
        super().done(r)
