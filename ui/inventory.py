import json
import sqlite3

import keyring
from PySide6.QtCore import QPointF, QTimer, Qt, Signal
from PySide6.QtGui import QColor, QFont, QIcon, QKeySequence, QPainter, QPen, QPixmap, QPolygonF, QShortcut
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog,
                               QDialogButtonBox, QFileDialog, QFormLayout, QHBoxLayout, QInputDialog, QLabel,
                               QLineEdit, QMenu, QMessageBox, QPlainTextEdit, QPushButton, QSizePolicy, QSpinBox, QStyle, QTabWidget,
                               QStackedWidget, QToolButton, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget, QWidgetAction)
from core import agents, audit, bulk, db, display, importer, nettools, orgs, profiles, proxy, scope, sessionimport, sessions, vendors, winmon
from ui import icons, theme
from ui.agentfleet import AgentFleet
from ui.columns import ColumnChooser
from ui.devicechecks import DeviceChecks
from ui.servicepicker import ServicePicker
from ui.snmpfields import SnmpFields
from core.runner import run_one
from ui.toast import toast
from ui import status as st



from ui.orgfield import GLOBAL_ONLY_CHOICE, SHARED_CHOICE, choice_file, org_choices  # noqa: E402  (Sessions takes them from here too)


class DeviceDialog(QDialog):
    def __init__(self, dev=None, parent=None, folder_id=None, org=None):
        """org: for a new device, the organization picked in Global's tree (its folders, profiles and jump hosts are offered)."""
        start = (dev or {}).get("org") if dev else choice_file(org)
        with db.within(start):                       # the lists and stored passwords come from the device's own organization
            self._build(dev, parent, folder_id, org)

    def _build(self, dev, parent, folder_id, org):
        super().__init__(parent)
        self.dev = dev or {}
        self.setWindowTitle("Edit device" if dev else "Add device")
        self.setMinimumWidth(460)
        self.name, self.host, self.username = QLineEdit(), QLineEdit(), QLineEdit()
        self.ssh_pw = QLineEdit()                                  # a firewall's SSH password, for the Command Runner (its checks use the API key)
        self.ssh_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.ssh_pw.setPlaceholderText("leave blank to keep the stored value")
        self.enable_pw = QLineEdit()                               # Cisco: enable mode's own password, when it differs from the login
        self.enable_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.enable_pw.setToolTip("Cisco devices: the password for enable mode, when it differs from the login password.")
        self.host.setPlaceholderText("10.0.0.2  or  core-sw1.corp.example.com")
        self.host.editingFinished.connect(self._mark_host)
        self.host.textEdited.connect(lambda _t: self.host.setStyleSheet("") or self.host.setToolTip(""))
        self.secret = QLineEdit()
        self.secret.setEchoMode(QLineEdit.EchoMode.Password)
        from ui.linkitem import LinkRow
        self.link_row = LinkRow()                                    # Link... to a password manager item (when one is chosen)
        self.secret.setPlaceholderText("leave blank to keep the stored value")
        self.get_key = QPushButton("Get API key from the firewall...")
        self.get_key.setToolTip("Sign in once with an administrator's user name and password: Toner asks the device for the key and fills it in.")
        self.get_key.setAutoDefault(False)
        self.get_key.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)          # as wide as its words, not the whole row
        self.get_key.clicked.connect(self._get_key)
        self.vendor = QComboBox()
        for v in vendors.listed():
            self.vendor.addItem(display.vendor_name(v), v)       # shown text, stored value
        self.platform = QComboBox()
        self.port = QSpinBox()
        self.port.setRange(0, 65535)
        self.port.setSpecialValueText("default")
        self.site = QLineEdit("default")
        self.location = QComboBox()
        self.location.setEditable(True)
        self.location.addItems(sorted({d["location"] for d in db.list_devices() if d.get("location")}))
        self.location.setCurrentText("")
        self.location.lineEdit().setPlaceholderText("e.g. Chicago (used for grouping)")
        self.folder = QComboBox()
        self.folder.addItem("(top level)", None)
        for fid, path in sorted(db.folder_paths().items(), key=lambda kv: kv[1].lower()):
            self.folder.addItem(path, fid)
        self.folder.setCurrentIndex(max(0, self.folder.findData((dev or {}).get("folder_id", folder_id))))
        self.details = QLineEdit()
        self.details.setPlaceholderText("optional notes, e.g. rack 3, core switch")
        self.preset = QComboBox()
        self.preset.addItem("(choose to fill in the address)", "")
        from drivers.cloud import PRESETS
        for label, host in PRESETS:
            self.preset.addItem(f"{label}  -  {host}", (label, host))
        self.preset.currentIndexChanged.connect(self._preset)
        self.verify = QCheckBox("Verify SSL certificate")
        self.verify.setChecked(bool(db.get_setting("default_verify_ssl")) and not dev)   # default for new devices
        self.ha = QCheckBox("HA pair expected")
        self.enabled = QCheckBox("Enabled")
        self.enabled.setChecked(True)
        self.profile = QComboBox()
        self.profile.addItem("(none - use the values below)", None)
        for p in profiles.list_profiles():
            self.profile.addItem(p["name"], p["id"])
        self.profile.setToolTip("A credential profile supplies the username, secret and SNMP settings; "
                                "anything you fill in here overrides it.")
        self.jump = QComboBox()
        self.jump.addItem("(connect directly)", "")
        for d in db.list_devices():
            if d["name"] != self.dev.get("name"):
                self.jump.addItem(d["name"], d["name"])
        self.jump.setToolTip("Reach this device over SSH through another inventory device (SSH checks, "
                             "backups and the console).")
        self.proxy_mode = QComboBox()
        self.proxy_mode.addItem("Use the global setting (Settings > Proxy)", "default")
        self.proxy_mode.addItem("Connect directly (no proxy)", "none")
        self.proxy_mode.addItem("Use a proxy for this device", "custom")
        self.proxy_kind = QComboBox()
        for k, label in proxy.KINDS:
            self.proxy_kind.addItem(label, k)
        self.proxy_host, self.proxy_user, self.proxy_pw = QLineEdit(), QLineEdit(), QLineEdit()
        self.proxy_host.setPlaceholderText("proxy.example.com")
        self.proxy_user.setPlaceholderText("optional")
        self.proxy_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.proxy_otp, self.proxy_otp_key = QComboBox(), QLineEdit()
        for k, label in proxy.OTP_MODES:
            self.proxy_otp.addItem(label, k)
        self.proxy_otp.setToolTip("For a proxy with two-step sign-in: the current code from an authenticator app is added to the end of the password.")
        self.proxy_otp_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.proxy_otp_key.setPlaceholderText("secret key from the authenticator setup")
        self.proxy_otp.currentIndexChanged.connect(lambda *_: self._proxy_rows())
        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(1, 65535)
        self.proxy_port.setValue(8080)
        self.proxy_mode.currentIndexChanged.connect(lambda *_: self._proxy_rows())
        self._proxy_kind_was = self.proxy_kind.currentData()

        def kind_changed(*_):
            new = self.proxy_kind.currentData()
            if self.proxy_port.value() == proxy.DEFAULT_PORTS.get(self._proxy_kind_was):
                self.proxy_port.setValue(proxy.DEFAULT_PORTS.get(new, self.proxy_port.value()))
            self._proxy_kind_was = new
            if hasattr(self, "access"):
                self._proxy_rows()
        self.proxy_kind.currentIndexChanged.connect(kind_changed)
        self.win_auth = QComboBox()
        for k, label in winmon.AUTHS:
            self.win_auth.addItem(label, k)
        self.win_auth.setToolTip("How Toner signs in over WinRM. Leave the user name empty to use the Windows account Toner runs as.")
        self.win_https = QCheckBox("Use HTTPS (port 5986) instead of HTTP (port 5985)")
        self.win_watch = QLineEdit()
        self.win_watch.setPlaceholderText("services that must be running, e.g. DNS, NTDS, MSSQLSERVER")
        self.win_ignore = QLineEdit()
        self.win_ignore.setPlaceholderText("automatic services to leave out of the stopped-services check (* works at the end)")
        self.win_pick_watch = QPushButton("Choose...")
        self.win_pick_watch.setToolTip("List the services on this computer and tick the ones that must be running")
        self.win_pick_ignore = QPushButton("Choose...")
        self.win_pick_ignore.setToolTip("List the services on this computer and tick the ones to leave out of the stopped-services check")
        for b, field, title, hint in (
                (self.win_pick_watch, self.win_watch, "Services that must be running",
                 "Tick the services that must be running. A tick here makes the Services check FAIL when that service is not running."),
                (self.win_pick_ignore, self.win_ignore, "Services to ignore",
                 "Tick the automatic services that are allowed to be stopped. They are left out of the stopped-services warning.")):
            b.setAutoDefault(False)
            b.clicked.connect(lambda _=False, f=field, t=title, h=hint: self._pick_services(f, t, h))
        self.win_script = QPushButton("Get agent script...")
        self.win_script.setAutoDefault(False)
        self.win_script.clicked.connect(self._agent_script)
        self.win_note = QLabel("")
        self.win_note.setWordWrap(True)
        self.win_note.setProperty("muted", True)
        self.use_snmp = QCheckBox("This device also answers SNMP")
        self.snmp = SnmpFields()
        self.tags = QLineEdit()
        self.tags.setPlaceholderText("comma separated, e.g. core, wan, PCI")
        self.fields = QPlainTextEdit()
        self.fields.setPlaceholderText("one per line:  serial=FDO1234  owner=Network team  support=2027-06")
        self.fields.setFixedHeight(90)

        def page(rows):
            w = QWidget()
            f = QFormLayout(w)
            for label, widget in rows:
                f.addRow(label, widget)
            return w, f
        self.org_pick = QComboBox()
        org_choices(self.org_pick, self.dev if dev else None, org)
        self.org_pick.setToolTip("Which organization the device belongs to. Shared devices are seen by every organization.")
        if dev and not db.everything():
            self.org_pick.setEnabled(False)                     # moved between organizations from Global
        self._org_was = choice_file(self.org_pick.currentData())
        self.org_pick.currentIndexChanged.connect(self._org_changed)
        self.page_general, self.form = page((("Organization", self.org_pick), ("Name", self.name), ("Vendor", self.vendor), ("Folder", self.folder),
                                             ("Location", self.location), ("Popular pages", self.preset), ("Host / DNS name", self.host),
                                             ("Port", self.port), ("Platform", self.platform),
                                             ("Details", self.details), ("", self.enabled)))
        self.form.setRowVisible(self.org_pick, bool(orgs.list_orgs()))      # nothing to choose before there are organizations
        self.page_access, self.access = page((("Credential profile", self.profile), ("Username", self.username), ("SSH password", self.ssh_pw),
                                              ("Password", self.secret), ("Enable password", self.enable_pw), ("", self.link_row), ("", self.get_key), ("Site", self.site),
                                              ("Jump host", self.jump), ("Proxy", self.proxy_mode), ("Proxy Type", self.proxy_kind),
                                              ("Proxy Address", self.proxy_host), ("Proxy Port", self.proxy_port),
                                              ("Proxy User", self.proxy_user), ("Proxy Password", self.proxy_pw),
                                              ("One-Time Code", self.proxy_otp), ("Secret Key", self.proxy_otp_key),
                                              ("", self.verify), ("", self.ha)))
        self.page_snmp = QWidget()
        sl = QVBoxLayout(self.page_snmp)
        sl.addWidget(self.use_snmp)
        sl.addWidget(self.snmp)
        sl.addStretch()
        self.page_more, self.more = page((("Tags", self.tags), ("Custom fields", self.fields)))
        self.page_windows, self.win = page((("", self.win_note), ("WinRM sign-in", self.win_auth), ("", self.win_https),
                                            ("Services to require", self._with_button(self.win_watch, self.win_pick_watch)),
                                            ("Services to ignore", self._with_button(self.win_ignore, self.win_pick_ignore)),
                                            ("Agent", self.win_script)))
        self.secret_label = "Password"
        self.secret_field = self.secret
        self.checks_tab = DeviceChecks()
        self.checks_tab.fetch_interfaces = self._fetch_interfaces
        self.tabs = QTabWidget()
        self.tabs.addTab(self.page_general, "General")
        self.tabs.addTab(self.page_access, "Access")
        self.tabs.addTab(self.page_snmp, "SNMP")
        self.tabs.addTab(self.page_more, "Tags and fields")
        self.tabs.addTab(self.page_windows, "Windows")
        self.tabs.addTab(self.checks_tab, "Checks")
        self.tabs.setUsesScrollButtons(False)                    # every tab stays in view; the window is made wide enough for all six
        self.tabs.setElideMode(Qt.TextElideMode.ElideNone)
        self.setMinimumWidth(max(460, self.tabs.tabBar().sizeHint().width() + 56))

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save |
                                   QDialogButtonBox.StandardButton.Cancel)
        test = buttons.addButton("Test connection", QDialogButtonBox.ButtonRole.ActionRole)
        test.clicked.connect(self.test)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(self.tabs)
        lay.addWidget(buttons)

        snmp_have = {}
        if dev:
            with db.within(dev.get("org")):
                self.link_row.load(db.secret_name(dev["name"]))
            self.name.setText(dev["name"])
            if not dev.get("vendor"):                         # imported without one: it stays so until a vendor is chosen
                self.vendor.insertItem(0, "(no vendor)", "")
            self.vendor.setCurrentIndex(max(0, self.vendor.findData(vendors.family(dev["vendor"]))))
            self.host.setText(dev["host"])
            self.location.setCurrentText(dev.get("location") or "")
            self.details.setText(dev.get("details") or "")
            self.port.setValue(dev.get("port") or 0)
            self.username.setText(dev.get("username") or "")
            self.site.setText(dev.get("site") or "default")
            self.verify.setChecked(bool(dev.get("verify_ssl")))
            self.ha.setChecked(bool(dev.get("ha_expected")))
            self.enabled.setChecked(bool(dev.get("enabled", 1)))
            self.profile.setCurrentIndex(max(0, self.profile.findData(dev.get("profile_id"))))
            self.tags.setText(dev.get("tags") or "")
            self.fields.setPlainText(fields_to_text(dev.get("fields")))
            try:
                jump = json.loads(dev.get("jump") or "{}")
            except ValueError:
                jump = {}
            self.jump.setCurrentIndex(max(0, self.jump.findData(jump.get("device", ""))))
            own_proxy = proxy.device_settings(dev)
            if own_proxy.get("kind") == "tunnel":            # saved by 1.5.2-1.5.5: it is the SSH tunnel's SOCKS5 port now
                from core import tunnel
                own_proxy = {**own_proxy, "kind": "socks5", "host": "127.0.0.1", "port": tunnel.settings()["local_port"],
                             "username": "", "otp": ""}
            self.proxy_mode.setCurrentIndex(max(0, self.proxy_mode.findData(own_proxy.get("mode", "default"))))
            self.proxy_kind.setCurrentIndex(max(0, self.proxy_kind.findData(own_proxy.get("kind", "http"))))
            self.proxy_host.setText(own_proxy.get("host", ""))
            self.proxy_port.setValue(int(own_proxy.get("port") or 8080))
            self.proxy_user.setText(own_proxy.get("username", ""))
            self.proxy_otp.setCurrentIndex(max(0, self.proxy_otp.findData(own_proxy.get("otp", ""))))
            if keyring.get_password(db.SERVICE, db.secret_name(dev["name"], "proxy_otp")):
                self.proxy_otp_key.setPlaceholderText("saved; leave blank to keep")
            self.checks_tab.load(dev.get("checkopts"))
            wo = winmon.options(dev)
            self.win_auth.setCurrentIndex(max(0, self.win_auth.findData(wo["auth"])))
            self.win_https.setChecked(wo["https"])
            self.win_watch.setText(winmon.names_text(wo["watch"]))
            self.win_ignore.setText(winmon.names_text(wo["ignore"]))
            if keyring.get_password(db.SERVICE, db.secret_name(dev["name"], "proxy")):
                self.proxy_pw.setPlaceholderText("saved; leave blank to keep")
            if keyring.get_password(db.SERVICE, db.secret_name(dev["name"], "ssh")):
                self.ssh_pw.setPlaceholderText("saved; leave blank to keep")
            if keyring.get_password(db.SERVICE, db.secret_name(dev["name"], "enable")):
                self.enable_pw.setPlaceholderText("saved; leave blank to keep")
            try:
                own = json.loads(dev.get("snmp") or "{}")
            except ValueError:
                own = {}
            self.use_snmp.setChecked(bool(own))
            self.snmp.load(own)
            snmp_have = {k: bool(keyring.get_password(db.SERVICE, db.secret_name(dev["name"], k)))
                         for k in ("snmp", "snmp_auth", "snmp_priv")}
        self.snmp.set_stored(snmp_have)
        self.use_snmp.toggled.connect(lambda on: self.snmp.setEnabled(on))
        self.vendor.currentIndexChanged.connect(lambda _: self.adapt(self.vendor.currentData()))
        self.platform.currentIndexChanged.connect(lambda _: self._apply_type() if vendors.modes(self.vendor.currentData()) else self._windows_rows())
        self.adapt(self.vendor.currentData())
        self._start = self._snapshot()                           # how it was when it opened, to notice unsaved edits

    def _org_changed(self, *_):
        """Another organization: its folders, credential profiles, jump hosts and locations."""
        new = choice_file(self.org_pick.currentData())
        if new is None or new == self._org_was:
            return
        self._org_was = new
        with db.within(new):
            self.folder.clear()
            self.folder.addItem("(top level)", None)
            for fid, path in sorted(db.folder_paths().items(), key=lambda kv: kv[1].lower()):
                self.folder.addItem(path, fid)
            keep = self.profile.currentText()
            self.profile.clear()
            self.profile.addItem("(none - use the values below)", None)
            for p in profiles.list_profiles():
                self.profile.addItem(p["name"], p["id"])
            self.profile.setCurrentIndex(max(0, self.profile.findText(keep)))
            self.jump.clear()
            self.jump.addItem("(connect directly)", "")
            for d in db.list_devices():
                if d["name"] != self.dev.get("name"):
                    self.jump.addItem(d["name"], d["name"])
            text = self.location.currentText()
            self.location.clear()
            self.location.addItems(sorted({d["location"] for d in db.list_devices() if d.get("location")}))
            self.location.setCurrentText(text)

    def _vendor(self):
        """The type of device the dialog is describing: the vendor, or for a vendor with several ways to monitor it (UniFi) the way chosen."""
        v = self.vendor.currentData()
        return (self.platform.currentData() or v) if vendors.modes(v) else v

    def adapt(self, vendor):
        modes = vendors.modes(vendor)
        info = vendors.get(vendor)
        keep = self.platform.currentData() or (self.dev.get("vendor") if modes else self.dev.get("platform"))
        self.platform.blockSignals(True)
        self.platform.clear()                                    # the platforms belong to the vendor
        for key, label in (modes or info["platforms"]):
            self.platform.addItem(label, key)
        self.platform.setCurrentIndex(max(0, self.platform.findData(keep)))
        self.platform.blockSignals(False)
        self.form.setRowVisible(self.platform, len(modes or info["platforms"]) > 1)
        self.form.labelForField(self.platform).setText("How to monitor" if vendor == "windows" or modes else "Platform")
        self._apply_type()

    def _apply_type(self):
        """Show what the chosen kind of device needs: its labels, which boxes apply, its checks."""
        vendor = self._vendor()
        self.checks_tab.set_vendor(vendor)
        info = vendors.get(vendor)
        snmp_only = vendors.is_snmp(vendor)
        cli = vendor in vendors.CLI_TYPES
        self.access.setRowVisible(self.username, info["username"] or cli)
        self.access.setRowVisible(self.ssh_pw, cli)
        self.access.labelForField(self.username).setText("SSH user name" if cli else "Username")
        self.username.setPlaceholderText("optional, for the Command Runner and config backups (the checks use the API key)" if cli else "")
        tip = ("The Command Runner runs commands over this SSH login, and config backups use it when there is no API token or the API fails. "
               "The checks use the API key.") if cli else ""
        self.username.setToolTip(tip)
        self.ssh_pw.setToolTip(tip)
        self.access.setRowVisible(self.site, bool(info["site"]))
        from ui.keydialog import KEYS
        self.access.setRowVisible(self.get_key, vendor in KEYS)
        if vendor in KEYS:
            self.get_key.setText(KEYS[vendor]["button"])
        self.access.setRowVisible(self.ha, info["ha"])
        self.access.setRowVisible(self.verify, info["kind"] == "api")
        self.access.setRowVisible(self.jump, info["kind"] == "ssh")
        self.access.setRowVisible(self.enable_pw, info["kind"] == "ssh")
        login = vendors.has_login(vendor)
        self.form.setRowVisible(self.preset, vendor == "cloud")
        self.host.setPlaceholderText({"cloud": "the status page's address, e.g. www.githubstatus.com",
                                      "wifi": "localhost (this computer)",
                                      "unifi_network": "the console's address, e.g. 192.168.1.1 or unifi.corp.example.com",
                                      "unifi_protect": "the console's address, e.g. 192.168.1.1 or unifi.corp.example.com",
                                      "unifi_cloud": "api.ui.com"}.get(vendor, ""))
        if vendor == "wifi" and not self.host.text().strip():
            self.host.setText("localhost")
        if vendor == "unifi_cloud" and not self.host.text().strip():
            self.host.setText("api.ui.com")                       # Site Manager is always this address
        elif vendor != "unifi_cloud" and self.host.text().strip() == "api.ui.com":
            self.host.clear()                                     # that was filled in for Site Manager; another kind needs its own address
        self.access.setRowVisible(self.profile, login)
        self.access.setRowVisible(self.secret, not snmp_only and login)
        self.tabs.setTabVisible(2, login)
        if info["site"]:
            self.access.labelForField(self.site).setText(info["site"])
        self.access.labelForField(self.secret).setText(info["secret"])
        self.use_snmp.setVisible(not snmp_only and login)
        self._proxy_rows()
        self._windows_rows()
        self._link_rows()
        if snmp_only:
            self.use_snmp.setChecked(True)
        self.snmp.setEnabled(self.use_snmp.isChecked())

    def _link_rows(self):
        """Link... sits under the password, while there is a password box and a password manager is chosen."""
        from ui import linkitem
        self.access.setRowVisible(self.link_row, linkitem.wanted() and self.access.isRowVisible(self.secret))

    def _windows_rows(self):
        """Windows devices: which settings apply depends on how the computer is monitored."""
        win = self.vendor.currentData() == "windows"
        how = self.platform.currentData() or "agent"
        self.tabs.setTabVisible(4, win)
        if not win:
            return
        winrm = how == "winrm"
        self.access.setRowVisible(self.username, winrm)
        self.access.setRowVisible(self.secret, winrm)
        self.access.setRowVisible(self.profile, winrm)
        self.access.setRowVisible(self.verify, winrm)
        self.win.setRowVisible(self.win_auth, winrm)
        self.win.setRowVisible(self.win_https, winrm)
        self.win.setRowVisible(self.win_script, how == "agent")
        self._link_rows()
        if how == "local" and not self.host.text().strip():
            self.host.setText("localhost")
        self.win_script.setEnabled(bool(self.dev.get("id")))
        self.win_script.setToolTip("" if self.dev.get("id") else "Save the device first; the script is made for a saved device.")
        self.win_note.setText({
            "agent": "A small script on the Windows computer reports to Toner on a schedule. Nothing connects to the computer, so it works for "
                     "laptops, computers that are not in the domain and computers behind a firewall. Turn on Settings > Agents so "
                     "Toner can receive the reports, then create this computer's script below.",
            "winrm": "Toner connects to the computer over WinRM (PowerShell remoting) and reads its state. Nothing is installed on it. "
                     "Leave the user name empty on a domain to sign in as the Windows account Toner runs as; otherwise use DOMAIN\\user, "
                     "user@domain or .\\user and a password. The account needs to be in Remote Management Users and Event Log Readers.",
            "local": "Reads this computer directly. Nothing to set up."}[how])

    def _agent_script(self):
        from ui.winagent import AgentScriptDialog
        AgentScriptDialog(self.dev["name"], self, org=self.dev.get("org")).exec()

    def _proxy_rows(self):
        able = vendors.get(self._vendor()).get("kind") in ("ssh", "api", "status")     # not SNMP / UDP / local
        self.access.setRowVisible(self.proxy_mode, able)
        custom = able and self.proxy_mode.currentData() == "custom"
        for w in (self.proxy_kind, self.proxy_host, self.proxy_port, self.proxy_user, self.proxy_pw, self.proxy_otp):
            self.access.setRowVisible(w, custom)
        self.access.setRowVisible(self.proxy_otp_key, custom and self.proxy_otp.currentData() == "totp")

    def _proxy_values(self):
        if vendors.get(self._vendor()).get("kind") not in ("ssh", "api", "status"):
            return ""
        mode = self.proxy_mode.currentData()
        if mode == "none":
            return {"mode": "none"}
        if mode == "custom":
            vals = {"mode": "custom", "kind": self.proxy_kind.currentData(), "host": self.proxy_host.text().strip(),
                    "port": self.proxy_port.value(), "username": self.proxy_user.text().strip()}
            if self.proxy_otp.currentData():
                vals["otp"] = self.proxy_otp.currentData()
            return vals
        return ""

    def ssh_secrets(self):
        """A firewall's SSH password and a Cisco device's enable password, when they were typed."""
        out = {"ssh": self.ssh_pw.text()} if self._vendor() in vendors.CLI_TYPES and self.ssh_pw.text() else {}
        if self.enable_pw.text():
            out["enable"] = self.enable_pw.text()
        return out

    def proxy_secrets(self):
        v = self._proxy_values()
        out = {"proxy": self.proxy_pw.text()} if v and v["mode"] == "custom" and self.proxy_pw.text() else {}
        if v and v["mode"] == "custom" and v.get("otp") == "totp" and self.proxy_otp_key.text().strip():
            out["proxy_otp"] = proxy.clean_key(self.proxy_otp_key.text())
        return out

    def _preset(self, *_):
        picked = self.preset.currentData()
        if picked:
            label, host = picked
            self.host.setText(host)
            if not self.name.text().strip():
                self.name.setText(label)

    def values(self):
        v = self._vendor()
        snmp_on = (self.use_snmp.isChecked() and vendors.has_login(v)) or vendors.is_snmp(v)
        return {"id": self.dev.get("id"), "name": self.name.text().strip(), "vendor": v,
                "location": self.location.currentText().strip(),
                "folder_id": self.folder.currentData(),
                "details": self.details.text().strip(),
                "host": self.host.text().strip(), "port": self.port.value(),
                "platform": "" if vendors.modes(v) else (self.platform.currentData() or ""),
                "username": self.username.text().strip(), "site": self.site.text().strip() or "default",
                "verify_ssl": int(self.verify.isChecked()), "ha_expected": int(self.ha.isChecked()),
                "enabled": int(self.enabled.isChecked()),
                "profile_id": self.profile.currentData(), "tags": self.tags.text().strip(),
                "fields": text_to_fields(self.fields.toPlainText()),
                "snmp": self.snmp.settings() if snmp_on else "",
                "jump": {"device": self.jump.currentData()} if self.jump.currentData() else "",
                "proxy": self._proxy_values(), "winopts": self._win_values(),
                "checkopts": self.checks_tab.values(),
                "org": choice_file(self.org_pick.currentData()), "shared": int(self.org_pick.currentData() == SHARED_CHOICE)}

    def _snapshot(self):
        try:
            return json.dumps([self.values(), self.secret.text(), self.proxy_pw.text(), self.proxy_otp_key.text(), self.snmp_secrets(), self.ssh_pw.text(),
                               self.enable_pw.text()], sort_keys=True, default=str)
        except Exception:
            return ""

    def reject(self):
        """Cancel, Esc or the close button: ask first if anything was changed."""
        if self._snapshot() != self._start and QMessageBox.question(
                self, "Discard changes", "Close without saving your changes to this device?") != QMessageBox.StandardButton.Yes:
            return
        super().reject()

    @staticmethod
    def _with_button(field, button):
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.addWidget(field, 1)
        h.addWidget(button)
        return w

    def _pick_services(self, field, title, hint):
        """Ask the computer (or its agent's last report) for its services, and put the ticked names in `field`."""
        dev = self.values()
        dev["name"] = dev["name"] or self.dev.get("name", "")
        dev["winopts"] = json.dumps(dev["winopts"]) if dev["winopts"] else ""
        if self.secret.text():
            dev["password"] = self.secret.text()
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            dev = profiles.resolve(dev)
            services, source = winmon.list_services(dev, dev.get("password") or profiles.secret(dev, "main"))
        except Exception as e:
            QApplication.restoreOverrideCursor()
            QMessageBox.warning(self, title, f"Could not get the list of services:\n\n{e}")
            return
        QApplication.restoreOverrideCursor()
        dlg = ServicePicker(services, winmon._names(field.text()), title, hint, source, self)
        if dlg.exec():
            field.setText(winmon.names_text(dlg.selected()))

    def _get_key(self):
        """Palo Alto and Proxmox: ask the device for an API key with an administrator's sign-in, and put it in the key box."""
        from ui.keydialog import KeyDialog, KEYS
        kind = self._vendor()
        if kind not in KEYS:
            return
        dev = self.values()
        dev["name"] = dev["name"] or self.dev.get("name", "")
        if not dev["host"]:
            QMessageBox.warning(self, "API key", "Enter the device's address on the General tab first.")
            return
        try:
            nettools.check_host(dev["host"])
        except ValueError as e:
            QMessageBox.warning(self, "Invalid host", str(e))
            return
        if dev.get("proxy") and not isinstance(dev["proxy"], str):
            dev["proxy"] = json.dumps(dev["proxy"])
        if self.proxy_pw.text():
            dev["_proxy_secret"] = self.proxy_pw.text()
        if self.proxy_otp_key.text().strip():
            dev["_proxy_otp_secret"] = proxy.clean_key(self.proxy_otp_key.text())
        dlg = KeyDialog(dev, kind, self)
        if dlg.exec() and dlg.key:
            self.secret.setText(dlg.key)
            audit.log("api key requested", f"{dev['name']}: from {dev['host']}")
            if dlg.note:
                QMessageBox.information(self, "API key", dlg.note)
            toast(self, "Key filled in. Press Test connection, then Save to keep it.")

    def _fetch_interfaces(self):
        """The device's own list of interfaces, from the details typed in this dialog (nothing has to be saved first)."""
        from core import ifaces
        dev = self.values()
        dev["name"] = dev["name"] or self.dev.get("name", "")
        if not dev["host"]:
            raise ValueError("enter the device's address first")
        for key in ("winopts", "snmp", "jump", "proxy", "checkopts"):
            if dev.get(key) and not isinstance(dev[key], str):
                dev[key] = json.dumps(dev[key])
        if self.secret.text():
            dev["password"] = self.secret.text()
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            return ifaces.listing(dev)
        finally:
            QApplication.restoreOverrideCursor()

    def _win_values(self):
        if self.vendor.currentData() != "windows":
            return ""
        return {"auth": self.win_auth.currentData(), "https": self.win_https.isChecked(),
                "watch": winmon._names(self.win_watch.text()), "ignore": winmon._names(self.win_ignore.text())}

    def snmp_secrets(self):
        return self.snmp.secrets() if self.use_snmp.isChecked() or vendors.is_snmp(self._vendor()) else {}

    def accept(self):
        v = self.values()
        if self.org_pick.currentData() is None:
            QMessageBox.warning(self, "Organization", "Choose the organization this device belongs to.")
            return
        if not v["name"] or not v["host"]:
            QMessageBox.warning(self, "Missing data", "Name and host are required.")
            return
        bad = self.checks_tab.problems()
        if bad:
            self.tabs.setCurrentWidget(self.checks_tab)
            QMessageBox.warning(self, "Checks", "\n".join(bad))
            return
        if v["proxy"] and v["proxy"]["mode"] == "custom" and not v["proxy"]["host"]:
            QMessageBox.warning(self, "Missing data", "Enter the proxy's address, or choose another proxy option.")
            return
        try:
            self.host.setText(nettools.check_host(v["host"]))
        except ValueError as e:
            QMessageBox.warning(self, "Invalid host", str(e))
            return
        super().accept()

    def _mark_host(self, *_):
        """Say so as soon as the address is left with something that is neither an IP address nor a name, before any lookup is tried."""
        text = self.host.text().strip()
        try:
            if text:
                nettools.check_host(text)
            problem = ""
        except ValueError as e:
            problem = str(e)
        self.host.setStyleSheet(f"border: 1px solid {st.ink('FAIL')};" if problem else "")
        self.host.setToolTip(problem)
        return problem

    def test(self):
        try:
            nettools.check_host(self.host.text())
        except ValueError as e:                       # a mistyped address is said so, not sent off to DNS
            self.tabs.setCurrentIndex(0)
            self.host.setFocus()
            QMessageBox.warning(self, "Invalid host", str(e))
            return
        dev = self.values()
        if self.secret.text():
            dev["password"] = self.secret.text()
        dev["snmp"] = json.dumps(dev["snmp"]) if dev["snmp"] else ""
        dev["jump"] = json.dumps(dev["jump"]) if dev["jump"] else ""
        dev["proxy"] = json.dumps(dev["proxy"]) if dev["proxy"] else ""
        dev["winopts"] = json.dumps(dev["winopts"]) if dev["winopts"] else ""
        dev["checkopts"] = json.dumps(dev["checkopts"]) if dev["checkopts"] else ""
        if self.proxy_pw.text():
            dev["_proxy_secret"] = self.proxy_pw.text()
        if self.proxy_otp_key.text().strip():
            dev["_proxy_otp_secret"] = proxy.clean_key(self.proxy_otp_key.text())
        dev["_secrets"] = {k: s for k, s in self.snmp_secrets().items() if s}        # typed but not saved yet
        QApplication.setOverrideCursor(self.cursor())
        try:
            # a test must not move the error-counter baselines that real runs compare against
            res = run_one(dev, db.thresholds_for(dev), {**db.runtime_options(), "counter_mode": "total", "dry_run": True})
        finally:
            QApplication.restoreOverrideCursor()
        errs = [r for r in res if r.status == "ERROR"]
        if not res:
            QMessageBox.warning(self, "Test", "Connected, but no check results were returned.")
        elif errs:
            QMessageBox.warning(self, "Test", "\n".join(f"{r.check}: {r.message}" for r in errs[:5]))
        else:
            ip = nettools.resolve_host(dev["host"])
            shown = dev["host"] if ip == dev["host"] else f"{dev['host']} ({ip})"
            toast(self, f"Connected to {shown}. {len(res)} check results returned.")


def fields_to_text(raw):
    try:
        data = json.loads(raw) if isinstance(raw, str) and raw else (raw or {})
    except ValueError:
        data = {}
    return "\n".join(f"{k}={v}" for k, v in data.items())


def text_to_fields(text):
    out = {}
    for line in (text or "").splitlines():
        k, sep, v = line.partition("=")
        if sep and k.strip():
            out[k.strip()] = v.strip()
    return out


class BulkEditDialog(QDialog):
    """Change one or more fields on several devices at once. Only ticked rows are applied."""

    def __init__(self, count, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Edit {count} device(s)")
        self.setMinimumWidth(460)
        self.rows = {}
        form = QFormLayout()

        def row(key, label, widget):
            box = QCheckBox(label)
            widget.setEnabled(False)
            box.toggled.connect(widget.setEnabled)
            self.rows[key] = (box, widget)
            form.addRow(box, widget)
        self.folder = QComboBox()
        self.folder.addItem("(top level)", None)
        for fid, path in sorted(db.folder_paths().items(), key=lambda kv: kv[1].lower()):
            self.folder.addItem(path, fid)
        self.location = QLineEdit()
        self.add_tags, self.remove_tags = QLineEdit(), QLineEdit()
        self.add_tags.setPlaceholderText("tags to add, comma separated")
        self.remove_tags.setPlaceholderText("tags to remove")
        self.profile = QComboBox()
        self.profile.addItem("(none)", None)
        for p in profiles.list_profiles():
            self.profile.addItem(p["name"], p["id"])
        self.jump = QComboBox()
        self.jump.addItem("(connect directly)", "")
        for d in db.list_devices():
            self.jump.addItem(d["name"], d["name"])
        self.enabled = QComboBox()
        self.enabled.addItem("Enabled", True)
        self.enabled.addItem("Disabled", False)
        self.vendor_box = QComboBox()
        self.vendor_box.addItem("(leave as is)", None)
        for v in vendors.listed():
            self.vendor_box.addItem(display.vendor_name(v), v)
        row("vendor", "Vendor", self.vendor_box)
        row("folder_id", "Move to folder", self.folder)
        row("location", "Set location", self.location)
        row("add_tags", "Add tags", self.add_tags)
        row("remove_tags", "Remove tags", self.remove_tags)
        row("profile_id", "Credential profile", self.profile)
        row("jump", "Jump host", self.jump)
        row("enabled", "Checks", self.enabled)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Tick what to change; everything else stays as it is."))
        lay.addLayout(form)
        lay.addWidget(buttons)

    def operations(self):
        ops = {}
        for key, (box, w) in self.rows.items():
            if not box.isChecked():
                continue
            ops[key] = (w.currentData() if isinstance(w, QComboBox) else w.text().strip())
        return ops


ROLE = Qt.ItemDataRole.UserRole


class DeviceTree(QTreeWidget):
    """The inventory tree. Dropping on a folder moves the dragged devices and folders into it."""
    moved = Signal(list, object)          # [("device"|"folder", id), ...], target folder id (None = top level)

    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def mousePressEvent(self, e):
        if not self.indexAt(e.position().toPoint()).isValid():     # click on empty space deselects
            self.clearSelection()
            self.setCurrentItem(None)
        super().mousePressEvent(e)

    def dropEvent(self, e):
        # Qt would move the tree items itself; we move the data instead and rebuild from it.
        target = self.itemAt(e.position().toPoint())
        tid, where = None, db.target()
        if target is not None:
            kind, ident = self.owner.kind_of(target)
            where = self.owner.org_of(target)
            if kind == "folder":
                tid = ident
            elif kind == "device":
                tid = self.owner.payload[target.data(0, ROLE)].get("folder_id")
            elif kind != "org":
                e.ignore()
                return
        items = [i for i in self.selectedItems() if self.owner.kind_of(i)[0] in ("device", "folder")]
        e.setDropAction(Qt.DropAction.IgnoreAction)
        e.accept()
        if any(self.owner.org_of(i) != where for i in items) or not self.owner.editable(where):
            toast(self.owner, "Use Move to organization to move devices between organizations." if self.owner.editable(where)
                  else "Shared and archived devices are changed from Global.")
            return
        moves = [self.owner.kind_of(i) for i in items]
        if moves:
            self.moved.emit(moves, (where, tid))


class InventoryTab(QWidget):
    changed = Signal()
    open_agent_settings = Signal()
    open_ssh = Signal(dict)
    open_rdp_tab = Signal(dict)
    scan_requested = Signal()                    # the empty inventory's "Scan the network": the discovery tool
    open_details = Signal(dict)
    run_checks = Signal(list)                    # right-click > Run Checks: these devices (their keys), now
    scan_vulns = Signal(list)                    # right-click > Scan for vulnerabilities: these devices (their keys), on the Scanning section
    sessions_imported = Signal()                 # sessions from MobaXterm, PuTTY or SecureCRT were added (the Sessions list reloads)
    orgs_created = Signal()                      # an import made organizations from its folders (the switcher reloads)
    COLS = ["Name", "Vendor", "Platform", "Version", "Location", "Host", "Site", "Details", "Tags", "Status", "Last checked", "Organization"]
    VERSION = 3                                  # the software the device runs, as the checks last read it (db.software_of)
    STATUS = 9
    CHECKED = 10
    ORG = 11

    def __init__(self):
        super().__init__()
        self.payload = {}                       # item key -> device dict / folder id / group name
        self._building = False
        self.expanded = set(db.get_setting("inventory_expanded"))
        self.vendor_sel, self.location_sel, self.tag_sel = set(), set(), set()    # empty = all; location "" = none
        self.org_sel = set()                    # Global: the organizations ticked in the filter (empty = all active ones)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search devices  (Ctrl+F)")
        self.search.setClearButtonEnabled(True)
        self.search.setToolTip("Type part of a name, address, vendor, location, tag or detail. Several words must all match.")
        self.health = {}                        # device name -> latest state, for the dot beside it
        self.filter_btn = QToolButton()
        self.filter_btn.setIcon(self._filter_icon())
        self.filter_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.filter_btn.setStyleSheet("QToolButton::menu-indicator { image: none; }")
        self.filter_menu = QMenu(self.filter_btn)
        self.filter_menu.aboutToShow.connect(self._build_filter_menu)
        self.filter_btn.setMenu(self.filter_menu)
        self._update_filter_btn()

        self.table = DeviceTree(self)           # (named 'table' for older callers)
        self.table.setColumnCount(len(self.COLS))
        self.table.setHeaderLabels(self.COLS)
        self.table.header().setStretchLastSection(True)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setUniformRowHeights(True)
        self.table.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_menu)
        self.table.itemSelectionChanged.connect(self.update_buttons)
        self.table.itemDoubleClicked.connect(self.double_clicked)
        from ui.widgets import StatusDelegate
        self.table.setItemDelegateForColumn(self.STATUS, StatusDelegate(self.table))      # the same pill as Results and the Overview
        self.columns = ColumnChooser(self.table, self.table.header(), "inventory_columns", self.COLS, locked=(0,), auto=self._empty_columns,
                                     org_col=self.ORG)
        self.table.itemExpanded.connect(lambda it: (self.remember(it, True), self._autosize()))
        self.table.itemCollapsed.connect(lambda it: (self.remember(it, False), self._autosize()))
        self.table.moved.connect(self.handle_moves)
        here = Qt.ShortcutContext.WidgetWithChildrenShortcut    # only while the list has the focus, not in the search box
        for key in ("Return", "Enter"):                          # Enter opens the selected device, as a double-click does
            QShortcut(QKeySequence(key), self.table, activated=self._enter, context=here)
        QShortcut(QKeySequence("F2"), self.table, activated=self.rename_folder, context=here)
        QShortcut(QKeySequence("Delete"), self.table, activated=self.delete, context=here)

        bar = QHBoxLayout()
        self.buttons = {}
        for text, fn in (("Add", self.add), ("Edit", self.edit), ("Details", self.show_details), ("Delete", self.delete),
                         ("New folder", self.new_folder)):
            b = QPushButton(text)
            b.clicked.connect(lambda _=False, fn=fn: fn())
            bar.addWidget(b)
            self.buttons[text] = b
        self.more = QPushButton("More")                  # what is used now and then, so the row never outgrows a narrow window
        more_menu = QMenu(self.more)
        self.more_actions = {}
        for text, fn in (("Import...", self.import_file), ("Import PuTTY sessions on this computer...", self.import_putty_here),
                         ("Export...", self.export_file), (None, None),
                         ("Expand all", self.expand_all), ("Collapse all", self.collapse_all)):
            if text is None:
                more_menu.addSeparator()
            else:
                self.more_actions[text] = more_menu.addAction(text, fn)
        self.more.setMenu(more_menu)
        bar.addWidget(self.more)
        bar.addStretch()
        self.search.setMinimumWidth(96)                 # (Linux fonts are wider: the row still fits a 900-pixel window)
        self.search.setMaximumWidth(280)
        bar.addWidget(self.search, 1)
        bar.addWidget(self.filter_btn)
        self.search.textChanged.connect(lambda _: self._search_timer.start())
        self._search_timer = QTimer(self)               # wait for a pause in typing, then rebuild once
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(180)
        self._search_timer.timeout.connect(self.refresh)
        QShortcut(QKeySequence("Ctrl+F"), self, activated=self._focus_search)
        self.fleet = AgentFleet()
        self.fleet.changed.connect(self._fleet_changed)
        self.fleet.open_device.connect(self._open_named)
        self.fleet.open_settings.connect(self.open_agent_settings)
        self.stack = QStackedWidget()
        self.stack.addWidget(self.table)
        self.stack.addWidget(self.fleet)
        self.view_devices, self.view_agents = QPushButton("Devices"), QPushButton("Agents")
        for b in (self.view_devices, self.view_agents):
            b.setCheckable(True)
            b.setAutoExclusive(True)
        self.view_devices.setChecked(True)
        self.view_devices.clicked.connect(lambda: self.show_view("devices"))
        self.view_agents.clicked.connect(lambda: self.show_view("agents"))
        views = QHBoxLayout()
        views.setSpacing(0)
        views.addWidget(self.view_devices)
        views.addWidget(self.view_agents)
        views.addStretch()
        self.views_w = QWidget()
        self.views_w.setLayout(views)
        views.setContentsMargins(0, 0, 0, 0)
        self.bar_w = QWidget()
        self.bar_w.setLayout(bar)
        bar.setContentsMargins(0, 0, 0, 0)
        self.no_vendor = QLabel()                        # how many devices the checks skip because they have no vendor yet
        self.no_vendor.setProperty("muted", True)
        self.no_vendor.setWordWrap(True)
        self.no_vendor.hide()
        lay = QVBoxLayout(self)
        lay.addWidget(self.views_w)
        lay.addWidget(self.bar_w)
        lay.addWidget(self.no_vendor)
        lay.addWidget(self.stack)
        self.refresh()

    # ---------- Devices | Agents ----------
    def show_view(self, which):
        """The device tree, or the computers that report through an agent. The Agents button only appears once there are some."""
        agents_view = which == "agents" and self.view_agents.isVisibleTo(self)
        self.stack.setCurrentWidget(self.fleet if agents_view else self.table)
        self.view_agents.setChecked(agents_view)
        self.view_devices.setChecked(not agents_view)
        self.bar_w.setVisible(not agents_view)
        if agents_view:
            self.fleet.refresh()

    def _update_views(self):
        n = self.fleet.count()
        silent = self.fleet.silent_count()
        show = bool(n) or bool(db.get_setting("agent_enabled"))
        self.view_agents.setText(f"Agents ({n})" + (f"  -  {silent} silent" if silent else "") if n else "Agents")
        self.views_w.setVisible(show)
        if not show and self.stack.currentWidget() is self.fleet:
            self.show_view("devices")

    def _fleet_changed(self):
        self.refresh()
        self.changed.emit()

    def _open_named(self, name):
        d = db.find_device(name)
        if d:
            self.open_details.emit(d)

    # ---------- building the tree ----------
    def _icon(self, name, accent=False):
        t = theme.current()
        if not t:
            return QIcon()
        key = (name, t["accent"] if accent else t.get("icon", t["muted"]))
        cache = self.__dict__.setdefault("_icons", {})
        if key not in cache:
            cache[key] = icons.icon(name, key[1])
        return cache[key]

    SHAPES = {"OK": "circle", "WARN": "triangle", "FAIL": "square", "ERROR": "diamond"}

    def _device_icon(self, status):
        """The device icon with a dot for how its latest checks went (the words are in the tooltip, not only the colour)."""
        t = theme.current()
        if not t:
            return QIcon()
        ink = st.ink(status)
        key = ("dot", status, t.get("icon", t["muted"]), ink)
        cache = self.__dict__.setdefault("_icons", {})
        if key not in cache:
            cache[key] = icons.icon_with_dot("device", t.get("icon", t["muted"]), ink, shape=self.SHAPES.get(status, "circle"))
        return cache[key]

    @staticmethod
    def _filter_icon():
        from ui.widgets import filter_icon
        return filter_icon()

    def _build_filter_menu(self):
        """Vendor and Location only filter the folder tree; they never regroup it.
        Several values can be ticked: any of the ticked vendors AND any of the ticked locations."""
        m = self.filter_menu
        m.clear()
        devs = self._listed()
        if db.everything() and orgs.list_orgs():
            sub = m.addMenu("Organization")
            for text, val in [("Global", db.GLOBAL)] + [(o["name"] + ("  (archived)" if o["archived"] else ""), o["id"]) for o in orgs.list_orgs()]:
                box = QCheckBox(text)
                box.setChecked(val in self.org_sel)
                box.toggled.connect(lambda on, val=val: self.toggle_filter("org_sel", val, on))
                act = QWidgetAction(sub)
                act.setDefaultWidget(box)
                sub.addAction(act)
        for title, attr, values, shown in (
                ("Vendor", "vendor_sel", {vendors.family(d["vendor"]) for d in devs}, display.vendor_name),
                ("Location", "location_sel", {d["location"] for d in devs if d.get("location")}, str),
                ("Tag", "tag_sel", {t for d in devs for t in db.split_tags(d.get("tags"))}, str)):
            sub = m.addMenu(title)
            opts = [(shown(v), v) for v in sorted(values, key=lambda v: shown(v).lower())]
            if attr == "location_sel" and any(not d.get("location") for d in devs):
                opts.append(("(none)", ""))
            for text, val in opts:
                box = QCheckBox(text)                 # a widget action keeps the menu open while ticking
                box.setChecked(val in getattr(self, attr))
                box.toggled.connect(lambda on, attr=attr, val=val: self.toggle_filter(attr, val, on))
                act = QWidgetAction(sub)
                act.setDefaultWidget(box)
                sub.addAction(act)
        m.addSeparator()
        m.addAction("Clear filter", lambda: self.set_filter(None, None)).setEnabled(self.filtering())

    def toggle_filter(self, attr, val, on):
        sel = getattr(self, attr)
        (sel.add if on else sel.discard)(val)
        self._update_filter_btn()
        self.refresh()

    def set_filter(self, attr, val):
        """Replace one filter with a single value (None = all), or clear both with attr=None."""
        if attr is None:
            self.vendor_sel, self.location_sel, self.tag_sel, self.org_sel = set(), set(), set(), set()
        else:
            setattr(self, attr, set() if val is None else {val})
        self._update_filter_btn()
        self.refresh()

    def _update_filter_btn(self):
        parts = [db.org_name(o) for o in sorted(self.org_sel)] + [display.vendor_name(v) for v in sorted(self.vendor_sel)] + \
                [loc or "(no location)" for loc in sorted(self.location_sel)] + sorted(self.tag_sel)
        self.filter_btn.setToolTip("Filter: " + ", ".join(parts) if parts else "Filter by vendor or location")
        self.filter_btn.setText(f" {len(parts)}" if parts else "")
        self.filter_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon if parts
                                           else Qt.ToolButtonStyle.ToolButtonIconOnly)

    def expand_all(self):
        self.table.expandAll()
        self._autosize()

    def collapse_all(self):
        self.table.collapseAll()

    def _focus_search(self):
        if self.bar_w.isVisibleTo(self):
            self.search.setFocus()
            self.search.selectAll()

    def _words(self):
        return self.search.text().lower().split()

    @staticmethod
    def _haystack(d):
        org = db.org_name(d["org"]) if db.everything() and d.get("org") is not None else ""
        return " ".join(str(x) for x in (d["name"], d["host"], display.vendor_name(d["vendor"]), d.get("location"), d.get("details"),
                                         d.get("tags"), d.get("site"), d.get("platform"), org)
                        if x).lower()

    def _listed(self):
        """The devices of the view; in Global, archived organizations too when the filter ticks one."""
        with db.including_archived(db.everything() and bool(self.org_sel & db.archived_ids())):
            return db.list_devices()

    def _visible(self, devs):
        v, loc, tg = self.vendor_sel, self.location_sel, {x.lower() for x in self.tag_sel}
        words = self._words()
        og = self.org_sel if db.everything() else set()
        return [d for d in devs if (not og or d.get("org", db.GLOBAL) in og)
                and (not v or vendors.family(d["vendor"]) in v) and (not loc or (d.get("location") or "") in loc)
                and (not tg or tg & {x.lower() for x in db.split_tags(d.get("tags"))})
                and (not words or all(w in self._haystack(d) for w in words))]

    def kind_of(self, item):
        """('device', id), ('folder', id), ('org', organization) or ('group', text). Keys of items from another organization's file
        than the one being written to carry it: 'device:3:12' (see org_of)."""
        key = item.data(0, ROLE) or ""
        kind, _, ident = key.partition(":")
        if kind in ("folder", "device"):
            return kind, int(ident.rpartition(":")[2])
        if kind == "org":
            return "org", int(ident)
        return "group", ident

    def org_of(self, item):
        """The organization whose file a tree item belongs to."""
        key = item.data(0, ROLE) or ""
        kind, _, ident = key.partition(":")
        if kind == "org":
            return int(ident)
        if kind in ("folder", "device") and ":" in ident:
            return int(ident.partition(":")[0])
        return db.target()

    def _key(self, kind, org, ident):
        return f"{kind}:{ident}" if org == db.target() else f"{kind}:{org}:{ident}"

    def _ek(self, org, fid):
        """How an open folder is remembered: its id in the file being written to, 'org:id' for another organization's."""
        return fid if org == db.target() else f"{org}:{fid}"

    def _keep_open(self):
        db.set_setting("inventory_expanded", sorted(self.expanded, key=str))

    def editable(self, org):
        """Items of the organization being looked at can be changed here; Shared ones (from an organization) and archived ones cannot."""
        if org in db.archived_ids():
            return False
        return db.everything() or org == db.home()

    def _device_values(self, d):
        site = d["site"] if vendors.get(d["vendor"]).get("site") else ""              # blank where it does not apply, not "N/A"
        platform = vendors.mode_label(d["vendor"]) or (display.platform_name(d.get("platform") or vendors.default_platform(d["vendor"]))
                                                       if vendors.platform_keys(d["vendor"]) else "")
        state = self.health.get(d.get("key", d["name"])) if d["enabled"] else None
        org = db.org_name(d.get("org")) + (" (Shared)" if d.get("shared") else "")
        return [d["name"], display.vendor_name(d["vendor"]), platform, d.get("sw_version") or "", d.get("location") or "", d["host"], site,
                d.get("details") or "", d.get("tags") or "", self._status_word(d), display.ago(state["at"]) if state else "", org]

    def _status_word(self, d):
        """What the Status column says, in words as well as colour: OK, WARN, FAIL, ERROR, Not checked, or Disabled."""
        if not d["enabled"]:
            return "Disabled"
        state = self.health.get(d.get("key", d["name"]))
        return state["status"] if state else "Not checked"

    def _empty_columns(self):
        """Columns that say nothing for the devices shown: Platform, Version, Site, Details and Tags that are blank everywhere."""
        devs = [d for k, d in self.payload.items() if k.startswith("device:")]
        if not devs:
            return set()
        vals = [self._device_values(d) for d in devs]
        return {i for i in (2, self.VERSION, 6, 7, 8) if all(v[i] == "" for v in vals)}

    def update_values(self):
        """After a check run or a backup: the Version, Status and Last checked cells and the status dot of the rows on screen, from
        the stored devices. The list is not redrawn, which would drop the selection."""
        from PySide6.QtWidgets import QTreeWidgetItemIterator
        try:
            self.health = db.device_health()
        except Exception:
            self.health = {}
        fresh = {self._key("device", d.get("org", db.target()), d["id"]): d for d in self._listed()}
        found = QTreeWidgetItemIterator(self.table)
        while found.value():
            item = found.value()
            d = fresh.get(item.data(0, ROLE))
            if d is not None:
                new = self._device_item(d)                  # a throwaway row drawn as refresh() would (it also renews the payload)
                for col in (0, self.VERSION, self.STATUS, self.CHECKED):
                    item.setText(col, new.text(col))
                    item.setToolTip(col, new.toolTip(col))
                item.setIcon(0, new.icon(0))
            found += 1
        self.columns.apply()                                # a Version column hidden while blank everywhere shows once one is read
        if hasattr(self, "fleet") and self.stack.currentWidget() is self.fleet:
            self.fleet.refresh()

    def _device_item(self, d):
        it = QTreeWidgetItem(self._device_values(d))
        key = self._key("device", d.get("org", db.target()), d["id"])
        it.setData(0, ROLE, key)
        self.payload[key] = d
        state = self.health.get(d.get("key", d["name"]))
        it.setIcon(0, self._device_icon(state["status"]) if state and d["enabled"] else self._icon("device"))
        if state and d["enabled"]:
            bad = state["problems"]
            lines = [f"{state['status']} as of {state['at']}"] + ["  " + display.said(c, m) for c, _s, m in bad[:6]]
            if len(bad) > 6:
                lines.append(f"  ... and {len(bad) - 6} more")
            it.setToolTip(0, "\n".join(lines))
        elif not d["enabled"]:
            it.setToolTip(0, "Disabled: left out of runs")
        if db.normalize_checkopts(d.get("checkopts")):
            it.setToolTip(0, (it.toolTip(0) + "\n" if it.toolTip(0) else "") + "Has its own checks or thresholds (Edit > Checks)")
        it.setFlags((it.flags() | Qt.ItemFlag.ItemIsDragEnabled) & ~Qt.ItemFlag.ItemIsDropEnabled)
        if not d["enabled"]:                                      # left out of runs: the whole row is dimmed
            muted = QColor((theme.current() or {}).get("muted", "#888888"))
            for col in range(len(self.COLS)):
                it.setForeground(col, muted)
        if state and d["enabled"]:
            it.setToolTip(self.CHECKED, state["at"])
        sw = display.software_line(db.software_of(d))        # "17.09.04a, INSTALL mode, image cat9k_iosxe.17.09.04a.SPA.bin. Read 26 Oct 2026 at 14:02."
        if sw:
            it.setToolTip(self.VERSION, sw)
        return it

    def _enter(self):
        if self.selected() is not None:
            self.show_details()

    def folders_mode(self):
        return True

    def filtering(self):
        return bool(self.vendor_sel or self.location_sel or self.tag_sel or self._words() or (db.everything() and self.org_sel))

    def _empty_hint(self):
        """'No devices yet' with the three ways to start, or 'nothing matches' when a search or filter hides everything."""
        from ui.widgets import EmptyHint
        if getattr(self, "hint", None) is None:
            self.hint = EmptyHint(self.table, "No devices yet", "Add them one by one, import a list, or let Toner find them on the network")
        if scope.keep(db.list_devices()) or (db.list_devices() and scope.current() is None):
            self.hint.set_text("Nothing matches", "Clear the search box or the filter to see every device")
            self.hint.set_actions([])
        else:
            self.hint.set_text("No devices yet", "Add them one by one, import a list (CSV, JSON or YAML), or let Toner find them on the network")
            self.hint.set_actions([("Add device", self.add), ("Import...", self.import_file), ("Scan the network", self.scan_requested.emit)])
        return self.hint

    def org_switched(self):
        """Another organization was picked: its own open folders, a clean search box, and its devices. The list is drawn here:
        the `changed` signal that follows tells the other sections, not the inventory itself (1.6.10: a switch used to leave
        the old organization's devices on screen until a filter was touched)."""
        self.expanded = set(db.get_setting("inventory_expanded"))
        self.org_sel = set()
        self._update_filter_btn()
        self.search.blockSignals(True)                 # clearing would draw the list once for the search, once more below
        self.search.clear()
        self.search.blockSignals(False)
        self.refresh()

    def refresh(self):
        devs = scope.keep(self._visible(self._listed()))
        try:
            self.health = db.device_health()
        except Exception:
            self.health = {}
        self._building = True
        self.table.blockSignals(True)            # clearing announces 'selection changed' for rows being deleted
        self.table.clear()
        self.payload = {}
        self.table.setDragEnabled(True)
        self.table.setAcceptDrops(True)
        bold = QFont()
        bold.setBold(True)
        self._build_folders(devs, bold)
        for i in range(len(self.COLS)):
            self.table.resizeColumnToContents(i)
        self.columns.apply()
        self._building = False
        self.table.clearSelection()
        self.table.setCurrentItem(None)
        self.table.blockSignals(False)
        self.update_buttons()
        self._empty_hint().setVisible(self.table.topLevelItemCount() == 0)
        n = sum(1 for d in self._listed() if not d.get("vendor"))
        self.no_vendor.setText(f"{n} devices have no vendor yet, so the checks skip them. Choose a vendor to start checking them: "
                               "Bulk edit, or More > Detect vendors." if n else "")
        self.no_vendor.setVisible(bool(n))
        if hasattr(self, "fleet"):
            self._update_views()
            if self.stack.currentWidget() is self.fleet:
                self.fleet.refresh()

    def _build_folders(self, devs, bold):
        """The folder tree. In Global each organization is a branch of its own (Global's own and Shared devices under Global); in an
        organization, Global's Shared devices are in a Shared branch at the end."""
        me = db.target()
        if db.several():
            files = [db.GLOBAL] + [o["id"] for o in orgs.list_orgs() if not o["archived"] or o["id"] in self.org_sel]
            if self.org_sel:
                files = [o for o in files if o in self.org_sel]
            for org in files:
                mine = [d for d in devs if d.get("org", me) == org]
                if self.filtering() and not mine:
                    continue
                node = QTreeWidgetItem([f"{db.org_name(org)}  ({len(mine)})"])
                key = f"org:{org}"
                node.setData(0, ROLE, key)
                self.payload[key] = {"org": org}
                node.setFont(0, bold)
                node.setIcon(0, self._icon("folder", True))
                node.setFlags((node.flags() | Qt.ItemFlag.ItemIsDropEnabled) & ~Qt.ItemFlag.ItemIsDragEnabled)
                if org in db.archived_ids():
                    node.setText(0, node.text(0) + "  (archived)")
                self.table.addTopLevelItem(node)
                with db.within(org):
                    folders = db.list_folders()
                self._fill_tree(node, folders, mine, org, bold)
                node.setExpanded(key in self.expanded or self.filtering() or len(files) == 1)
            return
        own = [d for d in devs if d.get("org", me) == me]
        self._fill_tree(None, db.list_folders(), own, me, bold)
        shared = [d for d in devs if d.get("org", me) != me]
        if shared:
            node = QTreeWidgetItem([f"Shared  ({len(shared)})"])
            node.setData(0, ROLE, f"org:{db.GLOBAL}")
            self.payload[f"org:{db.GLOBAL}"] = {"org": db.GLOBAL}
            node.setFont(0, bold)
            node.setIcon(0, self._icon("folder", True))
            node.setToolTip(0, "Devices Global shares with every organization. They are changed from Global.")
            node.setFlags(node.flags() & ~Qt.ItemFlag.ItemIsDragEnabled & ~Qt.ItemFlag.ItemIsDropEnabled)
            self.table.addTopLevelItem(node)
            for d in sorted(shared, key=lambda d: d["name"].lower()):
                node.addChild(self._device_item(d))
            node.setExpanded(f"org:{db.GLOBAL}" in self.expanded or self.filtering())

    def _fill_tree(self, top, folders, devs, org, bold):
        """One organization's folders and devices, under `top` (None: at the top of the tree)."""
        known = {f["id"] for f in folders}
        kids, by_folder = {}, {}
        for f in folders:
            kids.setdefault(f["parent_id"] if f["parent_id"] in known else None, []).append(f)
        for d in devs:
            fid = d.get("folder_id")
            by_folder.setdefault(fid if fid in known else None, []).append(d)

        def count(fid):
            return len(by_folder.get(fid, [])) + sum(count(c["id"]) for c in kids.get(fid, []))

        def roll(fid):
            """{status: devices} for the enabled devices in a folder and the ones under it (what the folder's row says when it is closed)."""
            out = {}
            for d in by_folder.get(fid, []):
                state = self.health.get(d.get("key", d["name"])) if d["enabled"] else None
                if state and state["status"] != "OK":
                    out[state["status"]] = out.get(state["status"], 0) + 1
            for c in kids.get(fid, []):
                for k, v in roll(c["id"]).items():
                    out[k] = out.get(k, 0) + v
            return out

        def fill(parent_item, fid):
            for f in sorted(kids.get(fid, []), key=lambda f: f["name"].lower()):
                if self.filtering() and not count(f["id"]):
                    continue                      # while filtering, hide folders with nothing to show
                item = QTreeWidgetItem([f"{f['name']}  ({count(f['id'])})"])
                key = self._key("folder", org, f["id"])
                item.setData(0, ROLE, key)
                self.payload[key] = {**f, "org": org}
                item.setFont(0, bold)
                bad = roll(f["id"])
                if bad:                               # a closed folder still shows that something inside it is wrong
                    worst = next(k for k in ("ERROR", "FAIL", "WARN") if k in bad)
                    item.setText(self.STATUS, "  ".join(f"{bad[k]} {k}" for k in ("ERROR", "FAIL", "WARN") if k in bad))
                    item.setForeground(self.STATUS, st.qink(worst))
                    item.setFont(self.STATUS, bold)
                    item.setToolTip(self.STATUS, "Devices in this folder, and the folders in it, that are not OK")
                item.setIcon(0, self._icon("folder", True))
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsDragEnabled | Qt.ItemFlag.ItemIsDropEnabled)
                (parent_item.addChild if parent_item else self.table.addTopLevelItem)(item)
                fill(item, f["id"])
                item.setExpanded(self._ek(org, f["id"]) in self.expanded or self.filtering())
            for d in sorted(by_folder.get(fid, []), key=lambda d: d["name"].lower()):
                (parent_item.addChild if parent_item else self.table.addTopLevelItem)(self._device_item(d))

        fill(top, None)

    def _autosize(self):
        """Keep every column wide enough for what is showing, so opening a folder never leaves text cut off."""
        if not self._building:
            for i in range(len(self.COLS) - 1):
                self.table.resizeColumnToContents(i)

    def remember(self, item, open_):
        """Keep which folders are open, across restarts."""
        if self._building:
            return
        kind, ident = self.kind_of(item)
        if kind in ("folder", "org"):
            key = self._ek(self.org_of(item), ident) if kind == "folder" else f"org:{ident}"
            (self.expanded.add if open_ else self.expanded.discard)(key)
            self._keep_open()

    def expand_folder(self, fid):
        """Open a folder and the ones above it."""
        for item in self._all_items():
            if self.kind_of(item) == ("folder", fid):
                while item is not None:
                    item.setExpanded(True)
                    item = item.parent()
                return

    def _all_items(self):
        out, todo = [], [self.table.topLevelItem(i) for i in range(self.table.topLevelItemCount())]
        while todo:
            it = todo.pop()
            out.append(it)
            todo.extend(it.child(i) for i in range(it.childCount()))
        return out

    def select_device(self, dev_id, org=None):
        for it in self._all_items():
            if self.kind_of(it) == ("device", dev_id) and (org is None or self.org_of(it) == org):
                p = it.parent()
                while p is not None:
                    p.setExpanded(True)
                    p = p.parent()
                self.table.setCurrentItem(it)
                it.setSelected(True)
                return

    # ---------- selection ----------
    def selected_devices(self):
        return [self.payload[i.data(0, ROLE)] for i in self.table.selectedItems()
                if self.kind_of(i)[0] == "device" and i.data(0, ROLE) in self.payload]

    def selected_folders(self):
        return [self.kind_of(i)[1] for i in self.table.selectedItems() if self.kind_of(i)[0] == "folder"]

    def selected_org(self):
        """The organization of everything selected (the only one), else the one being written to; None when they differ."""
        found = {self.org_of(i) for i in self.table.selectedItems()}
        if len(found) > 1:
            return None
        return found.pop() if found else db.target()

    def selected(self):
        """The one selected device, or None (no selection, several, or a folder)."""
        items = self.table.selectedItems()
        devs = self.selected_devices()
        return devs[0] if len(items) == 1 and len(devs) == 1 else None

    def selected_keys(self):
        """The keys of every device the selection covers: the devices picked, those in the picked folders (and their subfolders),
        and every device of a picked organization's branch."""
        out = [d.get("key") or d["name"] for d in self.selected_devices()]
        devs = self._listed()
        for it in self.table.selectedItems():
            kind, ident = self.kind_of(it)
            org = self.org_of(it)
            if kind == "folder":
                with db.within(org):
                    below = db.folder_descendants(ident)
                out += [d.get("key") or d["name"] for d in devs if d.get("org", db.GLOBAL) == org and d.get("folder_id") in below]
            elif kind == "org":
                out += [d.get("key") or d["name"] for d in devs if d.get("org", db.GLOBAL) == ident]
        return list(dict.fromkeys(out))

    def current_folder(self):
        """Where a new folder or device should go: the selected folder, or the selected device's folder."""
        folders, devs = self.selected_folders(), self.selected_devices()
        if len(folders) == 1 and not devs:
            return folders[0]
        if len(devs) == 1 and not folders:
            return devs[0].get("folder_id")
        return None

    def update_buttons(self):
        org = self.selected_org()
        can = org is not None and self.editable(org)
        self.buttons["Edit"].setEnabled(self.selected() is not None and can)
        self.buttons["Details"].setEnabled(self.selected() is not None)
        self.buttons["Delete"].setEnabled(can and (bool(self.selected_devices()) or len(self.selected_folders()) == 1))
        self.buttons["New folder"].setEnabled(can)
        tip = "" if can or org is None else ("Archived organizations can only be viewed." if org in db.archived_ids()
                                             else "Shared devices are changed from Global.")
        for b in ("Edit", "Delete"):
            self.buttons[b].setToolTip(tip)

    def double_clicked(self, item, _col):
        if self.kind_of(item)[0] == "device":
            self.edit() if self.editable(self.org_of(item)) else self.show_details()

    # ---------- devices ----------
    def _save(self, dev, secret, old_name=None, extra_secrets=None, link=None):
        org = dev.get("org")
        try:
            db.save_device(dev)
        except db.NameTaken as e:
            QMessageBox.warning(self, "Duplicate", str(e))
            return False
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Duplicate", f"A device named '{dev['name']}' already exists.")
            return False
        with db.within(org):                                      # its passwords are kept under its own organization's names
            if old_name and old_name != dev["name"]:
                db.move_device_secrets(old_name, dev["name"])          # password, token and SNMP secrets follow the name
                agents.rename(old_name, dev["name"])
            if secret:
                db.set_secret(db.secret_name(dev["name"]), secret)
            for kind, value in (extra_secrets or {}).items():
                if value:
                    db.set_secret(db.secret_name(dev["name"], kind), value)
            if link is not None:
                link.apply(db.secret_name(dev["name"]))              # Link... / Unlink, chosen in the window
            audit.log("device " + ("edited" if old_name else "added"), dev["name"])
        if dev.get("folder_id"):
            self.expanded.add(self._ek(org if org is not None else db.target(), dev["folder_id"]))
        if org is not None and org != db.target():
            self.expanded.add(f"org:{org}")
        self.refresh()
        self.changed.emit()
        return True

    def add(self, prefill=None):
        """Add device; `prefill` ({'name', 'host', 'vendor'}, from the topology map) fills the boxes in first."""
        org = self.selected_org() if db.everything() and self.table.selectedItems() else None
        pre = None if org is None else (GLOBAL_ONLY_CHOICE if org == db.GLOBAL else org)
        dlg = DeviceDialog(parent=self, folder_id=self.current_folder() if self.folders_mode() else None, org=pre)
        if prefill:
            dlg.name.setText(prefill.get("name") or "")
            dlg.host.setText(prefill.get("host") or "")
            if dlg.vendor.findData(prefill.get("vendor") or "") >= 0:
                dlg.vendor.setCurrentIndex(dlg.vendor.findData(prefill["vendor"]))
        if dlg.exec():
            self._save(dlg.values(), dlg.secret.text(), extra_secrets={**dlg.snmp_secrets(), **dlg.proxy_secrets(), **dlg.ssh_secrets()},
                       link=dlg.link_row)

    def edit(self):
        d = self.selected()
        if d:
            self.edit_device(d)

    def edit_device(self, d):
        if not self.editable(d.get("org", db.target())):
            self.open_details.emit(d)
            return
        dlg = DeviceDialog(d, self)
        if dlg.exec():
            vals = dlg.values()
            dest = vals["org"]
            here = d.get("org", db.target())
            if dest is not None and dest != here:                    # Global: the Organization field changed
                vals.update(org=here, shared=0)
                if not self._save(vals, dlg.secret.text(), old_name=d["name"], extra_secrets={**dlg.snmp_secrets(), **dlg.proxy_secrets(), **dlg.ssh_secrets()}):
                    return
                moved = db.get_device(d["id"], here)
                if moved:
                    self.move_to_org([moved], dest, shared=dlg.values()["shared"])
                return
            self._save(vals, dlg.secret.text(), old_name=d["name"], extra_secrets={**dlg.snmp_secrets(), **dlg.proxy_secrets(), **dlg.ssh_secrets()},
                       link=dlg.link_row)

    def show_details(self):
        d = self.selected()
        if d:
            self.open_details.emit(d)

    def act_on(self, action, key):
        """A device action asked for elsewhere (the topology map's tile menu), run as the right-click here runs it: the device is
        selected first, so the same code works on it."""
        d = db.find_device(key)
        if not d:
            return
        self.select_device(d["id"], d.get("org"))
        if self.selected() is None or (self.selected().get("key") or self.selected()["name"]) != (d.get("key") or d["name"]):
            return                                           # not shown here now (another organization's view): nothing to act on
        {"edit": self.edit, "scan": lambda: self.scan_vulns.emit(self.selected_keys()), "tags": self.bulk_edit, "delete": self.delete,
         "details": self.show_details}.get(action, lambda: None)()

    def delete(self):
        """Delete the selected devices, or the selected folder (its contents move up, nothing else is lost)."""
        devs = self.selected_devices()
        if devs:
            what = f"{len(devs)} devices" if len(devs) > 1 else devs[0]["name"]
            if QMessageBox.question(self, "Delete", f"Delete {what}?") != QMessageBox.StandardButton.Yes:
                return
            for d in devs:
                with db.within(d.get("org")):
                    db.delete_device(d["id"])
                    db.delete_device_secrets(d["name"])
                    agents.forget(d["name"])
                    audit.log("device deleted", d["name"])
            self.refresh()
            self.changed.emit()
        elif len(self.selected_folders()) == 1:
            self.delete_folder()

    def open_in_ssh(self):
        d = self.selected()
        if d:
            self.open_ssh.emit(d)

    def open_rdp(self):
        d = self.selected()
        if d:
            self.open_rdp_tab.emit(d)

    # ---------- folders ----------
    def _ask_name(self, title, label, text=""):
        name, ok = QInputDialog.getText(self, title, label, text=text)
        return name.strip() if ok else None

    def new_folder(self, parent_id=None, use_selection=True):
        if not self.folders_mode():
            return
        parent = self.current_folder() if use_selection and parent_id is None else parent_id
        org = self.selected_org() if self.table.selectedItems() else db.target()
        if org is None or not self.editable(org):
            return
        name = self._ask_name("New folder", "Folder name:")
        if not name:
            return
        try:
            with db.within(org):
                fid = db.create_folder(name, parent)
        except ValueError as e:
            QMessageBox.warning(self, "New folder", str(e))
            return
        self.expanded.update({self._ek(org, fid)} | ({self._ek(org, parent)} if parent else set()) | ({f"org:{org}"} if db.everything() else set()))
        self._keep_open()
        self.refresh()
        self.changed.emit()

    def rename_folder(self):
        folders = self.selected_folders()
        if len(folders) != 1 or self.selected_devices():
            return
        fid, org = folders[0], self.selected_org()
        if org is None or not self.editable(org):
            return
        name = self._ask_name("Rename folder", "New name:", self.payload[self._key("folder", org, fid)]["name"])
        if not name:
            return
        try:
            with db.within(org):
                db.rename_folder(fid, name)
        except ValueError as e:
            QMessageBox.warning(self, "Rename folder", str(e))
            return
        self.refresh()
        self.changed.emit()

    def delete_folder(self):
        folders = self.selected_folders()
        if len(folders) != 1:
            return
        fid, org = folders[0], self.selected_org()
        if org is None or not self.editable(org):
            return
        f = self.payload[self._key("folder", org, fid)]
        with db.within(org):
            kids = sum(1 for x in db.list_folders() if x["parent_id"] == fid)
            devs = sum(1 for d in db.list_devices() if d.get("folder_id") == fid and d["org"] == org)
            where = db.folder_paths().get(f["parent_id"], "") or "the top level"
        if QMessageBox.question(self, "Delete folder", f"Delete the folder '{f['name']}'?\n\nIts {devs} device(s) and "
                                f"{kids} subfolder(s) move up to {where}. No device is deleted.") \
                != QMessageBox.StandardButton.Yes:
            return
        try:
            with db.within(org):
                db.delete_folder(fid)
        except ValueError as e:
            QMessageBox.warning(self, "Delete folder", str(e))
            return
        self.expanded.discard(self._ek(org, fid))
        self.refresh()
        self.changed.emit()

    def move_selected_to(self, target_id):
        moves = [("device", d["id"]) for d in self.selected_devices()] + [("folder", i) for i in self.selected_folders()]
        self.handle_moves(moves, target_id)

    def handle_moves(self, moves, target_id):
        """Move devices and folders into a folder (None = top level) of their own organization, reporting anything that cannot move.
        target_id can be (organization, folder id), from a drop."""
        org, target_id = target_id if isinstance(target_id, tuple) else (self.selected_org(), target_id)
        if org is None or not self.editable(org):
            return
        problems, dev_ids = [], []
        with db.within(org):
            for kind, ident in moves:
                if kind == "device":
                    dev_ids.append(ident)
                else:
                    try:
                        db.move_folder(ident, target_id)
                    except ValueError as e:
                        problems.append(str(e))
            db.move_devices(dev_ids, target_id)
        if target_id is not None:
            self.expanded.add(self._ek(org, target_id))
            self._keep_open()
        self.refresh()
        self.changed.emit()
        if problems:
            QMessageBox.warning(self, "Move", "\n".join(sorted(set(problems))))

    # ---------- right-click menu ----------
    def show_menu(self, pos):
        item = self.table.itemAt(pos)
        if item is not None and not item.isSelected():
            self.table.clearSelection()
            item.setSelected(True)
        devs, folders = self.selected_devices(), self.selected_folders()
        org = self.selected_org()
        can = org is not None and self.editable(org)
        menu = QMenu(self)
        if not devs and len(folders) <= 1 and can:          # an organization's branch, a folder, or empty space: a device goes there
            menu.addAction("Add Device", self.add)
        if not devs and not folders and any(self.kind_of(i)[0] == "org" for i in self.table.selectedItems()):
            menu.addAction("Scan for vulnerabilities", lambda: self.scan_vulns.emit(self.selected_keys()))     # an organization's branch
        if devs or folders:
            if len(devs) == 1 and not folders:
                menu.addAction("Details...", self.show_details)
                if can:
                    menu.addAction("Edit...", self.edit)
                if devs[0]["vendor"] == "windows":
                    menu.addAction("Open Remote Desktop", self.open_rdp)
                else:
                    menu.addAction("Open SSH session", self.open_in_ssh)
            if devs and not folders:
                menu.addAction("Run Checks", lambda: self.run_checks.emit([d.get("key") or d["name"] for d in self.selected_devices()]))
            if devs and can:
                menu.addAction("Edit selected..." if len(devs) > 1 else "Edit tags, folder, profile...", self.bulk_edit)
                menu.addAction("Detect vendors for selected...", self.detect_vendors)
            if len(folders) == 1 and not devs and can:
                menu.addAction("New subfolder...", lambda: self.new_folder(folders[0], use_selection=False))
                menu.addAction("Rename...", self.rename_folder)
            menu.addAction("Scan for vulnerabilities", lambda: self.scan_vulns.emit(self.selected_keys()))
            if self.folders_mode() and can:
                move = menu.addMenu("Move to folder")
                with db.within(org):
                    banned = set().union(*(db.folder_descendants(f) for f in folders)) if folders else set()
                    paths = db.folder_paths()
                move.addAction("(top level)", lambda: self.move_selected_to(None))
                for fid, path in sorted(paths.items(), key=lambda kv: kv[1].lower()):
                    if fid not in banned:
                        move.addAction(path, lambda fid=fid: self.move_selected_to(fid))
            if devs and not folders and db.everything() and all(d.get("org") not in db.archived_ids() for d in devs):
                to = menu.addMenu("Move to organization")
                for text, dest in [("Global", db.GLOBAL)] + [(o["name"], o["id"]) for o in orgs.list_orgs(archived=False)]:
                    act = to.addAction(text, lambda dest=dest: self.move_to_org(self.selected_devices(), dest))
                    act.setEnabled(any(d.get("org") != dest for d in devs))
            if can:
                menu.addSeparator()
                menu.addAction("Delete folder..." if folders and not devs else "Delete...", self.delete)
        else:
            if self.folders_mode():
                menu.addAction("New folder...", lambda: self.new_folder(None, use_selection=False))
        menu.addSeparator()
        menu.addAction("Expand all", self.expand_all)
        menu.addAction("Collapse all", self.collapse_all)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    # ---------- moving devices between organizations (Global) ----------
    def move_to_org(self, devs, dest, shared=0):
        """Ask, then move devices to another organization: with their data (results, config backups, sessions) or without."""
        devs = [d for d in devs if d.get("org") != dest]
        if not devs:
            return
        n = len(devs)
        box = QMessageBox(QMessageBox.Icon.Question, "Move to organization", f"Move {n} device{'s' if n != 1 else ''} to {db.org_name(dest)}?",
                          parent=self)
        both = box.addButton("Move Devices and Data", QMessageBox.ButtonRole.AcceptRole)
        only = box.addButton("Move Devices Only", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() not in (both, only):
            return
        try:
            orgs.move_devices(devs, dest, with_data=box.clickedButton() is both)
        except ValueError as e:
            QMessageBox.warning(self, "Move to organization", str(e))
            return
        if shared and dest == db.GLOBAL:
            for d in devs:
                with db.within(db.GLOBAL):
                    row = next((x for x in db._devices_here() if x["name"] == d["name"]), None)
                    if row:
                        db.save_device({**row, "org": db.GLOBAL, "shared": 1})
        audit.log("devices moved", f"{n} device(s) to {db.org_name(dest)}" + ("" if box.clickedButton() is both else " (without their data)"))
        self.expanded.add(f"org:{dest}")
        self.refresh()
        self.changed.emit()
        toast(self, f"Moved {n} device{'s' if n != 1 else ''} to {db.org_name(dest)}.")

    # ---------- export ----------
    def export_file(self):
        """Write the inventory (or just the selected devices) to a file. Passwords and keys are never included."""
        devs = self.selected_devices() or self._visible(self._listed())
        path, _ = QFileDialog.getSaveFileName(self, "Export devices", "devices.csv",
                                              "CSV (*.csv);;JSON (*.json);;YAML (*.yaml)")
        if not path:
            return
        try:
            importer.write_rows(importer.export_rows(devs), path)
        except (ValueError, OSError) as e:
            QMessageBox.warning(self, "Export failed", str(e))
            return
        audit.log("inventory exported", f"{len(devs)} device(s) to {path}")
        QMessageBox.information(self, "Export", f"Wrote {len(devs)} device(s) to:\n{path}\n\nPasswords, tokens and "
                                "SNMP communities are not included.")

    # ---------- bulk edit ----------
    def bulk_edit(self):
        devs = self.selected_devices()
        if not devs:
            return
        dlg = BulkEditDialog(len(devs), self)
        if dlg.exec():
            try:
                n = bulk.apply(devs, dlg.operations())
            except ValueError as e:
                QMessageBox.warning(self, "Edit devices", str(e))
                return
            self.refresh()
            self.changed.emit()
            toast(self, f"Changed {n} of {len(devs)} device(s).")

    def detect_vendors(self):
        """More > Detect vendors for selected: the vendor window from a session-file import, for devices already in the inventory.
        Detect Vendors signs in with each device's own user name and stored password."""
        devs = self.selected_devices()
        if not devs:
            return
        from ui import vendorassign
        rows, passwords = [], {}
        for i, d in enumerate(devs):
            with db.within(d.get("org")):
                paths = db.folder_paths()
                passwords[i] = profiles.secret(d) or ""
                user = profiles.username(d) or d.get("username") or ""
            rows.append({"kind": "rdp" if d.get("vendor") == "windows" else "ssh", "name": d["name"], "host": d.get("host") or "",
                         "port": int(d.get("port") or 22), "username": user, "org": d.get("org"),
                         "folder": [p for p in (paths.get(d.get("folder_id")) or "").split("/") if p],
                         "vendor": d.get("vendor") or "", "platform": d.get("platform") or ""})
        answer, chosen = vendorassign.choose(rows, passwords, self, inventory=True)
        if answer != "devices":
            return
        changed = 0
        for d, (vendor, platform) in zip(devs, chosen):
            if not vendor or (vendor, platform) == (d.get("vendor") or "", d.get("platform") or ""):
                continue
            with db.within(d.get("org")):
                now = db.get_device(d["id"])
                if now is not None:
                    db.save_device({**now, "vendor": vendor, "platform": platform})
                    changed += 1
        if changed:
            audit.log("vendors detected", f"{changed} of {len(devs)} device(s)")
        self.refresh()
        self.changed.emit()
        toast(self, f"Changed {changed} of {len(devs)} device(s).")

    # ---------- import ----------
    def import_file(self):
        both = "Device lists and sessions (*.yaml *.yml *.json *.csv " + " ".join("*" + e for e in sessionimport.EXTENSIONS) + ")"
        path, _ = QFileDialog.getOpenFileName(self, "Import devices", "", f"{both};;{importer.FILE_FILTER};;{sessionimport.SESSION_FILTER}")
        if not path:
            return
        if sessionimport.is_session_file(path):               # MobaXterm, PuTTY or SecureCRT: these become sessions
            try:
                found = sessionimport.load(path)
            except Exception as e:
                QMessageBox.warning(self, "Import failed", f"Could not read the file:\n{e}")
                return
            self.import_sessions(found)
            return
        try:
            rows = importer.load_rows(path)
        except Exception as e:                       # unreadable file, bad syntax, wrong shape
            QMessageBox.warning(self, "Import failed", f"Could not read the file:\n{e}")
            return
        from ui import orgassign
        added, dupes, bad, ready = 0, [], [], []
        for i, raw in enumerate(rows, start=1):
            label = importer.label(raw, i)
            try:
                dev, secret = importer.normalize(raw)
                community = importer.finalize(dev)
            except ValueError as e:
                bad.append(f"{label}: {e}")
                continue
            folder = [p for p in (dev.pop("folder", "") or "").replace("\\", "/").split("/") if p.strip()]
            ready.append((label, dev, secret, community, folder))
        made = []
        picks = orgassign.choose([(dev["name"], folder, "Device") for _l, dev, _s, _c, folder in ready], self, made)   # Global: whose each one is
        if picks is None:
            return
        if made:
            self.orgs_created.emit()
        existing = {}
        for (label, dev, secret, community, folder), org in zip(ready, picks):
            with db.within(org):                              # an import only adds to the organization it goes to
                here = db.target()
                if here not in existing:
                    existing[here] = {d["name"].lower() for d in db.list_devices()}
                if dev["name"].lower() in existing[here]:
                    dupes.append(dev["name"])
                    continue
                try:
                    dev["folder_id"] = db.ensure_folder_path("/".join(orgassign.strip_top(folder, org)))
                    db.save_device({**dev, "org": here})
                except sqlite3.IntegrityError:
                    dupes.append(dev["name"])
                    continue
                except ValueError as e:
                    bad.append(f"{label}: {e}")
                    continue
                existing[here].add(dev["name"].lower())
                if secret:
                    db.set_secret(db.secret_name(dev["name"]), secret)
                if community:
                    db.set_secret(db.secret_name(dev["name"], "snmp"), community)
            added += 1
        self.refresh()
        self.changed.emit()
        lines = [f"Imported {added} of {len(rows)} device(s)."]
        if dupes:
            lines.append(f"\nAlready in the inventory (skipped): {', '.join(dupes)}")
        if bad:
            lines.append(f"\nSkipped, with reasons ({len(bad)}):")
            lines += [f"  \u2022 {b}" for b in bad[:12]] + ([f"  ...and {len(bad) - 12} more"] if len(bad) > 12 else [])
        QMessageBox.information(self, "Import", "\n".join(lines))
        if made:
            toast(self, orgassign.created_text(made))

    # ---------------------------------------------------------------- sessions from other terminal programs
    def import_putty_here(self):
        found = sessionimport.putty_here()
        if not found.items and not found.skipped:
            QMessageBox.information(self, "Import", "No PuTTY sessions were found on this computer.")
            return
        self.import_sessions(found)

    @staticmethod
    def sessions_summary(found):
        """'Found 1,661 sessions in 211 folders: 1,473 SSH, ... 45 browser sessions are skipped (Toner has no web sessions).'"""
        counts = found.counts()
        total = len(found.items) + sum(found.skipped.values())
        kinds = ", ".join(f"{counts[k]:,} {label}" for k, label in (("ssh", "SSH"), ("rdp", "Remote Desktop"), ("vnc", "VNC"),
                                                                   ("telnet", "Telnet"), ("serial", "Serial")) if counts.get(k))
        text = f"Found {total:,} sessions in {len(found.folders()):,} folders: {kinds or 'none Toner can open'}."
        for kind, n in found.skipped.most_common():
            word = sessionimport.SKIPPED_NAMES.get(kind, kind)
            why = "Toner has no web sessions" if kind == "browser" else f"Toner has no {word} sessions"
            text += f" {n:,} {word} sessions are skipped ({why})."
        return text

    def import_sessions(self, found):
        if not found.items:
            QMessageBox.information(self, "Import", self.sessions_summary(found))
            return
        ask = self.sessions_summary(found) + " They go to Sessions, in the same folders. Import them?"
        if QMessageBox.question(self, "Import sessions", ask) != QMessageBox.StandardButton.Yes:
            return
        passwords = {}
        if found.source == "MobaXterm":
            box = QMessageBox(QMessageBox.Icon.Question, "Import sessions",
                              'Also import passwords from a MobaXterm "Stored Passwords" export? They are kept in Toner\'s vault, '
                              "never in its database. Delete the exported file afterwards: it holds them in plain text.",
                              parent=self)
            choose = box.addButton("Choose file...", QMessageBox.ButtonRole.AcceptRole)
            box.addButton("Not now", QMessageBox.ButtonRole.RejectRole)
            box.exec()
            if box.clickedButton() is choose:
                pw_path, _ = QFileDialog.getOpenFileName(self, "MobaXterm stored passwords", "", "Text files (*.txt);;All files (*)")
                if pw_path:
                    try:
                        passwords = sessionimport.mobaxterm_passwords(sessionimport.read_text(pw_path))
                    except OSError as e:
                        QMessageBox.warning(self, "Import failed", f"Could not read the file:\n{e}")
                        return
        from ui import orgassign
        made = []
        picks = orgassign.choose([(i["name"] or i["host"], list(i["folder"]), sessions.NAMES.get(i["kind"], i["kind"])) for i in found.items], self, made)
        if picks is None:
            return
        if made:
            self.orgs_created.emit()
        by_org = {}
        for item, org in zip(found.items, picks):
            by_org.setdefault(org, []).append({**item, "folder": orgassign.strip_top(list(item["folder"]), org)})
        as_devices = sessionimport.device_items(found)        # SSH, Telnet and Remote Desktop can be monitored devices too
        answer, chosen = None, None
        if as_devices:
            from ui import vendorassign
            rows = [{**item, "org": picks[i], "folder": orgassign.strip_top(list(item["folder"]), picks[i])} for i, item in as_devices]
            answer, chosen = vendorassign.choose(rows, {n: sessionimport.device_password(row, passwords) for n, row in enumerate(rows)}, self)
            if answer is None:
                return
        r = {"added": 0, "existing": 0, "folders": 0, "passwords": 0, "bad": []}
        new_ids = {}                                          # organization -> the ids of the sessions added there
        for org, items in by_org.items():                     # each organization gets only its own sessions
            with db.within(org):
                part = sessionimport.save(sessionimport.Found(found.source, items), passwords)
            for k in ("added", "existing", "folders", "passwords"):
                r[k] += part[k]
            r["bad"] += part["bad"]
            new_ids[org] = part["ids"]
        text = f"Imported {r['added']:,} sessions into Sessions ({r['folders']:,} folders created, {r['existing']:,} already there skipped)."
        if passwords:
            text += f" Passwords added for {r['passwords']:,} SSH sessions."
        lines = [text]
        if answer == "devices":
            d = {"added": 0, "existing": 0, "no_vendor": 0}
            by_org_dev = {}
            for (i, item), (vendor, platform) in zip(as_devices, chosen):
                by_org_dev.setdefault(picks[i], []).append({**item, "folder": orgassign.strip_top(list(item["folder"]), picks[i]),
                                                           "vendor": vendor, "platform": platform})
            for org, items in by_org_dev.items():
                with db.within(org):
                    part = sessionimport.add_devices(items, passwords)
                for k in d:
                    d[k] += part[k]
                r["bad"] += part["bad"]
            audit.log("devices imported", f"{found.source}: {d['added']} added, {d['no_vendor']} without a vendor")
            lines.append(f"Added {d['added']:,} devices to the device list ({d['existing']:,} were already there, "
                         f"{d['no_vendor']:,} without a vendor).")
            self.refresh()
            self.changed.emit()
        link = {"linked": 0, "unlinked": []}                   # after the devices, so one made from an entry counts too
        for org, ids in new_ids.items():
            with db.within(org):
                part = sessionimport.link_devices(ids)
            link["linked"] += part["linked"]
            link["unlinked"] += part["unlinked"]
        audit.log("sessions imported", f"{found.source}: {r['added']} added, {r['passwords']} passwords, {link['linked']} linked to devices")
        self.sessions_imported.emit()
        if r["added"]:
            lines.append(f"Linked {link['linked']:,} sessions to inventory devices with the same name." if link["linked"]
                         else "No new session had the same name as an inventory device, so none were linked.")
        if link["unlinked"]:
            lines.append(f"\nNot linked to a device ({len(link['unlinked'])}):")
            lines += [f"  \u2022 {b}" for b in link["unlinked"][:12]] + ([f"  ...and {len(link['unlinked']) - 12} more"] if len(link["unlinked"]) > 12 else [])
        if r["bad"]:
            lines.append(f"\nSkipped, with reasons ({len(r['bad'])}):")
            lines += [f"  \u2022 {b}" for b in r["bad"][:12]] + ([f"  ...and {len(r['bad']) - 12} more"] if len(r["bad"]) > 12 else [])
        QMessageBox.information(self, "Import", "\n".join(lines))
        if made:
            toast(self, orgassign.created_text(made))


    def screen_context(self):
        """What the Assistant is told about this page: the selected device(s), the folder, the search."""
        devs = self.selected_devices()
        out = {"page": "Inventory", "selected_devices": [d["name"] for d in devs], "devices_shown": sum(1 for k in self.payload if k.startswith("device:"))}
        if len(devs) == 1:
            d = devs[0]
            out["selected_device"] = {"name": d["name"], "vendor": d["vendor"], "host": d["host"], "location": d.get("location") or "",
                                      "tags": d.get("tags") or "", "details": d.get("details") or "", "enabled": bool(d.get("enabled", 1)),
                                      "status": self._status_word(d)}
        folders = self.selected_folders()
        if folders:
            paths = db.folder_paths()
            out["selected_folders"] = [paths.get(f, str(f)) for f in folders]
        words = self._words()
        if words:
            out["search"] = " ".join(words)
        return out
