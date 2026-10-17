"""Settings pages: proxy, agents and maintenance windows."""

import ipaddress
import os
import keyring
from datetime import datetime

from PySide6.QtCore import QDateTime, QTime
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QDateTimeEdit, QDialog, QDialogButtonBox,
                               QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QTableWidget,
                               QTableWidgetItem, QTimeEdit, QVBoxLayout, QWidget)
from core import agents, audit, db, maintenance, orgs, proxy, tunnel
from ui.widgets import GroupPicker
from ui.settings_base import Collapsible, Page, compact_row, note, row_of, spin


# ------------------------------------------------------------------ Proxy
TUNNEL_OTP = [("ask", "Ask me when the server asks (Duo, a code, a YubiKey)"), ("totp", "Make it from a secret key")]


class ProxyPage(Page):
    """Two sections: the proxy Toner's connections use, and an SSH tunnel (PuTTY's Dynamic port forwarding) that the proxy
    can point at, as SOCKS5 127.0.0.1:1080."""
    title = "Proxy"

    def __init__(self):
        super().__init__()
        # ---------------------------------------------------------------- the proxy
        self.mode, self.kind = QComboBox(), QComboBox()
        for k, label in proxy.MODES:
            self.mode.addItem(label, k)
        for k, label in proxy.KINDS:
            self.kind.addItem(label, k)
        self.host, self.user, self.bypass = QLineEdit(), QLineEdit(), QLineEdit()
        self.host.setPlaceholderText("proxy.example.com, or 127.0.0.1 for the SSH tunnel below")
        self.user.setPlaceholderText("optional")
        self.bypass.setPlaceholderText("localhost, 127.0.0.1, *.corp.example.com, 10.0.0.0/8")
        self.port = spin(1, 65535)
        self.port.setValue(8080)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.forget = QPushButton("Remove saved password")
        self.pw_note = note("")
        self.otp, self.otp_key = QComboBox(), QLineEdit()
        for k, label in proxy.OTP_MODES:
            self.otp.addItem(label, k)
        self.otp.setToolTip("For a proxy with two-step sign-in: the current code from an authenticator app is added to the end of the password.")
        self.otp_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.otp_note = note("")
        self.system = note("")
        self.test_to = QLineEdit("www.githubstatus.com:443")
        self.test_btn = QPushButton("Test")
        self.test_out = QLabel("")
        self.test_out.setWordWrap(True)
        self._forget = False
        self._have_key = False
        self.manual = [self.kind, self.host, self.port, self.user, self.password, self.forget, self.bypass, self.otp, self.otp_key]
        self.form.addRow("Connections Go", self.mode)
        self.form.addRow("", self.system)
        self.form.addRow("Proxy Type", self.kind)
        self.form.addRow("Address", self.host)
        self.form.addRow("Port", self.port)
        self.form.addRow("User Name", self.user)
        self.form.addRow("Password", self.password)
        self.forget_row = row_of(self.forget)
        self.form.addRow("", self.forget_row)
        self.form.addRow("", self.pw_note)
        self.form.addRow("One-Time Code", self.otp)
        self.form.addRow("Secret Key", self.otp_key)
        self.form.addRow("", self.otp_note)
        self.form.addRow("Do Not Use It For", self.bypass)
        self.form.addRow("Try a Connection To", row_of(self.test_to, self.test_btn))
        self.form.addRow("", self.test_out)

        # ---------------------------------------------------------------- the SSH tunnel
        self.t_enabled = QCheckBox("Use an SSH tunnel (like PuTTY's Dynamic port forwarding)")
        self.t_host, self.t_user, self.t_key = QLineEdit(), QLineEdit(), QLineEdit()
        self.t_host.setPlaceholderText("the SSH server, e.g. bastion.example.com")
        self.t_user.setPlaceholderText("as in PuTTY's 'login as'")
        self.t_key.setPlaceholderText("optional: a private key file (OpenSSH or PEM)")
        self.t_port = spin(1, 65535)
        self.t_port.setValue(22)
        self.t_browse = QPushButton("Browse...")
        self.t_browse.setAutoDefault(False)
        self.t_key_row = row_of(self.t_key, self.t_browse)
        self.t_password = QLineEdit()
        self.t_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.t_forget = QPushButton("Remove saved password")
        self.t_pw_note = note("")
        self.t_otp, self.t_otp_key = QComboBox(), QLineEdit()
        for k, label in TUNNEL_OTP:
            self.t_otp.addItem(label, k)
        self.t_otp_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.t_otp_note = note("")
        self.t_local = spin(1, 65535)
        self.t_local.setValue(1080)
        self.t_autostart = QCheckBox("Connect when Toner starts")
        self.t_connect, self.t_disconnect, self.t_use = QPushButton("Connect"), QPushButton("Disconnect"), QPushButton("Use it for the proxy above")
        for b in (self.t_connect, self.t_disconnect, self.t_use):
            b.setAutoDefault(False)
        self.t_use.setToolTip("Sets the proxy above to SOCKS5 127.0.0.1 and this Local SOCKS Port")
        self.t_status = QLabel("")
        self.t_status.setWordWrap(True)
        self._t_forget = False
        self._t_have_pw = self._t_have_key = False
        self.tform = QFormLayout()
        self.tform.addRow("", self.t_enabled)
        self.tform.addRow("Server", self.t_host)
        self.tform.addRow("Port", self.t_port)
        self.tform.addRow("User Name", self.t_user)
        self.tform.addRow("Key File", self.t_key_row)
        self.tform.addRow("Password", self.t_password)
        self.t_forget_row = row_of(self.t_forget)
        self.tform.addRow("", self.t_forget_row)
        self.tform.addRow("", self.t_pw_note)
        self.tform.addRow("Second Step", self.t_otp)
        self.tform.addRow("Secret Key", self.t_otp_key)
        self.tform.addRow("", self.t_otp_note)
        self.tform.addRow("Local SOCKS Port", self.t_local)
        self.tform.addRow("", self.t_autostart)
        self.t_buttons = row_of(self.t_connect, self.t_disconnect, self.t_use)
        self.tform.addRow("", self.t_buttons)
        self.tform.addRow("Status", self.t_status)
        self.t_fields = [self.t_host, self.t_port, self.t_user, self.t_key, self.t_browse, self.t_password, self.t_forget, self.t_otp,
                         self.t_otp_key, self.t_local, self.t_autostart, self.t_connect, self.t_disconnect, self.t_use]

        # ---------------------------------------------------------------- the two sections
        self.lay.removeItem(self.form)
        self.proxy_box, self.tunnel_box = QGroupBox("Proxy"), QGroupBox("SSH Tunnel")
        self.proxy_box.setLayout(self.form)
        tl = QVBoxLayout(self.tunnel_box)
        tl.addWidget(note(
            "Sign in to an SSH server and open a SOCKS5 port on this computer, as PuTTY's Dynamic port forwarding does (no PuTTY "
            "needed). Then point the proxy above at it: SOCKS5, address 127.0.0.1, port 1080 (the button below fills that in), "
            "or set it on just the devices that need it in their Access tab. Use the same server, user name and password as with "
            "PuTTY. When the server asks for a Duo option (type 1 for a push, then approve it), a code or a YubiKey touch, a box "
            "appears. A connection through the port while the tunnel is closed signs in first. Like PuTTY's, the port is on this "
            "computer only."))
        tl.addLayout(self.tform)
        self.lay.insertWidget(0, self.proxy_box)
        self.lay.insertWidget(1, self.tunnel_box)
        self.lay.insertWidget(0, note(
            "Send Toner's connections through a proxy. This is the setting for every connection; a device can override it "
            "in its own Access tab. It covers SSH (checks, backups, the console), the web APIs of Fortinet, Palo Alto, "
            "Meraki and UniFi, status pages, web, port and certificate checks, and notifications. SNMP, ping, "
            "traceroute and the listeners use UDP or ICMP, which a proxy does not carry, so they always connect directly. "
            "'Windows proxy settings' covers web connections only, as a browser would; choose 'Use the proxy below' to "
            "send SSH and port checks through a proxy as well."))

        self.mode.currentIndexChanged.connect(self.adapt)
        self.otp.currentIndexChanged.connect(self.adapt)
        self._kind_was = self.kind.currentData()
        self.kind.currentIndexChanged.connect(self._kind_changed)
        self.forget.clicked.connect(self._clear_password)
        self.test_btn.clicked.connect(self.test)
        self.t_enabled.toggled.connect(self.adapt)
        self.t_otp.currentIndexChanged.connect(self.adapt)
        self.t_key.textChanged.connect(self.adapt)
        self.t_browse.clicked.connect(self._browse_key)
        self.t_forget.clicked.connect(self._clear_tunnel_password)
        self.t_connect.clicked.connect(self.connect_tunnel)
        self.t_disconnect.clicked.connect(self.disconnect_tunnel)
        self.t_use.clicked.connect(self.use_tunnel)

    # ---------------------------------------------------------------- showing the right rows
    def adapt(self, *_):
        manual = self.mode.currentData() == "manual"
        for w in self.manual:
            w.setEnabled(manual)
        self.form.setRowVisible(self.system, self.mode.currentData() == "system")
        code = self.otp.currentData()
        self.form.setRowVisible(self.otp_key, code == "totp")
        self.form.setRowVisible(self.otp_note, bool(code))
        where = "The code is added to the end of the password (or used alone if there is no password)."
        self.otp_note.setText(
            f"When the proxy asks for a second step, type the code from your authenticator app (or touch your YubiKey) when Toner "
            f"connects. {where} Checks that run by themselves cannot ask you, so use a secret key for those." if code == "ask" else
            f"Toner works out the current code itself from the secret key (the text shown beside the QR code when the account was "
            f"set up). {where} The key is kept in Toner's vault."
            + (" A key is saved; leave the box empty to keep it." if self._have_key else "") if code == "totp" else "")
        on = self.t_enabled.isChecked()
        for w in self.t_fields:
            w.setEnabled(on)
        has_key = bool(self.t_key.text().strip())
        self.t_password.setPlaceholderText("the key's passphrase, if it has one" if has_key else "the password you use with PuTTY")
        self.tform.setRowVisible(self.t_otp_key, self.t_otp.currentData() == "totp")
        self.t_otp_note.setText(
            "Toner works out the code from the secret key and answers the server's question with it, so the tunnel can sign in "
            "again by itself." + (" A key is saved; leave the box empty to keep it." if self._t_have_key else "")
            if self.t_otp.currentData() == "totp" else
            "A box appears for the server's question. A Duo push or a YubiKey touch needs you, so checks that run by themselves "
            "use the tunnel while it is open and cannot sign it in again.")
        self.refresh_tunnel()

    def refresh_tunnel(self, message=""):
        s = tunnel.status()
        if s["open"]:
            since = datetime.fromtimestamp(s["since"]).strftime("%H:%M") if s["since"] else ""
            text = f"Connected to {s['label'].replace('SSH tunnel ', '')} since {since}; SOCKS5 is on 127.0.0.1:{s['port']}."
        else:
            text = "Not connected." + ("" if s["enabled"] else " Save to set it up (Connect tries it now)." if self.t_enabled.isChecked()
                                       else " Tick 'Use an SSH tunnel' to set it up.")
        self.t_status.setText((message + " " if message else "") + text)
        self.t_connect.setEnabled(self.t_enabled.isChecked() and not s["open"])
        self.t_disconnect.setEnabled(s["open"])

    def _kind_changed(self, *_):
        """A new type brings its usual port, unless the port was changed by hand."""
        new = self.kind.currentData()
        if self.port.value() == proxy.DEFAULT_PORTS.get(self._kind_was):
            self.port.setValue(proxy.DEFAULT_PORTS.get(new, self.port.value()))
        self._kind_was = new
        self.adapt()

    def _browse_key(self):
        start = self.t_key.text().strip() or os.path.join(os.path.expanduser("~"), ".ssh")
        path, _ = QFileDialog.getOpenFileName(self, "Private key file", start)
        if path:
            self.t_key.setText(os.path.normpath(path))

    def _clear_password(self):
        self._forget = True
        self.password.clear()
        self.pw_note.setText("The saved password will be removed when you save.")
        self.form.setRowVisible(self.pw_note, True)

    def _clear_tunnel_password(self):
        self._t_forget = True
        self.t_password.clear()
        self.t_pw_note.setText("The saved password will be removed when you save.")
        self.tform.setRowVisible(self.t_pw_note, True)

    # ---------------------------------------------------------------- the tunnel's buttons
    def _tunnel_values(self):
        return {"enabled": self.t_enabled.isChecked(), "host": self.t_host.text().strip(), "port": self.t_port.value(),
                "username": self.t_user.text().strip(), "key_file": self.t_key.text().strip(), "otp": self.t_otp.currentData(),
                "local_port": self.t_local.value(), "autostart": self.t_autostart.isChecked()}

    def _tunnel_config(self):
        """The tunnel as shown on the page (saved or not), with the typed password and key, or the saved ones."""
        return tunnel.config(self._tunnel_values(),
                             self.t_password.text() or ("" if self._t_forget else keyring.get_password(db.SERVICE, tunnel.SECRET) or ""),
                             proxy.clean_key(self.t_otp_key.text()) or keyring.get_password(db.SERVICE, tunnel.OTP_SECRET) or "")

    def connect_tunnel(self):
        cfg = self._tunnel_config()
        if cfg is None:
            self.refresh_tunnel("Enter the SSH server first.")
            return
        self.t_status.setText(f"Signing in to {cfg.host}... answer the box, or approve the Duo push, if one comes.")
        self.t_connect.setEnabled(False)
        try:
            tunnel.get(cfg, local_port=self.t_local.value())         # the window stays usable while it signs in
            self.refresh_tunnel()
        except OSError as e:
            self.refresh_tunnel(f"Failed: {e}.")

    def disconnect_tunnel(self):
        tunnel.close_all()
        self.refresh_tunnel("Disconnected; the next connection through it signs in again.")

    def use_tunnel(self):
        self.mode.setCurrentIndex(self.mode.findData("manual"))
        self.kind.setCurrentIndex(self.kind.findData("socks5"))
        self.host.setText("127.0.0.1")
        self.port.setValue(self.t_local.value())
        self.user.clear()
        self.otp.setCurrentIndex(self.otp.findData(""))
        self.adapt()
        self.test_out.setText(f"The proxy now points at the SSH tunnel (SOCKS5 127.0.0.1:{self.t_local.value()}). Save to keep it.")

    # ---------------------------------------------------------------- load, check, save
    def load(self):
        s = proxy.settings()
        self.mode.setCurrentIndex(max(0, self.mode.findData(s["mode"])))
        self.kind.setCurrentIndex(max(0, self.kind.findData(s["kind"])))
        self.host.setText(s["host"])
        self.port.setValue(int(s["port"] or 8080))
        self.user.setText(s["username"])
        self.bypass.setText(s["bypass"])
        self.password.clear()
        self._forget = False
        have = bool(keyring.get_password(db.SERVICE, proxy.GLOBAL_SECRET))
        self.pw_note.setText("A password is saved in the vault. Leave the box empty to keep it." if have else "")
        self.form.setRowVisible(self.forget_row, have)                    # no empty rows when nothing is saved
        self.form.setRowVisible(self.pw_note, have)
        self.otp.setCurrentIndex(max(0, self.otp.findData(s.get("otp") or "")))
        self.otp_key.clear()
        self._have_key = bool(keyring.get_password(db.SERVICE, proxy.GLOBAL_OTP))
        sys_text = proxy.system_text()
        self.system.setText(f"Windows is set to use: {sys_text}" if sys_text else
                            "Windows has no proxy configured, so connections go directly.")
        self.test_out.setText("")
        t = tunnel.settings()
        self.t_enabled.setChecked(bool(t["enabled"]))
        self.t_host.setText(t["host"])
        self.t_port.setValue(int(t["port"] or 22))
        self.t_user.setText(t["username"])
        self.t_key.setText(t["key_file"])
        self.t_otp.setCurrentIndex(max(0, self.t_otp.findData(t["otp"] or "ask")))
        self.t_local.setValue(int(t["local_port"] or 1080))
        self.t_autostart.setChecked(bool(t["autostart"]))
        self.t_password.clear()
        self.t_otp_key.clear()
        self._t_forget = False
        self._t_have_pw = bool(keyring.get_password(db.SERVICE, tunnel.SECRET))
        self._t_have_key = bool(keyring.get_password(db.SERVICE, tunnel.OTP_SECRET))
        self.t_pw_note.setText("A password is saved in the vault. Leave the box empty to keep it." if self._t_have_pw else "")
        self.tform.setRowVisible(self.t_forget_row, self._t_have_pw)
        self.tform.setRowVisible(self.t_pw_note, self._t_have_pw)
        self.adapt()

    def validate(self):
        if self.mode.currentData() == "manual" and not self.host.text().strip():
            return ["Proxy: enter the proxy's address, or choose another option."]
        if self.mode.currentData() == "manual" and self.otp.currentData() == "totp":
            if not self.otp_key.text().strip() and not self._have_key:
                return ["Proxy: enter the secret key for the one-time code, or choose 'Ask me for it when connecting'."]
            if self.otp_key.text().strip():
                try:
                    proxy.totp(self.otp_key.text())
                except proxy.ProxyError as e:
                    return [f"Proxy: {e}."]
        if self.t_enabled.isChecked():
            if not self.t_host.text().strip():
                return ["SSH Tunnel: enter the SSH server, or untick 'Use an SSH tunnel'."]
            key = os.path.expandvars(os.path.expanduser(self.t_key.text().strip().strip('"')))
            if key and not os.path.isfile(key):
                return [f"SSH Tunnel: the key file {key} was not found."]
            if self.t_otp.currentData() == "totp":
                if not self.t_otp_key.text().strip() and not self._t_have_key:
                    return ["SSH Tunnel: enter the secret key for the second step, or choose to be asked."]
                if self.t_otp_key.text().strip():
                    try:
                        proxy.totp(self.t_otp_key.text())
                    except proxy.ProxyError as e:
                        return [f"SSH Tunnel: {e}."]
        return []

    def save(self):
        db.set_setting("proxy", {"mode": self.mode.currentData(), "kind": self.kind.currentData(),
                                 "host": self.host.text().strip(), "port": self.port.value(),
                                 "username": self.user.text().strip(), "bypass": self.bypass.text().strip(),
                                 "otp": self.otp.currentData(), "key_file": ""})
        if self.password.text():
            db.set_secret(proxy.GLOBAL_SECRET, self.password.text())
        elif self._forget:
            db.delete_secret(proxy.GLOBAL_SECRET)
        if self.otp.currentData() != "totp":
            if self._have_key:
                db.delete_secret(proxy.GLOBAL_OTP)
        elif self.otp_key.text().strip():
            db.set_secret(proxy.GLOBAL_OTP, proxy.clean_key(self.otp_key.text()))
        before, after = tunnel.settings(), self._tunnel_values()
        if (any(before.get(k) != after[k] for k in ("enabled", "host", "port", "username", "key_file", "local_port"))
                or self.t_password.text() or self._t_forget):
            tunnel.close_all()                       # a tunnel signed in with the old settings is not kept
        db.set_setting("ssh_tunnel", after)
        if self.t_password.text():
            db.set_secret(tunnel.SECRET, self.t_password.text())
        elif self._t_forget:
            db.delete_secret(tunnel.SECRET)
        if self.t_otp.currentData() != "totp":
            if self._t_have_key:
                db.delete_secret(tunnel.OTP_SECRET)
        elif self.t_otp_key.text().strip():
            db.set_secret(tunnel.OTP_SECRET, proxy.clean_key(self.t_otp_key.text()))
        audit.log("proxy settings changed", (f"{self.mode.currentData()} {self.host.text().strip()}:{self.port.value()}"
                                             if self.mode.currentData() == "manual" else self.mode.currentData())
                  + (f"; SSH tunnel {after['host']}:{after['port']} on local port {after['local_port']}" if after["enabled"] else ""))
        self.load()

    def test(self):
        target = self.test_to.text().strip() or "www.githubstatus.com:443"
        host, _, port = target.rpartition(":") if target.count(":") == 1 else (target, "", "443")
        if not host or not port.isdigit():
            self.test_out.setText("Enter an address such as www.githubstatus.com:443.")
            return
        mode = self.mode.currentData()
        QApplication.setOverrideCursor(self.cursor())
        try:
            if mode == "manual":
                cfg = proxy._config({"kind": self.kind.currentData(), "host": self.host.text(), "port": self.port.value(),
                                     "username": self.user.text(), "otp": self.otp.currentData()},
                                    self.password.text() or ("" if self._forget else
                                                             keyring.get_password(db.SERVICE, proxy.GLOBAL_SECRET) or ""),
                                    proxy.clean_key(self.otp_key.text()) or keyring.get_password(db.SERVICE, proxy.GLOBAL_OTP) or "")
                ok, msg = (False, "Enter the proxy's address first.") if cfg is None else proxy.test_tunnel(cfg, host, int(port))
            else:
                ok, msg = proxy.test_web(host, int(port), direct=(mode == "none"))
        finally:
            QApplication.restoreOverrideCursor()
        self.test_out.setText(("OK: " if ok else "Failed: ") + msg)
        self.refresh_tunnel()


# ------------------------------------------------------------------ Agents
class AgentsPage(Page):
    title = "Agents"

    def __init__(self):
        super().__init__()
        self.enabled = QCheckBox("Receive reports from agents")
        self.enroll = QCheckBox("Let computers sign themselves up with the agent package")
        self.enroll.setToolTip("Anyone holding the package can add a computer to Toner while this is on. Turn it off when you have installed what you need.")
        self.key = QLineEdit()
        self.key.setReadOnly(True)
        self.key.setEchoMode(QLineEdit.EchoMode.Password)
        self.newkey = QPushButton("New key...")
        self.minutes = spin(1, 60, " minutes")
        self.minutes.setValue(5)
        self.push = QCheckBox("Also change computers that already have the agent")
        self.push.setToolTip("Toner tells each installed agent this interval in its next report, and the agent changes its own schedule. "
                             "Leave it off to keep each computer as it was installed. Only agents from this version of Toner on take it.")
        self.download = QPushButton("Download agent package...")
        self.download.setProperty("primary", True)
        self.dest = QComboBox()                                           # Global: which organization the package signs computers up to
        self.dest.setProperty("notSetting", True)
        self.dest.setToolTip("The package carries that organization's sign-up key, so the computers it signs up are added there.")
        self.dest_label = QLabel("Signs computers up to:")
        self.port = spin(1, 65535)
        self.port.setValue(agents.DEFAULT_PORT)
        self.bind = QLineEdit()
        self.bind.setPlaceholderText("0.0.0.0 (every network card)")
        self.address = QLineEdit()
        self.address.setPlaceholderText("this computer's DNS name, used in new agent scripts")
        self.print = QLineEdit()
        self.print.setReadOnly(True)
        self.print.setToolTip("SHA-256 fingerprint of Toner's agent certificate. Every agent script has it built in.")
        self.renew = QPushButton("New certificate...")
        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.firewall = QLineEdit()
        self.firewall.setReadOnly(True)
        self.computers = QLabel("")
        self.computers.setWordWrap(True)
        self.computers.setProperty("muted", True)
        self.token_days = spin(0, 3650, " days")
        self.token_days.setSpecialValueText("never")
        self.token_days.setToolTip("Computers that installed the package are given a new token this often. The old one still works for a week.")
        self.cert_note = QLabel("")
        self.cert_note.setWordWrap(True)
        self.banner = QLabel("")                                          # one line that says whether this works, before any of the settings
        self.banner.setWordWrap(True)
        self.banner.setStyleSheet("font-weight: 600; padding: 6px 0;")
        self.copy_fw = QPushButton("Copy")
        self.copy_fw.setAutoDefault(False)
        self.copy_fw.clicked.connect(lambda: QApplication.clipboard().setText(self.firewall.text()))
        self.form.addRow("", self.enabled)
        self.form.addRow("", self.enroll)
        self.form.addRow("Sign-up key", row_of(self.key, self.newkey))
        self.form.addRow("Report every", self.minutes)
        self.form.addRow("", self.push)
        self.form.addRow("Package", compact_row(self.download, self.dest_label, self.dest))
        self.form.addRow("Computers", self.computers)
        adv = QWidget()                                                   # what most people never change
        af = QFormLayout(adv)
        af.setContentsMargins(0, 0, 0, 0)
        af.addRow("Port", self.port)
        af.addRow("Listen on", self.bind)
        af.addRow("Toner's address", self.address)
        af.addRow("Certificate", row_of(self.print, self.renew))
        af.addRow("", self.cert_note)
        af.addRow("Replace tokens every", self.token_days)
        af.addRow("", self.status)
        af.addRow("Windows Firewall", row_of(self.firewall, self.copy_fw))
        self.advanced = Collapsible("Advanced: port, address, certificate, tokens, firewall", adv)
        self.lay.insertWidget(1, self.advanced)
        self.lay.insertWidget(0, self.banner)
        self.intro = note(
            "An agent is a small program on a Windows computer that reports to Toner on a schedule. Nothing connects to the computer, so it "
            "suits laptops, computers outside the domain and anything behind a firewall. Download the package below, copy it to the computer "
            "and double-click Install-TonerAgent.cmd: the computer signs itself up and appears in the Inventory. Reports arrive over HTTPS, "
            "one token per computer, pinned to the certificate below. To set up one computer by hand instead, add a Windows device with "
            "How to monitor: Agent, then use its Windows tab > Get agent script. Toner only receives reports while it is running (in the tray "
            "is fine). Windows may ask whether to allow Toner through its firewall the first time; allow it on the networks the agents are on.")
        self.lay.insertWidget(1, Collapsible("How agents work", self.intro))
        for w in (self.enabled, self.port, self.bind, self.address, self.renew, self.token_days):
            w.setProperty("globalOnly", True)                             # one receiver for every organization
        self.renew.clicked.connect(self._renew)
        self.newkey.clicked.connect(self._newkey)
        self.download.clicked.connect(self._download)

    def load(self):
        inside = db.home() != db.GLOBAL
        self.enroll.setText(f"Let computers sign themselves up to {db.org_name(db.home())} with the agent package" if inside
                            else "Let computers sign themselves up with the agent package")
        self.dest.clear()
        self.dest.addItem("Global", db.GLOBAL)
        for o in orgs.list_orgs(archived=False) if not inside else []:
            self.dest.addItem(o["name"], o["id"])
        self.dest.setVisible(self.dest.count() > 1)
        self.dest_label.setVisible(self.dest.count() > 1)
        self.enabled.setChecked(bool(db.get_setting("agent_enabled")))
        self.enroll.setChecked(bool(db.get_setting("agent_enroll")))
        self.port.setValue(int(db.get_setting("agent_port") or agents.DEFAULT_PORT))
        self.minutes.setValue(int(db.get_setting("agent_minutes") or 5))
        self.push.setChecked(bool(db.get_setting("agent_push_minutes")))
        self.bind.setText(db.get_setting("agent_bind") if db.get_setting("agent_bind") != "0.0.0.0" else "")
        self.address.setText(db.get_setting("agent_address") or "")
        self.token_days.setValue(int(db.get_setting("agent_token_days") or 0))
        self.refresh()

    def refresh(self):
        try:
            self.key.setText(agents.enroll_key())
        except Exception:
            self.key.setText("")
        try:
            self.print.setText(agents.fingerprint())
        except Exception as e:
            self.print.setText(f"(could not make the certificate: {e})")
        self.firewall.setText(f'New-NetFirewallRule -DisplayName "Toner agent receiver" -Direction Inbound -Protocol TCP -LocalPort {self.port.value()} -Action Allow')
        s = agents.status()
        if s["running"]:
            self.status.setText(f"Listening on port {s['port']}. {s['accepted']} report(s) accepted, {s['rejected']} refused since Toner started.")
        elif s["error"]:
            self.status.setText("Could not start: " + s["error"])
        else:
            self.status.setText("Not listening.")
        if self.enroll.isChecked() and not self.enabled.isChecked():
            self.status.setText(self.status.text() + " Sign-up needs the receiver turned on.")
        self.firewall.setCursorPosition(0)                                # show the start of the command, not its end
        try:
            left = agents.cert_days_left()
            self.cert_note.setText(f"The certificate is good for {left} more days." if left >= 90 else
                                   f"The certificate expires in {left} days. Renew it, then give every computer a new package or script.")
            self.cert_note.setProperty("muted", left >= 90)
            self.cert_note.setStyleSheet("" if left >= 90 else "color: #d32f2f; font-weight: bold;")
        except Exception:
            self.cert_note.setText("")
        rows = agents.overview()
        silent_after = float(db.get_thresholds()["agent_silent"]["fail"])
        silent = sum(1 for r in rows if r["has_token"] and r["age"] is not None and r["age"] > silent_after)
        self.computers.setText((f"{len(rows)} computer(s) report through an agent" + (f", {silent} silent" if silent else "") + ". ") if rows else
                               "No computer reports through an agent yet. ")
        self.computers.setText(self.computers.text() + "They are listed under Inventory > Agents, where you can revoke or remove one.")
        if s["running"]:
            self.banner.setText(f"Receiving reports on port {s['port']}  -  " + (f"{len(rows)} computer{'s' if len(rows) != 1 else ''} reporting"
                                                                                  + (f", {silent} silent" if silent else "") if rows else "no computer has reported yet"))
            self.banner.setStyleSheet("font-weight: 600; padding: 6px 0; color: #2e9e5b;")
        elif s["error"]:
            self.banner.setText("The receiver could not start: " + s["error"])
            self.banner.setStyleSheet("font-weight: 600; padding: 6px 0; color: #d32f2f;")
        else:
            self.banner.setText("The receiver is off  -  tick 'Receive reports from agents' and save to start it")
            self.banner.setStyleSheet("font-weight: 600; padding: 6px 0;")

    def validate(self):
        bind = self.bind.text().strip()
        if bind:
            try:
                ipaddress.ip_address(bind)
            except ValueError:
                return ["Agents: 'Listen on' must be an IP address (or empty for every network card)."]
        return []

    def save(self):
        db.set_setting("agent_enabled", self.enabled.isChecked())
        db.set_setting("agent_enroll", self.enroll.isChecked())
        db.set_setting("agent_port", self.port.value())
        was = (int(db.get_setting("agent_minutes") or 5), bool(db.get_setting("agent_push_minutes")))
        db.set_setting("agent_minutes", self.minutes.value())
        db.set_setting("agent_push_minutes", self.push.isChecked())
        if self.push.isChecked() and (self.minutes.value(), True) != was:
            audit.log("agent interval", f"installed agents are told to report every {self.minutes.value()} min")
        db.set_setting("agent_bind", self.bind.text().strip() or "0.0.0.0")
        db.set_setting("agent_address", self.address.text().strip())
        db.set_setting("agent_token_days", self.token_days.value())
        agents.apply()
        audit.log("agent receiver " + ("on" if self.enabled.isChecked() else "off"),
                  f"port {self.port.value()}, sign-up {'on' if self.enroll.isChecked() else 'off'}")
        self.refresh()

    def _stored_matches(self):
        """The package is built from what is saved, so unsaved edits would not be in it."""
        bind = self.bind.text().strip() or "0.0.0.0"
        return (self.port.value() == int(db.get_setting("agent_port") or agents.DEFAULT_PORT)
                and self.minutes.value() == int(db.get_setting("agent_minutes") or 5)
                and self.address.text().strip() == (db.get_setting("agent_address") or "")
                and self.enabled.isChecked() == bool(db.get_setting("agent_enabled"))
                and self.enroll.isChecked() == bool(db.get_setting("agent_enroll")) and bind == (db.get_setting("agent_bind") or "0.0.0.0"))

    def _download(self):
        if not self._stored_matches():
            QMessageBox.information(self, "Agent package", "Save your changes first: the package is made from the saved settings.")
            return
        org = db.home() if db.home() != db.GLOBAL else (self.dest.currentData() or db.GLOBAL)    # whose key goes in it
        with db.within(org):
            enroll_on = bool(db.get_setting("agent_enroll"))
            minutes = int(db.get_setting("agent_minutes") or 5)
        if not enroll_on:
            if QMessageBox.question(self, "Agent package", "Sign-up is off, so computers cannot add themselves with this package. "
                                    "Make it anyway?") != QMessageBox.StandardButton.Yes:
                return
        suffix = f"-{agents.safe_name(db.org_name(org))}" if org != db.GLOBAL else ""
        path, _ = QFileDialog.getSaveFileName(self, "Save agent package", f"Toner-Agent{suffix}.zip", "Zip file (*.zip)")
        if not path:
            return
        try:
            with db.within(org):
                data = agents.package_bytes(minutes)
            with open(path, "wb") as f:
                f.write(data)
        except Exception as e:
            QMessageBox.warning(self, "Agent package", f"The package could not be made: {e}")
            return
        with db.within(org):
            audit.log("agent package downloaded", f"reports every {minutes} min")
        QMessageBox.information(self, "Agent package", f"Saved {path}.\n\nCopy it to the Windows computer, unzip it, and double-click "
                                f"Install-TonerAgent.cmd. The package holds the sign-up key: keep it private.")

    def _newkey(self):
        if QMessageBox.question(self, "New sign-up key", "Packages already downloaded will no longer be able to sign computers up "
                                "(computers that already signed up keep working). Continue?") != QMessageBox.StandardButton.Yes:
            return
        agents.enroll_key(rotate=True)
        audit.log("agent sign-up key renewed")
        self.refresh()

    def _renew(self):
        if QMessageBox.question(self, "New certificate", "Every agent script has the current certificate's fingerprint built in. After a new "
                                "certificate, all agents are turned away until each one is given a new script. Continue?") != QMessageBox.StandardButton.Yes:
            return
        agents.renew_cert()
        audit.log("windows agent certificate renewed")
        self.refresh()


# ------------------------------------------------------------------ Maintenance windows
class MaintenanceDialog(QDialog):
    def __init__(self, win=None, parent=None):
        super().__init__(parent)
        self.win = win or {}
        self.setWindowTitle("Edit maintenance window" if win else "New maintenance window")
        self.setMinimumWidth(480)
        now = QDateTime.currentDateTime()
        self.name, self.note = QLineEdit(), QLineEdit()
        self.name.setPlaceholderText("e.g. Saturday patching, Chicago switch upgrade")
        self.note.setPlaceholderText("optional")
        self.kind = QComboBox()
        self.kind.addItem("One time", "once")
        self.kind.addItem("Repeats every week", "weekly")
        self.start, self.end = QDateTimeEdit(now), QDateTimeEdit(now.addSecs(2 * 3600))
        for w in (self.start, self.end):
            w.setCalendarPopup(True)
            w.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.days = [QCheckBox(d) for d in maintenance.DAYS]
        self.t_start, self.t_end = QTimeEdit(QTime(22, 0)), QTimeEdit(QTime(2, 0))
        for w in (self.t_start, self.t_end):
            w.setDisplayFormat("HH:mm")
        self.scope = GroupPicker(all_text="All devices", noun="groups")
        self.scope.set_labels(db.group_labels()[1:])
        self.enabled = QCheckBox("Enabled")
        self.enabled.setChecked(True)
        from ui.orgfield import OrgField, show_row
        self.org = OrgField(self.win)
        self.form = QFormLayout()
        self.form.addRow("Organization", self.org)
        show_row(self.form, self.org)
        daybox = QWidget()
        dl = QHBoxLayout(daybox)
        dl.setContentsMargins(0, 0, 0, 0)
        for c in self.days:
            dl.addWidget(c)
        timebox = row_of(QLabel("from"), self.t_start, QLabel("to"), self.t_end)
        self.rows = {"start": self.start, "end": self.end, "days": daybox, "times": timebox}
        for label, w in (("Name", self.name), ("Type", self.kind), ("Starts", self.start), ("Ends", self.end),
                         ("Days", daybox), ("Time of day", timebox), ("Applies to", self.scope), ("Note", self.note),
                         ("", self.enabled)):
            self.form.addRow(label, w)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(self.form)
        lay.addWidget(note("While a window is active, alerts for the devices it covers are held back. Checks still run "
                           "and are recorded. When it ends, a problem that is still there is announced, and one that "
                           "was fixed is reported as recovered. A time that runs past midnight (22:00 to 02:00) is "
                           "counted from the day it starts."))
        lay.addWidget(buttons)
        w = self.win
        if w:
            self.name.setText(w["name"])
            self.kind.setCurrentIndex(max(0, self.kind.findData(w["kind"])))
            self.note.setText(w.get("note") or "")
            self.enabled.setChecked(bool(w.get("enabled", 1)))
            self.scope.set_selected(w.get("scope") or [])
            if w["kind"] == "once":
                self.start.setDateTime(QDateTime.fromString(w["start_at"], "yyyy-MM-dd HH:mm"))
                self.end.setDateTime(QDateTime.fromString(w["end_at"], "yyyy-MM-dd HH:mm"))
            else:
                for i, c in enumerate(self.days):
                    c.setChecked(i in (w.get("days") or []))
                self.t_start.setTime(QTime.fromString(w["start_time"], "HH:mm"))
                self.t_end.setTime(QTime.fromString(w["end_time"], "HH:mm"))
        else:
            for c in self.days[5:]:
                c.setChecked(True)
        self.kind.currentIndexChanged.connect(self.adapt)
        self.adapt()

    def adapt(self, *_):
        once = self.kind.currentData() == "once"
        for key, w in self.rows.items():
            self.form.setRowVisible(w, once if key in ("start", "end") else not once)

    def values(self):
        return {"id": self.win.get("id"), "org": self.org.file(), "shared": self.org.shared(),
                "name": self.name.text().strip(), "kind": self.kind.currentData(),
                "start_at": self.start.dateTime().toString("yyyy-MM-dd HH:mm"),
                "end_at": self.end.dateTime().toString("yyyy-MM-dd HH:mm"),
                "days": [i for i, c in enumerate(self.days) if c.isChecked()],
                "start_time": self.t_start.time().toString("HH:mm"), "end_time": self.t_end.time().toString("HH:mm"),
                "scope": self.scope.selected(), "enabled": int(self.enabled.isChecked()), "note": self.note.text().strip()}

    def accept(self):
        if not self.org.chosen():
            QMessageBox.warning(self, "Organization", "Choose the organization this window belongs to.")
            return
        try:
            maintenance.validate(self.values())
        except ValueError as e:
            QMessageBox.warning(self, "Maintenance window", str(e))
            return
        super().accept()



class MaintenancePage(Page):
    title = "Maintenance"

    def __init__(self):
        super().__init__()
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Name", "When", "Applies to", "State", "Note", "Organization"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(240)
        self.table.doubleClicked.connect(lambda *_: self.edit())
        self.info = note("")
        bar = QHBoxLayout()
        for text, fn in (("New...", self.add), ("Edit...", self.edit), ("Delete", self.delete)):
            b = QPushButton(text)
            b.clicked.connect(lambda _=False, fn=fn: fn())
            bar.addWidget(b)
        bar.addStretch()
        self.form.addRow(self.table)
        self.form.addRow(bar)
        self.form.addRow(self.info)
        self.lay.insertWidget(0, note(
            "Planned work (patching, an upgrade, a power test) should not page anyone. During a maintenance window the "
            "devices it covers keep being checked and recorded, but their alerts are held back. Changes here apply "
            "immediately."))
        self.rows = []

    def refresh(self):
        self.rows = maintenance.listing()
        now = datetime.now()
        self.table.setRowCount(len(self.rows))
        self.table.setColumnHidden(5, not db.several())
        active = 0
        for i, w in enumerate(self.rows):
            on = maintenance.is_active(w, now)
            active += on
            state = "ACTIVE" if on else ("off" if not w["enabled"] else "scheduled")
            shared = "" if w["org"] == db.target() or db.everything() else "  (Shared)"
            for j, v in enumerate([w["name"] + shared, maintenance.describe(w), ", ".join(w["scope"]) or "all devices", state,
                                   w.get("note") or "", db.org_name(w["org"]) + ("  (Shared)" if w.get("shared") else "")]):
                it = QTableWidgetItem(v)
                if on and j == 3:
                    it.setForeground(QColor("#e6a100"))
                self.table.setItem(i, j, it)
        self.table.resizeColumnsToContents()
        held = maintenance.devices_in_maintenance(now)
        self.info.setText(f"{len(held)} device(s) in maintenance right now." if held else "No device is in maintenance right now.")

    def load(self):
        self.refresh()

    def current(self):
        r = self.table.currentRow()
        return self.rows[r] if 0 <= r < len(self.rows) else None

    def _save(self, dlg):
        try:
            maintenance.save_window(dlg.values())
        except ValueError as e:
            QMessageBox.warning(self, "Maintenance window", str(e))
            return
        with db.within(dlg.values()["org"]):
            audit.log("maintenance window saved", f"{dlg.values()['name']} ({maintenance.describe(dlg.values())})")
        self.refresh()

    def add(self):
        dlg = MaintenanceDialog(parent=self)
        if dlg.exec():
            self._save(dlg)

    def _mine(self, w):
        if w and not db.everything() and w.get("org") != db.target():
            QMessageBox.information(self, "Maintenance window", "Shared items are changed from Global.")
            return False
        return bool(w)

    def edit(self):
        w = self.current()
        if self._mine(w):
            dlg = MaintenanceDialog(w, self)
            if dlg.exec():
                self._save(dlg)

    def delete(self):
        w = self.current()
        if self._mine(w) and QMessageBox.question(self, "Delete window", f"Delete '{w['name']}'?") == QMessageBox.StandardButton.Yes:
            maintenance.delete_window(w["id"], w.get("org"))
            with db.within(w.get("org")):
                audit.log("maintenance window deleted", w["name"])
            self.refresh()
