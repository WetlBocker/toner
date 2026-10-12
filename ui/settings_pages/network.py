"""Settings pages: proxy, agents and maintenance windows."""

import ipaddress
import keyring
from datetime import datetime

from PySide6.QtCore import QDateTime, QTime
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QDateTimeEdit, QDialog, QDialogButtonBox,
                               QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QTableWidget,
                               QTableWidgetItem, QTimeEdit, QVBoxLayout, QWidget)
from core import agents, audit, db, maintenance, proxy
from ui.widgets import GroupPicker
from ui.settings_base import Collapsible, Page, compact_row, note, row_of, spin


# ------------------------------------------------------------------ Proxy
class ProxyPage(Page):
    title = "Proxy"

    def __init__(self):
        super().__init__()
        self.mode, self.kind = QComboBox(), QComboBox()
        for k, label in proxy.MODES:
            self.mode.addItem(label, k)
        for k, label in proxy.KINDS:
            self.kind.addItem(label, k)
        self.host, self.user, self.bypass = QLineEdit(), QLineEdit(), QLineEdit()
        self.host.setPlaceholderText("proxy.example.com")
        self.user.setPlaceholderText("optional")
        self.bypass.setPlaceholderText("localhost, 127.0.0.1, *.corp.example.com, 10.0.0.0/8")
        self.port = spin(1, 65535)
        self.port.setValue(8080)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.forget = QPushButton("Remove saved password")
        self.pw_note = note("")
        self.system = note("")
        self.test_to = QLineEdit("www.githubstatus.com:443")
        self.test_btn = QPushButton("Test")
        self.test_out = QLabel("")
        self.test_out.setWordWrap(True)
        self._forget = False
        self.manual = [self.kind, self.host, self.port, self.user, self.password, self.forget, self.bypass]
        self.form.addRow("Connections go", self.mode)
        self.form.addRow("", self.system)
        self.form.addRow("Proxy type", self.kind)
        self.form.addRow("Address", self.host)
        self.form.addRow("Port", self.port)
        self.form.addRow("User name", self.user)
        self.form.addRow("Password", self.password)
        self.form.addRow("", row_of(self.forget))
        self.form.addRow("", self.pw_note)
        self.form.addRow("Do not use it for", self.bypass)
        self.form.addRow("Try a connection to", row_of(self.test_to, self.test_btn))
        self.form.addRow("", self.test_out)
        self.lay.insertWidget(0, note(
            "Send Toner's connections through a proxy. This is the setting for every connection; a device can override it "
            "in its own Access tab. It covers SSH (checks, backups, the console), the web APIs of Fortinet, Palo Alto, "
            "Meraki and UniFi, status pages, web, port and certificate checks, and notifications. SNMP, ping, "
            "traceroute and the listeners use UDP or ICMP, which a proxy does not carry, so they always connect directly. "
            "'Windows proxy settings' covers web connections only, as a browser would; choose 'Use the proxy below' to "
            "send SSH and port checks through a proxy as well."))
        self.mode.currentIndexChanged.connect(self.adapt)
        self.forget.clicked.connect(self._clear_password)
        self.test_btn.clicked.connect(self.test)

    def adapt(self, *_):
        manual = self.mode.currentData() == "manual"
        for w in self.manual:
            w.setEnabled(manual)
        self.form.setRowVisible(self.system, self.mode.currentData() == "system")

    def _clear_password(self):
        self._forget = True
        self.password.clear()
        self.pw_note.setText("The saved password will be removed when you save.")

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
        self.pw_note.setText("A password is saved in Credential Manager. Leave the box empty to keep it." if have else "")
        self.forget.setVisible(have)
        sys_text = proxy.system_text()
        self.system.setText(f"Windows is set to use: {sys_text}" if sys_text else
                            "Windows has no proxy configured, so connections go directly.")
        self.test_out.setText("")
        self.adapt()

    def validate(self):
        if self.mode.currentData() == "manual" and not self.host.text().strip():
            return ["Proxy: enter the proxy's address, or choose another option."]
        return []

    def save(self):
        db.set_setting("proxy", {"mode": self.mode.currentData(), "kind": self.kind.currentData(),
                                 "host": self.host.text().strip(), "port": self.port.value(),
                                 "username": self.user.text().strip(), "bypass": self.bypass.text().strip()})
        if self.password.text():
            db.set_secret(proxy.GLOBAL_SECRET, self.password.text())
        elif self._forget:
            db.delete_secret(proxy.GLOBAL_SECRET)
        audit.log("proxy settings changed", f"{self.mode.currentData()} {self.host.text().strip()}:{self.port.value()}"
                  if self.mode.currentData() == "manual" else self.mode.currentData())
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
                                     "username": self.user.text()},
                                    self.password.text() or ("" if self._forget else
                                                             keyring.get_password(db.SERVICE, proxy.GLOBAL_SECRET) or ""))
                ok, msg = (False, "Enter the proxy's address first.") if cfg is None else proxy.test_tunnel(cfg, host, int(port))
            else:
                ok, msg = proxy.test_web(host, int(port), direct=(mode == "none"))
        finally:
            QApplication.restoreOverrideCursor()
        self.test_out.setText(("OK: " if ok else "Failed: ") + msg)


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
        self.download = QPushButton("Download agent package...")
        self.download.setProperty("primary", True)
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
        self.form.addRow("Package", compact_row(self.download, QLabel("reports every"), self.minutes))
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
        self.renew.clicked.connect(self._renew)
        self.newkey.clicked.connect(self._newkey)
        self.download.clicked.connect(self._download)

    def load(self):
        self.enabled.setChecked(bool(db.get_setting("agent_enabled")))
        self.enroll.setChecked(bool(db.get_setting("agent_enroll")))
        self.port.setValue(int(db.get_setting("agent_port") or agents.DEFAULT_PORT))
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
                and self.address.text().strip() == (db.get_setting("agent_address") or "")
                and self.enabled.isChecked() == bool(db.get_setting("agent_enabled"))
                and self.enroll.isChecked() == bool(db.get_setting("agent_enroll")) and bind == (db.get_setting("agent_bind") or "0.0.0.0"))

    def _download(self):
        if not self._stored_matches():
            QMessageBox.information(self, "Agent package", "Save your changes first: the package is made from the saved settings.")
            return
        if not self.enroll.isChecked():
            if QMessageBox.question(self, "Agent package", "Sign-up is off, so computers cannot add themselves with this package. "
                                    "Make it anyway?") != QMessageBox.StandardButton.Yes:
                return
        path, _ = QFileDialog.getSaveFileName(self, "Save agent package", "Toner-Agent.zip", "Zip file (*.zip)")
        if not path:
            return
        try:
            data = agents.package_bytes(self.minutes.value())
            with open(path, "wb") as f:
                f.write(data)
        except Exception as e:
            QMessageBox.warning(self, "Agent package", f"The package could not be made: {e}")
            return
        audit.log("agent package downloaded", f"reports every {self.minutes.value()} min")
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
        self.form = QFormLayout()
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
        return {"id": self.win.get("id"), "name": self.name.text().strip(), "kind": self.kind.currentData(),
                "start_at": self.start.dateTime().toString("yyyy-MM-dd HH:mm"),
                "end_at": self.end.dateTime().toString("yyyy-MM-dd HH:mm"),
                "days": [i for i, c in enumerate(self.days) if c.isChecked()],
                "start_time": self.t_start.time().toString("HH:mm"), "end_time": self.t_end.time().toString("HH:mm"),
                "scope": self.scope.selected(), "enabled": int(self.enabled.isChecked()), "note": self.note.text().strip()}

    def accept(self):
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
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Name", "When", "Applies to", "State", "Note"])
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
        self.rows = maintenance.list_windows()
        now = datetime.now()
        self.table.setRowCount(len(self.rows))
        active = 0
        for i, w in enumerate(self.rows):
            on = maintenance.is_active(w, now)
            active += on
            state = "ACTIVE" if on else ("off" if not w["enabled"] else "scheduled")
            for j, v in enumerate([w["name"], maintenance.describe(w), ", ".join(w["scope"]) or "all devices", state,
                                   w.get("note") or ""]):
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
        audit.log("maintenance window saved", f"{dlg.values()['name']} ({maintenance.describe(dlg.values())})")
        self.refresh()

    def add(self):
        dlg = MaintenanceDialog(parent=self)
        if dlg.exec():
            self._save(dlg)

    def edit(self):
        w = self.current()
        if w:
            dlg = MaintenanceDialog(w, self)
            if dlg.exec():
                self._save(dlg)

    def delete(self):
        w = self.current()
        if w and QMessageBox.question(self, "Delete window", f"Delete '{w['name']}'?") == QMessageBox.StandardButton.Yes:
            maintenance.delete_window(w["id"])
            audit.log("maintenance window deleted", w["name"])
            self.refresh()
