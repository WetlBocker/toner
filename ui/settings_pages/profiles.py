"""Settings page: credential profiles."""

import json

from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QLineEdit,
                               QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout)
from core import audit, profiles
from ui.snmpfields import SnmpFields
from ui.settings_base import Page, note


# ------------------------------------------------------------------ the tab
# ------------------------------------------------------------------ Credential profiles
class ProfileDialog(QDialog):
    def __init__(self, profile=None, parent=None):
        super().__init__(parent)
        self.profile = profile or {}
        self.setWindowTitle("Edit credential profile" if profile else "New credential profile")
        self.setMinimumWidth(440)
        self.name, self.username, self.secret = QLineEdit(), QLineEdit(), QLineEdit()
        self.secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.notes = QLineEdit()
        self.use_snmp = QCheckBox("Include SNMP settings")
        self.snmp = SnmpFields()
        form = QFormLayout()
        for label, w in (("Name", self.name), ("Username", self.username), ("Password / token / API key", self.secret),
                         ("Notes", self.notes)):
            form.addRow(label, w)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(self.use_snmp)
        lay.addWidget(self.snmp)
        lay.addWidget(buttons)
        have = {}
        if profile:
            self.name.setText(profile["name"])
            self.username.setText(profile.get("username") or "")
            self.notes.setText(profile.get("notes") or "")
            try:
                s = json.loads(profile.get("snmp") or "{}")
            except ValueError:
                s = {}
            self.use_snmp.setChecked(bool(s))
            self.snmp.load(s)
            have = {k: profiles.has_secret(profile["name"], k) for k in ("snmp", "snmp_auth", "snmp_priv")}
            self.secret.setPlaceholderText("leave blank to keep the stored value" if profiles.has_secret(profile["name"])
                                           else "")
        self.snmp.set_stored(have)
        self.use_snmp.toggled.connect(self.snmp.setEnabled)
        self.snmp.setEnabled(self.use_snmp.isChecked())

    def values(self):
        secrets = {"main": self.secret.text()}
        if self.use_snmp.isChecked():
            secrets.update(self.snmp.secrets())
        return ({"id": self.profile.get("id"), "name": self.name.text().strip(), "username": self.username.text().strip(),
                 "notes": self.notes.text().strip(), "snmp": self.snmp.settings() if self.use_snmp.isChecked() else ""},
                secrets)



class ProfilesPage(Page):
    title = "Credentials"

    def __init__(self):
        super().__init__()
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Profile", "Username", "SNMP", "Used by"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(220)
        self.table.doubleClicked.connect(lambda *_: self.edit())
        bar = QHBoxLayout()
        for text, fn in (("New...", self.add), ("Edit...", self.edit), ("Delete", self.delete)):
            b = QPushButton(text)
            b.clicked.connect(lambda _=False, fn=fn: fn())
            bar.addWidget(b)
        bar.addStretch()
        self.form.addRow(self.table)
        self.form.addRow(bar)
        self.lay.insertWidget(0, note(
            "A profile holds a username, a password or token, and SNMP settings, so many devices can share them. "
            "Choose it in a device's Access tab; anything set on the device itself overrides the profile. "
            "Secrets go to Windows Credential Manager. Changes here apply immediately."))
        self.ids = []

    def refresh(self):
        rows = profiles.list_profiles()
        self.ids = [p["id"] for p in rows]
        self.table.setRowCount(len(rows))
        for i, p in enumerate(rows):
            try:
                s = json.loads(p.get("snmp") or "{}")
            except ValueError:
                s = {}
            users = profiles.users_of(p["id"])
            for j, v in enumerate([p["name"], p.get("username") or "", ("v" + str(s.get("version", "2c"))) if s else "-",
                                   f"{len(users)} device(s)" if users else "no devices"]):
                self.table.setItem(i, j, QTableWidgetItem(v))
        self.table.resizeColumnsToContents()

    def load(self):
        self.refresh()

    def current(self):
        r = self.table.currentRow()
        return profiles.get(self.ids[r]) if 0 <= r < len(self.ids) else None

    def _save(self, dlg):
        prof, secrets = dlg.values()
        try:
            profiles.save(prof, secrets)
        except ValueError as e:
            QMessageBox.warning(self, "Profile", str(e))
            return
        audit.log("profile " + ("edited" if prof.get("id") else "created"), prof["name"])
        self.refresh()

    def add(self):
        dlg = ProfileDialog(parent=self)
        if dlg.exec():
            self._save(dlg)

    def edit(self):
        p = self.current()
        if p:
            dlg = ProfileDialog(p, self)
            if dlg.exec():
                self._save(dlg)

    def delete(self):
        p = self.current()
        if not p:
            return
        users = profiles.users_of(p["id"])
        extra = f"\n\n{len(users)} device(s) use it and will fall back to their own settings." if users else ""
        if QMessageBox.question(self, "Delete profile", f"Delete '{p['name']}'?{extra}") == QMessageBox.StandardButton.Yes:
            profiles.delete(p["id"])
            audit.log("profile deleted", p["name"])
            self.refresh()
