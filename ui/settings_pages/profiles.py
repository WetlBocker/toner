"""Settings page: credential profiles."""

import json

from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QLineEdit,
                               QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout)
from core import audit, db, profiles
from ui.orgfield import OrgField, show_row
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
        self.org = OrgField(self.profile)
        form = QFormLayout()
        form.addRow("Organization", self.org)
        show_row(form, self.org)
        from ui.linkitem import LinkRow, wanted
        self.link_row = LinkRow()                                    # Link... to a password manager item (when one is chosen)
        for label, w in (("Name", self.name), ("Username", self.username), ("Password / token / API key", self.secret),
                         ("", self.link_row), ("Notes", self.notes)):
            form.addRow(label, w)
        form.setRowVisible(self.link_row, wanted())
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
            org = profile.get("org")
            with db.within(org):
                self.link_row.load(db.secret_name(f"profile:{profile['name']}"))
            have = {k: profiles.has_secret(profile["name"], k, org) for k in ("snmp", "snmp_auth", "snmp_priv")}
            self.secret.setPlaceholderText("leave blank to keep the stored value" if profiles.has_secret(profile["name"], "main", org)
                                           else "")
        self.snmp.set_stored(have)
        self.use_snmp.toggled.connect(self.snmp.setEnabled)
        self.snmp.setEnabled(self.use_snmp.isChecked())

    def values(self):
        secrets = {"main": self.secret.text()}
        if self.use_snmp.isChecked():
            secrets.update(self.snmp.secrets())
        return ({"id": self.profile.get("id"), "org": self.org.file(), "shared": self.org.shared(),
                 "name": self.name.text().strip(), "username": self.username.text().strip(),
                 "notes": self.notes.text().strip(), "snmp": self.snmp.settings() if self.use_snmp.isChecked() else ""},
                secrets)



class ProfilesPage(Page):
    title = "Credentials"

    def __init__(self):
        super().__init__()
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Profile", "Username", "SNMP", "Used by", "Organization"])
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
            "Secrets go to Toner's vault. Changes here apply immediately."))
        self.ids = []

    def refresh(self):
        rows = profiles.listing()
        self.ids = [(p["id"], p["org"]) for p in rows]
        self.table.setRowCount(len(rows))
        self.table.setColumnHidden(4, not db.several())
        for i, p in enumerate(rows):
            try:
                s = json.loads(p.get("snmp") or "{}")
            except ValueError:
                s = {}
            users = profiles.users_of(p["id"], p["org"] if p["id"] > 0 else None)
            mine = p["org"] == db.target()
            for j, v in enumerate([p["name"] + ("" if mine or db.everything() else "  (Shared)"), p.get("username") or "",
                                   ("v" + str(s.get("version", "2c"))) if s else "-", f"{len(users)} device(s)" if users else "no devices",
                                   db.org_name(p["org"]) + ("  (Shared)" if p.get("shared") else "")]):
                self.table.setItem(i, j, QTableWidgetItem(v))
        self.table.resizeColumnsToContents()

    def load(self):
        self.refresh()

    def current(self):
        r = self.table.currentRow()
        if not 0 <= r < len(self.ids):
            return None
        pid, org = self.ids[r]
        return profiles.get(pid, org if pid > 0 else None)

    def _mine(self, p):
        """A Shared profile seen from an organization is Global's: it is changed from Global."""
        if p and not db.everything() and p.get("org") != db.target():
            QMessageBox.information(self, "Credential profile", "Shared items are changed from Global.")
            return False
        return bool(p)

    def _save(self, dlg):
        prof, secrets = dlg.values()
        if prof["org"] is None:
            QMessageBox.warning(self, "Organization", "Choose the organization this profile belongs to.")
            return
        try:
            profiles.save(prof, secrets)
        except ValueError as e:
            QMessageBox.warning(self, "Profile", str(e))
            return
        with db.within(prof["org"]):
            dlg.link_row.apply(db.secret_name(f"profile:{prof['name']}"))
            audit.log("profile " + ("edited" if prof.get("id") else "created"), prof["name"])
        self.refresh()

    def add(self):
        dlg = ProfileDialog(parent=self)
        if dlg.exec():
            self._save(dlg)

    def edit(self):
        p = self.current()
        if self._mine(p):
            dlg = ProfileDialog(p, self)
            if dlg.exec():
                self._save(dlg)

    def delete(self):
        p = self.current()
        if not self._mine(p):
            return
        users = profiles.users_of(p["id"], p["org"])
        extra = f"\n\n{len(users)} device(s) use it and will fall back to their own settings." if users else ""
        if QMessageBox.question(self, "Delete profile", f"Delete '{p['name']}'?{extra}") == QMessageBox.StandardButton.Yes:
            profiles.delete(p["id"], p["org"])
            with db.within(p["org"]):
                audit.log("profile deleted", p["name"])
            self.refresh()
