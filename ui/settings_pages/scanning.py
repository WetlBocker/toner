"""Settings > Scanning: whether the Scanning section looks up known vulnerabilities, the Cisco PSIRT account and the optional NVD
key (both kept in the vault), and a Test that asks Cisco about one well-known version with them."""
import threading

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QCheckBox, QLabel, QLineEdit, QListWidget, QListWidgetItem, QPushButton

from core import advisories, db, hardening
from ui.settings_base import Page, compact_row, note

CISCO_NOTE = ("From apiconsole.cisco.com: register an application with the Cisco PSIRT openVuln API. Needed for Cisco devices. "
              "The other vendors use NIST's database, which needs no account.")
NVD_NOTE = "Raises NIST's rate limit from 5 to 50 requests every 30 seconds. Free at nvd.nist.gov/developers/request-an-api-key."
RULES_NOTE = ("Each scan also reads a Cisco device's newest configuration backup against these rules (IOS, IOS XE, NX-OS and ASA). "
              "Untick a rule to leave it out of every scan.")
SAVED = "saved; leave blank to keep"
TESTING = "Testing…"


class ScanningPage(Page):
    title = "Scanning"
    tested = Signal(str)

    def __init__(self):
        super().__init__()
        self.enabled = QCheckBox("Look up known vulnerabilities for each device's software version")
        self.cisco_id = QLineEdit()
        self.cisco_id.setMinimumWidth(360)
        self.cisco_secret = QLineEdit()
        self.cisco_secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.nvd_key = QLineEdit()
        self.nvd_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.test_btn = QPushButton("Test")
        self.test_btn.setProperty("notSetting", True)
        self.test_btn.setAutoDefault(False)
        self.result = QLabel("")
        self.result.setWordWrap(True)
        self.result.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.form.addRow("", self.enabled)
        self.form.addRow("Cisco PSIRT client ID", self.cisco_id)
        self.form.addRow("Cisco PSIRT client secret", self.cisco_secret)
        self.form.addRow("", note(CISCO_NOTE))
        self.form.addRow("NVD API key", self.nvd_key)
        self.form.addRow("", note(NVD_NOTE))
        self.form.addRow("", compact_row(self.test_btn))
        self.form.addRow("", self.result)
        self.rules = QListWidget()
        for key, label, sev, _test in hardening.RULES:
            it = QListWidgetItem(f"{label}  ({sev})")
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setData(Qt.ItemDataRole.UserRole, key)
            self.rules.addItem(it)
        self.rules.setMinimumHeight(self.rules.sizeHintForRow(0) * (len(hardening.RULES) + 1) + 8)
        self.form.addRow("Configuration hardening", self.rules)
        self.form.addRow("", note(RULES_NOTE))
        self.test_btn.clicked.connect(self.test)
        self.tested.connect(self._tested)
        self._testing = False

    def load(self):
        self.enabled.setChecked(bool(db.get_setting("scan_enabled")))
        off = hardening.rules_off()
        for i in range(self.rules.count()):
            it = self.rules.item(i)
            it.setCheckState(Qt.CheckState.Unchecked if it.data(Qt.ItemDataRole.UserRole) in off else Qt.CheckState.Checked)
        for box, kind in ((self.cisco_id, "psirt_id"), (self.cisco_secret, "psirt_secret"), (self.nvd_key, "nvd_key")):
            box.clear()
            box.setPlaceholderText(SAVED if advisories.get_secret(kind) else "")
        self.result.setText("")

    def save(self):
        db.set_setting("scan_enabled", self.enabled.isChecked())
        db.set_setting("hardening_off", [self.rules.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.rules.count())
                                         if self.rules.item(i).checkState() != Qt.CheckState.Checked])
        for box, kind in ((self.cisco_id, "psirt_id"), (self.cisco_secret, "psirt_secret"), (self.nvd_key, "nvd_key")):
            typed = box.text().strip()
            if typed:
                advisories.set_secret(kind, typed)
                box.clear()
                box.setPlaceholderText(SAVED)

    def test(self):
        if self._testing:
            return
        cid = self.cisco_id.text().strip() or advisories.get_secret("psirt_id")
        secret = self.cisco_secret.text().strip() or advisories.get_secret("psirt_secret")
        nvd_key = self.nvd_key.text().strip() or advisories.get_secret("nvd_key")
        if not cid or not secret:
            self.result.setText("Enter the Cisco PSIRT client ID and secret first.")
            return
        self._testing = True
        self.test_btn.setEnabled(False)
        self.result.setText(TESTING)
        threading.Thread(target=lambda: self.tested.emit(advisories.test(cid, secret, nvd_key)), daemon=True).start()

    def _tested(self, text):
        self._testing = False
        self.test_btn.setEnabled(True)
        self.result.setText(text)
