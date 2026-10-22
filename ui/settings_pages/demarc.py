"""Settings > Connections > Demarc: connect Toner to a Demarc server, see how sending is going, and turn it off (core/demarc.py).

Connect... and Disconnect... act at once; Send data to Demarc and Config history wait for Save changes, like the other settings
(Connect... saves Config history too, since the first full copy uses it straight away)."""
from PySide6.QtCore import QTimer, Qt, Signal
from PySide6.QtWidgets import QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QLabel, QLineEdit, QMessageBox, QPushButton, QVBoxLayout

from core import demarc
from ui.settings_base import Page, compact_row, note

INTRO = ("Demarc collects organizations, devices and check results from Toner, so you can see every organization in one place in a "
         "browser. Toner always connects out to Demarc over HTTPS. Passwords and other secrets in Toner's vault are never sent. To "
         "connect, create an enrollment code in Demarc under Toners, then enter Demarc's address and the code here.")
ADDRESS_HINT = "demarc.example.com or demarc.example.com:8760"
TRUSTED = "Trusted by this computer"
CHECK_TITLE = "Check Demarc's certificate"
CHECK_TEXT = ("Toner reached {address}. Its certificate fingerprint (SHA-256) is:\n{fingerprint}\nCheck that Demarc shows the same "
              "fingerprint next to the enrollment code. Connect only if they match.")
CHECK_YES = "They match, connect"
HISTORY = [(demarc.HISTORY_ALL, "Every version Toner holds"), (demarc.HISTORY_LATEST, "Only each device's newest version")]
HISTORY_NOTE = "What Toner's first full copy sends to Demarc 0.0.8 or newer."
DISCONNECT_TITLE = "Disconnect from Demarc?"
DISCONNECT_TEXT = "Toner stops sending and forgets its token. Changes not sent yet are dropped. Demarc keeps what it already has."


class DemarcPage(Page):
    title = "Demarc"
    acted = Signal()                     # Connect... or Disconnect... changed what is stored: not an unsaved edit

    def __init__(self):
        super().__init__()
        self.lay.insertWidget(0, note(INTRO))
        self.address = QLineEdit()
        self.address.setPlaceholderText(ADDRESS_HINT)
        self.address.setProperty("notSetting", True)                       # used by Connect..., not saved by Save changes
        self.code = QLineEdit()
        self.code.setProperty("notSetting", True)
        self.connect_btn = QPushButton("Connect...")
        self.connect_btn.setProperty("primary", True)
        self.connect_btn.setAutoDefault(False)
        self.enabled = QCheckBox("Send data to Demarc")
        self.history = QComboBox()
        for key, label in HISTORY:
            self.history.addItem(label, key)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.cert = QLineEdit()
        self.cert.setReadOnly(True)
        self.disconnect_btn = QPushButton("Disconnect...")
        self.disconnect_btn.setAutoDefault(False)
        self.form.addRow("Demarc address", self.address)
        self.form.addRow("Enrollment code", self.code)
        self.form.addRow("", compact_row(self.connect_btn))
        self.form.addRow("", self.enabled)
        self.form.addRow("Config history", self.history)
        self.form.addRow("", note(HISTORY_NOTE))
        self.form.addRow("Status", self.status)
        self.form.addRow("Certificate", self.cert)
        self.form.addRow("", compact_row(self.disconnect_btn))
        self.connect_btn.clicked.connect(self._connect)
        self.disconnect_btn.clicked.connect(self._disconnect)
        self.timer = QTimer(self)                                           # the status changes as the sender works
        self.timer.setInterval(5000)
        self.timer.timeout.connect(lambda: self.isVisible() and self.show_status())
        self.timer.start()
        self.ask = self._ask                                                # the tests answer the questions instead

    # ---------- Settings' own calls
    def load(self):
        cfg = demarc.config()
        self.address.setText(cfg["address"])
        self.enabled.setChecked(bool(cfg["enabled"]))
        self.history.setCurrentIndex(max(0, self.history.findData(cfg.get("history", demarc.HISTORY_ALL))))
        self.show_status()

    def save(self):
        if demarc.config().get("history") != self.history.currentData():
            demarc.save_config(history=self.history.currentData())
        if demarc.connected() and bool(demarc.config()["enabled"]) != self.enabled.isChecked():
            demarc.save_config(enabled=self.enabled.isChecked())
            demarc.kick()
        self.show_status()

    def show_status(self):
        on = demarc.connected()
        cfg = demarc.config()
        self.status.setText("\n".join(demarc.status_lines()))
        self.cert.setText(TRUSTED if on and cfg["trusted"] else (cfg["pin"] if on else ""))
        self.enabled.setEnabled(on)
        self.disconnect_btn.setEnabled(on)

    # ---------- the buttons
    def _busy(self, work):
        from ui.otpprompt import wait_responsive
        self.connect_btn.setEnabled(False)
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            return wait_responsive(work)
        finally:
            QApplication.restoreOverrideCursor()
            self.connect_btn.setEnabled(True)

    def _connect(self):
        address, code = self.address.text().strip(), self.code.text().strip()
        try:
            if not address or not code:
                raise demarc.DemarcError(demarc.T_NEED)
            found = self._busy(lambda: demarc.probe(address))
            if not found.trusted and not self.ask(CHECK_TITLE, CHECK_TEXT.format(address=found.url, fingerprint=found.fingerprint),
                                                  CHECK_YES):
                return
            demarc.save_config(history=self.history.currentData())       # the first full copy follows at once
            self._busy(lambda: demarc.enroll(found, code))
        except demarc.DemarcError as e:
            self.tell(str(e))
            return
        demarc.apply()
        self.code.clear()
        self.load()
        self.acted.emit()

    def _disconnect(self):
        if not self.ask(DISCONNECT_TITLE, DISCONNECT_TEXT, "Disconnect"):
            return
        demarc.disconnect()
        self.load()
        self.acted.emit()

    def _ask(self, title, text, yes):
        box = QDialog(self)
        box.setWindowTitle(title)
        lay = QVBoxLayout(box)
        lab = QLabel(text)
        lab.setWordWrap(True)
        lab.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(lab)
        buttons = QDialogButtonBox()
        ok = buttons.addButton(yes, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        ok.setAutoDefault(False)
        buttons.accepted.connect(box.accept)
        buttons.rejected.connect(box.reject)
        lay.addWidget(buttons)
        return box.exec() == QDialog.DialogCode.Accepted

    def tell(self, text):
        QMessageBox.warning(self, "Demarc", text)
