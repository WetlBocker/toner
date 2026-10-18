"""The vault's windows: setting a master password (the first time, after Forgot it?, or Change master password) and unlocking."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QLabel, QLineEdit, QMessageBox, QVBoxLayout)

from core import audit, passvault

REMEMBER_TEXT = "Remember on this computer"
REMEMBER_NOTE = "Toner and its scheduled service open the vault without asking."       # under the tick box (it cannot wrap)
NO_KEYRING_TEXT = ("This computer has no keyring Toner can keep the vault's key in, so Toner will ask for the master password "
                   "each time it starts.")
FORGOT_WARNING = ("If you forget the master password and Toner doesn't remember it on this computer, the passwords in the vault "
                  "cannot be recovered.")


def _wrapped(text, muted=False):
    lab = QLabel(text)
    lab.setWordWrap(True)
    if muted:
        lab.setProperty("muted", True)
    return lab


class MasterDialog(QDialog):
    """Choose a master password. mode: 'create' (the first time), 'reset' (Forgot it?: a new, empty vault) or 'change'."""

    def __init__(self, mode="create", parent=None):
        super().__init__(parent)
        self.mode = mode
        self.setWindowTitle("Change master password" if mode == "change" else "Set a master password")
        self.setMinimumWidth(480)
        self.first, self.second = QLineEdit(), QLineEdit()
        for w in (self.first, self.second):
            w.setEchoMode(QLineEdit.EchoMode.Password)
            w.textChanged.connect(self._show_rules)
        self.rule = QLabel()                                   # the requirements, ticked off as they are met
        self.error = QLabel()
        self.error.setStyleSheet("color:#d32f2f;")
        self.error.hide()
        self.remember = QCheckBox(REMEMBER_TEXT)
        self.remember.setChecked(passvault.remembered() if mode == "change" else True)
        form = QFormLayout()
        form.setVerticalSpacing(10)
        form.setHorizontalSpacing(14)
        form.addRow("Master password", self.first)
        form.addRow("Confirm master password", self.second)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(22, 20, 22, 18)
        lay.setSpacing(6)
        if mode != "change":
            lay.addWidget(_wrapped("Toner stores its passwords in its own encrypted vault. Choose a master password to lock it."))
            lay.addSpacing(8)
        lay.addLayout(form)
        lay.addSpacing(12)
        lay.addWidget(QLabel("Password requirements:"))
        self.rule.setContentsMargins(12, 0, 0, 0)
        lay.addWidget(self.rule)
        lay.addWidget(self.error)
        if mode != "change":
            lay.addSpacing(10)
            lay.addWidget(self.remember)
            hint = _wrapped(REMEMBER_NOTE, muted=True)
            hint.setContentsMargins(26, 0, 0, 0)
            lay.addWidget(hint)
        lay.addSpacing(12)
        lay.addWidget(_wrapped(FORGOT_WARNING, muted=True))
        lay.addSpacing(10)
        self.buttons = QDialogButtonBox()
        self.ok = self.buttons.addButton("Change" if mode == "change" else "Create vault", QDialogButtonBox.ButtonRole.AcceptRole)
        self.ok.setProperty("primary", True)
        self.buttons.addButton("Quit" if mode == "create" else "Cancel", QDialogButtonBox.ButtonRole.RejectRole)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        lay.addWidget(self.buttons)
        self._show_rules()

    def _show_rules(self):
        met = len(self.first.text()) >= passvault.MIN_MASTER
        self.rule.setText(("✓ " if met else "• ") + f"At least {passvault.MIN_MASTER} characters")
        self.rule.setStyleSheet("color:#2e9e5b;" if met else "")
        self.error.hide()

    def problem(self):
        try:
            passvault.check_master(self.first.text())
        except ValueError as e:
            return str(e)
        if self.first.text() != self.second.text():
            return "The two passwords don't match."
        return ""

    def accept(self):
        why = self.problem()
        if why:
            self.error.setText(why)
            self.error.show()
            return
        super().accept()

    def master(self):
        return self.first.text()


class UnlockDialog(QDialog):
    """Unlock Toner: the master password, or Forgot it? (a new, empty vault)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Unlock Toner")
        self.setMinimumWidth(420)
        self.reset_done = False
        self.word = QLineEdit()
        self.word.setEchoMode(QLineEdit.EchoMode.Password)
        self.word.textChanged.connect(lambda _t: self.error.hide())
        self.error = QLabel("That master password isn't right.")
        self.error.setStyleSheet("color:#d32f2f;")
        self.error.hide()
        forgot = QLabel("<a href='forgot'>Forgot it?</a>")
        forgot.setTextFormat(Qt.TextFormat.RichText)
        forgot.linkActivated.connect(lambda _l: self.forgot())
        self.buttons = QDialogButtonBox()
        self.buttons.addButton("Unlock", QDialogButtonBox.ButtonRole.AcceptRole).setProperty("primary", True)
        self.buttons.addButton("Quit", QDialogButtonBox.ButtonRole.RejectRole)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(_wrapped("Enter the master password to open Toner's vault."))
        lay.addWidget(self.word)
        lay.addWidget(self.error)
        lay.addWidget(forgot)
        lay.addWidget(self.buttons)

    def accept(self):
        try:
            passvault.unlock(self.word.text())
        except passvault.WrongPassword:
            self.error.show()
            self.word.selectAll()
            self.word.setFocus()
            return
        super().accept()

    def forgot(self):
        if QMessageBox.question(self, "Unlock Toner", "Start a new, empty vault? Every saved password is lost. Devices, sessions and "
                                "settings stay.") != QMessageBox.StandardButton.Yes:
            return
        dlg = MasterDialog("reset", self)
        if dlg.exec():
            if not passvault.create(dlg.master(), dlg.remember.isChecked()):
                QMessageBox.information(self, "Set a master password", NO_KEYRING_TEXT)
            audit.log("vault started again", "the master password was forgotten; saved passwords were cleared")
            self.reset_done = True
            super().accept()


def open_at_start(parent=None):
    """Before Toner's window: make the vault the first time, else open it (remembered, or ask). False: the person chose Quit."""
    if not passvault.exists():
        dlg = MasterDialog("create", parent)
        if not dlg.exec():
            return False
        carry = passvault.left_in_credential_manager()        # an older Toner's passwords come along (nothing to say: they just work)
        if not passvault.create(dlg.master(), dlg.remember.isChecked(), carry):
            QMessageBox.information(parent, "Set a master password", NO_KEYRING_TEXT)
        passvault.forget_credential_manager(carry)
        audit.log("vault created", f"{len(carry)} password(s) moved from Credential Manager" if carry else "")
        return True
    if passvault.unlock_remembered():
        return True
    return bool(UnlockDialog(parent).exec())


def change_master(parent=None):
    """Settings > Security > Change master password..."""
    dlg = MasterDialog("change", parent)
    if not dlg.exec():
        return False
    passvault.change_master(dlg.master())
    if passvault.remembered():
        passvault.set_remembered(True)                    # (the remembered key is the same; nothing else to do)
    audit.log("vault master password changed")
    return True
