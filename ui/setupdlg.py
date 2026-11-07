"""Toner's first start: the first admin account, its recovery key, and on an upgrade the older vault's master password (once,
so its saved passwords move into the new account); then everything Toner kept is encrypted and Toner is signed in.

The encrypting step (encrypt) also runs at later starts while anything is still plain: a session log that was open, or a first
start that stopped halfway."""
import time

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QGuiApplication
from PySide6.QtWidgets import QApplication, QCheckBox, QDialog, QHBoxLayout, QLabel, QMessageBox, QProgressBar, QVBoxLayout

from core import audit, datakey, db, lockdown, passvault, passwords, quiet, session, sqldb
from core.sqldb import sqlite3
from ui.signinwindow import (DAMAGED, DAMAGED_ERRORS, MISMATCH, VAULT_CHANGED, brand, card, centred, error_label, field, heading, link,
                             primary, say, words)

TITLE = "Set up Toner"
INTRO = "Create the first admin account. Toner's data stays encrypted until someone signs in."
KEY_TITLE = "Save your recovery key"
KEY_TEXT = ("If every password is forgotten, this key is the only way back in. Store it somewhere safe, like your password manager. "
            "Toner shows it only once.")
KEY_FILE_TEXT = "Keep netcheck.keys with Toner's data too. Without it the recovery key can't open anything."
UPGRADE_TEXT = ("Enter the master password you used to unlock Toner's vault. Toner moves your saved passwords into the new account "
                "and won't ask for it again.")
LOST = "The saved passwords will be lost. Everything else is kept."
WRONG_MASTER = "That master password isn't right."
ENCRYPTING = "Encrypting Toner's data"
BUSY = "Toner's service is using the data. Stop it, then try again."


class _CardDialog(QDialog):
    def __init__(self, title, text="", parent=None, width=380):
        super().__init__(parent)
        self.setWindowTitle("Toner")
        self.setMinimumSize(width + 120, 420)
        self.card, self.lay = card(width)
        self.lay.addWidget(brand())
        self.lay.addWidget(heading(title))
        if text:
            self.lay.addWidget(words(text))
        centred(self.card, QVBoxLayout(self))


class AccountDialog(_CardDialog):
    """Set up Toner: the first account. Accepting makes it (datakey.create, which leaves the key open); `recovery` is its key."""

    def __init__(self, parent=None):
        super().__init__(TITLE, INTRO, parent)
        self.name = field(self.lay, "Username")
        self.pw = field(self.lay, "Password", secret=True)
        self.confirm = field(self.lay, "Confirm password", secret=True)
        self.error = error_label()
        self.ok = primary("Create account")
        self.lay.addWidget(self.error)
        self.lay.addSpacing(10)
        self.lay.addWidget(self.ok)
        self.ok.clicked.connect(self.accept)
        self.name.returnPressed.connect(self.pw.setFocus)
        self.pw.returnPressed.connect(self.confirm.setFocus)
        self.confirm.returnPressed.connect(self.accept)
        self.recovery = None
        self.name.setFocus()

    def accept(self):
        name, pw = self.name.text().strip(), self.pw.text()
        why = ("Enter a username." if not name else passwords.problem(pw, name)) or (MISMATCH if pw != self.confirm.text() else None)
        if not why:
            try:
                self.recovery = datakey.create(name, pw)
            except ValueError as e:                      # the same rules, said by datakey
                why = str(e)
        if why:
            say(self.error, why)
            return
        super().accept()


class RecoveryDialog(_CardDialog):
    """The recovery key, shown once. It can't be closed until "I've saved the recovery key" is ticked."""

    def __init__(self, key, parent=None):
        super().__init__(KEY_TITLE, KEY_TEXT, parent, width=420)
        self.lay.addWidget(words(KEY_FILE_TEXT))
        self.key = QLabel(key)
        mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        mono.setPointSizeF(mono.pointSizeF() + 1)
        self.key.setFont(mono)
        self.key.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        self.key.setAccessibleName("Recovery key")
        self.copy = link("Copy")
        self.copy.setAccessibleName("Copy the recovery key")
        self.copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(key))
        row = QHBoxLayout()
        row.addWidget(self.key, 1)
        row.addWidget(self.copy)
        self.lay.addSpacing(10)
        self.lay.addLayout(row)
        self.saved = QCheckBox("I've saved the recovery key")
        self.cont = primary("Continue")
        self.cont.setEnabled(False)
        self.saved.toggled.connect(self.cont.setEnabled)
        self.cont.clicked.connect(self.accept)
        self.lay.addSpacing(8)
        self.lay.addWidget(self.saved)
        self.lay.addSpacing(10)
        self.lay.addWidget(self.cont)
        self.copy.setFocus()

    def reject(self):
        if self.saved.isChecked():                       # Escape or the close button: only once the key is saved
            self.accept()


class OldVaultDialog(_CardDialog):
    """The upgrade: the older vault's master password, once. It opens that vault and moves it onto the data key (which must be
    open). "I don't know it" puts the old vault file aside, so signing in makes a new, empty one."""

    def __init__(self, parent=None):
        super().__init__(TITLE, UPGRADE_TEXT, parent)
        self.pw = field(self.lay, "Password", secret=True)
        self.error = error_label()
        self.ok = primary("Continue")
        self.dont_know = link("I don't know it")
        self.lay.addWidget(self.error)
        self.lay.addSpacing(10)
        self.lay.addWidget(self.ok)
        self.lay.addSpacing(6)
        self.lay.addWidget(self.dont_know, 0, Qt.AlignmentFlag.AlignLeft)
        self.ok.clicked.connect(self.accept)
        self.pw.returnPressed.connect(self.accept)
        self.dont_know.clicked.connect(self._dont_know)
        self.pw.setFocus()

    def accept(self):
        try:
            passvault.unlock(self.pw.text())
            passvault.adopt(sqldb.current_key())
        except passvault.WrongPassword:
            say(self.error, WRONG_MASTER)
            self.pw.setText("")
            return
        except passvault.Locked:
            say(self.error, VAULT_CHANGED)
            return
        except DAMAGED_ERRORS:
            say(self.error, DAMAGED)
            return
        super().accept()

    def _dont_know(self):
        if QMessageBox.warning(self, TITLE, LOST, QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel,
                               QMessageBox.StandardButton.Cancel) != QMessageBox.StandardButton.Ok:
            return
        passvault.lock()
        old = passvault.path()
        try:
            old.rename(old.with_name(f"{old.name}.old-{time.strftime('%Y%m%d-%H%M%S')}"))
        except OSError:
            say(self.error, DAMAGED)
            return
        super().accept()


def adopt_old_vault(parent=None):
    """Move an older master-password vault onto the data key (which must be open). The key "Remember on this computer" kept opens
    it with nothing asked; otherwise the master password, once. False when the person closed that dialog."""
    if passvault.unlock_remembered():
        try:
            passvault.adopt(sqldb.current_key())
            return True
        except (passvault.Locked, *DAMAGED_ERRORS):      # changed or unwritable since it was read: the dialog says which
            passvault.lock()
    return bool(OldVaultDialog(parent).exec())


class EncryptDialog(_CardDialog):
    def __init__(self, parent=None):
        super().__init__(ENCRYPTING, "", parent)
        self.count = words()
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setAccessibleName(ENCRYPTING)
        self.lay.addSpacing(8)
        self.lay.addWidget(self.count)
        self.lay.addWidget(self.bar)
        self.progress(0, len(lockdown.pending()))

    def progress(self, done, total):
        self.count.setText(f"{done} of {total} files")
        self.bar.setRange(0, max(1, total))
        self.bar.setValue(done)
        QApplication.processEvents()

    def reject(self):
        pass                                             # a file is half way: it finishes (each one stands alone, but don't invite it)


def encrypt(parent=None):
    """Encrypt everything still plain, with a progress bar (the data key must be open). False when Toner's service has the data
    and the person chose not to try again."""
    dlg = EncryptDialog(parent)
    dlg.show()
    try:
        while True:
            try:
                lockdown.run(dlg.progress)
                return True
            except (lockdown.Busy, sqlite3.OperationalError):  # the service, or another Toner, has a file open
                if QMessageBox.warning(dlg, ENCRYPTING, BUSY, QMessageBox.StandardButton.Retry | QMessageBox.StandardButton.Close,
                                       QMessageBox.StandardButton.Retry) != QMessageBox.StandardButton.Retry:
                    return False
    finally:
        dlg.hide()
        dlg.deleteLater()


def split_backups(parent=None):
    """Move the passwords in old config backups behind the backups key (core/backupsplit.py), with the same progress window.
    Never stops Toner starting: what didn't move is looked at again next time, and is no more exposed than it was. Only a locked
    file asks; Close carries on."""
    from core import backupsplit
    dlg = None
    try:
        while True:
            try:
                if backupsplit.pending():
                    dlg = dlg or EncryptDialog(parent)
                    dlg.show()
                    backupsplit.run(dlg.progress)
                return
            except Exception as e:
                if not backupsplit.locked(e):
                    quiet.ignored()
                    return
                if QMessageBox.warning(dlg, ENCRYPTING, BUSY, QMessageBox.StandardButton.Retry | QMessageBox.StandardButton.Close,
                                       QMessageBox.StandardButton.Retry) != QMessageBox.StandardButton.Retry:
                    return
    finally:
        if dlg is not None:
            dlg.hide()
            dlg.deleteLater()


def run_first_start(parent=None):
    """No keys file yet: make the first account, show its recovery key, move an older vault over, encrypt, and sign in.
    True once an account exists and the data is encrypted; False when the person quit."""
    if datakey.missing():                                # a new key would never open what is there
        QMessageBox.critical(parent, "Toner", datakey.MISSING)
        return False
    master_vault = passvault.exists() and passvault.uses_master()
    account = AccountDialog(parent)
    if not account.exec():
        return False
    try:
        RecoveryDialog(account.recovery, parent).exec()
        if master_vault and not adopt_old_vault(parent):
            return False                                 # the next start's sign-in asks again (ui/signinwindow.py)
        if lockdown.pending() and not encrypt(parent):
            return False
    finally:
        datakey.close()                                  # create left it open; signing in opens it again
    session.sign_in(account.name.text().strip(), account.pw.text())
    return True


def carry_credential_manager():
    """Passwords an older Toner kept in Windows Credential Manager move into the vault (signed in, data encrypted). Safe to run
    again: each leaves Credential Manager only once it is in the vault, so a start that stopped halfway carries on. A password
    the vault already has is kept (it is newer); the old copy is still removed. Once a pass reads it in full and finds none,
    later starts skip the scan (one read per name Toner knows); a pass that couldn't read it leaves that for the next start."""
    db.init()                                            # finding their names reads the devices
    if db.get_setting("credential_manager_carried"):
        return
    try:
        carry, complete = passvault.left_in_credential_manager(), True
    except passvault.Unreadable as e:                    # what was read moves now; the rest is tried again next start
        carry, complete = e.found, False
    if not carry:
        if complete:
            db.set_setting("credential_manager_carried", True)
        return
    new = {name: secret for name, secret in carry.items() if passvault.get(name) is None}
    if new:
        passvault.put_many(new)
    passvault.forget_credential_manager(carry)
    audit.log("passwords moved from Credential Manager", f"{len(new)} password(s)")
