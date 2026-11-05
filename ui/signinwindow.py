"""Signing in to Toner (layout C of the sign-in mockups): the username first, then the password, or the recovery key. After a
recovery-key sign-in an account gets a new password at once, and Toner is signed in as that account (a recovery session has no
password to lock with). The card helpers here are shared with the first start (ui/setupdlg.py) and the lock screen."""
from PySide6.QtCore import QObject, Qt, QTimer
from PySide6.QtWidgets import (QComboBox, QDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton, QStackedWidget,
                               QVBoxLayout, QWidget)

from core import datakey, passvault, passwords, session
from ui import theme

DAMAGED = "This file is damaged or was changed outside Toner."
# what a damaged or foreign netcheck.keys raises (JSONDecodeError is a ValueError); WrongPassword, also a ValueError, is caught first
DAMAGED_ERRORS = (OSError, ValueError, KeyError, TypeError)
RECOVERY_TEXT = "Enter the recovery key you saved when Toner was set up."
RESET_TEXT = "Choose the account, then a new password for it."
MISMATCH = "The two passwords don't match."


# ---------------------------------------------------------------- the card and what goes in it
def card(width=320):
    frame = QFrame()
    frame.setProperty("card", True)
    frame.setFixedWidth(width)
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(26, 24, 26, 22)
    lay.setSpacing(4)
    return frame, lay


def centred(widget, parent_layout):
    """`widget` in the middle of the space."""
    row = QHBoxLayout()
    row.addStretch(1)
    row.addWidget(widget)
    row.addStretch(1)
    parent_layout.addStretch(1)
    parent_layout.addLayout(row)
    parent_layout.addStretch(1)


def brand():
    lab = QLabel("Toner")
    lab.setStyleSheet(f"color: {theme.current().get('accent_ink', '#22d3ee')}; font-weight: 600; font-size: 11.5pt;")
    return lab


def heading(text=""):
    lab = QLabel(text)
    lab.setStyleSheet("font-size: 14pt; font-weight: 600;")
    lab.setWordWrap(True)
    return lab


def words(text=""):
    lab = QLabel(text)
    lab.setProperty("muted", True)
    lab.setWordWrap(True)
    return lab


def error_label():
    from ui import status
    lab = QLabel()
    lab.setWordWrap(True)
    lab.setStyleSheet(f"color: {status.ink('FAIL')};")
    lab.hide()
    return lab


def say(label, text):
    label.setText(text)
    label.setVisible(bool(text))


def field(lay, text, secret=False, widget=None):
    """A label over a box (the mockup's layout); the box is named by its label for screen readers."""
    lab = words(text)
    box = widget or QLineEdit()
    if secret:
        box.setEchoMode(QLineEdit.EchoMode.Password)
    box.setAccessibleName(text)
    lab.setBuddy(box)
    lay.addSpacing(6)
    lay.addWidget(lab)
    lay.addWidget(box)
    return box


def primary(text):
    b = QPushButton(text)
    b.setProperty("primary", True)
    b.setAutoDefault(False)                   # Enter in a box presses its own page's button (returnPressed), never a hidden one
    b.setMinimumHeight(34)
    return b


def link(text):
    b = QPushButton(text)
    b.setProperty("flat", True)
    b.setAutoDefault(False)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    b.setStyleSheet(f"color: {theme.current().get('accent_ink', '#22d3ee')}; text-align: left; padding: 2px 4px;")
    return b


class Wait(QObject):
    """Too many tries: the countdown in `label`, with `button` off until it ends."""

    def __init__(self, label, button):
        super().__init__(button)
        self.label, self.button, self.left = label, button, 0
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._tick)

    def start(self, seconds):
        self.left = int(seconds)
        self._show()
        self.timer.start()

    def _tick(self):
        self.left -= 1
        if self.left > 0:
            self._show()
            return
        self.timer.stop()
        self.button.setEnabled(True)
        say(self.label, "")

    def _show(self):
        say(self.label, str(datakey.Throttled(self.left)))
        self.button.setEnabled(False)


# ---------------------------------------------------------------- the window
class SignInWindow(QDialog):
    """exec() returns Accepted once session.state() == "open"; Escape or closing it quits Toner."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Toner")
        self.setMinimumSize(460, 440)
        self.pages = QStackedWidget()

        self.name_page, lay = self._page("Sign in")
        self.name = field(lay, "Username or email")
        self.name_error = error_label()
        self.next = primary("Next")
        self._finish(lay, self.name, self.name_error, self.next, self._next)

        self.password_page, lay = self._page("")
        self.who = lay.itemAt(1).widget()
        self.pw = field(lay, "Password", secret=True)
        self.error = error_label()
        self.sign_in = primary("Sign in")
        self.not_you, self.use_recovery = link("Not you?"), link("Use the recovery key")
        self._finish(lay, self.pw, self.error, self.sign_in, self._sign_in, self.not_you, self.use_recovery)

        self.recovery_page, lay = self._page("Sign in", RECOVERY_TEXT)
        self.recovery = field(lay, "Recovery key")
        self.recovery_error = error_label()
        self.recovery_sign_in = primary("Sign in")
        back = link("Not you?")
        self._finish(lay, self.recovery, self.recovery_error, self.recovery_sign_in, self._sign_in_recovery, back)

        self.reset_page, lay = self._page("Sign in", RESET_TEXT)
        self.account = field(lay, "Username", widget=QComboBox())
        self.new_pw = field(lay, "Password", secret=True)
        self.confirm = field(lay, "Confirm password", secret=True)
        self.reset_error = error_label()
        self.reset_ok = primary("Sign in")
        self._finish(lay, self.confirm, self.reset_error, self.reset_ok, self._reset)
        self.new_pw.returnPressed.connect(self.confirm.setFocus)

        self.sign_in_wait = Wait(self.error, self.sign_in)
        self.recovery_wait = Wait(self.recovery_error, self.recovery_sign_in)
        self.not_you.clicked.connect(lambda: self._go(self.name_page, self.name))
        back.clicked.connect(lambda: self._go(self.name_page, self.name))
        self.use_recovery.clicked.connect(lambda: self._go(self.recovery_page, self.recovery))
        outer = QVBoxLayout(self)
        centred(self.pages, outer)
        self._go(self.name_page, self.name)

    def _page(self, title, text=""):
        frame, lay = card()
        lay.addWidget(brand())
        lay.addWidget(heading(title))
        if text:
            lay.addWidget(words(text))
        self.pages.addWidget(frame)
        return frame, lay

    @staticmethod
    def _finish(lay, last_box, error, button, action, *links):
        lay.addWidget(error)
        lay.addSpacing(10)
        lay.addWidget(button)
        button.clicked.connect(action)
        last_box.returnPressed.connect(button.click)
        if links:
            lay.addSpacing(6)
        for b in links:
            lay.addWidget(b, 0, Qt.AlignmentFlag.AlignLeft)

    def _go(self, page, focus):
        for lab in (self.name_error, self.recovery_error, self.reset_error):
            say(lab, "")
        if not self.sign_in_wait.timer.isActive():
            say(self.error, "")
        self.pages.setCurrentWidget(page)
        self.pages.setFixedHeight(page.sizeHint().height())
        focus.setFocus()

    # ---------------------------------------------------------------- the steps
    def _next(self):
        """No lookup here: an unknown name gets the password step too, so the window never shows which names exist."""
        name = self.name.text().strip()
        if not name:
            say(self.name_error, "Enter a username.")
            return
        self.who.setText(name)
        self.pw.clear()
        self._go(self.password_page, self.pw)

    def _try(self, signing_in, error, wait, opener):
        """Run a sign-in; say what went wrong in `error`. True when it opened."""
        try:
            try:
                signing_in()
            except passvault.Locked:
                if not self._adopt_old_vault(opener):    # set up stopped before the old vault moved over: finish that first
                    return False
                signing_in()
            return True
        except datakey.Throttled as e:
            wait.start(e.seconds)
        except datakey.WrongPassword as e:
            say(error, str(e))
        except (passvault.WrongPassword, *DAMAGED_ERRORS):
            say(error, DAMAGED)
        return False

    def _adopt_old_vault(self, opener):
        from ui import setupdlg
        opener()
        try:
            return bool(setupdlg.OldVaultDialog(self).exec())
        finally:
            datakey.close()

    def _sign_in(self):
        name, pw = self.name.text().strip(), self.pw.text()
        self.pw.clear()
        if self._try(lambda: session.sign_in(name, pw), self.error, self.sign_in_wait, lambda: datakey.open_with_password(name, pw)):
            self.accept()
        else:
            self.pw.setFocus()

    def _sign_in_recovery(self):
        key = self.recovery.text()
        if not self._try(lambda: session.sign_in_recovery(key), self.recovery_error, self.recovery_wait,
                         lambda: datakey.open_with_recovery(key)):
            return
        self.recovery.clear()
        self.account.clear()
        self.account.addItems([a["name"] for a in datakey.accounts()])
        self._go(self.reset_page, self.new_pw)

    def _reset(self):
        """The recovery key opened Toner: the chosen account gets the new password, and Toner is signed in as it."""
        name, pw = self.account.currentText(), self.new_pw.text()
        why = passwords.problem(pw, name) or (MISMATCH if pw != self.confirm.text() else None)
        if why:
            say(self.reset_error, why)
            return
        try:
            datakey.set_password(name, pw)
            session.sign_out()
            session.sign_in(name, pw)
        except DAMAGED_ERRORS:
            say(self.reset_error, DAMAGED)
            return
        self.accept()

    def reject(self):
        if session.state() != "signed_out" and session.user() is None:
            session.sign_out()                           # never leave a recovery session behind
        super().reject()
