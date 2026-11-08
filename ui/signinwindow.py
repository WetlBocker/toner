"""Signing in to Toner (layout C of the sign-in mockups): the username first, then the password, or the recovery key. After a
recovery-key sign-in an account gets a new password at once, and Toner is signed in as that account (a recovery session has no
password to lock with). The card helpers here are shared with the first start (ui/setupdlg.py) and the lock screen.

A directory account (core/dirsignin.py) goes from the password to Duo, the PIN, and when needed a new PIN and an admin's
approval. Each slow step runs on a Job thread; its result is used only while the window is still on that attempt. An SSO
account goes to the browser instead of the password and Duo."""
import threading
import webbrowser

from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (QComboBox, QDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton, QStackedWidget,
                               QVBoxLayout)

from core import audit, datakey, directory, dirsignin, duo, oidc, passvault, passwords, perms, pinslot, session
from ui import theme

DAMAGED = "This file is damaged or was changed outside Toner."
VAULT_CHANGED = "The vault changed after it was opened. Open it again, then try again."
# what a damaged or foreign netcheck.keys raises (JSONDecodeError is a ValueError); WrongPassword, also a ValueError, is caught first
DAMAGED_ERRORS = (OSError, ValueError, KeyError, TypeError)
RECOVERY_TEXT = "Enter the recovery key you saved when Toner was set up."
RESET_TEXT = "Choose the account, then a new password for it."
MISMATCH = "The two passwords don't match."
DUO_TITLE = "Approve on your phone"
DUO_TEXT = "Duo sent a request to your phone. Approve it to finish signing in."
CHOOSE_TITLE = "Choose a PIN"
CHOOSE_TEXT = "You'll use this PIN to unlock Toner on this computer."
APPROVE_TITLE = "An admin needs to approve this"
PIN_MISMATCH = "The two PINs don't match."
SSO_TITLE = "Continue in your browser"
SSO_TEXT = dirsignin.SSO_TEXT
SSO_AGAIN = "Open the page again"
APPROVE_WITH_ACCOUNT = "Approve with a directory account"
APPROVER_TITLE = "Admin approval"
APPROVER_TEXT = "An admin who has signed in on this computer before signs in with their own account, then types their Toner PIN."
# directory steps' errors whose text is already the approved sentence
SAID = (datakey.WrongPassword, datakey.NameTaken, dirsignin.NotInGroup, dirsignin.Paused, dirsignin.CannotApprove, dirsignin.CaChanged,
        duo.Unavailable, duo.Denied, pinslot.WrongPin)


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
    """Too many tries: the countdown in `label`, with `button` off until it ends. `error` words it (pinslot.PinLocked for PINs)."""

    def __init__(self, label, button, error=datakey.Throttled):
        super().__init__(button)
        self.label, self.button, self.left, self.error = label, button, 0, error
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
        say(self.label, str(self.error(self.left)))
        self.button.setEnabled(False)


class Job(QThread):
    """Runs one function off the window's thread and hands back (job, result, error), as ui/firmware.py's Job does."""
    done = Signal(object, object, object)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            result, error = self.fn(), None
        except Exception as e:                       # noqa: BLE001  (the window says what it can, or raises it there)
            result, error = None, e
        self.done.emit(self, result, error)


# ---------------------------------------------------------------- the window
class SignInWindow(QDialog):
    """exec() returns Accepted once session.state() == "open"; Escape or closing it quits Toner.

    approver_for (an Attempt at "approve"): the nested window an Admin approves it in, with their own directory or SSO sign-in
    and PIN. It never opens a session; it accepts once the approval lands."""

    def __init__(self, parent=None, approver_for=None):
        super().__init__(parent)
        self.setWindowTitle("Toner")
        self.setMinimumSize(460, 440)
        self.pages = QStackedWidget()
        self.approver_for, self.approver = approver_for, None

        self.name_page, lay = self._page(APPROVER_TITLE, APPROVER_TEXT) if approver_for else self._page("Sign in")
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
        self.not_you.clicked.connect(self._not_you)
        back.clicked.connect(self._not_you)
        self.use_recovery.clicked.connect(lambda: self._go(self.recovery_page, self.recovery))

        # ------------------------------------------------ a directory account's pages
        self.directory, self.attempt, self._cancel, self._forgot, self._turn, self._jobs = False, None, None, False, 0, set()
        self.duo_page, lay = self._page(DUO_TITLE, DUO_TEXT)
        self.duo_cancel, self.use_code = primary("Cancel"), link("Enter a code instead")
        lay.addSpacing(10)
        lay.addWidget(self.duo_cancel)
        lay.addSpacing(6)
        for b in (self.use_code, self._not_you_link()):
            lay.addWidget(b, 0, Qt.AlignmentFlag.AlignLeft)
        self.duo_cancel.clicked.connect(self._duo_cancel)
        self.use_code.clicked.connect(self._use_code)

        self.sso, self._sso_attempt = None, []                  # the SSO connection typed for; the attempt once started
        self.sso_page, lay = self._page(SSO_TITLE, SSO_TEXT)
        self.sso_text = lay.itemAt(2).widget()
        self.sso_cancel, self.sso_again = primary("Cancel"), link(SSO_AGAIN)
        lay.addSpacing(10)
        lay.addWidget(self.sso_cancel)
        lay.addSpacing(6)
        lay.addWidget(self.sso_again, 0, Qt.AlignmentFlag.AlignLeft)
        self.sso_cancel.clicked.connect(lambda: self._cancel.set())    # the wait ends within a second and lands as Cancelled
        self.sso_again.clicked.connect(self._sso_again)
        self.name_wait = Wait(self.name_error, self.next)       # an SSO start while the shared counter's wait runs

        self.code_page, lay = self._page("")
        self.code_who = lay.itemAt(1).widget()
        self.code = field(lay, "Duo code")
        self.code_error, self.code_ok = error_label(), primary("Sign in")
        self._finish(lay, self.code, self.code_error, self.code_ok, self._duo_code, self._not_you_link())

        self.pin_page, lay = self._page("")
        self.pin_who = lay.itemAt(1).widget()
        self.pin = field(lay, "PIN", secret=True)
        self.pin_error, self.pin_ok, self.forgot = error_label(), primary("Sign in"), link("Forgot your PIN?")
        self._finish(lay, self.pin, self.pin_error, self.pin_ok, self._pin, self._not_you_link(), self.forgot)
        self.forgot.clicked.connect(self._forgot_pin)

        self.choose_page, lay = self._page(CHOOSE_TITLE, CHOOSE_TEXT)
        self.pin1, self.pin2 = field(lay, "PIN", secret=True), field(lay, "Confirm PIN", secret=True)
        self.choose_error, self.choose_ok = error_label(), primary("Next")
        self._finish(lay, self.pin2, self.choose_error, self.choose_ok, self._choose, self._not_you_link())
        self.pin1.returnPressed.connect(self.pin2.setFocus)

        self.approve_page, lay = self._page(APPROVE_TITLE, dirsignin.FIRST)
        self.approve_text = lay.itemAt(2).widget()
        self.admin, self.admin_pw = field(lay, "Admin username"), field(lay, "Password", secret=True)
        self.approve_error, self.approve_ok = error_label(), primary("Approve")
        self.approve_recovery, self.approve_with_account = link("Use the recovery key"), link(APPROVE_WITH_ACCOUNT)
        self._finish(lay, self.admin_pw, self.approve_error, self.approve_ok, self._approve, self._not_you_link(),
                     self.approve_with_account, self.approve_recovery)
        self.admin.returnPressed.connect(self.admin_pw.setFocus)
        self.approve_recovery.clicked.connect(lambda: self._go(self.approve_key_page, self.approve_key))
        self.approve_with_account.clicked.connect(self._approve_with_account)

        self.approve_key_page, lay = self._page(APPROVE_TITLE, RECOVERY_TEXT)
        self.approve_key = field(lay, "Recovery key")
        self.approve_key_error, self.approve_key_ok = error_label(), primary("Approve")
        self._finish(lay, self.approve_key, self.approve_key_error, self.approve_key_ok, self._approve_key, self._not_you_link())

        self.pin_wait = Wait(self.pin_error, self.pin_ok, pinslot.PinLocked)
        self.choose_wait = Wait(self.choose_error, self.choose_ok, pinslot.PinLocked)      # the chip's lockout refuses new keys too
        self.approve_wait = Wait(self.approve_error, self.approve_ok)
        self.approve_key_wait = Wait(self.approve_key_error, self.approve_key_ok)
        self._waits = (self.pin_wait, self.choose_wait, self.approve_wait, self.approve_key_wait)
        self._secrets = (self.pw, self.code, self.pin, self.pin1, self.pin2, self.admin, self.admin_pw, self.approve_key,
                         self.recovery, self.new_pw, self.confirm)
        if approver_for:                                 # the approver's own sign-in: no recovery key, new PIN or session
            self.use_recovery.hide()
            self.forgot.hide()
            self.pin_ok.setText("Approve")
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
        say(self.code_error, "")
        for wait in self._waits:
            if not wait.timer.isActive():
                say(wait.label, "")
        for box in self._secrets:                        # no password, PIN or code outlives its page
            box.setText("")
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
        self.sso, self._forgot = None, False             # a new sign-in: an earlier Forgot your PIN? that failed doesn't carry over
        try:
            kind = dirsignin.classify(name)
            self.directory = kind[0] == "directory"
            if self.directory and kind[1].get("kind") == "oidc":
                self.sso = kind[1]
        except dirsignin.Paused as e:
            say(self.name_error, str(e))
            return
        except DAMAGED_ERRORS:
            self.directory = False                       # the password step says what is wrong with the file, as before
        if self.approver_for and not self.directory:     # a local Admin approves on the approval page itself
            say(self.name_error, dirsignin.CANNOT_APPROVE)
            return
        for lab in (self.who, self.code_who, self.pin_who):
            lab.setText(name)
        self.pw.setText("")
        if self.sso:
            return self._sso()
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
        except passvault.Locked:                         # the old vault was replaced while it was being moved over
            say(error, VAULT_CHANGED)
        except (passvault.WrongPassword, *DAMAGED_ERRORS):
            say(error, DAMAGED)
        return False

    def _adopt_old_vault(self, opener):
        from ui import setupdlg
        opener()
        try:
            return setupdlg.adopt_old_vault(self)
        finally:
            datakey.close()

    def _sign_in(self):
        if self.directory:
            return self._begin()
        name, pw = self.name.text().strip(), self.pw.text()
        self.pw.setText("")
        if self._try(lambda: session.sign_in(name, pw), self.error, self.sign_in_wait, lambda: datakey.open_with_password(name, pw)):
            self.accept()
        else:
            self.pw.setFocus()

    def _sign_in_recovery(self):
        key = self.recovery.text()
        if not self._try(lambda: session.sign_in_recovery(key), self.recovery_error, self.recovery_wait,
                         lambda: datakey.open_with_recovery(key)):
            return
        self.recovery.setText("")
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
            audit.log("password reset with the recovery key", name)
            session.sign_out()
            session.sign_in(name, pw)
        except datakey.Throttled as e:                   # (Toner's service counted a wrong try meanwhile): sign in as usual
            self.name.setText(name)
            self._next()
            self.sign_in_wait.start(e.seconds)
            return
        except perms.Denied as e:                       # (a PermissionError, so an OSError: not "damaged")
            say(self.reset_error, str(e))
            return
        except DAMAGED_ERRORS:
            say(self.reset_error, DAMAGED)
            return
        self.accept()

    # ---------------------------------------------------------------- a directory account's steps
    def _not_you_link(self):
        b = link("Not you?")
        b.clicked.connect(self._not_you)
        return b

    def _drop(self):
        """Forget the attempt: a running push stops, and any step still running lands on nothing."""
        self._turn += 1
        if self._cancel is not None:
            self._cancel.set()
        self.attempt, self._forgot = None, False

    def _not_you(self):
        self._drop()
        self._go(self.name_page, self.name)

    def _run(self, fn, landed, block=True):
        """`fn` on a Job; `landed(result, error)` back on this thread, unless the attempt changed meanwhile. `block`: the page
        is off while it runs (the push leaves its page on, for Cancel and Enter a code instead)."""
        job = Job(fn)
        job.landed, job.turn, job.page = landed, self._turn, self.pages.currentWidget() if block else None
        if job.page is not None:
            job.page.setEnabled(False)
        job.done.connect(self._landed, Qt.ConnectionType.QueuedConnection)
        self._jobs.add(job)
        job.start()

    def _landed(self, job, result, error):
        job.wait()                                       # run() has emitted its last line: this returns at once
        job.fn = None                                    # (its closure holds the password, PIN or code)
        self._jobs.discard(job)
        if job.page is not None:
            job.page.setEnabled(True)
        if job.turn == self._turn:
            job.landed(result, error)

    def _fail(self, e, label, wait, box=None):
        if isinstance(e, (datakey.Throttled, pinslot.PinLocked)) and wait is not None:
            wait.start(e.seconds)
        elif isinstance(e, (directory.Unreachable, oidc.Unreachable)):
            say(label, self._unreachable())
        elif isinstance(e, oidc.OidcError):              # its own text names the provider's host: never shown
            say(label, dirsignin.sso_said(self.sso, e))
        elif isinstance(e, SAID):
            say(label, str(e))
        elif isinstance(e, DAMAGED_ERRORS):
            say(label, DAMAGED)
        else:
            raise e
        if box is not None:
            box.setFocus()

    def _step(self, fn, label, wait, box):
        """A step on the attempt: the next page when it works, else the error on this one."""
        self._run(fn, lambda _r, e: self._route() if e is None else self._fail(e, label, wait, box))

    def _route(self):
        """The page for the attempt's stage."""
        a = self.attempt
        if a.stage != "duo":
            forgot, self._forgot = self._forgot, False
            if forgot and a.stage == "pin":
                if a.offline:                            # the directory went away since Forgot your PIN? was pressed
                    self._go(self.pin_page, self.pin)
                    say(self.pin_error, self._unreachable())
                    return
                dirsignin.restart_pin(a)
        if self.approver_for and (a.offline or a.stage in ("choose-pin", "approve")):
            self._drop()                                 # the approver would need a new PIN (or the directory): not here
            self._go(self.name_page, self.name)
            say(self.name_error, self._unreachable() if a.offline else dirsignin.NOT_HERE_BEFORE)
            return
        if a.stage == "done":
            self.accept()
            return
        if a.stage == "approve":
            self.approve_text.setText(a.message)
        if a.name:                                       # the account's name as the directory or provider gives it, not as typed
            for lab in (self.code_who, self.pin_who):
                lab.setText(a.name)
        page, focus = {"duo": (self.duo_page, self.duo_cancel), "pin": (self.pin_page, self.pin),
                       "choose-pin": (self.choose_page, self.pin1), "approve": (self.approve_page, self.admin)}[a.stage]
        self._go(page, focus)
        if a.stage == "duo":
            self._push()

    def _begin(self):
        login, pw = self.name.text().strip(), self.pw.text()
        self.pw.setText("")

        def begin():
            a = dirsignin.begin(login, pw)
            if not a.offline:
                dirsignin.after_password(a)
            return a

        def landed(a, e):
            if e is not None:
                return self._fail(e, self.error, self.sign_in_wait, self.pw)
            self.attempt = a
            self._route()
        self._run(begin, landed)

    def _push(self):
        a, cancel = self.attempt, threading.Event()
        self._cancel = cancel

        def landed(_r, e):
            if cancel.is_set() or a is not self.attempt:  # Cancel, a code instead, or Not you? came first
                return
            if e is None:
                return self._route()
            self.attempt = None
            self._go(self.password_page, self.pw)
            self._fail(e, self.error, self.sign_in_wait, self.pw)
        self._run(lambda: dirsignin.duo_push(a, cancel), landed, block=False)

    def _duo_cancel(self):
        self._drop()
        self._go(self.password_page, self.pw)

    def _use_code(self):
        self._cancel.set()
        self._go(self.code_page, self.code)

    def _duo_code(self):
        a, code = self.attempt, self.code.text()
        self.code.setText("")

        def enter():
            try:
                dirsignin.duo_code(a, code)
            except RuntimeError:
                if a.stage == "duo":
                    raise                                # (else the push was approved just before it stopped: go on)
        self._step(enter, self.code_error, None, self.code)

    def _pin(self):
        a, pin = self.attempt, self.pin.text()
        self.pin.setText("")
        if self.approver_for:
            return self._run(lambda: dirsignin.approve_with_account(self.approver_for, a, pin),
                             lambda _r, e: self.accept() if e is None else self._fail(e, self.pin_error, self.pin_wait, self.pin))
        self._step(lambda: dirsignin.finish(a, pin), self.pin_error, self.pin_wait, self.pin)

    def _forgot_pin(self):
        """A new PIN needs the password (and Duo) checked online again, in a new attempt."""
        if self.attempt.offline:
            say(self.pin_error, self._unreachable())
            return
        self._drop()
        self._forgot = True
        if self.sso:
            return self._sso()
        self._go(self.password_page, self.pw)

    def _unreachable(self):
        return dirsignin.SSO_UNREACHABLE.format(provider=self.sso["name"]) if self.sso else dirsignin.UNREACHABLE

    def _sso(self):
        """The browser instead of the password. One Job starts the sign-in and waits for it, so its loopback port never outlives
        the Job: Cancel, Not you? or closing the window sets the Event, and the wait ends within a second."""
        cfg, login, cancel, started = self.sso, self.name.text().strip(), threading.Event(), []
        self._cancel, self._sso_attempt = cancel, started
        self.sso_text.setText(SSO_TEXT.format(provider=cfg["name"]))
        self._go(self.sso_page, self.sso_cancel)

        def sign_in():
            a = dirsignin.sso_start(cfg, login, open_url=webbrowser.open)
            started.append(a)
            if a.stage == "browser":                     # (offline: at the PIN already)
                dirsignin.sso_wait(a, cancel)
            return a

        def landed(a, e):
            if e is not None:
                self._go(self.name_page, self.name)
                return self._fail(e, self.name_error, self.name_wait, self.name)
            self.attempt = a
            self._route()
        self._run(sign_in, landed, block=False)

    def _sso_again(self):
        if self._sso_attempt and self._sso_attempt[0].browser is not None:
            self._sso_attempt[0].browser.open()

    def _choose(self):
        a, pin, again = self.attempt, self.pin1.text(), self.pin2.text()
        self.pin1.setText("")
        self.pin2.setText("")

        def choose():                                    # best_kind can take seconds the first time on Windows
            why = pinslot.problem(dirsignin.pin_kind(a), pin) or (PIN_MISMATCH if pin != again else None)
            if why is None:
                try:
                    dirsignin.choose_pin(a, pin)
                except ValueError:
                    why = pinslot.problem(dirsignin.pin_kind(a), pin)    # the chip refused a new key: the next kind's rule
                    if why is None:
                        raise
            return why

        def landed(why, e):
            if isinstance(e, datakey.NameTaken):         # the directory's name for this person is another account's here
                e, why = None, dirsignin.NAME_TAKEN
            if e is not None:
                return self._fail(e, self.choose_error, self.choose_wait, self.pin1)
            if why is None:
                return self._route()
            say(self.choose_error, why)
            self.pin1.setFocus()
        self._run(choose, landed)

    def _approve(self):
        a, admin, pw = self.attempt, self.admin.text().strip(), self.admin_pw.text()
        self.admin_pw.setText("")
        self._step(lambda: dirsignin.approve(a, admin, pw), self.approve_error, self.approve_wait, self.admin_pw)

    def _approve_with_account(self):
        """The nested window: once it closes, whatever its result (its Jobs have ended), this window routes the attempt on (to its
        PIN once approved)."""
        a = self.attempt
        self.approver = SignInWindow(self, approver_for=a)
        self.approver.finished.connect(lambda r: self._route() if self.attempt is a else None)
        self.approver.open()

    def _approve_key(self):
        a, key = self.attempt, self.approve_key.text()
        self.approve_key.setText("")
        self._step(lambda: dirsignin.approve_recovery(a, key), self.approve_key_error, self.approve_key_wait, self.approve_key)

    def _stop(self):
        """Closing: stop the push and let every running step end first (a Job must not outlive its window)."""
        self._drop()
        for job in list(self._jobs):
            job.wait()
        self._jobs.clear()

    def done(self, r):
        self._stop()
        super().done(r)

    def reject(self):
        self._stop()                                     # a PIN step that opens the session ends before the check below
        if session.state() != "signed_out" and session.user() is None:
            session.sign_out()                           # never leave a recovery session behind
        super().reject()
