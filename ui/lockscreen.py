"""The lock screen (layout B of the sign-in mockups): it covers Toner's window while the session is locked, and asks the
signed-in account's password again. It also runs the idle lock: no mouse or key input for Settings' signin_idle_minutes locks.

Locking keeps the data key open (core/session.py), so scheduled checks and backups go on underneath; only the window is hidden."""
import time

from PySide6.QtCore import QEvent, Qt, QTimer, Signal
from PySide6.QtGui import QShortcut
from PySide6.QtWidgets import QApplication, QLabel, QLineEdit, QVBoxLayout, QWidget

from core import datakey, db, session
from ui import theme
from ui.signinwindow import DAMAGED, DAMAGED_ERRORS, Wait, card, centred, error_label, heading, link, primary, say, words

_now = time.monotonic                                    # (the tests move this clock instead of waiting)
_INPUT = {QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress, QEvent.Type.MouseMove, QEvent.Type.Wheel, QEvent.Type.TouchBegin}


class LockScreen(QWidget):
    changed = Signal()                                   # the session changed (on any thread): followed on the window's thread

    def __init__(self, main):
        super().__init__(main)
        self.main = main
        self.setObjectName("lockScreen")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        frame, lay = card()
        self.avatar = QLabel()
        self.avatar.setFixedSize(44, 44)
        self.avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self.avatar)
        lay.addSpacing(6)
        lay.addWidget(heading("Toner is locked"))
        self.reason = words()
        lay.addWidget(self.reason)
        self.who = words()
        lay.addSpacing(8)
        lay.addWidget(self.who)
        self.pw = QLineEdit()                            # the mockup: the account above, "Password" inside the box
        self.pw.setPlaceholderText("Password")
        self.pw.setAccessibleName("Password")
        self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.who.setBuddy(self.pw)
        lay.addSpacing(4)
        lay.addWidget(self.pw)
        self.error = error_label()
        self.unlock = primary("Unlock")
        self.other = link("Sign in as someone else")
        lay.addWidget(self.error)
        lay.addSpacing(10)
        lay.addWidget(self.unlock)
        lay.addSpacing(6)
        lay.addWidget(self.other, 0, Qt.AlignmentFlag.AlignLeft)
        self.pw.returnPressed.connect(self.unlock.click)
        self.unlock.clicked.connect(self._unlock)
        self.other.clicked.connect(main.sign_out)
        self.wait = Wait(self.error, self.unlock)
        centred(frame, QVBoxLayout(self))
        self.idle = QTimer(self)                         # checks now and then; input moves `last` (eventFilter)
        self.idle.setInterval(15000)
        self.idle.timeout.connect(self.check_idle)
        self.last = _now()
        self._idle_minutes = None                        # set when the idle lock is what locked
        self._off, self._hidden = [], []
        QApplication.instance().installEventFilter(self)
        self.changed.connect(self.follow)
        session.on_change(lambda _state: self.changed.emit())
        self.hide()
        self.follow()

    def eventFilter(self, obj, event):
        kind = event.type()
        if kind in _INPUT:
            self.last = _now()
        elif kind == QEvent.Type.Resize and obj is self.main:
            self.setGeometry(self.main.rect())
        return False

    # ---------------------------------------------------------------- following the session
    def follow(self):
        """Read the state (callbacks can arrive out of order): open hides the lock and runs the idle timer; locked shows it."""
        state = session.state()
        if state == "open":
            self.last = _now()
            self.idle.start()
            if self.isVisible():
                self._uncover()
        else:
            self.idle.stop()
        if state == "locked" and not self.isVisible():
            self.show_locked()

    def check_idle(self):
        if session.state() != "open" or session.user() is None:
            return
        minutes = int(db.get_setting("signin_idle_minutes") or 0)
        if minutes > 0 and _now() - self.last >= minutes * 60:
            self._idle_minutes = minutes
            session.lock()

    def show_locked(self):
        user = session.user() or ""
        minutes, self._idle_minutes = self._idle_minutes, None
        self.reason.setText(f"Locked after {minutes} minutes without use." if minutes else f"Locked by {user}.")
        self.who.setText(f"{user}, local account")
        self.avatar.setText("".join(w[0] for w in user.split()[:2]).upper())
        t = theme.current()
        self.setStyleSheet(f"QWidget#lockScreen {{ background: {t.get('bg', '#081420')}; }}")   # opaque: nothing of the window shows
        self.avatar.setStyleSheet(f"background: {t.get('surface2', '#12283d')}; border: 1px solid {t.get('edge', '#3d5a76')}; "
                                  f"border-radius: 22px; color: {t.get('accent_ink', '#22d3ee')}; font-weight: 600;")
        say(self.error, "")
        # what's underneath can't be reached: its widgets and shortcuts are off, and the other Toner windows hide
        self._off = [w for w in self.main.findChildren(QWidget, options=Qt.FindChildOption.FindDirectChildrenOnly)
                     if w is not self and w.isEnabled()] + [s for s in self.main.findChildren(QShortcut) if s.isEnabled()]
        for w in self._off:
            w.setEnabled(False)
        self._hidden = [w for w in QApplication.topLevelWidgets() if w is not self.main and w.isVisible() and not w.isModal()
                        and w.windowType() in (Qt.WindowType.Window, Qt.WindowType.Dialog)]
        for w in self._hidden:
            w.hide()
        self.setGeometry(self.main.rect())
        self.show()
        self.raise_()
        self.pw.setFocus()

    def _uncover(self):
        self.pw.clear()
        say(self.error, "")
        self.hide()
        for w in self._off:
            w.setEnabled(True)
        for w in self._hidden:
            w.show()
        self._off, self._hidden = [], []

    def _unlock(self):
        pw = self.pw.text()
        self.pw.clear()
        try:
            session.unlock(pw)
        except datakey.Throttled as e:
            self.wait.start(e.seconds)
        except datakey.WrongPassword as e:
            say(self.error, str(e))
        except RuntimeError:
            self.follow()                                # unlocked already (from elsewhere)
        except DAMAGED_ERRORS:
            say(self.error, DAMAGED)
