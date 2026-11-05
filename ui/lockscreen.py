"""The lock screen (layout B of the sign-in mockups): while the session is locked it sits over Toner's window and asks the
signed-in account's password again. It also runs the idle lock: no mouse or key input for Settings' signin_idle_minutes locks.

It is its own application-modal window, so it is the newest modal even when a dialog was open (that dialog's exec() goes on,
blocked, and keeps what was typed), and every Toner window, Main included, gets an opaque cover over its contents until unlock.
A window that opens while locked is covered too, and the lock takes the top of the modal stack again.

Locking keeps the data key open (core/session.py), so scheduled checks and backups go on underneath; only the windows are hidden."""
import time

from PySide6.QtCore import QEvent, Qt, QTimer, Signal
from PySide6.QtWidgets import QApplication, QLabel, QLineEdit, QVBoxLayout, QWidget

from core import datakey, db, session
from ui import theme
from ui.signinwindow import DAMAGED, DAMAGED_ERRORS, Wait, card, centred, error_label, heading, link, primary, say, words

_now = time.time                                         # wall-clock: it keeps counting while the computer sleeps (the tests move it)
_INPUT = {QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress, QEvent.Type.MouseMove, QEvent.Type.Wheel, QEvent.Type.TouchBegin}
_NOT_WINDOWS = (Qt.WindowType.Popup, Qt.WindowType.ToolTip, Qt.WindowType.Desktop)    # menus, drop-downs and tips are not covered


class LockScreen(QWidget):
    changed = Signal()                                   # the session changed (on any thread): followed on the window's thread

    def __init__(self, main):
        super().__init__(main, Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint)
        self.main = main
        self.setWindowTitle("Toner")
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
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
        self.other.clicked.connect(self._sign_out)
        self.wait = Wait(self.error, self.unlock)
        centred(frame, QVBoxLayout(self))
        self.idle = QTimer(self)                         # checks now and then; input moves `last` (eventFilter)
        self.idle.setInterval(15000)
        self.idle.timeout.connect(self.check_idle)
        self.last = _now()
        self._idle_minutes = None                        # set when the idle lock is what locked
        self.covers = {}                                 # each covered window -> its cover
        self.locked = False                              # the lock is up (it may be hidden while every Toner window is)
        self._passing = False                            # Sign in as someone else: Main's closing questions must show
        QApplication.instance().installEventFilter(self)
        self.changed.connect(self.follow)
        session.on_change(lambda _state: self.changed.emit())
        self.follow()

    def eventFilter(self, obj, event):
        kind = event.type()
        if kind in _INPUT:
            self.last = _now()
        elif self.locked and not self._passing:
            if kind == QEvent.Type.Show and isinstance(obj, QWidget) and obj.isWindow() and obj is not self:
                QTimer.singleShot(0, self._cover_all)        # a window that opened (or came back) while locked
            elif kind in (QEvent.Type.Resize, QEvent.Type.Move) and obj in self.covers:
                self.covers[obj].setGeometry(obj.rect())
                if obj is self.main:
                    self.setGeometry(self.main.geometry())
        return False

    def closeEvent(self, event):
        if self.locked:
            event.ignore()                               # Alt+F4 on the lock doesn't unlock anything

    # ---------------------------------------------------------------- following the session
    def follow(self):
        """Read the state (callbacks can arrive out of order): open uncovers and runs the idle timer; locked covers."""
        state = session.state()
        if state == "open":
            self.last = _now()
            self.idle.start()
            if self.locked:
                self._uncover()
        else:
            self.idle.stop()
        if state == "locked" and not self.locked:
            self.show_locked()

    def check_idle(self):
        if session.state() != "open" or session.user() is None:
            return
        now = _now()
        if now < self.last:                              # the clock went back: count from now
            self.last = now
            return
        minutes = int(db.get_setting("signin_idle_minutes") or 0)
        if minutes > 0 and now - self.last >= minutes * 60:      # (a jump forward, a sleep, counts as time without use)
            self._idle_minutes = minutes
            session.lock()

    def show_locked(self):
        user = session.user() or ""
        minutes, self._idle_minutes = self._idle_minutes, None
        self.reason.setText(f"Locked after {minutes} minutes without use." if minutes else f"Locked by {user}.")
        self.who.setText(f"{user}, local account")
        self.avatar.setText("".join(w[0] for w in user.split()[:2]).upper())
        t = theme.current()
        self.setStyleSheet(f"QWidget#lockScreen, QWidget#lockCover {{ background: {t.get('bg', '#081420')}; }}")
        self.avatar.setStyleSheet(f"background: {t.get('surface2', '#12283d')}; border: 1px solid {t.get('edge', '#3d5a76')}; "
                                  f"border-radius: 22px; color: {t.get('accent_ink', '#22d3ee')}; font-weight: 600;")
        say(self.error, "")
        self.pw.clear()
        self.locked = True
        self._cover_all()

    def _cover_all(self):
        """An opaque cover over every visible Toner window (dialogs included, which stay open underneath), then the lock on top
        of Main as the newest modal, with the focus in its password box."""
        if not self.locked or self._passing:
            return
        bg = theme.current().get("bg", "#081420")
        for w in QApplication.topLevelWidgets():
            if isinstance(w, LockScreen) or w in self.covers or not w.isVisible() or w.windowType() in _NOT_WINDOWS:
                continue
            cover = QWidget(w)
            cover.setObjectName("lockCover")
            cover.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
            cover.setStyleSheet(f"QWidget#lockCover {{ background: {bg}; }}")
            cover.setGeometry(w.rect())
            cover.show()
            cover.raise_()
            self.covers[w] = cover
            w.destroyed.connect(lambda *_a, w=w: self.covers.pop(w, None))
        self.keep_covered()
        if not any(w.isVisible() for w in self.covers):
            self.hide()                                  # every Toner window is in the tray: the lock waits for one to show
            return
        if self.isVisible() and QApplication.activeModalWidget() is not self:
            self.hide()                                  # a modal opened since: showing again makes the lock the newest one
        self.setGeometry(self.main.geometry())
        self.show()
        self.raise_()
        self.activateWindow()
        self.pw.setFocus()

    def keep_covered(self):
        """Something in a covered window raised itself (the Assistant's button): the cover goes back on top."""
        for cover in self.covers.values():
            cover.raise_()

    def _uncover(self):
        self.locked = False
        self.pw.clear()
        say(self.error, "")
        self.hide()
        for cover in self.covers.values():
            cover.hide()
            cover.deleteLater()
        self.covers = {}

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

    def _sign_out(self):
        """Sign in as someone else: Main's closing questions (unsaved settings, a running playbook) must be answerable, so the
        lock steps aside for them, the windows staying covered; if one is refused, the lock comes back."""
        self._passing = True
        self.hide()
        try:
            self.main.sign_out()
        finally:
            self._passing = False
        if session.state() == "locked":
            self._cover_all()
