"""The lock screen (layout B of the sign-in mockups): while the session is locked it sits over Toner's window and asks the
signed-in account's password again. It also runs the idle lock: no mouse or key input for Settings' signin_idle_minutes locks.

It is its own application-modal window, so it is the newest modal even when a dialog was open (that dialog's exec() goes on,
blocked, and keeps what was typed), and every Toner window, Main included, gets an opaque cover over its contents until unlock.
A window that opens while locked is covered too, and the lock takes the top of the modal stack again.

Locking keeps the data key open (core/session.py), so scheduled checks and backups go on underneath; only the windows are hidden.
An account with security keys touches one after its password or PIN (ui/keyask.py): the unlock runs on a Job meanwhile."""
import time

from PySide6.QtCore import QEvent, Qt, QTimer, Signal
from PySide6.QtWidgets import QApplication, QLabel, QLineEdit, QVBoxLayout, QWidget

from core import datakey, db, dirpin, dirsignin, fidokey, pinslot, session
from ui import theme
from ui.keyask import KeyAsk
from ui.widgets import while_alive
from ui.signinwindow import (DAMAGED, DAMAGED_ERRORS, KEY_TEXT, KEY_TITLE, Job, Wait, card, centred, error_label, heading, link, primary,
                             say, words)

_now = time.time                                         # wall-clock: it keeps counting while the computer sleeps (the tests move it)
_INPUT = {QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress, QEvent.Type.MouseMove, QEvent.Type.Wheel, QEvent.Type.TouchBegin}
_NOT_WINDOWS = (Qt.WindowType.Popup, Qt.WindowType.ToolTip, Qt.WindowType.Desktop)    # menus, drop-downs and tips are not covered
LOCKED = "Toner is locked"
NOT_TOUCHED = "The key wasn't touched. Try again."


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
        self.head = heading(LOCKED)
        lay.addWidget(self.head)
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
        self.discard = link("Discard changes and close")     # shown with the "unlock to close" line when only unsaved changes block it
        self.discard.hide()
        self.again = primary("Sign in")                  # after the session, with the directory reachable: the full sign-in
        self.again.hide()
        lay.addWidget(self.error)
        lay.addSpacing(10)
        lay.addWidget(self.unlock)
        lay.addWidget(self.again)
        lay.addSpacing(6)
        lay.addWidget(self.other, 0, Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(self.discard, 0, Qt.AlignmentFlag.AlignLeft)
        self.discard.clicked.connect(lambda: self.main.discard_and_close())
        self.pw.returnPressed.connect(self.unlock.click)
        self.unlock.clicked.connect(self._unlock)
        self.other.clicked.connect(self._sign_out)
        self.again.clicked.connect(self._sign_out)
        self._locks = 0                                  # counts the locks: a probe's answer belongs to the lock that asked
        self._jobs = set()                               # the directory probes running off this thread
        self.wait = Wait(self.error, self.unlock)
        self.keyask, self._reason = KeyAsk(self), ""
        self.keyask.touching.connect(self._touching)
        centred(frame, QVBoxLayout(self))
        self.idle = QTimer(self)                         # checks now and then; input moves `last` (eventFilter)
        self.idle.setInterval(15000)
        self.idle.timeout.connect(self.check_idle)
        self.last = _now()
        self._idle_minutes = None                        # set when the idle lock is what locked
        self.covers = {}                                 # each covered window -> its cover
        self._on_top = []                                # covered windows that stayed on top, so they don't sit over the lock
        self.locked = False                              # the lock is up (it may be hidden while every Toner window is)
        self._passing = False                            # Sign in as someone else: Main's closing questions must show
        QApplication.instance().installEventFilter(self)
        self.changed.connect(self.follow)
        while_alive(self, session.on_change, session.off_change, lambda _state: self.changed.emit())
        self.follow()

    def eventFilter(self, obj, event):
        kind = event.type()
        if kind in _INPUT:
            now = _now()
            if now - self.last > 60 and session.state() == "open":
                self.check_idle()                        # waking from sleep: the idle timer may not have run yet
                if session.state() == "locked":
                    self.last = now
                    return True                          # the key or click that woke it doesn't reach the window underneath
            self.last = now
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
        elif state == "locked" and session.refused():
            self._arrange("refused")                     # the directory refused the account while the lock was up

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
        self._locks += 1
        for w in (self.pw, self.unlock, self.other):
            w.setEnabled(True)
        minutes, self._idle_minutes = self._idle_minutes, None
        self.reason.setText(f"Locked after {minutes} minutes without use." if minutes else f"Locked by {user}.")
        directory_user = session.kind() == "directory"
        self.who.setText(user if directory_user else f"{user}, local account")
        self.avatar.setText("".join(w[0] for w in user.split()[:2]).upper())
        t = theme.current()
        self.setStyleSheet(f"QWidget#lockScreen, QWidget#lockCover {{ background: {t.get('bg', '#081420')}; }}")
        self.avatar.setStyleSheet(f"background: {t.get('surface2', '#12283d')}; border: 1px solid {t.get('edge', '#3d5a76')}; "
                                  f"border-radius: 22px; color: {t.get('accent_ink', '#22d3ee')}; font-weight: 600;")
        say(self.error, "")
        self.discard.hide()
        self.pw.setText("")
        self._arrange("refused" if session.refused() else "directory" if directory_user else "local")
        self.locked = True
        self._cover_all()

    def _arrange(self, mode):
        """What the screen shows: "local" (password), "directory" (PIN), "again" (the session is over and the directory is
        reachable: sign in in full) or "refused" (only the sentence and the way out)."""
        full = mode in ("local", "directory")
        self.head.setText(LOCKED)                        # (not "Touch your security key" left from a wait this ends)
        label = "PIN" if mode == "directory" else "Password"
        self.pw.setPlaceholderText(label)
        self.pw.setAccessibleName(label)
        self.wait.error = pinslot.PinLocked if mode == "directory" else datakey.Throttled
        for w in (self.avatar, self.head, self.who, self.pw, self.unlock):
            w.setVisible(full)
        self.again.setVisible(mode == "again")
        self.other.setVisible(mode != "again")
        if not full:
            self.discard.hide()
            self.wait.timer.stop()                       # (a PIN countdown doesn't go on over these screens)
            say(self.error, "")
            self.pw.setText("")
            self.reason.setText(dirsignin.refused_text() if mode == "refused" else "Please sign in again.")

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
            handle = w.windowHandle()
            if handle is not None and handle.flags() & Qt.WindowType.WindowStaysOnTopHint:
                handle.setFlags(handle.flags() & ~Qt.WindowType.WindowStaysOnTopHint)   # (native flags: the widget isn't hidden)
                self._on_top.append(w)
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
        self.pw.setText("")
        say(self.error, "")
        self.discard.hide()
        self.hide()
        for cover in self.covers.values():
            cover.hide()
            cover.deleteLater()
        for w in self._on_top:
            try:
                w.windowHandle().setFlags(w.windowHandle().flags() | Qt.WindowType.WindowStaysOnTopHint)
            except (RuntimeError, AttributeError):
                pass                                     # closed meanwhile
        self.covers, self._on_top = {}, []

    def ask_unlock(self, reason, pending=False):
        say(self.error, f"Unlock to close Toner: {reason}")
        self.discard.setVisible(pending)

    def release(self):
        """Toner is closing: the lock and its covers go, so it isn't the last window left."""
        self._end_jobs()
        self._uncover()
        self.close()

    def _unlock(self):
        pw = self.pw.text()
        self.pw.setText("")
        if session.kind() == "directory":
            return self._unlock_pin(pw)
        self._try(session.unlock, pw)

    def _unlock_pin(self, pin):
        """After the session a reachable directory means a full sign-in, so the PIN isn't tried (and not counted); the
        probe runs on a Job, with the field off meanwhile."""
        if not session.session_over():
            return self._try(session.unlock_pin, pin)
        name, turn = session.user(), self._locks

        def probe():
            """Fails closed: a changed directories list or a missing config counts as reachable, so the full sign-in (which
            pauses with its own words) decides."""
            rec = datakey.directory_account(name)
            dirs = datakey.read().get("directories") or []
            cfg = next((d for d in dirs if d.get("id") == (rec or {}).get("directory")), None)
            return cfg is None or dirpin.changed(dirs) or dirsignin.reachable(cfg)     # (SSO: the provider)

        def landed(job, up, _error):                     # (an error: no config to probe, so not reachable)
            job.wait()
            job.fn = None
            self._jobs.discard(job)
            if turn != self._locks or session.state() != "locked":
                return                                   # a later lock (or none) owns the screen now
            for w in (self.pw, self.unlock, self.other):
                w.setEnabled(True)
            if session.refused():
                self._arrange("refused")
            elif up is True:
                self._arrange("again")
            else:
                self._try(session.unlock_pin, pin)
        job = Job(probe)
        job.ask = None
        job.done.connect(landed, Qt.ConnectionType.QueuedConnection)
        for w in (self.pw, self.unlock, self.other):
            w.setEnabled(False)
        self._jobs.add(job)
        job.start()

    def _try(self, unlock, secret):
        """The unlock on a Job, the field off meanwhile: a keyed account's touch waits there (Sign in as someone else stays on)."""
        turn, ask = self._locks, self.keyask.arm()

        def landed(job, _r, e):
            job.wait()
            job.fn = None
            self._jobs.discard(job)
            if self.head.text() == KEY_TITLE:
                self.head.setText(LOCKED)
                self.reason.setText(self._reason)
            for w in (self.pw, self.unlock, self.other):
                w.setEnabled(True)
            self.pw.setFocus()                           # (turning the field off moved the focus away)
            if e is None or turn != self._locks or session.state() != "locked":
                return                                   # open: follow() uncovers (changed); or signed out, or a later lock
            try:
                raise e
            except (datakey.Throttled, pinslot.PinLocked) as e:
                self.wait.start(e.seconds)
            except (datakey.WrongPassword, pinslot.WrongPin) as e:
                say(self.error, str(e))
            except session.Refused:
                self._arrange("refused")
            except RuntimeError:
                self.follow()                            # unlocked already (from elsewhere)
            except fidokey.NotTouched:
                say(self.error, NOT_TOUCHED)
            except fidokey.Failed as e:
                say(self.error, e.text)
            except DAMAGED_ERRORS:
                say(self.error, DAMAGED)
        job = Job(lambda: unlock(secret, present=self.keyask.present))
        job.ask = ask
        job.done.connect(landed, Qt.ConnectionType.QueuedConnection)
        for w in (self.pw, self.unlock, self.other):
            w.setEnabled(False)
        self._jobs.add(job)
        job.start()

    def _touching(self):
        """The password or PIN was right and the account has keys: say to touch one; the way out stays open meanwhile."""
        if not any(j.ask is not None and j.ask.asked and not j.ask.cancel.is_set() for j in self._jobs):
            return                                       # (a wait already cancelled)
        self._reason = self.reason.text()
        self.head.setText(KEY_TITLE)
        self.reason.setText(KEY_TEXT)
        self.other.setEnabled(True)

    def _end_jobs(self):
        """Release a key's wait, then let every Job end (one must not outlive the window, as SignInWindow._stop)."""
        self.keyask.cancel()
        for j in list(self._jobs):
            j.wait()

    def _sign_out(self):
        """Sign in as someone else: Main's closing questions (unsaved settings, a running playbook) must be answerable, so the
        lock steps aside for them, the windows staying covered; if one is refused, the lock comes back."""
        self._end_jobs()
        self._passing = True
        self.pw.setText("")
        self.hide()
        try:
            self.main.sign_out()
        finally:
            self._passing = False
        if session.state() == "locked":
            self._cover_all()
