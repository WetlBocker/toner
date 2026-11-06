"""Test login (Settings > Accounts > External Identities, right-click; Admins only): one directory user's password and, when the
directory has Duo on, the real Duo step, through dirsignin.TestLogin. Nothing is kept: no session, key, PIN slot or account change
in this process. The password and code boxes are emptied at the click and on close. Each step runs on a Job; a result that lands
after Cancel, a code instead, close or a newer Test is dropped, and an exception is dropped once its sentence is shown."""
import threading

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QStackedWidget, QVBoxLayout, QWidget

from core import datakey, directory, dirsignin, perms
from ui.signinwindow import (DAMAGED, DAMAGED_ERRORS, DUO_TEXT, DUO_TITLE, SAID, Job, Wait, field, heading, link, primary, say,
                             words)


class TestLoginDialog(QDialog):
    """Test one person against `cfg`, an entry of roles.verified()'s list."""

    def __init__(self, cfg, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Test login")
        self.setMinimumWidth(360)
        self.cfg, self.test, self._cancel, self._turn, self._jobs = cfg, None, None, 0, set()
        self.pages = QStackedWidget()

        self.form_page, lay = self._page()
        self.user, self.pw = field(lay, "Username"), field(lay, "Password", secret=True)
        self.result, self.test_btn = words(), primary("Test")
        self.result.hide()
        lay.addWidget(self.result)
        self._finish(lay, self.test_btn, self._test)
        self.pw.returnPressed.connect(self.test_btn.click)
        self.user.returnPressed.connect(self.pw.setFocus)
        self.wait = Wait(self.result, self.test_btn)

        self.push_page, lay = self._page()
        lay.addWidget(heading(DUO_TITLE))
        lay.addWidget(words(DUO_TEXT))
        self.duo_cancel, self.use_code = primary("Cancel"), link("Enter a code instead")
        self._finish(lay, self.duo_cancel, self._duo_cancel, self.use_code)
        self.use_code.clicked.connect(self._use_code)

        self.code_page, lay = self._page()
        self.code, self.code_ok = field(lay, "Duo code"), primary("Sign in")
        self._finish(lay, self.code_ok, self._duo_code)
        self.code.returnPressed.connect(self.code_ok.click)

        QVBoxLayout(self).addWidget(self.pages)
        self._go(self.form_page, self.user)

    def _page(self):
        page = QWidget()
        lay = QVBoxLayout(page)
        self.pages.addWidget(page)
        return page, lay

    @staticmethod
    def _finish(lay, button, action, *links):
        lay.addSpacing(10)
        lay.addWidget(button)
        for b in links:
            lay.addWidget(b, 0, Qt.AlignmentFlag.AlignLeft)
        lay.addStretch(1)
        button.clicked.connect(action)

    def _go(self, page, focus):
        for box in (self.pw, self.code):                # no password or code outlives its page
            box.clear()
        self.pages.setCurrentWidget(page)
        focus.setFocus()

    # ---------------------------------------------------------------- the steps
    def _test(self):
        login, box = self.user.text().strip(), [self.pw.text()]     # (popped on the Job: no frame keeps the password)
        self.pw.clear()
        say(self.result, "")
        self._turn += 1
        t = self.test = dirsignin.TestLogin(self.cfg)               # a fresh one each time: any failure ends a TestLogin

        def landed(_r, e):
            if e is None and t.stage == "duo":
                self._go(self.push_page, self.duo_cancel)
                return self._push()
            self._end(e)
        self._run(lambda: t.check_password(login, box.pop()), landed)

    def _push(self):
        t, cancel = self.test, threading.Event()
        self._cancel = cancel

        def landed(_r, e):
            if not cancel.is_set():                     # (a code instead came first: what the push says is dropped)
                self._end(e)
        self._run(lambda: t.duo_push(cancel), landed, block=False)

    def _use_code(self):
        self._cancel.set()
        self._go(self.code_page, self.code)

    def _duo_cancel(self):
        self._drop()
        self._go(self.form_page, self.user)

    def _duo_code(self):
        t, box = self.test, [self.code.text()]
        self.code.clear()

        def enter():
            try:
                t.duo_code(box.pop())
            except RuntimeError:
                if t.stage == "duo":
                    raise                               # (else the push ended the test just before it stopped: that stands)
        self._run(enter, lambda _r, e: self._end(e))

    def _end(self, e=None):
        """The first page with the test's sentence, or e's; the test is let go."""
        t, self.test, self._cancel = self.test, None, None
        self._go(self.form_page, self.pw)
        if e is None:
            return say(self.result, t.result)
        if isinstance(e, datakey.Throttled):
            self.wait.start(e.seconds)
        elif isinstance(e, directory.Unreachable):
            say(self.result, dirsignin.UNREACHABLE)
        elif isinstance(e, (*SAID, perms.Denied)):
            say(self.result, str(e))
        elif isinstance(e, DAMAGED_ERRORS):
            say(self.result, DAMAGED)
        else:
            raise e

    def _drop(self):
        """Forget the test: a running push stops, and any step still running lands on nothing."""
        self._turn += 1
        if self._cancel is not None:
            self._cancel.set()
        self.test = self._cancel = None

    # ---------------------------------------------------------------- Jobs
    def _run(self, fn, landed, block=True):
        """`fn` on a Job; `landed(result, error)` back here unless the test changed meanwhile. `block`: the page is off while it
        runs (the push leaves its page on, for Cancel and Enter a code instead)."""
        job = Job(fn)
        job.landed, job.turn, job.page = landed, self._turn, self.pages.currentWidget() if block else None
        if job.page is not None:
            job.page.setEnabled(False)
        job.done.connect(self._landed, Qt.ConnectionType.QueuedConnection)
        self._jobs.add(job)
        job.start()

    def _landed(self, job, result, error):
        job.wait()                                      # run() has emitted its last line: this returns at once
        landed, job.fn, job.landed = job.landed, None, None
        self._jobs.discard(job)
        if job.page is not None:
            job.page.setEnabled(True)
        if job.turn == self._turn:
            landed(result, error)

    def done(self, r):
        """Closing: the push stops and every step ends first (a Job must not outlive its window), and the boxes are emptied."""
        self._drop()
        for job in list(self._jobs):
            job.wait()
        self._jobs.clear()
        self.pw.clear()
        self.code.clear()
        super().done(r)
