"""Security keys... in the menu under your name: the signed-in account's own keys (core/datakey.py), with Add a key... and Remove.
Adding asks for the password (an AD or LDAP account: its Toner PIN) and proves it first, so a typo is caught before the touch; then
a touch on the new key (ui/keyask.py, on a Job), then its name. Removing asks for the password or PIN, then to confirm. Cancel,
closing the dialog, or the session locking or signing out releases the key's wait and drops what was typed and touched: nothing is
added. A key registered but never added leaves nothing in Toner (and on the key, a non-resident credential that takes no slot).

must_add (app.py, before the main window): keys are required and the account has none. It says why; closing it signs out."""
import atexit
import os
from datetime import datetime

from PySide6.QtCore import QEventLoop, Qt, QTimer, Signal
from PySide6.QtWidgets import (QAbstractItemView, QDialog, QHBoxLayout, QLineEdit, QMessageBox, QPushButton, QStackedWidget,
                               QTableWidget, QTableWidgetItem, QVBoxLayout)

from core import datakey, dirsignin, fidokey, pinslot, roles, session
from ui.keyask import KeyAsk
from ui.lockscreen import NOT_TOUCHED
from ui.signinwindow import (DAMAGED, DAMAGED_ERRORS, KEY_PIN_TEXT, KEY_PIN_TITLE, KEY_TEXT, Job, Wait, card, centred, error_label,
                             heading, primary, say, words)
from ui.widgets import while_alive

TITLE = "Security keys"
EMPTY = {"local": "No security keys. Add one to need it, with your password, every time you sign in.",
         "directory": "No security keys. Add one to need it, with your PIN, every time you sign in."}
ASK = {"local": "Enter your password", "directory": "Enter your PIN"}
TOUCH = "Touch the key you want to add"
NAME, NAME_HINT = "Name this key", "for example, Blue YubiKey on my keyring"
FIRST = ("From now on, signing in needs this key. Add a second key and keep it somewhere safe: if you lose your only key, an admin "
         "has to reset your account.")
ONLY_ADMIN = "You are the only admin. If you lose your only key, the recovery key is the only way back in."
REMOVE = "Remove {name}? You won't be able to sign in with it."
LAST = {"local": "This is your last key. Your account will sign in with its password alone.",
        "directory": "This is your last key. Your account will sign in without one."}
REQUIRED = "An admin requires a security key. Add another key before removing this one."
SENT = "An admin requires a security key. Add one to continue."


def offered():
    """Security keys... is in the menu under your name: a local, AD or LDAP account; never SSO, nor the recovery key."""
    me = session.user()
    return session.kind() in ("local", "directory") and any(
        a["name"] == me and a.get("directory_kind") != "oidc" for a in datakey.accounts())


def must_add():
    """roles.must_add_key() off the window's thread (it may wait on the service manager), once keys are required at all."""
    if not roles.require_keys():
        return False
    loop, out, job = QEventLoop(), [], Job(roles.must_add_key)
    job.done.connect(lambda _j, r, e: (out.append((r, e)), loop.quit()), Qt.ConnectionType.QueuedConnection)
    job.start()
    loop.exec()
    job.wait()
    if out[0][1] is not None:
        raise out[0][1]
    return out[0][0]


_left = set()      # Jobs still running when their dialog closed: kept until each ends (a QThread destroyed while it runs aborts Toner)
_sweeper = None


def _keep(job):
    """Closing never waits on a Job (keys_allowed can take 20 s): it lands on nothing and is let go once it has ended."""
    global _sweeper
    job.landed = job.page = None
    _left.add(job)
    if _sweeper is None:
        _sweeper = QTimer()
        _sweeper.setInterval(200)
        _sweeper.timeout.connect(_sweep)
        atexit.register(_finish)
    _sweeper.start()


def _sweep():
    for job in [j for j in _left if j.isFinished()]:
        job.wait()
        job.fn = None                                    # (its closure holds the password or PIN)
        _left.discard(job)
    if not _left:
        _sweeper.stop()


def _finish():
    """Toner is exiting: the Jobs still running end first (their key waits were released when their dialog closed)."""
    for job in list(_left):
        job.wait()
    _left.clear()


def confirm(parent, text, more=""):
    box = QMessageBox(QMessageBox.Icon.Question, TITLE, text, parent=parent)
    box.setInformativeText(more)
    go = box.addButton("Remove", QMessageBox.ButtonRole.AcceptRole)
    box.setDefaultButton(box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole))
    box.exec()
    return box.clickedButton() is go


def _added(at):
    """The day a key was added, on this computer's calendar."""
    try:
        return datetime.fromisoformat(at).astimezone().date().isoformat()
    except (TypeError, ValueError):
        return ""


class KeysDialog(QDialog):
    changed = Signal()                                   # the session changed (on any thread): followed on the window's thread

    def __init__(self, parent=None, must_add=False):
        super().__init__(parent)
        self.setWindowTitle(TITLE)
        self.setMinimumSize(520, 440)
        self.must_add, self.kind = must_add, "directory" if session.kind() == "directory" else "local"
        self._turn, self._jobs, self._secret, self._made, self._index, self._key_pins = 0, set(), None, None, None, 0
        self.pages = QStackedWidget()

        self.list_page, lay = self._page(TITLE)
        self.reason, self.note, self.empty = words(SENT), words(datakey.KEYS_HELPER_ON), words(EMPTY[self.kind])
        self.table = QTableWidget(0, 2)
        self.table.horizontalHeader().hide()
        self.table.verticalHeader().hide()
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAccessibleName(TITLE)
        self.error, self.add, self.remove = error_label(), primary("Add a key..."), QPushButton("Remove")
        row = QHBoxLayout()
        row.addWidget(self.add)
        row.addWidget(self.remove)
        for w in (self.reason, self.note, self.empty, self.table, self.error):
            lay.addWidget(w)
        lay.addSpacing(10)
        lay.addLayout(row)
        self.reason.setVisible(must_add)
        self.note.hide()
        self.add.clicked.connect(self._add)
        self.remove.clicked.connect(self._remove)
        self.table.itemSelectionChanged.connect(lambda: self.remove.setEnabled(bool(self.table.selectedItems())))

        self.secret_page, lay = self._page(ASK[self.kind])
        self.secret = self._box(lay, ASK[self.kind], secret=True)
        self.secret_error, self.secret_next, self.secret_cancel = self._buttons(lay, self.secret, "Next", self._prove)
        self.wait = Wait(self.secret_error, self.secret_next, pinslot.PinLocked if self.kind == "directory" else datakey.Throttled)

        self.touch_page, lay = self._page(TOUCH)
        lay.addWidget(words(KEY_TEXT))
        self.touch_cancel = QPushButton("Cancel")
        lay.addSpacing(10)
        lay.addWidget(self.touch_cancel)
        self.touch_cancel.clicked.connect(self._back)

        self.keypin_page, lay = self._page(KEY_PIN_TITLE)
        lay.addWidget(words(KEY_PIN_TEXT))
        self.key_pin = self._box(lay, KEY_PIN_TITLE, secret=True)
        self.key_pin_error, self.key_pin_ok, _ = self._buttons(lay, self.key_pin, "Next", self._give_key_pin)

        self.name_page, lay = self._page(NAME)
        self.key_name = self._box(lay, NAME)
        self.key_name.setPlaceholderText(NAME_HINT)
        self.key_name.setMaxLength(64)
        self.name_error, self.name_ok, self.name_cancel = self._buttons(lay, self.key_name, "OK", self._name)
        self.key_name.textChanged.connect(lambda t: self.name_ok.setEnabled(bool(t.strip())))

        self.keyask = KeyAsk(self)
        self.keyask.touching.connect(self._touching)
        self.keyask.pin_wanted.connect(self._pin_wanted)
        self.changed.connect(self._follow, Qt.ConnectionType.QueuedConnection)
        while_alive(self, session.on_change, session.off_change, lambda _state: self.changed.emit())
        centred(self.pages, QVBoxLayout(self))
        self._refresh()
        self._go(self.list_page, self.add)
        if not must_add:                                 # (must_add: app.py asked roles.must_add_key, so keys are allowed)
            self.add.setEnabled(False)
            name = session.user()
            self._run(lambda: dirsignin.keys_allowed(name), self._allowed)

    def _page(self, title):
        frame, lay = card(380)
        lay.addWidget(heading(title))
        self.pages.addWidget(frame)
        return frame, lay

    @staticmethod
    def _box(lay, text, secret=False):
        box = QLineEdit()
        if secret:
            box.setEchoMode(QLineEdit.EchoMode.Password)
        box.setAccessibleName(text)
        lay.addSpacing(6)
        lay.addWidget(box)
        return box

    def _buttons(self, lay, box, text, action):
        """The page's error, its button and Cancel (back to the list)."""
        error, ok, cancel = error_label(), primary(text), QPushButton("Cancel")
        row = QHBoxLayout()
        row.addWidget(ok)
        row.addWidget(cancel)
        lay.addWidget(error)
        lay.addSpacing(10)
        lay.addLayout(row)
        ok.clicked.connect(action)
        box.returnPressed.connect(ok.click)
        cancel.clicked.connect(self._back)
        return error, ok, cancel

    def _go(self, page, focus):
        for lab in (self.error, self.key_pin_error, self.name_error):
            say(lab, "")
        if not self.wait.timer.isActive():
            say(self.secret_error, "")
        for box in (self.secret, self.key_pin, self.key_name):    # no password, PIN or key PIN outlives its page
            box.setText("")
        self.pages.setCurrentWidget(page)
        focus.setFocus()

    def _refresh(self):
        keys = datakey.my_keys()
        self.table.setRowCount(0)
        for k in keys:
            self.table.insertRow(self.table.rowCount())
            for j, v in enumerate((k["name"], _added(k["added"]))):
                self.table.setItem(self.table.rowCount() - 1, j, QTableWidgetItem(v))
        self.empty.setVisible(not keys)
        self.table.setVisible(bool(keys))
        self.remove.setEnabled(False)

    def _allowed(self, allowed, e):
        allowed = e is None and allowed is True          # (an error: not offered, as the helper check fails closed)
        self.add.setEnabled(allowed)
        self.note.setVisible(not allowed and self.kind == "directory")

    # ---------------------------------------------------------------- Jobs
    def _run(self, fn, landed, ask=None):
        """`fn` on a Job; `landed(result, error)` back on this thread, unless the step was left meanwhile. `ask`: its keyask.arm()
        Wait, when it may ask a key or must see the step left."""
        job = Job(fn)
        job.landed, job.turn, job.page, job.ask = landed, self._turn, self.pages.currentWidget(), ask
        job.page.setEnabled(False)
        job.done.connect(self._landed, Qt.ConnectionType.QueuedConnection)
        self._jobs.add(job)
        job.start()

    def _landed(self, job, result, error):
        if job not in self._jobs:
            return                                       # handed on when the dialog closed (_keep): touches nothing here
        job.wait()
        job.fn = None                                    # (its closure holds the password or PIN)
        self._jobs.discard(job)
        job.page.setEnabled(True)
        if job.turn == self._turn:
            job.landed(result, error)

    def _drop(self):
        """Leave the step: a key's wait ends, a step still running lands on nothing, and what was typed and touched goes."""
        self._turn += 1
        self.keyask.cancel()
        self._secret = self._made = self._index = None

    def _back(self):
        self._drop()
        self._go(self.list_page, self.add)

    def _follow(self):
        if session.state() == "signed_out":
            self.reject()
        elif session.state() != "open" and self.pages.currentWidget() is not self.list_page:
            self._back()

    def _fail(self, e, label):
        if isinstance(e, (datakey.Throttled, pinslot.PinLocked)):
            if label is not self.secret_error:           # (from add_key or remove_key: the countdown is the password page's)
                self._go(self.secret_page, self.secret)
            self.wait.start(e.seconds)
        elif isinstance(e, (datakey.WrongPassword, pinslot.WrongPin, datakey.Locked)) or str(e) == datakey.KEYS_HELPER_ON:
            say(label, str(e))
        elif isinstance(e, fidokey.NotTouched):
            say(label, NOT_TOUCHED)
        elif isinstance(e, fidokey.Failed):
            say(label, e.text)
        elif isinstance(e, DAMAGED_ERRORS):
            say(label, DAMAGED)
        else:
            raise e

    # ---------------------------------------------------------------- adding and removing
    def _add(self):
        self._drop()
        self._go(self.secret_page, self.secret)

    def _remove(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        if self.table.rowCount() == 1 and roles.require_keys():
            say(self.error, REQUIRED)
            return
        self._drop()
        self._index = rows[0].row()
        self._go(self.secret_page, self.secret)

    def _prove(self):
        secret, removing = self.secret.text(), self._index is not None
        self.secret.setText("")

        def landed(_r, e):
            if e is not None:
                self.secret.setFocus()
                return self._fail(e, self.secret_error)
            if removing:
                return self._confirm(secret)
            self._secret = secret
            self._register()
        self._run(lambda: datakey.prove_mine(secret), landed)

    def _register(self):
        name = session.user()

        def landed(made, e):
            if e is not None:
                self._secret = None                      # back to the password: asked again, as at sign-in
                self._go(self.secret_page, self.secret)
                return self._fail(e, self.secret_error)
            self._made = made
            self._go(self.name_page, self.key_name)
            self.name_ok.setEnabled(False)
        ask = self.keyask                                # (not self: the Job may outlive this dialog)
        self._run(lambda: ask.register(name, os.urandom(32)), landed, ask=ask.arm())

    def _asking(self):
        """A key is being asked for the step on screen (a signal from a wait already cancelled lands on nothing)."""
        return any(j.turn == self._turn and j.ask is not None and j.ask.asked and not j.ask.cancel.is_set() for j in self._jobs)

    def _touching(self):
        if self._asking():
            self._key_pins = 0
            self._go(self.touch_page, self.touch_cancel)

    def _pin_wanted(self):
        if self._asking():
            self._go(self.keypin_page, self.key_pin)
            if self._key_pins:                           # asked again: the PIN given was wrong
                say(self.key_pin_error, fidokey.WrongKeyPin.text)

    def _give_key_pin(self):
        pin = self.key_pin.text()
        self.key_pin.setText("")
        self._key_pins += 1
        self._go(self.touch_page, self.touch_cancel)
        self.keyask.give_pin(pin)

    def _name(self):
        label = self.key_name.text().strip()
        if not label or self._made is None:
            return
        (cred, value), secret, wait = self._made, self._secret, self.keyask.arm()
        self._secret = self._made = None
        first, me = not datakey.my_keys(), session.user()

        def add():
            if wait.cancel.is_set():
                raise fidokey.NotTouched()               # left (Cancel, closed, locked) before the write began: nothing added
            datakey.add_key(secret, cred, value, label)
            return first and [a["name"] for a in datakey.accounts() if a["role"] == "Admin"] == [me]

        def landed(only_admin, e):
            self._go(self.list_page, self.add)
            self._refresh()
            if e is not None:
                return self._fail(e, self.error)
            if first:
                QMessageBox.information(self, TITLE, ONLY_ADMIN if only_admin else FIRST)
            if self.must_add:
                self.accept()
        self._run(add, landed, ask=wait)

    def _confirm(self, secret):
        index, keys, turn = self._index, datakey.my_keys(), self._turn
        last = len(keys) == 1
        if index is None or index >= len(keys) or not confirm(self, REMOVE.format(name=keys[index]["name"]), LAST[self.kind] if last else ""):
            return self._back()
        if turn != self._turn:
            return                                       # left while it asked

        def landed(_r, e):
            self._go(self.list_page, self.add)
            self._refresh()
            if e is not None:
                self._index = index                      # (a countdown goes back to the password page, for this key)
                self._fail(e, self.error)
        self._run(lambda: datakey.remove_key(secret, index), landed)

    # ---------------------------------------------------------------- closing
    def done(self, r):
        """Closing: a key's wait is released and what was typed goes; a Job still running is handed on (_keep), never waited for."""
        self._drop()
        for job in self._jobs:
            _keep(job)
        self._jobs.clear()
        for box in (self.secret, self.key_pin):
            box.setText("")
        super().done(r)
