"""Settings page: notification channels."""

import threading
from datetime import datetime, timedelta

from PySide6.QtCore import QObject, QSize, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout,
                               QHBoxLayout, QLabel, QLineEdit, QMenu, QMessageBox, QPushButton, QSpinBox, QTableWidget,
                               QTableWidgetItem, QToolButton, QVBoxLayout, QWidget)
from core import alerts, audit, db, mailauth, notify, oidc, passvault, quiet
from core.dirsignin import SSO_TEXT, sso_said
from ui.brandicons import channel_icon
from ui.settings_base import Page, note, row_of, spin
from ui.toast import toast
from ui.widgets import EmptyHint, filling

# An Email channel's fields for each way of signing in (the others are hidden), and the help shown under the form
METHOD_FIELDS = mailauth.METHOD_FIELDS
METHOD_HELP = {
    "ms_account": "In the Entra admin center, register an app for Toner as a public client (mobile and desktop) with the redirect URI "
                  "http://localhost and the delegated permission SMTP.Send. Turn on authenticated SMTP for the mailbox, then sign in "
                  "here as that mailbox.",
    "ms_app": "Register an app with the application permission SMTP.SendAsApp, admin consent and a client secret. Register it in "
              "Exchange Online and give it access to the mailbox. Nobody signs in.",
    "google_account": "In Google Cloud, create an OAuth client of type Desktop app in a project set to Internal, then sign in here as "
                      "the mailbox."}
SIGN_IN, SIGN_IN_AGAIN, NOT_SIGNED_IN, SIGNED_IN_AS = "Sign in", "Sign in again", "Not signed in.", "Signed in as {account}."
SAVED = "saved in the vault - leave blank to keep it"


class _Relay(QObject):
    """Hands a worker's result to the window's thread (as ui/notifier.py does)."""
    done = Signal(object, object, object)


def _run(fn, landed, tag=None):
    """fn on a daemon thread; landed(job, result, error) back on the window's thread, unless the window that asked is gone by then.
    Nothing ever waits for it: closing its window is immediate, and quitting Toner with one still running just ends it (a QThread
    still running at quit aborts the process)."""
    job = _Relay(QApplication.instance())
    job.tag = tag
    job.done.connect(landed, Qt.ConnectionType.QueuedConnection)
    job.done.connect(job.deleteLater, Qt.ConnectionType.QueuedConnection)

    def work():
        try:
            result, error = fn(), None
        except Exception as e:                       # noqa: BLE001  (the window says what it can, or raises it there)
            result, error = None, e
        try:
            job.done.emit(job, result, error)
        except RuntimeError:                         # the application, and the relay with it, has gone
            quiet.ignored()
    threading.Thread(target=work, daemon=True).start()


class _Attempt:
    """One browser sign-in from the form, kept in the vault under a draft name of its own (<channel id>.form<n>) until Save.
    Whichever learns last that it is not wanted removes what it stored: the worker when it finishes after a Cancel (the provider
    can keep it busy for many seconds, deaf to Cancel), or the window when it is cancelled, edited away or closed."""

    def __init__(self, cid, n):
        self.id, self.cancel, self.lock, self.stored = f"{cid}.form{n}", threading.Event(), threading.Lock(), False

    def finished(self):                              # the worker, once the sign-in returned or failed
        with self.lock:
            self.stored = True
            if self.cancel.is_set():
                self._remove()

    def drop(self):                                  # the window
        with self.lock:
            self.cancel.set()
            if self.stored:
                self._remove()

    def _remove(self):
        self.stored = False
        try:
            passvault.remove(mailauth.PREFIX + self.id)
        except Exception:
            quiet.ignored()


_KEYRING = (lambda n: notify.keyring.get_password(db.SERVICE, n), lambda n, v: notify.keyring.set_password(db.SERVICE, n, v),
            lambda n: notify.keyring.delete_password(db.SERVICE, n))
_VAULT = (lambda n: passvault.get(n), lambda n, v: passvault.put(n, v), lambda n: passvault.remove(n))


def _apply(changes, then):
    """changes: [(store, name, value)], None removing it; then then(). All or none: a failure puts back what was changed and raises."""
    done = []
    try:
        for store, name, value in changes:
            get, put, remove = store
            old = get(name)
            if value is None and old is None:
                continue
            put(name, value) if value is not None else remove(name)
            done.append((store, name, old))
        then()
    except Exception:
        for (_get, put, remove), name, old in reversed(done):
            try:
                put(name, old) if old is not None else remove(name)
            except Exception:
                quiet.ignored()
        raise


# ------------------------------------------------------------------ Notifications
class ChannelDialog(QDialog):
    """Add or edit one notification channel. Its fields come from notify.CHANNEL_TYPES.

    Save writes the channel through self.commit (set by the page) and its secrets, all or none. An Email channel's sign-in made
    here stays a draft (_Attempt) until then; Cancel removes it, so the channel's earlier sign-in is untouched."""
    popup = Signal(str, str)                # a desktop channel's test pop-up, from the worker to the window's thread

    def __init__(self, ch, desktop_cb, parent=None):
        super().__init__(parent)
        self.ch, self.desktop_cb = dict(ch), desktop_cb
        self.result_ch, self.typed_secrets, self.commit = None, {}, None
        self._closed, self.running, self.kept, self._attempts = False, None, None, []
        # destroyed without done() (its page went away): a sign-in still running cleans up after itself
        self.destroyed.connect(lambda *_, a=self._attempts: [x.drop() for x in a])
        signed = ch["type"] == "email" and mailauth.needs_sign_in(ch.get("auth")) and mailauth.signed_in_as(ch)
        self.sign_id, self.account = (ch["id"], signed) if signed else (None, None)
        if desktop_cb:
            self.popup.connect(desktop_cb)
        spec = notify.CHANNEL_TYPES[ch["type"]]
        self.setWindowTitle(f"{spec['label']} channel")
        self.setWindowIcon(channel_icon(ch["type"]))
        self.setMinimumWidth(500)
        self.stored = notify.get_secrets(ch)

        self.name = QLineEdit(ch["name"])
        self.enabled = QCheckBox("Enabled")
        self.enabled.setChecked(ch.get("enabled", True))
        self.min = QComboBox()
        self.min.addItems(list(notify.MIN_LEVELS))
        self.min.setCurrentText(ch.get("min", "WARN and worse"))
        self.recoveries = QCheckBox("Also tell me when a problem recovers")
        self.recoveries.setChecked(ch.get("recoveries", True))
        form = QFormLayout()
        form.addRow("Name", self.name)
        form.addRow("", self.enabled)
        form.addRow("Send", self.min)
        form.addRow("", self.recoveries)

        self.inputs = {}
        for key, label, kind, extra in spec["fields"]:
            if kind == "int":
                w = QSpinBox()
                w.setRange(*extra.get("range", (0, 1_000_000)))
                w.setValue(int(ch.get(key) or extra.get("default", 0)))
            elif kind == "choice":
                w = QComboBox()
                for c in extra["choices"]:
                    w.addItem(extra.get("labels", {}).get(c, c), c)
                w.setCurrentIndex(max(0, w.findData(ch.get(key) or extra.get("default", extra["choices"][0]))))
            else:
                w = QLineEdit(str(ch.get(key, "")) if kind == "text" else "")
                w.setPlaceholderText(extra.get("placeholder", ""))
                if kind == "secret":
                    w.setEchoMode(QLineEdit.EchoMode.Password)
                    if self.stored.get(key):
                        w.setPlaceholderText(SAVED)
            self.inputs[key] = (kind, w)
            form.addRow(label, w)
        self.form = form

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        self.test_btn = buttons.addButton("Send test", QDialogButtonBox.ButtonRole.ActionRole)
        self.test_btn.clicked.connect(self.test)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(note(spec["help"]))
        lay.addLayout(form)
        if "auth" in self.inputs:
            self._email_form(lay)
        lay.addWidget(buttons)
        self._fit()

    def _fit(self):
        """As tall as the form needs at this width: Qt sizes a window with wrapping text by its minimum, which squeezes the rows
        (the Sign in button lost its bottom edge)."""
        if self.layout():
            w = max(self.width(), self.minimumWidth()) if self.isVisible() else self.minimumWidth()
            h = self.layout().totalHeightForWidth(w)
            if h < self.height():
                self.layout().activate()     # the window's minimum is still the old layout's, and would stop it getting smaller
            self.resize(w, h)

    # ---------- an Email channel's way of signing in
    def _email_form(self, lay):
        self.sign_btn, self.sign_status = QPushButton(), QLabel()
        self.sign_status.setWordWrap(True)
        self.sign_btn.clicked.connect(self.sign_in)
        self.sign_row = row_of(self.sign_btn, self.sign_status)
        self.sign_row.layout().setStretch(1, 1)                  # the button at its own width, the status wraps in the rest
        self.form.insertRow(self.form.getWidgetPosition(self.inputs["password"][1])[0] + 1, "", self.sign_row)
        self.method_help = note("")
        lay.addWidget(self.method_help)
        self._user_hint = self.inputs["username"][1].placeholderText()
        self._secret_hint = {f[0]: f[3] for f in notify.CHANNEL_TYPES["email"]["fields"]}["client_secret"]["placeholder"]
        self.inputs["auth"][1].currentIndexChanged.connect(self._method)
        for key in ("auth", "tenant", "client_id", "client_secret", "username"):
            w = self.inputs[key][1]
            (w.currentIndexChanged if key == "auth" else w.textChanged).connect(self._drop)
        self._method()
        self._say()

    def _method(self):
        auth = self.inputs["auth"][1].currentData()
        self.layout().setEnabled(False)      # one change of size: row by row, Qt grows a shown window to every in-between minimum
        for key in ("tenant", "client_id", "client_secret", "username", "password"):
            self.form.setRowVisible(self.inputs[key][1], key in METHOD_FIELDS[auth])
        self.form.setRowVisible(self.sign_row, mailauth.needs_sign_in(auth))
        self.method_help.setText(METHOD_HELP.get(auth, ""))
        self.method_help.setVisible(auth in METHOD_HELP)
        self.inputs["username"][1].setPlaceholderText(self._user_hint if auth == "password" else "")
        self.inputs["client_secret"][1].setPlaceholderText(     # Google's app may have none; Microsoft's must
            SAVED if self.stored.get("client_secret") else self._secret_hint if auth == "google_account" else "")
        self.layout().setEnabled(True)
        self._fit()

    def _say(self, text=None):
        self.sign_btn.setText("Cancel" if self.running else SIGN_IN_AGAIN if self.sign_id else SIGN_IN)
        self.sign_status.setText(text or (SIGNED_IN_AS.format(account=self.account) if self.sign_id else NOT_SIGNED_IN))
        self._fit()

    def _drop(self, *_):
        """The method, tenant, client ID, client secret or username changed: a sign-in made for the old ones is not used."""
        for a in (self.running, self.kept):
            if a:
                a.drop()
        self.running = self.kept = self.sign_id = self.account = None
        self._say()

    def sign_in(self):
        """The browser sign-in, on a worker; while it waits the button is Cancel, which lets it go at once."""
        if self.running:
            self.running.drop()
            self.running = None
            return self._say()
        ch, _typed, merged = self.collect()
        missing = [f"{label} is required." for key, label in (("tenant", "Tenant ID"), ("client_id", "Client ID"))
                   if not ch[key] and (key == "client_id" or ch["auth"].startswith("ms_"))]
        if missing:
            return self._warn(missing)
        a = self.running = _Attempt(self.ch["id"], len(self._attempts) + 1)
        self._attempts.append(a)
        ch = dict(ch, id=a.id)

        def work():
            try:
                return mailauth.sign_in(ch, merged, a.cancel)
            finally:
                a.finished()
        self._say(SSO_TEXT.format(provider=mailauth.provider(ch["auth"])))
        _run(work, self._signed, tag=a)

    def _signed(self, job, account, error):
        a = job.tag
        if a is not self.running:                            # let go meanwhile: it removed what it stored itself
            return
        self.running = None
        if error is None:
            if self.kept:
                self.kept.drop()
            self.kept, self.sign_id, self.account = a, a.id, account
            return self._say()
        a.drop()
        self._say()
        self._say(self._failed(error, mailauth.provider(self.inputs["auth"][1].currentData())))

    @staticmethod
    def _failed(e, prov):
        """A failed sign-in in the approved words; an oidc error's own text names the provider's host, so is never shown."""
        if isinstance(e, (mailauth.MailAuthError, passvault.Locked)):
            return str(e)
        if isinstance(e, (oidc.Cancelled, oidc.Refused)):  # the person didn't finish, or said no
            return sso_said({"name": prov}, e)
        if isinstance(e, oidc.OidcError):                   # unreachable, or the app's setup (invalid_client, a wrong tenant)
            return mailauth.said(prov, e)
        raise e

    def _as_signed(self, ch):
        """The channel with the form's sign-in (its own, the draft made here, or none), for the checks and Send test."""
        if not mailauth.needs_sign_in(ch.get("auth")):
            return ch
        if self.kept:
            return dict(ch, id=self.kept.id, draft=True)
        return dict(ch, id=self.sign_id or self.ch["id"] + ".form")      # (a name that never holds a sign-in)

    def done(self, r):
        """Never waits: a sign-in still running is let go and removes what it stores itself. Save has already moved its draft."""
        self._closed = True
        for a in (self.running, self.kept):
            if a:
                a.drop()
        self.running = self.kept = None
        super().done(r)

    def collect(self):
        ch = dict(self.ch, name=self.name.text().strip(), enabled=self.enabled.isChecked(),
                  min=self.min.currentText(), recoveries=self.recoveries.isChecked())
        typed = {}
        for key, (kind, w) in self.inputs.items():
            if kind == "secret":
                typed[key] = w.text().strip()
            elif kind == "int":
                ch[key] = w.value()
            elif kind == "choice":
                ch[key] = w.currentData()
            else:
                ch[key] = w.text().strip()
        merged = {**self.stored, **{k: v for k, v in typed.items() if v}}      # blank = keep what is stored
        return ch, typed, merged

    def _checked(self):
        ch, typed, merged = self.collect()
        problems = notify.validate(self._as_signed(ch), merged)
        if problems:
            self._warn(problems)
            return None
        return ch, typed, merged

    def _warn(self, problems):
        QMessageBox.warning(self, "Check the settings", "\n".join(f"\u2022 {p}" for p in problems))

    def accept(self):
        got = self._checked()
        if not got:
            return
        if self.commit:
            try:
                self._save(got[0], got[1])
            except passvault.Locked as e:                   # nothing was saved; the dialog stays open
                return self._warn([str(e)])
        self.result_ch, self.typed_secrets = got[0], got[1]
        super().accept()

    def _save(self, ch, typed):
        """The secrets typed, those the method doesn't use removed, the sign-in made here made the channel's (or one the form
        dropped removed), then the channel itself: all or none."""
        used = METHOD_FIELDS[ch["auth"]] if ch["type"] == "email" else None
        keep, changes = notify.used_elsewhere(ch["id"]), []         # what a copy of this channel in another list still uses
        for key, (kind, _w) in self.inputs.items():
            if kind == "secret" and (used is None or key in used):
                if typed.get(key):
                    changes.append((_KEYRING, notify._secret_name(ch["id"], key), typed[key]))
            elif kind == "secret" and key not in keep:
                changes.append((_KEYRING, notify._secret_name(ch["id"], key), None))
        own, old = mailauth.PREFIX + ch["id"], None
        if self.kept:
            changes += [(_VAULT, own, passvault.get(mailauth.PREFIX + self.kept.id)), (_VAULT, mailauth.PREFIX + self.kept.id, None)]
        elif self.sign_id is None and mailauth.needs_sign_in(self.ch.get("auth")) and "sign-in" not in keep:
            old = mailauth.signed_in_as(self.ch)
            changes.append((_VAULT, own, None))
        _apply(changes, lambda: self.commit(ch))
        if self.kept:
            self.kept.stored = False                         # moved: nothing of the draft is left
        if old:
            audit.log("email sign-in removed", f"{self.ch['name']}, {mailauth.provider(self.ch.get('auth'))}, {old}")

    def test(self):
        got = self._checked()
        if not got:
            return
        ch, _typed, merged = got
        ch, popup = self._as_signed(ch), self.popup.emit if self.desktop_cb else None
        self.test_btn.setEnabled(False)
        _run(lambda: notify.send_test(ch, merged, popup), self._tested, tag=self.kept)

    def _tested(self, job, result, error):
        if self._closed:
            return
        self.test_btn.setEnabled(True)
        if error is not None:
            raise error
        ok, detail = result
        a = job.tag
        if not ok and a and a is self.kept and (
                detail == mailauth.GONE.format(provider=mailauth.provider(self.inputs["auth"][1].currentData()))):
            self._drop()                                     # the provider refused the sign-in made here: it is gone
            self._say(detail)
        (QMessageBox.information if ok else QMessageBox.warning)(
            self, "Test", f"Sent: {detail}" if ok else f"The test failed:\n\n{detail}")



class NotificationsPage(Page):
    title = "Notifications"
    desktop_cb = None                       # set by the main window: shows a tray pop-up
    popup = Signal(str, str)                # a desktop channel's test pop-up, from the worker to the window's thread

    def __init__(self):
        super().__init__()
        self.enabled = QCheckBox("Send notifications")
        self.consecutive = spin(1, 10, " run(s) in a row", choices=(1, 2, 3, 5))
        self.remind = spin(0, 168, " hours", choices=(0, 4, 8, 24))
        self.remind.setSpecialValueText("never")
        self.manual = QCheckBox("Also notify after runs I start by hand")
        self.snooze_label = QLabel("")
        snooze = QHBoxLayout()
        for text, hours in (("Snooze 1 hour", 1), ("4 hours", 4), ("24 hours", 24)):
            b = QPushButton(text)
            b.clicked.connect(lambda _=False, h=hours: self.snooze(h))
            snooze.addWidget(b)
        resume = QPushButton("Resume now")
        resume.clicked.connect(lambda: self.snooze(0))
        snooze.addWidget(resume)
        snooze.addStretch()
        snooze_w = QWidget()
        snooze_w.setLayout(snooze)
        snooze.setContentsMargins(0, 0, 0, 0)

        self.form.addRow("", self.enabled)
        self.form.addRow("Alert after", self.consecutive)
        self.form.addRow("Remind me every", self.remind)
        self.form.addRow("", self.manual)
        self.form.addRow("Snooze", snooze_w)
        self.form.addRow("", self.snooze_label)
        self.lay.insertWidget(1, note(
            "You are told when a check turns bad, gets worse, or recovers, not on every run. One message per "
            "run per channel. 'Alert after' waits for a problem to last several runs before telling you, "
            "which filters out one-off blips. Snooze and these buttons act immediately; the rest needs Save."))

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["On", "Name", "Type", "Sends"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setMinimumHeight(130)
        self.table.setIconSize(QSize(20, 20))
        self.table.verticalHeader().setVisible(False)             # row numbers mean nothing here
        hh = self.table.horizontalHeader()
        for col in range(3):
            hh.setSectionResizeMode(col, hh.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(3, hh.ResizeMode.Stretch)         # the last column takes the rest, so it is not cut off
        self.table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.table.doubleClicked.connect(lambda *_: self.edit())
        add = QToolButton()
        add.setText("Add channel")
        add.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(add)
        for t, spec in notify.CHANNEL_TYPES.items():
            menu.addAction(channel_icon(t), spec["label"], lambda t=t: self.add_channel(t))
        menu.setStyleSheet("QMenu::icon { padding-left: 6px; }")
        add.setMenu(menu)
        edit, remove, self.test_btn = QPushButton("Edit"), QPushButton("Remove"), QPushButton("Send test")
        edit.clicked.connect(self.edit)
        remove.clicked.connect(self.remove)
        self.test_btn.clicked.connect(self.test)
        self.popup.connect(self._popup)
        bar = QHBoxLayout()
        for w in (add, edit, remove, self.test_btn):
            bar.addWidget(w)
        bar.addStretch()
        bar_w = QWidget()
        bar_w.setLayout(bar)
        bar.setContentsMargins(0, 0, 0, 0)

        self.log = QTableWidget(0, 4)
        self.log.setHorizontalHeaderLabels(["When", "Channel", "Result", "Details"])
        self.log.horizontalHeader().setStretchLastSection(True)
        self.log.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.log.setMinimumHeight(130)
        self.log.verticalHeader().setVisible(False)
        self.log_hint = EmptyHint(self.log, "No messages sent yet", "Each alert, and each test, is listed here")
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh_log)

        self.lay.insertWidget(2, QLabel("<b>Channels</b>  (add, edit and remove take effect immediately; "
                                        "you can use as many as you like)"))
        self.lay.insertWidget(3, self.table)
        self.lay.insertWidget(4, bar_w)
        self.lay.insertWidget(5, QLabel("<b>Recent deliveries</b>"))
        self.lay.insertWidget(6, self.log)
        self.lay.insertWidget(7, refresh, 0, Qt.AlignmentFlag.AlignLeft)

    # ---------- channels ----------
    def selected_channel(self):
        rows = {i.row() for i in self.table.selectedIndexes()}
        chs = notify.channels()
        if len(rows) != 1:
            return None
        r = next(iter(rows))
        return chs[r] if 0 <= r < len(chs) else None

    def reload_channels(self):
        chs = notify.channels()
        with filling(self.table):
            self.table.setRowCount(len(chs))
            for i, c in enumerate(chs):
                sends = c.get("min", "WARN and worse") + (", recoveries" if c.get("recoveries", True) else "")
                for j, v in enumerate(("yes" if c.get("enabled", True) else "no", c["name"],
                                       notify.CHANNEL_TYPES[c["type"]]["label"], sends)):
                    item = QTableWidgetItem(v)
                    item.setToolTip(v)
                    if j == 1:                                        # the service's mark beside the channel's name (the type is plain text)
                        item.setIcon(channel_icon(c["type"]))
                    self.table.setItem(i, j, item)

    def add_channel(self, ctype):
        dlg = ChannelDialog(notify.new_channel(ctype), self.desktop_cb, self)
        dlg.commit = lambda new: notify.save_channels(notify.channels() + [new])      # Save writes it, with its secrets
        if dlg.exec():
            self.reload_channels()

    def edit(self):
        ch = self.selected_channel()
        if not ch:
            return
        dlg = ChannelDialog(ch, self.desktop_cb, self)
        dlg.commit = lambda new: notify.save_channels([new if c["id"] == ch["id"] else c for c in notify.channels()])
        if dlg.exec():
            self.reload_channels()

    def remove(self):
        ch = self.selected_channel()
        if ch and QMessageBox.question(self, "Remove channel", f"Remove '{ch['name']}'?\n\nIts saved "
                                       "webhook URL, password or sign-in is deleted too.") == QMessageBox.StandardButton.Yes:
            notify.delete_secrets(ch, notify.used_elsewhere(ch["id"]))
            notify.save_channels([c for c in notify.channels() if c["id"] != ch["id"]])
            self.reload_channels()

    def test(self):
        ch = self.selected_channel()
        if not ch:
            toast(self, "Select a channel first.")
            return
        self.test_btn.setEnabled(False)
        popup = self.popup.emit if self.desktop_cb else None
        _run(lambda: notify.send_test(ch, None, popup), self._tested)

    def _popup(self, title, body):
        self.desktop_cb(title, body)

    def _tested(self, _job, result, error):
        self.test_btn.setEnabled(True)
        if error is not None:
            raise error
        ok, detail = result
        self.refresh_log()
        if ok:
            toast(self, f"Sent: {detail}")
        else:
            QMessageBox.warning(self, "Test", f"The test failed:\n\n{detail}")

    # ---------- snooze / log ----------
    def snooze(self, hours):
        until = (datetime.now() + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S") if hours else ""
        db.set_setting("notify_snooze_until", until)
        self.show_snooze()

    def show_snooze(self):
        self.snooze_label.setText(f"Snoozed until {db.get_setting('notify_snooze_until')[11:16]}. "
                                  "Nothing is sent, and changes are caught up when it ends."
                                  if notify.snoozed() else "Not snoozed.")

    def refresh_log(self):
        rows = alerts.recent_deliveries()
        self.log.setRowCount(len(rows))
        self.log_hint.setVisible(not rows)
        for i, r in enumerate(rows):
            for j, v in enumerate((r["at"], r["channel"], "sent" if r["ok"] else "FAILED", r["detail"] or "")):
                it = QTableWidgetItem(v)
                if not r["ok"]:
                    it.setForeground(QColor("#d32f2f"))
                self.log.setItem(i, j, it)
        self.log.resizeColumnsToContents()

    def refresh(self):
        self.reload_channels()
        self.refresh_log()
        self.show_snooze()

    def load(self):
        self.enabled.setChecked(bool(db.get_setting("notify_enabled")))
        self.consecutive.setValue(int(db.get_setting("notify_consecutive")))
        self.remind.setValue(int(db.get_setting("notify_remind_hours")))
        self.manual.setChecked(bool(db.get_setting("notify_on_manual")))
        self.refresh()

    def save(self):
        db.set_setting("notify_enabled", self.enabled.isChecked())
        db.set_setting("notify_consecutive", self.consecutive.value())
        db.set_setting("notify_remind_hours", self.remind.value())
        db.set_setting("notify_on_manual", self.manual.isChecked())
