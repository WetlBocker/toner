"""Settings page: notification channels."""

import threading
from datetime import datetime, timedelta

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout,
                               QHBoxLayout, QLabel, QLineEdit, QMenu, QMessageBox, QPushButton, QSpinBox, QTableWidget,
                               QTableWidgetItem, QToolButton, QVBoxLayout, QWidget)
from core import alerts, db, mailauth, notify, oidc, passvault, quiet
from core.dirsignin import SSO_TEXT, sso_said
from ui.brandicons import channel_icon
from ui.settings_base import Page, note, row_of, spin
from ui.signinwindow import Job
from ui.toast import toast
from ui.widgets import EmptyHint, filling

# An Email channel's fields for each way of signing in (the others are hidden), and the help shown under the form
METHOD_FIELDS = {"password": {"username", "password"}, "ms_account": {"tenant", "client_id", "username"},
                 "ms_app": {"tenant", "client_id", "client_secret", "username"},
                 "google_account": {"client_id", "client_secret", "username"}}
METHOD_HELP = {
    "ms_account": "In the Entra admin center, register an app for Toner as a public client (mobile and desktop) with the redirect URI "
                  "http://localhost and the delegated permission SMTP.Send. Turn on authenticated SMTP for the mailbox, then sign in "
                  "here as that mailbox.",
    "ms_app": "Register an app with the application permission SMTP.SendAsApp, admin consent and a client secret. Register it in "
              "Exchange Online and give it access to the mailbox. Nobody signs in.",
    "google_account": "In Google Cloud, create an OAuth client of type Desktop app in a project set to Internal, then sign in here as "
                      "the mailbox."}
SIGN_IN, SIGN_IN_AGAIN, NOT_SIGNED_IN, SIGNED_IN_AS = "Sign in", "Sign in again", "Not signed in.", "Signed in as {account}."


def _run(owner, fn, landed):
    """fn on a worker; landed(result, error) back on the window's thread. owner._jobs keeps the thread alive meanwhile."""
    job = Job(fn)
    job.landed = landed
    job.done.connect(owner._landed, Qt.ConnectionType.QueuedConnection)
    owner._jobs.add(job)
    job.start()
    return job


# ------------------------------------------------------------------ Notifications
class ChannelDialog(QDialog):
    """Add or edit one notification channel. Its fields come from notify.CHANNEL_TYPES.

    An Email channel's sign-in made here is kept in the vault under a name of the dialog's own (self.draft) until Save, when
    keep_sign_in() makes it the channel's; Cancel removes it, so the channel's earlier sign-in is untouched."""
    popup = Signal(str, str)                # a desktop channel's test pop-up, from the worker to the window's thread

    def __init__(self, ch, desktop_cb, parent=None):
        super().__init__(parent)
        self.ch, self.desktop_cb = dict(ch), desktop_cb
        self.result_ch, self.typed_secrets = None, {}
        self._jobs, self._cancel, self._sign_job, self._closed, self._drafted = set(), None, None, False, False
        self.draft = ch["id"] + ".form"
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
                        w.setPlaceholderText("saved in the vault - leave blank to keep it")
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
        self.inputs["auth"][1].currentIndexChanged.connect(self._method)
        for key in ("auth", "tenant", "client_id", "client_secret", "username"):
            w = self.inputs[key][1]
            (w.currentIndexChanged if key == "auth" else w.textChanged).connect(self._drop)
        self._method()
        self._say()

    def _method(self):
        auth = self.inputs["auth"][1].currentData()
        for key in ("tenant", "client_id", "client_secret", "username", "password"):
            self.form.setRowVisible(self.inputs[key][1], key in METHOD_FIELDS[auth])
        self.form.setRowVisible(self.sign_row, mailauth.needs_sign_in(auth))
        self.method_help.setText(METHOD_HELP.get(auth, ""))
        self.method_help.setVisible(auth in METHOD_HELP)
        self.inputs["username"][1].setPlaceholderText(self._user_hint if auth == "password" else "")

    def _say(self, text=None):
        self.sign_btn.setText("Cancel" if self._cancel else SIGN_IN_AGAIN if self.sign_id else SIGN_IN)
        self.sign_status.setText(text or (SIGNED_IN_AS.format(account=self.account) if self.sign_id else NOT_SIGNED_IN))

    def _drop(self, *_):
        """The method, tenant, client ID, client secret or username changed: a sign-in made for the old ones is not used."""
        if self._cancel:
            self._cancel.set()
        if self.sign_id == self.draft:
            self._forget_draft()
        self.sign_id = self.account = None
        self._say()

    def _forget_draft(self):
        try:
            passvault.remove(mailauth.PREFIX + self.draft)
        except Exception:
            quiet.ignored()

    def sign_in(self):
        """The browser sign-in, on a worker; while it waits the button is Cancel."""
        if self._cancel:
            return self._cancel.set()
        ch, _typed, merged = self.collect()
        ch, cancel = dict(ch, id=self.draft), threading.Event()
        self._cancel, self._drafted = cancel, True
        self._say(SSO_TEXT.format(provider=mailauth.provider(ch["auth"])))
        self._sign_job = _run(self, lambda: mailauth.sign_in(ch, merged, cancel),
                              lambda r, e: self._signed(r, e, cancel.is_set(), mailauth.provider(ch["auth"])))

    def _signed(self, account, error, cancelled, prov):
        self._cancel = self._sign_job = None
        if error is None and not cancelled:
            self.sign_id, self.account = self.draft, account
        elif error is None:                                  # it finished just as it was cancelled: not kept
            self._forget_draft()
        self._say()
        if error is not None and not cancelled:
            self._say(self._failed(error, prov))

    @staticmethod
    def _failed(e, prov):
        """A failed sign-in in the approved words; an oidc error's own text names the provider's host, so is never shown."""
        if isinstance(e, (mailauth.MailAuthError, passvault.Locked)):
            return str(e)
        if isinstance(e, oidc.Unreachable):
            return mailauth.UNREACHABLE.format(provider=prov)
        if isinstance(e, (oidc.Cancelled, oidc.Refused, oidc.BadAnswer)):
            return sso_said({"name": prov}, e)
        if isinstance(e, oidc.OidcError):                   # invalid_client, a wrong tenant: the app's setup
            return mailauth.APP_REFUSED.format(provider=prov)
        raise e

    def _as_signed(self, ch):
        """The channel with the form's sign-in (its own, the one made here, or none), for the checks and Send test."""
        return dict(ch, id=self.sign_id or self.draft) if "auth" in self.inputs else ch

    def keep_sign_in(self):
        """After Save: the sign-in made here becomes the channel's; one the form dropped is removed."""
        if self.sign_id == self.draft:
            got = passvault.get(mailauth.PREFIX + self.draft)
            if got:
                passvault.put(mailauth.PREFIX + self.ch["id"], got)
            self._forget_draft()
        elif self.sign_id is None and mailauth.needs_sign_in(self.ch.get("auth")):
            mailauth.sign_out(self.ch)

    def _landed(self, job, result, error):
        job.wait()
        self._jobs.discard(job)
        if not self._closed:
            job.landed(result, error)
        job.landed = None

    def done(self, r):
        """A sign-in's wait ends with the dialog, and only Save (keep_sign_in) keeps what it made."""
        self._closed = True
        if self._cancel:
            self._cancel.set()
            self._sign_job.wait()                            # the browser wait ends within a tenth of a second
        if self._drafted and (r != QDialog.DialogCode.Accepted or self.sign_id != self.draft):
            self._forget_draft()
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
            QMessageBox.warning(self, "Check the settings", "\n".join(f"\u2022 {p}" for p in problems))
            return None
        return ch, typed, merged

    def accept(self):
        got = self._checked()
        if got:
            self.result_ch, self.typed_secrets = got[0], got[1]
            super().accept()

    def test(self):
        got = self._checked()
        if not got:
            return
        ch, _typed, merged = got
        ch, popup = self._as_signed(ch), self.popup.emit if self.desktop_cb else None
        self.test_btn.setEnabled(False)
        _run(self, lambda: notify.send_test(ch, merged, popup), self._tested)

    def _tested(self, result, error):
        self.test_btn.setEnabled(True)
        if error is not None:
            raise error
        ok, detail = result
        (QMessageBox.information if ok else QMessageBox.warning)(
            self, "Test", f"Sent: {detail}" if ok else f"The test failed:\n\n{detail}")



class NotificationsPage(Page):
    title = "Notifications"
    desktop_cb = None                       # set by the main window: shows a tray pop-up
    popup = Signal(str, str)                # a desktop channel's test pop-up, from the worker to the window's thread

    def __init__(self):
        super().__init__()
        self._jobs = set()
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
        if dlg.exec() and dlg.result_ch:
            notify.set_secrets(dlg.result_ch, dlg.typed_secrets)
            dlg.keep_sign_in()
            notify.save_channels(notify.channels() + [dlg.result_ch])
            self.reload_channels()

    def edit(self):
        ch = self.selected_channel()
        if not ch:
            return
        dlg = ChannelDialog(ch, self.desktop_cb, self)
        if dlg.exec() and dlg.result_ch:
            notify.set_secrets(dlg.result_ch, dlg.typed_secrets)
            dlg.keep_sign_in()
            notify.save_channels([dlg.result_ch if c["id"] == ch["id"] else c for c in notify.channels()])
            self.reload_channels()

    def remove(self):
        ch = self.selected_channel()
        if ch and QMessageBox.question(self, "Remove channel", f"Remove '{ch['name']}'?\n\nIts saved "
                                       "webhook URL, password or sign-in is deleted too.") == QMessageBox.StandardButton.Yes:
            notify.delete_secrets(ch)
            notify.save_channels([c for c in notify.channels() if c["id"] != ch["id"]])
            self.reload_channels()

    def test(self):
        ch = self.selected_channel()
        if not ch:
            toast(self, "Select a channel first.")
            return
        self.test_btn.setEnabled(False)
        popup = self.popup.emit if self.desktop_cb else None
        _run(self, lambda: notify.send_test(ch, None, popup), self._tested)

    def _popup(self, title, body):
        self.desktop_cb(title, body)

    def _landed(self, job, result, error):
        job.wait()
        self._jobs.discard(job)
        job.landed(result, error)

    def _tested(self, result, error):
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
