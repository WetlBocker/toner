"""Settings page: notification channels."""

from datetime import datetime, timedelta

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout,
                               QHBoxLayout, QLabel, QLineEdit, QMenu, QMessageBox, QPushButton, QSpinBox, QTableWidget,
                               QTableWidgetItem, QToolButton, QVBoxLayout, QWidget)
from core import alerts, db, notify
from ui.brandicons import channel_icon
from ui.settings_base import Page, note, spin


# ------------------------------------------------------------------ Notifications
class ChannelDialog(QDialog):
    """Add or edit one notification channel. Its fields come from notify.CHANNEL_TYPES."""

    def __init__(self, ch, desktop_cb, parent=None):
        super().__init__(parent)
        self.ch, self.desktop_cb = dict(ch), desktop_cb
        self.result_ch, self.typed_secrets = None, {}
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
                w.addItems(extra["choices"])
                w.setCurrentText(ch.get(key, extra.get("default", extra["choices"][0])))
            else:
                w = QLineEdit(str(ch.get(key, "")) if kind == "text" else "")
                w.setPlaceholderText(extra.get("placeholder", ""))
                if kind == "secret":
                    w.setEchoMode(QLineEdit.EchoMode.Password)
                    if self.stored.get(key):
                        w.setPlaceholderText("saved in Credential Manager - leave blank to keep it")
            self.inputs[key] = (kind, w)
            form.addRow(label, w)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        test = buttons.addButton("Send test", QDialogButtonBox.ButtonRole.ActionRole)
        test.clicked.connect(self.test)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(note(spec["help"]))
        lay.addLayout(form)
        lay.addWidget(buttons)

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
                ch[key] = w.currentText()
            else:
                ch[key] = w.text().strip()
        merged = {**self.stored, **{k: v for k, v in typed.items() if v}}      # blank = keep what is stored
        return ch, typed, merged

    def _checked(self):
        ch, typed, merged = self.collect()
        problems = notify.validate(ch, merged)
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
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            ok, detail = notify.send_test(ch, merged, self.desktop_cb)
        finally:
            QApplication.restoreOverrideCursor()
        (QMessageBox.information if ok else QMessageBox.warning)(
            self, "Test", f"Sent: {detail}" if ok else f"The test failed:\n\n{detail}")



class NotificationsPage(Page):
    title = "Notifications"
    desktop_cb = None                       # set by the main window: shows a tray pop-up

    def __init__(self):
        super().__init__()
        self.enabled = QCheckBox("Send notifications")
        self.consecutive = spin(1, 10, " run(s) in a row")
        self.remind = spin(0, 168, " hours")
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
        edit, remove, test = QPushButton("Edit"), QPushButton("Remove"), QPushButton("Send test")
        edit.clicked.connect(self.edit)
        remove.clicked.connect(self.remove)
        test.clicked.connect(self.test)
        bar = QHBoxLayout()
        for w in (add, edit, remove, test):
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
        self.table.setRowCount(len(chs))
        for i, c in enumerate(chs):
            sends = c.get("min", "WARN and worse") + (", recoveries" if c.get("recoveries", True) else "")
            for j, v in enumerate(("yes" if c.get("enabled", True) else "no", c["name"],
                                   notify.CHANNEL_TYPES[c["type"]]["label"], sends)):
                item = QTableWidgetItem(v)
                item.setToolTip(v)
                if j in (1, 2):                                   # the service's mark beside its name and its type
                    item.setIcon(channel_icon(c["type"]))
                self.table.setItem(i, j, item)

    def add_channel(self, ctype):
        dlg = ChannelDialog(notify.new_channel(ctype), self.desktop_cb, self)
        if dlg.exec() and dlg.result_ch:
            notify.set_secrets(dlg.result_ch, dlg.typed_secrets)
            notify.save_channels(notify.channels() + [dlg.result_ch])
            self.reload_channels()

    def edit(self):
        ch = self.selected_channel()
        if not ch:
            return
        dlg = ChannelDialog(ch, self.desktop_cb, self)
        if dlg.exec() and dlg.result_ch:
            notify.set_secrets(dlg.result_ch, dlg.typed_secrets)
            notify.save_channels([dlg.result_ch if c["id"] == ch["id"] else c for c in notify.channels()])
            self.reload_channels()

    def remove(self):
        ch = self.selected_channel()
        if ch and QMessageBox.question(self, "Remove channel", f"Remove '{ch['name']}'?\n\nIts saved "
                                       "webhook URL or password is deleted too.") == QMessageBox.StandardButton.Yes:
            notify.delete_secrets(ch)
            notify.save_channels([c for c in notify.channels() if c["id"] != ch["id"]])
            self.reload_channels()

    def test(self):
        ch = self.selected_channel()
        if not ch:
            QMessageBox.information(self, "Send test", "Select a channel first.")
            return
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            ok, detail = notify.send_test(ch, None, self.desktop_cb)
        finally:
            QApplication.restoreOverrideCursor()
        self.refresh_log()
        (QMessageBox.information if ok else QMessageBox.warning)(
            self, "Test", f"Sent: {detail}" if ok else f"The test failed:\n\n{detail}")

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
