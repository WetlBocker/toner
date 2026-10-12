"""Settings pages: custom checks, configuration backups and the audit log."""

from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
                               QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QTableWidget,
                               QTableWidgetItem, QVBoxLayout)
from core import audit, custom, db
from ui.widgets import EmptyHint, GroupPicker
from ui.settings_base import Page, note, spin


# ------------------------------------------------------------------ Custom checks
class CheckDialog(QDialog):
    HINTS = {"ssh": ("Command", "show processes memory | include Total"),
             "snmp": ("OID or name", "1.3.6.1.2.1.1.3.0  or  sysUpTime.0"),
             "http": ("URL", "https://{host}/health   ({host} = the device's address)"),
             "tcp": ("", ""), "tls": ("Server name (optional)", "leave blank to use the device's address"),
             "ping": ("", ""), "iperf": ("Server address (optional)", "blank = the device itself   ({host} = its address)")}

    def __init__(self, chk=None, parent=None):
        super().__init__(parent)
        self.chk = chk or {}
        self.setWindowTitle("Edit custom check" if chk else "New custom check")
        self.setMinimumWidth(520)
        self.name, self.target, self.parse, self.expect, self.unit = (QLineEdit() for _ in range(5))
        self.kind, self.mode, self.direction = QComboBox(), QComboBox(), QComboBox()
        for k, label in custom.KINDS:
            self.kind.addItem(label, k)
        for k, label in custom.MODES:
            self.mode.addItem(label, k)
        self.direction.addItem("A higher value is worse (CPU, latency)", 1)
        self.direction.addItem("A lower value is worse (days left, free space)", 0)
        self.port = spin(0, 65535)
        self.port.setSpecialValueText("default")
        self.seconds, self.streams = spin(1, 3600, " s"), spin(1, 128)
        self.seconds.setValue(10)
        self.reverse, self.udp = QCheckBox("Download (the server sends)"), QCheckBox("UDP instead of TCP")
        self.bandwidth = QLineEdit()
        self.bandwidth.setPlaceholderText("UDP rate, e.g. 100M")
        self.warn, self.fail = QLineEdit(), QLineEdit()
        self.warn.setPlaceholderText("off")
        self.fail.setPlaceholderText("off")
        self.scope = GroupPicker(all_text="All devices", noun="groups")
        self.scope.set_labels(db.group_labels()[1:])
        self.enabled = QCheckBox("Enabled")
        self.enabled.setChecked(True)
        self.form = QFormLayout()
        self.target_label = QLabel("Command")
        for label, w in (("Name", self.name), ("Kind", self.kind), (self.target_label, self.target), ("Port", self.port),
                         ("Test length", self.seconds), ("Streams", self.streams), ("", self.reverse), ("", self.udp),
                         ("UDP rate", self.bandwidth), ("Answer is", self.mode), ("Pattern", self.parse), ("Expected status", self.expect),
                         ("Direction", self.direction), ("WARN at", self.warn), ("FAIL at", self.fail),
                         ("Unit", self.unit), ("Applies to", self.scope), ("", self.enabled)):
            self.form.addRow(label, w)
        self.help = note("")
        self.test_dev = QComboBox()
        for d in db.list_devices():
            self.test_dev.addItem(d["name"], d)
        self.test_btn = QPushButton("Test on this device")
        self.test_btn.clicked.connect(self.test)
        self.result = QLabel("")
        self.result.setWordWrap(True)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(self.form)
        lay.addWidget(self.help)
        lay.addLayout(row_of_layout(QLabel("Try it on"), self.test_dev, self.test_btn))
        lay.addWidget(self.result)
        lay.addWidget(buttons)
        if chk:
            self.name.setText(chk["name"])
            self.kind.setCurrentIndex(max(0, self.kind.findData(chk["kind"])))
            self.target.setText(chk.get("target") or "")
            self.port.setValue(int(chk.get("port") or 0))
            self.mode.setCurrentIndex(max(0, self.mode.findData(chk.get("mode") or "number")))
            self.parse.setText(chk.get("parse") or "")
            self.expect.setText(chk.get("expect") or "")
            self.direction.setCurrentIndex(0 if chk.get("higher_worse", 1) else 1)
            self.warn.setText("" if chk.get("warn") is None else f"{chk['warn']:g}")
            self.fail.setText("" if chk.get("fail") is None else f"{chk['fail']:g}")
            self.unit.setText(chk.get("unit") or "")
            self.scope.set_selected(chk.get("scope") or [])
            self.enabled.setChecked(bool(chk.get("enabled", 1)))
            o = chk.get("options") or {}
            self.seconds.setValue(int(o.get("seconds", 10)))
            self.streams.setValue(int(o.get("streams", 1)))
            self.reverse.setChecked(bool(o.get("reverse")))
            self.udp.setChecked(bool(o.get("udp")))
            self.bandwidth.setText(o.get("bandwidth", ""))
        self.kind.currentIndexChanged.connect(self.adapt)
        self.mode.currentIndexChanged.connect(self.adapt)
        self.adapt()

    def adapt(self, *_):
        kind, mode = self.kind.currentData(), self.mode.currentData()
        label, placeholder = self.HINTS[kind]
        self.target_label.setText(label or "Target")
        self.target.setPlaceholderText(placeholder)
        show = self.form.setRowVisible
        show(self.target, kind in ("ssh", "snmp", "http", "tls", "iperf"))
        show(self.port, kind in ("tcp", "tls", "iperf"))
        for w in (self.seconds, self.streams, self.reverse, self.udp, self.bandwidth):
            show(w, kind == "iperf")
        text_kind = kind in ("ssh", "snmp", "http")
        show(self.mode, kind in ("ssh", "snmp") or kind == "http")
        show(self.parse, text_kind and (mode in ("match", "nomatch") or kind in ("ssh", "snmp")))
        show(self.expect, kind == "http")
        numeric = mode == "number" if kind in ("ssh", "snmp") else kind in ("http", "tcp", "tls", "ping", "iperf")
        for w in (self.direction, self.warn, self.fail, self.unit):
            show(w, numeric or kind in ("http",))
        self.direction.setEnabled(kind in ("ssh", "snmp"))
        if kind in ("tls", "iperf"):
            self.direction.setCurrentIndex(1)
        if kind == "iperf":
            self.port.setSpecialValueText("5201")
            if not self.unit.text():
                self.unit.setPlaceholderText(" Mbit/s")
        else:
            self.port.setSpecialValueText("default")
        self.mode.setEnabled(kind in ("ssh", "snmp", "http"))
        if kind in ("http",):
            self.help.setText("Passes when the status code is as expected (and the pattern matches, if you choose "
                              "'must match'). WARN and FAIL limits apply to the response time in milliseconds.")
        elif kind == "tcp":
            self.help.setText("Passes when the port accepts a connection. WARN and FAIL limits apply to the connect "
                              "time in milliseconds.")
        elif kind == "tls":
            self.help.setText("Counts the days left on the certificate the port serves. Defaults: WARN at 30 days, "
                              "FAIL at 7.")
        elif kind == "iperf":
            self.help.setText("Runs an iperf3 test from this computer to an iperf3 server (start one on the device with "
                              "'iperf3 -s'). The result is the speed in Mbit/s, so a LOWER value is worse: set WARN and "
                              "FAIL to the speeds below which you want to hear about it. The speed is kept for the "
                              "History charts. It needs iperf3.exe (see Tools > Throughput).")
        elif kind == "ping":
            self.help.setText("Sends four pings from this computer. FAIL if none are answered, WARN on packet loss. "
                              "Limits apply to the average time in milliseconds.")
        elif mode == "number":
            self.help.setText("The first number in the answer is compared with the limits. Use a pattern with one "
                              "( ) group to pick a different number, for example  free=(\\d+).")
        else:
            self.help.setText("The pattern is a regular expression searched for in the answer.")

    @staticmethod
    def _num(text):
        text = text.strip()
        return float(text) if text else None

    def values(self):
        kind = self.kind.currentData()
        return {"id": self.chk.get("id"), "name": self.name.text().strip(), "kind": kind,
                "target": self.target.text().strip(), "port": self.port.value(),
                "mode": self.mode.currentData() if kind in ("ssh", "snmp", "http") else "number",
                "parse": self.parse.text().strip(), "expect": self.expect.text().strip(),
                "higher_worse": self.direction.currentData(), "warn": self._num(self.warn.text()),
                "fail": self._num(self.fail.text()), "unit": self.unit.text(),
                "scope": self.scope.selected(), "enabled": int(self.enabled.isChecked()),
                "options": {"seconds": self.seconds.value(), "streams": self.streams.value(),
                            "reverse": self.reverse.isChecked(), "udp": self.udp.isChecked(),
                            "bandwidth": self.bandwidth.text().strip()} if kind == "iperf" else {}}

    def _check(self):
        try:
            v = self.values()
            custom.validate(v)
            return v
        except ValueError as e:
            QMessageBox.warning(self, "Custom check", str(e))
            return None

    def accept(self):
        if self._check():
            super().accept()

    def test(self):
        v = self._check()
        d = self.test_dev.currentData()
        if not v or not d:
            return
        QApplication.setOverrideCursor(self.cursor())
        try:
            r = custom.test_check(v, d)
            text = f"{r.status}: {r.value}  {r.message}".strip()
        except Exception as e:
            text = f"ERROR: {type(e).__name__}: {e}"
        finally:
            QApplication.restoreOverrideCursor()
        self.result.setText(text)



def row_of_layout(*widgets):
    h = QHBoxLayout()
    for w in widgets:
        h.addWidget(w, 1 if isinstance(w, QComboBox) else 0)
    return h



class CustomChecksPage(Page):
    title = "Custom checks"

    def __init__(self):
        super().__init__()
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Name", "Kind", "What it checks", "Applies to", "On"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(240)
        self.table.doubleClicked.connect(lambda *_: self.edit())
        self.hint = EmptyHint(self.table, "No custom checks yet", "Press New... to add one")
        bar = QHBoxLayout()
        for text, fn in (("New...", self.add), ("Edit...", self.edit), ("Delete", self.delete)):
            b = QPushButton(text)
            b.clicked.connect(lambda _=False, fn=fn: fn())
            bar.addWidget(b)
        bar.addStretch()
        self.form.addRow(self.table)
        self.form.addRow(bar)
        self.lay.insertWidget(0, note(
            "Add your own checks without writing code: run a command over SSH, read an SNMP object, fetch a web "
            "page, test a TCP port, count the days left on a certificate, or ping. Each one gets a result row "
            "named after it, with history and alerts like the built-in checks. Changes here apply immediately."))
        self.rows = []

    def refresh(self):
        self.rows = custom.list_checks()
        self.hint.setVisible(not self.rows)
        kinds = dict(custom.KINDS)
        self.table.setRowCount(len(self.rows))
        for i, c in enumerate(self.rows):
            what = c["target"] if c["kind"] in ("ssh", "snmp", "http") else (f"port {c['port'] or 443}" if c["kind"] in ("tcp", "tls") else (f"iperf3 port {c['port'] or 5201}" if c["kind"] == "iperf" else ""))
            for j, v in enumerate([c["name"], kinds.get(c["kind"], c["kind"]), what,
                                   ", ".join(c["scope"]) or "all devices", "yes" if c["enabled"] else "no"]):
                self.table.setItem(i, j, QTableWidgetItem(v))
        self.table.resizeColumnsToContents()

    def load(self):
        self.refresh()

    def current(self):
        r = self.table.currentRow()
        return self.rows[r] if 0 <= r < len(self.rows) else None

    def _save(self, dlg):
        try:
            custom.save_check(dlg.values())
        except ValueError as e:
            QMessageBox.warning(self, "Custom check", str(e))
            return
        audit.log("custom check saved", dlg.values()["name"])
        self.refresh()

    def add(self):
        dlg = CheckDialog(parent=self)
        if dlg.exec():
            self._save(dlg)

    def edit(self):
        c = self.current()
        if c:
            dlg = CheckDialog(c, self)
            if dlg.exec():
                self._save(dlg)

    def delete(self):
        c = self.current()
        if c and QMessageBox.question(self, "Delete check", f"Delete '{c['name']}'?") == QMessageBox.StandardButton.Yes:
            custom.delete_check(c["id"])
            audit.log("custom check deleted", c["name"])
            self.refresh()

    def refresh_dynamic(self):
        pass


# ------------------------------------------------------------------ Backups
class BackupsPage(Page):
    title = "Config backups"

    def __init__(self):
        super().__init__()
        self.enabled = QCheckBox("Back up configurations automatically (while Toner is open, or with the background service)")
        self.hours = spin(1, 720, " hours")
        self.on_start = QCheckBox("Also back up shortly after Toner starts")
        self.groups = GroupPicker()
        self.groups.set_labels(db.group_labels()[1:])
        self.keep = spin(0, 1000, " versions")
        self.keep.setSpecialValueText("keep everything")
        self.mask = QCheckBox("Mask passwords, keys and SNMP communities in stored copies")
        self.form.addRow("", self.enabled)
        self.form.addRow("Every", self.hours)
        self.form.addRow("", self.on_start)
        self.form.addRow("Devices", self.groups)
        self.form.addRow("Keep per device", self.keep)
        self.form.addRow("", self.mask)
        self.lay.insertWidget(1, note(
            "A new version is stored only when the configuration really changed: timestamps and counters that "
            "change on every read are ignored. A change shows up as a WARN on the device's 'config backup' check, "
            "so your notification channels can announce it. Stored copies live in Toner's database on this "
            "computer, which is not encrypted; keep masking on unless you need exact copies. Masking is a "
            "best effort for common password and key lines, so review a stored copy before sharing it."))

    def load(self):
        self.enabled.setChecked(bool(db.get_setting("backup_enabled")))
        self.hours.setValue(int(db.get_setting("backup_hours")))
        self.on_start.setChecked(bool(db.get_setting("backup_on_start")))
        self.keep.setValue(int(db.get_setting("backup_keep")))
        self.mask.setChecked(bool(db.get_setting("backup_mask")))
        self.groups.set_labels(db.group_labels()[1:])
        self.groups.set_selected(db.get_setting("backup_groups"))

    def refresh(self):
        keep = self.groups.selected()
        self.groups.set_labels(db.group_labels()[1:])
        self.groups.set_selected(keep)

    def save(self):
        db.set_setting("backup_enabled", self.enabled.isChecked())
        db.set_setting("backup_hours", self.hours.value())
        db.set_setting("backup_on_start", self.on_start.isChecked())
        db.set_setting("backup_keep", self.keep.value())
        db.set_setting("backup_mask", self.mask.isChecked())
        db.set_setting("backup_groups", self.groups.selected())


# ------------------------------------------------------------------ Audit log
class AuditPage(Page):
    title = "Audit log"
    track = False                                  # its filter box is not a setting

    def __init__(self):
        super().__init__()
        self.search = QLineEdit()
        self.search.setPlaceholderText("filter by action, detail or user")
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["When", "Who", "What", "Detail"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setMinimumHeight(340)
        self.info = note("")
        bar = QHBoxLayout()
        refresh, export = QPushButton("Refresh"), QPushButton("Export CSV...")
        refresh.clicked.connect(self.refresh)
        export.clicked.connect(self.export)
        bar.addWidget(self.search, 1)
        bar.addWidget(refresh)
        bar.addWidget(export)
        self.form.addRow(bar)
        self.form.addRow(self.table)
        self.form.addRow(self.info)
        self.lay.insertWidget(0, note("A record of changes made in Toner: devices, credentials, custom checks, "
                                      "backups, commands run, discovery scans and settings. Entries are kept for a year."))
        self.search.textChanged.connect(self.refresh)
        self.rows = []

    def refresh(self, *_):
        self.rows = audit.recent(1000, self.search.text().strip())
        self.table.setRowCount(len(self.rows))
        for i, r in enumerate(self.rows):
            for j, v in enumerate([r["at"], r["actor"], r["action"], r["detail"]]):
                self.table.setItem(i, j, QTableWidgetItem(v or ""))
        self.table.resizeColumnsToContents()
        self.info.setText(f"{len(self.rows)} entr{'y' if len(self.rows) == 1 else 'ies'} shown (newest first).")

    def load(self):
        self.refresh()

    def export(self):
        import csv
        path, _ = QFileDialog.getSaveFileName(self, "Export audit log", "toner-audit.csv", "CSV (*.csv)")
        if path:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["when", "who", "action", "detail"])
                for r in self.rows:
                    w.writerow([r["at"], r["actor"], r["action"], r["detail"]])
