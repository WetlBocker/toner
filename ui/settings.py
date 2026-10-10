"""Settings tab: a category list on the left, one page per category, one Save for everything.

Pages whose controls change data immediately (forget a host key, back up the database, ...)
say so on the page; everything else waits for 'Save changes'.
"""
import json
import os
import sqlite3
from datetime import datetime, timedelta

import keyring
from PySide6.QtCore import QDateTime, QTime, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QColorDialog, QComboBox, QDialog,
                               QDateTimeEdit, QDialogButtonBox, QDoubleSpinBox, QFileDialog, QFontComboBox, QFormLayout,
                               QHBoxLayout, QLabel, QLineEdit, QListWidget, QMenu, QMessageBox, QPushButton,
                               QScrollArea, QSpinBox, QStackedWidget, QTableWidget, QTableWidgetItem, QTimeEdit,
                               QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)
from core import alerts, audit, checks, custom, db, display, maintenance, nettools, notify, profiles, proxy, reports, sessionlog
from ui import terminal, theme
from ui.snmpfields import SnmpFields
from ui.widgets import GroupPicker


def spin(lo, hi, suffix=""):
    s = QSpinBox()
    s.setRange(lo, hi)
    if suffix:
        s.setSuffix(suffix)
    return s


def note(text):
    lab = QLabel(text)
    lab.setWordWrap(True)
    lab.setProperty("muted", True)
    return lab


def row_of(*widgets):
    w = QWidget()
    h = QHBoxLayout(w)
    h.setContentsMargins(0, 0, 0, 0)
    for x in widgets:
        h.addWidget(x)
    return w


class Page(QWidget):
    title = ""

    def __init__(self):
        super().__init__()
        self.form = QFormLayout()
        self.lay = QVBoxLayout(self)
        self.lay.addLayout(self.form)
        self.lay.addStretch()

    def load(self):
        """Show the stored values."""

    def validate(self):
        """Return a list of problems that stop a save."""
        return []

    def save(self):
        """Write the shown values."""

    def refresh(self):
        """Inventory or data changed elsewhere; update lists that depend on it."""


# ------------------------------------------------------------------ General
class GeneralPage(Page):
    title = "General"

    def __init__(self):
        super().__init__()
        self.retention, self.ssh_logs = spin(1, 3650, " days"), spin(1, 3650, " days")
        self.workers = spin(1, 50)
        self.ssh_port = spin(1, 65535)
        self.verify = QCheckBox("Verify SSL certificates on new devices by default")
        self.background = QCheckBox("Keep running in the system tray when the window is closed")
        self.background.setToolTip("Scheduled checks, backups and alerts keep working. Use the tray icon to open or quit.")
        self.scan_over = spin(0, 10_000_000, " addresses")
        self.scan_over.setSpecialValueText("never ask")
        for label, w in (("Keep run history", self.retention), ("Keep SSH session logs", self.ssh_logs),
                         ("Devices checked in parallel", self.workers),
                         ("Default SSH port (console)", self.ssh_port), ("", self.verify), ("", self.background),
                         ("Confirm scans larger than", self.scan_over)):
            self.form.addRow(label, w)
        self.lay.insertWidget(1, note("History and logs older than this are deleted when Toner starts "
                                      "(history also after each run)."))

    def load(self):
        self.retention.setValue(int(db.get_setting("retention_days")))
        self.ssh_logs.setValue(int(db.get_setting("ssh_log_days")))
        self.workers.setValue(int(db.get_setting("workers")))
        self.ssh_port.setValue(int(db.get_setting("default_ssh_port")))
        self.verify.setChecked(bool(db.get_setting("default_verify_ssl")))
        self.background.setChecked(bool(db.get_setting("run_in_background")))
        self.scan_over.setValue(int(db.get_setting("scan_confirm_over")))

    def save(self):
        for key, w in (("retention_days", self.retention), ("ssh_log_days", self.ssh_logs),
                       ("workers", self.workers), ("default_ssh_port", self.ssh_port),
                       ("scan_confirm_over", self.scan_over)):
            db.set_setting(key, w.value())
        db.set_setting("default_verify_ssl", self.verify.isChecked())
        db.set_setting("run_in_background", self.background.isChecked())


# ------------------------------------------------------------------ Connections
class ConnectionsPage(Page):
    title = "Connections"

    def __init__(self):
        super().__init__()
        self.ssh, self.http = spin(5, 300, " s"), spin(5, 300, " s")
        self.retries, self.delay = spin(0, 5), spin(0, 60, " s")
        for label, w in (("SSH timeout (switches, routers)", self.ssh), ("Web API timeout (firewalls, controllers)", self.http),
                         ("Retries after a timeout", self.retries), ("Wait between retries", self.delay)):
            self.form.addRow(label, w)
        self.lay.insertWidget(1, note(
            "Raise the timeouts for slow or remote links. Only timeouts and dropped connections are retried. "
            "A rejected login is never retried, because repeating a wrong password can lock the account."))

    def load(self):
        self.ssh.setValue(int(db.get_setting("ssh_timeout")))
        self.http.setValue(int(db.get_setting("http_timeout")))
        self.retries.setValue(int(db.get_setting("retries")))
        self.delay.setValue(int(db.get_setting("retry_delay")))

    def save(self):
        for key, w in (("ssh_timeout", self.ssh), ("http_timeout", self.http),
                       ("retries", self.retries), ("retry_delay", self.delay)):
            db.set_setting(key, w.value())


# ------------------------------------------------------------------ Thresholds
def _bad_pair(key, warn, fail):
    """True if a WARN/FAIL pair contradicts itself."""
    if key in db.LOWER_IS_WORSE:                  # e.g. uptime: FAIL must be the smaller number
        return warn > 0 and fail > warn
    return warn > fail


class ThresholdsPage(Page):
    title = "Thresholds"

    def __init__(self):
        super().__init__()
        self.form.addRow(QLabel("<b>When a check turns WARN / FAIL</b>"))
        self.spins = {}
        for key in db.DEFAULT_THRESHOLDS:
            w, f = QDoubleSpinBox(), QDoubleSpinBox()
            for s in (w, f):
                s.setRange(0, 1_000_000)
                s.setDecimals(1 if key != "port_errors" else 0)
            self.spins[key] = (w, f)
            self.form.addRow(db.THRESHOLD_LABELS.get(key, key), row_of(w, f))
        self.form.addRow(note("Uptime and Wi-Fi signal work the other way round: a device that restarted less than "
                              "this many hours ago, or a signal weaker than the limit, is flagged. 0 switches a level off."))
        self.mode = QComboBox()
        self.mode.addItem("Total since the device last reset", "total")
        self.mode.addItem("Increase since the last run", "delta")
        self.fw = QComboBox()
        self.fw.addItems(["WARN", "FAIL", "Ignore"])
        self.form.addRow("Error counters measure", self.mode)
        self.form.addRow(note("Cumulative counters (interface errors on switches and routers, UniFi port errors) only ever "
                              "grow, so 'total' warns forever after one bad packet. 'Increase' reports "
                              "only new errors; the port-error thresholds then apply to the increase."))
        self.form.addRow("UniFi firmware update available", self.fw)

        reset = QPushButton("Reset thresholds to defaults")
        reset.clicked.connect(self.reset)
        self.lay.insertWidget(1, reset, 0, Qt.AlignmentFlag.AlignLeft)

        self.lay.insertWidget(2, QLabel("<b>Overrides</b>  (a vendor, location, folder or device can use different limits; "
                                        "device beats folder beats location beats vendor)"))
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Applies to", "Check", "WARN", "FAIL"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setMinimumHeight(150)
        bar = QHBoxLayout()
        add, rem = QPushButton("Add override"), QPushButton("Remove selected")
        add.clicked.connect(lambda: self.add_row())
        rem.clicked.connect(self.remove_row)
        bar.addWidget(add)
        bar.addWidget(rem)
        bar.addStretch()
        self.lay.insertWidget(3, self.table)
        self.lay.insertLayout(4, bar)

    def reset(self):
        for key, (w, f) in self.spins.items():
            w.setValue(db.DEFAULT_THRESHOLDS[key]["warn"])
            f.setValue(db.DEFAULT_THRESHOLDS[key]["fail"])

    def add_row(self, scope=None, check="cpu", warn=None, fail=None):
        r = self.table.rowCount()
        self.table.insertRow(r)
        sc = QComboBox()
        scopes = db.override_scopes()
        sc.addItems(scopes + ([scope] if scope and scope not in scopes else []))
        if scope:
            sc.setCurrentText(scope)
        ck = QComboBox()
        for key in db.DEFAULT_THRESHOLDS:
            ck.addItem(db.THRESHOLD_LABELS.get(key, key), key)
        ck.setCurrentIndex(max(0, ck.findData(check)))
        w, f = QDoubleSpinBox(), QDoubleSpinBox()
        for s in (w, f):
            s.setRange(0, 1_000_000)
            s.setDecimals(1)
        base = db.DEFAULT_THRESHOLDS[ck.currentData()]
        w.setValue(base["warn"] if warn is None else warn)
        f.setValue(base["fail"] if fail is None else fail)
        for col, widget in enumerate((sc, ck, w, f)):
            self.table.setCellWidget(r, col, widget)
        self.table.resizeColumnsToContents()

    def remove_row(self):
        rows = {i.row() for i in self.table.selectedIndexes()}
        for r in sorted(rows, reverse=True):
            self.table.removeRow(r)

    def _rules(self):
        return [{"scope": self.table.cellWidget(r, 0).currentText(), "check": self.table.cellWidget(r, 1).currentData(),
                 "warn": self.table.cellWidget(r, 2).value(), "fail": self.table.cellWidget(r, 3).value()}
                for r in range(self.table.rowCount())]

    def load(self):
        th = db.get_thresholds()
        for key, (w, f) in self.spins.items():
            w.setValue(th[key]["warn"])
            f.setValue(th[key]["fail"])
        self.mode.setCurrentIndex(max(0, self.mode.findData(db.get_setting("counter_mode"))))
        self.fw.setCurrentText(db.get_setting("firmware_severity"))
        self.table.setRowCount(0)
        for rule in db.get_setting("threshold_overrides"):
            if isinstance(rule, dict) and all(k in rule for k in ("scope", "check", "warn", "fail")):
                self.add_row(rule["scope"], rule["check"], rule["warn"], rule["fail"])

    def refresh(self):
        scopes = db.override_scopes()
        for r in range(self.table.rowCount()):
            combo = self.table.cellWidget(r, 0)
            cur = combo.currentText()
            combo.clear()
            combo.addItems(scopes + ([cur] if cur not in scopes else []))
            combo.setCurrentText(cur)

    def validate(self):
        bad = [db.THRESHOLD_LABELS[k] for k, (w, f) in self.spins.items() if _bad_pair(k, w.value(), f.value())]
        probs = [f"Thresholds: WARN and FAIL contradict each other for {', '.join(bad)}."] if bad else []
        for rule in self._rules():
            if _bad_pair(rule["check"], rule["warn"], rule["fail"]):
                probs.append(f"Override for {rule['scope']} ({db.THRESHOLD_LABELS[rule['check']]}): "
                             "WARN and FAIL contradict each other.")
        return probs

    def save(self):
        db.set_thresholds({k: {"warn": w.value(), "fail": f.value()} for k, (w, f) in self.spins.items()})
        db.set_setting("counter_mode", self.mode.currentData())
        db.set_setting("firmware_severity", self.fw.currentText())
        db.set_setting("threshold_overrides", self._rules())


# ------------------------------------------------------------------ Checks
class ChecksPage(Page):
    title = "Checks"

    def __init__(self):
        super().__init__()
        self.lay.insertWidget(0, note("Untick a check to stop running it. This saves time on devices that "
                                      "do not have the feature (for example BGP on a switch)."))
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.lay.insertWidget(1, self.tree, 1)

    def load(self):
        off = set(db.get_setting("disabled_checks"))
        self.tree.clear()
        for vendor, items in checks.CATALOG.items():
            top = QTreeWidgetItem([display.vendor_name(vendor)])
            self.tree.addTopLevelItem(top)
            for key, label in items:
                it = QTreeWidgetItem([label])
                it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                it.setCheckState(0, Qt.CheckState.Unchecked if checks.key(vendor, key) in off
                                 else Qt.CheckState.Checked)
                it.setData(0, Qt.ItemDataRole.UserRole, checks.key(vendor, key))
                top.addChild(it)
            top.setExpanded(True)

    def save(self):
        off = []
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            for j in range(top.childCount()):
                it = top.child(j)
                if it.checkState(0) != Qt.CheckState.Checked:
                    off.append(it.data(0, Qt.ItemDataRole.UserRole))
        db.set_setting("disabled_checks", off)


# ------------------------------------------------------------------ Automation
class AutomationPage(Page):
    title = "Automation"

    def __init__(self):
        super().__init__()
        self.enabled = QCheckBox("Run health checks automatically")
        self.minutes = spin(1, 1440, " minutes")
        self.groups = GroupPicker()
        self.on_start = QCheckBox("Also run once when Toner starts")
        for label, w in (("", self.enabled), ("Every", self.minutes), ("Devices", self.groups),
                         ("", self.on_start)):
            self.form.addRow(label, w)
        self.lay.insertWidget(1, note("Scheduled runs happen only while Toner is open. Each run is saved "
                                      "to History like a manual one. If a run is still going when the next is "
                                      "due, that one is skipped."))

    def load(self):
        self.enabled.setChecked(bool(db.get_setting("schedule_enabled")))
        self.minutes.setValue(int(db.get_setting("schedule_minutes")))
        self.groups.set_labels(db.group_labels()[1:])
        self.groups.set_selected(db.get_setting("schedule_groups"))
        self.on_start.setChecked(bool(db.get_setting("schedule_on_start")))

    def refresh(self):
        keep = self.groups.selected()
        self.groups.set_labels(db.group_labels()[1:])
        self.groups.set_selected(keep)

    def save(self):
        db.set_setting("schedule_enabled", self.enabled.isChecked())
        db.set_setting("schedule_minutes", self.minutes.value())
        db.set_setting("schedule_groups", self.groups.selected())
        db.set_setting("schedule_on_start", self.on_start.isChecked())


# ------------------------------------------------------------------ Appearance
class AppearancePage(Page):
    title = "Appearance"
    STATUSES = ["OK", "WARN", "FAIL", "ERROR"]

    def __init__(self):
        super().__init__()
        self.theme = QComboBox()
        self.theme.addItems(theme.THEMES)
        self.font = spin(0, 24, " pt")
        self.font.setSpecialValueText("default")
        self.preset = QComboBox()
        self.preset.addItems(reports.COLOR_PRESETS)
        self.colors = {}
        self.swatch = {}
        for s in self.STATUSES:
            b = QPushButton(s)
            b.clicked.connect(lambda _=False, s=s: self.pick(s))
            self.swatch[s] = b
        self.accent = QComboBox()
        self.accent.addItems(theme.ACCENTS)
        self.form.addRow("Theme", self.theme)
        self.form.addRow("Accent colour", self.accent)
        self.form.addRow("Text size", self.font)
        self.form.addRow("Status colours", self.preset)
        self.form.addRow("", row_of(*self.swatch.values()))
        self.lay.insertWidget(1, note("Click a status to choose its colour. Text on top of each colour is "
                                      "switched between dark and white automatically so it stays readable. "
                                      "The status word is always shown, so colour is never the only signal."))
        self.preset.currentTextChanged.connect(self.use_preset)

    def use_preset(self, name):
        self.colors = dict(reports.COLOR_PRESETS.get(name, reports.DEFAULT_COLORS))
        self.paint()

    def paint(self):
        for s, b in self.swatch.items():
            bg = self.colors[s]
            b.setStyleSheet(f"background:{bg}; color:{reports.fg_for(bg)}; padding:6px 14px; "
                            "border:1px solid #888; border-radius:3px;")

    def pick(self, status):
        c = QColorDialog.getColor(QColor(self.colors[status]), self, f"Colour for {status}")
        if c.isValid():
            self.colors[status] = c.name()
            self.paint()

    def load(self):
        self.theme.setCurrentText(db.get_setting("theme"))
        self.accent.setCurrentText(db.get_setting("accent"))
        self.font.setValue(int(db.get_setting("font_size")))
        self.preset.blockSignals(True)
        self.preset.setCurrentText(db.get_setting("color_preset"))
        self.preset.blockSignals(False)
        self.colors = {**reports.COLOR_PRESETS.get(self.preset.currentText(), reports.DEFAULT_COLORS),
                       **db.get_setting("status_colors")}
        self.paint()

    def save(self):
        preset = self.preset.currentText()
        base = reports.COLOR_PRESETS.get(preset, reports.DEFAULT_COLORS)
        db.set_setting("theme", self.theme.currentText())
        db.set_setting("accent", self.accent.currentText())
        db.set_setting("font_size", self.font.value())
        db.set_setting("color_preset", preset)
        db.set_setting("status_colors", {s: c for s, c in self.colors.items() if c != base[s]})


# ------------------------------------------------------------------ Terminal
class TerminalPage(Page):
    title = "Terminal"

    def __init__(self):
        super().__init__()
        self.family = QFontComboBox()
        self.family.setFontFilters(QFontComboBox.FontFilter.MonospacedFonts)
        self.size = spin(6, 32, " pt")
        self.scrollback = spin(100, 100_000, " lines")
        self.scheme = QComboBox()
        self.scheme.addItems(terminal.SCHEMES)
        self.paging = QLineEdit()
        for label, w in (("Font", self.family), ("Size", self.size), ("Colours", self.scheme),
                         ("Scrollback", self.scrollback), ("Paging command", self.paging)):
            self.form.addRow(label, w)
        self.lay.insertWidget(1, note("Font, size and colours apply to the console straight away. A new "
                                      "scrollback length applies from the next connection. Each vendor "
                                      "has its own paging command; the one here is used for every vendor once you change it "
                                      "from the default, and is sent after login when 'Disable paging' is ticked."))

    def load(self):
        self.family.setCurrentFont(QFont(db.get_setting("term_font")))
        self.size.setValue(int(db.get_setting("term_font_size")))
        self.scheme.setCurrentText(db.get_setting("term_scheme"))
        self.scrollback.setValue(int(db.get_setting("term_scrollback")))
        self.paging.setText(db.get_setting("paging_cmd"))

    def save(self):
        db.set_setting("term_font", self.family.currentFont().family())
        db.set_setting("term_font_size", self.size.value())
        db.set_setting("term_scheme", self.scheme.currentText())
        db.set_setting("term_scrollback", self.scrollback.value())
        db.set_setting("paging_cmd", self.paging.text().strip() or "terminal length 0")


# ------------------------------------------------------------------ Reports
class ReportsPage(Page):
    title = "Reports"

    def __init__(self):
        super().__init__()
        self.report_title, self.org, self.folder = QLineEdit(), QLineEdit(), QLineEdit()
        self.org.setPlaceholderText("shown under the title, e.g. your company or site name")
        self.folder.setPlaceholderText("where the Save dialog opens (blank = wherever it opened last)")
        browse = QPushButton("Browse...")
        browse.clicked.connect(self.browse)
        self.include_all = QCheckBox("Include the full per-device listing (not just 'Needs attention')")
        self.form.addRow("Report title", self.report_title)
        self.form.addRow("Organisation", self.org)
        self.form.addRow("Default folder", row_of(self.folder, browse))
        self.form.addRow("", self.include_all)

    def browse(self):
        d = QFileDialog.getExistingDirectory(self, "Default report folder", self.folder.text())
        if d:
            self.folder.setText(d)

    def load(self):
        self.report_title.setText(db.get_setting("report_title"))
        self.org.setText(db.get_setting("report_org"))
        self.folder.setText(db.get_setting("report_folder"))
        self.include_all.setChecked(bool(db.get_setting("report_include_all")))

    def validate(self):
        f = self.folder.text().strip()
        return [f"Reports: the folder '{f}' does not exist."] if f and not os.path.isdir(f) else []

    def save(self):
        db.set_setting("report_title", self.report_title.text().strip() or "Toner Health Report")
        db.set_setting("report_org", self.org.text().strip())
        db.set_setting("report_folder", self.folder.text().strip())
        db.set_setting("report_include_all", self.include_all.isChecked())


# ------------------------------------------------------------------ Notifications
class ChannelDialog(QDialog):
    """Add or edit one notification channel. Its fields come from notify.CHANNEL_TYPES."""

    def __init__(self, ch, desktop_cb, parent=None):
        super().__init__(parent)
        self.ch, self.desktop_cb = dict(ch), desktop_cb
        self.result_ch, self.typed_secrets = None, {}
        spec = notify.CHANNEL_TYPES[ch["type"]]
        self.setWindowTitle(f"{spec['label']} channel")
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
        self.table.doubleClicked.connect(lambda *_: self.edit())
        add = QToolButton()
        add.setText("Add channel")
        add.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(add)
        for t, spec in notify.CHANNEL_TYPES.items():
            menu.addAction(spec["label"], lambda t=t: self.add_channel(t))
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
                self.table.setItem(i, j, QTableWidgetItem(v))
        self.table.resizeColumnsToContents()

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


# ------------------------------------------------------------------ Security
class SecurityPage(Page):
    title = "Security"

    def __init__(self):
        super().__init__()
        self.mode = QComboBox()
        self.mode.addItems(nettools.HOSTKEY_MODES)
        self.form.addRow("SSH console host keys", self.mode)
        self.form.addRow(note(
            "Trust on first use: remember each device's key the first time, and refuse the connection if it "
            "ever changes (protects against a swapped or spoofed device). Always trust: accept anything, "
            "remember nothing. Reject unknown hosts: only connect to devices already remembered."))

        self.keys = QTableWidget(0, 3)
        self.keys.setHorizontalHeaderLabels(["Host", "Type", "Fingerprint"])
        self.keys.horizontalHeader().setStretchLastSection(True)
        self.keys.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.keys.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.keys.setMinimumHeight(110)
        forget, forget_all = QPushButton("Forget selected key"), QPushButton("Forget all keys")
        forget.clicked.connect(self.forget_one)
        forget_all.clicked.connect(self.forget_all)
        self.lay.insertWidget(1, QLabel("<b>Remembered host keys</b>  (these actions take effect immediately)"))
        self.lay.insertWidget(2, self.keys)
        self.lay.insertWidget(3, row_of(forget, forget_all, QWidget()))

        self.creds = QTableWidget(0, 3)
        self.creds.setHorizontalHeaderLabels(["Device", "Vendor", "Stored in Credential Manager"])
        self.creds.horizontalHeader().setStretchLastSection(True)
        self.creds.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.creds.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.creds.setMinimumHeight(110)
        clear = QPushButton("Delete stored secret for selected device")
        clear.clicked.connect(self.clear_secret)
        self.lay.insertWidget(4, QLabel("<b>Stored credentials</b>  (passwords and API tokens; "
                                        "re-enter them in Inventory > Edit)"))
        self.lay.insertWidget(5, self.creds)
        self.lay.insertWidget(6, row_of(clear, QWidget()))

    def load(self):
        self.mode.setCurrentText(db.get_setting("hostkey_mode"))
        self.refresh()

    def refresh(self):
        keys = nettools.list_host_keys()
        self.keys.setRowCount(len(keys))
        for i, row in enumerate(keys):
            for j, v in enumerate(row):
                self.keys.setItem(i, j, QTableWidgetItem(v))
        self.keys.resizeColumnsToContents()
        devs = db.list_devices()
        self.creds.setRowCount(len(devs))
        for i, d in enumerate(devs):
            try:
                has = bool(keyring.get_password(db.SERVICE, d["name"]))
            except Exception:
                has = False
            for j, v in enumerate((d["name"], display.vendor_name(d["vendor"]), "yes" if has else "no")):
                self.creds.setItem(i, j, QTableWidgetItem(v))
        self.creds.resizeColumnsToContents()

    def forget_one(self):
        r = self.keys.currentRow()
        if r >= 0 and self.keys.selectedIndexes():
            host = self.keys.item(r, 0).text()
            if QMessageBox.question(self, "Forget key", f"Forget the saved key for {host}?\n\nThe next "
                                    "connection will save whatever key the device presents.") \
                    == QMessageBox.StandardButton.Yes:
                nettools.forget_host_key(host)
                self.refresh()

    def forget_all(self):
        if self.keys.rowCount() and QMessageBox.question(
                self, "Forget all keys", "Forget every saved host key?") == QMessageBox.StandardButton.Yes:
            nettools.forget_host_key(None)
            self.refresh()

    def clear_secret(self):
        r = self.creds.currentRow()
        if r >= 0 and self.creds.selectedIndexes():
            name = self.creds.item(r, 0).text()
            if QMessageBox.question(self, "Delete secret", f"Delete the stored password/token for {name}?\n\n"
                                    "Checks on that device will fail until you enter it again.") \
                    == QMessageBox.StandardButton.Yes:
                db.delete_secret(name)
                self.refresh()

    def save(self):
        db.set_setting("hostkey_mode", self.mode.currentText())


# ------------------------------------------------------------------ Data & logs
class DataPage(Page):
    title = "Data and logs"

    def __init__(self, on_imported):
        super().__init__()
        self.on_imported = on_imported
        self.info = QLabel()
        self.info.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.info.setWordWrap(True)
        self.lay.insertWidget(0, self.info)
        self.lay.insertWidget(1, note("The buttons on this page act immediately."))
        for text, fn in (("Open data folder", self.open_folder), ("Back up database...", self.backup),
                         ("Export settings...", self.export_settings), ("Import settings...", self.import_settings),
                         ("Clear run history...", self.clear_history),
                         ("Delete all SSH session logs...", self.delete_logs)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            self.lay.insertWidget(self.lay.count() - 1, b, 0, Qt.AlignmentFlag.AlignLeft)

    def refresh(self):
        path = db.db_path()
        with db.connect() as c:
            runs = c.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            rows = c.execute("SELECT COUNT(*) FROM results").fetchone()[0]
            sessions = c.execute("SELECT COUNT(*) FROM ssh_sessions").fetchone()[0]
        size = path.stat().st_size / 1_048_576 if path.exists() else 0
        self.info.setText(
            f"<b>Database</b>: {path} ({size:.1f} MB)<br>"
            f"<b>Run history</b>: {runs:,} runs, {rows:,} results<br>"
            f"<b>SSH session logs</b>: {sessions:,} sessions in {sessionlog.log_dir()}<br>"
            f"<b>Saved host keys</b>: {nettools.known_hosts_path()}")

    load = refresh

    def open_folder(self):
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(db.db_path().parent)))

    def backup(self):
        default = str(db.db_path().parent / f"toner-backup-{datetime.now():%Y-%m-%d}.db")
        path, _ = QFileDialog.getSaveFileName(self, "Back up database", default, "SQLite database (*.db)")
        if not path:
            return
        try:
            src, dst = db.connect(), sqlite3.connect(path)
            with dst:
                src.backup(dst)                          # consistent copy even while the app is using it
            src.close()
            dst.close()
            QMessageBox.information(self, "Backup", f"Saved to {path}\n\nThe backup holds devices, history and "
                                    "settings. Passwords and API tokens live in Windows Credential Manager "
                                    "and are not included.")
        except (OSError, sqlite3.Error) as e:
            QMessageBox.warning(self, "Backup failed", str(e))

    def export_settings(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export settings", "toner-settings.json", "JSON (*.json)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(db.export_settings(), f, indent=2)
            QMessageBox.information(self, "Export", "Settings exported. Devices and passwords are not included.")

    def import_settings(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import settings", "", "JSON (*.json)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8-sig") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("expected a settings object")
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, "Import failed", f"Could not read the file:\n{e}")
            return
        applied, skipped = db.import_settings(data)
        self.on_imported()
        msg = f"Applied {len(applied)} setting(s)."
        if skipped:
            msg += f"\nIgnored (unknown or invalid): {', '.join(skipped)}"
        QMessageBox.information(self, "Import", msg)

    def clear_history(self):
        if QMessageBox.question(self, "Clear history", "Delete ALL run history and trend data?\n\n"
                                "Devices, settings and SSH logs are kept. This cannot be undone.") \
                != QMessageBox.StandardButton.Yes:
            return
        with db.connect() as c:
            c.execute("DELETE FROM runs")                # results go with them (cascade)
        self.refresh()
        self.on_imported()

    def delete_logs(self):
        if QMessageBox.question(self, "Delete session logs", "Delete ALL finished SSH session logs "
                                "(files and index)?\n\nThis removes the audit trail and cannot be undone.") \
                != QMessageBox.StandardButton.Yes:
            return
        n = sessionlog.delete_closed()
        self.refresh()
        QMessageBox.information(self, "Session logs", f"Deleted {n} session log(s).")


# ------------------------------------------------------------------ the tab
# ------------------------------------------------------------------ Credential profiles
class ProfileDialog(QDialog):
    def __init__(self, profile=None, parent=None):
        super().__init__(parent)
        self.profile = profile or {}
        self.setWindowTitle("Edit credential profile" if profile else "New credential profile")
        self.setMinimumWidth(440)
        self.name, self.username, self.secret = QLineEdit(), QLineEdit(), QLineEdit()
        self.secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.notes = QLineEdit()
        self.use_snmp = QCheckBox("Include SNMP settings")
        self.snmp = SnmpFields()
        form = QFormLayout()
        for label, w in (("Name", self.name), ("Username", self.username), ("Password / token / API key", self.secret),
                         ("Notes", self.notes)):
            form.addRow(label, w)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(self.use_snmp)
        lay.addWidget(self.snmp)
        lay.addWidget(buttons)
        have = {}
        if profile:
            self.name.setText(profile["name"])
            self.username.setText(profile.get("username") or "")
            self.notes.setText(profile.get("notes") or "")
            try:
                s = json.loads(profile.get("snmp") or "{}")
            except ValueError:
                s = {}
            self.use_snmp.setChecked(bool(s))
            self.snmp.load(s)
            have = {k: profiles.has_secret(profile["name"], k) for k in ("snmp", "snmp_auth", "snmp_priv")}
            self.secret.setPlaceholderText("leave blank to keep the stored value" if profiles.has_secret(profile["name"])
                                           else "")
        self.snmp.set_stored(have)
        self.use_snmp.toggled.connect(self.snmp.setEnabled)
        self.snmp.setEnabled(self.use_snmp.isChecked())

    def values(self):
        secrets = {"main": self.secret.text()}
        if self.use_snmp.isChecked():
            secrets.update(self.snmp.secrets())
        return ({"id": self.profile.get("id"), "name": self.name.text().strip(), "username": self.username.text().strip(),
                 "notes": self.notes.text().strip(), "snmp": self.snmp.settings() if self.use_snmp.isChecked() else ""},
                secrets)


class ProfilesPage(Page):
    title = "Credentials"

    def __init__(self):
        super().__init__()
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Profile", "Username", "SNMP", "Used by"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(220)
        self.table.doubleClicked.connect(lambda *_: self.edit())
        bar = QHBoxLayout()
        for text, fn in (("New...", self.add), ("Edit...", self.edit), ("Delete", self.delete)):
            b = QPushButton(text)
            b.clicked.connect(lambda _=False, fn=fn: fn())
            bar.addWidget(b)
        bar.addStretch()
        self.form.addRow(self.table)
        self.form.addRow(bar)
        self.lay.insertWidget(0, note(
            "A profile holds a username, a password or token, and SNMP settings, so many devices can share them. "
            "Choose it in a device's Access tab; anything set on the device itself overrides the profile. "
            "Secrets go to Windows Credential Manager. Changes here apply immediately."))
        self.ids = []

    def refresh(self):
        rows = profiles.list_profiles()
        self.ids = [p["id"] for p in rows]
        self.table.setRowCount(len(rows))
        for i, p in enumerate(rows):
            try:
                s = json.loads(p.get("snmp") or "{}")
            except ValueError:
                s = {}
            users = profiles.users_of(p["id"])
            for j, v in enumerate([p["name"], p.get("username") or "", ("v" + str(s.get("version", "2c"))) if s else "-",
                                   f"{len(users)} device(s)" if users else "no devices"]):
                self.table.setItem(i, j, QTableWidgetItem(v))
        self.table.resizeColumnsToContents()

    def load(self):
        self.refresh()

    def current(self):
        r = self.table.currentRow()
        return profiles.get(self.ids[r]) if 0 <= r < len(self.ids) else None

    def _save(self, dlg):
        prof, secrets = dlg.values()
        try:
            profiles.save(prof, secrets)
        except ValueError as e:
            QMessageBox.warning(self, "Profile", str(e))
            return
        audit.log("profile " + ("edited" if prof.get("id") else "created"), prof["name"])
        self.refresh()

    def add(self):
        dlg = ProfileDialog(parent=self)
        if dlg.exec():
            self._save(dlg)

    def edit(self):
        p = self.current()
        if p:
            dlg = ProfileDialog(p, self)
            if dlg.exec():
                self._save(dlg)

    def delete(self):
        p = self.current()
        if not p:
            return
        users = profiles.users_of(p["id"])
        extra = f"\n\n{len(users)} device(s) use it and will fall back to their own settings." if users else ""
        if QMessageBox.question(self, "Delete profile", f"Delete '{p['name']}'?{extra}") == QMessageBox.StandardButton.Yes:
            profiles.delete(p["id"])
            audit.log("profile deleted", p["name"])
            self.refresh()


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


# ------------------------------------------------------------------ Proxy
class ProxyPage(Page):
    title = "Proxy"

    def __init__(self):
        super().__init__()
        self.mode, self.kind = QComboBox(), QComboBox()
        for k, label in proxy.MODES:
            self.mode.addItem(label, k)
        for k, label in proxy.KINDS:
            self.kind.addItem(label, k)
        self.host, self.user, self.bypass = QLineEdit(), QLineEdit(), QLineEdit()
        self.host.setPlaceholderText("proxy.example.com")
        self.user.setPlaceholderText("optional")
        self.bypass.setPlaceholderText("localhost, 127.0.0.1, *.corp.example.com, 10.0.0.0/8")
        self.port = spin(1, 65535)
        self.port.setValue(8080)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.forget = QPushButton("Remove saved password")
        self.pw_note = note("")
        self.system = note("")
        self.test_to = QLineEdit("www.githubstatus.com:443")
        self.test_btn = QPushButton("Test")
        self.test_out = QLabel("")
        self.test_out.setWordWrap(True)
        self._forget = False
        self.manual = [self.kind, self.host, self.port, self.user, self.password, self.forget, self.bypass]
        self.form.addRow("Connections go", self.mode)
        self.form.addRow("", self.system)
        self.form.addRow("Proxy type", self.kind)
        self.form.addRow("Address", self.host)
        self.form.addRow("Port", self.port)
        self.form.addRow("User name", self.user)
        self.form.addRow("Password", self.password)
        self.form.addRow("", row_of(self.forget))
        self.form.addRow("", self.pw_note)
        self.form.addRow("Do not use it for", self.bypass)
        self.form.addRow("Try a connection to", row_of(self.test_to, self.test_btn))
        self.form.addRow("", self.test_out)
        self.lay.insertWidget(0, note(
            "Send Toner's connections through a proxy. This is the setting for every connection; a device can override it "
            "in its own Access tab. It covers SSH (checks, backups, the console), the web APIs of Fortinet, Palo Alto, "
            "Meraki and UniFi, status pages, web, port and certificate checks, and notifications. SNMP, ping, "
            "traceroute and the listeners use UDP or ICMP, which a proxy does not carry, so they always connect directly. "
            "'Windows proxy settings' covers web connections only, as a browser would; choose 'Use the proxy below' to "
            "send SSH and port checks through a proxy as well."))
        self.mode.currentIndexChanged.connect(self.adapt)
        self.forget.clicked.connect(self._clear_password)
        self.test_btn.clicked.connect(self.test)

    def adapt(self, *_):
        manual = self.mode.currentData() == "manual"
        for w in self.manual:
            w.setEnabled(manual)
        self.form.setRowVisible(self.system, self.mode.currentData() == "system")

    def _clear_password(self):
        self._forget = True
        self.password.clear()
        self.pw_note.setText("The saved password will be removed when you save.")

    def load(self):
        s = proxy.settings()
        self.mode.setCurrentIndex(max(0, self.mode.findData(s["mode"])))
        self.kind.setCurrentIndex(max(0, self.kind.findData(s["kind"])))
        self.host.setText(s["host"])
        self.port.setValue(int(s["port"] or 8080))
        self.user.setText(s["username"])
        self.bypass.setText(s["bypass"])
        self.password.clear()
        self._forget = False
        have = bool(keyring.get_password(db.SERVICE, proxy.GLOBAL_SECRET))
        self.pw_note.setText("A password is saved in Credential Manager. Leave the box empty to keep it." if have else "")
        self.forget.setVisible(have)
        sys_text = proxy.system_text()
        self.system.setText(f"Windows is set to use: {sys_text}" if sys_text else
                            "Windows has no proxy configured, so connections go directly.")
        self.test_out.setText("")
        self.adapt()

    def validate(self):
        if self.mode.currentData() == "manual" and not self.host.text().strip():
            return ["Proxy: enter the proxy's address, or choose another option."]
        return []

    def save(self):
        db.set_setting("proxy", {"mode": self.mode.currentData(), "kind": self.kind.currentData(),
                                 "host": self.host.text().strip(), "port": self.port.value(),
                                 "username": self.user.text().strip(), "bypass": self.bypass.text().strip()})
        if self.password.text():
            db.set_secret(proxy.GLOBAL_SECRET, self.password.text())
        elif self._forget:
            db.delete_secret(proxy.GLOBAL_SECRET)
        audit.log("proxy settings changed", f"{self.mode.currentData()} {self.host.text().strip()}:{self.port.value()}"
                  if self.mode.currentData() == "manual" else self.mode.currentData())
        self.load()

    def test(self):
        target = self.test_to.text().strip() or "www.githubstatus.com:443"
        host, _, port = target.rpartition(":") if target.count(":") == 1 else (target, "", "443")
        if not host or not port.isdigit():
            self.test_out.setText("Enter an address such as www.githubstatus.com:443.")
            return
        mode = self.mode.currentData()
        QApplication.setOverrideCursor(self.cursor())
        try:
            if mode == "manual":
                cfg = proxy._config({"kind": self.kind.currentData(), "host": self.host.text(), "port": self.port.value(),
                                     "username": self.user.text()},
                                    self.password.text() or ("" if self._forget else
                                                             keyring.get_password(db.SERVICE, proxy.GLOBAL_SECRET) or ""))
                ok, msg = (False, "Enter the proxy's address first.") if cfg is None else proxy.test_tunnel(cfg, host, int(port))
            else:
                ok, msg = proxy.test_web(host, int(port), direct=(mode == "none"))
        finally:
            QApplication.restoreOverrideCursor()
        self.test_out.setText(("OK: " if ok else "Failed: ") + msg)


# ------------------------------------------------------------------ Maintenance windows
class MaintenanceDialog(QDialog):
    def __init__(self, win=None, parent=None):
        super().__init__(parent)
        self.win = win or {}
        self.setWindowTitle("Edit maintenance window" if win else "New maintenance window")
        self.setMinimumWidth(480)
        now = QDateTime.currentDateTime()
        self.name, self.note = QLineEdit(), QLineEdit()
        self.name.setPlaceholderText("e.g. Saturday patching, Chicago switch upgrade")
        self.note.setPlaceholderText("optional")
        self.kind = QComboBox()
        self.kind.addItem("One time", "once")
        self.kind.addItem("Repeats every week", "weekly")
        self.start, self.end = QDateTimeEdit(now), QDateTimeEdit(now.addSecs(2 * 3600))
        for w in (self.start, self.end):
            w.setCalendarPopup(True)
            w.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.days = [QCheckBox(d) for d in maintenance.DAYS]
        self.t_start, self.t_end = QTimeEdit(QTime(22, 0)), QTimeEdit(QTime(2, 0))
        for w in (self.t_start, self.t_end):
            w.setDisplayFormat("HH:mm")
        self.scope = GroupPicker(all_text="All devices", noun="groups")
        self.scope.set_labels(db.group_labels()[1:])
        self.enabled = QCheckBox("Enabled")
        self.enabled.setChecked(True)
        self.form = QFormLayout()
        daybox = QWidget()
        dl = QHBoxLayout(daybox)
        dl.setContentsMargins(0, 0, 0, 0)
        for c in self.days:
            dl.addWidget(c)
        timebox = row_of(QLabel("from"), self.t_start, QLabel("to"), self.t_end)
        self.rows = {"start": self.start, "end": self.end, "days": daybox, "times": timebox}
        for label, w in (("Name", self.name), ("Type", self.kind), ("Starts", self.start), ("Ends", self.end),
                         ("Days", daybox), ("Time of day", timebox), ("Applies to", self.scope), ("Note", self.note),
                         ("", self.enabled)):
            self.form.addRow(label, w)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(self.form)
        lay.addWidget(note("While a window is active, alerts for the devices it covers are held back. Checks still run "
                           "and are recorded. When it ends, a problem that is still there is announced, and one that "
                           "was fixed is reported as recovered. A time that runs past midnight (22:00 to 02:00) is "
                           "counted from the day it starts."))
        lay.addWidget(buttons)
        w = self.win
        if w:
            self.name.setText(w["name"])
            self.kind.setCurrentIndex(max(0, self.kind.findData(w["kind"])))
            self.note.setText(w.get("note") or "")
            self.enabled.setChecked(bool(w.get("enabled", 1)))
            self.scope.set_selected(w.get("scope") or [])
            if w["kind"] == "once":
                self.start.setDateTime(QDateTime.fromString(w["start_at"], "yyyy-MM-dd HH:mm"))
                self.end.setDateTime(QDateTime.fromString(w["end_at"], "yyyy-MM-dd HH:mm"))
            else:
                for i, c in enumerate(self.days):
                    c.setChecked(i in (w.get("days") or []))
                self.t_start.setTime(QTime.fromString(w["start_time"], "HH:mm"))
                self.t_end.setTime(QTime.fromString(w["end_time"], "HH:mm"))
        else:
            for c in self.days[5:]:
                c.setChecked(True)
        self.kind.currentIndexChanged.connect(self.adapt)
        self.adapt()

    def adapt(self, *_):
        once = self.kind.currentData() == "once"
        for key, w in self.rows.items():
            self.form.setRowVisible(w, once if key in ("start", "end") else not once)

    def values(self):
        return {"id": self.win.get("id"), "name": self.name.text().strip(), "kind": self.kind.currentData(),
                "start_at": self.start.dateTime().toString("yyyy-MM-dd HH:mm"),
                "end_at": self.end.dateTime().toString("yyyy-MM-dd HH:mm"),
                "days": [i for i, c in enumerate(self.days) if c.isChecked()],
                "start_time": self.t_start.time().toString("HH:mm"), "end_time": self.t_end.time().toString("HH:mm"),
                "scope": self.scope.selected(), "enabled": int(self.enabled.isChecked()), "note": self.note.text().strip()}

    def accept(self):
        try:
            maintenance.validate(self.values())
        except ValueError as e:
            QMessageBox.warning(self, "Maintenance window", str(e))
            return
        super().accept()


class MaintenancePage(Page):
    title = "Maintenance"

    def __init__(self):
        super().__init__()
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Name", "When", "Applies to", "State", "Note"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(240)
        self.table.doubleClicked.connect(lambda *_: self.edit())
        self.info = note("")
        bar = QHBoxLayout()
        for text, fn in (("New...", self.add), ("Edit...", self.edit), ("Delete", self.delete)):
            b = QPushButton(text)
            b.clicked.connect(lambda _=False, fn=fn: fn())
            bar.addWidget(b)
        bar.addStretch()
        self.form.addRow(self.table)
        self.form.addRow(bar)
        self.form.addRow(self.info)
        self.lay.insertWidget(0, note(
            "Planned work (patching, an upgrade, a power test) should not page anyone. During a maintenance window the "
            "devices it covers keep being checked and recorded, but their alerts are held back. Changes here apply "
            "immediately."))
        self.rows = []

    def refresh(self):
        self.rows = maintenance.list_windows()
        now = datetime.now()
        self.table.setRowCount(len(self.rows))
        active = 0
        for i, w in enumerate(self.rows):
            on = maintenance.is_active(w, now)
            active += on
            state = "ACTIVE" if on else ("off" if not w["enabled"] else "scheduled")
            for j, v in enumerate([w["name"], maintenance.describe(w), ", ".join(w["scope"]) or "all devices", state,
                                   w.get("note") or ""]):
                it = QTableWidgetItem(v)
                if on and j == 3:
                    it.setForeground(QColor("#e6a100"))
                self.table.setItem(i, j, it)
        self.table.resizeColumnsToContents()
        held = maintenance.devices_in_maintenance(now)
        self.info.setText(f"{len(held)} device(s) in maintenance right now." if held else "No device is in maintenance right now.")

    def load(self):
        self.refresh()

    def current(self):
        r = self.table.currentRow()
        return self.rows[r] if 0 <= r < len(self.rows) else None

    def _save(self, dlg):
        try:
            maintenance.save_window(dlg.values())
        except ValueError as e:
            QMessageBox.warning(self, "Maintenance window", str(e))
            return
        audit.log("maintenance window saved", f"{dlg.values()['name']} ({maintenance.describe(dlg.values())})")
        self.refresh()

    def add(self):
        dlg = MaintenanceDialog(parent=self)
        if dlg.exec():
            self._save(dlg)

    def edit(self):
        w = self.current()
        if w:
            dlg = MaintenanceDialog(w, self)
            if dlg.exec():
                self._save(dlg)

    def delete(self):
        w = self.current()
        if w and QMessageBox.question(self, "Delete window", f"Delete '{w['name']}'?") == QMessageBox.StandardButton.Yes:
            maintenance.delete_window(w["id"])
            audit.log("maintenance window deleted", w["name"])
            self.refresh()


class SettingsTab(QWidget):
    changed = Signal()                    # emitted after a successful save (or an import)

    def __init__(self):
        super().__init__()
        self.pages = [GeneralPage(), ThresholdsPage(), ChecksPage(), CustomChecksPage(), ConnectionsPage(), ProxyPage(), AutomationPage(),
                      BackupsPage(), MaintenancePage(), NotificationsPage(), ProfilesPage(), AppearancePage(), TerminalPage(), ReportsPage(), SecurityPage(),
                      AuditPage(), DataPage(self.reload)]
        self.nav = QListWidget()
        self.nav.setObjectName("settingsNav")
        self.nav.setFixedWidth(180)
        self.stack = QStackedWidget()
        for p in self.pages:
            self.nav.addItem(p.title)
            area = QScrollArea()
            area.setWidgetResizable(True)
            area.setFrameShape(QScrollArea.Shape.NoFrame)
            area.setWidget(p)
            self.stack.addWidget(area)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)

        self.status = QLabel("")
        save, revert = QPushButton("Save changes"), QPushButton("Revert")
        save.setProperty("primary", True)
        save.setDefault(True)
        save.clicked.connect(self.save)
        revert.clicked.connect(self.reload)
        bar = QHBoxLayout()
        bar.addWidget(self.status, 1)
        bar.addWidget(revert)
        bar.addWidget(save)
        right = QVBoxLayout()
        right.addWidget(self.stack, 1)
        right.addLayout(bar)
        lay = QHBoxLayout(self)
        lay.addWidget(self.nav)
        lay.addLayout(right, 1)
        self.nav.setCurrentRow(0)
        self.reload()

    def reload(self):
        """Show what is stored, discarding unsaved edits."""
        for p in self.pages:
            p.load()
        self.status.setText("")
        self.changed.emit()

    def refresh_dynamic(self):
        for p in self.pages:
            p.refresh()

    def showEvent(self, e):
        self.refresh_dynamic()
        super().showEvent(e)

    def save(self):
        problems = []
        first_bad = None
        for i, p in enumerate(self.pages):
            found = p.validate()
            if found and first_bad is None:
                first_bad = i
            problems += found
        if problems:
            self.nav.setCurrentRow(first_bad)
            QMessageBox.warning(self, "Cannot save", "Please fix:\n\n" + "\n".join(f"• {p}" for p in problems))
            return
        for p in self.pages:
            p.save()
        audit.log("settings saved")
        self.status.setText(f"Saved at {datetime.now():%H:%M:%S}")
        self.changed.emit()
