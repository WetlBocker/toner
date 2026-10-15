"""Settings pages: General, Connections, Thresholds, and Checks (which holds the list of checks, their schedule and the custom ones)."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QDoubleSpinBox, QHBoxLayout, QLabel, QLineEdit,
                               QPushButton, QTableWidget, QTabWidget, QToolButton, QTreeWidget, QTreeWidgetItem, QWidget)
from core import checks, custom, db, display
from ui.widgets import GroupPicker
from ui.settings_base import Page, TrimSpin, note, row_of, spin


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
        def heading(text):
            title = QLabel(text.upper())
            title.setProperty("muted", True)
            title.setStyleSheet("font-weight: 600; padding-top: 10px;")
            self.form.addRow(title)
        heading("Stored data")
        self.form.addRow("Keep run history", self.retention)
        self.form.addRow("Keep SSH session logs", self.ssh_logs)
        self.form.addRow("", note("History and logs older than this are deleted when Toner starts (history also after each run)."))
        heading("Running")
        self.form.addRow("Devices checked in parallel", self.workers)
        self.form.addRow("", self.background)
        heading("Devices and scans")
        self.form.addRow("Default SSH port (console)", self.ssh_port)
        self.form.addRow("", self.verify)
        self.form.addRow("Confirm scans larger than", self.scan_over)

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
_bad_pair = db.bad_pair



class ThresholdsPage(Page):
    title = "Thresholds"

    def __init__(self):
        super().__init__()
        self.form.addRow(QLabel("<b>When a check turns WARN / FAIL</b>"))
        self.spins, self.resets = {}, {}
        grouped = {k for _t, keys in db.THRESHOLD_GROUPS for k in keys}
        for heading, keys in db.THRESHOLD_GROUPS + [("Other", [k for k in db.DEFAULT_THRESHOLDS if k not in grouped])]:
            keys = [k for k in keys if k in db.DEFAULT_THRESHOLDS]
            if not keys:
                continue
            title = QLabel(heading.upper())
            title.setProperty("muted", True)
            title.setStyleSheet("font-weight: 600; padding-top: 10px;")
            self.form.addRow(title)
            for key in keys:
                w, f = TrimSpin(), TrimSpin()
                w.setPrefix("WARN at ")                          # the label is inside the box, so it can never drift from it
                f.setPrefix("FAIL at ")
                for s_ in (w, f):
                    s_.setRange(0, 1_000_000)
                    s_.setDecimals(0 if key == "port_errors" else 2)
                self.spins[key] = (w, f)
                reset = QToolButton()
                reset.setText("Reset")
                d = db.DEFAULT_THRESHOLDS[key]
                reset.setToolTip(f"Back to the default: WARN at {d['warn']:g}, FAIL at {d['fail']:g}")
                reset.clicked.connect(lambda _=False, k=key: self.reset_one(k))
                self.resets[key] = reset
                for s_ in (w, f):
                    s_.valueChanged.connect(lambda _=0, k=key: self._mark_reset(k))
                box = QWidget()
                bl = QHBoxLayout(box)
                bl.setContentsMargins(0, 0, 0, 0)
                bl.addWidget(w)
                bl.addWidget(f)
                bl.addWidget(reset)
                bl.addStretch()
                self.form.addRow(db.THRESHOLD_LABELS.get(key, key), box)
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

        ov = QLabel("<b>Overrides</b>  (a vendor, location, folder or device can use different limits; "
                                        "device beats folder beats location beats vendor). A device can also carry its own limits "
                                        "(Inventory > Edit device > Checks); they beat everything here.")
        ov.setWordWrap(True)
        self.lay.insertWidget(2, ov)
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

    def reset_one(self, key):
        w, f = self.spins[key]
        w.setValue(db.DEFAULT_THRESHOLDS[key]["warn"])
        f.setValue(db.DEFAULT_THRESHOLDS[key]["fail"])

    def _mark_reset(self, key):
        """The Reset button is only there to press when the row differs from the default."""
        w, f = self.spins[key]
        d = db.DEFAULT_THRESHOLDS[key]
        self.resets[key].setEnabled(abs(w.value() - d["warn"]) > 1e-9 or abs(f.value() - d["fail"]) > 1e-9)

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
        w, f = TrimSpin(), TrimSpin()
        for s in (w, f):
            s.setRange(0, 1_000_000)
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
            self._mark_reset(key)
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

    def describe_extra(self):
        """The override table, for the list of changes shown before saving."""
        return [(f"Override: {r['scope']} / {db.THRESHOLD_LABELS.get(r['check'], r['check'])}", f"WARN {r['warn']:g} / FAIL {r['fail']:g}") for r in self._rules()]

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
class ChecksListPage(Page):
    """Which checks run (the list, by kind of device). It is the first tab of the Checks page."""
    title = "Checks"

    def __init__(self):
        super().__init__()
        self.lay.insertWidget(0, note("Untick a check to stop running it. This saves time on devices that "
                                      "do not have the feature (for example BGP on a switch). A single device can have its own list: "
                                      "Inventory > Edit device > Checks. Devices without one use this list."))
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.collapse_all, self.expand_all = QPushButton("Collapse all"), QPushButton("Expand all")
        self.collapse_all.setToolTip("Fold every group, to see the list of device types")
        self.expand_all.setToolTip("Open every group, to see all of its checks")
        self.collapse_all.clicked.connect(self.tree.collapseAll)
        self.expand_all.clicked.connect(self.tree.expandAll)
        bar = QHBoxLayout()
        bar.addWidget(self.expand_all)
        bar.addWidget(self.collapse_all)
        bar.addStretch()
        self.lay.insertLayout(1, bar)
        self.lay.insertWidget(2, self.tree, 1)

    def load(self):
        off = set(db.get_setting("disabled_checks"))
        self.tree.clear()
        for vendor, items in checks.CATALOG.items():
            top = QTreeWidgetItem([display.type_name(vendor)])
            self.tree.addTopLevelItem(top)
            for key, label in items:
                it = QTreeWidgetItem([label])
                it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                it.setCheckState(0, Qt.CheckState.Unchecked if checks.key(vendor, key) in off
                                 else Qt.CheckState.Checked)
                it.setData(0, Qt.ItemDataRole.UserRole, checks.key(vendor, key))
                top.addChild(it)
            top.setExpanded(True)

    def describe_extra(self):
        """Every check, on or off, for the list of changes shown before saving."""
        rows = []
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            for j in range(top.childCount()):
                it = top.child(j)
                rows.append((f"{top.text(0)}: {it.text(0)}", "on" if it.checkState(0) == Qt.CheckState.Checked else "off"))
        return rows

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
        self.sweep = QCheckBox("Also check the HTTPS certificate of every device, and warn before it expires")
        self.sweep_ports = QLineEdit()
        self.sweep_ports.setPlaceholderText("443, 8443")
        self.sweep_ports.setToolTip("Ports to look for a certificate on. A device with nothing listening there is simply skipped.")
        for label, w in (("", self.enabled), ("Every", self.minutes), ("Devices", self.groups),
                         ("", self.on_start), ("", self.sweep), ("Certificate ports", self.sweep_ports)):
            self.form.addRow(label, w)
        self.sweep.toggled.connect(self.sweep_ports.setEnabled)
        self.lay.insertWidget(1, note("Scheduled runs happen only while Toner is open. Each run is saved "
                                      "to History like a manual one. If a run is still going when the next is "
                                      "due, that one is skipped."))

    def load(self):
        self.enabled.setChecked(bool(db.get_setting("schedule_enabled")))
        self.minutes.setValue(int(db.get_setting("schedule_minutes")))
        self.groups.set_labels(db.group_labels()[1:])
        self.groups.set_selected(db.get_setting("schedule_groups"))
        self.on_start.setChecked(bool(db.get_setting("schedule_on_start")))
        self.sweep.setChecked(bool(db.get_setting("tls_sweep")))
        self.sweep_ports.setText(db.get_setting("tls_sweep_ports"))
        self.sweep_ports.setEnabled(self.sweep.isChecked())

    def refresh(self):
        keep = self.groups.selected()
        self.groups.set_labels(db.group_labels()[1:])
        self.groups.set_selected(keep)

    def save(self):
        db.set_setting("schedule_enabled", self.enabled.isChecked())
        db.set_setting("schedule_minutes", self.minutes.value())
        db.set_setting("schedule_groups", self.groups.selected())
        db.set_setting("schedule_on_start", self.on_start.isChecked())
        db.set_setting("tls_sweep", self.sweep.isChecked())
        db.set_setting("tls_sweep_ports", ", ".join(str(p) for p in custom.sweep_ports(self.sweep_ports.text())))


# ------------------------------------------------------------------ Checks: the list, when they run, and the ones you write
class ChecksPage(Page):
    """One page, three tabs: Checks (which run), Schedule (when they run, and the certificate check) and Custom (checks you write)."""
    title = "Checks"
    TABS = ("Checks", "Schedule", "Custom")

    def __init__(self):
        super().__init__()
        from ui.settings_pages.checks import CustomChecksPage
        self.list, self.schedule, self.custom = ChecksListPage(), AutomationPage(), CustomChecksPage()
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        for name, page in zip(self.TABS, (self.list, self.schedule, self.custom)):
            self.tabs.addTab(page, name)
        self.lay.insertWidget(0, self.tabs, 1)
        self.tree, self.collapse_all, self.expand_all = self.list.tree, self.list.collapse_all, self.list.expand_all       # the list's own parts, as before

    def pages(self):
        return (self.list, self.schedule, self.custom)

    def select_tab(self, name):
        """Open the Checks, Schedule or Custom tab (any case; 'Custom checks' and 'Automation' work too)."""
        want = {"automation": "Schedule", "custom checks": "Custom"}.get(name.lower(), name).lower()
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i).lower() == want:
                self.tabs.setCurrentIndex(i)
                return True
        return False

    def context_of(self, widget):
        """Which tab a setting is on, so the list of changes can say 'Schedule: Every' and not just 'Every'."""
        for name, page in zip(self.TABS, self.pages()):
            if page is widget or page.isAncestorOf(widget):
                return "" if page is self.list else name
        return ""

    def load(self):
        for p in self.pages():
            p.load()

    def validate(self):
        return [x for p in self.pages() for x in p.validate()]

    def save(self):
        for p in self.pages():
            p.save()

    def refresh(self):
        for p in self.pages():
            p.refresh()

    def describe_extra(self):
        return self.list.describe_extra()
