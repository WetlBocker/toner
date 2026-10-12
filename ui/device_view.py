"""Everything about one device in one window: details, latest checks, history, configuration, and quick actions."""
import json

from PySide6.QtCore import QThread, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFontDatabase
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QDialog, QFormLayout, QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit,
                               QPushButton, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget)
from core import backup, db, display, profiles, sessions, snmp, vendors
from core.runner import run_one
from ui.configs import DiffHighlighter
from ui.history import ChartStack
from ui.widgets import GroupPicker, StatusDelegate


class _Job(QThread):
    done = Signal(object)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            self.done.emit(self.fn())
        except Exception as e:
            self.done.emit(e)


class DeviceView(QDialog):
    ssh_requested = Signal(dict)
    tool_requested = Signal(str, dict)          # 'ping' | 'snmp' | 'tls' | 'mtr', device
    edit_requested = Signal(dict)
    changed = Signal()                          # a run or backup was done from here

    def __init__(self, dev, parent=None):
        super().__init__(parent)
        self.dev = dev
        self.job = None
        self.setWindowTitle(dev["name"])
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        self.resize(900, 640)
        self.setModal(False)

        self.title = QLabel(dev["name"])
        self.title.setProperty("title", True)
        self.sub = QLabel("")
        self.sub.setProperty("muted", True)
        head = QVBoxLayout()
        head.setSpacing(0)
        head.addWidget(self.title)
        head.addWidget(self.sub)
        actions = QHBoxLayout()
        self.buttons = {}
        for key, text in (("checks", "Run checks"), ("backup", "Back up config"), ("ssh", "SSH session"), ("rdp", "Remote Desktop"), ("ping", "Ping"),
                          ("snmp", "SNMP"), ("web", "Open web page"), ("edit", "Edit...")):
            b = QPushButton(text)
            b.setAutoDefault(False)                     # Enter must not trigger whichever button comes first
            if key == "checks":
                b.setProperty("primary", True)
            b.clicked.connect(lambda _=False, k=key: self.act(k))
            actions.addWidget(b)
            self.buttons[key] = b
        actions.addStretch()
        self.status = QLabel("")
        self.status.setProperty("muted", True)

        self.info = QFormLayout()
        info_w = QWidget()
        info_w.setLayout(self.info)
        self.checks = QTableWidget(0, 4)
        self.checks.setHorizontalHeaderLabels(["Check", "Status", "Value", "Message"])
        self._table(self.checks)
        self.checks.setItemDelegateForColumn(1, StatusDelegate(self.checks))
        over = QWidget()
        ol = QHBoxLayout(over)
        ol.addWidget(info_w, 2)
        right = QVBoxLayout()
        right.addWidget(QLabel("<b>Latest checks</b>"))
        right.addWidget(self.checks, 1)
        ol.addLayout(right, 3)

        self.pick = GroupPicker(all_text="Choose checks", noun="checks", clear_text="Clear selection")
        self.chart = ChartStack()
        hist = QWidget()
        hl = QVBoxLayout(hist)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Checks"))
        bar.addWidget(self.pick)
        bar.addStretch()
        hl.addLayout(bar)
        hl.addWidget(self.chart, 1)
        self.pick.changed.connect(self.draw)

        self.versions = QComboBox()
        self.cfg_view = QComboBox()
        self.cfg_view.addItem("Changes from the previous version", "diff")
        self.cfg_view.addItem("Full configuration", "full")
        self.cfg = QPlainTextEdit()
        self.cfg.setReadOnly(True)
        self.cfg.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.cfg.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.highlighter = DiffHighlighter(self.cfg.document())
        cfgw = QWidget()
        cl = QVBoxLayout(cfgw)
        cb = QHBoxLayout()
        for w in (QLabel("Version"), self.versions, QLabel("Show"), self.cfg_view):
            cb.addWidget(w, 1 if isinstance(w, QComboBox) else 0)
        cl.addLayout(cb)
        cl.addWidget(self.cfg, 1)
        self.versions.currentIndexChanged.connect(self.show_config)
        self.cfg_view.currentIndexChanged.connect(self.show_config)

        self.tabs = QTabWidget()
        self.tabs.addTab(over, "Overview")
        self.tabs.addTab(hist, "History")
        self.tabs.addTab(cfgw, "Configuration")
        lay = QVBoxLayout(self)
        lay.addLayout(head)
        lay.addLayout(actions)
        lay.addWidget(self.status)
        lay.addWidget(self.tabs, 1)
        self.reload()

    @staticmethod
    def _table(t):
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.verticalHeader().setVisible(False)
        t.setShowGrid(False)
        t.horizontalHeader().setStretchLastSection(True)

    # ---------- content
    def reload(self):
        d = db.get_device(self.dev["id"]) if self.dev.get("id") else None
        if d:
            self.dev = d
        d = self.dev
        info = vendors.get(d["vendor"])
        plat = vendors.mode_label(d["vendor"]) or (display.platform_name(d.get("platform")) if d.get("platform") else "")
        self.title.setText(d["name"])
        self.sub.setText(f"{display.vendor_name(d['vendor'])} {plat}  -  {d['host']}" + (f":{d['port']}" if d.get("port") else ""))
        self.buttons["ssh"].setEnabled(info.get("kind") == "ssh")
        self.buttons["ssh"].setVisible(d["vendor"] != "windows")
        self.buttons["rdp"].setVisible(d["vendor"] == "windows")
        self.buttons["backup"].setEnabled(backup.supported(d))
        self.buttons["snmp"].setEnabled(profiles.snmp_configured(d) or vendors.is_snmp(d["vendor"]))
        self.buttons["web"].setEnabled(True)
        self._fill_info()
        self._fill_checks()
        self._fill_history()
        self._fill_versions()

    def _fill_info(self):
        while self.info.rowCount():
            self.info.removeRow(0)
        d = self.dev
        prof = (profiles.get(d.get("profile_id")) or {}).get("name", "")
        try:
            jump = json.loads(d.get("jump") or "{}").get("device", "")
        except ValueError:
            jump = ""
        try:
            fields = json.loads(d.get("fields") or "{}")
        except ValueError:
            fields = {}
        health = db.device_health().get(d["name"])
        rows = [("Status", (health["status"] + f"  ({health['at']})") if health else "no results yet"),
                ("Checks and limits", self._own_settings(d)),
                ("Folder", db.folder_paths().get(d.get("folder_id"), "(top level)")),
                ("Location", d.get("location") or ""), ("Tags", d.get("tags") or ""),
                ("Credential profile", prof), ("Jump host", jump),
                ("SNMP", "configured" if profiles.snmp_configured(d) else ""),
                ("Enabled", "yes" if d.get("enabled", 1) else "no (checks skip this device)"), ("Notes", d.get("details") or "")]
        rows += [(k, str(v)) for k, v in fields.items()]
        s = backup.summary().get(d["name"])
        if s:
            rows.append(("Configuration", f"{s['versions']} version(s), last backup {s.get('last', '')}"))
        for k, v in rows:
            if v:
                lab = QLabel(v)
                if k == "Status" and health and health["status"] in ("WARN", "FAIL", "ERROR"):
                    lab.setStyleSheet("font-weight: 600; color: " + {"WARN": "#e0a100", "FAIL": "#d32f2f", "ERROR": "#8e44ad"}[health["status"]] + ";")
                lab.setWordWrap(True)
                lab.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                self.info.addRow(QLabel(f"<span style='color:gray'>{k}</span>"), lab)

    @staticmethod
    def _own_settings(d):
        """Whether this device follows the global checks and limits or has its own (Edit > Checks)."""
        from core import checks
        own = db.normalize_checkopts(d.get("checkopts"))
        if not own:
            return "Global checks and limits"
        labels = dict(checks.CATALOG.get(d["vendor"], []))
        parts = []
        if "checks" in own:
            parts.append("runs only: " + (", ".join(labels.get(c, c) for c in own["checks"]) or "nothing"))
        if "thresholds" in own:
            parts.append("own limits: " + ", ".join(f"{db.THRESHOLD_LABELS.get(k, k)} {p['warn']:g}/{p['fail']:g}" for k, p in own["thresholds"].items()))
        return "; ".join(parts)

    def _latest_rows(self):
        name = self.dev["name"]
        runs = [r for r in db.list_runs(60)]
        for r in runs:
            rows = [x for x in db.run_results(r["id"]) if (x["device"] or "").split(" / ")[0] == name
                    and x["check_name"] != "config backup"]
            if rows:
                return rows
        return []

    def _fill_checks(self):
        rows = self._latest_rows()
        rows.sort(key=lambda r: (-{"OK": 0, "WARN": 1, "FAIL": 2, "ERROR": 3}.get(r["status"], 0), r["device"], r["check_name"]))
        self.checks.setRowCount(len(rows))
        for i, r in enumerate(rows):
            label = display.check_name(r["check_name"]) if r["device"] == self.dev["name"] else \
                f"{r['device'].split(' / ', 1)[1]}: {display.check_name(r['check_name'])}"
            for j, v in enumerate([label, r["status"], display.value(r["value"]), r["message"] or ""]):
                self.checks.setItem(i, j, QTableWidgetItem(v))
        self.checks.resizeColumnsToContents()

    def _fill_history(self):
        keep = self.pick.selected()
        checks = db.device_checks().get(self.dev["name"], [])
        self.keys = {display.check_name(c): c for c in checks}
        self.pick.set_labels(list(self.keys))
        keep = [k for k in keep if k in self.keys] or list(self.keys)[:1]
        self.pick.set_selected(keep)
        self.draw()

    def draw(self, *_):
        picked = [self.keys[k] for k in self.pick.selected() if k in self.keys]
        self.chart.set_series([(c, db.series(self.dev["name"], c)) for c in picked],
                              db.thresholds_for(self.dev).get(picked[0].split(" (")[0]) if picked else None)

    def _fill_versions(self):
        self.versions.blockSignals(True)
        self.versions.clear()
        self.vers = backup.list_backups(self.dev["name"])
        for v in self.vers:
            self.versions.addItem(f"{v['taken_at']}   +{v['added']} / -{v['removed']}" if v is not self.vers[-1] else f"{v['taken_at']}   (first copy)", v["id"])
        self.versions.blockSignals(False)
        self.show_config()

    def show_config(self, *_):
        if not self.vers:
            self.cfg.setPlainText("No configuration backed up yet." if backup.supported(self.dev)
                                  else "Not available: " + backup.why_unsupported(self.dev))
            return
        i = max(0, self.versions.currentIndex())
        v = self.vers[i]
        if self.cfg_view.currentData() == "diff" and i + 1 < len(self.vers):
            lines, a, r = backup.diff_lines(backup.get_text(self.vers[i + 1]["id"]), backup.get_text(v["id"]),
                                            self.vers[i + 1]["taken_at"], v["taken_at"])
            self.cfg.setPlainText("\n".join(lines) or "No difference.")
        elif self.cfg_view.currentData() == "diff":
            self.cfg.setPlainText("This is the first copy; switch to 'Full configuration' to read it.")
        else:
            self.cfg.setPlainText(backup.get_text(v["id"]))

    # ---------- actions
    def act(self, key):
        d = self.dev
        if key == "checks":
            self._run(lambda: run_one(profiles.resolve(d), db.thresholds_for(d), db.runtime_options()), self._checks_done, "Running checks...")
        elif key == "backup":
            self._run(lambda: backup.backup_device(d), self._backup_done, "Backing up...")
        elif key == "ssh":
            self.ssh_requested.emit(d)
        elif key == "rdp":
            try:
                sessions.launch_rdp(sessions.rdp_for_device(d))
            except OSError as e:
                QMessageBox.warning(self, "Remote Desktop", str(e))
        elif key == "ping":
            self.tool_requested.emit("ping", d)
        elif key == "snmp":
            self.tool_requested.emit("snmp", d)
        elif key == "web":
            QDesktopServices.openUrl(QUrl(f"https://{d['host']}" + (f":{d['port']}" if d.get("port") else "")))
        elif key == "edit":
            self.edit_requested.emit(d)

    def _run(self, fn, done, text):
        if self.job and self.job.isRunning():
            return
        for k in ("checks", "backup"):
            self.buttons[k].setEnabled(False)
        self.status.setText(text)
        self.job = _Job(fn)
        self.job.done.connect(done)
        self.job.start()

    def _enable(self):
        self.buttons["checks"].setEnabled(True)
        self.buttons["backup"].setEnabled(backup.supported(self.dev))

    def _checks_done(self, res):
        self._enable()
        if isinstance(res, Exception):
            self.status.setText(f"Failed: {res}")
            return
        db.save_run(res)
        bad = sum(1 for r in res if r.status != "OK")
        self.status.setText(f"{len(res)} check(s) done, {bad} not OK.")
        self.reload()
        self.changed.emit()

    def _backup_done(self, res):
        self._enable()
        if isinstance(res, Exception):
            self.status.setText(f"Failed: {res}")
            return
        self.status.setText(f"Backup: {res.status} {res.value} {res.message}".strip())
        db.save_run([res])
        self.reload()
        self.changed.emit()

    def closeEvent(self, e):
        if self.job and self.job.isRunning():
            self.job.wait(5000)
        super().closeEvent(e)
