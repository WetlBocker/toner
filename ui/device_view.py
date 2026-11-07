"""Everything about one device in one window: details, latest checks, history, configuration, and quick actions."""
import json

from PySide6.QtCore import QThread, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFontDatabase
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QDialog, QFormLayout, QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit,
                               QPushButton, QStackedWidget, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget)
from core import backup, db, display, perms, profiles, sessions, snmp, unifikids, vendors
from core.runner import run_one
from ui.configs import DiffHighlighter
from ui.history import ChartStack, _table as history_table, draw_over_time
from ui.widgets import GroupPicker, StatusDelegate
from ui import chartspec, status as st
from ui.webchart import ChartView


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


class DeviceSummary(QWidget):
    """A device's facts (status, version, folder, location, tags...) beside its latest checks. The device window's Overview tab,
    and the details pane on the Inventory."""

    def __init__(self, stacked=False):
        super().__init__()
        self.dev = None
        self.stacked = stacked                              # the pane shows the status as a chip above, so its facts leave the Status row out
        self.info = QFormLayout()
        info_w = QWidget()
        info_w.setLayout(self.info)
        self.checks = QTableWidget(0, 4)
        self.checks.setHorizontalHeaderLabels(["Check", "Status", "Value", "Message"])
        DeviceView._table(self.checks)
        self.checks.setItemDelegateForColumn(1, StatusDelegate(self.checks))
        self.checks_title = QLabel("<b>Latest checks</b>")
        if stacked:                                                 # the pane: facts above the checks
            lay = QVBoxLayout(self)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.addWidget(info_w)
            lay.addWidget(self.checks_title)
            lay.addWidget(self.checks, 1)
        else:                                                       # the window: side by side
            lay = QHBoxLayout(self)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.addWidget(info_w, 2)
            right = QVBoxLayout()
            right.addWidget(self.checks_title)
            right.addWidget(self.checks, 1)
            lay.addLayout(right, 3)

    def set_device(self, dev):
        self.dev = dev
        self._fill_info()
        self._fill_checks()

    def _fill_info(self):
        while self.info.rowCount():
            self.info.removeRow(0)
        d = self.dev
        if d.get("kid"):                                    # a console's device: a view, with no record of its own to describe
            self.info.addRow(QLabel("<span style='color:gray'>Status</span>"), QLabel(f"{d['kid']['status']}  ({d['kid']['last_seen']})"))
            return
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
                ("Version", display.software_line(db.software_of(d), long=True)),     # "17.09.04a (INSTALL mode, ...), read 26 Oct 2026 at 14:02"
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
        if self.stacked:
            rows = [r for r in rows if r[0] != "Status"]
        for k, v in rows:
            if v:
                lab = QLabel(v)
                if k == "Status" and health and health["status"] in ("WARN", "FAIL", "ERROR"):
                    lab.setStyleSheet(f"font-weight: 600; color: {st.ink(health['status'])};")
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
        """The device's own latest rows: a UniFi console's devices have pages of their own, so their rows are theirs, not the console's."""
        kid = self.dev.get("kid")
        if kid:
            return unifikids.rows_for(kid["parent"], kid["key"])
        name = self.dev["name"]
        theirs = unifikids.labels(self.dev)
        runs = [r for r in db.list_runs(60)]
        for r in runs:
            rows = [x for x in db.run_results(r["id"]) if (x["device"] or "").split(" / ")[0] == name
                    and x["check_name"] != "config backup" and (x["device"] or "").partition(" / ")[2] not in theirs]
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


class DeviceView(QDialog):
    ssh_requested = Signal(dict)
    rdp_requested = Signal(dict)
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
        self.mark = QLabel()                               # the maker's mark beside the name
        self.mark.setFixedSize(40, 40)
        self.mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        names = QVBoxLayout()
        names.setSpacing(0)
        names.addWidget(self.title)
        names.addWidget(self.sub)
        head = QHBoxLayout()
        head.setSpacing(10)
        head.addWidget(self.mark, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addLayout(names, 1)
        actions = QHBoxLayout()
        self.buttons = {}
        for key, text in (("checks", "Run checks"), ("backup", "Back up config"), ("ssh", "SSH session"), ("rdp", "Remote Desktop"), ("services", "Services"), ("ping", "Ping"),
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

        self.summary = DeviceSummary()                 # the facts and the latest checks (the Inventory's details pane shows the same)
        self.info, self.checks = self.summary.info, self.summary.checks
        self.gauges = QWidget()                        # the latest readings that have limits (CPU, memory, disk...), as dials
        self.gauges_lay = QHBoxLayout(self.gauges)
        self.gauges_lay.setContentsMargins(0, 0, 0, 0)
        self.gauges_lay.setSpacing(8)
        self._gauges = []
        over = QWidget()
        ol = QVBoxLayout(over)
        ol.setContentsMargins(0, 0, 0, 0)
        ol.addWidget(self.gauges)
        ol.addWidget(self.summary, 1)

        self.pick = GroupPicker(all_text="Choose checks", noun="checks", clear_text="Clear selection")
        self.chart = ChartStack()
        self.over_chart = ChartView(min_height=240)            # a status check: how often each status happened, by day (as on History)
        self.over_chart.setAccessibleName("Values over time")
        self.over_table = history_table(["Device", "Value", "Checked"])     # a text check: each time its value changed
        self.over_table.setAccessibleName("Values over time")
        self.over_stack = QStackedWidget()
        for w_ in (self.chart, self.over_chart, self.over_table):
            self.over_stack.addWidget(w_)
        hist = QWidget()
        hl = QVBoxLayout(hist)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Checks"))
        bar.addWidget(self.pick)
        bar.addStretch()
        hl.addLayout(bar)
        hl.addWidget(self.over_stack, 1)
        self.pick.changed.connect(self.draw)
        self.trend = ChartView(min_height=260)         # the same checks as areas over time, with the limits as dashed lines
        self.trend.setAccessibleName("Trend of the chosen checks")
        trend_tab = QWidget()
        tl = QVBoxLayout(trend_tab)
        tl.setContentsMargins(0, 8, 0, 0)
        self.trend_note = QLabel("The checks chosen on the History tab, over time. Hover for the values at a moment.")
        self.trend_note.setProperty("muted", True)
        self.trend_note.setWordWrap(True)
        tl.addWidget(self.trend_note)
        tl.addWidget(self.trend, 1)

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
        self.tabs.addTab(trend_tab, "Trends")
        self.tabs.addTab(cfgw, "Configuration")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(10)
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
        d = db.get_device(self.dev["id"], self.dev.get("org")) if self.dev.get("id") else None
        if d:
            self.dev = d
        d = self.dev
        plat = vendors.mode_label(d["vendor"]) or (display.platform_name(d.get("platform")) if d.get("platform") else "")
        self.title.setText(d["name"])
        self.sub.setText(f"{display.vendor_name(d['vendor'])} {plat}  -  {d['host']}" + (f":{d['port']}" if d.get("port") else ""))
        from ui import brandicons
        self.mark.setPixmap(brandicons.vendor_icon(d["vendor"]).pixmap(36, 36))
        self.mark.setToolTip(display.vendor_name(d["vendor"]))
        self.buttons["ssh"].setEnabled(vendors.ssh_reachable(d["vendor"]))
        self.buttons["ssh"].setVisible(d["vendor"] != "windows" and perms.allowed("tool:sessions"))
        self.buttons["rdp"].setVisible(d["vendor"] == "windows" and perms.allowed("tool:rdp"))
        self.buttons["ping"].setVisible(perms.allowed("tool:ping"))
        self.buttons["snmp"].setVisible(perms.allowed("tool:snmp"))
        self.buttons["services"].setVisible(d["vendor"] == "windows")
        self.buttons["services"].setToolTip("List the computer's services, and start, stop or restart them")
        self.buttons["backup"].setEnabled(backup.supported(d))
        self.buttons["snmp"].setEnabled(profiles.snmp_configured(d) or vendors.is_snmp(d["vendor"]))
        self.buttons["web"].setEnabled(True)
        if d.get("kid"):                                     # a console's device: dials, history and trends only
            self.title.setText(unifikids.shown_name(d["kid"]))
            self.setWindowTitle(self.title.text())
            self.sub.setText("  -  ".join(x for x in (d["kid"]["model"], d["kid"]["parent"]["name"]) if x))
            for b in self.buttons.values():
                b.setVisible(False)
            self.tabs.setTabVisible(3, False)
        self._fill_info()
        self._fill_checks()
        self._fill_history()
        if not d.get("kid"):
            self._fill_versions()

    def _fill_info(self):
        self.summary.dev = self.dev
        self.summary._fill_info()

    _own_settings = DeviceSummary._own_settings

    def _latest_rows(self):
        self.summary.dev = self.dev
        return self.summary._latest_rows()

    def _fill_checks(self):
        self.summary.dev = self.dev
        self.summary._fill_checks()
        self._fill_gauges()

    GAUGED = ("cpu", "memory", "disk", "storage", "temperature", "utilization", "sessions", "channel_util", "load")

    def _fill_gauges(self):
        """A dial for each of the latest readings that is a percentage (or has limits in Settings > Thresholds): CPU, memory, disk and
        the like. Nothing with a number means no dials and no empty strip."""
        for g in self._gauges:
            g.setParent(None)
            g.deleteLater()
        self._gauges = []
        th = db.thresholds_for(self.dev)
        shown = 0
        for r in self._latest_rows():
            base = (r["check_name"] or "").split(" (")[0]
            key = next((k for k in self.GAUGED if base == k or base.startswith(k + " ") or base.startswith(k + "_")), None)
            if key is None or r.get("numeric") is None or shown >= 6:
                continue
            limits = th.get(key) or th.get(base) or {}
            value = float(r["numeric"])
            pct = "%" in (r.get("value") or "") or key in ("cpu", "memory", "disk", "storage", "utilization", "sessions", "channel_util")
            maximum = 100 if pct else max(value * 1.25, float(limits.get("fail") or 0) * 1.1, 1)
            unit = "%" if pct else (" °C" if key == "temperature" else "")
            title = display.check_name(r["check_name"])
            g = ChartView(min_height=150)
            g.setMaximumHeight(170)
            g.setFixedWidth(210)
            g.setAccessibleName(f"{title} dial")
            g.draw(lambda p, v=value, w=limits.get("warn"), f=limits.get("fail"), t=title, u=unit, m=maximum:
                   chartspec.gauge(p, v, warn=w or None, fail=f or None, title=t, unit=u, maximum=m))
            self.gauges_lay.addWidget(g)
            self._gauges.append(g)
            shown += 1
        if shown and not getattr(self, "_gauge_stretch", False):
            self.gauges_lay.addStretch(1)                          # the dials sit together on the left, as the facts do
            self._gauge_stretch = True
        self.gauges.setVisible(shown > 0)

    def restyle(self):
        for g in self._gauges + [self.trend, self.over_chart]:
            g.restyle()

    def _fill_history(self):
        keep = self.pick.selected()
        checks = (db.device_all_checks() if self.dev.get("kid") else db.device_checks()).get(self.dev["name"], [])
        self.keys = {display.check_name(c): c for c in checks}
        self.pick.set_labels(list(self.keys))
        keep = [k for k in keep if k in self.keys] or list(self.keys)[:1]
        self.pick.set_selected(keep)
        self.draw()

    def draw(self, *_):
        picked = [self.keys[k] for k in self.pick.selected() if k in self.keys]
        th = db.thresholds_for(self.dev)
        series = draw_over_time(self.dev["name"], picked, th, self.chart, self.over_chart, self.over_table, self.over_stack)
        self._draw_trend(series, th.get(picked[0].split(" (")[0]) if picked else None)

    def _draw_trend(self, series, limits):
        """The Trends tab: every picked check as an area over time; the first check's limits as dashed lines when all share a scale."""
        series = [(display.check_name(c), pts) for c, pts in series if pts]
        if not series:
            self.trend.draw(lambda p: chartspec.empty("Choose checks on the History tab; a check with numbers is drawn here"))
            return
        times = sorted({t for _n, pts in series for t, _v in pts})
        index = {t: i for i, t in enumerate(times)}
        cols = []
        for name, pts in series:
            vals = [None] * len(times)
            for t, v in pts:
                vals[index[t]] = v
            cols.append((name, vals))
        from datetime import datetime
        stamps = []
        for t in times:
            try:
                stamps.append(datetime.strptime(str(t)[:19], "%Y-%m-%d %H:%M:%S") if not isinstance(t, datetime) else t)
            except ValueError:
                stamps.append(datetime.strptime(str(t)[:16], "%Y-%m-%d %H:%M"))
        one_scale = len(cols) == 1
        warn = fail = None
        if limits and one_scale:
            warn, fail = limits.get("warn") or None, limits.get("fail") or None
            if limits.get("warn", 0) and limits.get("fail", 0) and limits["warn"] > limits["fail"]:        # lower is worse (uptime): no bands
                warn = fail = None
        self.trend.draw(lambda p: chartspec.area(p, stamps, cols, warn=warn, fail=fail, stacked=False))

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
            self.rdp_requested.emit(d)
        elif key == "services":
            self.open_services()
        elif key == "ping":
            self.tool_requested.emit("ping", d)
        elif key == "snmp":
            self.tool_requested.emit("snmp", d)
        elif key == "web":
            QDesktopServices.openUrl(QUrl(f"https://{d['host']}" + (f":{d['port']}" if d.get("port") else "")))
        elif key == "edit":
            self.edit_requested.emit(d)

    def open_services(self):
        """The computer's services in a window of their own (one per device; asking again brings it back)."""
        from ui.serviceswindow import ServicesDialog
        win = getattr(self, "services_window", None)
        if win is None or not win.isVisible():
            self.services_window = win = ServicesDialog(self.dev, self)
        win.show()
        win.raise_()
        win.activateWindow()
        return win

    def _run(self, fn, done, text):
        if self.job and self.job.isRunning():
            return
        for k in ("checks", "backup"):
            self.buttons[k].setEnabled(False)
        self.status.setText(text)
        org = self.dev.get("org")
        def in_org():
            with db.within(org):                         # its passwords, baselines and history are in its own file
                return fn()
        self.job = _Job(in_org)
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
        bad = sum(1 for r in res if r.status not in ("OK", "N/A"))
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


def _in_own_org(fn):
    """Run a DeviceView method inside the device's own organization's file, where its name is its key (Global lists every
    organization, so the same name can belong to two devices there)."""
    def wrapped(self, *a, **k):
        with db.within(self.dev.get("org")):
            return fn(self, *a, **k)
    wrapped.__name__, wrapped.__doc__ = fn.__name__, fn.__doc__
    return wrapped


for _name in ("reload", "_fill_info", "_latest_rows", "_fill_checks", "_fill_history", "draw", "_fill_versions", "show_config",
              "_checks_done", "_backup_done"):
    setattr(DeviceView, _name, _in_own_org(getattr(DeviceView, _name)))
