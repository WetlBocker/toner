"""Over time: one panel per ticked check, each drawn as its own kind (core.chartkinds): lines (checks of one scale share a panel), a
status heatmap with the readings of a selected square underneath, tables, gauges, the patches wheel and the configuration versions.
The History page's Over time tab and the device page's History tab share it. A panel is drawn when it first scrolls into view."""
import re
from datetime import datetime, timedelta

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QComboBox, QFrame, QHBoxLayout, QLabel, QPlainTextEdit, QScrollArea, QVBoxLayout, QWidget

from core import backup, db, display, heatgrid
from core.chartkinds import over_time_kind, shown_name
from core.firmware import human_size
from ui import chartspec
from ui.configs import DiffHighlighter
from ui.detaillist import DetailList
from ui.history import ChartStack, restarts, scale_key
from ui.webchart import ChartView
from ui.widgets import FlowLayout, GroupPicker

EMPTY = "No readings in this time range"
HINT = "Select a square to see what happened then"
OLD_AGENT = "Not reported by this computer's agent yet"
NOT_REPORTED = "Not reported by this computer"
SEARCHED = "Windows last searched for updates on {date}"
DETAIL = [("t", "Time"), ("device", "Device"), ("status", "Status"), ("value", "Value"), ("message", "Message")]
CHANGES = [("t", "Checked"), ("status", "Status"), ("value", "Value"), ("message", "Message")]
UPTIME = [("restarted", "Restarted (about)"), ("up", "Had been up for")]
HA = [("t", "Checked"), ("ha", "HA"), ("sync", "HA sync")]
CONFIG = [("t", "Saved"), ("changed", "Changed")]
CERTS = [("name", "Certificate"), ("expires", "Expires"), ("days", "Days left"), ("where", "Found in")]
PATCHES = [("name", "Update"), ("kb", "KB"), ("severity", "Severity")]
SEVERITIES = ("Critical", "Important", "Moderate", "Low", "Unrated")
RANK = {"OK": 1, "WARN": 2, "FAIL": 3, "ERROR": 3}           # a square takes the worst status in it
PLACEHOLDER = 260                                            # a panel's height until it is drawn, so later panels start below the view
STAMP = "%Y-%m-%d %H:%M:%S"


def _when(t):
    try:
        return datetime.strptime(str(t)[:19], STAMP)
    except ValueError:
        return None


def _severity_colour(p, s):
    return {"Critical": chartspec.status_color(p, "FAIL"), "Important": chartspec.status_color(p, "WARN"), "Moderate": p["series"][3],
            "Low": p["accent"]}.get(s, chartspec.status_color(p, "N/A"))


def _found(where):
    """Where a certificate was found: 'store' -> 'Certificate store', 'port 443' -> 'Port 443'."""
    m = re.fullmatch(r"port (\d+)", where or "")
    return "Certificate store" if where == "store" else f"Port {m.group(1)}" if m else where or ""


def cert_rows(check, last, items):
    """The certificates table's rows from a certificate check's newest row and its items (Across devices shares it)."""
    if items is None:                                                  # stored before each certificate was kept: the row itself,
        return [] if last is None or last["numeric"] is None else [{"name": display.check_name(check), "days": last["numeric"]}]   # unless it holds none (an error)
    return [{"name": it["name"], "expires": it["data"].get("expires", ""), "days": None if it["numeric"] is None else int(it["numeric"]),
             "where": _found(it["data"].get("where"))} for it in items]


def _day(stamp):
    """An RFC 3339 time (UTC) as a local date, '8 Nov 2026'; unreadable: as it is."""
    try:
        d = datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).astimezone()
    except ValueError:
        return stamp
    return f"{d.day} {d:%b %Y}"


# ---------- the configuration versions (also the device page's Configuration tab)
def config_switch():
    box = QComboBox()
    box.addItem("Changes from the previous version", "diff")
    box.addItem("Full configuration", "full")
    return box


def config_text_view():
    view = QPlainTextEdit()
    view.setReadOnly(True)
    view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    view.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
    view.highlighter = DiffHighlighter(view.document())
    return view


def config_text(vers, i, mode):
    """Version i of backup.list_backups (newest first): its changes from the version before ("diff"), or all of it ("full")."""
    v = vers[i]
    if mode == "diff" and i + 1 < len(vers):
        old = vers[i + 1]
        lines, _a, _r = backup.diff_lines(backup.get_text(old["id"], old.get("org")), backup.get_text(v["id"], v.get("org")),
                                          old["taken_at"], v["taken_at"])
        return "\n".join(lines) or "No difference."
    if mode == "diff":
        return "This is the first copy; switch to 'Full configuration' to read it."
    return backup.get_text(v["id"], v.get("org"))


class Panel(QFrame):
    """One check's (or one scale's) panel: its name, then what its kind draws, filled in by `fill(panel)` when first shown."""

    def __init__(self, kind, checks, fill, key=None):
        super().__init__()
        self.kind, self.checks, self.fill, self.key, self.drawn = kind, list(checks), fill, key, False
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(0, 0, 0, 0)
        self.head = QLabel()
        font = QFont(self.head.font())
        font.setBold(True)
        self.head.setFont(font)
        self.lay.addWidget(self.head)
        self.text = None
        self.setMinimumHeight(PLACEHOLDER)

    def draw(self):
        self.drawn = True
        self.head.setText(", ".join(dict.fromkeys(display.check_name(shown_name(c)) for c in self.checks)))
        self.fill(self)
        for w in self.findChildren(QWidget, options=Qt.FindChildOption.FindDirectChildrenOnly):
            if not (w.isHidden() and w.testAttribute(Qt.WidgetAttribute.WA_WState_ExplicitShowHide)):
                w.setVisible(True)                                # now, so the panel has its height when the next ones are placed
        self.setMinimumHeight(0)

    def note(self, text):
        self.text = QLabel(text)
        self.text.setProperty("muted", True)
        self.text.setWordWrap(True)
        self.lay.addWidget(self.text)


class CheckPanels(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.Shape.NoFrame)
        self.body = QWidget()
        self.col = QVBoxLayout(self.body)
        self.col.setContentsMargins(0, 0, 0, 0)
        self.col.setSpacing(16)
        self.prompt = QLabel("Select one or more checks")
        self.prompt.setProperty("muted", True)
        self.col.addWidget(self.prompt)
        self.col.addStretch(1)
        self.setWidget(self.body)
        self.panels, self._series, self.th = [], {}, {}
        self.device, self.vendor, self._busy = "", "", False
        bar = self.verticalScrollBar()
        bar.valueChanged.connect(self._reveal)
        bar.rangeChanged.connect(self._reveal)

    # ---------- what to show
    def show_checks(self, device, vendor, checks, start, end, th):
        """Panels for `checks` (stored names, in the picker's order) of `device` (a key) between start and end (datetimes); with no
        checks, the prompt to pick some."""
        self.device, self.vendor, self.th = device, (vendor or "").lower(), th or {}
        self.start, self.end, self.s, self.e = start, end, start.strftime(STAMP), end.strftime(STAMP)
        for p in self.panels:
            p.hide()
            p.setParent(None)
            p.deleteLater()
        self.panels = []
        self.prompt.setVisible(not checks)
        kinds = {c: over_time_kind(c, self.vendor, db.check_rows(device, c, 20, end=self.e)) for c in checks}
        self._series = {c: db.series(device, c, start=self.s, end=self.e) for c in checks if kinds[c] in ("line", "gauges")}
        groups = {}
        for c in checks:
            groups.setdefault(shown_name(c), []).append(c)
        fills = {"heatmap": self._heatmap, "table": self._table, "gauges": self._gauges, "wheel": self._wheel, "config": self._config,
                 "uptime": self._uptime, "ha": self._ha, "certs": self._certs}
        for shown, names in groups.items():
            kind = kinds[names[0]]
            if kind == "hidden":
                continue
            if shown == "interface errors":
                panel = Panel(kind, names, self._interface_errors)
            elif kind == "line":
                key = scale_key(names[0], self._series[names[0]])
                last = self.panels[-1] if self.panels else None
                if last is not None and last.key == key:          # the same scale as the panel above: one chart
                    last.checks += names
                    continue
                panel = Panel(kind, names, self._lines, key)
            else:
                panel = Panel(kind, names, fills[kind])
            self.col.insertWidget(self.col.count() - 1, panel)
            panel.setVisible(True)                                # now, not at the next event-loop turn: the layout places shown widgets only
            self.panels.append(panel)
        self._reveal()

    def line_series(self):
        """[(check, [(time, value)])] for the ticked checks that are measurements, in the picker's order (the device page's Trends)."""
        return list(self._series.items())

    def restyle(self):
        for view in self.findChildren(ChartView):
            view.restyle()

    # ---------- drawing as they come into view
    def _reveal(self, *_):
        """Draw the panels that are in view; a panel that came out smaller than its placeholder may pull the next one into view."""
        if self._busy or not self.isVisible():
            return
        self._busy = True
        try:
            while True:
                self.col.activate()                               # place the panels now, as the scroll area would at its next turn
                self.body.resize(self.viewport().width(), max(self.viewport().height(), self.body.minimumSizeHint().height()))
                top = self.verticalScrollBar().value()
                bottom = top + self.viewport().height()
                todo = [p for p in self.panels if not p.drawn and p.y() < bottom and p.y() + p.height() > top]
                if not todo:
                    return
                for p in todo:
                    p.draw()
        finally:
            self._busy = False

    def showEvent(self, e):
        super().showEvent(e)
        self._reveal()

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._reveal()

    # ---------- the kinds
    def _rows(self, check):
        return db.check_rows(self.device, check, start=self.s, end=self.e)

    def _latest(self, check):
        """(the check's newest row, that row's items as db.latest_items gives them) whatever the range, or (None, None): gauges,
        certificates and the wheel show the latest reading."""
        rows = db.check_rows(self.device, check, 1)
        if not rows:
            return None, None
        t, items = db.latest_items(self.device, check)
        return rows[-1], (items if t == rows[-1]["t"] else None)

    def _lines(self, panel):
        series = [(c, self._series.get(c) or []) for c in panel.checks]
        marks = [(r["t"], r["numeric"] or 0) for r in self._rows("reachability") if r["status"] == "FAIL"] if "reachability" in panel.checks else []
        if not marks and not any(pts for _c, pts in series):
            return panel.note(EMPTY)
        panel.stack = ChartStack()
        panel.stack.setMinimumHeight(300)
        panel.stack.set_series(series, self.th.get(panel.checks[0].split(" (")[0]), marks=marks)
        panel.lay.addWidget(panel.stack)

    def _heatmap(self, panel):
        check = panel.checks[0]
        grid = panel.grid = heatgrid.layout(self.start, self.end)
        worst, panel.rows = {}, []
        for r in self._rows(check):
            t = _when(r["t"])
            xy = grid.cell(t) if t else None
            if xy is None:
                continue
            panel.rows.append((t, r))
            if RANK.get(r["status"], 0) >= RANK.get(worst.get(xy), -1):
                worst[xy] = r["status"]
        if not panel.rows:
            return panel.note(EMPTY)
        cells = [(x, y, s) for (x, y), s in worst.items()]
        panel.chart = ChartView(min_height=max(240, 60 + 16 * len(grid.rows)))     # 30 days: every date row tall enough to be labelled
        panel.chart.setAccessibleName(display.check_name(check))
        panel.chart.draw(lambda p: chartspec.status_heatmap(p, grid.cols, grid.rows, cells))
        panel.chart.clicked.connect(lambda hit: self._square(panel, hit))
        panel.lay.addWidget(panel.chart)
        panel.note(HINT)
        panel.detail = DetailList()
        panel.detail.setMinimumHeight(160)
        panel.detail.hide()
        panel.lay.addWidget(panel.detail)
        if self.vendor == "truenas" and shown_name(check) == "disks":     # each drive's temperature under its SMART squares
            self._item_lines(panel, check, "drives")

    def _square(self, panel, hit):
        """A heatmap square was selected: the readings in it, newest first."""
        v = hit.get("value") if hit.get("kind") == "series" else None
        if not (isinstance(v, list) and len(v) >= 2):
            return
        try:
            a, b = panel.grid.slot(int(v[0]), int(v[1]))
        except IndexError:
            return
        rows = [{"t": r["t"], "device": db.label_org(self.device), "status": r["status"], "value": display.value(r["value"]),
                 "message": r["message"] or ""} for t, r in reversed(panel.rows) if a <= t < b]
        panel.detail.show_rows(rows, DETAIL)
        panel.detail.show()
        panel.text.hide()

    def _interface_errors(self, panel):
        if not self._item_lines(panel, panel.checks[0], "interfaces"):
            panel.note(EMPTY)

    def _item_lines(self, panel, check, noun):
        """A line per item (an interface, a drive) from the items' numbers, with a picker of the items; an interface picker starts with
        those that have had errors. Rows from before items were kept draw the check's own number. False when there is nothing."""
        lines = {}
        for row in db.items_of(self.device, check, self.s, self.e):
            for it in row["items"] or []:
                if it["numeric"] is not None:
                    lines.setdefault(it["name"], []).append((row["t"], it["numeric"]))
        if not lines and self._series.get(check):
            lines = {display.check_name(shown_name(check)): self._series[check]}
        if not lines:
            return False
        panel.picker = GroupPicker(all_text=f"Choose {noun}", noun=noun, clear_text="Clear selection")
        panel.picker.set_labels(sorted(lines))
        if noun == "interfaces":
            panel.picker.set_selected([n for n, pts in lines.items() if any(v for _t, v in pts)])
        panel.lines = ChartStack()
        panel.lines.setMinimumHeight(300)
        named = (lambda n: f"temperature ({n})") if noun == "drives" else (lambda n: n)     # drives: in °C, on the temperature scale
        draw = lambda: panel.lines.set_series([(named(n), lines[n]) for n in panel.picker.selected() or sorted(lines)])
        panel.picker.changed.connect(draw)
        draw()
        row = QHBoxLayout()
        row.addWidget(panel.picker)
        row.addStretch(1)
        panel.lay.addLayout(row)
        panel.lay.addWidget(panel.lines)
        return True

    def _table(self, panel):
        changes = []
        for r in self._rows(panel.checks[0]):
            if not changes or changes[-1]["value"] != r["value"]:
                changes.append(r)
        if not changes:
            return panel.note(EMPTY)
        self._add_table(panel, [{"t": r["t"], "status": r["status"], "value": display.value(r["value"]), "message": r["message"] or ""}
                                for r in reversed(changes)], CHANGES)

    def _add_table(self, panel, rows, columns):
        panel.table = DetailList()
        panel.table.setMinimumHeight(200)
        panel.table.show_rows(rows, columns)
        panel.lay.addWidget(panel.table)

    def _gauges(self, panel):
        check = panel.checks[0]
        last, items = self._latest(check)
        if last is None:
            return panel.note(EMPTY)
        dials = [(it["name"], it["numeric"], it["data"]) for it in items or [] if it["numeric"] is not None]
        if not dials and last["numeric"] is not None:                 # a reader that gives no drives: the row's own percentage
            dials = [(display.check_name(check), last["numeric"], {})]
        if not dials:
            return panel.note(EMPTY)
        limits = self.th.get("disk") or {}
        box = QWidget()
        flow = FlowLayout(8, 8)
        box.setLayout(flow)
        panel.gauges = []
        for name, value, data in dials:
            title = name + (f"\n{human_size(data['used'])} of {human_size(data['total'])}" if data.get("used") is not None and data.get("total") else "")
            g = ChartView(min_height=170)
            g.setFixedWidth(210)
            g.setAccessibleName(f"{name} dial")
            g.draw(lambda p, v=value, t=title: chartspec.gauge(p, v, warn=limits.get("warn") or None, fail=limits.get("fail") or None, title=t))
            flow.addWidget(g)
            panel.gauges.append(g)
        panel.lay.addWidget(box)

    def _wheel(self, panel):
        check = panel.checks[0]
        last, items = self._latest(check)
        if last is None:
            return panel.note(EMPTY)
        if items is None:                                              # an agent from before pending updates were reported
            return panel.note(OLD_AGENT)
        if any((it["data"] or {}).get("updates_error") for it in items):   # it said its search was refused or failed
            return panel.note(NOT_REPORTED)
        groups = {s: [] for s in SEVERITIES}
        for it in items:
            sev = (it["data"] or {}).get("severity") or ""
            groups[sev if sev in groups else "Unrated"].append(it)
        panel.groups = groups
        panel.chart = ChartView(min_height=240)
        panel.chart.setAccessibleName(display.check_name(check))
        panel.chart.draw(lambda p: chartspec.ring(p, [(s, len(groups[s]), _severity_colour(p, s)) for s in SEVERITIES], len(items)))
        panel.chart.clicked.connect(lambda hit: self._segment(panel, hit))
        panel.lay.addWidget(panel.chart)
        searched = next((it["data"].get("searched") for it in items if (it["data"] or {}).get("searched")), "")
        if searched:
            panel.note(SEARCHED.format(date=_day(searched)))
        panel.detail = DetailList()
        panel.detail.setMinimumHeight(160)
        panel.detail.hide()
        panel.lay.addWidget(panel.detail)

    def _segment(self, panel, hit):
        """A severity of the wheel was selected: those updates."""
        updates = panel.groups.get(hit.get("name")) if hit.get("kind") == "series" else None
        if updates is None:
            return
        panel.detail.show_rows([{"name": it["name"], "kb": it["text"], "severity": hit["name"]} for it in updates], PATCHES)
        panel.detail.show()

    def _uptime(self, panel):
        pts = db.series(self.device, panel.checks[0], start=self.s, end=self.e)
        if not pts:
            return panel.note(EMPTY)
        began = lambda t, h: (_when(t) - timedelta(hours=h)).strftime("%Y-%m-%d %H:%M") if _when(t) else ""
        last_t, last_h = pts[-1]
        rows = [{"restarted": began(last_t, last_h), "up": display.uptime_words(last_h), "_up": last_h}]     # the current uptime on top
        rows += [{"restarted": began(t, after + before), "up": display.uptime_words(before), "_up": before}
                 for t, before, after in reversed(restarts(pts))]
        self._add_table(panel, rows, UPTIME)

    def _ha(self, panel):
        ha, sync = ({r["t"]: r["value"] for r in self._rows(c)} for c in ("ha", "ha sync"))
        rows, now = [], (None, None)
        for t in sorted(set(ha) | set(sync)):
            new = (ha.get(t, now[0]), sync.get(t, now[1]))
            if new != now:
                rows.append({"t": t, "ha": display.value(new[0]) if new[0] is not None else "", "sync": display.value(new[1]) if new[1] is not None else ""})
                now = new
        if not rows:
            return panel.note(EMPTY)
        self._add_table(panel, rows[::-1], HA)

    def _config(self, panel):
        vers = backup.list_backups(self.device)
        rows = [{"t": v["taken_at"], "changed": f"+{v['added']} / -{v['removed']}" if i + 1 < len(vers) else "", "i": i}
                for i, v in enumerate(vers) if self.s <= str(v["taken_at"]) <= self.e]
        if not rows:
            return panel.note(EMPTY)
        self._add_table(panel, rows, CONFIG)
        panel.switch = config_switch()
        panel.config = config_text_view()
        panel.config.setMinimumHeight(240)

        def show(*_):
            r = panel.table.row_at(panel.table.currentIndex())
            panel.config.setPlainText(config_text(vers, r["i"], panel.switch.currentData()) if r else "")
        panel.table.selectionModel().currentRowChanged.connect(show)
        panel.switch.currentIndexChanged.connect(show)
        panel.lay.addWidget(panel.switch)
        panel.lay.addWidget(panel.config)
        panel.table.selectRow(0)

    def _certs(self, panel):
        rows = []
        for c in panel.checks:
            last, items = self._latest(c)
            if last is not None:
                rows += cert_rows(c, last, items)
        if not rows:
            return panel.note(EMPTY)
        self._add_table(panel, rows, CERTS)
