"""Organizations, on the Global Overview in place of Network at a glance (a map of every organization's devices is too many dots to
read): one row per organization with its worst status and how many of its devices are down, failing or warned, the ones that need
attention first and the rest quiet below. A click or Enter on a row switches Toner to that organization; a box above finds one by
name or code. Counts leave out devices put aside (acknowledged or snoozed), as Needs attention does."""
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFontMetrics, QIcon, QKeySequence, QPixmap, QShortcut
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from core import db, display, orgs
from ui import glance, theme
from ui.finder import SearchBox
from ui.widgets import EmptyHint, StatusDelegate

COLS = ["Organization", "Status", "Down", "Failing", "Warnings", "Devices", "Last run"]
SHOWN = 12                                    # rows on show before the list scrolls
NUMBERS = (2, 3, 4, 5)                        # Down, Failing, Warnings, Devices: as wide as their heading, so the names have the room
RANK = Qt.ItemDataRole.UserRole + 1           # what a column sorts by (worst first in Status; numbers as numbers)
OID = Qt.ItemDataRole.UserRole + 2            # the organization a row stands for (0: Global's own devices)


def dot(colour, size=10):
    """An organization's colour as a small square icon, as the switcher shows it."""
    pm = QPixmap(size, size)
    pm.fill(QColor(colour or "#888888"))
    return QIcon(pm)


def tally(healths):
    """(down, failing, warned) for a list of device health entries: down = Toner could not reach it, failing = any other FAIL or
    ERROR, warned = its worst is WARN."""
    down = sum(1 for v in healths if glance.is_down(v))
    failing = sum(1 for v in healths if v["status"] in ("FAIL", "ERROR") and not glance.is_down(v))
    warned = sum(1 for v in healths if v["status"] == "WARN")
    return down, failing, warned


def counts_text(down, failing, warned):
    """'1 down, 2 failing, 3 with a warning', leaving out what is 0."""
    return ", ".join(t for n, t in ((down, f"{down} down"), (failing, f"{failing} failing"), (warned, f"{warned} with a warning")) if n)


def worst(down, failing, warned, checked):
    if down:
        return "ERROR", 3
    if failing:
        return "FAIL", 2
    if warned:
        return "WARN", 1
    return ("OK", 0) if checked else ("not checked", -1)


class _Item(QTableWidgetItem):
    """Sorts by its RANK when it has one (a status, a number), else by its text."""

    def __lt__(self, other):
        a, b = self.data(RANK), other.data(RANK)
        return a < b if a is not None and b is not None else super().__lt__(other)


class OrgBoard(QWidget):
    open_org = Signal(int)                   # a row was clicked or Enter pressed: switch Toner to that organization

    def __init__(self, page=None):
        super().__init__()
        self.find = SearchBox("Search organizations", page=page)
        self.find.setMaximumWidth(16777215)
        self.find.textChanged.connect(self._filter)
        t = self.table = QTableWidget(0, len(COLS))
        t.setAccessibleName("Organizations")
        t.setHorizontalHeaderLabels(COLS)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        t.verticalHeader().setVisible(False)
        t.setShowGrid(False)
        t.setItemDelegateForColumn(1, StatusDelegate(t))
        hh = t.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for c in range(1, len(COLS)):
            hh.setSectionResizeMode(c, QHeaderView.ResizeMode.Fixed if c in NUMBERS else QHeaderView.ResizeMode.ResizeToContents)
        t.setTextElideMode(Qt.TextElideMode.ElideRight)
        t.cellClicked.connect(lambda row, _col: self._open(row))
        for key in ("Return", "Enter"):
            QShortcut(QKeySequence(key), t, activated=lambda: self._open(t.currentRow()), context=Qt.ShortcutContext.WidgetShortcut)
        self.hint = EmptyHint(t, "No organizations match", wrap=True)
        self.hint.hide()
        self.summary = ""                    # "· 3 of 52 need attention" or "· all 52 OK", for the panel's title row
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        lay.addWidget(self.find)
        lay.addWidget(t, 1)

    def fill(self, devs, health, aside=()):
        """devs: the devices listed (with 'key' and 'org'); health: db.device_health(); aside: keys put aside."""
        names = {0: "Global"}
        colours = {0: ""}
        listed = [0] if any(not d.get("org") for d in devs) else []
        for o in orgs.list_orgs(archived=False):
            names[o["id"]], colours[o["id"]] = o["name"] + (f" ({o['code']})" if o.get("code") else ""), o["colour"]
            listed.append(o["id"])
        per = {oid: [] for oid in listed}
        for d in devs:
            per.setdefault(d.get("org") or 0, []).append(d)
        muted = QColor((theme.current() or {}).get("muted", "#888888"))
        rows = []
        for oid in listed:
            mine = per.get(oid, [])
            seen = [health[d["key"]] for d in mine if d["key"] in health]
            open_ = [health[d["key"]] for d in mine if d["key"] in health and d["key"] not in aside]
            down, failing, warned = tally(open_)
            status, rank = worst(down, failing, warned, bool(seen))
            with db.within(oid):
                run = db.last_run()
            rows.append((oid, status, rank, down, failing, warned, len(mine), run["started_at"] if run else ""))
        rows.sort(key=lambda r: (-r[2], -r[3], -r[4], -r[5], names[r[0]].lower()))
        t = self.table
        t.setSortingEnabled(False)
        t.setRowCount(len(rows))
        for i, (oid, status, rank, down, failing, warned, n, at) in enumerate(rows):
            quiet = rank <= 1                                          # warnings only, OK or never checked: quiet
            cells = [(names[oid], None), (status, rank), (str(down), down), (str(failing), failing), (str(warned), warned), (str(n), n),
                     (display.ago(at) if at else "never", at or "")]
            for j, (text, key) in enumerate(cells):
                item = _Item(text)
                item.setData(RANK, key)
                item.setData(OID, oid)
                if j == 0:
                    item.setIcon(dot(colours[oid]))
                    f = item.font()
                    f.setBold(not quiet)
                    item.setFont(f)
                if j >= 2:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                if quiet and j != 1:
                    item.setForeground(muted)
                item.setToolTip(f"Switch Toner to {names[oid]}" if oid else names[oid])
                t.setItem(i, j, item)
        t.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)   # worst first, as filled, until a heading is clicked
        t.setSortingEnabled(True)
        need = sum(1 for r in rows if r[2] > 0)
        checked = all(r[2] >= 0 for r in rows)
        self._fit_numbers()
        rh = t.verticalHeader().defaultSectionSize()
        t.setFixedHeight(t.horizontalHeader().sizeHint().height() + rh * max(1, min(len(rows), SHOWN)) + 2 * t.frameWidth() + 2)
        self.summary = ("" if not rows else f"· all {len(rows)} OK" if not need and checked
                        else f"· {need} of {len(rows)} need attention")
        self._filter()

    def _fit_numbers(self):
        """The number columns as wide as their bold heading and its padding (Qt leaves room for a sort arrow besides)."""
        hh = self.table.horizontalHeader()
        f = hh.font()
        f.setBold(True)
        fm = QFontMetrics(f)
        pad = (theme.current() or {}).get("pad_header", "6px 8px").split()
        side = int(pad[-1][:-2]) if pad and pad[-1].endswith("px") else 8
        for c in NUMBERS:
            text = max([COLS[c]] + [self.table.item(r, c).text() for r in range(self.table.rowCount()) if self.table.item(r, c)], key=fm.horizontalAdvance)
            hh.resizeSection(c, fm.horizontalAdvance(text) + 2 * side + 6)

    def _filter(self):
        words = self.find.text().strip().lower()
        shown = 0
        for i in range(self.table.rowCount()):
            hit = not words or words in self.table.item(i, 0).text().lower()
            self.table.setRowHidden(i, not hit)
            shown += hit
        self.hint.setVisible(bool(words) and not shown)

    def _open(self, row):
        item = self.table.item(row, 0) if row >= 0 else None
        if item is not None and item.data(OID):
            self.open_org.emit(int(item.data(OID)))
