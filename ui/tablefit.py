"""One rule for every table and tree: when there is room each column is as wide as its longest text (heading included); when there
isn't, the columns share the width (none narrower than its heading, the widest give way first, cut-off text shows in full on hover).
Every column can always be dragged, and a column the person dragged keeps its width until the view closes. Qt cannot drag a section set
to ResizeToContents or Stretch, so sections are Interactive and the fitting is done here."""
import weakref

from PySide6.QtCore import QEvent, QObject, Qt, QTimer
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView, QToolTip, QTreeView


def fit_widths(content, header, available):
    """Widths for the columns. Water-fill: find the level L so that sum(min(content, max(L, header))) is the available width."""
    want = [max(c, h) for c, h in zip(content, header)]            # a column is never narrower than its heading
    if sum(want) <= available:
        return want
    def at(level):
        return [min(w, max(level, h)) for w, h in zip(want, header)]
    lo, hi = 0, max(want)                                           # largest level whose total still fits
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if sum(at(mid)) <= available: lo = mid
        else: hi = mid - 1
    out = at(lo)
    spare = available - sum(out)
    for i, w in enumerate(out):                                     # hand the leftover pixels to the columns still held back
        if spare > 0 and w < want[i] and w == max(lo, header[i]):
            out[i] += 1; spare -= 1
    return out


def _header(view):
    return view.horizontalHeader() if isinstance(view, QTableView) else view.header()


def full_text_at(view, pos):
    """The whole text of the cell at pos (viewport coordinates) when the column is too narrow to show it, else None."""
    ix = view.indexAt(pos)
    if not ix.isValid() or ix.data(Qt.ItemDataRole.ToolTipRole):
        return None
    text = ix.data(Qt.ItemDataRole.DisplayRole)
    if not isinstance(text, str) or not text:
        return None
    return text if view.sizeHintForIndex(ix).width() > view.visualRect(ix).width() + 1 else None


class _Fitter(QObject):
    def __init__(self, view):
        super().__init__(view)
        self.view, self.head = view, _header(view)
        self.pinned, self.busy, self.pressed, self.model = set(), False, False, None
        self.timer = QTimer(self); self.timer.setSingleShot(True); self.timer.setInterval(0)
        self.timer.timeout.connect(self.run)
        self.head.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.head.sectionResized.connect(self._resized)
        self.head.setResizeContentsPrecision(200)                   # at most 200 rows are measured
        if isinstance(view, QTableView): view.verticalHeader().setResizeContentsPrecision(200)   # (the table asks this one)
        if self.head.defaultAlignment() & Qt.AlignmentFlag.AlignHCenter:   # a table's headings over its text, as a tree's are (Qt centres them);
            self.head.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)   # a column of its own sets its item's
        view.installEventFilter(self); view.viewport().installEventFilter(self); self.hv, self.vp = self.head.viewport(), view.viewport(); self.hv.installEventFilter(self)
        self.run()

    def schedule(self, *_):
        self.timer.start()

    def _resized(self, i, _old, _new):
        if self.pressed and not self.busy:                          # only a drag with the mouse down pins; code never does
            self.pinned.add(i)

    def eventFilter(self, o, e):
        t = e.type()
        if o is self.hv:
            if t == QEvent.Type.MouseButtonPress: self.pressed = True
            elif t == QEvent.Type.MouseButtonRelease: self.pressed = False
            return False
        if t in (QEvent.Type.Resize, QEvent.Type.Show) and o is not self.vp:
            self.schedule()
        elif t == QEvent.Type.ToolTip and o is self.vp:
            text = full_text_at(self.view, e.pos())
            if text:
                QToolTip.showText(e.globalPos(), text, self.view.viewport()); return True
        return False

    def run(self):
        view, head = self.view, self.head
        m = view.model()
        if m is not self.model:
            self.model = m
            if m is not None:
                for sig in (m.modelReset, m.rowsInserted, m.dataChanged, m.columnsInserted, m.layoutChanged):
                    sig.connect(self.schedule)
        if m is None or not view.isVisible() or view.viewport().width() <= 0:
            return
        self.busy = True
        for c in range(head.count()):                               # a mode set by code since the last fit is undone
            if head.sectionResizeMode(c) != QHeaderView.ResizeMode.Interactive: head.setSectionResizeMode(c, QHeaderView.ResizeMode.Interactive)
        self.busy = False
        cols = [c for c in range(head.count()) if not head.isSectionHidden(c) and c not in self.pinned]
        if not cols:
            return
        taken = sum(head.sectionSize(c) for c in range(head.count()) if not head.isSectionHidden(c) and c in self.pinned)
        content = [view.sizeHintForColumn(c) for c in cols]
        heads = [head.sectionSizeFromContents(c).width() for c in cols]
        widths = fit_widths(content, heads, max(0, view.viewport().width() - taken))
        self.busy = True
        try:
            for c, w in zip(cols, widths):
                if head.sectionSize(c) != w: head.resizeSection(c, w)
        finally:
            self.busy = False


def fit(view):
    """Apply the rule to one table or tree (once; calling it again does nothing)."""
    if not isinstance(view, QAbstractItemView) or view.findChild(_Fitter, options=Qt.FindChildOption.FindDirectChildrenOnly):
        return
    _Fitter(view)


class _Everywhere(QObject):
    def __init__(self, app):
        super().__init__(app)
        self.seen = weakref.WeakSet()

    def eventFilter(self, o, e):
        if e.type() == QEvent.Type.Polish and isinstance(o, (QTableView, QTreeView)) and o not in self.seen:
            self.seen.add(o); fit(o)
        return False


def install_everywhere(app):
    app._tablefit = _Everywhere(app)
    app.installEventFilter(app._tablefit)
