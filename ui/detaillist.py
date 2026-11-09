"""The rows behind a selection (a heatmap square, a ring segment), and the tables of the Over time panels: one model/view table that
takes plain dicts. Sortable by any column; the columns fit as every table in Toner does (ui.tablefit); a status column shows as chips."""
from PySide6.QtCore import Qt
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QAbstractItemView, QTableView

from ui import tablefit
from ui.widgets import StatusDelegate

SORT = Qt.ItemDataRole.UserRole + 1


class _Cell(QStandardItem):
    """Numbers sort as numbers, before any text, and a blank cell ends up last whichever way the column is sorted."""

    def __lt__(self, other):
        a, b = self.data(SORT), other.data(SORT)
        blank_a, blank_b = a in ("", None), b in ("", None)
        if blank_a or blank_b:
            if blank_a == blank_b:
                return False
            desc = self.model().parent().horizontalHeader().sortIndicatorOrder() == Qt.SortOrder.DescendingOrder
            return blank_b != desc                     # a descending sort asks the other way round
        num_a, num_b = isinstance(a, (int, float)), isinstance(b, (int, float))
        if num_a or num_b:
            return a < b if num_a and num_b else num_a
        return str(a) < str(b)


class DetailList(QTableView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []
        self.setModel(QStandardItemModel(self))
        self.model().setSortRole(SORT)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)
        self.chip = StatusDelegate(self)
        tablefit.fit(self)

    def show_rows(self, rows, columns):
        """rows: [dict]; columns: [(key, label)]. Numbers stay numbers, so they sort as numbers; a row's '_<key>' is that column's sort
        value when the text would sort wrongly ('12 days' before '2 days'). Rows keep the given order until a header is clicked."""
        self.rows = list(rows)
        m = self.model()
        self.setSortingEnabled(False)
        m.clear()
        m.setHorizontalHeaderLabels([label for _k, label in columns])
        for i, r in enumerate(self.rows):
            cells = []
            for key, _label in columns:
                v = r.get(key)
                it = _Cell()
                it.setData("" if v is None else v, Qt.ItemDataRole.DisplayRole)
                it.setData(r.get("_" + key, "" if v is None else v), SORT)
                cells.append(it)
            cells[0].setData(i, Qt.ItemDataRole.UserRole)
            m.appendRow(cells)
        for j, (key, _label) in enumerate(columns):
            self.setItemDelegateForColumn(j, self.chip if key == "status" else None)
        head = self.horizontalHeader()
        if not head.isSortIndicatorShown():
            head.setSortIndicator(-1, Qt.SortOrder.AscendingOrder)       # no column chosen yet: the order given
        self.setSortingEnabled(True)
        head.setSortIndicatorShown(True)

    def row_at(self, index):
        """The dict shown on the row of `index` (sorted or not), or None."""
        if not index.isValid():
            return None
        i = self.model().index(index.row(), 0).data(Qt.ItemDataRole.UserRole)
        return self.rows[i] if isinstance(i, int) and 0 <= i < len(self.rows) else None
