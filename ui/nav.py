"""Main window layout: a sidebar of sections on the left, the current section on the right.

Offers the small part of QTabWidget's API that the rest of the app uses (addTab, setCurrentWidget,
currentWidget, indexOf, count, tabText), so sections can be switched from code.
"""
from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QStackedWidget, QVBoxLayout,
                               QWidget)
from ui import icons, theme


class NavStack(QWidget):
    currentChanged = Signal(int)
    PAGE_MARGINS = (24, 20, 24, 20)

    def __init__(self, title="Toner"):
        super().__init__()
        self._names, self._icon_names = [], []
        self.side = QWidget()
        self.side.setObjectName("sidebar")
        self.side.setFixedWidth(208)
        from ui import logo
        mark = QLabel()
        mark.setPixmap(logo.pixmap(32, 2.0))
        mark.setFixedSize(32, 32)
        brand = QLabel(title)
        brand.setObjectName("brand")
        head = QHBoxLayout()
        head.setContentsMargins(6, 4, 0, 8)
        head.setSpacing(10)
        head.addWidget(mark)
        head.addWidget(brand, 1)
        self.list = QListWidget()
        self.list.setObjectName("nav")
        self.list.setIconSize(QSize(20, 20))
        self.list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        side = QVBoxLayout(self.side)
        side.setContentsMargins(12, 16, 12, 12)
        side.addLayout(head)
        side.addWidget(self.list, 1)
        self.stack = QStackedWidget()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(self.side)
        lay.addWidget(self.stack, 1)
        self.list.currentRowChanged.connect(self._row_changed)

    def _row_changed(self, row):
        if row >= 0:
            self.stack.setCurrentIndex(row)
            self.currentChanged.emit(row)

    def addTab(self, widget, label, icon_name=None):
        if widget.layout() is not None:
            widget.layout().setContentsMargins(*self.PAGE_MARGINS)
            widget.layout().setSpacing(12)
        self.stack.addWidget(widget)
        item = QListWidgetItem(label)
        item.setSizeHint(QSize(0, 42))
        self.list.addItem(item)
        self._names.append(label)
        self._icon_names.append(icon_name)
        self.restyle()
        if self.list.currentRow() < 0:
            self.list.setCurrentRow(0)

    def setBadge(self, widget, on):
        """Mark a section that has something new (a dot after its name)."""
        i = self.stack.indexOf(widget)
        if i >= 0:
            self.list.item(i).setText(self._names[i] + ("   \u25cf" if on else ""))

    def restyle(self):
        """Re-tint the icons after the theme or accent changed."""
        t = theme.current()
        if not t:
            return
        for i, name in enumerate(self._icon_names):
            if name:
                self.list.item(i).setIcon(icons.icon(name, t["muted"], t["accent"]))

    def count(self):
        return self.stack.count()

    def indexOf(self, widget):
        return self.stack.indexOf(widget)

    def tabText(self, i):
        return self._names[i]

    def currentWidget(self):
        return self.stack.currentWidget()

    def currentIndex(self):
        return self.stack.currentIndex()

    def setCurrentWidget(self, widget):
        i = self.stack.indexOf(widget)
        if i >= 0:
            self.list.setCurrentRow(i)

    def setCurrentIndex(self, i):
        self.list.setCurrentRow(i)


class PageStack(QWidget):
    """A list of pages on the left (with optional section headings) and the chosen page on the right.
    Offers addTab, setCurrentWidget, currentWidget, indexOf, count and tabText like QTabWidget."""
    currentChanged = Signal(int)

    def __init__(self, width=190):
        super().__init__()
        self.list = QListWidget()
        self.list.setObjectName("settingsNav")
        self.list.setFixedWidth(width)
        self.list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.stack = QStackedWidget()
        self._rows = []                         # stack index -> list row
        self._names = []
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)
        lay.addWidget(self.list)
        lay.addWidget(self.stack, 1)
        self.list.currentRowChanged.connect(self._row_changed)

    def addSection(self, title):
        item = QListWidgetItem(title.upper())
        item.setFlags(Qt.ItemFlag.NoItemFlags)
        f = item.font()
        f.setBold(True)
        f.setPointSizeF(max(7.0, f.pointSizeF() - 2))
        item.setFont(f)
        item.setSizeHint(QSize(0, 30))
        self.list.addItem(item)

    def addTab(self, widget, label):
        self.stack.addWidget(widget)
        item = QListWidgetItem(label)
        self.list.addItem(item)
        self._rows.append(self.list.count() - 1)
        self._names.append(label)
        if self.list.currentRow() < 0:
            self.list.setCurrentRow(self._rows[-1])

    def _row_changed(self, row):
        if row in self._rows:
            i = self._rows.index(row)
            self.stack.setCurrentIndex(i)
            self.currentChanged.emit(i)

    def count(self):
        return self.stack.count()

    def indexOf(self, widget):
        return self.stack.indexOf(widget)

    def tabText(self, i):
        return self._names[i]

    def currentWidget(self):
        return self.stack.currentWidget()

    def setCurrentWidget(self, widget):
        i = self.stack.indexOf(widget)
        if i >= 0:
            self.list.setCurrentRow(self._rows[i])

    def setCurrentIndex(self, i):
        self.list.setCurrentRow(self._rows[i])
