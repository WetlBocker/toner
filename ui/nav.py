"""Main window layout: a sidebar of sections on the left, the current section on the right.

Offers the small part of QTabWidget's API that the rest of the app uses (addTab, setCurrentWidget,
currentWidget, indexOf, count, tabText), so sections can be switched from code.
"""
from PySide6.QtCore import QEvent, QSize, Qt, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (QBoxLayout, QComboBox, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QPushButton, QScrollArea,
                               QStackedWidget, QVBoxLayout, QWidget)
from ui import icons, theme


ITEM_HEIGHT = 36            # a row in a page list; Qt does not take the style sheet's padding into account by itself
EXPANDED_WIDTH = 208        # the sidebar in full
COLLAPSED_WIDTH = 68        # and as a strip of icons
HEADING_HEIGHT = 44        # a group heading: the room is above it, so the heading sits close to its own items


class NavStack(QWidget):
    currentChanged = Signal(int)
    search_requested = Signal()
    collapsed_changed = Signal(bool)
    client_changed = Signal(object)            # a top-level folder id, or None for all clients
    PAGE_MARGINS = (24, 20, 24, 20)

    def __init__(self, title="Toner"):
        super().__init__()
        self._names, self._icon_names = [], []
        self.side = QWidget()
        self.side.setObjectName("sidebar")
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
        self.client = QComboBox()                 # the client being looked at: every section follows it
        self.client.setObjectName("clientPicker")
        self.client.setToolTip("Show one client (a top-level folder of the Inventory) in every section, or all of them")
        self.client.currentIndexChanged.connect(lambda _i: None if self._filling else self.client_changed.emit(self.client.currentData()))
        self._filling = False
        side.addWidget(self.client)
        side.addSpacing(6)
        side.addWidget(self.list, 1)
        self.quick = QPushButton("Search      Ctrl+K")                   # the command palette is easy to miss otherwise
        self.quick.setProperty("ghost", True)
        self.quick.setToolTip("Jump to a section, tool, device or action")
        self.quick.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.quick.clicked.connect(self.search_requested)
        self.fold = QPushButton()                                          # shrinks the sidebar to a strip of icons, and back
        self.fold.setProperty("ghost", True)
        self.fold.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.fold.clicked.connect(lambda: self.setCollapsed(not self._collapsed))
        self.bottom = QBoxLayout(QBoxLayout.Direction.LeftToRight)
        self.bottom.setSpacing(6)
        self.bottom.addWidget(self.quick, 1)
        self.bottom.addWidget(self.fold)
        side.addLayout(self.bottom)
        self.stack = QStackedWidget()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(self.side)
        lay.addWidget(self.stack, 1)
        self.list.currentRowChanged.connect(self._row_changed)
        self.list.installEventFilter(self)             # a short window squeezes the rows rather than hiding the last sections
        self._brand = brand
        self._badges = set()
        self.setCollapsed(False)

    ROW_MIN = 28

    @staticmethod
    def expanded_width():
        return 176 if theme.is_ops() else EXPANDED_WIDTH

    @staticmethod
    def row_height():
        return 32 if theme.is_ops() else 42

    def eventFilter(self, obj, event):
        if obj is self.list and event.type() == QEvent.Type.Resize:
            self._fit_rows(event.size().height())
        return super().eventFilter(obj, event)

    def _fit_rows(self, height=None):
        """The sections share the height there is: 42 px each when it all fits, less (down to 30) in a short window."""
        n = self.list.count()
        if not n:
            return
        if height is None and not self.list.isVisible():
            return                                     # not laid out yet: the first resize does it
        avail = (self.list.height() if height is None else height) - 6
        h = max(self.ROW_MIN, min(self.row_height(), avail // n))
        for i in range(n):
            if self.list.item(i).sizeHint().height() != h:
                self.list.item(i).setSizeHint(QSize(0, h))

    def collapsed(self):
        return self._collapsed

    def set_clients(self, clients, current=None):
        """[(folder id, name)]: the choices besides "All clients". Hidden while there are none."""
        self._filling = True
        self.client.clear()
        self.client.addItem("All clients", None)
        for fid, name in clients:
            self.client.addItem(name, fid)
        self.client.setCurrentIndex(max(0, self.client.findData(current)))
        self._filling = False
        self.client.setVisible(bool(clients) and not self._collapsed)

    def setCollapsed(self, on):
        """The sidebar as a strip of icons (names show as tooltips) or in full."""
        on = bool(on)
        changed = on != getattr(self, "_collapsed", None)
        self._collapsed = on
        self.side.setFixedWidth(COLLAPSED_WIDTH if on else self.expanded_width())
        self._brand.setVisible(not on)
        if hasattr(self, "client"):
            self.client.setVisible(not on and self.client.count() > 1)
        self.quick.setText("" if on else ("Search   Ctrl+K" if theme.is_ops() else "Search      Ctrl+K"))
        self.bottom.setDirection(QBoxLayout.Direction.TopToBottom if on else QBoxLayout.Direction.LeftToRight)
        self.fold.setToolTip("Show the sidebar in full   (Ctrl+B)" if on else "Collapse the sidebar   (Ctrl+B)")
        self.quick.setToolTip("Search   (Ctrl+K)\nJump to a section, tool, device or action" if on else "Jump to a section, tool, device or action")
        for i, name in enumerate(self._names):
            self._label(i)
        self.restyle()
        if changed:
            self.collapsed_changed.emit(on)

    def _label(self, i):
        """What row i shows: its name, and a dot after it when something is new (the dot is on the icon when only icons show)."""
        item = self.list.item(i)
        dot = i in self._badges
        item.setText("" if self._collapsed else self._names[i] + ("   ●" if dot else ""))
        tip = self._names[i] + ("   (new)" if dot and self._collapsed else "")
        item.setToolTip(tip + (f"   (Ctrl+{i + 1})" if i < 9 else ""))

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
        self._fit_rows()
        self._label(self.list.count() - 1)
        self.restyle()
        if self.list.currentRow() < 0:
            self.list.setCurrentRow(0)

    def setBadge(self, widget, on):
        """Mark a section that has something new (a dot after its name, or on its icon when only icons show)."""
        i = self.stack.indexOf(widget)
        if i >= 0:
            (self._badges.add if on else self._badges.discard)(i)
            self._label(i)
            self.restyle()

    def restyle(self):
        """Re-tint the icons after the theme or accent changed."""
        t = theme.current()
        if not t:
            return
        if not self._collapsed:
            self.side.setFixedWidth(self.expanded_width())              # the console style has a narrower sidebar
            self.quick.setText("Search   Ctrl+K" if theme.is_ops() else "Search      Ctrl+K")
        self._fit_rows()
        for i, name in enumerate(self._icon_names):
            if name:
                self.list.item(i).setIcon(icons.icon_with_dot(name, t["muted"], t["accent"]) if self._collapsed and i in self._badges
                                          else icons.icon(name, t["muted"], t["accent"]))
        self.fold.setIcon(icons.icon("panel", t["muted"], t["text"]))
        self.quick.setIcon(icons.icon("search", t["muted"], t["text"]) if self._collapsed else QIcon())

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
        self._rows = []                         # page index -> list row
        self._pages = []                        # the pages themselves (each is inside a scroll area in the stack)
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
        item.setSizeHint(QSize(0, HEADING_HEIGHT if self.list.count() else HEADING_HEIGHT - 10))    # air above each group, none above the first
        item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignBottom)
        self.list.addItem(item)

    def addTab(self, widget, label):
        """Each page sits in a scroll area, so a window smaller than the page needs scrolls instead of squeezing the
        controls on top of each other. A page that fits fills the area exactly as before."""
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QScrollArea.Shape.NoFrame)
        area.setWidget(widget)
        self.stack.addWidget(area)
        self._pages.append(widget)
        item = QListWidgetItem(label)
        item.setSizeHint(QSize(0, ITEM_HEIGHT))
        item.setToolTip(label)
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
        return len(self._pages)

    def indexOf(self, widget):
        return self._pages.index(widget) if widget in self._pages else -1

    def tabText(self, i):
        return self._names[i]

    def currentWidget(self):
        i = self.stack.currentIndex()
        return self._pages[i] if 0 <= i < len(self._pages) else None

    def setCurrentWidget(self, widget):
        i = self.indexOf(widget)
        if i >= 0:
            self.list.setCurrentRow(self._rows[i])

    def setCurrentIndex(self, i):
        self.list.setCurrentRow(self._rows[i])
