"""Main window layout: a top bar of sections (as in Demarc), with the current section centred below it.

Offers the small part of QTabWidget's API that the rest of the app uses (addTab, setCurrentWidget,
currentWidget, indexOf, count, tabText), so sections can be switched from code.
"""
from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QFont, QFontMetrics, QIcon
from PySide6.QtWidgets import (QApplication, QComboBox, QStyleOptionViewItem, QHBoxLayout, QLabel, QListView, QListWidget, QListWidgetItem, QPushButton, QScrollArea,
                               QStackedWidget, QVBoxLayout, QWidget)
from ui import icons, theme


ITEM_HEIGHT = 36            # a row in a page list; Qt does not take the style sheet's padding into account by itself
HEADING_HEIGHT = 44        # a group heading: the room is above it, so the heading sits close to its own items
BAR_HEIGHT = 60             # the top bar
BAR_HEIGHT_OPS = 50         # and in the console style
CONTENT_WIDTH = 2400        # the widest a section gets, centred in the window: a 1920 or 2560 screen uses all of it; ultra-wide screens keep margins
WIDE_SECTIONS = ("Sessions",)   # sections that use the whole window width (a terminal or a remote desktop needs the room)
TAB_PAD = 10                # space each side of a section's icon and name (the style sheet's item padding)
QT_MARGINS = 12             # what Qt adds round an item's icon and text by itself
NAV_ICON = 18               # the icon before each section's name
NAV_GAP = 8                 # between the icon and the name
NAV_SCALE = 1.12            # the section names, a little larger than the page text
LOGO = 34                   # the mark in the top bar
ICON_TAB = 44               # a section shown as just its icon


class NavStack(QWidget):
    currentChanged = Signal(int)
    search_requested = Signal()
    collapsed_changed = Signal(bool)
    org_changed = Signal(int)                  # the organization picked in the switcher (0 = Global)
    PAGE_MARGINS = (24, 20, 24, 20)

    def __init__(self, title="Toner"):
        super().__init__()
        self._names, self._icon_names = [], []
        self.leave_guard = None                    # (from index, to index) -> False to stay on the section being left
        self._filling = False
        self._level = 0                            # 0: brand, icons and names; 1: icons and names; 2: names only; 3: icons only. The window width decides (not stored)
        self._badges = set()
        self.side = QWidget()                      # the top bar
        self.side.setObjectName("topbar")
        from ui import logo
        mark = QLabel()
        mark.setPixmap(logo.pixmap(LOGO, 2.0))
        mark.setFixedSize(LOGO, LOGO)
        brand = QLabel(title)
        brand.setObjectName("brand")
        self.list = QListWidget()                  # the sections, side by side
        self.list.setObjectName("nav")
        self.list.setFlow(QListView.Flow.LeftToRight)
        self.list.setWrapping(False)
        self.list.setSpacing(0)
        self.list.setMovement(QListView.Movement.Static)
        self.list.setIconSize(QSize(NAV_ICON, NAV_ICON))
        self.list.setTextElideMode(Qt.TextElideMode.ElideNone)   # a name is never cut short: the bar drops icons, then names, first
        self.list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.org = QComboBox()                    # the organization being looked at: every section follows it
        self.org.setObjectName("orgPicker")
        self.org.setToolTip("The organization every section shows. Global lists every organization.")
        self.org.setMinimumWidth(150)
        self.org.setMaximumWidth(240)
        self.org.currentIndexChanged.connect(lambda _i: None if self._filling else self.org_changed.emit(int(self.org.currentData() or 0)))
        self.quick = QPushButton()                                          # the command palette (Ctrl+K) is easy to miss otherwise
        self.quick.setProperty("ghost", True)
        self.quick.setFixedWidth(36)
        self.quick.setToolTip("Search   (Ctrl+K)\nJump to a section, tool, device or action")
        self.quick.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.quick.clicked.connect(self.search_requested)
        self.fold = QPushButton()                                          # shows the sections as icons only, and back
        self.fold.setProperty("ghost", True)
        self.fold.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.fold.setFixedWidth(36)
        self.fold.clicked.connect(lambda: self.setCollapsed(not self._collapsed))
        bar = QHBoxLayout(self.side)
        bar.setContentsMargins(16, 0, 16, 0)
        bar.setSpacing(12)
        bar.addWidget(mark)
        bar.addWidget(brand)
        bar.addSpacing(8)
        bar.addWidget(self.list, 1)
        bar.addWidget(self.org)
        bar.addWidget(self.quick)
        bar.addWidget(self.fold)
        self.stack = QStackedWidget()
        self.stack.setMaximumWidth(CONTENT_WIDTH)
        body = QHBoxLayout()                       # the section in the middle, as wide as it may be; the rest of the width is margin
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addStretch(1)
        body.addWidget(self.stack, 100)
        body.addStretch(1)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(self.side)
        lay.addLayout(body, 1)
        self.list.currentRowChanged.connect(self._row_changed)
        self._brand = brand
        self.setCollapsed(False)

    @staticmethod
    def bar_height():
        return BAR_HEIGHT_OPS if theme.is_ops() else BAR_HEIGHT

    # ---------- what the top bar shows
    def collapsed(self):
        return self._collapsed

    def _icons_only(self):
        """Only icons show, either because that was chosen (Ctrl+B) or because the names do not fit the window."""
        return self._collapsed or self._level >= 3

    def set_orgs(self, orgs, current=0):
        """[(id, name, colour)]: the organizations besides Global (archived ones are not offered). Hidden while there are none."""
        from PySide6.QtGui import QColor, QPixmap
        def dot(colour):
            pm = QPixmap(10, 10)
            pm.fill(QColor(colour or "#888888"))
            return QIcon(pm)
        self._filling = True
        self.org.clear()
        self.org.addItem("Global", 0)
        for oid, name, colour in orgs:
            self.org.addItem(dot(colour), name, oid)
        self.org.setCurrentIndex(max(0, self.org.findData(current)))
        self._filling = False
        self.org.setVisible(bool(orgs))
        self._fit_tabs()

    def setCollapsed(self, on):
        """The sections as icons only (names show as tooltips) or with their names."""
        on = bool(on)
        changed = on != getattr(self, "_collapsed", None)
        self._collapsed = on
        self._apply_mode()
        if changed:
            self.collapsed_changed.emit(on)

    def _apply_mode(self):
        """Show the names or just the icons, in the sections and the fold button."""
        self.side.setFixedHeight(self.bar_height())
        self.list.setFixedHeight(self.bar_height() - 1)
        self.fold.setToolTip("Show the sidebar in full   (Ctrl+B)" if self._collapsed else "Collapse the sidebar   (Ctrl+B)")
        self._brand.setVisible(self._level < 1)
        for i in range(len(self._names)):
            self._label(i)
        self.restyle()

    def _tab_width(self, i):
        if self._icons_only():
            return ICON_TAB
        f = QFont(self.list.font())
        f.setBold(True)                            # measured in bold, so the selected section does not change the layout
        text = self._names[i] + ("   ●" if i in self._badges else "")
        bold_extra = QFontMetrics(f).horizontalAdvance(text) - QFontMetrics(self.list.font()).horizontalAdvance(text)
        mine = QFontMetrics(f).horizontalAdvance(text) + (NAV_ICON + NAV_GAP if self._level < 2 else 0) + 2 * TAB_PAD + QT_MARGINS
        try:                                       # what Qt itself needs for the item, style sheet padding and all
            item = self.list.item(i)
            keep = item.sizeHint()
            item.setSizeHint(QSize())
            opt = QStyleOptionViewItem()
            self.list.initViewItemOption(opt)
            qt = self.list.itemDelegate().sizeHint(opt, self.list.indexFromItem(item)).width() + bold_extra
            item.setSizeHint(keep)
        except Exception:
            qt = 0
        return max(mine, qt)

    def _label(self, i):
        """What section i shows: its name, and a dot after it when something is new (the dot is on the icon when only icons show)."""
        item = self.list.item(i)
        dot = i in self._badges
        icons_only = self._icons_only()
        item.setText("" if icons_only else self._names[i] + ("   ●" if dot else ""))
        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        item.setSizeHint(QSize(self._tab_width(i), self.bar_height() - 1))
        tip = self._names[i] + ("   (new)" if dot and icons_only else "")
        item.setToolTip(tip + (f"   (Ctrl+{i + 1})" if i < 9 else ""))

    def _fit_tabs(self):
        """The brand and the names while they fit the window width, then the names, then icons only. The same answer for the same
        width, whatever is shown now."""
        if not self._names:
            return
        f = QFont(self.list.font())
        f.setBold(True)
        fm = QFontMetrics(f)
        names = sum(fm.horizontalAdvance(n + ("   ●" if i in self._badges else "")) + 2 * TAB_PAD + QT_MARGINS for i, n in enumerate(self._names))
        with_icons = names + (NAV_ICON + NAV_GAP) * len(self._names)
        brand = QFontMetrics(self._brand.font()).horizontalAdvance(self._brand.text()) + 12
        org = 150 if not self.org.isHidden() else 0                    # the switcher is at least this wide
        fixed = 32 + LOGO + 36 + 36 + org + 92                           # margins, logo, Search, fold, switcher and the gaps between
        w = self.width()
        level = 0 if fixed + brand + with_icons <= w else 1 if fixed + with_icons <= w else 2 if fixed + names <= w else 3
        if level != self._level:
            self._level = level
            self._apply_mode()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._fit_tabs()

    def _row_changed(self, row):
        if row < 0:
            return
        was = self.stack.currentIndex()
        if self.leave_guard is not None and was >= 0 and was != row and not self.leave_guard(was, row):
            self.list.blockSignals(True)                   # stay where we were (unsaved settings, and the person chose to stay)
            self.list.setCurrentRow(was)
            self.list.blockSignals(False)
            return
        self.stack.setMaximumWidth(16777215 if self._names[row] in WIDE_SECTIONS else CONTENT_WIDTH)
        self.stack.setCurrentIndex(row)
        self.currentChanged.emit(row)

    def addTab(self, widget, label, icon_name=None):
        if widget.layout() is not None:
            widget.layout().setContentsMargins(*self.PAGE_MARGINS)
            widget.layout().setSpacing(12)
        self.stack.addWidget(widget)
        item = QListWidgetItem(label)
        self.list.addItem(item)
        self._names.append(label)
        self._icon_names.append(icon_name)
        self._label(self.list.count() - 1)
        self._fit_tabs()
        self.restyle()
        if self.list.currentRow() < 0:
            self.list.setCurrentRow(0)

    def setBadge(self, widget, on):
        """Mark a section that has something new (a dot after its name, or on its icon when only icons show)."""
        i = self.stack.indexOf(widget)
        if i >= 0:
            (self._badges.add if on else self._badges.discard)(i)
            self._label(i)
            self._fit_tabs()
            self.restyle()

    def restyle(self):
        """Re-tint the icons and re-measure the names after the theme, accent or text size changed."""
        t = theme.current()
        if not t:
            return
        self.side.setFixedHeight(self.bar_height())
        self.list.setFixedHeight(self.bar_height() - 1)
        icons_only = self._icons_only()
        f = QFont(QApplication.font())                         # the section names a little larger than the page text
        f.setPointSizeF(f.pointSizeF() * NAV_SCALE)
        self.list.setFont(f)
        for i, name in enumerate(self._icon_names):
            if not name or (self._level == 2 and not icons_only):   # short of room: the names without their icons
                self.list.item(i).setIcon(QIcon())
            elif icons_only and i in self._badges:             # the dot is on the icon when the name (and its dot) is hidden
                self.list.item(i).setIcon(icons.icon_with_dot(name, t.get("icon", t["muted"]), t["accent"]))
            else:                                              # the icon before the name; tinted in the accent on the current section
                self.list.item(i).setIcon(icons.icon(name, t.get("icon", t["muted"]), t["accent"]))
            self._label(i)                                     # measured after the icon is set, so its room is counted
        if self._names:
            self._fit_tabs()
        self.fold.setIcon(icons.icon("panel", t.get("icon", t["muted"]), t["text"]))
        self.quick.setIcon(icons.icon("search", t.get("icon", t["muted"]), t["text"]))

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
            if row > 0 and not (self.list.item(row - 1).flags() & Qt.ItemFlag.ItemIsSelectable):
                self.list.scrollToItem(self.list.item(row - 1))      # the first page of a group keeps its heading in view

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
