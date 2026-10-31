"""Main window layout: a sidebar of sections on the left, in groups, with the current section centred beside it.

Offers the small part of QTabWidget's API that the rest of the app uses (addTab, setCurrentWidget,
currentWidget, indexOf, count, tabText), so sections can be switched from code.
"""
from PySide6.QtCore import QEvent, QSize, Qt, Signal
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import (QApplication, QComboBox, QHBoxLayout, QLabel, QListView, QListWidget, QListWidgetItem, QPushButton, QScrollArea,
                               QStackedWidget, QVBoxLayout, QWidget)
from ui import icons, theme


ITEM_HEIGHT = 36            # a row in a page list; Qt does not take the style sheet's padding into account by itself
HEADING_HEIGHT = 44        # a group heading: the room is above it, so the heading sits close to its own items
NAV_HEADING = 34            # a group name in the sidebar (less above the first)
NAV_ITEM = 34               # a section row in the sidebar
NAV_ITEM_FOLDED = 30        # and folded to its icon
SIDE_WIDTH = 236            # the sidebar with names
SIDE_FOLDED = 68            # and folded to icons
AUTO_FOLD_BELOW = 1000      # a window narrower than this folds the sidebar by itself (not stored)
CONTENT_WIDTH = 2400        # the widest a section gets, centred beside the sidebar: a 1920 or 2560 screen uses all of it; ultra-wide screens keep margins
WIDE_SECTIONS = ("Sessions",)   # sections that use the whole window width (a terminal or a remote desktop needs the room)
NAV_ICON = 18               # the icon before each section's name
NAV_SCALE = 1.0             # the section names, the size of the page text
LOGO = 32                   # the mark at the top of the sidebar


class Beat(QWidget):
    """The Toner mark. Under Motion: Lively it swells a little every four seconds, like a slow heartbeat."""

    def __init__(self, size):
        super().__init__()
        from ui import logo, motion
        self.size_px, self.scale = size, 1.0
        self.pm = logo.pixmap(size, 2.0)
        self.setFixedSize(size, size)
        self.beat = motion.Phase(self, 4000, self._on_phase, fps=20)

    def restyle(self):
        from ui import motion
        if motion.lively() and self.isVisible():
            self.beat.start()
        else:
            self.beat.stop()
            self.scale = 1.0
            self.update()

    def showEvent(self, e):
        super().showEvent(e)
        self.restyle()

    def hideEvent(self, e):
        super().hideEvent(e)
        self.beat.stop()

    def _on_phase(self, p):
        import math
        self.scale = 1.0 + 0.08 * (0.5 - 0.5 * math.cos(p * 2 * math.pi))
        self.update()

    def paintEvent(self, _e):
        from PySide6.QtGui import QPainter
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        s = self.size_px
        p.translate(s / 2, s / 2)
        p.scale(self.scale, self.scale)
        p.drawPixmap(int(-s / 2), int(-s / 2), self.pm)


class NavStack(QWidget):
    """The sidebar on the left: the Toner mark, the organization switcher, Search, the sections in groups (Watch, Network, Work),
    and Settings and About at the bottom. Ctrl+B folds it to icons; a narrow window folds it by itself (not stored)."""
    currentChanged = Signal(int)
    search_requested = Signal()
    collapsed_changed = Signal(bool)
    org_changed = Signal(int)                  # the organization picked in the switcher (0 = Global)
    PAGE_MARGINS = (24, 20, 24, 20)
    BOTTOM = "__bottom__"                      # the group that sits at the bottom of the sidebar (Settings, About)

    def __init__(self, title="Toner"):
        super().__init__()
        self._names, self._icon_names, self._rows = [], [], []       # section index -> list row
        self._headings = []                        # the rows that are group names (and the spacer before the bottom group)
        self._spacer = None
        self._groups = {}                          # group name -> its last row, so a section joins its group wherever it comes in the order
        self.leave_guard = None                    # (from index, to index) -> False to stay on the section being left
        self._filling = False
        self._auto = False                         # folded because the window is narrow (not stored)
        self._collapsed = False
        self._badges = set()
        from ui.backdrop import Backdrop
        self.side = QWidget()                      # the sidebar
        self.side.setObjectName("sidebar")
        self.mark = Beat(LOGO)                     # the logo; it beats slowly under Motion: Lively
        self._brand = QLabel(title)
        self._brand.setObjectName("brand")
        self.fold = QPushButton()                  # folds the sidebar to icons, and back
        self.fold.setProperty("ghost", True)
        self.fold.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.fold.setFixedSize(32, 32)
        self.fold.clicked.connect(lambda: self.setCollapsed(not self._collapsed))
        self.org_label = QLabel("Organization")
        self.org_label.setProperty("muted", True)
        self.org = QComboBox()                     # the organization being looked at: every section follows it
        self.org.setObjectName("orgPicker")
        self.org.setToolTip("The organization every section shows. Global lists every organization.")
        self.org.currentIndexChanged.connect(lambda _i: None if self._filling else self.org_changed.emit(int(self.org.currentData() or 0)))
        self.quick = QPushButton()                 # the command palette (Ctrl+K) is easy to miss otherwise
        self.quick.setProperty("ghost", True)
        self.quick.setObjectName("navSearch")
        self.quick.setToolTip("Search   (Ctrl+K)\nJump to a section, tool, device or action")
        self.quick.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.quick.setMinimumHeight(36)
        self.quick.clicked.connect(self.search_requested)
        self.list = QListWidget()                  # the sections, one under another, with their group names
        self.list.setObjectName("nav")
        self.list.setSpacing(0)
        self.list.setMovement(QListView.Movement.Static)
        self.list.setIconSize(QSize(NAV_ICON, NAV_ICON))
        self.list.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list.setFrameShape(QListWidget.Shape.NoFrame)
        head = QHBoxLayout()
        head.setContentsMargins(0, 0, 0, 0)
        head.setSpacing(8)
        head.addWidget(self.mark)
        head.addWidget(self._brand, 1)
        head.addWidget(self.fold)
        col = QVBoxLayout(self.side)
        col.setContentsMargins(10, 12, 10, 10)
        col.setSpacing(6)
        col.addLayout(head)
        col.addSpacing(4)
        col.addWidget(self.org_label)
        col.addWidget(self.org)
        col.addWidget(self.quick)
        col.addSpacing(2)
        col.addWidget(self.list, 1)
        self.stack = QStackedWidget()
        self.stack.setMaximumWidth(CONTENT_WIDTH)
        self.backdrop = Backdrop()                 # the page colour, and a theme's glow or wash, behind the sections
        body = QHBoxLayout(self.backdrop)          # the section in the middle, as wide as it may be; the rest of the width is margin
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addStretch(1)
        body.addWidget(self.stack, 100)
        body.addStretch(1)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(self.side)
        lay.addWidget(self.backdrop, 1)
        self.list.currentRowChanged.connect(self._row_changed)
        self.list.viewport().installEventFilter(self)       # the spacer follows the list's own height
        self.org.setVisible(False)
        self.org_label.setVisible(False)
        self._apply_mode()

    # ---------- what the sidebar shows
    def collapsed(self):
        return self._collapsed

    def _icons_only(self):
        """Only icons show, either because that was chosen (Ctrl+B) or because the window is too narrow for the names."""
        return self._collapsed or self._auto

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
        self.org_label.setVisible(bool(orgs) and not self._icons_only())

    def setCollapsed(self, on):
        """The sections as icons only (names show as tooltips) or with their names."""
        on = bool(on)
        changed = on != self._collapsed
        self._collapsed = on
        self._apply_mode()
        if changed:
            self.collapsed_changed.emit(on)

    def _apply_mode(self):
        """Show the names or just the icons: in the sections, the group names, Search, the switcher and the fold button."""
        icons_only = self._icons_only()
        self.side.setFixedWidth(SIDE_FOLDED if icons_only else SIDE_WIDTH)
        self.fold.setToolTip("Show the sidebar in full (Ctrl+B)" if self._collapsed else "Fold the sidebar to icons (Ctrl+B)")
        self._brand.setVisible(not icons_only)
        self.quick.setText("" if icons_only else "Search")
        self.org_label.setVisible(not icons_only and not self.org.isHidden())
        for row in self._headings:
            item = self.list.item(row)
            if row == self._spacer:
                continue
            item.setText("" if icons_only else item.data(Qt.ItemDataRole.UserRole))
            item.setSizeHint(QSize(0, 10 if icons_only else (NAV_HEADING if row else NAV_HEADING - 12)))
        for i in range(len(self._names)):
            self._label(i)
        self._place_spacer()
        self.restyle()

    def _label(self, i):
        """What section i shows: its icon and name, and a dot after the name when something is new (on the icon when only icons show)."""
        item = self.list.item(self._rows[i])
        dot = i in self._badges
        icons_only = self._icons_only()
        item.setText("" if icons_only else self._names[i] + ("   ●" if dot else ""))
        item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | (Qt.AlignmentFlag.AlignHCenter if icons_only else Qt.AlignmentFlag.AlignLeft))
        item.setSizeHint(QSize(0, NAV_ITEM_FOLDED if icons_only else NAV_ITEM))
        tip = self._names[i] + ("   (new)" if dot and icons_only else "")
        item.setToolTip(tip + (f"   (Ctrl+{i + 1})" if i < 9 else ""))

    def _place_spacer(self):
        """The blank row before the bottom group takes whatever height is left, so Settings and About sit at the bottom."""
        if self._spacer is None:
            return
        used = sum(self.list.sizeHintForRow(r) for r in range(self.list.count()) if r != self._spacer)
        free = self.list.viewport().height() - used - 2
        self.list.item(self._spacer).setSizeHint(QSize(0, max(6, free)))

    def _fit(self):
        """A window too narrow for the names folds the sidebar to icons by itself; it unfolds again when there is room."""
        auto = self.width() < AUTO_FOLD_BELOW
        if auto != self._auto:
            self._auto = auto
            self._apply_mode()
        else:
            self._place_spacer()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._fit()

    def eventFilter(self, obj, event):
        if obj is self.list.viewport() and event.type() == QEvent.Type.Resize:
            self._place_spacer()
        return super().eventFilter(obj, event)

    def showEvent(self, event):
        super().showEvent(event)
        self._fit()

    def _row_changed(self, row):
        if row < 0 or row not in self._rows:
            return
        i = self._rows.index(row)
        was = self.stack.currentIndex()
        if self.leave_guard is not None and was >= 0 and was != i and not self.leave_guard(was, i):
            self.list.blockSignals(True)                   # stay where we were (unsaved settings, and the person chose to stay)
            self.list.setCurrentRow(self._rows[was])
            self.list.blockSignals(False)
            return
        self.stack.setMaximumWidth(16777215 if self._names[i] in WIDE_SECTIONS else CONTENT_WIDTH)
        self.stack.setCurrentIndex(i)
        self.currentChanged.emit(i)

    def _insert(self, row, item):
        """Put an item in at `row`, keeping every map of rows right."""
        self.list.insertItem(row, item)
        self._rows = [r + 1 if r >= row else r for r in self._rows]
        self._headings = [r + 1 if r >= row else r for r in self._headings]
        if self._spacer is not None and self._spacer >= row:
            self._spacer += 1
        for g, r in self._groups.items():
            if r >= row:
                self._groups[g] = r + 1

    def _start_group(self, group):
        """The heading row of a new group (or the blank spacer before the bottom group), placed before the bottom group if there is one."""
        row = self._spacer if self._spacer is not None else self.list.count()
        if group == self.BOTTOM:
            item = QListWidgetItem("")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.list.addItem(item)
            self._spacer = self.list.count() - 1
            self._headings.append(self._spacer)
            return self._spacer
        item = QListWidgetItem(group.upper())
        item.setData(Qt.ItemDataRole.UserRole, group.upper())
        item.setFlags(Qt.ItemFlag.NoItemFlags)
        f = item.font()
        f.setBold(True)
        f.setPointSizeF(max(7.0, f.pointSizeF() - 2))
        item.setFont(f)
        item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignBottom)
        self._insert(row, item)
        self._headings.append(row)
        return row

    def addTab(self, widget, label, icon_name=None, group=None):
        """A section. `group` names the heading it sits under; a section joins its group whatever its place in the order (the order
        is what Ctrl+1..9 and the stack know). NavStack.BOTTOM puts it at the bottom."""
        if widget.layout() is not None:
            widget.layout().setContentsMargins(*self.PAGE_MARGINS)
            widget.layout().setSpacing(12)
        key = group or ""
        if key not in self._groups:
            self._groups[key] = self._start_group(group) if group else -1
        after = self._groups[key]
        row = after + 1
        self.stack.addWidget(widget)
        item = QListWidgetItem(label)
        self._insert(row, item)
        self._rows.append(row)
        self._groups[key] = row
        self._names.append(label)
        self._icon_names.append(icon_name)
        self._label(len(self._names) - 1)
        self.restyle()
        if self.list.currentRow() < 0:
            self.list.setCurrentRow(self._rows[0])

    def row_of(self, i):
        """The list row of section i."""
        return self._rows[i]

    def item_for(self, widget):
        """The list item of a section (by its page)."""
        i = self.stack.indexOf(widget)
        return self.list.item(self._rows[i]) if i >= 0 else None

    def setBadge(self, widget, on):
        """Mark a section that has something new (a dot after its name, or on its icon when only icons show)."""
        i = self.stack.indexOf(widget)
        if i >= 0:
            (self._badges.add if on else self._badges.discard)(i)
            self._label(i)
            self.restyle()

    def restyle(self):
        """Re-tint the icons and re-measure the names after the theme, accent or text size changed."""
        t = theme.current()
        if not t:
            return
        icons_only = self._icons_only()
        f = QFont(QApplication.font())
        f.setPointSizeF(f.pointSizeF() * NAV_SCALE)
        self.list.setFont(f)
        for i, name in enumerate(self._icon_names):
            item = self.list.item(self._rows[i])
            if not name:
                item.setIcon(QIcon())
            elif icons_only and i in self._badges:             # the dot is on the icon when the name (and its dot) is hidden
                item.setIcon(icons.icon_with_dot(name, t.get("icon", t["muted"]), t["accent"]))
            else:                                              # the icon before the name; tinted in the accent on the current section
                item.setIcon(icons.icon(name, t.get("icon", t["muted"]), t["accent"]))
        self.fold.setIcon(icons.icon("panel", t.get("icon", t["muted"]), t["text"]))
        self.quick.setIcon(icons.icon("search", t.get("icon", t["muted"]), t["text"]))
        self.mark.restyle()
        self.backdrop.restyle()
        self._place_spacer()

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
            self.list.setCurrentRow(self._rows[i])

    def setCurrentIndex(self, i):
        self.list.setCurrentRow(self._rows[i])


FOLD_WIDTH = 36                                 # what a folded page list leaves: its button
HIDE_LIST, SHOW_LIST = "Hide the page list", "Show the page list"


def fold_button():
    """The small button that hides and shows a page list, as the Sessions list has."""
    b = QPushButton()
    b.setProperty("ghost", True)
    b.setFixedWidth(FOLD_WIDTH)
    b.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    return b


def show_fold(button, on):
    """The button's tooltip and icon for a list that is shown (on) or hidden."""
    button.setToolTip(HIDE_LIST if on else SHOW_LIST)
    t = theme.current()
    if t:
        button.setIcon(icons.icon("panel", t.get("icon", t["muted"]), t["text"]))
        button.setText("")
    else:
        button.setText("List")


def db_setting(key):
    from core import db
    return bool(db.get_setting(key))


class PageStack(QWidget):
    """A list of pages on the left (with optional section headings) and the chosen page on the right, with a button above
    the list that folds it away to give the page the width. `key`: the setting that remembers the list folded.
    Offers addTab, setCurrentWidget, currentWidget, indexOf, count and tabText like QTabWidget."""
    currentChanged = Signal(int)

    def __init__(self, width=190, key=None):
        super().__init__()
        self.key, self.width_open = key, width
        self.list = QListWidget()
        self.list.setObjectName("settingsNav")
        self.list.setFixedWidth(width)
        self.list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.fold = fold_button()
        self.side = QWidget()
        side = QVBoxLayout(self.side)
        side.setContentsMargins(0, 0, 0, 0)
        side.setSpacing(4)
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.addStretch(1)
        row.addWidget(self.fold)
        side.addLayout(row)
        side.addWidget(self.list, 1)
        side.addStretch(0)                      # folded, the button stays at the top
        self.stack = QStackedWidget()
        self._rows = []                         # page index -> list row
        self._pages = []                        # the pages themselves (each is inside a scroll area in the stack)
        self._names = []
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)
        lay.addWidget(self.side)
        lay.addWidget(self.stack, 1)
        self.list.currentRowChanged.connect(self._row_changed)
        self.fold.clicked.connect(lambda: self.show_list(not self.list_shown()))
        self.show_list(not (key and db_setting(key)), remember=False)

    def list_shown(self):
        return not self.list.isHidden()

    def show_list(self, on, remember=True):
        """Show the page list, or fold it to its button so the page gets the width."""
        self.list.setVisible(on)
        self.side.setFixedWidth(self.width_open if on else FOLD_WIDTH)
        show_fold(self.fold, on)
        if remember and self.key:
            from core import db
            db.set_setting(self.key, not on)

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
