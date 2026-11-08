"""Main window layout: a sidebar of sections on the left, in groups, with the current section centred beside it.

Offers the small part of QTabWidget's API that the rest of the app uses (addTab, setCurrentWidget,
currentWidget, indexOf, count, tabText), so sections can be switched from code.
"""
from PySide6.QtCore import QEvent, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QIcon
from PySide6.QtWidgets import (QApplication, QComboBox, QHBoxLayout, QLabel, QListView, QListWidget, QListWidgetItem, QPushButton, QScrollArea,
                               QStackedWidget, QStyledItemDelegate, QVBoxLayout, QWidget)
from ui import icons, theme
from ui import status as st


ITEM_HEIGHT = 36            # a row in a page list; Qt does not take the style sheet's padding into account by itself
HEADING_HEIGHT = 44        # a group heading: the room is above it, so the heading sits close to its own items
NAV_HEADING = 36            # a group name in the sidebar (less above the first)
NAV_BREAK = 18              # folded to icons, a group name becomes a short rule between the groups
NAV_ITEM = 34               # a section row in the sidebar
NAV_ITEM_FOLDED = 32        # and folded to its icon
SIDE_WIDTH = 236            # the sidebar with names
SIDE_FOLDED = 68            # and folded to icons
AUTO_FOLD_BELOW = 1000      # a window narrower than this folds the sidebar by itself (not stored)
CONTENT_WIDTH = 2400        # the widest a section gets, centred beside the sidebar: a 1920 or 2560 screen uses all of it; ultra-wide screens keep margins
WIDE_SECTIONS = ("Sessions",)   # sections that use the whole window width (a terminal or a remote desktop needs the room)
NAV_ICON = 21               # the icon before each section's name
NAV_SCALE = 1.0             # the section names, the size of the page text
LOGO = 32                   # the mark at the top of the sidebar
BADGE = 18                  # a count on a section's row (the Results row: devices needing attention)
FOLD = 28                   # the fold button: inside the sidebar's top row with the names, astride its edge when folded to icons


def see_through(widget):
    """A section's scroll areas let the page behind them show (the theme's wash or glow): a scroll area paints itself opaque otherwise."""
    areas = [widget] if isinstance(widget, QScrollArea) else []
    areas += widget.findChildren(QScrollArea)
    for area in areas:
        area.setStyleSheet("QScrollArea { background: transparent; }")
        area.viewport().setAutoFillBackground(False)
        if area.widget() is not None:
            area.widget().setAutoFillBackground(False)


class NavDelegate(QStyledItemDelegate):
    """Draws the sidebar's rows, and a count after a section's name (on its icon's corner when only icons show)."""

    def __init__(self, nav):
        super().__init__(nav.list)
        self.nav = nav

    def paint(self, p, opt, index):
        super().paint(p, opt, index)
        from PySide6.QtCore import QRectF
        from PySide6.QtGui import QFont, QFontMetrics, QPainter, QPen
        row = index.row()
        if self.nav.is_break(row):                                     # a short rule between the groups: in place of the name when folded, above it when open
            t = theme.current() or {}
            r = opt.rect
            y = r.top() + NAV_BREAK // 2                               # the same height from the row's top either way, so it never jumps
            p.save()
            p.setPen(QPen(QColor(t.get("border", "#444444")), 1))
            p.drawLine(r.left() + 14, y, r.right() - 14, y)
            p.restore()
            return
        n = self.nav.count_for_row(row)
        if not n:
            return
        bg, fg = st.chip(self.nav.tone_for_row(row))
        f = QFont(opt.font)
        f.setBold(True)
        f.setPointSizeF(max(7.0, f.pointSizeF() - 1.5))
        text = str(n)
        w = max(BADGE, QFontMetrics(f).horizontalAdvance(text) + 10)
        r = opt.rect
        if self.nav._icons_only():                                     # a small pill on the icon's top-right corner
            rect = QRectF(r.center().x() + 2, r.top() + 1, w, BADGE - 2)
        else:
            rect = QRectF(r.right() - w - 10, r.center().y() - BADGE / 2, w, BADGE)
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(bg.red(), bg.green(), bg.blue(), min(255, bg.alpha() * 2)))
        p.drawRoundedRect(rect, rect.height() / 2, rect.height() / 2)
        p.setPen(fg)
        p.setFont(f)
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)
        p.restore()


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
    """The sidebar on the left: the Toner mark, the organization switcher, Search, the sections in groups (Observability, Network,
    Work), and Settings and About at the bottom. Ctrl+B folds it to icons; a narrow window folds it by itself (not stored)."""
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
        self._off = set()                          # section indexes hidden for the signed-in role
        self._counts = {}                          # section index -> a number shown after its name (0 shows nothing)
        self._tones, self._words = {}, {}          # section index -> that number's colour ("FAIL" or "WARN"), and what it counts in words
        self._slide = None                         # the sidebar's width on its way between folded and open
        from ui.backdrop import Backdrop
        self.side = QWidget()                      # the sidebar
        self.side.setObjectName("sidebar")
        self.mark = Beat(LOGO)                     # the logo; it beats slowly under Motion: Lively
        self._brand = QLabel(title)
        self._brand.setObjectName("brand")
        self.fold = QPushButton(self)              # folds the sidebar to icons, and back: in the top row, or astride the edge when folded
        self.fold.setObjectName("navFold")
        self.fold.setProperty("ghost", True)
        self.fold.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.fold.setFixedSize(FOLD, FOLD)
        self.fold.clicked.connect(lambda: self.setCollapsed(not self._collapsed))
        self.org_label = QLabel("Organization")
        self.org_label.setProperty("muted", True)
        self.org = QComboBox()                     # the organization being looked at: every section follows it
        self.org.setObjectName("orgPicker")
        self.org.setAccessibleName("Organization")
        self.org.setToolTip("The organization every section shows. Global lists every organization.")
        self.org.currentIndexChanged.connect(lambda _i: None if self._filling else self.org_changed.emit(int(self.org.currentData() or 0)))
        self.quick = QPushButton()                 # the command palette (Ctrl+K) is easy to miss otherwise
        self.quick.setProperty("ghost", True)
        self.quick.setObjectName("navSearch")
        self.quick.setAccessibleName("Search Toner (Ctrl+K)")
        self.quick.setToolTip("Search   (Ctrl+K)\nJump to a section, tool, device or action")
        self.quick.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.quick.setMinimumHeight(36)
        self.quick.clicked.connect(self.search_requested)
        self.user = QPushButton()                  # who is signed in: Lock and Sign out (set_user)
        self.user.setProperty("ghost", True)
        self.user.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.user.setObjectName("navUser")                # the theme lays it out like Search, folded or open, with no menu arrow
        self.user.hide()
        self._user_name = ""
        self.list = QListWidget()                  # the sections, one under another, with their group names
        self.list.setObjectName("nav")
        self.list.setAccessibleName("Sections")
        self.list.setSpacing(0)
        self.list.setMovement(QListView.Movement.Static)
        self.list.setIconSize(QSize(NAV_ICON, NAV_ICON))
        self.list.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.list.setFocusPolicy(Qt.FocusPolicy.TabFocus)       # Tab reaches it, the arrow keys move between sections
        self.list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list.setFrameShape(QListWidget.Shape.NoFrame)
        self.list.setItemDelegate(NavDelegate(self))
        self.head = head = QHBoxLayout()           # the mark and the name; centred on the mark alone when folded
        head.setContentsMargins(0, 0, 0, 0)
        head.setSpacing(8)
        head.addSpacing((SIDE_FOLDED - 20 - LOGO) // 2)   # the mark's place: centred in the folded column, and the same when open
        head.addWidget(self.mark)
        head.addWidget(self._brand, 1)
        head.addSpacing(FOLD + 4)                  # where the fold button sits while the names show
        head.addStretch(0)
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

    def set_user(self, name, menu):
        """The signed-in account at the top of the sidebar; clicking it opens `menu`."""
        self._user_name = name
        self.user.setMenu(menu)
        self.user.setToolTip(name)
        self.user.setAccessibleName(name)
        self.user.setText("" if self._icons_only() else name)
        self.user.show()
        for r in range(self.list.count()):
            if self.list.itemWidget(self.list.item(r)) is self.user:
                self.list.setRowHidden(r, False)
        self._place_spacer()

    # ---------- what the sidebar shows
    def collapsed(self):
        return self._collapsed

    def _icons_only(self):
        """Only icons show, either because that was chosen (Ctrl+B) or because the window is too narrow for the names."""
        return self._collapsed or self._auto

    def is_break(self, row):
        """A group name's row carries a short rule between the groups: in place of the name when folded, above it when open (none
        above the first group)."""
        return row in self._headings and row != self._spacer and row != 0

    def _place_fold(self):
        """The fold button: at the right of the top row while the names show; astride the sidebar's edge, just outside it, when
        folded. It rides along while the sidebar slides."""
        m = self.side.layout().contentsMargins()
        w = self.side.width()
        if self._icons_only():
            self.fold.move(w - FOLD // 2, m.top() + (LOGO - FOLD) // 2)
        else:
            self.fold.move(w - m.right() - FOLD, m.top() + (LOGO - FOLD) // 2)
        self.fold.raise_()

    def _slide_to(self, width, heights, then=None):
        """One motion to the folded or open sidebar: its width and its rows' heights (the group headings, the sections) ease there
        together, ease-out, never past the end (a bounce squeezed the icons). `then` runs at the end. At once with motion off, or before
        the window is up."""
        from ui import motion
        motion.stop(self._slide)
        self._slide = None
        start = self.side.width()
        before = {row: self.list.item(row).sizeHint().height() for row in heights}

        def step(p):
            self.side.setFixedWidth(round(start + (width - start) * p))
            for row, h in heights.items():
                self.list.item(row).setSizeHint(QSize(0, round(before[row] + (h - before[row]) * p)))
            self._place_spacer()
            self._place_fold()

        def done():
            self._slide = None
            if then:
                then()
        if (start == width and before == heights) or not motion.enabled() or not self.isVisible():
            step(1.0)
            return done()
        self._slide = motion.animate(self, 320, step, on_done=done)

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

    def _heights(self, icons_only):
        """{row: height} for the group headings and the sections, folded or open."""
        h = {row: (NAV_BREAK if row else 6) if icons_only else (NAV_HEADING if row else NAV_HEADING - 12) for row in self._headings
             if row != self._spacer}
        h.update({row: NAV_ITEM_FOLDED if icons_only else NAV_ITEM for row in self._rows})
        return h

    def _apply_mode(self):
        """Show the names or just the icons, as one motion: folding, the group names go at once (their rule stays put as the rows
        shrink) and the other names when the sidebar is narrow; opening, the names come back at once and show as it widens. The mark
        never moves sideways."""
        icons_only = self._icons_only()
        self.fold.setToolTip("Show the sidebar in full (Ctrl+B)" if self._collapsed else "Fold the sidebar to icons (Ctrl+B)")
        self._heading_names(not icons_only)
        if icons_only:
            self._slide_to(SIDE_FOLDED, self._heights(True), then=lambda: self._names_shown(not self._icons_only()))
        else:
            self._names_shown(True)
            self._slide_to(SIDE_WIDTH, self._heights(False))
        self._place_fold()
        self.restyle()

    def _heading_names(self, on):
        for row in self._headings:
            if row != self._spacer:
                item = self.list.item(row)
                item.setText(item.data(Qt.ItemDataRole.UserRole) if on else "")

    def _names_shown(self, on):
        """The names beside the icons: the sections', the brand's, Search's and the account's (centred icons when off)."""
        self._brand.setVisible(on)
        self.head.itemAt(3).changeSize(FOLD + 4 if on else 0, 0)       # where the fold button sits while the names show
        self.head.invalidate()
        self.quick.setText("Search" if on else "")
        self.user.setText(self._user_name if on else "")
        for b in (self.quick, self.user):                              # the icon alone, in the middle of the button
            b.setProperty("folded", not on)
            b.style().unpolish(b)
            b.style().polish(b)
        self.org_label.setVisible(on and not self.org.isHidden())
        for i in range(len(self._names)):
            self._label(i, sized=False)
        self._place_spacer()

    def _label(self, i, sized=True):
        """What section i shows: its icon and name, and a dot after the name when something is new (on the icon when only icons show).
        sized: its row's height too (not while the sidebar is sliding, which sets the heights)."""
        item = self.list.item(self._rows[i])
        dot = i in self._badges
        icons_only = self._icons_only()
        item.setText("" if icons_only else self._names[i] + ("   ●" if dot else ""))
        item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | (Qt.AlignmentFlag.AlignHCenter if icons_only else Qt.AlignmentFlag.AlignLeft))
        if sized and self._slide is None:
            item.setSizeHint(QSize(0, NAV_ITEM_FOLDED if icons_only else NAV_ITEM))
        tip = self._names[i] + ("   (new)" if dot and icons_only else "")
        item.setToolTip(tip + (f"   (Ctrl+{i + 1})" if i < 9 else "") + (f"\n{self._words[i]}" if self._words.get(i) else ""))

    def _place_spacer(self):
        """The blank row before the bottom group takes whatever height is left, so Settings and About sit at the bottom."""
        if self._spacer is None:
            return
        used = sum(self.list.sizeHintForRow(r) for r in range(self.list.count()) if r != self._spacer and not self.list.isRowHidden(r))
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
        self._place_fold()

    def eventFilter(self, obj, event):
        if obj is self.list.viewport() and event.type() == QEvent.Type.Resize:
            self._place_spacer()
        return super().eventFilter(obj, event)

    def showEvent(self, event):
        super().showEvent(event)
        self._fit()
        if self.stack.currentIndex() >= 0:
            QTimer.singleShot(0, lambda: self._entered(self.stack.currentIndex()))     # the first section, once the window is up

    def _row_changed(self, row):
        if row < 0 or row not in self._rows:
            return
        i = self._rows.index(row)
        if i in self._off:
            return
        was = self.stack.currentIndex()
        if self.leave_guard is not None and was >= 0 and was != i and not self.leave_guard(was, i):
            self.list.blockSignals(True)                   # stay where we were (unsaved settings, and the person chose to stay)
            self.list.setCurrentRow(self._rows[was])
            self.list.blockSignals(False)
            return
        self.stack.setMaximumWidth(16777215 if self._names[i] in WIDE_SECTIONS else CONTENT_WIDTH)
        self.stack.setCurrentIndex(i)
        self.currentChanged.emit(i)
        self._entered(i)

    def _entered(self, i):
        """A section came into view: it may bring its lists in with motion (`entered()`, where a section has one)."""
        w = self.stack.widget(i)
        if w is not None and hasattr(w, "entered"):
            w.entered()

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
            row = QListWidgetItem("")                                   # the signed-in user, in the row above Settings
            row.setFlags(Qt.ItemFlag.NoItemFlags)
            row.setSizeHint(QSize(0, NAV_ITEM))
            self.list.addItem(row)
            self.list.setItemWidget(row, self.user)
            self.list.setRowHidden(self.list.count() - 1, True)
            return self.list.count() - 1
        item = QListWidgetItem(group)
        item.setData(Qt.ItemDataRole.UserRole, group)
        item.setFlags(Qt.ItemFlag.NoItemFlags)
        f = item.font()
        f.setBold(True)
        f.setPointSizeF(max(8.5, f.pointSizeF() - 0.5))                # a group name reads as a heading, not a footnote
        f.setLetterSpacing(QFont.SpacingType.PercentageSpacing, 108)
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
        see_through(widget)
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

    def setTabVisible(self, widget, on):
        """Show or hide a section (by its page) in the list; a group heading with no section left shows nothing. A hidden section
        can't be selected, and leaving it moves to the first one shown."""
        i = self.stack.indexOf(widget)
        if i < 0:
            return
        (self._off.discard if on else self._off.add)(i)
        self.list.setRowHidden(self._rows[i], not on)
        head = None                                # a group heading shows while a section under it does
        for r in range(self.list.count()):
            if r in self._headings:
                if head is not None:
                    self.list.setRowHidden(head[0], not head[1])
                head = None if r == self._spacer else [r, False]
            elif head is not None and not self.list.isRowHidden(r):
                head[1] = True
        if head is not None:
            self.list.setRowHidden(head[0], not head[1])
        if not on and self.stack.currentIndex() == i:
            first = next((j for j in range(len(self._rows)) if j not in self._off), None)
            if first is not None:
                self.list.setCurrentRow(self._rows[first])
        self._place_spacer()

    def shown(self, i):
        return i not in self._off

    def row_of(self, i):
        """The list row of section i."""
        return self._rows[i]

    def item_for(self, widget):
        """The list item of a section (by its page)."""
        i = self.stack.indexOf(widget)
        return self.list.item(self._rows[i]) if i >= 0 else None

    def setBadge(self, widget, on, tone="FAIL", words=""):
        """Mark a section that has something new: True puts a dot after its name (on its icon when only icons show); a number is
        drawn as a count after the name, in the colour of `tone` ("FAIL", or "WARN" when only warnings are left), with `words` in
        its tooltip; 0 or False clears it."""
        i = self.stack.indexOf(widget)
        if i < 0:
            return
        if isinstance(on, bool) or on is None:
            (self._badges.add if on else self._badges.discard)(i)
        else:
            self._counts[i] = int(on)
            self._tones[i], self._words[i] = tone, (words if on else "")
        self._label(i)
        self.restyle()
        self.list.viewport().update()

    def count_for_row(self, row):
        """The number drawn on this list row, if it is a section with one."""
        return self._counts.get(self._rows.index(row), 0) if row in self._rows else 0

    def tone_for_row(self, row):
        """The status colour of that row's count: "FAIL", or "WARN" when only warnings are left."""
        return self._tones.get(self._rows.index(row), "FAIL") if row in self._rows else "FAIL"

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
        self.user.setIcon(icons.icon("user", t.get("icon", t["muted"]), t["text"]))
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
        if i >= 0 and i not in self._off:
            self.list.setCurrentRow(self._rows[i])

    def setCurrentIndex(self, i):
        if i not in self._off:
            self.list.setCurrentRow(self._rows[i])


FOLD_WIDTH = 36                                 # what a folded page list leaves: its button
HIDE_LIST, SHOW_LIST = "Hide the page list", "Show the page list"


def fold_button():
    """The small button that hides and shows a page list, as the Sessions list has."""
    b = QPushButton()
    b.setProperty("ghost", True)
    b.setFixedWidth(FOLD_WIDTH)
    b.setFocusPolicy(Qt.FocusPolicy.TabFocus)
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
        self.list.setAccessibleName("Pages")
        self.list.setFixedWidth(width)
        self.list.setFocusPolicy(Qt.FocusPolicy.TabFocus)
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
        self._off = set()                       # page indexes hidden for the signed-in role
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
        item = QListWidgetItem(title)                                  # (sentence case, a step smaller: no tracked capitals)
        item.setFlags(Qt.ItemFlag.NoItemFlags)
        f = item.font()
        f.setBold(True)
        f.setPointSizeF(max(8.5, f.pointSizeF() - 1))
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
        see_through(area)
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
            if i in self._off:
                return
            self.stack.setCurrentIndex(i)
            self.currentChanged.emit(i)
            if row > 0 and not (self.list.item(row - 1).flags() & Qt.ItemFlag.ItemIsSelectable):
                self.list.scrollToItem(self.list.item(row - 1))      # the first page of a group keeps its heading in view

    def setTabVisible(self, widget, on):
        """Show or hide a page in the list (a section heading with nothing left under it hides too). A hidden page can't be selected."""
        i = self.indexOf(widget)
        if i < 0:
            return
        (self._off.discard if on else self._off.add)(i)
        self.list.setRowHidden(self._rows[i], not on)
        head = None
        for r in range(self.list.count()):
            if r in self._rows:
                if head is not None and not self.list.isRowHidden(r):
                    head[1] = True
            else:
                if head is not None:
                    self.list.setRowHidden(head[0], not head[1])
                head = [r, False]
        if head is not None:
            self.list.setRowHidden(head[0], not head[1])
        if not on and self.stack.currentIndex() == i:
            first = next((j for j in range(len(self._rows)) if j not in self._off), None)
            if first is not None:
                self.list.setCurrentRow(self._rows[first])

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
        if i >= 0 and i not in self._off:
            self.list.setCurrentRow(self._rows[i])

    def setCurrentIndex(self, i):
        if i not in self._off:
            self.list.setCurrentRow(self._rows[i])
