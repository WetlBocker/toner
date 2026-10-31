from PySide6.QtCore import QEvent, QObject, QPoint, QPointF, QRect, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QIcon, QIconEngine, QPainter, QPalette, QPen, QPixmap, QPolygonF
from PySide6.QtWidgets import (QAbstractButton, QAbstractSpinBox, QApplication, QCheckBox, QComboBox, QHBoxLayout, QHeaderView, QLabel, QLayout, QLineEdit,
                               QMenu, QPushButton, QSizePolicy, QStyle, QStyledItemDelegate, QStyleOptionViewItem, QToolButton,
                               QVBoxLayout, QWidget, QWidgetAction)
from core import db, reports
from ui import status as st, theme


def remember_sizes(splitter, key):
    """Start a splitter at the sizes it had last time on this computer (the 'splitters' setting, one entry per pane), and keep
    the new sizes once it has been dragged. A wider window keeps the proportions."""
    saved = (db.get_setting("splitters") or {}).get(key)
    if saved and len(saved) == splitter.count():
        splitter.setSizes([int(s) for s in saved])
    timer = QTimer(splitter)
    timer.setSingleShot(True)
    timer.setInterval(400)                                   # one write per drag, not one per pixel
    timer.timeout.connect(lambda: db.set_setting("splitters", {**(db.get_setting("splitters") or {}), key: splitter.sizes()}))
    splitter.splitterMoved.connect(lambda *_: timer.start())


class FlowLayout(QLayout):
    """A row of controls that wraps onto more lines when the window is too narrow, instead of squeezing or overlapping.
    On a wide window it looks like an ordinary row: boxes that can grow (text fields) share the spare width."""

    def __init__(self, hspacing=8, vspacing=6):
        super().__init__()
        self._items, self._h, self._v = [], hspacing, vspacing
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item):
        self._items.append(item)

    def addStretch(self, *_):                      # accepted so it can stand in for a QHBoxLayout; the row just ends there
        pass

    def count(self):
        return len(self._items)

    def itemAt(self, i):
        return self._items[i] if 0 <= i < len(self._items) else None

    def takeAt(self, i):
        return self._items.pop(i) if 0 <= i < len(self._items) else None

    def expandingDirections(self):
        return Qt.Orientation(0)

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self._arrange(QRect(0, 0, width, 0), True)

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self._arrange(rect, False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for it in self._items:
            size = size.expandedTo(it.minimumSize())
        m = self.contentsMargins()
        return size + QSize(m.left() + m.right(), m.top() + m.bottom())

    @staticmethod
    def _grows(item):
        """Whether an item takes a share of the spare width. A widget says so with its own size policy: a pair whose box is capped
        (a country code) must not grow just because the line edit inside it would."""
        w = item.widget()
        policy = w.sizePolicy().expandingDirections() if w is not None else item.expandingDirections()
        return bool(policy & Qt.Orientation.Horizontal)

    def _arrange(self, rect, test):
        m = self.contentsMargins()
        eff = rect.adjusted(m.left(), m.top(), -m.right(), -m.bottom())
        avail = max(1, eff.width())
        lines, line, used = [], [], 0
        for it in self._items:
            if it.isEmpty():
                continue
            w = max(min(it.sizeHint().width(), avail), min(it.minimumSize().width(), avail))
            need = w + (self._h if line else 0)
            if line and used + need > avail:
                lines.append(line)
                line, used, need = [], 0, w
            line.append([it, w])
            used += need
        if line:
            lines.append(line)
        y = eff.y()
        for line in lines:
            height = max(it.sizeHint().height() for it, _ in line)
            extra = avail - sum(w for _, w in line) - self._h * (len(line) - 1)
            grow = [e for e in line if self._grows(e[0])]
            if extra > 0 and grow:
                share, rest = divmod(extra, len(grow))
                for k, e in enumerate(grow):
                    e[1] += share + (1 if k < rest else 0)
            x = eff.x()
            for it, w in line:
                if not test:
                    ih = it.sizeHint().height()
                    it.setGeometry(QRect(x, y + (height - ih) // 2, w, ih))
                x += w + self._h
            y += height + self._v
        return (y - self._v - eff.y() if lines else 0) + m.top() + m.bottom()


def _pair(label, widget):
    """A caption and its box kept together, so a wrap never separates them."""
    box = QWidget()
    h = QHBoxLayout(box)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(6)
    lab = label if isinstance(label, QLabel) else QLabel(label)
    grows = bool(widget.sizePolicy().expandingDirections() & Qt.Orientation.Horizontal) and widget.maximumWidth() >= 16777215   # a box capped in width (a country code) keeps its size
    h.addWidget(lab)
    h.addWidget(widget, 1 if grows else 0)
    box.setSizePolicy(QSizePolicy.Policy.Expanding if grows else QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
    return box


def flow(*items):
    """A wrapping row. Text (or a QLabel) followed by a box is a caption for that box and stays with it; everything else
    (buttons, tick boxes, a lone label) is its own item."""
    row = FlowLayout()
    items = list(items)
    i = 0
    while i < len(items):
        it = items[i]
        nxt = items[i + 1] if i + 1 < len(items) else None
        is_caption = isinstance(it, str) or (isinstance(it, QLabel) and it.parent() is None)
        if is_caption and nxt is not None and not isinstance(nxt, (str, QLabel)) and isinstance(nxt, QWidget):
            row.addWidget(_pair(it, nxt))
            i += 2
        else:
            row.addWidget(QLabel(it) if isinstance(it, str) else it)
            i += 1
    return row


class _FunnelEngine(QIconEngine):
    """Draws the funnel when it is shown, in the palette's text colour then, so it follows a change of theme."""

    def paint(self, painter, rect, mode, state):
        c = QApplication.palette().text().color()
        if mode == QIcon.Mode.Disabled:
            c = QApplication.palette().color(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        k = min(rect.width(), rect.height()) / 32.0
        painter.translate(rect.x() + (rect.width() - 32 * k) / 2, rect.y() + (rect.height() - 32 * k) / 2)
        painter.scale(k, k)
        painter.setPen(QPen(c, 3.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPolygon(QPolygonF([QPointF(5, 7), QPointF(27, 7), QPointF(18, 17), QPointF(18, 26), QPointF(14, 24),
                                       QPointF(14, 17)]))
        painter.restore()

    def pixmap(self, size, mode, state):
        pm = QPixmap(size)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        self.paint(p, pm.rect(), mode, state)
        p.end()
        return pm

    def clone(self):
        return _FunnelEngine()


def filter_icon():
    """The funnel used by every filter button."""
    return QIcon(_FunnelEngine())


class FilterButton(QToolButton):
    """A funnel button that opens a menu with one submenu of tick boxes per kind of filter (Status, Location, ...).
    Ticking several values in one submenu means 'any of these'; different submenus must all match. The button shows
    how many values are ticked. It looks and behaves like the filter button on the Inventory tab."""
    changed = Signal()

    def __init__(self, tip="Filter"):
        super().__init__()
        self.tip = tip
        self.sections = {}                        # title -> [(shown text, value)]
        self.picked = {}                          # title -> set of ticked values
        self.setIcon(filter_icon())
        self.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.setStyleSheet("QToolButton::menu-indicator { image: none; }")
        self.menu = QMenu(self)
        self.menu.aboutToShow.connect(self._build)
        self.setMenu(self.menu)
        self._update()

    def set_sections(self, sections):
        """sections: {title: [(shown text, value), ...]}. Ticks for values that no longer exist are dropped.
        Does not emit."""
        self.sections = {k: list(v) for k, v in sections.items()}
        for title in list(self.picked):
            have = {val for _, val in self.sections.get(title, [])}
            self.picked[title] = self.picked[title] & have
        self._update()

    def selected(self, title):
        return set(self.picked.get(title, ()))

    def filtering(self):
        return any(self.picked.values())

    def clear(self):
        self.picked = {}
        self._update()
        self.changed.emit()

    def describe(self):
        """'Status: FAIL; Location: Chicago, Denver' for the ticked values, in menu order."""
        parts = []
        for title, opts in self.sections.items():
            names = [text for text, val in opts if val in self.picked.get(title, ())]
            if names:
                parts.append(f"{title}: {', '.join(names)}")
        return "; ".join(parts)

    def _build(self):
        self.menu.clear()
        for title, opts in self.sections.items():
            sub = self.menu.addMenu(title)
            if not opts:
                sub.setEnabled(False)
            for text, val in opts:
                box = QCheckBox(text)                 # a widget action keeps the menu open while ticking
                box.setChecked(val in self.picked.get(title, ()))
                box.toggled.connect(lambda on, title=title, val=val: self._toggle(title, val, on))
                act = QWidgetAction(sub)
                act.setDefaultWidget(box)
                sub.addAction(act)
        self.menu.addSeparator()
        self.menu.addAction("Clear filter", self.clear).setEnabled(self.filtering())

    def _toggle(self, title, val, on):
        s = self.picked.setdefault(title, set())
        (s.add if on else s.discard)(val)
        self._update()
        self.changed.emit()

    def _update(self):
        n = sum(len(v) for v in self.picked.values())
        text = self.describe()
        self.setToolTip(f"Filter: {text}" if text else self.tip)
        self.setText(f" {n}" if n else "")
        self.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon if n else Qt.ToolButtonStyle.ToolButtonIconOnly)


class StatusDelegate(QStyledItemDelegate):
    """Draws a status word (OK / WARN / FAIL / ERROR) as a soft chip: a faint tint of the status colour behind a small icon and the word
    in the readable ink. Colours are looked up when painting, so a change in Settings > Appearance shows immediately."""
    GLYPH = 10

    def paint(self, painter, option, index):
        status = index.data(Qt.ItemDataRole.DisplayRole)
        if not reports.COLORS.get(status):
            return super().paint(painter, option, index)
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.text = ""
        style = opt.widget.style() if opt.widget else QApplication.style()
        style.drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, opt.widget)
        terminal = theme.is_terminal()
        font = QFont(option.font)
        font.setBold(True)
        font.setPointSizeF(max(7.0, font.pointSizeF() - (1.5 if terminal else 1)))
        painter.save()
        painter.setFont(font)
        fm = painter.fontMetrics()
        pad, gap = (6, 4) if terminal else (9, 5)
        w, h = fm.horizontalAdvance(status) + pad * 2 + self.GLYPH + gap, fm.height() + (2 if terminal else 4)
        r = QRect(option.rect.left() + 6, option.rect.center().y() - h // 2, w, h)
        bg, ink = st.chip(status)
        rad = min(st.radius(), h / 2)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(bg)
        painter.drawRoundedRect(r, rad, rad)
        pm = st.glyph(status, self.GLYPH)
        if pm:
            painter.drawPixmap(r.left() + pad, r.center().y() - self.GLYPH // 2 + 1, pm)
        painter.setPen(ink)
        painter.drawText(QRect(r.left() + pad + self.GLYPH + gap, r.top(), w - pad * 2 - self.GLYPH - gap, h), Qt.AlignmentFlag.AlignCenter, status)
        painter.restore()

    def sizeHint(self, option, index):
        s = super().sizeHint(option, index)
        return QSize(s.width() + (28 if theme.is_terminal() else 34), s.height())


class _Chip(QLabel):
    clicked = Signal()

    def mousePressEvent(self, e):
        self.clicked.emit()


class StatChips(QWidget):
    """The counts as chips: All, OK, WARN, FAIL or ERROR, ERROR. Click one to show only those rows (picked), click it again for all."""
    ORDER = ["OK", "WARN", "FAIL", "ERROR"]
    KEYS = ["ALL"] + ORDER
    TIPS = {"ALL": "Show every result", "OK": "OK: the check passed", "WARN": "WARN: over a warning limit",
            "FAIL": "FAIL: the check ran and the device failed it", "ERROR": "ERROR: Toner couldn't run the check"}
    picked = Signal(str)                                  # "ALL", "OK", "WARN", "FAIL" (FAIL or ERROR) or "ERROR"

    def __init__(self):
        super().__init__()
        self.counts = {s: 0 for s in self.ORDER}
        self.current = "ALL"
        self.labels = {s: _Chip() for s in self.KEYS}
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        for key, lab in self.labels.items():
            lab.setToolTip(self.TIPS[key])
            lab.setCursor(Qt.CursorShape.PointingHandCursor)
            lab.clicked.connect(lambda k=key: self.pick(k))
            lay.addWidget(lab)
        self.set_counts({})

    def pick(self, key):
        self.current = "ALL" if key == self.current and key != "ALL" else key
        self.restyle()
        self.picked.emit(self.current)

    def set_counts(self, counts):
        self.counts = {s: int(counts.get(s, 0)) for s in self.ORDER}
        self.restyle()

    def restyle(self):
        total = sum(self.counts.values())
        t = theme.current() or {}
        for key, lab in self.labels.items():
            n = total if key == "ALL" else self.counts[key] + (self.counts["ERROR"] if key == "FAIL" else 0)
            lab.setText(f"All {n}" if key == "ALL" else f"{n} {key}" + (" or ERROR" if key == "FAIL" else ""))
            on = key == self.current
            ring = f" border:1px solid {t.get('accent', '#2563eb')};" if on else ""
            if key == "ALL":
                lab.setStyleSheet(f"background:{t.get('accent_soft', 'transparent') if on else 'transparent'}; color:{t.get('text', 'palette(text)')}; "
                                  f"border-radius:{st.radius()}px; padding:1px 10px; font-weight:600;{ring or ' border:1px solid palette(mid);'}")
            elif n:
                lab.setStyleSheet(st.chip_css(key) + ring)
            else:                                         # nothing of this kind: show it, but quietly
                lab.setStyleSheet(f"background:transparent; color:palette(placeholder-text); border-radius:{st.radius()}px; "
                                  "padding:0px 9px; border:1px solid palette(mid);")


class SectionHeader(QWidget):
    """The top line of a section: its name, one line of context ("8 devices, 2 failing") and, on the right, its main actions.
    Every section has one, so where to look and where to click is the same everywhere."""

    def __init__(self, title, context=""):
        super().__init__()
        self.title = QLabel(title)
        self.title.setProperty("title", True)
        self.context = QLabel(context)
        self.context.setProperty("muted", True)
        self.context.setWordWrap(True)                     # a long line wraps under itself instead of pushing the actions off
        self.context.setMinimumWidth(80)
        self.lay = QHBoxLayout(self)
        self.lay.setContentsMargins(0, 0, 0, 4)
        self.lay.setSpacing(10)
        self.lay.addWidget(self.title)
        self.lay.addWidget(self.context, 1)

    def set_context(self, text):
        self.context.setText(text)

    def add(self, *widgets):
        for w in widgets:
            self.lay.addWidget(w)
        return self


class filling:
    """`with filling(table):` refill a table without it measuring itself again after every cell. Columns that fit their contents
    are held at their width while the cells go in, then fitted once at the end. Without this, replacing the cells of a table
    that already has a few hundred rows takes seconds: Qt measures every row again after each cell."""

    def __init__(self, table):
        self.table = table

    def __enter__(self):
        hh = self.table.horizontalHeader()
        self.fit = [i for i in range(hh.count()) if hh.sectionResizeMode(i) == QHeaderView.ResizeMode.ResizeToContents]
        for i in self.fit:
            hh.setSectionResizeMode(i, QHeaderView.ResizeMode.Fixed)
        return self.table

    def __exit__(self, *exc):
        hh = self.table.horizontalHeader()
        for i in self.fit:
            hh.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        return False


class EmptyHint(QWidget):
    """A centred message laid over an empty list or table, with optional buttons for the next step. Show or hide it as the view fills."""

    def __init__(self, view, title, detail="", actions=(), wrap=False):
        super().__init__(view.viewport())
        self.view = view
        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.head = QLabel(title)
        self.head.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.head.setWordWrap(wrap)                          # in a narrow list the title wraps instead of being cut off
        self.head.setStyleSheet("font-size: 13pt; font-weight: 600; background: transparent;")
        self.sub = QLabel(detail)
        self.sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.sub.setProperty("muted", True)
        self.sub.setStyleSheet("background: transparent;")
        self.sub.setWordWrap(wrap)
        lay.addWidget(self.head)
        lay.addWidget(self.sub)
        self.bar = QHBoxLayout()
        self.bar.setSpacing(8)
        self.bar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addSpacing(6)
        lay.addLayout(self.bar)
        self.buttons = []
        self.set_actions(actions)
        view.viewport().installEventFilter(self)
        self._place()

    def set_text(self, title, detail=""):
        self.head.setText(title)
        self.sub.setText(detail)
        self._place()

    def set_actions(self, actions):
        """[(text, callable)] or [(text, callable, primary)]: buttons under the message. The first one is the main one unless said."""
        for b in self.buttons:
            b.hide()
            self.bar.removeWidget(b)
            b.setParent(None)
            b.deleteLater()
        self.buttons = []
        for n, spec in enumerate(actions or ()):
            text, fn = spec[0], spec[1]
            b = QPushButton(text)
            b.setProperty("primary", bool(spec[2]) if len(spec) > 2 else n == 0)
            b.setAutoDefault(False)
            b.clicked.connect(lambda _=False, fn=fn: fn())
            self.bar.addWidget(b)
            self.buttons.append(b)
        # without buttons the hint lets clicks through to the view (right-click, drops); with them it takes only its own rectangle
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, not self.buttons)
        self._place()

    def _place(self):
        r = self.view.viewport().rect()
        if not self.buttons:
            self.setGeometry(r)
            return
        hint = self.sizeHint()
        w, h = min(r.width(), max(hint.width(), 360)), min(r.height(), hint.height())
        self.setGeometry(r.x() + (r.width() - w) // 2, r.y() + (r.height() - h) // 2, w, h)

    def eventFilter(self, obj, ev):
        if obj is self.view.viewport() and ev.type() == QEvent.Type.Resize:
            self._place()
        return False

class GroupPicker(QToolButton):
    """Drop-down of checkboxes. Nothing ticked means 'everything'; several ticked = union."""
    changed = Signal()

    def __init__(self, all_text="All devices", noun="groups", clear_text=None):
        super().__init__()
        self.all_text, self.noun = all_text, noun
        self.clear_text = clear_text or f"{all_text} (clear selection)"
        self.boxes = {}
        self.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.setMinimumWidth(170)
        self.menu = QMenu(self)
        self.setMenu(self.menu)
        self._update_text()

    def set_labels(self, labels):
        """Rebuild the list, keeping ticks for labels that still exist. Does not emit."""
        keep = {k for k, b in self.boxes.items() if b.isChecked()} & set(labels)
        self.menu.clear()
        self.boxes = {}
        clear = self.menu.addAction(self.clear_text)
        clear.triggered.connect(self.clear)
        self.menu.addSeparator()
        for label in labels:
            box = QCheckBox(label)
            box.setChecked(label in keep)
            box.toggled.connect(self._toggled)
            act = QWidgetAction(self.menu)
            act.setDefaultWidget(box)             # a widget action keeps the menu open on click
            self.menu.addAction(act)
            self.boxes[label] = box
        self._update_text()

    def selected(self):
        return [k for k, b in self.boxes.items() if b.isChecked()]

    def set_selected(self, labels):
        """Tick exactly these labels (unknown ones are ignored). Does not emit."""
        for k, b in self.boxes.items():
            b.blockSignals(True)
            b.setChecked(k in labels)
            b.blockSignals(False)
        self._update_text()

    def clear(self):
        for b in self.boxes.values():
            b.blockSignals(True)
            b.setChecked(False)
            b.blockSignals(False)
        self._toggled()

    def _toggled(self, *_):
        self._update_text()
        self.changed.emit()

    def _update_text(self):
        sel = self.selected()
        text = ", ".join(sel) if sel else self.all_text
        self.setText(text if len(text) <= 32 else f"{len(sel)} {self.noun} selected")
        self.setToolTip(", ".join(sel) if sel else self.all_text)


class MenuPlacer(QObject):
    """A menu that drops down from a button (New session, More, Add channel, the filters) opens above the button when there is
    not room for it below, inside Toner's window as well as on the screen. Qt only checks the screen, and under WSLg (and some
    Linux desktops) the screen it is told about is not the one shown, so a menu near the bottom was cut off."""

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.Show and isinstance(obj, QMenu):
            button = obj.parentWidget()
            if isinstance(button, QAbstractButton) and button.isVisible():
                place_menu(obj, button)
        return False


def place_menu(menu, button):
    """Put `menu` below `button`, or above it when it would not fit below (in the window and on the screen)."""
    win = button.window()
    top_left = button.mapToGlobal(QPoint(0, 0))
    below, above = top_left.y() + button.height(), top_left.y()
    h = menu.sizeHint().height()
    bounds = win.geometry() if win is not None else None
    screen = button.screen().availableGeometry() if button.screen() else None
    limit = min(r.bottom() for r in (bounds, screen) if r is not None) if (bounds or screen) else None
    if limit is not None and below + h > limit and above - h >= ((screen.top() if screen else 0)):
        menu.move(menu.x(), above - h)

