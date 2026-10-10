from PySide6.QtCore import QEvent, QPointF, QRect, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPen, QPixmap, QPolygonF
from PySide6.QtWidgets import (QApplication, QCheckBox, QHBoxLayout, QLabel, QMenu, QStyle, QStyledItemDelegate,
                               QStyleOptionViewItem, QToolButton, QVBoxLayout, QWidget, QWidgetAction)
from core import reports


def filter_icon():
    """The funnel used by every filter button."""
    pm = QPixmap(32, 32)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(QPen(QApplication.palette().text().color(), 2.4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap,
                  Qt.PenJoinStyle.RoundJoin))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPolygon(QPolygonF([QPointF(5, 7), QPointF(27, 7), QPointF(18, 17), QPointF(18, 26), QPointF(14, 24),
                             QPointF(14, 17)]))
    p.end()
    return QIcon(pm)


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
    """Draws a status word (OK / WARN / FAIL / ERROR) as a coloured pill. Colours are looked up when painting,
    so a change in Settings > Appearance shows immediately."""

    def paint(self, painter, option, index):
        status = index.data(Qt.ItemDataRole.DisplayRole)
        bg = reports.COLORS.get(status)
        if not bg:
            return super().paint(painter, option, index)
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.text = ""
        style = opt.widget.style() if opt.widget else QApplication.style()
        style.drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, opt.widget)
        font = QFont(option.font)
        font.setBold(True)
        font.setPointSizeF(max(7.0, font.pointSizeF() - 1))
        painter.save()
        painter.setFont(font)
        fm = painter.fontMetrics()
        w, h = fm.horizontalAdvance(status) + 20, fm.height() + 4
        r = QRect(option.rect.left() + 6, option.rect.center().y() - h // 2, w, h)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(bg))
        painter.drawRoundedRect(r, h / 2, h / 2)
        painter.setPen(QColor(reports.fg_for(bg)))
        painter.drawText(r, Qt.AlignmentFlag.AlignCenter, status)
        painter.restore()

    def sizeHint(self, option, index):
        s = super().sizeHint(option, index)
        return QSize(s.width() + 22, s.height())


class StatChips(QWidget):
    """OK / WARN / FAIL / ERROR counters shown as small coloured pills."""
    ORDER = ["OK", "WARN", "FAIL", "ERROR"]

    def __init__(self):
        super().__init__()
        self.counts = {s: 0 for s in self.ORDER}
        self.labels = {s: QLabel() for s in self.ORDER}
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        for lab in self.labels.values():
            lay.addWidget(lab)
        self.set_counts({})

    def set_counts(self, counts):
        self.counts = {s: int(counts.get(s, 0)) for s in self.ORDER}
        self.restyle()

    def restyle(self):
        for s, lab in self.labels.items():
            n = self.counts[s]
            lab.setText(f"{n} {s}")
            bg = reports.COLORS.get(s, "#cccccc")
            if n:
                lab.setStyleSheet(f"background:{bg}; color:{reports.fg_for(bg)}; border-radius:11px; "
                                  "padding:1px 10px; font-weight:600;")
            else:                                         # nothing of this kind: show it, but quietly
                lab.setStyleSheet("background:transparent; color:palette(placeholder-text); border-radius:11px; "
                                  "padding:0px 9px; border:1px solid palette(mid);")


class EmptyHint(QWidget):
    """A centred message laid over an empty list or table. Show or hide it as the view fills."""

    def __init__(self, view, title, detail=""):
        super().__init__(view.viewport())
        self.view = view
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        head = QLabel(title)
        head.setAlignment(Qt.AlignmentFlag.AlignCenter)
        head.setStyleSheet("font-size: 13pt; font-weight: 600; background: transparent;")
        sub = QLabel(detail)
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setProperty("muted", True)
        sub.setStyleSheet("background: transparent;")
        lay.addWidget(head)
        lay.addWidget(sub)
        view.viewport().installEventFilter(self)
        self.setGeometry(view.viewport().rect())

    def eventFilter(self, obj, ev):
        if obj is self.view.viewport() and ev.type() == QEvent.Type.Resize:
            self.setGeometry(self.view.viewport().rect())
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
