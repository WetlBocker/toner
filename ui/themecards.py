"""Settings > Appearance > Theme: every theme as a small card, a picture of what the window would look like in it, grouped
Dark / Light / Interactive / Classic. Clicking one previews it at once; Save keeps it."""
from PySide6.QtCore import QRect, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QAbstractButton, QButtonGroup, QLabel, QVBoxLayout, QWidget
from ui import theme, themes
from ui.widgets import FlowLayout

CARD_W, CARD_H = 168, 118
PREVIEW_H = 84


class ThemeCard(QAbstractButton):
    """One theme: a mini window (sidebar strip, a panel, OK / WARN / FAIL chips, a primary button) in its own colours, its name
    and its kind. Checked = the chosen theme (an accent ring)."""

    def __init__(self, name):
        super().__init__()
        self.name = name
        self.setCheckable(True)
        self.setProperty("notSetting", True)                 # the page tells Settings about the choice itself (describe_extra)
        self.setFixedSize(CARD_W, CARD_H)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(themes.note(name))
        self.setAccessibleName(f"{name} theme")
        self.custom = {}                                     # Your colour: the accent and base chosen on the page

    def tokens(self):
        look = dict(themes.DEFAULT_LOOK, theme=self.name, **self.custom)
        ctx = dict(system_dark=bool((theme.current() or {}).get("dark")), worst="OK", org_colour="#f0883e")
        return themes.resolve(look, ctx)

    def sizeHint(self):
        return QSize(CARD_W, CARD_H)

    def paintEvent(self, _e):
        t = self.tokens()
        dark = t["dark"]
        sc = themes.STATUS[dark]
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        cur = theme.current() or {}
        ring = QColor(cur.get("accent", t["accent"])) if self.isChecked() else QColor(cur.get("border", t["border"]))
        pen = QPen(ring)
        pen.setWidth(2 if self.isChecked() else 1)
        p.setPen(pen)
        p.setBrush(QColor(t["bg"]))
        p.drawRoundedRect(QRectF(1, 1, CARD_W - 2, CARD_H - 2), 9, 9)
        p.setClipRect(QRect(2, 2, CARD_W - 4, PREVIEW_H))
        # the sidebar strip
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(t["surface"]))
        p.drawRect(QRect(2, 2, 40, PREVIEW_H))
        p.setBrush(QColor(t["accent"]))
        p.drawRoundedRect(QRectF(9, 12, 26, 6), 3, 3)
        p.setBrush(QColor(t["surface2"]))
        for y in (24, 36, 48):
            p.drawRoundedRect(QRectF(9, y, 26, 6), 3, 3)
        # a heading line, three chips, a panel, a button
        x0 = 50
        p.setBrush(QColor(t["text"]))
        p.setOpacity(0.85)
        p.drawRoundedRect(QRectF(x0, 11, 58, 6), 3, 3)
        p.setOpacity(1.0)
        f = QFont(self.font())
        f.setPointSizeF(6.5)
        f.setBold(True)
        p.setFont(f)
        cx = x0
        for s in ("OK", "WARN", "FAIL"):
            col = QColor(sc[s])
            soft = QColor(col)
            soft.setAlphaF(0.18 if dark else 0.12)
            w = p.fontMetrics().horizontalAdvance(s) + 10
            p.setBrush(soft)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawRoundedRect(QRectF(cx, 23, w, 12), 6, 6)
            p.setPen(col)
            p.drawText(QRect(cx, 23, w, 12), Qt.AlignmentFlag.AlignCenter, s)
            cx += w + 4
        p.setPen(QPen(QColor(t["border"]), 1))
        p.setBrush(QColor(t["surface"]))
        p.drawRoundedRect(QRectF(x0, 41, CARD_W - x0 - 10, 24), 4, 4)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(t["muted"]))
        p.drawRoundedRect(QRectF(x0 + 6, 47, 44, 4), 2, 2)
        p.setBrush(QColor(t["border"]))
        p.drawRoundedRect(QRectF(x0 + 6, 55, 70, 4), 2, 2)
        p.setBrush(QColor(t["accent"]))
        p.drawRoundedRect(QRectF(x0, 70, 54, 11), 3, 3)
        p.setPen(QColor(t["accent_text"]))
        p.drawText(QRect(x0, 70, 54, 11), Qt.AlignmentFlag.AlignCenter, "Run checks")
        p.setClipping(False)
        # the name strip, in the window's own colours
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(cur.get("surface", t["surface"])))
        p.drawRect(QRect(2, PREVIEW_H + 2, CARD_W - 4, CARD_H - PREVIEW_H - 4))
        p.setPen(QPen(ring, 2 if self.isChecked() else 1))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawRoundedRect(QRectF(1, 1, CARD_W - 2, CARD_H - 2), 9, 9)
        f = QFont(self.font())
        f.setBold(True)
        p.setFont(f)
        p.setPen(QColor(cur.get("text", t["text"])))
        p.drawText(QRect(10, PREVIEW_H + 4, CARD_W - 20, 16), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                   p.fontMetrics().elidedText(self.name, Qt.TextElideMode.ElideRight, CARD_W - 20))
        f.setBold(False)
        f.setPointSizeF(max(7.0, f.pointSizeF() - 1.5))
        p.setFont(f)
        p.setPen(QColor(cur.get("muted", t["muted"])))
        p.drawText(QRect(10, PREVIEW_H + 18, CARD_W - 20, 14), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, themes.kind(self.name))


class ThemeGrid(QWidget):
    """The cards, grouped. picked(name) when a card is clicked."""
    picked = Signal(str)

    def __init__(self):
        super().__init__()
        self.cards = {}
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        self._add_group(None, [themes.SYSTEM], lay)
        for title, names in themes.GROUPS:
            self._add_group(title, names, lay)
        self.group.buttonClicked.connect(lambda b: self.picked.emit(b.name))

    def _add_group(self, title, names, lay):
        if title:
            head = QLabel(title.upper())
            head.setProperty("muted", True)
            hf = head.font()
            hf.setPointSizeF(max(7.0, hf.pointSizeF() - 1.5))
            hf.setBold(True)
            head.setFont(hf)
            head.setContentsMargins(0, 8, 0, 0)
            lay.addWidget(head)
        row = QWidget()
        flow = FlowLayout(8, 8)
        row.setLayout(flow)
        for name in names:
            card = ThemeCard(name)
            self.cards[name] = card
            self.group.addButton(card)
            flow.addWidget(card)
        lay.addWidget(row)

    def set_current(self, name, emit=False):
        card = self.cards.get(name) or self.cards[themes.SYSTEM]
        card.setChecked(True)
        self.update()
        if emit:
            self.picked.emit(card.name)

    def current(self):
        b = self.group.checkedButton()
        return b.name if b else themes.SYSTEM

    def set_custom(self, accent, base, tint):
        """Your colour: repaint its card with what the page's controls say."""
        card = self.cards["Your colour"]
        card.custom = dict(custom_accent=accent, custom_base=base, custom_tint=bool(tint))
        card.update()

    def restyle(self):
        for c in self.cards.values():
            c.update()
