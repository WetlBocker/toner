"""Panels and the small moving parts the Overview uses: a card that casts a soft shadow under Panels: Raised, a thin progress line with
a shimmer while checks run, and a progress bar for the status strip that shimmers the same way."""
from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QLinearGradient, QPainter
from PySide6.QtWidgets import QFrame, QProgressBar, QVBoxLayout, QWidget
from ui import motion, theme

SHADOW = 6                      # the room a raised panel keeps round itself for its shadow


class Panel(QWidget):
    """A card: `card` is the QFrame[card="true"] to lay things out in. When Panels is Raised, the panel keeps a margin round the card and
    paints a soft shadow there (Qt paints a stylesheet background before paintEvent, so the shadow has to sit beside the card, not under it)."""

    def __init__(self):
        super().__init__()
        self.card = QFrame(self)
        self.card.setProperty("card", True)
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(0, 0, 0, 0)
        self._lay.setSpacing(0)
        self._lay.addWidget(self.card)
        self.restyle()

    def restyle(self):
        raised = bool((theme.current() or {}).get("raised"))
        self._lay.setContentsMargins(SHADOW, 2, SHADOW, SHADOW + 2) if raised else self._lay.setContentsMargins(0, 0, 0, 0)
        self.update()

    def paintEvent(self, e):
        t = theme.current() or {}
        if t.get("raised"):
            p = QPainter(self)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            dark = t.get("dark")
            rad = int(t.get("r_card", 8)) + 2
            p.setPen(Qt.PenStyle.NoPen)
            for i, alpha in ((3, 0.05), (2, 0.08), (1, 0.12)) if dark else ((3, 0.03), (2, 0.045), (1, 0.07)):
                p.setBrush(QColor(0, 0, 0, int(255 * alpha)))
                p.drawRoundedRect(QRectF(self.card.geometry().adjusted(-i, -i + 2, i, i + 3)), rad, rad)
            p.end()
        super().paintEvent(e)


class ProgressLine(QFrame):
    """A thin line that fills from the left as checks run, with a sweep of light along it (the shimmer) while motion is on."""

    def __init__(self):
        super().__init__()
        self.setFixedHeight(4)
        self.done, self.total = 0, 0
        self.shown, self.phase = 0.0, 0.0
        self._fill = None
        self.sweep = motion.Phase(self, 1200, self._on_phase, fps=30)
        self.hide()

    def set_progress(self, done, total):
        self.done, self.total = done, total
        running = 0 <= done < total
        self.setVisible(running)
        if running:
            target = done / max(1, total)
            if self._fill is not None:
                self._fill.stop()
            start = self.shown
            self._fill = motion.animate(self, 350, lambda v: self._on_fill(start + (target - start) * v))
            if motion.enabled() and not self.sweep.isActive():
                self.sweep.start()
        else:
            self.sweep.stop()
            self.shown = 0.0

    def _on_fill(self, v):
        self.shown = float(v)
        self.update()

    def _on_phase(self, v):
        self.phase = v
        self.update()

    def hideEvent(self, e):
        super().hideEvent(e)
        self.sweep.stop()

    def paintEvent(self, _e):
        t = theme.current() or {}
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(t.get("surface2", "#e0e0e0")))
        p.drawRoundedRect(QRectF(self.rect()), 2, 2)
        w = self.width() * self.shown
        p.setBrush(QColor(t.get("accent", "#2563eb")))
        p.drawRoundedRect(QRectF(0, 0, w, self.height()), 2, 2)
        if self.sweep.isActive() and w > 10:
            g = QLinearGradient(w * self.phase - 40, 0, w * self.phase + 40, 0)
            g.setColorAt(0.0, QColor(255, 255, 255, 0))
            g.setColorAt(0.5, QColor(255, 255, 255, 110))
            g.setColorAt(1.0, QColor(255, 255, 255, 0))
            p.setBrush(g)
            p.drawRoundedRect(QRectF(0, 0, w, self.height()), 2, 2)


class ShimmerBar(QProgressBar):
    """The status strip's progress bar, with the same sweep of light while motion is on. Its API is QProgressBar's."""

    def __init__(self):
        super().__init__()
        self.phase = 0.0
        self.sweep = motion.Phase(self, 1200, self._on_phase, fps=30)

    def _on_phase(self, v):
        self.phase = v
        self.update()

    def showEvent(self, e):
        super().showEvent(e)
        if motion.enabled():
            self.sweep.start()

    def hideEvent(self, e):
        super().hideEvent(e)
        self.sweep.stop()

    def paintEvent(self, e):
        super().paintEvent(e)
        if not self.sweep.isActive() or self.maximum() <= 0:
            return
        w = self.width() * self.value() / self.maximum()
        if w < 10:
            return
        p = QPainter(self)
        g = QLinearGradient(w * self.phase - 30, 0, w * self.phase + 30, 0)
        g.setColorAt(0.0, QColor(255, 255, 255, 0))
        g.setColorAt(0.5, QColor(255, 255, 255, 100))
        g.setColorAt(1.0, QColor(255, 255, 255, 0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(g)
        p.drawRoundedRect(QRectF(0, 0, w, self.height()), 3, 3)
