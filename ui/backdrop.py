"""The page behind the sections: a plain colour, or, for a theme with a glow, a soft wash of the accent at the top; for Aurora,
the sky-blue to violet wash that drifts slowly across the page with a faint constellation behind the panels (Motion: Lively).
It only moves while the window is shown and the app is in front, and never when motion is off."""
from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPen, QRadialGradient
from PySide6.QtWidgets import QApplication, QWidget
from ui import motion, theme

# a constellation: points in a 640x420 box, and which are joined (the same one the mockup drew)
_DOTS = [(80, 120), (210, 70), (330, 140), (450, 90), (560, 160), (250, 210), (140, 300), (470, 230), (590, 300), (300, 360), (600, 60)]
_LINKS = [(0, 1), (1, 2), (2, 3), (3, 4), (1, 5), (2, 5), (5, 6), (3, 7), (7, 2), (7, 8), (8, 4), (6, 9), (9, 7), (4, 10)]
AURORA = ("#38bdf8", "#8b5cf6", "#2dd4bf")
PERIOD_MS = 30000


def _rgba(hexcol, alpha):
    c = QColor(hexcol)
    c.setAlphaF(alpha)
    return c


class Backdrop(QWidget):
    def __init__(self):
        super().__init__()
        self.setAutoFillBackground(False)
        self.phase = 0.0
        self.drift = motion.Phase(self, PERIOD_MS, self._on_phase)
        QApplication.instance().applicationStateChanged.connect(lambda _s: self.restyle())

    def restyle(self):
        """After the look changed, or the window was shown or hidden: start or stop drifting."""
        t = theme.current()
        moving = bool(t.get("aurora")) and motion.lively() and self.isVisible() and QApplication.applicationState() == Qt.ApplicationState.ApplicationActive
        if moving and not self.drift.isActive():
            self.drift.start()
        elif not moving and self.drift.isActive():
            self.drift.stop()
        self.update()

    def showEvent(self, e):
        super().showEvent(e)
        self.restyle()

    def hideEvent(self, e):
        super().hideEvent(e)
        self.drift.stop()

    def _on_phase(self, p):
        self.phase = p
        self.update()

    def paintEvent(self, _e):
        t = theme.current()
        if not t:
            return
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(t["bg"]))
        if not t.get("glow"):
            return
        dark = t.get("dark")
        w, h = self.width(), self.height()
        if t.get("aurora"):
            # the wash: three hues across the page, slid by the phase (back and forth over one period)
            shift = (1 - abs(self.phase * 2 - 1)) * 0.5
            g = QLinearGradient(QPointF(-w * shift, 0), QPointF(w * (1.6 - shift), h * 0.7))
            g.setColorAt(0.0, _rgba(AURORA[0], 0.16))
            g.setColorAt(0.35, _rgba(AURORA[1], 0.14))
            g.setColorAt(0.65, _rgba(AURORA[2], 0.12))
            g.setColorAt(1.0, _rgba(AURORA[0], 0.16))
            p.fillRect(self.rect(), g)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            self._constellation(p, t)
        r = QRadialGradient(QPointF(w * 0.12, -h * 0.06), max(w * 0.75, 600.0))
        r.setColorAt(0.0, _rgba(t["accent"], 0.18 if dark else 0.10))
        r.setColorAt(0.6, _rgba(t["accent"], 0.0))
        p.fillRect(self.rect(), r)

    def _constellation(self, p, t):
        """A faint set of linked dots at the top right, drifting a little under Lively."""
        box_w = min(640, int(self.width() * 0.6))
        s = box_w / 640
        dx = -36 * (1 - abs(self.phase * 2 - 1)) if motion.lively() else 0
        ox, oy = self.width() - box_w + dx, 40 + 22 * (1 - abs(self.phase * 2 - 1)) * (1 if motion.lively() else 0)
        pen = QPen(_rgba(t["accent"], 0.14))
        pen.setWidthF(1.0)
        p.setPen(pen)
        pts = [QPointF(ox + x * s, oy + y * s) for x, y in _DOTS]
        for a, b in _LINKS:
            p.drawLine(pts[a], pts[b])
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(_rgba(t["accent"], 0.28))
        for i, pt in enumerate(pts):
            rad = (3, 5, 6, 4, 5, 4, 5, 6, 4, 5, 3)[i % 11] * s
            p.drawEllipse(QRectF(pt.x() - rad, pt.y() - rad, rad * 2, rad * 2))
