"""The page behind the sections: a plain colour, or, for a theme with a glow, a soft wash of the accent at the top; for Aurora,
the sky-blue to violet wash that drifts slowly across the page with a faint constellation behind the panels (Motion: Lively).
Under Lively the constellation also wanders slowly round the edges of the page, stretching and changing shape as it goes.
It only moves while the window is shown and the app is in front, and never when motion is off."""
import math

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPen, QRadialGradient
from PySide6.QtWidgets import QApplication, QWidget
from ui import motion, theme

# a constellation: points in a 640x420 box, and which are joined (the same one the mockup drew)
_DOTS = [(80, 120), (210, 70), (330, 140), (450, 90), (560, 160), (250, 210), (140, 300), (470, 230), (590, 300), (300, 360), (600, 60)]
_LINKS = [(0, 1), (1, 2), (2, 3), (3, 4), (1, 5), (2, 5), (5, 6), (3, 7), (7, 2), (7, 8), (8, 4), (6, 9), (9, 7), (4, 10)]
AURORA = ("#38bdf8", "#8b5cf6", "#2dd4bf")
PERIOD_MS = 30000
ORBIT_MS = 180000           # one slow lap of the constellation round the page's edges (three minutes)
WOBBLE = 16                 # how far a dot strays from its place in the shape, in pixels at full size


def _rgba(hexcol, alpha):
    c = QColor(hexcol)
    c.setAlphaF(alpha)
    return c


class Backdrop(QWidget):
    def __init__(self):
        super().__init__()
        self.setAutoFillBackground(False)
        self.phase = 0.0
        self.orbit = 0.875                         # where on its lap the constellation is: it starts at the top right, as the mockup drew it
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
        self.orbit = (self.orbit + self.drift.interval() / ORBIT_MS) % 1.0
        self.update()

    def constellation_centre(self):
        """Where the constellation's box is centred: wandering round the edges of the page under Lively, else at the top right."""
        w, h = self.width(), self.height()
        box_w = min(640, int(w * 0.6))
        s = box_w / 640
        box_h = 420 * s
        if not motion.lively():
            return QPointF(w - box_w / 2, 40 + box_h / 2), s
        u = self.orbit * 2 * math.pi
        squarish = lambda v: math.copysign(abs(v) ** 0.55, v)         # a loop that hugs the edges rather than a circle through the middle
        cx = w / 2 + max(0.0, w / 2 - box_w / 2 - 16) * squarish(math.cos(u))
        cy = h / 2 + max(0.0, h / 2 - box_h / 2 - 16) * squarish(math.sin(u))
        return QPointF(cx, cy), s

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
        """A faint set of linked dots: at the top right, or, under Lively, wandering round the page's edges while the shape
        stretches and its dots stray a little from their places."""
        centre, s = self.constellation_centre()
        lively = motion.lively()
        u = self.orbit * 2 * math.pi
        sx = 1 + (0.22 * math.sin(u + 1.3) if lively else 0)           # the shape stretches and squeezes as it goes
        sy = 1 - (0.15 * math.sin(u * 1.7) if lively else 0)
        pts = []
        for i, (x, y) in enumerate(_DOTS):
            wx = WOBBLE * s * math.sin(u * 3 + i * 1.7) if lively else 0
            wy = WOBBLE * s * math.cos(u * 2 + i * 1.1) if lively else 0
            pts.append(QPointF(centre.x() + (x - 320) * s * sx + wx, centre.y() + (y - 210) * s * sy + wy))
        pen = QPen(_rgba(t["accent"], 0.09))
        pen.setWidthF(1.0)
        p.setPen(pen)
        for a, b in _LINKS:
            p.drawLine(pts[a], pts[b])
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(_rgba(t["accent"], 0.20))
        for i, pt in enumerate(pts):
            rad = (3, 5, 6, 4, 5, 4, 5, 6, 4, 5, 3)[i % 11] * s
            p.drawEllipse(QRectF(pt.x() - rad, pt.y() - rad, rad * 2, rad * 2))
