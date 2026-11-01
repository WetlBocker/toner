"""The page behind the sections: a plain colour, or, for a theme with a glow, a soft wash of the accent at the top; for Constellation,
Nebula and Tide (dark and light), the theme's three-colour wash that drifts slowly across the page with a faint constellation behind
the panels (Motion: Lively).
Under Lively the constellation also wanders slowly round the edges of the page, stretching and changing shape as it goes.
It only moves while the window is shown and the app is in front, and never when motion is off."""
import math

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPen, QRadialGradient
from PySide6.QtWidgets import QApplication, QWidget
from ui import motion, theme

# a constellation: points in a 640x420 box, and which are joined (the mockup's eleven, and six more round them)
_DOTS = [(80, 120), (210, 70), (330, 140), (450, 90), (560, 160), (250, 210), (140, 300), (470, 230), (590, 300), (300, 360), (600, 60),
         (40, 230), (170, 390), (400, 300), (520, 380), (620, 200), (360, 30)]
_LINKS = [(0, 1), (1, 2), (2, 3), (3, 4), (1, 5), (2, 5), (5, 6), (3, 7), (7, 2), (7, 8), (8, 4), (6, 9), (9, 7), (4, 10),
          (6, 11), (11, 0), (9, 12), (12, 6), (9, 13), (13, 7), (13, 14), (14, 8), (8, 15), (15, 10), (3, 16), (16, 1)]
AURORA = ("#38bdf8", "#8b5cf6", "#2dd4bf")
PERIOD_MS = 30000
ORBIT_MS = 180000           # one slow lap of the constellation round the page's edges (three minutes)
WANDER = 44                 # how far each dot wanders from its place in the shape, in pixels at full size (its lines follow it)


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

    def dot_drift(self):
        """Where each dot is on its own slow path, as (x factor, y factor) of its place in the shape: a loop of its own speed and
        size for every dot, so the dots move apart and together while the shape as a whole stretches and squeezes."""
        u = self.orbit * 2 * math.pi
        sx = 1 + 0.22 * math.sin(u + 1.3)                                # the whole shape
        sy = 1 - 0.15 * math.sin(u * 1.7)
        out = []
        for i, (x, y) in enumerate(_DOTS):
            kx, ky = 3 + (i * 7) % 5, 4 + (i * 5) % 4                    # a loop every 22 to 60 seconds, different for each dot
            wx = WANDER * math.sin(u * kx + i * 1.7)
            wy = WANDER * math.cos(u * ky + i * 1.1)
            out.append((sx + wx / (x - 320 or 1), sy + wy / (y - 210 or 1)))
        return out

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
            # the wash: the theme's three hues across the page, slid by the phase (back and forth over one period); lighter on a light page
            wash = tuple(t.get("wash") or AURORA)
            a = (0.16, 0.14, 0.12) if dark else (0.11, 0.09, 0.08)
            shift = (1 - abs(self.phase * 2 - 1)) * 0.5
            g = QLinearGradient(QPointF(-w * shift, 0), QPointF(w * (1.6 - shift), h * 0.7))
            g.setColorAt(0.0, _rgba(wash[0], a[0]))
            g.setColorAt(0.35, _rgba(wash[1], a[1]))
            g.setColorAt(0.65, _rgba(wash[2], a[2]))
            g.setColorAt(1.0, _rgba(wash[0], a[0]))
            p.fillRect(self.rect(), g)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            self._constellation(p, t)
        r = QRadialGradient(QPointF(w * 0.12, -h * 0.06), max(w * 0.75, 600.0))
        r.setColorAt(0.0, _rgba(t["accent"], 0.18 if dark else 0.10))
        r.setColorAt(0.6, _rgba(t["accent"], 0.0))
        p.fillRect(self.rect(), r)

    def _constellation(self, p, t):
        """A faint set of linked dots: at the top right, or, under Lively, wandering round the page's edges while the shape
        stretches and every dot drifts on a slow path of its own (the lines between them stay joined)."""
        centre, s = self.constellation_centre()
        lively = motion.lively()
        pts = [QPointF(centre.x() + (x - 320) * s * dx, centre.y() + (y - 210) * s * dy) for (x, y), (dx, dy) in zip(_DOTS, self.dot_drift())]
        if not lively:
            pts = [QPointF(centre.x() + (x - 320) * s, centre.y() + (y - 210) * s) for x, y in _DOTS]
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
