"""The page behind the sections: a plain colour, or, for a theme with a glow, a soft wash of the accent at the top; for Constellation,
Nebula and Tide (dark and light), the theme's three-colour wash that drifts slowly across the page with a faint constellation behind
the panels (Motion: Lively).
Under Lively every dot also drifts on a smooth random path of its own across the whole page (its lines follow it).
It only moves while the window is shown and the app is in front, and never when motion is off."""
import math
import random

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
SPEED = (0.0040, 0.0060)    # a dot's step per frame, as a share of the page (about 11 to 17 seconds to cross it at 15 frames a second)
TURN = 0.14                 # the most a heading is nudged at random each frame, in radians: a slow, smooth curve
MARGIN = 0.12               # within this share of an edge a dot is steered back in


def _rgba(hexcol, alpha):
    c = QColor(hexcol)
    c.setAlphaF(alpha)
    return c


class Backdrop(QWidget):
    def __init__(self, seed=None):
        super().__init__()
        self.setAutoFillBackground(False)
        self.phase = 0.0
        rng = self._rng = random.Random(seed)       # a seed makes the paths repeatable (tests); none gives fresh ones each run
        self._dots = [[0.05 + 0.9 * x / 640, 0.05 + 0.9 * y / 420] for x, y in _DOTS]       # the shape, spread over the page; then each goes its own way
        self._heading = [rng.uniform(0, 2 * math.pi) for _ in _DOTS]
        self._speed = [rng.uniform(*SPEED) for _ in _DOTS]
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
        self.step_dots()
        self.update()

    def dot_positions(self):
        """Each dot's place on the page, as (x, y) shares of its width and height."""
        return [tuple(d) for d in self._dots]

    def step_dots(self):
        """One frame: every dot moves a little along its heading, the heading turns a little at random, and near an edge it turns away
        (so a dot never slides along one). Nothing moves when motion is off."""
        if not motion.enabled():
            return
        for i, d in enumerate(self._dots):
            px = (MARGIN - d[0]) / MARGIN if d[0] < MARGIN else (d[0] - 1 + MARGIN) / -MARGIN if d[0] > 1 - MARGIN else 0.0      # push in from an edge: 0 to 1
            py = (MARGIN - d[1]) / MARGIN if d[1] < MARGIN else (d[1] - 1 + MARGIN) / -MARGIN if d[1] > 1 - MARGIN else 0.0
            # near an edge the heading is also shaken up, so a dot that met a wall head-on does not bounce back along the same line
            h = self._heading[i] + self._rng.uniform(-TURN, TURN) * (1 + 4 * (abs(px) + abs(py)))
            h = self._heading[i] = math.atan2(math.sin(h) + 0.25 * py, math.cos(h) + 0.25 * px)
            d[0] = min(0.99, max(0.01, d[0] + self._speed[i] * math.cos(h)))
            d[1] = min(0.99, max(0.01, d[1] + self._speed[i] * math.sin(h)))

    def constellation_centre(self):
        """Where the constellation's box is centred when it keeps still: at the top right."""
        w, h = self.width(), self.height()
        box_w = min(640, int(w * 0.6))
        s = box_w / 640
        return QPointF(w - box_w / 2, 40 + 420 * s / 2), s

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
        """A faint set of linked dots: at the top right, or, under Lively, each drifting on a path of its own across the page
        (the lines between them stay joined)."""
        centre, s = self.constellation_centre()
        if motion.lively():
            w, h = self.width(), self.height()
            pts = [QPointF(x * w, y * h) for x, y in self._dots]
        else:
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
