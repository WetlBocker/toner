"""Motion: whether, and how much, things move. Settings > Appearance > Motion (Off, Subtle, Lively), and Windows' own
"animation effects" switch, which turns everything off regardless. Every animation in Toner asks here, so one setting
rules them all, and a test can hold them still."""
import os
import sys

from PySide6.QtCore import QEasingCurve, QPoint, QRectF, Qt, QTimer, QVariantAnimation
from PySide6.QtWidgets import QAbstractItemView, QGraphicsEffect
from core import quiet

LEVELS = ("Off", "Subtle", "Lively")
_forced = None


def system_allows():
    """False when the system asks for no animation: Windows' "Animation effects" is off, or there is no screen (tests)."""
    if os.environ.get("QT_QPA_PLATFORM", "").lower() == "offscreen":
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            on = ctypes.c_int(1)
            if ctypes.windll.user32.SystemParametersInfoW(0x1042, 0, ctypes.byref(on), 0):      # SPI_GETCLIENTAREAANIMATION
                return bool(on.value)
        except Exception:
            quiet.ignored()
    return True


def force(level):
    """Tests: hold the motion level at `level` ("Off", "Subtle", "Lively"), or None to follow the setting again."""
    global _forced
    _forced = level


def level():
    if _forced is not None:
        return _forced
    if not system_allows():
        return "Off"
    from ui import theme
    return (theme.current() or {}).get("motion") or "Subtle"


def enabled():
    return level() != "Off"


def lively():
    return level() == "Lively"


def animate(owner, ms, on_value, start=0.0, end=1.0, curve=QEasingCurve.Type.OutCubic, loop=False, on_done=None):
    """Run on_value(v) from start to end over ms milliseconds. With motion off it calls on_value(end) once and returns None;
    otherwise the running animation (kept alive by `owner`)."""
    if not enabled():
        on_value(end)
        if on_done:
            on_done()
        return None
    anim = QVariantAnimation(owner)
    anim.setStartValue(float(start))
    anim.setEndValue(float(end))
    anim.setDuration(int(ms))
    anim.setEasingCurve(curve)
    if loop:
        anim.setLoopCount(-1)
    anim.valueChanged.connect(on_value)
    if on_done:
        anim.finished.connect(on_done)
    anim.start(QVariantAnimation.DeletionPolicy.DeleteWhenStopped)
    return anim


def stop(anim):
    """Stop a running animation from animate(); one that has already finished deleted itself, and that is fine."""
    try:
        if anim is not None:
            anim.stop()
    except RuntimeError:
        pass


class Phase(QTimer):
    """A slow, looping phase from 0 to 1, stepped at a few frames a second (a drifting wash needs no more, and costs little).
    on_phase(p) is called each step; period_ms is one full loop."""

    def __init__(self, owner, period_ms, on_phase, fps=15):
        super().__init__(owner)
        self.period, self.on_phase = max(1, period_ms), on_phase
        self.p = 0.0
        self.setInterval(max(16, int(1000 / fps)))
        self.timeout.connect(self._step)

    def _step(self):
        self.p = (self.p + self.interval() / self.period) % 1.0
        self.on_phase(self.p)


# ---- rows that fly up a little and fade in, one after another, when a list comes into view (the mockup's "fade up")
REVEAL_MS = 380             # one row's fade and lift
REVEAL_STAGGER = 40         # the gap between one row starting and the next
REVEAL_LIFT = 10            # how far up a row travels, in pixels
REVEAL_TOTAL = 1100         # the longest a whole list takes: a long list starts its rows closer together, every row still in its turn


def row_bands(view):
    """(top, height) of each row showing in an item view's viewport, top to bottom (a tree's open children count as rows)."""
    bands, y, vp_h = [], 0, view.viewport().height()
    while y < vp_h:
        idx = view.indexAt(QPoint(4, y))
        if not idx.isValid():
            break
        r = view.visualRect(idx)
        if r.height() <= 0:
            break
        if bands and r.top() <= bands[-1][0]:                  # a grid line: the same row again, one pixel down
            y += 1
            continue
        bands.append((r.top(), r.height()))
        y = r.bottom() + 1
    return [(top, (bands[i + 1][0] - top) if i + 1 < len(bands) else h) for i, (top, h) in enumerate(bands)]   # each band reaches the next


class Reveal(QGraphicsEffect):
    """Paints a widget's rows (bands of it, from `bands()`) sliding up and fading in, each a little after the one above. The effect
    takes itself off the widget when the last row has landed, so painting costs nothing afterwards."""

    def __init__(self, target, bands):
        super().__init__()
        self.target, self.bands_fn, self.t = target, bands, 0.0
        self._anim = None
        self._stagger, self._total = float(REVEAL_STAGGER), float(REVEAL_MS)

    def start(self):
        n = max(1, len(self.bands_fn()))
        self._stagger = min(float(REVEAL_STAGGER), (REVEAL_TOTAL - REVEAL_MS) / max(1, n - 1))
        self._total = REVEAL_MS + self._stagger * (n - 1)
        self.target.setGraphicsEffect(self)
        self.target._reveal = self                             # (a Python reference, or the effect is collected and comes off at once)
        self._anim = animate(self, self._total, self._on_value, curve=QEasingCurve.Type.Linear, on_done=self._done)

    def _on_value(self, v):
        self.t = float(v)
        self.update()

    def _done(self):
        if self.target.graphicsEffect() is self:
            self.target.setGraphicsEffect(None)                # (deletes this effect)
        if getattr(self.target, "_reveal", None) is self:
            self.target._reveal = None

    def progress(self, i):
        """How far row i has come: 0 (not started) to 1 (landed). Every row has its own turn, the gaps shorter in a long list."""
        started = self.t * self._total - self._stagger * i
        p = max(0.0, min(1.0, started / REVEAL_MS))
        return QEasingCurve(QEasingCurve.Type.OutCubic).valueForProgress(p)

    def draw(self, painter):
        pm = self.sourcePixmap(Qt.CoordinateSystem.LogicalCoordinates, mode=QGraphicsEffect.PixmapPadMode.NoPad)
        if pm.isNull():
            return
        off = self.sourceBoundingRect(Qt.CoordinateSystem.LogicalCoordinates).topLeft()
        dpr = pm.devicePixelRatio() or 1.0
        w, h = pm.width() / dpr, pm.height() / dpr
        bands = self.bands_fn()
        if not bands or self.t >= 1.0:
            painter.drawPixmap(off, pm)
            return
        painter.save()
        last = bands[-1][0] + bands[-1][1]
        if last < h:                                           # whatever lies under the rows (the empty part of the list) as it is
            painter.drawPixmap(QRectF(off.x(), off.y() + last, w, h - last), pm, QRectF(0, last * dpr, pm.width(), (h - last) * dpr))
        for i, (top, height) in enumerate(bands):
            p = self.progress(i)
            if p <= 0:
                continue
            painter.setOpacity(p)
            painter.drawPixmap(QRectF(off.x(), off.y() + top + REVEAL_LIFT * (1 - p), w, height), pm, QRectF(0, top * dpr, pm.width(), height * dpr))
        painter.restore()


def reveal(widget, bands=None):
    """Bring a list into view with its rows flying up and fading in (nothing when motion is off). `widget` is an item view, or any
    widget with `bands()` giving its rows as (top, height)."""
    if not enabled() or not widget.isVisible():
        return None
    if isinstance(widget, QAbstractItemView):
        target, bands = widget.viewport(), (lambda: row_bands(widget))
    else:
        target = widget
    if not bands:
        return None
    eff = Reveal(target, bands)
    eff.start()
    return eff
