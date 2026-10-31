"""Motion: whether, and how much, things move. Settings > Appearance > Motion (Off, Subtle, Lively), and Windows' own
"animation effects" switch, which turns everything off regardless. Every animation in Toner asks here, so one setting
rules them all, and a test can hold them still."""
import os
import sys

from PySide6.QtCore import QEasingCurve, QTimer, QVariantAnimation

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
            pass
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
